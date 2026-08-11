mod api;
mod auth;
mod collector;
mod config;
mod conntrack;
mod dns;
mod dns_proxy;
mod domain;
mod service;
mod state;
mod storage;
mod web;

use auth::AuthService;
use axum::Router;
use collector::{ConntrackEnrichedCollector, FlowCollector, SimulatedCollector, TcEbpfCollector};
use config::Config;
use conntrack::{CachedConntrackReader, NetlinkConntrackReader};
use dns::{DnsAttributionCache, DnsObservationQueue, DnsObservationSource};
use dns_proxy::DnsProxy;
use service::ObservationService;
use state::AppState;
use std::error::Error;
use std::io::BufRead;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use storage::SqliteRepository;
use tokio::net::TcpListener;
use tokio::time::{self, MissedTickBehavior};

const RETENTION_CLEANUP_INTERVAL_SECS: u64 = 60 * 60;

/// 进程入口：加载配置、初始化存储与服务、启动后台任务并监听 HTTP。
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    if std::env::args().nth(1).as_deref() == Some("hash-password") {
        let mut password = String::new();
        std::io::stdin().lock().read_line(&mut password)?;
        let password = password.trim_end_matches(['\r', '\n']);
        if password.is_empty() {
            return Err("password must not be empty".into());
        }
        let password_hash = AuthService::hash_password(password)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        println!("{password_hash}");
        return Ok(());
    }

    let config = Config::from_env();

    if let Some(parent) = Path::new(&config.database_path).parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }

    let repo = Arc::new(SqliteRepository::open(&config.database_path)?);
    let observation = Arc::new(ObservationService::new(
        Arc::clone(&repo),
        config.flow_retention_hours,
        config.aggregate_retention_days,
    ));
    let auth = Arc::new(AuthService::from_repository(
        Arc::clone(&repo),
        config.admin_username.clone(),
        config.admin_password_hash.clone(),
    )?);

    let _retention_task = tokio::spawn(run_retention_cleanup_loop(Arc::clone(&observation)));

    if config.simulator_enabled && config.tc_ebpf_enabled {
        return Err(
            "ROUTESCOPE_ENABLE_SIMULATOR and ROUTESCOPE_ENABLE_TC_EBPF cannot both be enabled"
                .into(),
        );
    }

    let collector: Option<(Arc<dyn FlowCollector>, u64)> = if config.simulator_enabled {
        Some((
            Arc::new(SimulatedCollector::with_interval_secs(
                config.simulator_interval_secs,
            )),
            config.simulator_interval_secs,
        ))
    } else if config.tc_ebpf_enabled {
        let tc_collector: Arc<dyn FlowCollector> = Arc::new(TcEbpfCollector::new(
            config.lan_interface.clone(),
            config.wan_interface.clone(),
        )?);
        let collector: Arc<dyn FlowCollector> = if config.conntrack_enabled {
            Arc::new(ConntrackEnrichedCollector::new(
                tc_collector,
                Arc::new(CachedConntrackReader::new(
                    Arc::new(NetlinkConntrackReader),
                    Duration::from_secs(config.conntrack_refresh_interval_secs.max(1)),
                )),
            ))
        } else {
            tc_collector
        };

        Some((collector, config.collector_interval_secs))
    } else {
        None
    };

    let dns_cache = Arc::new(DnsAttributionCache::new());
    let dns_source_queue = Arc::new(DnsObservationQueue::new());
    let dns_source: Arc<dyn DnsObservationSource> = dns_source_queue.clone();

    let _dns_task = if config.dns_proxy_enabled {
        let proxy = DnsProxy::new(
            config.dns_listen_addr,
            config.dns_upstream_addr,
            Duration::from_millis(config.dns_query_timeout_ms.max(1)),
            Arc::clone(&dns_source_queue),
        );
        let proxy = proxy.bind().await.map_err(std::io::Error::other)?;
        Some(tokio::spawn(async move {
            if let Err(error) = proxy.run().await {
                eprintln!("DNS proxy stopped: {error}");
            }
        }))
    } else {
        None
    };

    // Drain/purge must not depend on a flow collector: the DNS proxy can run alone.
    let _dns_attribution_task = if config.dns_proxy_enabled {
        Some(tokio::spawn(run_dns_attribution_loop(
            Arc::clone(&dns_cache),
            Arc::clone(&dns_source),
            config.collector_interval_secs,
        )))
    } else {
        None
    };

    let _collector_task = collector.map(|(collector, interval_secs)| {
        tokio::spawn(run_collection_loop(
            Arc::clone(&observation),
            collector,
            Arc::clone(&dns_cache),
            Arc::clone(&dns_source),
            interval_secs,
        ))
    });

    let state = AppState {
        observation,
        auth,
        dev_bypass_auth: config.dev_bypass_auth,
        secure_cookies: config.secure_cookies,
    };

    let listener = TcpListener::bind(config.listen_addr).await?;
    println!("RouteScope listening on http://{}", config.listen_addr);
    axum::serve(
        listener,
        app(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

/// 合并公开/受保护的 API 与 Web 路由，并注入共享状态。
fn app(state: AppState) -> Router {
    Router::new()
        .merge(api::public_routes())
        .merge(api::protected_routes(state.clone()))
        .merge(web::public_routes())
        .merge(web::protected_routes(state.clone()))
        .with_state(state)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Drain DNS observations into the attribution cache and drop expired bindings.
fn refresh_dns_attribution(
    dns_cache: &DnsAttributionCache,
    dns_source: &dyn DnsObservationSource,
    now_ms: i64,
) {
    if let Err(error) = dns_cache.collect_from(dns_source) {
        eprintln!(
            "DNS source {} failed to collect observations: {error}",
            dns_source.source_name()
        );
    }
    dns_cache.purge_expired(now_ms);
}

/// Keep the DNS observation queue drained even when no flow collector is running.
async fn run_dns_attribution_loop(
    dns_cache: Arc<DnsAttributionCache>,
    dns_source: Arc<dyn DnsObservationSource>,
    interval_secs: u64,
) {
    let mut ticker = time::interval(Duration::from_secs(interval_secs.max(1)));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;
        refresh_dns_attribution(dns_cache.as_ref(), dns_source.as_ref(), now_ms());
    }
}

/// 按固定间隔调用采集器，将 flow 写入观测服务，并打印健康/错误信息。
async fn run_collection_loop(
    observation: Arc<ObservationService>,
    collector: Arc<dyn FlowCollector>,
    dns_cache: Arc<DnsAttributionCache>,
    dns_source: Arc<dyn DnsObservationSource>,
    interval_secs: u64,
) {
    let mut ticker = time::interval(Duration::from_secs(interval_secs.max(1)));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;

        match collector.collect() {
            Ok(mut batch) => {
                // Fresh drain immediately before attribution for lower latency.
                refresh_dns_attribution(
                    dns_cache.as_ref(),
                    dns_source.as_ref(),
                    batch.observed_at_ms,
                );
                dns_cache.attribute_flows(&mut batch.flows);

                if batch.health.state != collector::CollectorHealthState::Healthy {
                    eprintln!(
                        "collector {} health={:?} observed_at_ms={} error={:?}",
                        collector.source_name(),
                        batch.health.state,
                        batch.observed_at_ms,
                        batch.health.last_error
                    );
                }

                if let Err(error) = observation.ingest_flows(&batch.flows) {
                    eprintln!(
                        "collector {} failed to ingest flows: {error}",
                        collector.source_name()
                    );
                }
            }
            Err(failure) => {
                eprintln!(
                    "collector {} health={:?} failed: {}",
                    collector.source_name(),
                    failure.health.state,
                    failure.error
                );
            }
        }
    }
}

/// 定期清理过期的 flow 与分钟聚合数据。
async fn run_retention_cleanup_loop(observation: Arc<ObservationService>) {
    let mut ticker = time::interval(Duration::from_secs(RETENTION_CLEANUP_INTERVAL_SECS));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;

        match observation.cleanup_expired_data() {
            Ok((deleted_flows, deleted_aggregates))
                if deleted_flows > 0 || deleted_aggregates > 0 =>
            {
                eprintln!(
                    "retention cleanup removed {deleted_flows} flows and \
                     {deleted_aggregates} aggregate rows"
                );
            }
            Ok(_) => {}
            Err(error) => eprintln!("retention cleanup failed: {error}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{HeaderValue, Request, StatusCode, header},
    };
    use storage::RouteScopeRepository;
    use tower::ServiceExt;

    /// 构造带内存库的测试用 Router。
    fn test_app(dev_bypass_auth: bool) -> Router {
        let repo = Arc::new(SqliteRepository::open_in_memory().unwrap());
        let auth = Arc::new(
            AuthService::from_repository(Arc::clone(&repo), "admin".to_owned(), None).unwrap(),
        );
        let observation = Arc::new(ObservationService::new(repo, 24, 30));
        app(AppState {
            observation,
            auth,
            dev_bypass_auth,
            secure_cookies: false,
        })
    }

    /// 构造带测试管理员账户的 Router。
    fn configured_test_app() -> Router {
        let repo = Arc::new(SqliteRepository::open_in_memory().unwrap());
        let observation = Arc::new(ObservationService::new(Arc::clone(&repo), 24, 30));
        let auth = Arc::new(AuthService::from_password("admin", "correct-password").unwrap());
        app(AppState {
            observation,
            auth,
            dev_bypass_auth: false,
            secure_cookies: false,
        })
    }

    fn cookie_pair(header_value: &HeaderValue) -> String {
        header_value
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned()
    }

    fn cookie_value(cookie: &str) -> &str {
        cookie.split_once('=').unwrap().1
    }

    #[tokio::test]
    async fn health_check_is_public() {
        let response = test_app(false)
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn protected_api_requires_authentication() {
        let response = test_app(false)
            .oneshot(
                Request::builder()
                    .uri("/api/v1/devices")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_page_is_public() {
        let response = test_app(false)
            .oneshot(
                Request::builder()
                    .uri("/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn login_session_and_csrf_protect_management_api() {
        let application = configured_test_app();
        let login_page = application
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login_page.status(), StatusCode::OK);

        let csrf_cookie = cookie_pair(
            login_page
                .headers()
                .get(header::SET_COOKIE)
                .expect("login page sets CSRF cookie"),
        );
        let csrf_token = cookie_value(&csrf_cookie);

        let login = application
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(header::COOKIE, &csrf_cookie)
                    .body(Body::from(format!(
                        "username=admin&password=correct-password&csrf_token={csrf_token}"
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::SEE_OTHER);

        let cookies = login.headers().get_all(header::SET_COOKIE);
        let session_cookie = cookies
            .iter()
            .find(|value| cookie_pair(value).starts_with("routescope_session="))
            .map(cookie_pair)
            .expect("login sets session cookie");
        let csrf_cookie = cookies
            .iter()
            .find(|value| cookie_pair(value).starts_with("routescope_csrf="))
            .map(cookie_pair)
            .expect("login rotates CSRF cookie");
        let cookie_header = format!("{session_cookie}; {csrf_cookie}");

        let authenticated = application
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/devices")
                    .header(header::COOKIE, &cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authenticated.status(), StatusCode::OK);

        let logout = application
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/logout")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(header::COOKIE, &cookie_header)
                    .body(Body::from(format!(
                        "csrf_token={}",
                        cookie_value(&csrf_cookie)
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(logout.status(), StatusCode::SEE_OTHER);

        let after_logout = application
            .oneshot(
                Request::builder()
                    .uri("/api/v1/devices")
                    .header(header::COOKIE, &cookie_header)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(after_logout.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn list_devices_returns_seeded_data_when_auth_bypassed() {
        let repo = Arc::new(SqliteRepository::open_in_memory().unwrap());
        repo.upsert_device(&crate::domain::Device {
            mac_address: "aa:bb:cc:dd:ee:ff".into(),
            display_name: Some("laptop".into()),
            current_ip: Some("192.168.1.10".into()),
        })
        .unwrap();

        let auth = Arc::new(
            AuthService::from_repository(Arc::clone(&repo), "admin".to_owned(), None).unwrap(),
        );
        let observation = Arc::new(ObservationService::new(repo, 24, 30));
        let response = app(AppState {
            observation,
            auth,
            dev_bypass_auth: true,
            secure_cookies: false,
        })
        .oneshot(
            Request::builder()
                .uri("/api/v1/devices")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
