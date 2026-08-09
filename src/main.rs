mod api;
mod auth;
mod collector;
mod config;
mod domain;
mod service;
mod state;
mod storage;
mod web;

use axum::Router;
use collector::{FlowCollector, SimulatedCollector};
use config::Config;
use service::ObservationService;
use state::AppState;
use std::error::Error;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use storage::SqliteRepository;
use tokio::net::TcpListener;
use tokio::time::{self, MissedTickBehavior};

const RETENTION_CLEANUP_INTERVAL_SECS: u64 = 60 * 60;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::from_env();

    if let Some(parent) = Path::new(&config.database_path).parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }

    let repo = Arc::new(SqliteRepository::open(&config.database_path)?);
    let observation = Arc::new(ObservationService::new(
        repo,
        config.flow_retention_hours,
        config.aggregate_retention_days,
    ));

    let _retention_task = tokio::spawn(run_retention_cleanup_loop(Arc::clone(&observation)));

    let _simulator_task = if config.simulator_enabled {
        let collector: Arc<dyn FlowCollector> = Arc::new(SimulatedCollector::with_interval_secs(
            config.simulator_interval_secs,
        ));

        Some(tokio::spawn(run_collection_loop(
            Arc::clone(&observation),
            collector,
            config.simulator_interval_secs,
        )))
    } else {
        None
    };

    let state = AppState {
        observation,
        dev_bypass_auth: config.dev_bypass_auth,
    };

    let listener = TcpListener::bind(config.listen_addr).await?;
    println!("RouteScope listening on http://{}", config.listen_addr);
    axum::serve(listener, app(state)).await?;
    Ok(())
}

fn app(state: AppState) -> Router {
    Router::new()
        .merge(api::public_routes())
        .merge(api::protected_routes(state.clone()))
        .merge(web::public_routes())
        .merge(web::protected_routes(state.clone()))
        .with_state(state)
}

async fn run_collection_loop(
    observation: Arc<ObservationService>,
    collector: Arc<dyn FlowCollector>,
    interval_secs: u64,
) {
    let mut ticker = time::interval(Duration::from_secs(interval_secs.max(1)));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;

        let flows = collector.collect();
        if let Err(error) = observation.ingest_flows(&flows) {
            eprintln!(
                "collector {} failed to ingest flows: {error}",
                collector.source_name()
            );
        }
    }
}

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
        http::{Request, StatusCode},
    };
    use storage::RouteScopeRepository;
    use tower::ServiceExt;

    fn test_app(dev_bypass_auth: bool) -> Router {
        let repo = Arc::new(SqliteRepository::open_in_memory().unwrap());
        let observation = Arc::new(ObservationService::new(repo, 24, 30));
        app(AppState {
            observation,
            dev_bypass_auth,
        })
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
    async fn protected_api_is_unavailable_until_auth_is_implemented() {
        let response = test_app(false)
            .oneshot(
                Request::builder()
                    .uri("/api/v1/devices")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
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
    async fn list_devices_returns_seeded_data_when_auth_bypassed() {
        let repo = Arc::new(SqliteRepository::open_in_memory().unwrap());
        repo.upsert_device(&crate::domain::Device {
            mac_address: "aa:bb:cc:dd:ee:ff".into(),
            display_name: Some("laptop".into()),
            current_ip: Some("192.168.1.10".into()),
        })
        .unwrap();

        let observation = Arc::new(ObservationService::new(repo, 24, 30));
        let response = app(AppState {
            observation,
            dev_bypass_auth: true,
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
