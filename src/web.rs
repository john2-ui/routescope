use askama::Template;
use axum::{
    Router,
    extract::{ConnectInfo, Extension, Form, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde::Deserialize;
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::auth;
use crate::domain::{Device, DeviceMinuteStat, DomainTrafficSummary, Flow, normalize_display_name};
use crate::state::AppState;

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate {
    csrf_token: String,
    error: String,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate {
    csrf_token: String,
    collector_status: String,
    device_count: usize,
    total_upload: String,
    total_download: String,
    active_flow_count: usize,
    devices: Vec<DeviceRow>,
}

#[derive(Template)]
#[template(path = "devices.html")]
struct DevicesTemplate {
    csrf_token: String,
    devices: Vec<DeviceRow>,
}

#[derive(Template)]
#[template(path = "device_detail.html")]
struct DeviceDetailTemplate {
    csrf_token: String,
    device: DeviceRow,
    collector_status: String,
    traffic: Vec<TrafficRow>,
    domains: Vec<DomainRow>,
    flows: Vec<FlowRow>,
}

#[derive(Clone)]
struct DeviceRow {
    mac_address: String,
    display_name: String,
    raw_name: String,
    current_ip: String,
    upload_total: u64,
    download_total: u64,
    upload_bytes: String,
    download_bytes: String,
    total_bytes: String,
    flow_count: usize,
    last_seen: String,
    top_domain: String,
    top_domain_meta: String,
}

struct TrafficRow {
    minute: String,
    upload_bytes: String,
    download_bytes: String,
    total_bytes: String,
    bar_width: u8,
}

struct DomainRow {
    domain: String,
    upload_bytes: String,
    download_bytes: String,
    total_bytes: String,
    source: String,
    confidence: String,
}

struct FlowRow {
    last_seen: String,
    protocol: String,
    client_endpoint: String,
    destination_endpoint: String,
    nat_mapping: String,
    upload_bytes: String,
    download_bytes: String,
    packet_count: String,
    domain: String,
    source: String,
    confidence: String,
    connection_state: String,
}

/// 注册公开 Web 路由：登录、登出与静态样式。
pub fn public_routes() -> Router<AppState> {
    Router::new()
        .route("/login", get(login_page).post(login))
        .route("/logout", post(logout))
        .route("/static/app.css", get(stylesheet))
}

/// 注册需鉴权的管理页路由：仪表盘、设备列表与详情。
pub fn protected_routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/", get(dashboard))
        .route("/devices", get(devices))
        .route("/devices/{mac_address}", get(device_detail))
        .route("/devices/{mac_address}/name", post(update_device_name))
        .route_layer(middleware::from_fn_with_state(state, auth::require_admin))
}

/// 渲染登录页。
async fn login_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    let csrf_token = auth::cookie_value(&headers, auth::CSRF_COOKIE_NAME)
        .unwrap_or_else(auth::generate_csrf_token);
    render_login(&state, csrf_token, String::new(), StatusCode::OK)
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    csrf_token: String,
}

/// 校验 CSRF 后创建本地管理员会话。
async fn login(
    State(state): State<AppState>,
    remote: Option<Extension<ConnectInfo<SocketAddr>>>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let csrf_cookie = auth::cookie_value(&headers, auth::CSRF_COOKIE_NAME);
    if csrf_cookie.as_deref() != Some(form.csrf_token.as_str()) {
        return render_login(
            &state,
            auth::generate_csrf_token(),
            "登录请求已失效，请刷新页面后重试。".to_owned(),
            StatusCode::FORBIDDEN,
        )
        .unwrap_or_else(internal_error_response);
    }

    if !state.auth.is_configured() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "No local administrator account is configured.",
        )
            .into_response();
    }

    let source = login_source(&headers, remote.map(|extension| extension.0.0));
    if let Some(retry_after) = state.auth.retry_after_secs(&source) {
        let mut response = (
            StatusCode::TOO_MANY_REQUESTS,
            "Too many failed login attempts. Try again later.",
        )
            .into_response();
        response.headers_mut().insert(
            header::RETRY_AFTER,
            HeaderValue::from_str(&retry_after.to_string()).expect("retry-after is numeric"),
        );
        return response;
    }

    let auth_service = Arc::clone(&state.auth);
    let username = form.username;
    let password = form.password;
    let valid =
        tokio::task::spawn_blocking(move || auth_service.verify_credentials(&username, &password))
            .await
            .unwrap_or(false);

    if !valid {
        state.auth.record_login_failure(&source);
        return render_login(
            &state,
            auth::generate_csrf_token(),
            "用户名或密码错误。".to_owned(),
            StatusCode::UNAUTHORIZED,
        )
        .unwrap_or_else(internal_error_response);
    }

    state.auth.record_login_success(&source);
    let session = state.auth.create_session();
    let mut response = Redirect::to("/").into_response();
    auth::append_cookie(
        &mut response,
        auth::SESSION_COOKIE_NAME,
        &session.session_token,
        auth::SESSION_TTL.as_secs() as i64,
        true,
        state.secure_cookies,
    );
    auth::append_cookie(
        &mut response,
        auth::CSRF_COOKIE_NAME,
        &session.csrf_token,
        auth::SESSION_TTL.as_secs() as i64,
        false,
        state.secure_cookies,
    );
    response
}

#[derive(Debug, Default, Deserialize)]
struct CsrfForm {
    csrf_token: Option<String>,
}

/// 校验会话 CSRF 后使当前会话失效。
async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let session_token = auth::cookie_value(&headers, auth::SESSION_COOKIE_NAME);
    if let Some(session_token) = session_token.as_deref() {
        let csrf_token = form
            .csrf_token
            .or_else(|| {
                headers
                    .get("x-csrf-token")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned)
            })
            .unwrap_or_default();
        if !state.auth.is_csrf_valid(session_token, &csrf_token) {
            return (StatusCode::FORBIDDEN, "Invalid CSRF token.").into_response();
        }
        state.auth.invalidate_session(session_token);
    }

    let mut response = Redirect::to("/login").into_response();
    auth::append_cookie(
        &mut response,
        auth::SESSION_COOKIE_NAME,
        "",
        0,
        true,
        state.secure_cookies,
    );
    auth::append_cookie(
        &mut response,
        auth::CSRF_COOKIE_NAME,
        "",
        0,
        false,
        state.secure_cookies,
    );
    response
}

/// 渲染仪表盘页面。
async fn dashboard(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    let devices = build_device_rows(&state.observation)?;
    let (total_upload, total_download, active_flow_count) = summarize_device_rows(&devices);

    let csrf_token = page_csrf_token(&headers);
    render_page(
        &state,
        DashboardTemplate {
            csrf_token: csrf_token.clone(),
            collector_status: state.collector_health.snapshot().state,
            device_count: devices.len(),
            total_upload,
            total_download,
            active_flow_count,
            devices,
        },
        &csrf_token,
    )
}

/// 渲染设备列表页面。
async fn devices(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    let csrf_token = page_csrf_token(&headers);
    render_page(
        &state,
        DevicesTemplate {
            csrf_token: csrf_token.clone(),
            devices: build_device_rows(&state.observation)?,
        },
        &csrf_token,
    )
}

/// 渲染设备详情页面。
async fn device_detail(
    State(state): State<AppState>,
    Path(mac_address): Path<String>,
    headers: HeaderMap,
) -> Result<Response, StatusCode> {
    let device = state
        .observation
        .device(&mac_address)
        .map_err(service_error)?
        .ok_or(StatusCode::NOT_FOUND)?;
    let flows = state
        .observation
        .recent_flows(&mac_address)
        .map_err(service_error)?;
    let traffic = state
        .observation
        .device_traffic(&mac_address)
        .map_err(service_error)?;
    let domains = state
        .observation
        .device_domain_top(&mac_address)
        .map_err(service_error)?;
    let device_row = build_device_row(&state.observation, device)?;

    let csrf_token = page_csrf_token(&headers);
    render_page(
        &state,
        DeviceDetailTemplate {
            csrf_token: csrf_token.clone(),
            device: device_row,
            collector_status: state.collector_health.snapshot().state,
            traffic: build_traffic_rows(traffic),
            domains: domains.into_iter().map(domain_row).collect(),
            flows: flows.into_iter().map(flow_row).collect(),
        },
        &csrf_token,
    )
}

#[derive(Debug, Deserialize)]
struct DeviceNameForm {
    csrf_token: String,
    display_name: String,
}

/// Update a device name from the management page.
async fn update_device_name(
    State(state): State<AppState>,
    Path(mac_address): Path<String>,
    headers: HeaderMap,
    Form(form): Form<DeviceNameForm>,
) -> Response {
    if !auth::csrf_request_is_valid(&state, &headers, &form.csrf_token) {
        return (StatusCode::FORBIDDEN, "Invalid CSRF token.").into_response();
    }

    let display_name = match normalize_display_name(Some(&form.display_name)) {
        Ok(display_name) => display_name,
        Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
    };
    match state
        .observation
        .rename_device(&mac_address, display_name.as_deref())
    {
        Ok(true) => Redirect::to(&format!("/devices/{mac_address}")).into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => {
            eprintln!("device rename failed: {error}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn build_device_rows(
    state: &Arc<crate::service::ObservationService>,
) -> Result<Vec<DeviceRow>, StatusCode> {
    state
        .devices()
        .map_err(service_error)?
        .into_iter()
        .map(|device| build_device_row(state, device))
        .collect()
}

fn build_device_row(
    observation: &crate::service::ObservationService,
    device: Device,
) -> Result<DeviceRow, StatusCode> {
    let flows = observation
        .recent_flows(&device.mac_address)
        .map_err(service_error)?;
    let domains = observation
        .device_domain_top(&device.mac_address)
        .map_err(service_error)?;
    let upload_bytes = flows
        .iter()
        .map(|flow| flow.upload_bytes)
        .fold(0_u64, u64::saturating_add);
    let download_bytes = flows
        .iter()
        .map(|flow| flow.download_bytes)
        .fold(0_u64, u64::saturating_add);
    let last_seen = flows.iter().map(|flow| flow.last_seen).max();
    let (top_domain, top_domain_meta) = domains
        .first()
        .map(|domain| {
            (
                domain.domain.clone(),
                format!(
                    "{} / {}",
                    domain.source.as_str(),
                    domain.confidence.as_str()
                ),
            )
        })
        .unwrap_or_else(|| ("未知".to_owned(), "unknown / unknown".to_owned()));
    let raw_name = device.display_name.clone().unwrap_or_default();

    Ok(DeviceRow {
        mac_address: device.mac_address,
        display_name: if raw_name.is_empty() {
            "未命名设备".to_owned()
        } else {
            raw_name.clone()
        },
        raw_name,
        current_ip: device.current_ip.unwrap_or_else(|| "未知".to_owned()),
        upload_total: upload_bytes,
        download_total: download_bytes,
        upload_bytes: format_bytes(upload_bytes),
        download_bytes: format_bytes(download_bytes),
        total_bytes: format_bytes(upload_bytes.saturating_add(download_bytes)),
        flow_count: flows.len(),
        last_seen: last_seen
            .map(format_timestamp)
            .unwrap_or_else(|| "暂无".to_owned()),
        top_domain,
        top_domain_meta,
    })
}

fn summarize_device_rows(devices: &[DeviceRow]) -> (String, String, usize) {
    let mut total_upload = 0_u64;
    let mut total_download = 0_u64;
    let mut active_flow_count = 0_usize;
    for device in devices {
        total_upload = total_upload.saturating_add(device.upload_total);
        total_download = total_download.saturating_add(device.download_total);
        active_flow_count = active_flow_count.saturating_add(device.flow_count);
    }
    (
        format_bytes(total_upload),
        format_bytes(total_download),
        active_flow_count,
    )
}

fn build_traffic_rows(stats: Vec<DeviceMinuteStat>) -> Vec<TrafficRow> {
    let cutoff = now_ms().saturating_sub(24 * 60 * 60 * 1_000);
    let mut stats = stats
        .into_iter()
        .filter(|stat| stat.minute_ms >= cutoff)
        .collect::<Vec<_>>();
    if stats.len() > 180 {
        stats = stats.split_off(stats.len() - 180);
    }

    let max_total = stats
        .iter()
        .map(|stat| stat.upload_bytes.saturating_add(stat.download_bytes))
        .max()
        .unwrap_or(0);
    stats
        .into_iter()
        .map(|stat| {
            let total = stat.upload_bytes.saturating_add(stat.download_bytes);
            let bar_width = if max_total == 0 {
                0
            } else {
                ((total as f64 / max_total as f64) * 100.0).round() as u8
            };
            TrafficRow {
                minute: format_timestamp(stat.minute_ms),
                upload_bytes: format_bytes(stat.upload_bytes),
                download_bytes: format_bytes(stat.download_bytes),
                total_bytes: format_bytes(total),
                bar_width,
            }
        })
        .collect()
}

fn domain_row(domain: DomainTrafficSummary) -> DomainRow {
    DomainRow {
        domain: domain.domain,
        upload_bytes: format_bytes(domain.upload_bytes),
        download_bytes: format_bytes(domain.download_bytes),
        total_bytes: format_bytes(domain.total_bytes),
        source: domain.source.as_str().to_owned(),
        confidence: domain.confidence.as_str().to_owned(),
    }
}

fn flow_row(flow: Flow) -> FlowRow {
    let nat_mapping = match (
        flow.nat_source_ip.as_deref(),
        flow.nat_source_port,
        flow.nat_destination_ip.as_deref(),
        flow.nat_destination_port,
    ) {
        (Some(source_ip), Some(source_port), Some(destination_ip), Some(destination_port)) => {
            format!("{source_ip}:{source_port} → {destination_ip}:{destination_port}")
        }
        _ => "未关联".to_owned(),
    };
    let (domain, source, confidence) = match flow.domain {
        Some(domain) => (
            domain.domain,
            domain.source.as_str().to_owned(),
            domain.confidence.as_str().to_owned(),
        ),
        None => (
            "未知".to_owned(),
            "unknown".to_owned(),
            "unknown".to_owned(),
        ),
    };
    FlowRow {
        last_seen: format_timestamp(flow.last_seen),
        protocol: flow.protocol,
        client_endpoint: format!("{}:{}", flow.client_ip, flow.client_port),
        destination_endpoint: format!("{}:{}", flow.destination_ip, flow.destination_port),
        nat_mapping,
        upload_bytes: format_bytes(flow.upload_bytes),
        download_bytes: format_bytes(flow.download_bytes),
        packet_count: flow.packet_count.to_string(),
        domain,
        source,
        confidence,
        connection_state: flow.connection_state.as_str().to_owned(),
    }
}

fn format_bytes(value: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = value as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", value as u64, UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn format_timestamp(timestamp_ms: i64) -> String {
    let seconds = timestamp_ms.div_euclid(1_000);
    let millis = timestamp_ms.rem_euclid(1_000);
    format!("{seconds}.{millis:03} UTC")
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn service_error(error: rusqlite::Error) -> StatusCode {
    eprintln!("web data query failed: {error}");
    StatusCode::INTERNAL_SERVER_ERROR
}

/// 返回内嵌的应用 CSS。
async fn stylesheet() -> &'static str {
    include_str!("../static/app.css")
}

/// 将 Askama 模板渲染为 HTML，失败时返回 500。
fn render(template: impl Template) -> Result<Html<String>, StatusCode> {
    template
        .render()
        .map(Html)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn render_page(
    state: &AppState,
    template: impl Template,
    csrf_token: &str,
) -> Result<Response, StatusCode> {
    let html = render(template)?;
    let mut response = html.into_response();
    auth::append_cookie(
        &mut response,
        auth::CSRF_COOKIE_NAME,
        csrf_token,
        auth::SESSION_TTL.as_secs() as i64,
        false,
        state.secure_cookies,
    );
    Ok(response)
}

fn render_login(
    state: &AppState,
    csrf_token: String,
    error: String,
    status: StatusCode,
) -> Result<Response, StatusCode> {
    let csrf_cookie = csrf_token.clone();
    let html = render(LoginTemplate { csrf_token, error })?;
    let mut response = (status, html).into_response();
    auth::append_cookie(
        &mut response,
        auth::CSRF_COOKIE_NAME,
        &csrf_cookie,
        auth::SESSION_TTL.as_secs() as i64,
        false,
        state.secure_cookies,
    );
    Ok(response)
}

fn internal_error_response(_: StatusCode) -> Response {
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

fn page_csrf_token(headers: &HeaderMap) -> String {
    auth::cookie_value(headers, auth::CSRF_COOKIE_NAME).unwrap_or_else(auth::generate_csrf_token)
}

fn login_source(headers: &HeaderMap, remote: Option<SocketAddr>) -> String {
    if let Some(remote) = remote {
        return remote.ip().to_string();
    }

    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
        .unwrap_or("unknown")
        .to_owned()
}
