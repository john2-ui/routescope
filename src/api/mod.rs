use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    middleware,
    response::IntoResponse,
    routing::get,
};

use crate::auth;
use crate::domain::{Device, DeviceMinuteStat, DomainTrafficSummary, Flow};
use crate::state::AppState;

/// 注册公开 API 路由（健康检查）。
pub fn public_routes() -> Router<AppState> {
    Router::new().route("/healthz", get(health_check))
}

/// 注册需鉴权的设备/流量/域名 JSON API。
pub fn protected_routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/api/v1/devices", get(list_devices))
        .route("/api/v1/devices/{mac_address}", get(device_detail))
        .route("/api/v1/devices/{mac_address}/traffic", get(device_traffic))
        .route("/api/v1/devices/{mac_address}/flows", get(device_flows))
        .route("/api/v1/devices/{mac_address}/domains", get(device_domains))
        .route_layer(middleware::from_fn_with_state(state, auth::require_admin))
}

/// 健康检查，返回 `{"status":"ok"}`。
async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

/// 返回全部设备列表。
async fn list_devices(State(state): State<AppState>) -> Result<Json<Vec<Device>>, StatusCode> {
    state.observation.devices().map(Json).map_err(|err| {
        eprintln!("error listing failed: {err}");
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

/// 按 MAC 返回单个设备；不存在时 404。
async fn device_detail(
    State(state): State<AppState>,
    Path(mac_address): Path<String>,
) -> Result<Json<Device>, StatusCode> {
    match state.observation.device(&mac_address) {
        Ok(Some(device)) => Ok(Json(device)),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(err) => {
            eprintln!("error finding device: {err}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// 返回某设备的分钟流量序列。
async fn device_traffic(
    State(state): State<AppState>,
    Path(mac_address): Path<String>,
) -> Result<Json<Vec<DeviceMinuteStat>>, StatusCode> {
    require_device(&state, &mac_address)?;
    state
        .observation
        .device_traffic(&mac_address)
        .map(Json)
        .map_err(|err| {
            eprintln!("device_traffic failed: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        })
}

/// 返回某设备的近期 flow/连接列表。
async fn device_flows(
    State(state): State<AppState>,
    Path(mac_address): Path<String>,
) -> Result<Json<Vec<Flow>>, StatusCode> {
    require_device(&state, &mac_address)?;
    state
        .observation
        .recent_flows(&mac_address)
        .map(Json)
        .map_err(|err| {
            eprintln!("device_flows failed: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        })
}

/// 返回某设备的域名流量 Top。
async fn device_domains(
    State(state): State<AppState>,
    Path(mac_address): Path<String>,
) -> Result<Json<Vec<DomainTrafficSummary>>, StatusCode> {
    require_device(&state, &mac_address)?;
    state
        .observation
        .device_domain_top(&mac_address)
        .map(Json)
        .map_err(|err| {
            eprintln!("device_domains failed: {err}");
            StatusCode::INTERNAL_SERVER_ERROR
        })
}

/// 确认设备存在；不存在返回 404，查询失败返回 500。
fn require_device(state: &AppState, mac_address: &str) -> Result<(), StatusCode> {
    match state.observation.device(mac_address) {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(err) => {
            eprintln!("device lookup failed: {err}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
