use axum::{
        Json, Router,
        extract::{Path, State},
        http::{HeaderMap, StatusCode},
        middleware,
        response::IntoResponse,
        routing::{get, post},
};
use serde::Deserialize;

use crate::auth;
use crate::domain::{
        Device, DeviceMinuteStat, DomainMinuteStat, DomainTrafficSummary, Flow,
        normalize_display_name,
};
use crate::state::AppState;

/// 注册公开 API 路由（健康检查）。
pub fn public_routes() -> Router<AppState> {
        Router::new()
                .route("/healthz", get(health_check))
                .route("/readyz", get(readiness_check))
}

/// 注册需鉴权的设备/流量/域名 JSON API。
pub fn protected_routes(state: AppState) -> Router<AppState> {
        Router::new()
                .route("/api/v1/devices", get(list_devices))
                .route("/api/v1/devices/{mac_address}", get(device_detail))
                .route("/api/v1/devices/{mac_address}/traffic", get(device_traffic))
                .route("/api/v1/devices/{mac_address}/flows", get(device_flows))
                .route("/api/v1/devices/{mac_address}/domains", get(device_domains))
                .route(
                        "/api/v1/devices/{mac_address}/domains/{domain}/traffic",
                        get(device_domain_traffic),
                )
                .route(
                        "/api/v1/devices/{mac_address}/name",
                        post(update_device_name),
                )
                .route_layer(middleware::from_fn_with_state(state, auth::require_admin))
}

/// Liveness check; collector failures are reported in the payload, not as a
/// process liveness failure.
async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
        let collector = state.collector_health.snapshot();
        let status = match collector.state.as_str() {
                "unhealthy" | "degraded" => "degraded",
                _ => "ok",
        };
        Json(serde_json::json!({
            "status": status,
            "collector": collector,
        }))
}

/// Readiness check; startup succeeds only after configured sources are bound,
/// while runtime collector failures flip the endpoint to unavailable.
async fn readiness_check(State(state): State<AppState>) -> impl IntoResponse {
        let collector = state.collector_health.snapshot();
        let ready = collector.ready;
        let status = if ready {
                StatusCode::OK
        } else {
                StatusCode::SERVICE_UNAVAILABLE
        };
        (
                status,
                Json(serde_json::json!({
                    "status": if ready { "ready" } else { "starting" },
                    "collector": collector,
                })),
        )
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
        state.observation
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
        state.observation
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
        state.observation
                .device_domain_top(&mac_address)
                .map(Json)
                .map_err(|err| {
                        eprintln!("device_domains failed: {err}");
                        StatusCode::INTERNAL_SERVER_ERROR
                })
}

/// 返回某设备、某域名在聚合保留窗口内的原始分钟流量序列。
async fn device_domain_traffic(
        State(state): State<AppState>,
        Path((mac_address, domain)): Path<(String, String)>,
) -> Result<Json<Vec<DomainMinuteStat>>, StatusCode> {
        require_device(&state, &mac_address)?;
        state.observation
                .domain_traffic(&mac_address, &domain)
                .map(Json)
                .map_err(|err| {
                        eprintln!("device_domain_traffic failed: {err}");
                        StatusCode::INTERNAL_SERVER_ERROR
                })
}

#[derive(Debug, Deserialize)]
struct DeviceNameRequest {
        display_name: Option<String>,
}

/// Update or clear a device's manual display name.
async fn update_device_name(
        State(state): State<AppState>,
        Path(mac_address): Path<String>,
        headers: HeaderMap,
        Json(request): Json<DeviceNameRequest>,
) -> Result<Json<Device>, StatusCode> {
        let csrf_token = headers
                .get("x-csrf-token")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
        if !auth::csrf_request_is_valid(&state, &headers, csrf_token) {
                return Err(StatusCode::FORBIDDEN);
        }

        let display_name = normalize_display_name(request.display_name.as_deref())
                .map_err(|_| StatusCode::BAD_REQUEST)?;
        match state
                .observation
                .rename_device(&mac_address, display_name.as_deref())
        {
                Ok(true) => state
                        .observation
                        .device(&mac_address)
                        .map_err(|error| {
                                eprintln!("device lookup after rename failed: {error}");
                                StatusCode::INTERNAL_SERVER_ERROR
                        })?
                        .map(Json)
                        .ok_or(StatusCode::NOT_FOUND),
                Ok(false) => Err(StatusCode::NOT_FOUND),
                Err(error) => {
                        eprintln!("device rename failed: {error}");
                        Err(StatusCode::INTERNAL_SERVER_ERROR)
                }
        }
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
