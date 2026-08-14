use axum::{
        Json, Router,
        extract::{Path, Query, State},
        http::{HeaderMap, StatusCode},
        middleware,
        response::IntoResponse,
        routing::{delete, get, post},
};
use serde::Deserialize;

use crate::auth;
use crate::domain::{
        DataDeletionResult, DataTimeRange, Device, DeviceMinuteStat, DomainMinuteStat,
        DomainTrafficSummary, normalize_display_name, normalize_domain_name,
};
use crate::service::{FlowPage, FlowQueryError};
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
                .route("/api/v1/devices/{mac_address}", delete(delete_device_data))
                .route("/api/v1/devices/{mac_address}/traffic", get(device_traffic))
                .route("/api/v1/devices/{mac_address}/flows", get(device_flows))
                .route("/api/v1/devices/{mac_address}/domains", get(device_domains))
                .route(
                        "/api/v1/devices/{mac_address}/domains/{domain}/traffic",
                        get(device_domain_traffic),
                )
                .route(
                        "/api/v1/devices/{mac_address}/domains/{domain}",
                        delete(delete_device_domain_data),
                )
                .route(
                        "/api/v1/domains/{domain}",
                        delete(delete_global_domain_data),
                )
                .route("/api/v1/data", delete(delete_time_range_data))
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
        Query(query): Query<FlowPageQuery>,
) -> Result<Json<FlowPage>, StatusCode> {
        require_device(&state, &mac_address)?;
        state.observation
                .flow_page(
                        &mac_address,
                        query.window.as_deref(),
                        query.limit,
                        query.cursor.as_deref(),
                )
                .map(Json)
                .map_err(flow_query_error)
}

#[derive(Debug, Default, Deserialize)]
struct FlowPageQuery {
        window: Option<String>,
        limit: Option<usize>,
        cursor: Option<String>,
}

fn flow_query_error(error: FlowQueryError) -> StatusCode {
        if error.is_bad_request() {
                StatusCode::BAD_REQUEST
        } else {
                eprintln!("device_flows failed: {error}");
                StatusCode::INTERNAL_SERVER_ERROR
        }
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

/// Hard-delete a device and every persisted observation associated with it.
async fn delete_device_data(
        State(state): State<AppState>,
        Path(mac_address): Path<String>,
        headers: HeaderMap,
) -> Result<Json<DataDeletionResult>, StatusCode> {
        require_csrf(&state, &headers)?;
        match state.observation.delete_device_data(&mac_address) {
                Ok(Some(result)) => {
                        state.dns_cache.purge_device_data(&mac_address);
                        Ok(Json(result))
                }
                Ok(None) => Err(StatusCode::NOT_FOUND),
                Err(error) => {
                        eprintln!("device data deletion failed: {error}");
                        Err(StatusCode::INTERNAL_SERVER_ERROR)
                }
        }
}

/// Remove one canonical domain from a selected device while retaining traffic totals.
async fn delete_device_domain_data(
        State(state): State<AppState>,
        Path((mac_address, domain)): Path<(String, String)>,
        headers: HeaderMap,
) -> Result<Json<DataDeletionResult>, StatusCode> {
        require_csrf(&state, &headers)?;
        require_device(&state, &mac_address)?;
        let domain = normalize_domain_name(&domain).map_err(|_| StatusCode::BAD_REQUEST)?;
        let result = state
                .observation
                .delete_domain_data(Some(&mac_address), &domain)
                .map_err(|error| {
                        eprintln!("device domain deletion failed: {error}");
                        StatusCode::INTERNAL_SERVER_ERROR
                })?;
        state.dns_cache
                .purge_domain_data(Some(&mac_address), &domain);
        Ok(Json(result))
}

/// Remove a canonical domain attribution from every device.
async fn delete_global_domain_data(
        State(state): State<AppState>,
        Path(domain): Path<String>,
        headers: HeaderMap,
) -> Result<Json<DataDeletionResult>, StatusCode> {
        require_csrf(&state, &headers)?;
        let domain = normalize_domain_name(&domain).map_err(|_| StatusCode::BAD_REQUEST)?;
        let result = state
                .observation
                .delete_domain_data(None, &domain)
                .map_err(|error| {
                        eprintln!("global domain deletion failed: {error}");
                        StatusCode::INTERNAL_SERVER_ERROR
                })?;
        state.dns_cache.purge_domain_data(None, &domain);
        Ok(Json(result))
}

#[derive(Debug, Default, Deserialize)]
struct DeleteTimeRangeQuery {
        from_ms: Option<i64>,
        to_ms: Option<i64>,
}

/// Delete Flow rows intersecting a range and minute rows whose key falls inside it.
async fn delete_time_range_data(
        State(state): State<AppState>,
        Query(query): Query<DeleteTimeRangeQuery>,
        headers: HeaderMap,
) -> Result<Json<DataDeletionResult>, StatusCode> {
        require_csrf(&state, &headers)?;
        let range = DataTimeRange::new(query.from_ms, query.to_ms)
                .map_err(|_| StatusCode::BAD_REQUEST)?;
        let result = state
                .observation
                .delete_data_range(range)
                .map_err(|error| {
                        eprintln!("time range deletion failed: {error}");
                        StatusCode::INTERNAL_SERVER_ERROR
                })?;
        state.dns_cache.purge_data_range(range);
        Ok(Json(result))
}

fn require_csrf(state: &AppState, headers: &HeaderMap) -> Result<(), StatusCode> {
        let csrf_token = headers
                .get("x-csrf-token")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
        auth::csrf_request_is_valid(state, headers, csrf_token)
                .then_some(())
                .ok_or(StatusCode::FORBIDDEN)
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
