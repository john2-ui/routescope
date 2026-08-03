use axum::{Json, Router, extract::Path, middleware, response::IntoResponse, routing::get};
use serde::Serialize;

use crate::auth;

#[derive(Serialize)]
struct TodoResponse {
    status: &'static str,
    message: &'static str,
}

pub fn public_routes() -> Router {
    Router::new().route("/healthz", get(health_check))
}

pub fn protected_routes() -> Router {
    Router::new()
        .route("/api/v1/devices", get(list_devices))
        .route("/api/v1/devices/{mac_address}", get(device_detail))
        .route("/api/v1/devices/{mac_address}/traffic", get(device_traffic))
        .route("/api/v1/devices/{mac_address}/flows", get(device_flows))
        .route("/api/v1/devices/{mac_address}/domains", get(device_domains))
        .route_layer(middleware::from_fn(auth::require_admin))
}

async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn list_devices() -> Json<TodoResponse> {
    todo_response("Device discovery and statistics are not implemented.")
}

async fn device_detail(Path(_mac_address): Path<String>) -> Json<TodoResponse> {
    todo_response("Device detail lookup is not implemented.")
}

async fn device_traffic(Path(_mac_address): Path<String>) -> Json<TodoResponse> {
    todo_response("Minute traffic aggregation is not implemented.")
}

async fn device_flows(Path(_mac_address): Path<String>) -> Json<TodoResponse> {
    todo_response("Flow collection and retention are not implemented.")
}

async fn device_domains(Path(_mac_address): Path<String>) -> Json<TodoResponse> {
    todo_response("DNS and SNI domain attribution are not implemented.")
}

fn todo_response(message: &'static str) -> Json<TodoResponse> {
    Json(TodoResponse {
        status: "todo",
        message,
    })
}
