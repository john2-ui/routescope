use askama::Template;
use axum::{
    Router,
    http::StatusCode,
    middleware,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};

use crate::auth;

#[derive(Template)]
#[template(path = "login.html")]
struct LoginTemplate;

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardTemplate;

#[derive(Template)]
#[template(path = "devices.html")]
struct DevicesTemplate;

#[derive(Template)]
#[template(path = "device_detail.html")]
struct DeviceDetailTemplate;

pub fn public_routes() -> Router {
    Router::new()
        .route("/login", get(login_page).post(login))
        .route("/logout", post(logout))
        .route("/static/app.css", get(stylesheet))
}

pub fn protected_routes() -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/devices", get(devices))
        .route("/devices/{mac_address}", get(device_detail))
        .route_layer(middleware::from_fn(auth::require_admin))
}

async fn login_page() -> Result<Html<String>, StatusCode> {
    render(LoginTemplate)
}

async fn login() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        "TODO: Local account login is not implemented.",
    )
        .into_response()
}

async fn logout() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        "TODO: Session logout is not implemented.",
    )
        .into_response()
}

async fn dashboard() -> Result<Html<String>, StatusCode> {
    render(DashboardTemplate)
}

async fn devices() -> Result<Html<String>, StatusCode> {
    render(DevicesTemplate)
}

async fn device_detail() -> Result<Html<String>, StatusCode> {
    render(DeviceDetailTemplate)
}

async fn stylesheet() -> &'static str {
    include_str!("../static/app.css")
}

fn render(template: impl Template) -> Result<Html<String>, StatusCode> {
    template
        .render()
        .map(Html)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}
