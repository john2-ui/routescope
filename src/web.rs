use askama::Template;
use axum::{
    Router,
    http::StatusCode,
    middleware,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};

use crate::auth;
use crate::state::AppState;

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
        .route_layer(middleware::from_fn_with_state(state, auth::require_admin))
}

/// 渲染登录页。
async fn login_page() -> Result<Html<String>, StatusCode> {
    render(LoginTemplate)
}

/// 本地账号登录占位（尚未实现）。
async fn login() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        "TODO: Local account login is not implemented.",
    )
        .into_response()
}

/// 会话登出占位（尚未实现）。
async fn logout() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        "TODO: Session logout is not implemented.",
    )
        .into_response()
}

/// 渲染仪表盘页面。
async fn dashboard() -> Result<Html<String>, StatusCode> {
    render(DashboardTemplate)
}

/// 渲染设备列表页面。
async fn devices() -> Result<Html<String>, StatusCode> {
    render(DevicesTemplate)
}

/// 渲染设备详情页面。
async fn device_detail() -> Result<Html<String>, StatusCode> {
    render(DeviceDetailTemplate)
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
