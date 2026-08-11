use askama::Template;
use axum::{
    Router,
    extract::{ConnectInfo, Extension, Form, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use serde::Deserialize;
use std::{net::SocketAddr, sync::Arc};

use crate::auth;
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
}

#[derive(Template)]
#[template(path = "devices.html")]
struct DevicesTemplate {
    csrf_token: String,
}

#[derive(Template)]
#[template(path = "device_detail.html")]
struct DeviceDetailTemplate {
    csrf_token: String,
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
async fn dashboard(headers: HeaderMap) -> Result<Html<String>, StatusCode> {
    render(DashboardTemplate {
        csrf_token: page_csrf_token(&headers),
    })
}

/// 渲染设备列表页面。
async fn devices(headers: HeaderMap) -> Result<Html<String>, StatusCode> {
    render(DevicesTemplate {
        csrf_token: page_csrf_token(&headers),
    })
}

/// 渲染设备详情页面。
async fn device_detail(headers: HeaderMap) -> Result<Html<String>, StatusCode> {
    render(DeviceDetailTemplate {
        csrf_token: page_csrf_token(&headers),
    })
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
