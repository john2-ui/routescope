//! Management authentication boundary.
//!
//! TODO: Implement local account storage, password hashing, sessions, CSRF protection,
//! and rate limiting before exposing the management interface beyond localhost.

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::state::AppState;

/// 管理路由鉴权中间件：开发绕过开启则放行，否则返回 503（鉴权尚未实现）。
pub async fn require_admin(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // TODO: Local wiring bypass; remove once real auth lands.
    if state.dev_bypass_auth {
        return next.run(request).await;
    }

    (
        StatusCode::SERVICE_UNAVAILABLE,
        "Authentication is not implemented yet. Management routes are disabled.",
    )
        .into_response()
}
