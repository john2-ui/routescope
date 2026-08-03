//! Management authentication boundary.
//!
//! TODO: Implement local account storage, password hashing, sessions, CSRF protection,
//! and rate limiting before exposing the management interface beyond localhost.

use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};

pub async fn require_admin(_request: Request<Body>, _next: Next) -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        "Authentication is not implemented yet. Management routes are disabled.",
    )
        .into_response()
}

use axum::response::IntoResponse;
