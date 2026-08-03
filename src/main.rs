mod api;
mod auth;
#[allow(dead_code)]
mod collector;
#[allow(dead_code)]
mod config;
#[allow(dead_code)]
mod domain;
#[allow(dead_code)]
mod service;
#[allow(dead_code)]
mod storage;
mod web;

use axum::Router;
use config::Config;
use std::error::Error;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::from_env();
    let listener = TcpListener::bind(config.listen_addr).await?;

    println!("RouteScope listening on http://{}", config.listen_addr);
    axum::serve(listener, app()).await?;
    Ok(())
}

fn app() -> Router {
    Router::new()
        .merge(api::public_routes())
        .merge(api::protected_routes())
        .merge(web::public_routes())
        .merge(web::protected_routes())
}

#[cfg(test)]
mod tests {
    use super::app;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_check_is_public() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn protected_api_is_unavailable_until_auth_is_implemented() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/devices")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn login_page_is_public() {
        let response = app()
            .oneshot(
                Request::builder()
                    .uri("/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
