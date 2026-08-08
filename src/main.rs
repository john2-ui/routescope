mod api;
mod auth;
#[allow(dead_code)]
mod collector;
mod config;
mod domain;
mod service;
mod state;
mod storage;
mod web;

use axum::Router;
use config::Config;
use service::ObservationService;
use state::AppState;
use std::error::Error;
use std::path::Path;
use std::sync::Arc;
use storage::SqliteRepository;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::from_env();

    if let Some(parent) = Path::new(&config.database_path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let repo = Arc::new(SqliteRepository::open(&config.database_path)?);
    let observation = Arc::new(ObservationService::new(
        repo,
        config.flow_retention_hours,
        config.aggregate_retention_days,
    ));
    let state = AppState {
        observation,
        dev_bypass_auth: config.dev_bypass_auth,
    };

    let listener = TcpListener::bind(config.listen_addr).await?;
    println!("RouteScope listening on http://{}", config.listen_addr);
    axum::serve(listener, app(state)).await?;
    Ok(())
}

fn app(state: AppState) -> Router {
    Router::new()
        .merge(api::public_routes())
        .merge(api::protected_routes(state.clone()))
        .merge(web::public_routes())
        .merge(web::protected_routes(state.clone()))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use storage::RouteScopeRepository;
    use tower::ServiceExt;

    fn test_app(dev_bypass_auth: bool) -> Router {
        let repo = Arc::new(SqliteRepository::open_in_memory().unwrap());
        let observation = Arc::new(ObservationService::new(repo, 24, 30));
        app(AppState {
            observation,
            dev_bypass_auth,
        })
    }

    #[tokio::test]
    async fn health_check_is_public() {
        let response = test_app(false)
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
        let response = test_app(false)
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
        let response = test_app(false)
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

    #[tokio::test]
    async fn list_devices_returns_seeded_data_when_auth_bypassed() {
        let repo = Arc::new(SqliteRepository::open_in_memory().unwrap());
        repo.upsert_device(&crate::domain::Device {
            mac_address: "aa:bb:cc:dd:ee:ff".into(),
            display_name: Some("laptop".into()),
            current_ip: Some("192.168.1.10".into()),
        })
        .unwrap();

        let observation = Arc::new(ObservationService::new(repo, 24, 30));
        let response = app(AppState {
            observation,
            dev_bypass_auth: true,
        })
        .oneshot(
            Request::builder()
                .uri("/api/v1/devices")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
