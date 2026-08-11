use crate::auth::AuthService;
use crate::service::ObservationService;
use std::sync::Arc;

/// Axum 共享应用状态：观测服务、认证服务与开发态鉴权开关。
#[derive(Clone)]
pub struct AppState {
    pub observation: Arc<ObservationService>,
    pub auth: Arc<AuthService>,
    pub dev_bypass_auth: bool,
    pub secure_cookies: bool,
}
