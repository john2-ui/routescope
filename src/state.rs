use crate::service::ObservationService;
use std::sync::Arc;

/// Axum 共享应用状态：观测服务与开发态鉴权绕过开关。
#[derive(Clone)]
pub struct AppState {
    pub observation: Arc<ObservationService>,
    pub dev_bypass_auth: bool,
}
