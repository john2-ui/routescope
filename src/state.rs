use crate::service::ObservationService;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub observation: Arc<ObservationService>,
    pub dev_bypass_auth: bool,
}
