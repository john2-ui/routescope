//! Application use cases.
//!
//! TODO: Wire collectors and the repository into these services.

use crate::domain::{Device, Flow};

#[derive(Default)]
pub struct ObservationService;

impl ObservationService {
    pub fn devices(&self) -> Vec<Device> {
        // TODO: Query the device repository.
        Vec::new()
    }

    pub fn device(&self, _mac_address: &str) -> Option<Device> {
        // TODO: Query a device by its stable MAC address.
        None
    }

    pub fn recent_flows(&self, _mac_address: &str) -> Vec<Flow> {
        // TODO: Return the 24-hour flow-detail window.
        Vec::new()
    }
}
