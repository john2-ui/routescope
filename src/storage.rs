//! Persistence boundaries for SQLite implementation.
//!
//! TODO: Add SQLite migrations, retention cleanup, and implementations.

use crate::domain::{Device, Flow};

pub trait RouteScopeRepository: Send + Sync {
    fn list_devices(&self) -> Vec<Device>;
    fn find_device(&self, mac_address: &str) -> Option<Device>;
    fn list_recent_flows(&self, mac_address: &str) -> Vec<Flow>;
    fn delete_expired_data(&self);
}
