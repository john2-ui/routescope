//! Kernel and network data-source boundaries.
//!
//! TODO: Implement the collectors with TC eBPF, conntrack events, and the local DNS proxy.

use crate::domain::Flow;

pub trait FlowCollector: Send + Sync {
    fn source_name(&self) -> &'static str;

    fn collect(&self) -> Vec<Flow> {
        // TODO: Read and normalize data from the underlying source.
        Vec::new()
    }
}

pub struct TcEbpfCollector;

impl FlowCollector for TcEbpfCollector {
    fn source_name(&self) -> &'static str {
        "tc-ebpf"
    }
}

pub struct ConntrackCollector;

impl FlowCollector for ConntrackCollector {
    fn source_name(&self) -> &'static str {
        "conntrack"
    }
}

pub struct DnsAttributionCollector;

impl FlowCollector for DnsAttributionCollector {
    fn source_name(&self) -> &'static str {
        "dns-attribution"
    }
}
