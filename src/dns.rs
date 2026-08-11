use crate::domain::{DomainAttribution, DomainConfidence, DomainSource, Flow};
use std::{collections::HashMap, net::Ipv4Addr, sync::Mutex};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsObservation {
    pub client_ip: Ipv4Addr,
    pub domain: String,
    pub target_ips: Vec<Ipv4Addr>,
    pub observed_at_ms: i64,
    pub ttl_secs: u32,
}

/// DNS observation source boundary. A proxy can implement this by draining
/// observations collected from DNS responses.
pub trait DnsObservationSource: Send + Sync {
    fn source_name(&self) -> &'static str;
    fn collect(&self) -> Result<Vec<DnsObservation>, String>;
}

#[derive(Debug, Default)]
pub struct DnsObservationQueue {
    pending: Mutex<Vec<DnsObservation>>,
}

impl DnsObservationQueue {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&self, observation: DnsObservation) {
        self.pending
            .lock()
            .expect("DNS observation queue mutex poisoned")
            .push(observation);
    }
}

impl DnsObservationSource for DnsObservationQueue {
    fn source_name(&self) -> &'static str {
        "dns-proxy"
    }

    fn collect(&self) -> Result<Vec<DnsObservation>, String> {
        let mut pending = self
            .pending
            .lock()
            .expect("DNS observation queue mutex poisoned");
        Ok(std::mem::take(&mut *pending))
    }
}

#[derive(Debug, Clone)]
struct DomainBinding {
    domain: String,
    associated_at: i64,
    expires_at: i64,
}

#[derive(Debug, Default)]
pub struct DnsAttributionCache {
    bindings: Mutex<HashMap<(Ipv4Addr, Ipv4Addr), Vec<DomainBinding>>>,
}

impl DnsAttributionCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn collect_from(&self, source: &dyn DnsObservationSource) -> Result<usize, String> {
        let observed = source
            .collect()?
            .into_iter()
            .map(|observation| self.observe(observation))
            .sum();
        Ok(observed)
    }

    pub fn observe(&self, observation: DnsObservation) -> usize {
        let Some(domain) = normalize_domain(&observation.domain) else {
            return 0;
        };

        let expires_at = observation
            .observed_at_ms
            .saturating_add(i64::from(observation.ttl_secs).saturating_mul(1_000));

        if expires_at <= observation.observed_at_ms {
            return 0;
        }

        let mut bindings = self
            .bindings
            .lock()
            .expect("DNS attribution cache mutex poisoned");

        let mut updated = 0;

        for target_ip in observation.target_ips {
            let entries = bindings
                .entry((observation.client_ip, target_ip))
                .or_default();

            entries.retain(|entry| entry.expires_at > observation.observed_at_ms);

            if let Some(entry) = entries.iter_mut().find(|entry| entry.domain == domain) {
                if observation.observed_at_ms >= entry.associated_at {
                    entry.associated_at = observation.observed_at_ms;
                    entry.expires_at = expires_at;
                    updated += 1;
                }
            } else {
                entries.push(DomainBinding {
                    domain: domain.clone(),
                    associated_at: observation.observed_at_ms,
                    expires_at,
                });
                updated += 1;
            }
        }

        updated
    }

    pub fn attribute_flows(&self, flows: &mut [Flow]) -> usize {
        flows
            .iter_mut()
            .filter_map(|flow| self.attribute_flow(flow).then_some(()))
            .count()
    }

    pub fn attribute_flow(&self, flow: &mut Flow) -> bool {
        let Ok(client_ip) = flow.client_ip.parse::<Ipv4Addr>() else {
            return false;
        };
        let Ok(destination_ip) = flow.destination_ip.parse::<Ipv4Addr>() else {
            return false;
        };

        let attribution = {
            let bindings = self
                .bindings
                .lock()
                .expect("DNS attribution cache mutex poisoned");
            let Some(entries) = bindings.get(&(client_ip, destination_ip)) else {
                return false;
            };

            let matches = entries
                .iter()
                .filter(|entry| {
                    entry.associated_at <= flow.last_seen && flow.first_seen < entry.expires_at
                })
                .collect::<Vec<_>>();

            if matches.len() != 1 {
                return false;
            }

            let entry = matches[0];

            Some(DomainAttribution {
                domain: entry.domain.clone(),
                source: DomainSource::Dns,
                associated_at: entry.associated_at,
                confidence: DomainConfidence::High,
                expires_at: Some(entry.expires_at),
            })
        };

        if let Some(attribution) = attribution {
            // DNS 精确命中优先于已有的低置信度 SNI
            flow.domain = Some(attribution);
            true
        } else {
            false
        }
    }

    pub fn purge_expired(&self, now_ms: i64) -> usize {
        let mut bindings = self
            .bindings
            .lock()
            .expect("DNS attribution cache mutex poisoned");

        let before = bindings.values().map(Vec::len).sum::<usize>();

        bindings.retain(|_, entries| {
            entries.retain(|entry| entry.expires_at > now_ms);
            !entries.is_empty()
        });

        let after = bindings.values().map(Vec::len).sum::<usize>();
        before.saturating_sub(after)
    }
}

fn normalize_domain(value: &str) -> Option<String> {
    let domain = value.trim().trim_end_matches('.').to_ascii_lowercase();

    if domain.is_empty()
        || domain.len() > 253
        || domain
            .split('.')
            .any(|label| label.is_empty() || label.len() > 63)
    {
        return None;
    }

    Some(domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{ConnectionState, FlowDirection};

    fn sample_flow(
        flow_id: &str,
        first_seen: i64,
        last_seen: i64,
        client_ip: &str,
        destination_ip: &str,
    ) -> Flow {
        Flow {
            flow_id: flow_id.to_owned(),
            first_seen,
            last_seen,
            protocol: "tcp".to_owned(),
            direction: FlowDirection::Bidirectional,
            lan_interface: "br-lan".to_owned(),
            wan_interface: "eth0".to_owned(),
            client_mac: "aa:bb:cc:dd:ee:ff".to_owned(),
            client_ip: client_ip.to_owned(),
            client_port: 40_000,
            destination_ip: destination_ip.to_owned(),
            destination_port: 443,
            nat_source_ip: None,
            nat_source_port: None,
            nat_destination_ip: None,
            nat_destination_port: None,
            upload_bytes: 1_024,
            download_bytes: 2_048,
            packet_count: 10,
            domain: None,
            connection_state: ConnectionState::Established,
        }
    }

    fn observation(domain: &str, observed_at_ms: i64, ttl_secs: u32) -> DnsObservation {
        DnsObservation {
            client_ip: "192.168.1.10".parse().unwrap(),
            domain: domain.to_owned(),
            target_ips: vec!["93.184.216.34".parse().unwrap()],
            observed_at_ms,
            ttl_secs,
        }
    }

    struct FixedDnsSource {
        observations: Vec<DnsObservation>,
    }

    impl DnsObservationSource for FixedDnsSource {
        fn source_name(&self) -> &'static str {
            "fixed-test-dns"
        }

        fn collect(&self) -> Result<Vec<DnsObservation>, String> {
            Ok(self.observations.clone())
        }
    }

    #[test]
    fn collect_from_ingests_observations_from_source() {
        let cache = DnsAttributionCache::new();
        let source = FixedDnsSource {
            observations: vec![observation("example.com", 1_000, 60)],
        };

        assert_eq!(source.source_name(), "fixed-test-dns");
        assert_eq!(cache.collect_from(&source).unwrap(), 1);

        let mut flow = sample_flow("flow-source", 2_000, 3_000, "192.168.1.10", "93.184.216.34");
        assert!(cache.attribute_flow(&mut flow));
    }

    #[test]
    fn observation_queue_drains_each_batch_once() {
        let queue = DnsObservationQueue::new();
        queue.push(observation("example.com", 1_000, 60));

        let first = queue.collect().unwrap();
        let second = queue.collect().unwrap();

        assert_eq!(first.len(), 1);
        assert!(second.is_empty());
        assert_eq!(queue.source_name(), "dns-proxy");
    }

    #[test]
    fn exact_client_and_target_match_adds_high_confidence_dns_attribution() {
        let cache = DnsAttributionCache::new();
        assert_eq!(cache.observe(observation("Example.COM.", 1_000, 60)), 1);

        let mut flow = sample_flow("flow-1", 2_000, 3_000, "192.168.1.10", "93.184.216.34");

        assert!(cache.attribute_flow(&mut flow));
        assert_eq!(
            flow.domain,
            Some(DomainAttribution {
                domain: "example.com".to_owned(),
                source: DomainSource::Dns,
                confidence: DomainConfidence::High,
                associated_at: 1_000,
                expires_at: Some(61_000),
            })
        );
    }

    #[test]
    fn attribute_flows_returns_number_of_successful_matches() {
        let cache = DnsAttributionCache::new();
        cache.observe(observation("example.com", 1_000, 60));

        let mut flows = vec![
            sample_flow("flow-match", 2_000, 3_000, "192.168.1.10", "93.184.216.34"),
            sample_flow("flow-miss", 2_000, 3_000, "192.168.1.11", "93.184.216.34"),
        ];

        assert_eq!(cache.attribute_flows(&mut flows), 1);
        assert!(flows[0].domain.is_some());
        assert!(flows[1].domain.is_none());
    }

    #[test]
    fn expired_binding_is_not_used() {
        let cache = DnsAttributionCache::new();
        cache.observe(observation("example.com", 1_000, 1));

        let mut flow = sample_flow(
            "flow-expired",
            2_000,
            2_500,
            "192.168.1.10",
            "93.184.216.34",
        );

        assert!(!cache.attribute_flow(&mut flow));
        assert!(flow.domain.is_none());
    }

    #[test]
    fn ambiguous_shared_ip_is_left_unattributed() {
        let cache = DnsAttributionCache::new();
        cache.observe(observation("first.example", 1_000, 60));
        cache.observe(observation("second.example", 1_000, 60));

        let mut flow = sample_flow(
            "flow-ambiguous",
            2_000,
            3_000,
            "192.168.1.10",
            "93.184.216.34",
        );

        assert!(!cache.attribute_flow(&mut flow));
        assert!(flow.domain.is_none());
    }

    #[test]
    fn dns_attribution_replaces_existing_low_confidence_sni() {
        let cache = DnsAttributionCache::new();
        cache.observe(observation("example.com", 1_000, 60));

        let mut flow = sample_flow("flow-sni", 2_000, 3_000, "192.168.1.10", "93.184.216.34");
        flow.domain = Some(DomainAttribution {
            domain: "unknown-cdn.example".to_owned(),
            source: DomainSource::Sni,
            confidence: DomainConfidence::Low,
            associated_at: 2_000,
            expires_at: None,
        });

        assert!(cache.attribute_flow(&mut flow));
        assert_eq!(flow.domain.as_ref().unwrap().domain, "example.com");
        assert_eq!(
            flow.domain.as_ref().unwrap().confidence,
            DomainConfidence::High
        );
    }

    #[test]
    fn purge_expired_removes_only_expired_bindings() {
        let cache = DnsAttributionCache::new();
        let mut expired_observation = observation("expired.example", 1_000, 1);
        expired_observation.target_ips = vec!["203.0.113.10".parse().unwrap()];
        cache.observe(expired_observation);
        cache.observe(observation("active.example", 1_000, 60));

        assert_eq!(cache.purge_expired(2_000), 1);

        let mut expired_flow =
            sample_flow("flow-expired", 1_500, 1_900, "192.168.1.10", "203.0.113.10");
        assert!(!cache.attribute_flow(&mut expired_flow));

        let mut active_flow =
            sample_flow("flow-active", 2_000, 3_000, "192.168.1.10", "93.184.216.34");
        assert!(cache.attribute_flow(&mut active_flow));
        assert_eq!(
            active_flow.domain.as_ref().unwrap().domain,
            "active.example"
        );
    }

    #[test]
    fn invalid_domain_and_zero_ttl_are_ignored() {
        let cache = DnsAttributionCache::new();

        assert_eq!(cache.observe(observation("..", 1_000, 60)), 0);
        assert_eq!(cache.observe(observation("example.com", 1_000, 0)), 0);
    }

    #[test]
    fn domain_names_are_normalized() {
        assert_eq!(
            normalize_domain("  ExAmPle.COM. "),
            Some("example.com".to_owned())
        );
        assert_eq!(normalize_domain("example..com"), None);
        assert_eq!(normalize_domain(""), None);
    }
}
