use crate::domain::{DomainAttribution, DomainConfidence, DomainSource, Flow};
use std::{
        collections::{HashMap, HashSet, VecDeque},
        net::Ipv4Addr,
        sync::Mutex,
};

const IDENTITY_MATCH_GRACE_MS: i64 = 5_000;
const IDENTITY_IDLE_RETENTION_MS: i64 = 5 * 60 * 1_000;
const MAX_PENDING_AGE_MS: i64 = 5 * 60 * 1_000;
const MAX_PENDING_OBSERVATIONS: usize = 4_096;

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

#[derive(Debug, Clone)]
struct ClientIdentityInterval {
        client_ip: Ipv4Addr,
        client_mac: String,
        first_seen: i64,
        last_seen: i64,
}

#[derive(Debug, Clone)]
struct PendingDnsObservation {
        client_ip: Ipv4Addr,
        domain: String,
        target_ips: Vec<Ipv4Addr>,
        observed_at_ms: i64,
        binding_expires_at: i64,
        pending_expires_at: i64,
}

#[derive(Debug, Default)]
struct DnsCacheState {
        bindings: HashMap<(String, Ipv4Addr), Vec<DomainBinding>>,
        identities: HashMap<String, ClientIdentityInterval>,
        pending: VecDeque<PendingDnsObservation>,
}

#[derive(Debug, Default)]
pub struct DnsAttributionCache {
        state: Mutex<DnsCacheState>,
}

impl DnsAttributionCache {
        pub fn new() -> Self {
                Self::default()
        }

        pub fn collect_from(
                &self,
                source: &dyn DnsObservationSource,
                now_ms: i64,
        ) -> Result<usize, String> {
                let pending = source
                        .collect()?
                        .into_iter()
                        .filter_map(prepare_observation)
                        .collect::<Vec<_>>();
                if pending.is_empty() {
                        return Ok(0);
                }

                let mut state = self
                        .state
                        .lock()
                        .expect("DNS attribution cache mutex poisoned");
                purge_state(&mut state, now_ms);
                for observation in pending {
                        enqueue_pending(&mut state, observation);
                }
                Ok(resolve_pending(&mut state, now_ms))
        }

        /// Learn time-bounded IP-to-MAC identities from observed flows and retry pending DNS data.
        pub fn learn_flow_identities(&self, flows: &[Flow], now_ms: i64) -> usize {
                let mut state = self
                        .state
                        .lock()
                        .expect("DNS attribution cache mutex poisoned");
                purge_state(&mut state, now_ms);

                let mut learned = 0;
                let identity_cutoff = now_ms.saturating_sub(IDENTITY_IDLE_RETENTION_MS);
                for flow in flows {
                        let Ok(client_ip) = flow.client_ip.parse::<Ipv4Addr>() else {
                                continue;
                        };
                        let Some(client_mac) = normalize_mac(&flow.client_mac) else {
                                continue;
                        };
                        if flow.flow_id.is_empty()
                                || flow.first_seen > flow.last_seen
                                || flow.last_seen < identity_cutoff
                        {
                                continue;
                        }

                        state.identities.insert(
                                flow.flow_id.clone(),
                                ClientIdentityInterval {
                                        client_ip,
                                        client_mac,
                                        first_seen: flow.first_seen,
                                        last_seen: flow.last_seen,
                                },
                        );
                        learned += 1;
                }

                resolve_pending(&mut state, now_ms);
                learned
        }

        #[cfg(test)]
        fn observe(&self, observation: DnsObservation) -> usize {
                let Some(observation) = prepare_observation(observation) else {
                        return 0;
                };
                let now_ms = observation.observed_at_ms;
                let mut state = self
                        .state
                        .lock()
                        .expect("DNS attribution cache mutex poisoned");
                purge_state(&mut state, now_ms);
                enqueue_pending(&mut state, observation);
                resolve_pending(&mut state, now_ms)
        }

        pub fn attribute_flows(&self, flows: &mut [Flow]) -> usize {
                flows.iter_mut()
                        .filter_map(|flow| self.attribute_flow(flow).then_some(()))
                        .count()
        }

        pub fn attribute_flow(&self, flow: &mut Flow) -> bool {
                let Some(client_mac) = normalize_mac(&flow.client_mac) else {
                        return false;
                };
                let Ok(destination_ip) = flow.destination_ip.parse::<Ipv4Addr>() else {
                        return false;
                };

                let attribution = {
                        let state = self
                                .state
                                .lock()
                                .expect("DNS attribution cache mutex poisoned");
                        let Some(entries) = state.bindings.get(&(client_mac, destination_ip))
                        else {
                                return false;
                        };

                        let matches = entries
                                .iter()
                                .filter(|entry| {
                                        entry.associated_at <= flow.last_seen
                                                && flow.first_seen < entry.expires_at
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
                let mut state = self
                        .state
                        .lock()
                        .expect("DNS attribution cache mutex poisoned");
                purge_state(&mut state, now_ms)
        }
}

fn prepare_observation(observation: DnsObservation) -> Option<PendingDnsObservation> {
        let domain = normalize_domain(&observation.domain)?;
        let binding_expires_at = observation
                .observed_at_ms
                .saturating_add(i64::from(observation.ttl_secs).saturating_mul(1_000));
        if binding_expires_at <= observation.observed_at_ms {
                return None;
        }

        let mut target_ips = observation.target_ips;
        target_ips.sort_unstable();
        target_ips.dedup();
        if target_ips.is_empty() {
                return None;
        }

        Some(PendingDnsObservation {
                client_ip: observation.client_ip,
                domain,
                target_ips,
                observed_at_ms: observation.observed_at_ms,
                binding_expires_at,
                pending_expires_at: binding_expires_at.min(observation
                        .observed_at_ms
                        .saturating_add(MAX_PENDING_AGE_MS)),
        })
}

fn enqueue_pending(state: &mut DnsCacheState, observation: PendingDnsObservation) {
        while state.pending.len() >= MAX_PENDING_OBSERVATIONS {
                state.pending.pop_front();
        }
        state.pending.push_back(observation);
}

fn resolve_pending(state: &mut DnsCacheState, now_ms: i64) -> usize {
        let mut pending = std::mem::take(&mut state.pending);
        let mut unresolved = VecDeque::with_capacity(pending.len());
        let mut updated = 0;

        while let Some(observation) = pending.pop_front() {
                if observation.pending_expires_at <= now_ms
                        || observation.binding_expires_at <= now_ms
                {
                        continue;
                }

                let candidates = state
                        .identities
                        .values()
                        .filter(|identity| {
                                identity.client_ip == observation.client_ip
                                        && identity.first_seen <= observation.observed_at_ms
                                        && observation.observed_at_ms
                                                <= identity
                                                        .last_seen
                                                        .saturating_add(IDENTITY_MATCH_GRACE_MS)
                        })
                        .map(|identity| identity.client_mac.clone())
                        .collect::<HashSet<_>>();

                if candidates.len() == 1 {
                        let client_mac = candidates.into_iter().next().expect("one candidate");
                        updated +=
                                add_domain_bindings(&mut state.bindings, &client_mac, &observation);
                } else {
                        unresolved.push_back(observation);
                }
        }

        state.pending = unresolved;
        updated
}

fn add_domain_bindings(
        bindings: &mut HashMap<(String, Ipv4Addr), Vec<DomainBinding>>,
        client_mac: &str,
        observation: &PendingDnsObservation,
) -> usize {
        let mut updated = 0;
        for target_ip in &observation.target_ips {
                let entries = bindings
                        .entry((client_mac.to_owned(), *target_ip))
                        .or_default();
                entries.retain(|entry| entry.expires_at > observation.observed_at_ms);

                if let Some(entry) = entries
                        .iter_mut()
                        .find(|entry| entry.domain == observation.domain)
                {
                        if observation.observed_at_ms >= entry.associated_at {
                                entry.associated_at = observation.observed_at_ms;
                                entry.expires_at = observation.binding_expires_at;
                                updated += 1;
                        }
                } else {
                        entries.push(DomainBinding {
                                domain: observation.domain.clone(),
                                associated_at: observation.observed_at_ms,
                                expires_at: observation.binding_expires_at,
                        });
                        updated += 1;
                }
        }
        updated
}

fn purge_state(state: &mut DnsCacheState, now_ms: i64) -> usize {
        let binding_count = state.bindings.values().map(Vec::len).sum::<usize>();
        let identity_count = state.identities.len();
        let pending_count = state.pending.len();

        state.bindings.retain(|_, entries| {
                entries.retain(|entry| entry.expires_at > now_ms);
                !entries.is_empty()
        });
        let identity_cutoff = now_ms.saturating_sub(IDENTITY_IDLE_RETENTION_MS);
        state.identities
                .retain(|_, identity| identity.last_seen >= identity_cutoff);
        state.pending.retain(|observation| {
                observation.pending_expires_at > now_ms && observation.binding_expires_at > now_ms
        });

        let remaining = state.bindings.values().map(Vec::len).sum::<usize>()
                + state.identities.len()
                + state.pending.len();
        binding_count
                .saturating_add(identity_count)
                .saturating_add(pending_count)
                .saturating_sub(remaining)
}

fn normalize_mac(value: &str) -> Option<String> {
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_ascii_lowercase())
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

        fn learn_identity(
                cache: &DnsAttributionCache,
                flow_id: &str,
                client_ip: &str,
                client_mac: &str,
                first_seen: i64,
                last_seen: i64,
        ) {
                let mut flow = sample_flow(flow_id, first_seen, last_seen, client_ip, "192.0.2.1");
                flow.client_mac = client_mac.to_owned();
                assert_eq!(cache.learn_flow_identities(&[flow], last_seen), 1);
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
                learn_identity(
                        &cache,
                        "dns-flow",
                        "192.168.1.10",
                        "aa:bb:cc:dd:ee:ff",
                        500,
                        1_500,
                );
                let source = FixedDnsSource {
                        observations: vec![observation("example.com", 1_000, 60)],
                };

                assert_eq!(source.source_name(), "fixed-test-dns");
                assert_eq!(cache.collect_from(&source, 1_500).unwrap(), 1);

                let mut flow =
                        sample_flow("flow-source", 2_000, 3_000, "192.168.1.10", "93.184.216.34");
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
                learn_identity(
                        &cache,
                        "dns-flow",
                        "192.168.1.10",
                        "AA:BB:CC:DD:EE:FF",
                        500,
                        1_500,
                );
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
                learn_identity(
                        &cache,
                        "dns-flow",
                        "192.168.1.10",
                        "aa:bb:cc:dd:ee:ff",
                        500,
                        1_500,
                );
                cache.observe(observation("example.com", 1_000, 60));

                let mut flows = vec![
                        sample_flow("flow-match", 2_000, 3_000, "192.168.1.10", "93.184.216.34"),
                        sample_flow("flow-miss", 2_000, 3_000, "192.168.1.11", "93.184.216.34"),
                ];
                flows[1].client_mac = "aa:bb:cc:dd:ee:00".to_owned();

                assert_eq!(cache.attribute_flows(&mut flows), 1);
                assert!(flows[0].domain.is_some());
                assert!(flows[1].domain.is_none());
        }

        #[test]
        fn expired_binding_is_not_used() {
                let cache = DnsAttributionCache::new();
                learn_identity(
                        &cache,
                        "dns-flow",
                        "192.168.1.10",
                        "aa:bb:cc:dd:ee:ff",
                        500,
                        1_500,
                );
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
                learn_identity(
                        &cache,
                        "dns-flow",
                        "192.168.1.10",
                        "aa:bb:cc:dd:ee:ff",
                        500,
                        1_500,
                );
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
                learn_identity(
                        &cache,
                        "dns-flow",
                        "192.168.1.10",
                        "aa:bb:cc:dd:ee:ff",
                        500,
                        1_500,
                );
                cache.observe(observation("example.com", 1_000, 60));

                let mut flow =
                        sample_flow("flow-sni", 2_000, 3_000, "192.168.1.10", "93.184.216.34");
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
                learn_identity(
                        &cache,
                        "dns-flow",
                        "192.168.1.10",
                        "aa:bb:cc:dd:ee:ff",
                        500,
                        1_500,
                );
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

        #[test]
        fn observation_waits_for_identity_and_resolves_when_flow_arrives() {
                let cache = DnsAttributionCache::new();
                assert_eq!(cache.observe(observation("example.com", 1_000, 60)), 0);
                assert_eq!(cache.state.lock().unwrap().pending.len(), 1);

                learn_identity(
                        &cache,
                        "dns-flow",
                        "192.168.1.10",
                        "aa:bb:cc:dd:ee:ff",
                        500,
                        1_500,
                );
                assert!(cache.state.lock().unwrap().pending.is_empty());

                let mut flow =
                        sample_flow("flow-after", 2_000, 3_000, "192.168.1.10", "93.184.216.34");
                assert!(cache.attribute_flow(&mut flow));
                assert_eq!(flow.domain.as_ref().unwrap().domain, "example.com");
        }

        #[test]
        fn identity_match_accepts_only_the_five_second_post_flow_grace() {
                let cache = DnsAttributionCache::new();
                learn_identity(
                        &cache,
                        "dns-flow",
                        "192.168.1.10",
                        "aa:bb:cc:dd:ee:ff",
                        500,
                        1_000,
                );

                assert_eq!(
                        cache.observe(observation("within-grace.example", 6_000, 60)),
                        1
                );
                assert_eq!(
                        cache.observe(observation("outside-grace.example", 6_001, 60)),
                        0
                );
                assert_eq!(cache.state.lock().unwrap().pending.len(), 1);
        }

        #[test]
        fn dhcp_ip_reuse_does_not_leak_binding_to_new_mac() {
                let cache = DnsAttributionCache::new();
                learn_identity(
                        &cache,
                        "old-dns-flow",
                        "192.168.1.10",
                        "aa:bb:cc:dd:ee:01",
                        8_000,
                        10_000,
                );
                assert_eq!(
                        cache.observe(observation("old-owner.example", 9_000, 60)),
                        1
                );

                let mut old_flow =
                        sample_flow("old-owner", 9_500, 11_000, "192.168.1.10", "93.184.216.34");
                old_flow.client_mac = "aa:bb:cc:dd:ee:01".to_owned();
                assert!(cache.attribute_flow(&mut old_flow));

                let mut new_flow =
                        sample_flow("new-owner", 20_000, 21_000, "192.168.1.10", "93.184.216.34");
                new_flow.client_mac = "aa:bb:cc:dd:ee:02".to_owned();
                assert!(!cache.attribute_flow(&mut new_flow));
                assert!(new_flow.domain.is_none());
        }

        #[test]
        fn overlapping_mac_identities_keep_observation_unresolved_until_expiry() {
                let cache = DnsAttributionCache::new();
                learn_identity(
                        &cache,
                        "dns-flow-a",
                        "192.168.1.10",
                        "aa:bb:cc:dd:ee:01",
                        500,
                        1_500,
                );
                learn_identity(
                        &cache,
                        "dns-flow-b",
                        "192.168.1.10",
                        "aa:bb:cc:dd:ee:02",
                        500,
                        1_500,
                );

                assert_eq!(
                        cache.observe(observation("ambiguous.example", 1_000, 60)),
                        0
                );
                assert_eq!(cache.state.lock().unwrap().pending.len(), 1);
                assert_eq!(cache.purge_expired(61_000), 1);
                assert!(cache.state.lock().unwrap().pending.is_empty());
        }

        #[test]
        fn same_target_ip_is_isolated_by_stable_mac_identity() {
                let cache = DnsAttributionCache::new();
                learn_identity(
                        &cache,
                        "dns-flow-a",
                        "192.168.1.10",
                        "aa:bb:cc:dd:ee:01",
                        500,
                        1_500,
                );
                learn_identity(
                        &cache,
                        "dns-flow-b",
                        "192.168.1.11",
                        "aa:bb:cc:dd:ee:02",
                        500,
                        1_500,
                );
                assert_eq!(cache.observe(observation("device-a.example", 1_000, 60)), 1);
                let mut device_b_observation = observation("device-b.example", 1_000, 60);
                device_b_observation.client_ip = "192.168.1.11".parse().unwrap();
                assert_eq!(cache.observe(device_b_observation), 1);

                let mut flow_a =
                        sample_flow("flow-a", 2_000, 3_000, "192.168.1.10", "93.184.216.34");
                flow_a.client_mac = "aa:bb:cc:dd:ee:01".to_owned();
                let mut flow_b =
                        sample_flow("flow-b", 2_000, 3_000, "192.168.1.11", "93.184.216.34");
                flow_b.client_mac = "aa:bb:cc:dd:ee:02".to_owned();

                assert!(cache.attribute_flow(&mut flow_a));
                assert!(cache.attribute_flow(&mut flow_b));
                assert_eq!(flow_a.domain.as_ref().unwrap().domain, "device-a.example");
                assert_eq!(flow_b.domain.as_ref().unwrap().domain, "device-b.example");
        }

        #[test]
        fn pending_observation_queue_is_bounded_and_evicts_oldest() {
                let cache = DnsAttributionCache::new();
                let source = FixedDnsSource {
                        observations: (0..=MAX_PENDING_OBSERVATIONS)
                                .map(|index| observation(&format!("{index}.example"), 1_000, 600))
                                .collect(),
                };
                assert_eq!(cache.collect_from(&source, 1_000).unwrap(), 0);

                let state = cache.state.lock().unwrap();
                assert_eq!(state.pending.len(), MAX_PENDING_OBSERVATIONS);
                assert_eq!(state.pending.front().unwrap().domain, "1.example");
                assert_eq!(state.pending.back().unwrap().domain, "4096.example");
        }

        #[test]
        fn stale_source_observation_is_not_resolved_after_pending_deadline() {
                let cache = DnsAttributionCache::new();
                learn_identity(
                        &cache,
                        "dns-flow",
                        "192.168.1.10",
                        "aa:bb:cc:dd:ee:ff",
                        500,
                        1_500,
                );
                let source = FixedDnsSource {
                        observations: vec![observation("stale.example", 1_000, 600)],
                };

                assert_eq!(cache.collect_from(&source, 301_001).unwrap(), 0);
                assert!(cache.state.lock().unwrap().bindings.is_empty());
        }

        #[test]
        fn unresolved_observation_and_idle_identity_are_cleaned_after_five_minutes() {
                let cache = DnsAttributionCache::new();
                learn_identity(
                        &cache,
                        "unrelated-flow",
                        "192.168.1.11",
                        "aa:bb:cc:dd:ee:02",
                        500,
                        1_500,
                );
                assert_eq!(cache.observe(observation("pending.example", 1_000, 600)), 0);

                assert_eq!(cache.purge_expired(301_501), 2);
                let state = cache.state.lock().unwrap();
                assert!(state.pending.is_empty());
                assert!(state.identities.is_empty());
        }
}
