 //! Read-only conntrack snapshots and LAN Flow enrichment.

use crate::domain::{ConnectionState, Flow};
use conntrack::{
    Conntrack,
    model::{Flow as KernelFlow, IpProto, IpTuple, TcpState},
};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// A normalized IPv4 TCP/UDP tuple in the LAN client's perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkTuple {
    pub protocol: u8,
    pub source_ip: Ipv4Addr,
    pub source_port: u16,
    pub destination_ip: Ipv4Addr,
    pub destination_port: u16,
}

impl NetworkTuple {
    /// Builds the original client-to-destination tuple represented by a Flow.
    pub fn from_flow(flow: &Flow) -> Option<Self> {
        Some(Self {
            protocol: match flow.protocol.as_str() {
                "tcp" => 6,
                "udp" => 17,
                _ => return None,
            },
            source_ip: flow.client_ip.parse().ok()?,
            source_port: flow.client_port,
            destination_ip: flow.destination_ip.parse().ok()?,
            destination_port: flow.destination_port,
        })
    }
}

/// The translated tuple observed on the WAN side of a conntrack entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatMapping {
    pub source_ip: Ipv4Addr,
    pub source_port: u16,
    pub destination_ip: Ipv4Addr,
    pub destination_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConntrackEntry {
    pub original: NetworkTuple,
    pub reply: NetworkTuple,
    pub state: ConnectionState,
}

impl ConntrackEntry {
    /// Returns the translated client-to-server tuple when the reply differs
    /// from the reverse of the original tuple.
    pub fn nat_mapping(&self) -> Option<NatMapping> {
        let reverse_matches = self.original.source_ip == self.reply.destination_ip
            && self.original.source_port == self.reply.destination_port
            && self.original.destination_ip == self.reply.source_ip
            && self.original.destination_port == self.reply.source_port;

        if reverse_matches {
            return None;
        }

        Some(NatMapping {
            source_ip: self.reply.destination_ip,
            source_port: self.reply.destination_port,
            destination_ip: self.reply.source_ip,
            destination_port: self.reply.source_port,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Association {
    Matched(ConntrackEntry),
    Unmatched,
    Ambiguous,
}

/// An immutable conntrack table snapshot indexed by both original and reply
/// tuples so the caller can match either observation point without guessing.
#[derive(Debug, Clone, Default)]
pub struct ConntrackSnapshot {
    entries: Vec<ConntrackEntry>,
    tuple_index: HashMap<NetworkTuple, Vec<usize>>,
}

impl ConntrackSnapshot {
    pub fn from_entries(entries: Vec<ConntrackEntry>) -> Self {
        let mut tuple_index: HashMap<NetworkTuple, Vec<usize>> = HashMap::new();

        for (index, entry) in entries.iter().enumerate() {
            tuple_index.entry(entry.original).or_default().push(index);
            tuple_index.entry(entry.reply).or_default().push(index);
        }

        Self {
            entries,
            tuple_index,
        }
    }

    /// Finds exactly one conntrack entry for a Flow's normalized tuple.
    pub fn associate(&self, flow: &Flow) -> Association {
        let Some(tuple) = NetworkTuple::from_flow(flow) else {
            return Association::Unmatched;
        };
        let Some(candidate_indices) = self.tuple_index.get(&tuple) else {
            return Association::Unmatched;
        };

        let unique_indices = candidate_indices.iter().copied().collect::<HashSet<_>>();
        if unique_indices.len() != 1 {
            return Association::Ambiguous;
        }

        let index = *unique_indices.iter().next().expect("one candidate exists");
        Association::Matched(self.entries[index].clone())
    }
}

/// Source boundary so production netlink access can be replaced by fixtures.
pub trait ConntrackReader: Send + Sync {
    fn snapshot(&self) -> Result<ConntrackSnapshot, String>;
}

/// A read-only netlink dump of the kernel conntrack table.
#[derive(Debug, Default)]
pub struct NetlinkConntrackReader;

impl ConntrackReader for NetlinkConntrackReader {
    fn snapshot(&self) -> Result<ConntrackSnapshot, String> {
        let connection =
            Conntrack::connect().map_err(|error| format!("connect to conntrack: {error}"))?;
        let flows = connection
            .dump()
            .map_err(|error| format!("dump conntrack table: {error}"))?;

        let entries = flows
            .iter()
            .filter_map(entry_from_kernel_flow)
            .collect::<Vec<_>>();

        Ok(ConntrackSnapshot::from_entries(entries))
    }
}

/// Caches a successful snapshot so the kernel table is not dumped on every
/// high-frequency TC collection tick.
pub struct CachedConntrackReader {
    inner: Arc<dyn ConntrackReader>,
    refresh_interval: Duration,
    cache: Mutex<Option<(Instant, ConntrackSnapshot)>>,
}

impl CachedConntrackReader {
    pub fn new(inner: Arc<dyn ConntrackReader>, refresh_interval: Duration) -> Self {
        Self {
            inner,
            refresh_interval,
            cache: Mutex::new(None),
        }
    }
}

impl ConntrackReader for CachedConntrackReader {
    fn snapshot(&self) -> Result<ConntrackSnapshot, String> {
        let now = Instant::now();
        if let Some((ref refreshed_at, ref snapshot)) =
            *self.cache.lock().expect("conntrack cache mutex poisoned")
            && now.duration_since(*refreshed_at) < self.refresh_interval
        {
            return Ok(snapshot.clone());
        }

        let snapshot = self.inner.snapshot()?;
        *self.cache.lock().expect("conntrack cache mutex poisoned") = Some((now, snapshot.clone()));
        Ok(snapshot)
    }
}

fn entry_from_kernel_flow(flow: &KernelFlow) -> Option<ConntrackEntry> {
    Some(ConntrackEntry {
        original: tuple_from_kernel(flow.origin.as_ref())?,
        reply: tuple_from_kernel(flow.reply.as_ref())?,
        state: state_from_kernel(flow),
    })
}

fn tuple_from_kernel(tuple: Option<&IpTuple>) -> Option<NetworkTuple> {
    let tuple = tuple?;
    let source_ip = ipv4(tuple.src.as_ref()?)?;
    let destination_ip = ipv4(tuple.dst.as_ref()?)?;
    let proto = tuple.proto.as_ref()?;
    let protocol = match proto.number.as_ref()? {
        IpProto::Tcp => 6,
        IpProto::Udp => 17,
        _ => return None,
    };

    Some(NetworkTuple {
        protocol,
        source_ip,
        source_port: proto.src_port?,
        destination_ip,
        destination_port: proto.dst_port?,
    })
}

fn ipv4(address: &IpAddr) -> Option<Ipv4Addr> {
    match address {
        IpAddr::V4(address) => Some(*address),
        IpAddr::V6(_) => None,
    }
}

fn state_from_kernel(flow: &KernelFlow) -> ConnectionState {
    if let Some(tcp) = flow.proto_info.as_ref().and_then(|info| info.tcp.as_ref())
        && let Some(state) = tcp.state.as_ref()
    {
        return match state {
            TcpState::SynSent | TcpState::SynRecv | TcpState::SynSent2 => ConnectionState::New,
            TcpState::Established => ConnectionState::Established,
            TcpState::FinWait | TcpState::CloseWait | TcpState::LastAck | TcpState::TimeWait => {
                ConnectionState::Closing
            }
            TcpState::Close => ConnectionState::Closed,
            TcpState::None | TcpState::UnrecognizedConst(_) => ConnectionState::Unknown,
        };
    }

    if flow.status.as_ref().is_some_and(|statuses| {
        statuses
            .iter()
            .any(|status| status == "StatusConfirmed" || status == "StatusAssured")
    }) {
        ConnectionState::Established
    } else {
        ConnectionState::New
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{Flow, FlowDirection};

    fn flow() -> Flow {
        Flow {
            flow_id: "tc-flow-1".into(),
            first_seen: 1_000,
            last_seen: 2_000,
            protocol: "tcp".into(),
            direction: FlowDirection::Bidirectional,
            lan_interface: "br-lan".into(),
            wan_interface: "wan0".into(),
            client_mac: "02:00:00:00:00:0a".into(),
            client_ip: "10.0.0.10".into(),
            client_port: 40_000,
            destination_ip: "10.0.2.2".into(),
            destination_port: 8080,
            nat_source_ip: None,
            nat_source_port: None,
            nat_destination_ip: None,
            nat_destination_port: None,
            upload_bytes: 100,
            download_bytes: 200,
            packet_count: 4,
            domain: None,
            connection_state: ConnectionState::Unknown,
        }
    }

    fn entry(source_port: u16, translated_port: u16) -> ConntrackEntry {
        ConntrackEntry {
            original: NetworkTuple {
                protocol: 6,
                source_ip: "10.0.0.10".parse().unwrap(),
                source_port,
                destination_ip: "10.0.2.2".parse().unwrap(),
                destination_port: 8080,
            },
            reply: NetworkTuple {
                protocol: 6,
                source_ip: "10.0.2.2".parse().unwrap(),
                source_port: 8080,
                destination_ip: "10.0.2.1".parse().unwrap(),
                destination_port: translated_port,
            },
            state: ConnectionState::Established,
        }
    }

    #[test]
    fn associates_snat_entry_by_original_tuple() {
        let snapshot = ConntrackSnapshot::from_entries(vec![entry(40_000, 50_000)]);
        let association = snapshot.associate(&flow());

        let Association::Matched(entry) = association else {
            panic!("expected a conntrack match");
        };
        assert_eq!(
            entry.nat_mapping(),
            Some(NatMapping {
                source_ip: "10.0.2.1".parse().unwrap(),
                source_port: 50_000,
                destination_ip: "10.0.2.2".parse().unwrap(),
                destination_port: 8080,
            })
        );
    }

    #[test]
    fn direct_entry_has_no_nat_mapping() {
        let mut direct = entry(40_000, 40_000);
        direct.reply.destination_ip = direct.original.source_ip;
        let snapshot = ConntrackSnapshot::from_entries(vec![direct.clone()]);

        assert_eq!(direct.nat_mapping(), None);
        assert!(matches!(
            snapshot.associate(&flow()),
            Association::Matched(_)
        ));
    }

    #[test]
    fn unmatched_tuple_does_not_guess_nat() {
        let mut other = flow();
        other.client_port = 40_001;
        let snapshot = ConntrackSnapshot::from_entries(vec![entry(40_000, 50_000)]);

        assert_eq!(snapshot.associate(&other), Association::Unmatched);
    }

    #[test]
    fn multiple_entries_for_same_tuple_are_ambiguous() {
        let snapshot =
            ConntrackSnapshot::from_entries(vec![entry(40_000, 50_000), entry(40_000, 50_001)]);

        assert_eq!(snapshot.associate(&flow()), Association::Ambiguous);
    }

    #[test]
    fn reply_tuple_is_indexed_without_changing_original_mapping() {
        let entry = entry(40_000, 50_000);
        let mut reply_flow = flow();
        reply_flow.client_ip = "10.0.2.2".into();
        reply_flow.client_port = 8080;
        reply_flow.destination_ip = "10.0.2.1".into();
        reply_flow.destination_port = 50_000;
        let snapshot = ConntrackSnapshot::from_entries(vec![entry]);

        assert!(matches!(
            snapshot.associate(&reply_flow),
            Association::Matched(_)
        ));
    }
}
