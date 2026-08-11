use crate::dns::{DnsObservation, DnsObservationQueue};
use hickory_proto::{op::Message, rr::RData};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};

const MAX_DNS_PACKET_SIZE: usize = 65_535;

/// Local DNS forwarder which records IPv4 answers for later Flow attribution.
#[derive(Clone)]
pub struct DnsProxy {
    listen_addr: SocketAddr,
    upstream_addr: SocketAddr,
    query_timeout: Duration,
    observations: Arc<DnsObservationQueue>,
}

pub struct BoundDnsProxy {
    proxy: DnsProxy,
    udp_socket: Arc<UdpSocket>,
    tcp_listener: TcpListener,
}

impl DnsProxy {
    pub fn new(
        listen_addr: SocketAddr,
        upstream_addr: SocketAddr,
        query_timeout: Duration,
        observations: Arc<DnsObservationQueue>,
    ) -> Self {
        Self {
            listen_addr,
            upstream_addr,
            query_timeout,
            observations,
        }
    }

    /// Binds UDP and TCP listeners for the DNS proxy.
    pub async fn bind(self) -> Result<BoundDnsProxy, String> {
        let udp_socket = Arc::new(
            UdpSocket::bind(self.listen_addr)
                .await
                .map_err(|error| format!("bind DNS UDP listener: {error}"))?,
        );
        let tcp_listener = TcpListener::bind(self.listen_addr)
            .await
            .map_err(|error| format!("bind DNS TCP listener: {error}"))?;

        Ok(BoundDnsProxy {
            proxy: self,
            udp_socket,
            tcp_listener,
        })
    }
}

impl BoundDnsProxy {
    pub async fn run(self) -> Result<(), String> {
        let Self {
            proxy,
            udp_socket,
            tcp_listener,
        } = self;

        tokio::try_join!(
            proxy.clone().serve_udp(udp_socket),
            proxy.serve_tcp(tcp_listener)
        )
        .map(|_| ())
    }
}

impl DnsProxy {
    async fn serve_udp(self, socket: Arc<UdpSocket>) -> Result<(), String> {
        loop {
            let mut request = vec![0_u8; MAX_DNS_PACKET_SIZE];
            let (length, peer) = socket
                .recv_from(&mut request)
                .await
                .map_err(|error| format!("receive DNS UDP query: {error}"))?;
            request.truncate(length);

            let proxy = self.clone();
            let socket = Arc::clone(&socket);
            tokio::spawn(async move {
                if let Err(error) = proxy.handle_udp(socket, peer, request).await {
                    eprintln!("DNS UDP request from {peer} failed: {error}");
                }
            });
        }
    }

    async fn handle_udp(
        &self,
        client_socket: Arc<UdpSocket>,
        peer: SocketAddr,
        request: Vec<u8>,
    ) -> Result<(), String> {
        let upstream = UdpSocket::bind(any_addr_for(self.upstream_addr))
            .await
            .map_err(|error| format!("bind DNS upstream socket: {error}"))?;
        upstream
            .connect(self.upstream_addr)
            .await
            .map_err(|error| format!("connect DNS upstream: {error}"))?;
        upstream
            .send(&request)
            .await
            .map_err(|error| format!("send DNS UDP query upstream: {error}"))?;

        let mut response = vec![0_u8; MAX_DNS_PACKET_SIZE];
        let length = timeout(self.query_timeout, upstream.recv(&mut response))
            .await
            .map_err(|_| "DNS UDP upstream query timed out".to_owned())?
            .map_err(|error| format!("receive DNS UDP response upstream: {error}"))?;
        response.truncate(length);

        client_socket
            .send_to(&response, peer)
            .await
            .map_err(|error| format!("send DNS UDP response to client: {error}"))?;

        self.record_observations(peer.ip(), &request, &response);
        Ok(())
    }

    async fn serve_tcp(self, listener: TcpListener) -> Result<(), String> {
        loop {
            let (stream, peer) = listener
                .accept()
                .await
                .map_err(|error| format!("accept DNS TCP client: {error}"))?;

            let proxy = self.clone();
            tokio::spawn(async move {
                if let Err(error) = proxy.handle_tcp(stream, peer).await {
                    eprintln!("DNS TCP client {peer} failed: {error}");
                }
            });
        }
    }

    async fn handle_tcp(&self, mut client: TcpStream, peer: SocketAddr) -> Result<(), String> {
        loop {
            let mut length_bytes = [0_u8; 2];
            match client.read_exact(&mut length_bytes).await {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(error) => return Err(format!("read DNS TCP frame length: {error}")),
            }

            let request_length = usize::from(u16::from_be_bytes(length_bytes));
            if request_length == 0 {
                return Err("DNS TCP query frame must not be empty".to_owned());
            }

            let mut request = vec![0_u8; request_length];
            client
                .read_exact(&mut request)
                .await
                .map_err(|error| format!("read DNS TCP query: {error}"))?;

            let response = timeout(self.query_timeout, self.forward_tcp(&request))
                .await
                .map_err(|_| "DNS TCP upstream query timed out".to_owned())??;

            let response_length = u16::try_from(response.len())
                .map_err(|_| "DNS TCP response exceeds 65535 bytes".to_owned())?;
            client
                .write_u16(response_length)
                .await
                .map_err(|error| format!("write DNS TCP response length: {error}"))?;
            client
                .write_all(&response)
                .await
                .map_err(|error| format!("write DNS TCP response: {error}"))?;

            self.record_observations(peer.ip(), &request, &response);
        }
    }

    async fn forward_tcp(&self, request: &[u8]) -> Result<Vec<u8>, String> {
        let mut upstream = TcpStream::connect(self.upstream_addr)
            .await
            .map_err(|error| format!("connect DNS TCP upstream: {error}"))?;
        let request_length = u16::try_from(request.len())
            .map_err(|_| "DNS TCP query exceeds 65535 bytes".to_owned())?;

        upstream
            .write_u16(request_length)
            .await
            .map_err(|error| format!("write DNS TCP query length upstream: {error}"))?;
        upstream
            .write_all(request)
            .await
            .map_err(|error| format!("write DNS TCP query upstream: {error}"))?;

        let response_length = upstream
            .read_u16()
            .await
            .map_err(|error| format!("read DNS TCP response length upstream: {error}"))?;
        if response_length == 0 {
            return Err("DNS TCP upstream returned an empty response".to_owned());
        }

        let mut response = vec![0_u8; usize::from(response_length)];
        upstream
            .read_exact(&mut response)
            .await
            .map_err(|error| format!("read DNS TCP response upstream: {error}"))?;
        Ok(response)
    }

    fn record_observations(&self, client_ip: IpAddr, request: &[u8], response: &[u8]) {
        for observation in parse_dns_observations(client_ip, request, response, now_ms()) {
            self.observations.push(observation);
        }
    }
}

fn parse_dns_observations(
    client_ip: IpAddr,
    request: &[u8],
    response: &[u8],
    observed_at_ms: i64,
) -> Vec<DnsObservation> {
    let IpAddr::V4(client_ip) = client_ip else {
        return Vec::new();
    };

    let Ok(request) = Message::from_vec(request) else {
        return Vec::new();
    };
    let Ok(response) = Message::from_vec(response) else {
        return Vec::new();
    };
    let Some(query) = request.queries.first() else {
        return Vec::new();
    };

    let mut target_ips = Vec::new();
    let mut ttl_secs = None;

    for record in &response.answers {
        if let RData::A(address) = &record.data {
            if !target_ips.contains(&address.0) {
                target_ips.push(address.0);
            }
            ttl_secs = Some(ttl_secs.map_or(record.ttl, |ttl: u32| ttl.min(record.ttl)));
        }
    }

    let Some(ttl_secs) = ttl_secs.filter(|ttl| *ttl > 0) else {
        return Vec::new();
    };

    vec![DnsObservation {
        client_ip,
        domain: query.name.to_string(),
        target_ips,
        observed_at_ms,
        ttl_secs,
    }]
}

fn any_addr_for(address: SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        SocketAddr::V6(_) => SocketAddr::from(([0; 16], 0)),
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX_EPOCH")
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::DnsObservationSource;
    use hickory_proto::{
        op::{Message, Query},
        rr::{Record, RecordType, domain::Name, rdata::A},
    };
    use std::sync::Arc;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, UdpSocket},
    };

    fn dns_packets() -> (Vec<u8>, Vec<u8>) {
        let query = Query::query(Name::from_ascii("Example.COM.").unwrap(), RecordType::A);
        let mut request = Message::query();
        request.add_query(query);

        let mut response = Message::response(request.metadata.id, request.metadata.op_code);
        response.add_query(request.queries[0].clone());
        response.add_answer(Record::from_rdata(
            Name::from_ascii("Example.COM.").unwrap(),
            60,
            RData::A(A::new(93, 184, 216, 34)),
        ));

        (request.to_vec().unwrap(), response.to_vec().unwrap())
    }

    #[test]
    fn parses_ipv4_answers_into_dns_observations() {
        let (request, response) = dns_packets();
        let observations =
            parse_dns_observations("192.168.1.10".parse().unwrap(), &request, &response, 1_000);

        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].domain, "Example.COM.");
        assert_eq!(observations[0].ttl_secs, 60);
        assert_eq!(
            observations[0].target_ips,
            vec!["93.184.216.34".parse::<std::net::Ipv4Addr>().unwrap()]
        );
    }

    #[test]
    fn ignores_ipv6_clients_and_responses_without_ipv4_answers() {
        let (request, response) = dns_packets();
        assert!(
            parse_dns_observations("::1".parse().unwrap(), &request, &response, 1_000).is_empty()
        );

        let mut no_answer = Message::response(1, request_metadata_op_code(&request));
        no_answer.add_query(Message::from_vec(&request).unwrap().queries[0].clone());
        assert!(
            parse_dns_observations(
                "192.168.1.10".parse().unwrap(),
                &request,
                &no_answer.to_vec().unwrap(),
                1_000
            )
            .is_empty()
        );
    }

    #[tokio::test]
    async fn forwards_udp_query_and_queues_observation() {
        let (request, response) = dns_packets();
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let expected_request = request.clone();
        let expected_response = response.clone();
        let upstream_task = tokio::spawn(async move {
            let mut request_buffer = vec![0_u8; MAX_DNS_PACKET_SIZE];
            let (length, peer) = upstream.recv_from(&mut request_buffer).await.unwrap();
            assert_eq!(&request_buffer[..length], expected_request);
            upstream.send_to(&expected_response, peer).await.unwrap();
        });

        let proxy_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_socket.local_addr().unwrap();
        let queue = Arc::new(DnsObservationQueue::new());
        let proxy = DnsProxy::new(
            "127.0.0.1:5353".parse().unwrap(),
            upstream_addr,
            Duration::from_secs(1),
            Arc::clone(&queue),
        );

        proxy
            .handle_udp(Arc::clone(&proxy_socket), client_addr, request)
            .await
            .unwrap();

        let mut response_buffer = vec![0_u8; MAX_DNS_PACKET_SIZE];
        let (length, peer) = client_socket.recv_from(&mut response_buffer).await.unwrap();
        assert_eq!(peer, proxy_socket.local_addr().unwrap());
        assert_eq!(&response_buffer[..length], response);
        assert_eq!(queue.collect().unwrap().len(), 1);

        upstream_task.await.unwrap();
    }

    #[tokio::test]
    async fn forwards_tcp_query_with_dns_length_prefix() {
        let (request, response) = dns_packets();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = listener.local_addr().unwrap();
        let expected_request = request.clone();
        let expected_response = response.clone();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request_length = stream.read_u16().await.unwrap();
            let mut received = vec![0_u8; usize::from(request_length)];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(received, expected_request);
            stream
                .write_u16(u16::try_from(expected_response.len()).unwrap())
                .await
                .unwrap();
            stream.write_all(&expected_response).await.unwrap();
        });

        let queue = Arc::new(DnsObservationQueue::new());
        let proxy = DnsProxy::new(
            "127.0.0.1:5353".parse().unwrap(),
            upstream_addr,
            Duration::from_secs(1),
            Arc::clone(&queue),
        );

        let forwarded = proxy.forward_tcp(&request).await.unwrap();
        assert_eq!(forwarded, response);
        upstream_task.await.unwrap();
    }

    fn request_metadata_op_code(packet: &[u8]) -> hickory_proto::op::OpCode {
        Message::from_vec(packet).unwrap().metadata.op_code
    }
}
