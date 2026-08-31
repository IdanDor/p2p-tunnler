use std::collections::HashSet;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use anyhow::Context;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, mpsc};

use crate::utils::{TaskMonitor, UDP_QUEUE_CAPACITY, UdpReceiver, UdpSender, spawn, try_send};

pub const MAX_PEER_REFLEXIVE_CANDIDATES: usize = 64;

#[derive(Default)]
pub struct CandidateSet {
    advertised: HashSet<SocketAddr>,
    peer_reflexive: HashSet<SocketAddr>,
}

impl CandidateSet {
    pub fn contains(&self, address: &SocketAddr) -> bool {
        self.advertised.contains(address) || self.peer_reflexive.contains(address)
    }

    pub fn addresses(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.advertised.iter().copied().chain(
            self.peer_reflexive
                .iter()
                .filter(|address| !self.advertised.contains(address))
                .copied(),
        )
    }

    pub fn advertised(&self) -> &HashSet<SocketAddr> {
        &self.advertised
    }

    pub fn replace_advertised(&mut self, addresses: HashSet<SocketAddr>) {
        self.advertised = addresses;
    }

    /// Adds a source which proved knowledge of this connection's current
    /// probe token. These candidates are kept separately so a DHT refresh
    /// does not immediately remove a working peer-reflexive endpoint.
    pub fn add_peer_reflexive(&mut self, address: SocketAddr) -> bool {
        if self.contains(&address) || self.peer_reflexive.len() == MAX_PEER_REFLEXIVE_CANDIDATES {
            return false;
        }
        self.peer_reflexive.insert(address)
    }
}

pub type Connections = Arc<RwLock<CandidateSet>>;
pub type LocalPeer = Arc<RwLock<(UdpSender, Option<SocketAddr>)>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InternetPacketKind {
    Probe,
    Stun,
    Data,
    Drop,
}

pub async fn bind_loopback_and_forward(
    monitor: TaskMonitor,
    parent_log: slog::Logger,
    to_internet: UdpSender,
    local_port: u16,
    remote_peers: Connections,
) -> anyhow::Result<LocalPeer> {
    slog::info!(parent_log, "Setting up new local address"; "local_port" => local_port);

    let socket = UdpSocket::bind(("127.0.0.1", local_port)).await?;
    let local_addr = socket.local_addr()?;
    let log = parent_log.new(slog::o!("direction" => "outbound"));
    let (local_sender, mut local_receiver) =
        crate::utils::split_udp_socket(monitor.clone(), log.clone(), socket);
    let local_peer = Arc::new(RwLock::new((local_sender, None)));
    let local_peer_for_task = local_peer.clone();

    spawn(
        monitor,
        log.clone(),
        "loopback UDP forwarding",
        async move {
            while let Some((packet, wireguard_addr)) = local_receiver.recv().await {
                if local_peer_for_task.read().await.1 != Some(wireguard_addr) {
                    slog::info!(log, "lo_peer_addr changed, it is now..."; "lo_peer_addr" => wireguard_addr);
                    local_peer_for_task.write().await.1 = Some(wireguard_addr);
                }

                let peers = remote_peers.read().await;
                for remote_peer in peers.addresses() {
                    let _ = try_send(&to_internet, (packet.to_vec(), remote_peer))?;
                    slog::debug!(log, "Outbound packet forwarded"; "src" => wireguard_addr, "via_lo" => local_addr, "dst" => remote_peer, "bytes" => packet.len());
                }
            }
            Ok(())
        },
    );

    Ok(local_peer)
}

pub fn split_internet_receiver(
    monitor: TaskMonitor,
    log: slog::Logger,
    mut receiver: UdpReceiver,
    classify: impl Fn(&[u8]) -> InternetPacketKind + Send + 'static,
) -> (UdpReceiver, UdpReceiver, UdpReceiver) {
    let (probe_sender, probe_receiver) = mpsc::channel(UDP_QUEUE_CAPACITY);
    let (stun_sender, stun_receiver) = mpsc::channel(UDP_QUEUE_CAPACITY);
    let (data_sender, data_receiver) = mpsc::channel(UDP_QUEUE_CAPACITY);

    spawn(monitor, log, "internet UDP receive routing", async move {
        while let Some((packet, source)) = receiver.recv().await {
            let source = normalize_ipv4_mapped_source(source);
            let sender = match classify(&packet) {
                InternetPacketKind::Probe => Some(&probe_sender),
                InternetPacketKind::Stun => Some(&stun_sender),
                InternetPacketKind::Data => Some(&data_sender),
                InternetPacketKind::Drop => None,
            };
            if let Some(sender) = sender {
                let _ = try_send(sender, (packet, source))?;
            }
        }
        Ok(())
    });

    (probe_receiver, stun_receiver, data_receiver)
}

/// Dual-stack sockets may report IPv4 senders as IPv4-mapped IPv6 addresses.
/// DHT candidates use ordinary IPv4 `SocketAddr` values, so normalize once at
/// the common receive boundary before matching data or control paths.
fn normalize_ipv4_mapped_source(source: SocketAddr) -> SocketAddr {
    let SocketAddr::V6(source_v6) = source else {
        return source;
    };
    let Some(ipv4) = source_v6.ip().to_ipv4_mapped() else {
        return source;
    };
    SocketAddr::new(IpAddr::V4(ipv4), source_v6.port())
}

pub async fn forward_inbound_traffic(
    log: slog::Logger,
    mut from_internet: UdpReceiver,
    connections: Connections,
    local_peer: LocalPeer,
) -> anyhow::Result<()> {
    while let Some((packet, remote_peer)) = from_internet.recv().await {
        slog::debug!(log, "Received inbound packet"; "src" => remote_peer, "bytes" => packet.len());

        if !connections.read().await.contains(&remote_peer) {
            slog::debug!(log, "Ignoring inbound packet from an unconfigured source"; "src" => remote_peer, "bytes" => packet.len());
            continue;
        }

        let local_peer = local_peer.read().await;
        if let Some(wireguard_addr) = local_peer.1 {
            let _ = try_send(&local_peer.0, (packet.to_vec(), wireguard_addr))?;
            slog::debug!(log, "Forwarded inbound packet"; "remote_addr" => remote_peer, "lo_addr" => wireguard_addr);
        } else {
            slog::debug!(
                log,
                "Local peer address is not yet set, skipping forwading packet"
            );
        }
    }

    Ok(())
}

pub async fn open_internet_socket(
    log: &slog::Logger,
    requested_port: u16,
) -> anyhow::Result<(UdpSocket, u16)> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket
        .set_only_v6(false)
        .context("Enabling dual-stack IPv4/IPv6 UDP support failed")?;
    socket.bind(&socket2::SockAddr::from(SocketAddr::new(
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        requested_port,
    )))?;
    socket.set_nonblocking(true)?;
    let socket = UdpSocket::from_std(socket.into())?;
    let local_addr = socket.local_addr()?;
    slog::info!(log, "Creating device udp socket"; "address" => local_addr);

    Ok((socket, local_addr.port()))
}

#[cfg(test)]
mod tests {
    use super::{
        CandidateSet, InternetPacketKind, MAX_PEER_REFLEXIVE_CANDIDATES,
        normalize_ipv4_mapped_source, open_internet_socket,
    };
    use std::collections::HashSet;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::net::UdpSocket;

    #[test]
    fn dual_stack_internet_socket_receives_ipv4_datagrams() -> anyhow::Result<()> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let log = slog::Logger::root(slog::Discard, slog::o!());
                let (socket, _) = open_internet_socket(&log, 0).await?;
                let destination = SocketAddr::from(([127, 0, 0, 1], socket.local_addr()?.port()));
                let sender = UdpSocket::bind("127.0.0.1:0").await?;
                sender.send_to(b"ipv4", destination).await?;

                let mut buffer = [0; 64];
                let (length, source) =
                    tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut buffer))
                        .await??;
                assert_eq!(&buffer[..length], b"ipv4");
                assert_eq!(source.port(), sender.local_addr()?.port());
                Ok(())
            })
    }

    #[test]
    fn receive_router_gives_control_frames_priority_over_data() {
        let classify = |packet: &[u8]| {
            if packet.starts_with(b"P2PC") {
                if packet.len() == 20 {
                    InternetPacketKind::Probe
                } else {
                    InternetPacketKind::Drop
                }
            } else if packet.len() > 20 && packet[4..12] == 0x2112_A442_0000_0000u64.to_be_bytes() {
                InternetPacketKind::Stun
            } else {
                InternetPacketKind::Data
            }
        };
        let mut probe = [0; 20];
        probe[..4].copy_from_slice(b"P2PC");
        assert_eq!(classify(&probe), InternetPacketKind::Probe);
        assert_eq!(classify(b"P2PC-short"), InternetPacketKind::Drop);
        assert_eq!(classify(b"wireguard"), InternetPacketKind::Data);
    }

    #[test]
    fn normalizes_ipv4_mapped_sources_before_candidate_matching() {
        let mapped: SocketAddr = "[::ffff:192.0.2.10]:12345".parse().unwrap();
        assert_eq!(
            normalize_ipv4_mapped_source(mapped),
            "192.0.2.10:12345".parse().unwrap()
        );
    }

    #[test]
    fn peer_reflexive_candidates_are_bounded() {
        let mut candidates = CandidateSet::default();
        for port in 10_000..(10_000 + MAX_PEER_REFLEXIVE_CANDIDATES as u16) {
            assert!(candidates.add_peer_reflexive(SocketAddr::from(([192, 0, 2, 1], port))));
        }
        assert!(!candidates.add_peer_reflexive(SocketAddr::from(([192, 0, 2, 2], 20_000))));
        assert_eq!(
            candidates.addresses().count(),
            MAX_PEER_REFLEXIVE_CANDIDATES
        );
    }

    #[test]
    fn peer_reflexive_candidates_survive_advertised_candidate_refreshes() {
        let peer_reflexive = SocketAddr::from(([192, 0, 2, 1], 10_000));
        let advertised = SocketAddr::from(([192, 0, 2, 2], 10_001));
        let mut candidates = CandidateSet::default();
        assert!(candidates.add_peer_reflexive(peer_reflexive));
        candidates.replace_advertised(HashSet::from([advertised]));

        assert!(candidates.contains(&peer_reflexive));
        assert!(candidates.contains(&advertised));
    }
}
