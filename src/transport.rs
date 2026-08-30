use std::collections::HashSet;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use anyhow::Context;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, mpsc};

use crate::utils::{TaskMonitor, UDP_QUEUE_CAPACITY, UdpReceiver, UdpSender, spawn, try_send};

pub type Connections = Arc<RwLock<HashSet<SocketAddr>>>;
pub type LocalPeer = Arc<RwLock<(UdpSender, Option<SocketAddr>)>>;

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
                for remote_peer in peers.iter() {
                    let _ = try_send(&to_internet, (packet.to_vec(), *remote_peer))?;
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
    is_control_packet: impl Fn(&[u8]) -> bool + Send + 'static,
) -> (UdpReceiver, UdpReceiver) {
    let (control_sender, control_receiver) = mpsc::channel(UDP_QUEUE_CAPACITY);
    let (data_sender, data_receiver) = mpsc::channel(UDP_QUEUE_CAPACITY);

    spawn(monitor, log, "internet UDP receive routing", async move {
        while let Some((packet, source)) = receiver.recv().await {
            let sender = if is_control_packet(&packet) {
                &control_sender
            } else {
                &data_sender
            };
            let _ = try_send(sender, (packet, source))?;
        }
        Ok(())
    });

    (control_receiver, data_receiver)
}

pub async fn forward_inbound_traffic(
    log: slog::Logger,
    mut from_internet: UdpReceiver,
    connections: Connections,
    local_peer: LocalPeer,
) -> anyhow::Result<()> {
    while let Some((packet, remote_peer)) = from_internet.recv().await {
        slog::debug!(log, "Received inbound packet"; "src" => remote_peer, "bytes" => packet.len());

        let known_peers = connections.read().await;
        if !known_peers.contains(&remote_peer) {
            drop(known_peers);
            slog::info!(log, "New inbound peer, adding to connections"; "src" => remote_peer);
            connections.write().await.insert(remote_peer);
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
    use super::open_internet_socket;
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
}
