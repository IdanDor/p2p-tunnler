use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{Context, anyhow, bail};
use futures::future::join_all;

use crate::candidates::{
    StunSetup, listen_for_peer_candidates, publish_candidates, start_stun_candidates,
};
use crate::config::{ConnectionFlags, P2PConnection, Peer, RunCommand, StunFlags};
use crate::crypto::{PublicKey, SecretKey};
use crate::dht::OpenDht;
use crate::probe::{self, ProbeController};
use crate::stun::codec::MAGIC_COOKIE;
use crate::transport::{
    Connections, InternetPacketKind, bind_loopback_and_forward, forward_inbound_traffic,
    open_internet_socket, split_internet_receiver,
};
use crate::utils::{TaskMonitor, spawn};

pub async fn start_dht(
    log: &slog::Logger,
    monitor: TaskMonitor,
    flags: &crate::config::DhtFlags,
) -> anyhow::Result<OpenDht> {
    OpenDht::new(
        monitor,
        log.new(slog::o!("task" => "dht")),
        flags.opendht_port,
        flags.bootstrap_addr.clone(),
    )
    .await
    .context("Initializing DHT failed")
}

pub async fn run(log: &slog::Logger, command: &RunCommand) -> anyhow::Result<()> {
    validate_connections(&command.connections)?;
    let peer_count: usize = command
        .connections
        .iter()
        .map(|connection| connection.peers.len())
        .sum();
    if peer_count == 0 {
        bail!("No peers configured");
    }
    if command.connection_flags.out_port != 0 && peer_count > 1 {
        bail!(
            "--out-port supports one peer at a time; use the default ephemeral port or run separate processes"
        );
    }

    let (monitor, mut failures) = TaskMonitor::new();
    let dht = start_dht(log, monitor.clone(), &command.dht_flags).await?;
    let setups = command
        .connections
        .iter()
        .enumerate()
        .map(|(index, connection)| {
            setup_connection(
                monitor.clone(),
                log.new(slog::o!("dev" => index.to_string())),
                dht.clone(),
                &command.stun_flags,
                connection,
                command.connection_flags.clone(),
            )
        });
    join_all(setups)
        .await
        .into_iter()
        .collect::<anyhow::Result<()>>()?;

    failures
        .changed()
        .await
        .context("Task supervision stopped unexpectedly")?;
    let failure =
        failures
            .borrow_and_update()
            .clone()
            .unwrap_or_else(|| crate::utils::TaskFailure {
                task: "unknown task",
                error: "failure notification did not include a reason".to_string(),
            });
    bail!(
        "Background task stopped: {}: {}",
        failure.task,
        failure.error
    )
}

fn validate_connections(connections: &[P2PConnection]) -> anyhow::Result<()> {
    for (connection_index, connection) in connections.iter().enumerate() {
        SecretKey::try_from(connection.secret_key.as_str()).map_err(|error| {
            anyhow!("Failed to parse secret key for connection {connection_index}: {error}")
        })?;
        for (peer_index, peer) in connection.peers.iter().enumerate() {
            parse_peer_key(peer, peer_index)?;
        }
    }
    Ok(())
}

async fn setup_connection(
    monitor: TaskMonitor,
    log: slog::Logger,
    dht: OpenDht,
    stun_flags: &StunFlags,
    config: &P2PConnection,
    connection_flags: ConnectionFlags,
) -> anyhow::Result<()> {
    let secret_key = SecretKey::try_from(config.secret_key.as_str())
        .map_err(|error| anyhow!("Failed to parse own secret key: {error}"))?;

    for (peer_index, peer) in config.peers.iter().enumerate() {
        let remote_key = parse_peer_key(peer, peer_index)?;
        let peer_log = peer
            .name
            .as_ref()
            .map(|name| log.new(slog::o!("peer" => name.clone())))
            .unwrap_or_else(|| log.new(slog::o!("peer" => remote_key.to_string())));

        let (internet_socket, local_port) =
            open_internet_socket(&peer_log, connection_flags.out_port).await?;
        let (to_internet, from_internet) =
            crate::utils::split_udp_socket(monitor.clone(), peer_log.clone(), internet_socket);
        let (from_probes, from_stun, from_peers) =
            split_internet_receiver(monitor.clone(), peer_log.clone(), from_internet, |packet| {
                if probe::classify(packet) {
                    if packet.len() == probe::FRAME_LEN {
                        InternetPacketKind::Probe
                    } else {
                        InternetPacketKind::Drop
                    }
                } else if packet.len() > 20
                    && packet[4..12] == ((MAGIC_COOKIE as u64) << 32).to_be_bytes()
                {
                    InternetPacketKind::Stun
                } else {
                    InternetPacketKind::Data
                }
            });
        let probes = ProbeController::new();

        let nat_mapping = if connection_flags.nat_map {
            request_nat_mapping(&peer_log, local_port).await
        } else {
            None
        };
        let local_candidates = start_stun_candidates(
            monitor.clone(),
            &peer_log,
            stun_flags,
            StunSetup {
                to_internet: to_internet.clone(),
                from_internet: from_stun,
                local_port,
                gather_ipv6: !connection_flags.filter_ipv6,
                nat_mapping,
                run_once: false,
            },
        )
        .await?;

        let connections: Connections = Arc::new(tokio::sync::RwLock::new(HashSet::new()));
        let local_peer = bind_loopback_and_forward(
            monitor.clone(),
            peer_log.new(slog::o!("traffic" => "outbound")),
            to_internet.clone(),
            peer.local_port,
            connections.clone(),
        )
        .await?;

        spawn(
            monitor.clone(),
            peer_log.new(slog::o!("traffic" => "control")),
            "control UDP handler",
            probe::handle_packets(
                peer_log.new(slog::o!("traffic" => "control")),
                probes.clone(),
                from_probes,
                to_internet.clone(),
            ),
        );
        spawn(
            monitor.clone(),
            peer_log.new(slog::o!("traffic" => "control")),
            "control probe scheduler",
            probe::schedule_probes(probes.clone(), to_internet.clone()),
        );

        spawn(
            monitor.clone(),
            peer_log.new(slog::o!("traffic" => "inbound")),
            "inbound UDP forwarding",
            forward_inbound_traffic(
                peer_log.new(slog::o!("traffic" => "inbound")),
                from_peers,
                connections.clone(),
                local_peer,
            ),
        );
        spawn(
            monitor.clone(),
            peer_log.new(slog::o!("dht" => "put")),
            "DHT address publishing",
            publish_candidates(
                peer_log.new(slog::o!("dht" => "put")),
                dht.clone(),
                secret_key.clone(),
                remote_key.clone(),
                local_candidates,
                probes.clone(),
            ),
        );
        spawn(
            monitor.clone(),
            peer_log.new(slog::o!("dht" => "get")),
            "DHT address listening",
            listen_for_peer_candidates(
                peer_log.new(slog::o!("dht" => "get")),
                dht.clone(),
                secret_key.clone(),
                remote_key,
                connections,
                connection_flags.clone(),
                probes,
            ),
        );
    }
    Ok(())
}

fn parse_peer_key(peer: &Peer, peer_index: usize) -> anyhow::Result<PublicKey> {
    PublicKey::try_from(peer.public_key.as_str()).map_err(|error| {
        anyhow!(
            "Failed to parse public key for peer {peer_index} ({}): {error}",
            peer.name.as_deref().unwrap_or("unnamed")
        )
    })
}

async fn request_nat_mapping(log: &slog::Logger, local_port: u16) -> Option<crate::nat::Mapping> {
    slog::info!(log, "Requesting local-router UDP mapping"; "local_port" => local_port);
    match crate::nat::map_udp_port(log.clone(), local_port).await {
        Ok(mapping) => {
            slog::info!(log, "Local-router UDP mapping created"; "external_addr" => mapping.external_addr, "method" => mapping.method.to_string());
            Some(mapping)
        }
        Err(error) => {
            slog::error!(log, "Local-router UDP mapping unavailable; continuing with STUN"; "error" => format!("{error:#}"));
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_peer_key, validate_connections};
    use crate::config::{P2PConnection, Peer};

    #[test]
    fn malformed_peer_key_fails_startup_validation_without_echoing_it() {
        let peer = Peer {
            local_port: 10001,
            public_key: "not-a-key".to_string(),
            name: Some("desktop".to_string()),
        };

        let error = match parse_peer_key(&peer, 0) {
            Ok(_) => panic!("malformed key was accepted"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("peer 0 (desktop)"));
        assert!(!error.contains(&peer.public_key));
    }

    #[test]
    fn invalid_configuration_is_rejected_before_service_setup() {
        let connection = P2PConnection {
            secret_key: "not-a-key".to_string(),
            peers: vec![],
        };

        assert!(validate_connections(&[connection]).is_err());
    }
}
