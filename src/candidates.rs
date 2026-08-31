use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime};

use anyhow::{Context, bail};
use async_broadcast::{Receiver, RecvError, Sender, broadcast};
use base64::{Engine, engine::general_purpose};
use futures::stream::StreamExt;
use tokio::net::UdpSocket;

use crate::config::{ConnectionFlags, StunFlags};
use crate::crypto::{CryptoBox, PublicKey, SecretKey};
use crate::dht::OpenDht;
use crate::message::{Control, Message};
use crate::nat;
use crate::probe::{ProbeController, decode_token};
use crate::stun;
use crate::transport::Connections;
use crate::utils::{TaskMonitor, UdpReceiver, UdpSender, spawn};

const MAX_DHT_MESSAGE_AGE: Duration = Duration::from_secs(10 * 60);
const MAX_DHT_FUTURE_SKEW: Duration = Duration::from_secs(5 * 60);
const MAX_REMOTE_CANDIDATES: usize = 64;

pub fn dht_key(publisher: &PublicKey, subscriber: &PublicKey) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(publisher.as_bytes());
    key.extend_from_slice(subscriber.as_bytes());
    key
}

pub fn is_usable_peer_addr(addr: &SocketAddr) -> bool {
    // TODO: When address.is_global() is stable, just use that; this is missing many edge cases.
    !addr.ip().is_loopback()
        && !addr.ip().is_unspecified()
        && !addr.ip().is_multicast()
        && addr.port() > 1024
}

fn retained_known_connections(
    known_connections: &HashSet<SocketAddr>,
    only_ipv4: bool,
) -> impl Iterator<Item = SocketAddr> + '_ {
    known_connections
        .iter()
        .copied()
        .filter(move |addr| !only_ipv4 || addr.ip().is_ipv4())
}

fn parse_dht_message(log: &slog::Logger, plaintext: &[u8]) -> Option<Message> {
    match serde_json::from_slice(plaintext) {
        Ok(message) => Some(message),
        Err(error) => {
            slog::info!(log, "Invalid DHT message ignored"; "error" => format!("{error:#}"));
            None
        }
    }
}

fn is_fresh_dht_timestamp(timestamp: SystemTime, now: SystemTime) -> bool {
    match timestamp.duration_since(now) {
        Ok(future_skew) => future_skew <= MAX_DHT_FUTURE_SKEW,
        Err(_) => now
            .duration_since(timestamp)
            .is_ok_and(|age| age <= MAX_DHT_MESSAGE_AGE),
    }
}

pub async fn listen_for_peer_candidates(
    log: slog::Logger,
    dht: OpenDht,
    private_key: SecretKey,
    remote_key: PublicKey,
    connections: Connections,
    flags: ConnectionFlags,
    probes: ProbeController,
) -> anyhow::Result<()> {
    let local_key = private_key.public_key();
    let crypto = CryptoBox::new(&remote_key, &private_key);
    let key = dht_key(&remote_key, &local_key);
    slog::debug!(log, "Waiting for remote peer to publish IP in DHT..."; "dht_key" => general_purpose::STANDARD.encode(&key));

    let mut last_timestamp = None;
    let mut values = dht.listen(key.clone());
    while let Some(value) = values.next().await {
        let Some(plaintext) = crypto.decrypt(&value) else {
            slog::debug!(log, "DHT value decryption failed");
            continue;
        };
        let Some(message) = parse_dht_message(&log, &plaintext) else {
            continue;
        };
        if !is_fresh_dht_timestamp(message.timestamp, SystemTime::now()) {
            slog::debug!(log, "Ignoring DHT message with an implausible timestamp");
            continue;
        }

        let message_timestamp = message
            .timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .ok();
        let previous_timestamp = last_timestamp.and_then(|timestamp: SystemTime| {
            timestamp
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|duration| duration.as_secs())
                .ok()
        });
        slog::debug!(log, "DHT message timestamp compared"; "message_timestamp" => message_timestamp, "last_timestamp" => previous_timestamp);
        if last_timestamp.is_some_and(|last| message.timestamp <= last) {
            slog::debug!(log, "Ignoring stale or replayed DHT message"; "message_timestamp" => message_timestamp, "last_timestamp" => previous_timestamp);
            continue;
        }
        last_timestamp = Some(message.timestamp);

        let remote_token = message
            .control
            .as_ref()
            .and_then(|control| decode_token(&control.probe_token));
        if message.control.is_some() && remote_token.is_none() {
            slog::debug!(log, "Ignoring invalid control extension in DHT message");
        }

        let mut updated_peers: HashSet<_> = message
            .ip_addr_list
            .into_iter()
            .filter(|addr| !flags.filter_ipv6 || addr.ip().is_ipv4())
            .filter(is_usable_peer_addr)
            .take(MAX_REMOTE_CANDIDATES)
            .collect();

        let known_peers = connections.read().await;
        if flags.no_clear {
            for peer in retained_known_connections(known_peers.advertised(), flags.filter_ipv6) {
                if updated_peers.len() == MAX_REMOTE_CANDIDATES {
                    break;
                }
                updated_peers.insert(peer);
            }
        }
        for peer in known_peers.advertised().difference(&updated_peers) {
            slog::info!(log, "Known peer address will no longer be used, not found in DHT"; "addr" => peer);
        }
        for peer in updated_peers.difference(known_peers.advertised()) {
            slog::info!(log, "New peer address found"; "addr" => peer);
        }
        let changed = known_peers.advertised() != &updated_peers;
        drop(known_peers);
        if changed {
            connections
                .write()
                .await
                .replace_advertised(updated_peers.clone());
        }

        probes
            .update_remote(remote_token, updated_peers.into_iter().collect())
            .await;

        slog::debug!(log, "Waiting for remote peer to publish a new IP in DHT..."; "dht_key" => general_purpose::STANDARD.encode(&key));
    }

    bail!("DHT listener ended")
}

pub async fn publish_candidates(
    log: slog::Logger,
    dht: OpenDht,
    private_key: SecretKey,
    remote_key: PublicKey,
    mut candidates: Receiver<Vec<SocketAddr>>,
    probes: ProbeController,
) -> anyhow::Result<()> {
    let local_key = private_key.public_key();
    let crypto = CryptoBox::new(&remote_key, &private_key);
    let key = dht_key(&local_key, &remote_key);
    slog::info!(log, "Will publish own public address on DHT"; "dht_key" => general_purpose::STANDARD.encode(&key));

    let control = Control {
        probe_token: probes.local_token_base64().await,
    };
    let mut addresses = Vec::new();
    loop {
        let address_log = format!("{addresses:?}");
        let message = Message {
            timestamp: SystemTime::now(),
            ip_addr_list: addresses.clone(),
            control: Some(control.clone()),
        };
        let plaintext = serde_json::to_vec(&message)?;
        let value = crypto.encrypt(&plaintext)?;

        dht.put(&key, &value).await?;
        slog::info!(log, "Published own public address on DHT"; "dht_key" => general_purpose::STANDARD.encode(&key), "addrs" => address_log);

        match tokio::time::timeout(Duration::from_secs(60), candidates.recv()).await {
            Err(_) => {}
            Ok(received) => match received {
                Ok(new_addresses) => addresses = new_addresses,
                Err(RecvError::Closed) => bail!("STUN candidate source stopped"),
                Err(RecvError::Overflowed(_)) => {
                    slog::debug!(log, "Missed a new public address, overflowed, continuing");
                }
            },
        }
    }
}

struct StunLookup {
    log: slog::Logger,
    server: String,
    to_internet: UdpSender,
    from_internet: UdpReceiver,
    candidates: Sender<Vec<SocketAddr>>,
    local_port: u16,
    gather_ipv6: bool,
    nat_mapping: Option<nat::Mapping>,
    run_once: bool,
}

pub struct StunSetup {
    pub to_internet: UdpSender,
    pub from_internet: UdpReceiver,
    pub local_port: u16,
    pub gather_ipv6: bool,
    pub nat_mapping: Option<nat::Mapping>,
    pub run_once: bool,
}

fn local_ipv6_candidate(
    local_ipv6: Option<IpAddr>,
    local_port: u16,
    gather_ipv6: bool,
) -> Option<SocketAddr> {
    gather_ipv6
        .then_some(local_ipv6)
        .flatten()
        .map(|ip| SocketAddr::new(ip, local_port))
}

pub async fn start_stun_candidates(
    monitor: TaskMonitor,
    log: &slog::Logger,
    flags: &StunFlags,
    setup: StunSetup,
) -> anyhow::Result<Receiver<Vec<SocketAddr>>> {
    let StunSetup {
        to_internet,
        from_internet,
        local_port,
        gather_ipv6,
        nat_mapping,
        run_once,
    } = setup;
    let log = log.new(slog::o!("traffic" => "stun"));
    if !gather_ipv6 {
        slog::info!(log, "IPv6 candidate gathering disabled");
    }
    let (mut sender, receiver) = broadcast(1);
    sender.set_overflow(true);

    spawn(
        monitor,
        log.clone(),
        "STUN candidate gathering",
        lookup_public_address(StunLookup {
            log,
            server: flags.stun_addr.clone(),
            to_internet,
            from_internet,
            candidates: sender,
            local_port,
            gather_ipv6,
            nat_mapping,
            run_once,
        }),
    );

    Ok(receiver)
}

async fn lookup_public_address(lookup: StunLookup) -> anyhow::Result<()> {
    let StunLookup {
        log,
        server,
        mut to_internet,
        mut from_internet,
        candidates,
        local_port,
        gather_ipv6,
        mut nat_mapping,
        run_once,
    } = lookup;
    let stun = stun::Stun;
    let mut previous_addresses = vec![];
    let mut previous_server = None;

    loop {
        let server_addresses: Vec<_> = tokio::net::lookup_host(&server).await?.collect();
        let server = server_addresses
            .iter()
            .copied()
            .find(SocketAddr::is_ipv4)
            .context("Failed to resolve an IPv4 STUN server address")?;
        if Some(server) != previous_server {
            slog::debug!(log, "Resolved stun server addrs"; "addrs" => format!("{server_addresses:?}"), "stun_server" => server);
            previous_server = Some(server);
        }

        let mut addresses = vec![];
        let local_ipv6 = if gather_ipv6 {
            get_local_ipv6_addr().await?
        } else {
            None
        };
        if let Some(address) = local_ipv6_candidate(local_ipv6, local_port, gather_ipv6) {
            addresses.push(address);
        }

        match stun
            .lookup_public_address(&log, &mut to_internet, &mut from_internet, server)
            .await
        {
            Ok(address) => {
                if let Some(mapping) = nat_mapping.as_ref() {
                    if !mapping.is_active() {
                        slog::info!(log, "Ignoring inactive router mapping"; "mapping" => mapping.external_addr, "method" => mapping.method.to_string());
                    } else if mapping.external_addr.ip() == address.ip() {
                        addresses.push(mapping.external_addr);
                    } else {
                        slog::info!(log, "Ignoring router mapping with a different public IP than STUN"; "mapping" => mapping.external_addr, "method" => mapping.method.to_string(), "stun" => address);
                    }
                }
                addresses.push(address);
                if previous_addresses != addresses {
                    slog::info!(log, "STUN found new addresses"; "addr" => format!("{addresses:?}"));
                    previous_addresses = addresses.clone();
                }
                candidates.broadcast_direct(addresses).await?;
                wait_for_next_stun_attempt(&mut nat_mapping, Duration::from_secs(60)).await;
            }
            Err(error) => {
                slog::error!(log, "STUN failed"; "error" => format!("{error:#}"));
                candidates.broadcast_direct(addresses).await?;
                wait_for_next_stun_attempt(&mut nat_mapping, Duration::from_secs(15)).await;
            }
        }

        if run_once {
            return Ok(());
        }
    }
}

async fn wait_for_next_stun_attempt(mapping: &mut Option<nat::Mapping>, delay: Duration) {
    if let Some(mapping) = mapping {
        if matches!(
            tokio::time::timeout(delay, mapping.changed()).await,
            Ok(Err(_))
        ) {
            tokio::time::sleep(delay).await;
        }
    } else {
        tokio::time::sleep(delay).await;
    }
}

async fn get_local_ipv6_addr() -> anyhow::Result<Option<IpAddr>> {
    let socket = UdpSocket::bind("[::]:0").await?;
    if socket.connect("[2001:4860:4860::8888]:53").await.is_ok() {
        let address = socket.local_addr()?;
        if !address.ip().is_unspecified() && !address.ip().is_loopback() {
            return Ok(Some(address.ip()));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_DHT_FUTURE_SKEW, dht_key, is_fresh_dht_timestamp, is_usable_peer_addr,
        local_ipv6_candidate, parse_dht_message, retained_known_connections,
    };
    use crate::crypto::PublicKey;
    use std::collections::HashSet;
    use std::net::{IpAddr, Ipv6Addr, SocketAddr};
    use std::time::{Duration, SystemTime};

    #[test]
    fn accepts_the_full_unprivileged_port_range() {
        let ip = [192, 0, 2, 1];
        assert!(!is_usable_peer_addr(&SocketAddr::from((ip, 1024))));
        assert!(is_usable_peer_addr(&SocketAddr::from((ip, 1025))));
        assert!(is_usable_peer_addr(&SocketAddr::from((ip, u16::MAX))));
    }

    #[test]
    fn derives_the_legacy_dht_key_in_publisher_order() {
        let publisher = PublicKey::new([0x11; 32]);
        let subscriber = PublicKey::new([0x22; 32]);
        assert_eq!(
            dht_key(&publisher, &subscriber),
            [[0x11; 32], [0x22; 32]].concat()
        );
    }

    #[test]
    fn ipv4_only_mode_does_not_publish_a_local_ipv6_candidate() {
        let ipv6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(local_ipv6_candidate(Some(ipv6), 12345, false), None);
        assert_eq!(
            local_ipv6_candidate(Some(ipv6), 12345, true),
            Some(SocketAddr::new(ipv6, 12345))
        );
    }

    #[test]
    fn ipv4_only_mode_does_not_retain_an_old_ipv6_peer() {
        let ipv4 = SocketAddr::from(([192, 0, 2, 1], 12345));
        let ipv6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 12345);
        let known = HashSet::from([ipv4, ipv6]);
        assert_eq!(
            retained_known_connections(&known, true).collect::<HashSet<_>>(),
            HashSet::from([ipv4])
        );
    }

    #[test]
    fn malformed_dht_messages_are_ignored() {
        let log = slog::Logger::root(slog::Discard, slog::o!());
        assert!(parse_dht_message(&log, br#"{"timestamp":{}}"#).is_none());
    }

    #[test]
    fn rejects_dht_timestamps_outside_the_freshness_window() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        assert!(is_fresh_dht_timestamp(now, now));
        assert!(is_fresh_dht_timestamp(now + MAX_DHT_FUTURE_SKEW, now));
        assert!(!is_fresh_dht_timestamp(
            now + MAX_DHT_FUTURE_SKEW + Duration::from_secs(1),
            now
        ));
        assert!(!is_fresh_dht_timestamp(
            now - Duration::from_secs(10 * 60 + 1),
            now
        ));
    }
}
