mod config;
mod crypto;
mod dht;
mod message;
mod stun;
mod utils;

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;

use std::convert::{TryFrom, TryInto};

use anyhow::{Context, anyhow, bail};
use async_broadcast::{Receiver, RecvError, Sender, broadcast};
use async_std::net::ToSocketAddrs;
use async_std::net::UdpSocket;
use async_std::sync::RwLock;

use slog::Drain;
use slog::{crit, debug, error, info};

use base64::{Engine, engine::general_purpose};
use config::{CliConfig, Command, DhtFlags, P2PConnection, StunFlags};
use crypto::*;
use dht::OpenDht;
use futures::stream::StreamExt;
use message::Message;
use stun::codec::MAGIC_COOKIE;
use utils::*;
use utils::{UdpReceiver, UdpSender};

type RwAddrConnections = RwLock<HashSet<SocketAddr>>;
type RwLocalAddr = RwLock<(UdpSender, Option<SocketAddr>)>;

async fn create_local_receiever(lo_port: u16) -> anyhow::Result<UdpSocket> {
    Ok(UdpSocket::bind(("127.0.0.1", lo_port)).await?)
}

/// Creates a new local socket and forwards all incoming data (outbound wireguard traffic) to the internet
/// The returned local socket can be used to forward inbound wireguard traffic from this peer_addr
/// to the wireguard interface at wg_lo_port (typically done in forward_incoming_traffic() via the connections map)
///
/// public_socket: public internet socket
async fn new_local_socket(
    parent_log: slog::Logger,
    to_inet_tx: UdpSender,
    lo_port: u16,
    remote_peer_addrs: Arc<RwAddrConnections>,
) -> anyhow::Result<Arc<RwLocalAddr>> {
    info!(parent_log, "Setting up new local address"; slog::o!("local_port" => lo_port));

    let lo_sock = create_local_receiever(lo_port).await?;
    let local_addr = lo_sock.local_addr()?;
    let (lo_sender, lo_receiver) = split_udp_socket(lo_sock);
    let local_addr_rw = Arc::new(RwLock::new((lo_sender, None)));
    let local_addr_rw_clone = local_addr_rw.clone();
    // let mut buf = vec![0u8; 64 * 1024];

    let log_out = parent_log.new(slog::o!("direction" => "outbound"));
    spawn(async move {
        // forward data from local socket (outbound wireguard) to the internet
        loop {
            // let (n, lo_peer_addr) = lo_receiver.recv_from(&mut buf).await?;
            let (buf, lo_peer_addr) = lo_receiver.recv().await?;
            let n = buf.len();

            if local_addr_rw.read().await.1 != Some(lo_peer_addr) {
                info!(log_out, "lo_peer_addr changed, it is now..."; slog::o!("lo_peer_addr" => lo_peer_addr));
                local_addr_rw.write().await.1 = Some(lo_peer_addr);
            }

            let guard = remote_peer_addrs.read().await;
            for remote_peer_addr in guard.iter() {
                // lo_peer_addr must be wireguard on localhost
                // to_inet_tx.send((buf[..n].to_vec(), *remote_peer_addr)).await?;
                to_inet_tx.send((buf.to_vec(), *remote_peer_addr)).await?;
                debug!(log_out, "Outbound packet forwarded"; slog::o!("src" => lo_peer_addr, "via_lo" => local_addr, "dst" => remote_peer_addr, "bytes" => n));
            }
        }
    });

    Ok(local_addr_rw_clone)
}

async fn dht_get(
    log_get: slog::Logger,
    dht: OpenDht,
    private_key: SecretKey,
    remote_pkey: PublicKey,
    connections: Arc<RwAddrConnections>,
) -> anyhow::Result<()> {
    let secret_key = private_key;
    let local_pkey = secret_key.public_key();
    let crypto = Sodiumoxide::new(&remote_pkey, &secret_key);

    let key = [remote_pkey.0.0, local_pkey.0.0].concat();
    debug!(log_get, "Waiting for remote peer to publish IP in DHT..."; slog::o!("dht_key" => general_purpose::STANDARD.encode(&key)));

    // TODO: if not found within X seconds, repeat

    let mut last_timestamp: Option<SystemTime> = None;

    let listen = batches(dht.listen(key.clone()));
    futures::pin_mut!(listen);
    while let Some(batch) = listen.next().await {
        // TODO: need secret key for PublicKeyCrypto
        let batch: Vec<_> = batch.collect();
        let batch = batch.into_iter();

        let batch = batch
            .map(|value| crypto.decrypt(&value[..]))
            .filter_map(|value| {
                if value.is_none() {
                    debug!(log_get, "Decryption failed")
                };
                value
            });

        let batch: Vec<_> = batch.collect();
        let batch = batch.into_iter();

        let batch = batch
            .map(|value| serde_json::from_slice::<Message>(&value[..]))
            .filter_map(|value| {
                if value.is_err() {
                    info!(log_get, "Deserialization failed")
                };
                value.ok()
            });
        let batch: Vec<_> = batch.collect();
        let batch = batch.into_iter();

        let msg = batch.max_by_key(|m| m.timestamp);

        let a = msg.as_ref().and_then(|m| {
            m.timestamp
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .ok()
        });
        let b = last_timestamp.as_ref().and_then(|t| {
            t.duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .ok()
        });
        debug!(log_get, "msg_ts < last_ts?"; slog::o!("msg_ts" => a, "last_ts" => b));
        if msg.as_ref().map(|m| m.timestamp) < last_timestamp {
            debug!(log_get, "skipping"; slog::o!("msg_ts" => a, "last_ts" => b));
            continue;
        }
        last_timestamp = msg.as_ref().map(|m| m.timestamp);
        let ip_addr_list = msg.map(|m| m.ip_addr_list).unwrap_or(vec![]);

        let new_set: HashSet<_> = ip_addr_list.into_iter().filter(
            // TODO: When address.is_global() is stable, just use that, this is missing many edge cases.
            |addr| !addr.ip().is_loopback() && !addr.ip().is_unspecified() && !addr.ip().is_multicast()
                // Make sure the port seems reasonable
                && !addr.port() > 1024
        ).collect();
        let mut need_write = false;

        let known_connections = connections.read().await;
        for remote_peer_addr in known_connections.difference(&new_set) {
            need_write = true;
            info!(log_get, "Known peer address will no longer be used, not found in DHT"; slog::o!("addr" => remote_peer_addr));
        }
        for remote_peer_addr in new_set.difference(&known_connections) {
            need_write = true;
            info!(log_get, "New peer address found"; slog::o!("addr" => remote_peer_addr));
        }
        drop(known_connections);
        if need_write {
            *connections.write().await = new_set;
        }

        debug!(log_get, "Waiting for remote peer to publish a new IP in DHT..."; slog::o!("dht_key" => general_purpose::STANDARD.encode(&key)));
    }

    Ok(())
}

async fn dht_put(
    log_put: slog::Logger,
    dht: OpenDht,
    private_key: SecretKey,
    remote_pkey: PublicKey,
    mut public_address_r: Receiver<Option<SocketAddr>>,
) -> anyhow::Result<()> {
    let secret_key = private_key;
    let local_pkey = secret_key.public_key();
    let crypto = Sodiumoxide::new(&remote_pkey, &secret_key);

    let key = [local_pkey.0.0, remote_pkey.0.0].concat();
    info!(log_put, "Will publish own public address on DHT"; slog::o!("dht_key" => general_purpose::STANDARD.encode(&key)));

    debug!(log_put, "Starting to wait for new public address");

    loop {
        let public_addr: Option<SocketAddr> = match public_address_r.recv().await {
            Ok(addr) => addr,
            Err(RecvError::Closed) => break,
            Err(RecvError::Overflowed(_)) => {
                debug!(
                    log_put,
                    "Missed a new public address, overflowed, continuing"
                );
                continue;
            }
        };
        debug!(log_put, "Got myown a new public address"; slog::o!("addr" => format!("{:?}", public_addr)));

        let msg = Message {
            timestamp: std::time::SystemTime::now(),
            ip_addr_list: public_addr.map(|a| vec![a]).unwrap_or(vec![]),
        };

        let value = serde_json::to_vec(&msg)?;
        let value = crypto.encrypt(&value[..])?;

        dht.put(&key[..], &value[..]).await?;
        info!(log_put, "Published own public address on DHT"; slog::o!("dht_key" => general_purpose::STANDARD.encode(&key), "addr" => public_addr));

        // if res.timed_out() {
        //     debug!(log_put, "Republishing old address..."; slog::o!("addr" => public_addr));
        // }
    }

    Ok(())
}

fn split_inet_rx(rx: UdpReceiver) -> (UdpReceiver, UdpReceiver) {
    let (tx1, rx1) = async_std::channel::unbounded();
    let (tx2, rx2) = async_std::channel::unbounded();

    spawn(async move {
        loop {
            let (buf, dst) = rx.recv().await?;
            // Only send "stun packets" to first channel, and do not send to the second.
            if buf.len() > 20
                && u64::from_be_bytes(buf[4..12].try_into().unwrap()) == (MAGIC_COOKIE as u64) << 32
            {
                tx1.send((buf.clone(), dst)).await?;
            } else {
                tx2.send((buf, dst)).await?;
            }
        }
    });

    (rx1, rx2)
}

async fn forward_inbound_traffic(
    log_fwd: slog::Logger,
    mut from_inet_rx: UdpReceiver,
    connections: Arc<RwAddrConnections>,
    local_pair: Arc<RwLocalAddr>,
) -> anyhow::Result<()> {
    while let Some((buf, remote_peer_addr)) = from_inet_rx.next().await {
        debug!(log_fwd, "Received inbound packet"; slog::o!("src" => remote_peer_addr, "bytes" => buf.len()));

        let read_set = connections.read().await;
        if !read_set.contains(&remote_peer_addr) {
            drop(read_set);
            info!(log_fwd, "New inbound peer, adding to connections"; slog::o!("src" => remote_peer_addr));
            let mut write = connections.write().await;
            write.insert(remote_peer_addr);
        }

        let guard = local_pair.read().await;
        let lo_socket = &guard.0;
        let lo_peer_addr = guard.1;
        if let Some(lo_peer_addr) = lo_peer_addr {
            lo_socket.send((buf.to_vec(), lo_peer_addr)).await?;
            debug!(log_fwd, "Forwarded inbound packet"; slog::o!("remote_addr" => remote_peer_addr, "lo_addr" => lo_peer_addr));
        } else {
            debug!(
                log_fwd,
                "Local peer address is not yet set, skipping forwading packet"
            );
        }
    }

    Ok(())
}

async fn lookup_public_address(
    log: slog::Logger,
    stun_server: SocketAddr,
    mut to_inet_tx: UdpSender,
    mut from_inet_rx: UdpReceiver,
    public_address_s: Sender<Option<SocketAddr>>,
) -> anyhow::Result<()> {
    let stun = stun::Stun;
    let mut old_address = None;
    loop {
        match stun
            .lookup_public_address(&log, &mut to_inet_tx, &mut from_inet_rx, stun_server)
            .await
        {
            Ok(new_address) => {
                let addr: Option<SocketAddr> = new_address.into();
                debug!(log, "STUN succeeded"; slog::o!("addr" => addr));
                if old_address != addr {
                    info!(log, "STUN found new address"; slog::o!("addr" => addr));
                    old_address = addr;
                }
                public_address_s.broadcast_direct(addr).await?;
                debug!(log, "STUN all tasks notified"; slog::o!("addr" => addr));
                async_std::task::sleep(Duration::from_secs(60)).await;
            }
            Err(err) => {
                error!(log, "STUN failed"; slog::o!("error" => format!("{:?}", err)));
                async_std::task::sleep(Duration::from_secs(15)).await;
            }
        }
    }
}

async fn setup_stun(
    log_dev: &slog::Logger,
    flags: &StunFlags,
    to_inet_tx: UdpSender,
    from_inet_rx: UdpReceiver,
) -> anyhow::Result<Receiver<Option<SocketAddr>>> {
    let log_stun = log_dev.new(slog::o!("traffic" => "stun"));
    // TODO: resolve ip later
    let stun_server = flags.stun_addr.to_socket_addrs().await?.next().unwrap();
    let (mut public_address_s, public_address_r) = broadcast::<Option<SocketAddr>>(1);
    public_address_s.set_overflow(true);

    spawn(lookup_public_address(
        log_stun,
        stun_server,
        to_inet_tx,
        from_inet_rx,
        public_address_s,
    ));

    Ok(public_address_r)
}

async fn handle_device(
    log_dev: slog::Logger,
    dht: OpenDht,
    stun_flags: &StunFlags,
    cfg: &P2PConnection,
) -> anyhow::Result<()> {
    let secret_key = SecretKey::try_from(cfg.secret_key.as_str()).map_err(|e| {
        anyhow!(
            "Failed to parse own secret key {}, with error: {}",
            cfg.secret_key,
            e
        )
    })?;

    // TODO: drop last public_socket
    //    todo!();

    for peer in cfg.peers.iter() {
        let remote_pkey_base64 = peer.public_key.clone();
        let remote_pkey = match PublicKey::try_from(remote_pkey_base64.as_str()) {
            Ok(remote_pkey) => remote_pkey,
            Err(e) => {
                error!(
                    log_dev,
                    "Failed to parse pubkey of peer {:?} with error {:?}", remote_pkey_base64, e
                );
                continue;
            }
        };

        let public_socket = UdpSocket::bind("[::]:0").await?;
        info!(log_dev, "Creating a stun udp socket"; "address" => public_socket.local_addr()?);
        let (to_inet_tx, from_inet_rx) = split_udp_socket(public_socket);
        let (stun_rx, data_inet_rx) = split_inet_rx(from_inet_rx);
        let public_address_r =
            setup_stun(&log_dev, stun_flags, to_inet_tx.clone(), stun_rx).await?;

        let connections: Arc<RwAddrConnections> = Arc::new(RwLock::new(HashSet::new()));

        let lo_port = peer.local_port;
        debug!(log_dev, "Connection local port is"; "port" => lo_port);
        let log_out = log_dev.new(slog::o!("traffic" => "outbound"));
        let local_pair =
            new_local_socket(log_out, to_inet_tx, lo_port, connections.clone()).await?;
        let log_fwd = log_dev.new(slog::o!("traffic" => "inbound"));
        spawn(forward_inbound_traffic(
            log_fwd,
            data_inet_rx,
            connections.clone(),
            local_pair,
        ));

        let log_peer = if let Some(name) = &peer.name {
            log_dev.new(slog::o!("peer" => format!("{:}", name)))
        } else {
            log_dev.new(slog::o!("peer" => format!("{:}", remote_pkey)))
        };
        let log_put = log_peer.new(slog::o!("dht" => "put"));
        let log_get = log_peer.new(slog::o!("dht" => "get"));

        spawn(dht_put(
            log_put,
            dht.clone(),
            secret_key.clone(),
            remote_pkey.clone(),
            public_address_r,
        ));
        spawn(dht_get(
            log_get,
            dht.clone(),
            secret_key.clone(),
            remote_pkey,
            connections,
        ));
    }

    Ok(())
}

async fn start_dht(log: &slog::Logger, flags: &DhtFlags) -> anyhow::Result<OpenDht> {
    let dht_log = log.new(slog::o!("task" => "dht"));
    let dht = OpenDht::new(dht_log, flags.opendht_port, flags.bootstrap_ip.clone())
        .await
        .context("Initializing DHT failed")?;

    Ok(dht)
}

#[async_std::main]
async fn main() -> anyhow::Result<()> {
    if let Err(()) = sodiumoxide::init() {
        bail!("Initializing sodiumoxide failed");
    }

    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    let log = slog::Logger::root(drain, slog::o!());

    let cfg = CliConfig::new(&log)?;

    match cfg.command {
        Command::Generate => {
            let (sk, display, pk) = generate_secret_key_base64();
            info!(log, "SecretKey is {:}", display);
            info!(log, "PublicKey is {:}", sk.public_key());
            debug!(log, "PublicKey from library is {:}", pk);
            let new_sk = SecretKey::try_from(display.as_str())
                .expect("Failed at reloading a key just generated");
            debug!(
                log,
                "PublicKey after reloading from displayed secret is {:}",
                new_sk.public_key()
            )
        }
        Command::Stun { ref flags } => {
            let log_dev = log.new(slog::o!("dev" => "stun"));

            let public_socket = UdpSocket::bind("[::]:0").await?;
            info!(log_dev, "Creating a stun udp socket"; "address" => public_socket.local_addr()?);
            let (to_inet_tx, from_inet_rx) = split_udp_socket(public_socket);

            let mut public_address_r =
                setup_stun(&log_dev, flags, to_inet_tx, from_inet_rx).await?;

            let public_address = public_address_r.recv_direct().await?;
            info!(log, "Got public address {:?}", public_address);
        }
        Command::Dht { ref flags } => {
            let dht = start_dht(&log, flags).await?;
            let key = &[9, 9, 9];
            let val = &[1, 1, 1, 2];
            dht.put(key, val).await?;
            debug!(log, "put done: {:?}", val);
            let mut stream = dht.get(key.to_vec());
            while let Some(val) = stream.next().await {
                debug!(log, "{:?}", val);
            }
        }
        Command::Run(ref cmd) => {
            let dht = start_dht(&log, &cmd.dht_flags).await?;

            let mut futures = vec![];
            // Connection is peer public key, currently devices are just numbered.
            for (i, connection) in cmd.connections.iter().enumerate() {
                let dev_name = i.to_string();
                let log_dev = log.new(slog::o!("dev" => dev_name));
                futures.push(handle_device(
                    log_dev,
                    dht.clone(),
                    &cmd.stun_flags,
                    connection,
                ));
            }

            let results = futures::future::join_all(futures).await;
            if results.is_empty() {
                crit!(log, "No connections configured!");
            } else {
                results.into_iter().collect::<anyhow::Result<()>>()?;
                async_std::future::pending::<()>().await;
            }
        }
    };

    Ok(())
}
