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
use async_std::net::{IpAddr, ToSocketAddrs, UdpSocket};
use async_std::sync::RwLock;

use slog::{Drain, Level, LevelFilter};
use slog::{crit, debug, error, info};

use base64::{Engine, engine::general_purpose};
use config::{CliConfig, Command, DhtFlags, GenFlags, P2PConnection, StunFlags};
use crypto::*;
use dht::OpenDht;
use futures::stream::StreamExt;
use message::Message;
use stun::codec::MAGIC_COOKIE;
use utils::*;
use utils::{UdpReceiver, UdpSender};

use std::fs::{File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

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
    info!(parent_log, "Setting up new local address"; "local_port" => lo_port);

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
                info!(log_out, "lo_peer_addr changed, it is now..."; "lo_peer_addr" => lo_peer_addr);
                local_addr_rw.write().await.1 = Some(lo_peer_addr);
            }

            let guard = remote_peer_addrs.read().await;
            for remote_peer_addr in guard.iter() {
                // lo_peer_addr must be wireguard on localhost
                // to_inet_tx.send((buf[..n].to_vec(), *remote_peer_addr)).await?;
                to_inet_tx.send((buf.to_vec(), *remote_peer_addr)).await?;
                debug!(log_out, "Outbound packet forwarded"; "src" => lo_peer_addr, "via_lo" => local_addr, "dst" => remote_peer_addr, "bytes" => n);
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
    debug!(log_get, "Waiting for remote peer to publish IP in DHT..."; "dht_key" => general_purpose::STANDARD.encode(&key));

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
        debug!(log_get, "msg_ts < last_ts?"; "msg_ts" => a, "last_ts" => b);
        if msg.as_ref().map(|m| m.timestamp) < last_timestamp {
            debug!(log_get, "skipping"; "msg_ts" => a, "last_ts" => b);
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
            info!(log_get, "Known peer address will no longer be used, not found in DHT"; "addr" => remote_peer_addr);
        }
        for remote_peer_addr in new_set.difference(&known_connections) {
            need_write = true;
            info!(log_get, "New peer address found"; "addr" => remote_peer_addr);
        }
        drop(known_connections);
        if need_write {
            *connections.write().await = new_set;
        }

        debug!(log_get, "Waiting for remote peer to publish a new IP in DHT..."; "dht_key" => general_purpose::STANDARD.encode(&key));
    }

    Ok(())
}

async fn dht_put(
    log_put: slog::Logger,
    dht: OpenDht,
    private_key: SecretKey,
    remote_pkey: PublicKey,
    mut public_address_r: Receiver<Vec<SocketAddr>>,
) -> anyhow::Result<()> {
    let secret_key = private_key;
    let local_pkey = secret_key.public_key();
    let crypto = Sodiumoxide::new(&remote_pkey, &secret_key);

    let key = [local_pkey.0.0, remote_pkey.0.0].concat();
    info!(log_put, "Will publish own public address on DHT"; "dht_key" => general_purpose::STANDARD.encode(&key));

    debug!(log_put, "Starting to wait for new public address");

    loop {
        let public_addrs: Vec<SocketAddr> = match public_address_r.recv().await {
            Ok(addrs) => addrs,
            Err(RecvError::Closed) => break,
            Err(RecvError::Overflowed(_)) => {
                debug!(
                    log_put,
                    "Missed a new public address, overflowed, continuing"
                );
                continue;
            }
        };
        let public_addrs_str = format!("{:?}", &public_addrs);
        debug!(log_put, "Got myown a new public addresses"; "addrs" => &public_addrs_str);

        let msg = Message {
            timestamp: std::time::SystemTime::now(),
            ip_addr_list: public_addrs,
        };

        let value = serde_json::to_vec(&msg)?;
        let value = crypto.encrypt(&value[..])?;

        dht.put(&key[..], &value[..]).await?;
        info!(log_put, "Published own public address on DHT"; "dht_key" => general_purpose::STANDARD.encode(&key), "addrs" => public_addrs_str);

        // if res.timed_out() {
        //     debug!(log_put, "Republishing old address..."; "addr" => public_addr);
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
        debug!(log_fwd, "Received inbound packet"; "src" => remote_peer_addr, "bytes" => buf.len());

        let read_set = connections.read().await;
        if !read_set.contains(&remote_peer_addr) {
            drop(read_set);
            info!(log_fwd, "New inbound peer, adding to connections"; "src" => remote_peer_addr);
            let mut write = connections.write().await;
            write.insert(remote_peer_addr);
        }

        let guard = local_pair.read().await;
        let lo_socket = &guard.0;
        let lo_peer_addr = guard.1;
        if let Some(lo_peer_addr) = lo_peer_addr {
            lo_socket.send((buf.to_vec(), lo_peer_addr)).await?;
            debug!(log_fwd, "Forwarded inbound packet"; "remote_addr" => remote_peer_addr, "lo_addr" => lo_peer_addr);
        } else {
            debug!(
                log_fwd,
                "Local peer address is not yet set, skipping forwading packet"
            );
        }
    }

    Ok(())
}

async fn get_local_ipv6_addr() -> anyhow::Result<Option<IpAddr>> {
    let public_socket = UdpSocket::bind("[::]:0").await?;
    let local_addr = public_socket.local_addr()?;
    if local_addr.is_ipv6() {
        // Public IPv6 addr of google's 8.8.8.8 server
        if public_socket
            .connect("[2001:4860:4860::8888]:53")
            .await
            .is_ok()
        {
            let actual_addr = public_socket.local_addr();
            // TODO: When address.is_global() is stable, just use that, this is missing many edge cases.
            if let Ok(actual_addr) = actual_addr
                && !actual_addr.ip().is_unspecified()
                && !actual_addr.ip().is_loopback()
            {
                return Ok(Some(actual_addr.ip()));
            }
        }
    }

    Ok(None)
}

async fn lookup_public_address(
    log: slog::Logger,
    stun_server_addr: String,
    mut to_inet_tx: UdpSender,
    mut from_inet_rx: UdpReceiver,
    public_address_s: Sender<Vec<SocketAddr>>,
    local_out_port: u16,
    run_once: bool,
) -> anyhow::Result<()> {
    let stun = stun::Stun;
    let mut old_address = vec![];
    let mut old_server_address = None;
    loop {
        // Resolve address here in case it changes over runtime.
        let stun_addrs: Vec<_> = stun_server_addr.to_socket_addrs().await?.collect();
        // Only connect to ipv4 addresses of STUN servers, as IPv6 NAT doesn't actually exist.
        let stun_addrs_str = format!("{:?}", &stun_addrs);
        let stun_server = stun_addrs
            .into_iter()
            .find(|a| a.is_ipv4())
            .context("Failed to resolve stun server address")?;
        if Some(stun_server) != old_server_address {
            debug!(log, "Resolved stun server addrs"; "addrs" => stun_addrs_str, "stun_server" => stun_server);
            old_server_address = Some(stun_server);
        }

        let mut addr_vec = vec![];
        if let Some(addr) = get_local_ipv6_addr().await? {
            // This hack is used so we can get the ipv6 out address, and connect to google servers in get_local_ipv6_addr, but without ruining our current socket, which cannot be unconnected easily.
            addr_vec.push(SocketAddr::new(addr, local_out_port));
        }

        match stun
            .lookup_public_address(&log, &mut to_inet_tx, &mut from_inet_rx, stun_server)
            .await
        {
            Ok(new_address) => {
                let addr: Option<SocketAddr> = new_address.into();
                debug!(log, "STUN succeeded"; "addr" => addr);
                if let Some(addr) = addr {
                    addr_vec.push(addr);
                }
                if old_address != addr_vec {
                    let addr_vec_str = format!("{:?}", &addr_vec);
                    info!(log, "STUN found new addresses"; "addr" => addr_vec_str);
                    old_address = addr_vec.clone();
                }
                public_address_s.broadcast_direct(addr_vec).await?;
                debug!(log, "STUN all tasks notified"; "addr" => addr);
                async_std::task::sleep(Duration::from_secs(60)).await;
            }
            Err(err) => {
                error!(log, "STUN failed"; "error" => format!("{:?}", err));
                // Send an empty vector, or possibly our optional extra addr.
                public_address_s.broadcast_direct(addr_vec).await?;
                async_std::task::sleep(Duration::from_secs(15)).await;
            }
        }

        if run_once {
            break Ok(());
        }
    }
}

async fn setup_stun(
    log_dev: &slog::Logger,
    flags: &StunFlags,
    to_inet_tx: UdpSender,
    from_inet_rx: UdpReceiver,
    local_out_port: u16,
    run_once: bool,
) -> anyhow::Result<Receiver<Vec<SocketAddr>>> {
    let log_stun = log_dev.new(slog::o!("traffic" => "stun"));
    let stun_server_addr = flags.stun_addr.clone();
    debug!(log_stun, "Stun starting resolving server"; "addr" => &stun_server_addr);
    let (mut public_address_s, public_address_r) = broadcast::<Vec<SocketAddr>>(1);
    public_address_s.set_overflow(true);

    spawn(lookup_public_address(
        log_stun,
        stun_server_addr,
        to_inet_tx,
        from_inet_rx,
        public_address_s,
        local_out_port,
        run_once,
    ));

    Ok(public_address_r)
}

async fn get_inet_socket(log: &slog::Logger) -> anyhow::Result<(UdpSocket, u16)> {
    let public_socket = UdpSocket::bind("[::]:0").await?;
    let local_addr = public_socket.local_addr()?;
    info!(log, "Creating device udp socket"; "address" => local_addr);

    Ok((public_socket, local_addr.port()))
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

        let log_peer = if let Some(name) = &peer.name {
            log_dev.new(slog::o!("peer" => format!("{:}", name)))
        } else {
            log_dev.new(slog::o!("peer" => format!("{:}", remote_pkey)))
        };

        let (public_socket, local_out_port) = get_inet_socket(&log_peer).await?;

        let (to_inet_tx, from_inet_rx) = split_udp_socket(public_socket);
        let (stun_rx, data_inet_rx) = split_inet_rx(from_inet_rx);
        let public_address_r = setup_stun(
            &log_peer,
            stun_flags,
            to_inet_tx.clone(),
            stun_rx,
            local_out_port,
            false,
        )
        .await?;

        let connections: Arc<RwAddrConnections> = Arc::new(RwLock::new(HashSet::new()));

        let lo_port = peer.local_port;
        debug!(log_peer, "Connection local port is"; "port" => lo_port);
        let log_out = log_peer.new(slog::o!("traffic" => "outbound"));
        let local_pair =
            new_local_socket(log_out, to_inet_tx, lo_port, connections.clone()).await?;
        let log_fwd = log_peer.new(slog::o!("traffic" => "inbound"));
        spawn(forward_inbound_traffic(
            log_fwd,
            data_inet_rx,
            connections.clone(),
            local_pair,
        ));
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
    let dht = OpenDht::new(dht_log, flags.opendht_port, flags.bootstrap_addr.clone())
        .await
        .context("Initializing DHT failed")?;

    Ok(dht)
}

fn get_generate_file(flags: &GenFlags) -> anyhow::Result<(Option<File>, Option<File>)> {
    let file = match &flags.path {
        Some(path) => {
            let mut opts = OpenOptions::new();
            if flags.override_files {
                opts.create(true);
            } else {
                opts.create_new(true);
            }

            Some(opts
                .write(true)
                .open(path)
                .context("Failed to open private key file for writing (and create new if not --override-files)")?)
        }
        None => None,
    };

    #[cfg(unix)]
    if !flags.insecure_priv
        && let Some(ref f) = file
    {
        let metadata = f.metadata()?;
        let mut permissions = metadata.permissions();

        permissions.set_mode(0o600);
        f.set_permissions(permissions)
            .context("Failed to set security permissions for private key file")?;
    }

    let pub_path = flags
        .pub_path
        .clone()
        .or_else(|| flags.path.clone().map(|path| path + ".pub"));
    let pub_file = match pub_path {
        Some(path) => {
            let mut opts = OpenOptions::new();
            if flags.override_files {
                opts.create(true);
            } else {
                opts.create_new(true);
            }

            Some(opts
                .write(true)
                .open(path)
                .context("Failed to open public key file for writing (and create new if not --override-files)")?)
        }
        None => None,
    };
    Ok((file, pub_file))
}

#[async_std::main]
async fn main() -> anyhow::Result<()> {
    if let Err(()) = sodiumoxide::init() {
        bail!("Initializing sodiumoxide failed");
    }

    let cfg = CliConfig::new()?;

    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    let log_level = if cfg.verbose {
        Level::Debug
    } else {
        Level::Info
    };
    let filtered_drain = LevelFilter::new(drain, log_level).fuse();
    let log = slog::Logger::root(filtered_drain, slog::o!());

    match cfg.command {
        Command::Generate { ref flags } => {
            let (sk, sk_base64, pk) = generate_secret_key_base64();
            let (priv_file, pub_file) = get_generate_file(&flags)?;

            if let Some(mut file) = priv_file {
                file.write_all(sk_base64.as_bytes())
                    .context("Failed to write base64 to secret key file")?;
            } else {
                info!(log, "SecretKey is {:}", sk_base64);
            }

            info!(log, "PublicKey is {:}", sk.public_key());
            if let Some(mut file) = pub_file {
                file.write_all(pk.to_string().as_bytes())
                    .context("Failed to write base64 to secret key file")?;
            }

            debug!(log, "PublicKey from library is {:}", pk);
            let new_sk = SecretKey::try_from(sk_base64.as_str())
                .expect("Failed at reloading a key just generated");
            debug!(
                log,
                "PublicKey after reloading from displayed secret is {:}",
                new_sk.public_key()
            )
        }
        Command::Stun { ref flags } => {
            let log_dev = log.new(slog::o!("dev" => "stun"));

            let (public_socket, local_out_port) = get_inet_socket(&log_dev).await?;
            let (to_inet_tx, from_inet_rx) = split_udp_socket(public_socket);

            let mut public_address_r = setup_stun(
                &log_dev,
                flags,
                to_inet_tx,
                from_inet_rx,
                local_out_port,
                true,
            )
            .await?;

            let public_address = public_address_r.recv().await;
            info!(log, "Got public address result {:?}", public_address);
            // To get the final log print.
            drop(log);
            std::thread::sleep(std::time::Duration::from_secs(2));
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
