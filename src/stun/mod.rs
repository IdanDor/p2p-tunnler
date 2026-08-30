pub mod codec;

use anyhow::{anyhow, bail};

use slog::{debug, info};

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::sync::LazyLock;
use std::time::Duration;
use std::time::Instant;

use rand::{RngExt, rngs::SmallRng};

use tokio::sync::Mutex;

//pub const NETWORK_UNREACHABLE: i32 = 101;

use crate::stun::codec::*;
use crate::utils::{UdpReceiver, UdpSender, try_send};

static RNG: LazyLock<Mutex<SmallRng>> = LazyLock::new(|| Mutex::new(rand::make_rng()));

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum Connectivity {
    OpenInternet(SocketAddr),
    FullConeNat(SocketAddr),
    SymmetricNat,
    RestrictedPortNat(SocketAddr),
    RestrictedConeNat(SocketAddr),
    SymmetricFirewall(SocketAddr),
}

impl From<Connectivity> for Option<SocketAddr> {
    fn from(val: Connectivity) -> Self {
        match val {
            Connectivity::OpenInternet(addr) => Some(addr),
            Connectivity::FullConeNat(addr) => Some(addr),
            Connectivity::SymmetricNat => None,
            Connectivity::RestrictedPortNat(addr) => Some(addr),
            Connectivity::RestrictedConeNat(addr) => Some(addr),
            Connectivity::SymmetricFirewall(addr) => Some(addr),
        }
    }
}

pub struct Stun;

impl Stun {
    pub async fn lookup_public_address(
        &self,
        stun_log: &slog::Logger,
        to_inet_tx: &mut UdpSender,
        from_inet_rx: &mut UdpReceiver,
        stun_server: SocketAddr,
    ) -> anyhow::Result<Connectivity> {
        let bind_addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let conn = check(stun_log, to_inet_tx, from_inet_rx, bind_addr, stun_server).await?;
        Ok(conn)
    }
}

async fn check(
    stun_log: &slog::Logger,
    to_inet_tx: &mut UdpSender,
    from_inet_rx: &mut UdpReceiver,
    bind_addr: IpAddr,
    stun_server: SocketAddr,
) -> Result<Connectivity, anyhow::Error> {
    let resp = change_request(
        stun_log,
        to_inet_tx,
        from_inet_rx,
        stun_server,
        ChangeRequest::None,
    )
    .await?;
    if let Some(Response::Bind(resp)) = resp {
        let public_addr = resp.mapped_address;

        if bind_addr == public_addr.ip() {
            debug!(
                stun_log,
                "No NAT. Public IP ({}) == Bind IP ({})",
                bind_addr,
                public_addr.ip()
            );
            let resp = change_request(
                stun_log,
                to_inet_tx,
                from_inet_rx,
                stun_server,
                ChangeRequest::IpAndPort,
            )
            .await?;
            if resp.is_some() {
                info!(stun_log, "OpenInternet: {}", public_addr);
                return Ok(Connectivity::OpenInternet(public_addr));
            } else {
                info!(stun_log, "SymmetricFirewall: {}", public_addr);
                return Ok(Connectivity::SymmetricFirewall(public_addr));
            }
        }
        debug!(
            stun_log,
            "Public IP ({}) != Bind IP ({})",
            bind_addr,
            public_addr.ip()
        );

        // NAT detected
        let resp = change_request(
            stun_log,
            to_inet_tx,
            from_inet_rx,
            stun_server,
            ChangeRequest::IpAndPort,
        )
        .await?;
        if resp.is_some() {
            info!(stun_log, "FullConeNat: {}", public_addr);
            return Ok(Connectivity::FullConeNat(public_addr));
        }

        debug!(stun_log, "No respone from different IP and Port");
        let resp = change_request(
            stun_log,
            to_inet_tx,
            from_inet_rx,
            stun_server,
            ChangeRequest::Port,
        )
        .await?;
        if let Some(Response::Bind(resp)) = resp {
            if resp.mapped_address.ip() != public_addr.ip() {
                info!(stun_log, "SymmetricNat");
                return Ok(Connectivity::SymmetricNat);
            }

            let resp = change_request(
                stun_log,
                to_inet_tx,
                from_inet_rx,
                stun_server,
                ChangeRequest::Port,
            )
            .await?;
            if resp.is_some() {
                info!(stun_log, "RestrictedConeNat: {}", public_addr);
                Ok(Connectivity::RestrictedConeNat(public_addr))
            } else {
                info!(stun_log, "RestrictedPortNat: {}", public_addr);
                Ok(Connectivity::RestrictedPortNat(public_addr))
            }
        } else {
            Err(anyhow!(
                "Expected Some(BindResponse) but got {:?} instead!",
                resp
            ))
        }
    } else {
        Err(anyhow!("Network unreachable"))
    }
}

async fn change_request(
    stun_log: &slog::Logger,
    to_inet_tx: &mut UdpSender,
    from_inet_rx: &mut UdpReceiver,
    stun_server: SocketAddr,
    req: ChangeRequest,
) -> Result<Option<Response>, anyhow::Error> {
    let req = codec::Request::Bind(BindRequest {
        change_request: req,
        ..Default::default()
    });

    send_request(stun_log, to_inet_tx, from_inet_rx, stun_server, req).await
}

async fn send_request(
    stun_log: &slog::Logger,
    to_inet_tx: &mut UdpSender,
    from_inet_rx: &mut UdpReceiver,
    stun_server: SocketAddr,
    req: Request,
) -> Result<Option<Response>, anyhow::Error> {
    let mut lock = RNG.lock().await;
    let id: u64 = lock.random();

    let mut buf = bytes::BytesMut::new();
    StunCodec::encode((id, req.clone()), &mut buf)?;
    if !try_send(to_inet_tx, (buf.to_vec(), stun_server))? {
        bail!("STUN request dropped because the UDP send queue is full");
    }

    let start = Instant::now();

    loop {
        let dur = Duration::from_secs(3).checked_sub(Instant::now() - start);
        let dur = dur.unwrap_or(Duration::from_secs(0));
        match tokio::time::timeout(dur, from_inet_rx.recv()).await {
            Err(_) => {
                debug!(stun_log, "STUN request timed out");
                break;
            }
            Ok(None) => {
                debug!(stun_log, "STUN socket receiver closed");
                break;
            }
            Ok(Some((buf, _src))) => {
                let buf = buf.into_iter().collect();
                debug!(stun_log, "Got packet for stun {:?}", buf);
                if let Some(resp) = StunCodec::decode_const(id, buf)? {
                    return Ok(Some(resp));
                } else {
                    continue;
                }
            }
        }
    }

    Err(anyhow!("Failed to get stun response"))
}
