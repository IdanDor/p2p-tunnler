pub mod codec;

use anyhow::{anyhow, bail};

use slog::debug;

use std::net::{IpAddr, SocketAddr};
use std::sync::LazyLock;
use std::time::Duration;
use std::time::Instant;

use rand::{RngExt, rngs::SmallRng};

use tokio::sync::Mutex;

use crate::stun::codec::*;
use crate::utils::{UdpReceiver, UdpSender, try_send};

static RNG: LazyLock<Mutex<SmallRng>> = LazyLock::new(|| Mutex::new(rand::make_rng()));

pub struct Stun;

impl Stun {
    pub async fn lookup_public_address(
        &self,
        stun_log: &slog::Logger,
        to_inet_tx: &mut UdpSender,
        from_inet_rx: &mut UdpReceiver,
        stun_server: SocketAddr,
    ) -> anyhow::Result<SocketAddr> {
        let request = Request::Bind(BindRequest::default());
        match send_request(stun_log, to_inet_tx, from_inet_rx, stun_server, request).await? {
            Response::Bind(response) => Ok(response.mapped_address),
        }
    }
}

async fn send_request(
    stun_log: &slog::Logger,
    to_inet_tx: &mut UdpSender,
    from_inet_rx: &mut UdpReceiver,
    stun_server: SocketAddr,
    req: Request,
) -> Result<Response, anyhow::Error> {
    let id: u64 = {
        let mut rng = RNG.lock().await;
        rng.random()
    };

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
            Ok(Some((buf, source))) => {
                if !is_expected_stun_source(source, stun_server) {
                    debug!(stun_log, "Ignoring STUN response from unexpected source"; "src" => source, "expected" => stun_server, "bytes" => buf.len());
                    continue;
                }
                debug!(stun_log, "Received STUN response"; "src" => source, "bytes" => buf.len());
                if let Some(response) = StunCodec::decode_const(id, &buf)? {
                    return Ok(response);
                }
            }
        }
    }

    Err(anyhow!("Failed to get stun response"))
}

fn is_expected_stun_source(source: SocketAddr, stun_server: SocketAddr) -> bool {
    normalize_ipv4_mapped_source(source) == stun_server
}

/// A dual-stack socket can report an IPv4 peer as an IPv4-mapped IPv6 address.
/// STUN is configured with an IPv4 server address, so compare that form as IPv4.
fn normalize_ipv4_mapped_source(source: SocketAddr) -> SocketAddr {
    let SocketAddr::V6(source_v6) = source else {
        return source;
    };
    let Some(ipv4) = source_v6.ip().to_ipv4_mapped() else {
        return source;
    };
    SocketAddr::new(IpAddr::V4(ipv4), source_v6.port())
}

#[cfg(test)]
mod tests {
    use super::is_expected_stun_source;
    use std::net::SocketAddr;

    #[test]
    fn accepts_only_the_configured_stun_server() {
        let server: SocketAddr = "192.0.2.1:3478".parse().unwrap();
        assert!(is_expected_stun_source(server, server));
        assert!(!is_expected_stun_source(
            "192.0.2.2:3478".parse().unwrap(),
            server
        ));
        assert!(!is_expected_stun_source(
            "192.0.2.1:3479".parse().unwrap(),
            server
        ));
    }

    #[test]
    fn accepts_ipv4_mapped_source_from_dual_stack_socket() {
        let server: SocketAddr = "192.0.2.1:3478".parse().unwrap();
        assert!(is_expected_stun_source(
            "[::ffff:192.0.2.1]:3478".parse().unwrap(),
            server
        ));
        assert!(!is_expected_stun_source(
            "[::ffff:192.0.2.2]:3478".parse().unwrap(),
            server
        ));
        assert!(!is_expected_stun_source(
            "[::ffff:192.0.2.1]:3479".parse().unwrap(),
            server
        ));
    }
}
