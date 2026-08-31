use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use rand::RngExt;
use tokio::sync::Mutex;

use crate::utils::{UdpReceiver, UdpSender, try_send};

pub const MAGIC: [u8; 4] = *b"P2PC";
pub const FRAME_LEN: usize = 20;
const MAX_PROBE_PATHS: usize = 64;
const MAX_REPLY_SOURCES: usize = 256;
const REPLY_INTERVAL: Duration = Duration::from_secs(1);
const ACK_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone)]
pub struct ProbeController {
    inner: Arc<Mutex<State>>,
}

struct State {
    local_token: [u8; 16],
    remote_token: Option<[u8; 16]>,
    paths: HashMap<SocketAddr, Path>,
    reply_sources: HashMap<SocketAddr, Instant>,
}

struct Path {
    next_probe: Instant,
    outstanding: Option<Instant>,
    verified: bool,
    fast_stage: u8,
    last_control_response: Option<Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PacketAction {
    Echo,
    Acknowledged,
    Drop,
}

impl ProbeController {
    pub fn new() -> Self {
        let mut rng = rand::rng();
        let local_token = rng.random();
        Self {
            inner: Arc::new(Mutex::new(State {
                local_token,
                remote_token: None,
                paths: HashMap::new(),
                reply_sources: HashMap::new(),
            })),
        }
    }

    pub async fn local_token_base64(&self) -> String {
        use base64::{Engine, engine::general_purpose};
        general_purpose::STANDARD.encode(self.inner.lock().await.local_token)
    }

    /// Replaces the set learned from the most recent authenticated DHT record.
    /// A missing or invalid extension deliberately leaves the peer data-plane
    /// compatible but disables control probes for that record.
    pub async fn update_remote(&self, token: Option<[u8; 16]>, candidates: Vec<SocketAddr>) {
        let mut state = self.inner.lock().await;
        if state.remote_token != token {
            state.paths.clear();
            state.remote_token = token;
        }
        let Some(_) = state.remote_token else {
            state.paths.clear();
            return;
        };

        let now = Instant::now();
        let mut selected = HashSet::new();
        for candidate in candidates {
            if selected.len() == MAX_PROBE_PATHS {
                break;
            }
            selected.insert(candidate);
        }
        state.paths.retain(|address, _| selected.contains(address));
        for address in selected {
            state.paths.entry(address).or_insert(Path {
                next_probe: now,
                outstanding: None,
                verified: false,
                fast_stage: 0,
                last_control_response: None,
            });
        }
    }

    async fn packet_action(&self, packet: &[u8], source: SocketAddr) -> PacketAction {
        let Some(token) = parse_frame(packet) else {
            return PacketAction::Drop;
        };
        let mut state = self.inner.lock().await;
        let now = Instant::now();
        state
            .reply_sources
            .retain(|_, last| now.duration_since(*last) < REPLY_INTERVAL);
        if token == state.local_token {
            if state.reply_sources.len() >= MAX_REPLY_SOURCES
                && !state.reply_sources.contains_key(&source)
            {
                return PacketAction::Drop;
            }
            if state
                .reply_sources
                .insert(source, now)
                .is_some_and(|last| now.duration_since(last) < REPLY_INTERVAL)
            {
                return PacketAction::Drop;
            }
            return PacketAction::Echo;
        }
        if state.remote_token != Some(token) {
            return PacketAction::Drop;
        }
        let Some(path) = state.paths.get_mut(&source) else {
            return PacketAction::Drop;
        };
        if path.outstanding.is_none() {
            return PacketAction::Drop;
        }
        path.outstanding = None;
        path.verified = true;
        path.fast_stage = 0;
        path.next_probe = now + jitter(Duration::from_secs(15));
        path.last_control_response = Some(now);
        PacketAction::Acknowledged
    }

    async fn due_frames(&self) -> Vec<(Vec<u8>, SocketAddr)> {
        let mut state = self.inner.lock().await;
        let Some(remote_token) = state.remote_token else {
            return Vec::new();
        };
        let now = Instant::now();
        let mut destinations = Vec::new();
        for (address, path) in &mut state.paths {
            if path.verified
                && path
                    .outstanding
                    .is_some_and(|sent| now.duration_since(sent) >= ACK_TIMEOUT)
            {
                path.verified = false;
                path.fast_stage = 0;
                path.outstanding = None;
                path.next_probe = now;
            }
            if now < path.next_probe {
                continue;
            }
            path.outstanding = Some(now);
            path.next_probe = if path.verified {
                now + jitter(Duration::from_secs(15))
            } else {
                let delay = match path.fast_stage {
                    0 => Duration::from_secs(1),
                    1 => Duration::from_secs(2),
                    _ => jitter(Duration::from_secs(5)),
                };
                path.fast_stage = path.fast_stage.saturating_add(1);
                now + delay
            };
            destinations.push((frame(remote_token).to_vec(), *address));
        }
        destinations
    }
}

pub fn classify(packet: &[u8]) -> bool {
    packet.starts_with(&MAGIC)
}

pub fn parse_frame(packet: &[u8]) -> Option<[u8; 16]> {
    if packet.len() != FRAME_LEN || !packet.starts_with(&MAGIC) {
        return None;
    }
    packet[4..].try_into().ok()
}

pub fn frame(token: [u8; 16]) -> [u8; FRAME_LEN] {
    let mut frame = [0; FRAME_LEN];
    frame[..4].copy_from_slice(&MAGIC);
    frame[4..].copy_from_slice(&token);
    frame
}

pub fn decode_token(token: &str) -> Option<[u8; 16]> {
    use base64::{Engine, engine::general_purpose};
    general_purpose::STANDARD
        .decode(token)
        .ok()?
        .try_into()
        .ok()
}

pub async fn handle_packets(
    log: slog::Logger,
    controller: ProbeController,
    mut from_internet: UdpReceiver,
    to_internet: UdpSender,
) -> Result<()> {
    while let Some((packet, source)) = from_internet.recv().await {
        match controller.packet_action(&packet, source).await {
            PacketAction::Echo => {
                let _ = try_send(&to_internet, (packet.to_vec(), source))?;
            }
            PacketAction::Acknowledged => {
                slog::info!(log, "Control path verified this run"; "source" => source);
            }
            PacketAction::Drop => {}
        }
    }
    anyhow::bail!("control UDP receiver stopped")
}

pub async fn schedule_probes(controller: ProbeController, to_internet: UdpSender) -> Result<()> {
    let mut timer = tokio::time::interval(Duration::from_millis(100));
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        timer.tick().await;
        for datagram in controller.due_frames().await {
            let _ = try_send(&to_internet, datagram)?;
        }
    }
}

fn jitter(interval: Duration) -> Duration {
    let percent: u32 = rand::rng().random_range(90..=110);
    interval.mul_f64(f64::from(percent) / 100.0)
}

#[cfg(test)]
mod tests {
    use super::{
        FRAME_LEN, PacketAction, ProbeController, classify, decode_token, frame, parse_frame,
    };
    use std::net::SocketAddr;

    #[test]
    fn frames_are_exact_and_malformed_control_frames_stay_control() {
        let token = [7; 16];
        let packet = frame(token);
        assert_eq!(packet.len(), FRAME_LEN);
        assert_eq!(parse_frame(&packet), Some(token));
        assert!(classify(&packet));
        assert!(classify(b"P2PC-short"));
        assert_eq!(parse_frame(b"P2PC-short"), None);
        assert!(!classify(b"not-control"));
    }

    #[test]
    fn accepts_only_exactly_sized_base64_tokens() {
        assert_eq!(decode_token("AAAAAAAAAAAAAAAAAAAAAA=="), Some([0; 16]));
        assert_eq!(decode_token("AAAA"), None);
        assert_eq!(decode_token("not base64"), None);
    }

    #[test]
    fn request_is_echoed_but_unknown_packets_are_dropped() -> anyhow::Result<()> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let controller = ProbeController::new();
                let token = decode_token(&controller.local_token_base64().await).unwrap();
                let source: SocketAddr = "192.0.2.10:12345".parse().unwrap();
                assert_eq!(
                    controller.packet_action(&frame(token), source).await,
                    PacketAction::Echo
                );
                assert_eq!(
                    controller.packet_action(&frame([9; 16]), source).await,
                    PacketAction::Drop
                );
                Ok(())
            })
    }

    #[test]
    fn acknowledgement_must_match_an_outstanding_same_family_path() -> anyhow::Result<()> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let controller = ProbeController::new();
                let remote = [5; 16];
                let ipv4: SocketAddr = "192.0.2.10:12345".parse().unwrap();
                let ipv6: SocketAddr = "[2001:db8::10]:12345".parse().unwrap();
                controller.update_remote(Some(remote), vec![ipv4]).await;
                assert_eq!(
                    controller.packet_action(&frame(remote), ipv4).await,
                    PacketAction::Drop
                );
                let frames = controller.due_frames().await;
                assert_eq!(frames.len(), 1);
                assert_eq!(
                    controller.packet_action(&frame(remote), ipv6).await,
                    PacketAction::Drop
                );
                assert_eq!(
                    controller.packet_action(&frame(remote), ipv4).await,
                    PacketAction::Acknowledged
                );
                Ok(())
            })
    }
}
