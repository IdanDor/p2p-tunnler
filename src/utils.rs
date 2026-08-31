use std::future::Future;
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use anyhow::anyhow;
use futures::FutureExt;
use tokio::sync::{mpsc, watch};

pub const UDP_QUEUE_CAPACITY: usize = 256;

#[derive(Clone)]
pub struct TaskMonitor {
    failure_sender: watch::Sender<Option<TaskFailure>>,
}

#[derive(Clone, Debug)]
pub struct TaskFailure {
    pub task: &'static str,
    pub error: String,
}

impl TaskMonitor {
    pub fn new() -> (Self, watch::Receiver<Option<TaskFailure>>) {
        let (failure_sender, failure_receiver) = watch::channel(None);
        (Self { failure_sender }, failure_receiver)
    }

    fn report_failure(&self, task: &'static str, error: String) {
        self.failure_sender.send_if_modified(|failure| {
            if failure.is_some() {
                false
            } else {
                *failure = Some(TaskFailure { task, error });
                true
            }
        });
    }
}

pub fn spawn<F>(monitor: TaskMonitor, log: slog::Logger, task: &'static str, future: F)
where
    F: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    tokio::spawn(async move {
        match AssertUnwindSafe(future).catch_unwind().await {
            Ok(Ok(())) => {
                let error = "task ended unexpectedly".to_string();
                slog::error!(log, "Background task stopped"; "task" => task, "error" => error.clone());
                monitor.report_failure(task, error);
            }
            Ok(Err(error)) => {
                let error = format!("{error:#}");
                slog::error!(log, "Background task stopped"; "task" => task, "error" => error.clone());
                monitor.report_failure(task, error);
            }
            Err(_) => {
                let error = "task panicked".to_string();
                slog::error!(log, "Background task panicked"; "task" => task);
                monitor.report_failure(task, error);
            }
        }
    });
}

pub type UdpSender = mpsc::Sender<(Vec<u8>, SocketAddr)>;
pub type UdpReceiver = mpsc::Receiver<(bytes::Bytes, SocketAddr)>;

/// Enqueue a UDP datagram without allowing a congested peer to retain
/// unbounded application memory. Returning `Ok(false)` deliberately drops a
/// datagram; UDP already has lossy backpressure semantics.
pub fn try_send<T>(sender: &mpsc::Sender<T>, message: T) -> anyhow::Result<bool> {
    match sender.try_send(message) {
        Ok(()) => Ok(true),
        Err(mpsc::error::TrySendError::Full(_)) => Ok(false),
        Err(mpsc::error::TrySendError::Closed(_)) => Err(anyhow!("UDP task stopped")),
    }
}

pub fn split_udp_socket(
    monitor: TaskMonitor,
    log: slog::Logger,
    sock: tokio::net::UdpSocket,
) -> (UdpSender, UdpReceiver) {
    let (tx1, mut rx2) = mpsc::channel::<(Vec<u8>, SocketAddr)>(UDP_QUEUE_CAPACITY);
    let (tx2, rx1) = mpsc::channel::<(bytes::Bytes, SocketAddr)>(UDP_QUEUE_CAPACITY);

    let sock = Arc::new(sock);
    let sock1 = sock.clone();

    spawn(
        monitor.clone(),
        log.clone(),
        "UDP socket receiver",
        async move {
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let (n, peer) = sock.recv_from(&mut buf).await?;
                let b = bytes::Bytes::copy_from_slice(&buf[..n]);
                let _ = try_send(&tx2, (b, peer))?;
            }
        },
    );

    spawn(monitor, log, "UDP socket sender", async move {
        while let Some((buf, dst)) = rx2.recv().await {
            let n = sock1.send_to(&buf[..], dst).await?;
            anyhow::ensure!(
                n == buf.len(),
                "UDP socket sent {n} bytes of a {}-byte datagram",
                buf.len()
            );
        }
        Ok(())
    });

    (tx1, rx1)
}

#[cfg(test)]
mod tests {
    use super::{TaskMonitor, spawn, split_udp_socket, try_send};
    use anyhow::Context;
    use std::time::Duration;

    #[test]
    fn forwards_datagrams_in_both_directions() -> anyhow::Result<()> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let tunnel_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
                let tunnel_addr = tunnel_socket.local_addr()?;
                let log = slog::Logger::root(slog::Discard, slog::o!());
                let (monitor, _failure_receiver) = TaskMonitor::new();
                let (to_socket, mut from_socket) = split_udp_socket(monitor, log, tunnel_socket);
                let peer_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
                let peer_addr = peer_socket.local_addr()?;

                to_socket.send((b"outbound".to_vec(), peer_addr)).await?;
                let mut buffer = [0; 64];
                let (len, source) = tokio::time::timeout(
                    Duration::from_secs(1),
                    peer_socket.recv_from(&mut buffer),
                )
                .await
                .context("timed out waiting for the outbound datagram")??;
                assert_eq!(&buffer[..len], b"outbound");
                assert_eq!(source, tunnel_addr);

                peer_socket.send_to(b"inbound", tunnel_addr).await?;
                let (packet, source) =
                    tokio::time::timeout(Duration::from_secs(1), from_socket.recv())
                        .await
                        .context("timed out waiting for the inbound datagram")?
                        .context("UDP receiver closed before forwarding the inbound datagram")?;
                assert_eq!(&packet[..], b"inbound");
                assert_eq!(source, peer_addr);

                Ok(())
            })
    }

    #[test]
    fn drops_datagrams_when_a_bounded_queue_is_full() -> anyhow::Result<()> {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);

        assert!(try_send(&sender, 1)?);
        assert!(!try_send(&sender, 2)?);
        assert_eq!(receiver.try_recv()?, 1);

        Ok(())
    }

    #[test]
    fn reports_an_unexpected_clean_task_exit() -> anyhow::Result<()> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let (monitor, mut failures) = TaskMonitor::new();
                spawn(
                    monitor,
                    slog::Logger::root(slog::Discard, slog::o!()),
                    "clean exit",
                    async { Ok(()) },
                );

                tokio::time::timeout(Duration::from_secs(1), failures.changed()).await??;
                let failure = failures
                    .borrow_and_update()
                    .clone()
                    .expect("failure reported");
                assert_eq!(failure.task, "clean exit");
                assert_eq!(failure.error, "task ended unexpectedly");
                Ok(())
            })
    }

    #[test]
    fn reports_a_task_panic() -> anyhow::Result<()> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let (monitor, mut failures) = TaskMonitor::new();
                spawn(
                    monitor,
                    slog::Logger::root(slog::Discard, slog::o!()),
                    "panic",
                    async {
                        panic!("test panic");
                        #[allow(unreachable_code)]
                        Ok(())
                    },
                );

                tokio::time::timeout(Duration::from_secs(1), failures.changed()).await??;
                let failure = failures
                    .borrow_and_update()
                    .clone()
                    .expect("failure reported");
                assert_eq!(failure.task, "panic");
                assert_eq!(failure.error, "task panicked");
                Ok(())
            })
    }
}
