use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use futures::StreamExt;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

pub fn spawn<F>(log: slog::Logger, task: &'static str, future: F)
where
    F: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    tokio::spawn(async move {
        if let Err(error) = future.await {
            slog::error!(log, "Background task stopped"; "task" => task, "error" => format!("{error:#}"));
        }
    });
}

pub fn batches<T: Unpin, S: futures::Stream<Item = T> + Unpin>(
    mut stream: S,
) -> impl futures::Stream<Item = impl Iterator<Item = T>> {
    async_stream::stream! {
        loop {
            while let Some(res) = stream.next().await {
                yield vec![res].into_iter();
            }
        }
    }
}

pub type UdpSender = UnboundedSender<(Vec<u8>, SocketAddr)>;
pub type UdpReceiver = UnboundedReceiver<(bytes::Bytes, SocketAddr)>;

pub fn split_udp_socket(
    log: slog::Logger,
    sock: tokio::net::UdpSocket,
) -> (UdpSender, UdpReceiver) {
    let (tx1, mut rx2) = tokio::sync::mpsc::unbounded_channel::<(Vec<u8>, SocketAddr)>();
    let (tx2, rx1) = tokio::sync::mpsc::unbounded_channel::<(bytes::Bytes, SocketAddr)>();

    let sock = Arc::new(sock);
    let sock1 = sock.clone();

    spawn(log.clone(), "UDP socket receiver", async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let (n, peer) = sock.recv_from(&mut buf).await?;
            let b = bytes::Bytes::copy_from_slice(&buf[..n]);
            tx2.send((b, peer))?
        }
    });

    spawn(log, "UDP socket sender", async move {
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
    use super::split_udp_socket;
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
                let (to_socket, mut from_socket) = split_udp_socket(log, tunnel_socket);
                let peer_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
                let peer_addr = peer_socket.local_addr()?;

                to_socket.send((b"outbound".to_vec(), peer_addr))?;
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
}
