use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use async_std::channel::{Receiver, Sender};
use async_std::prelude::*;

pub fn spawn<F>(future: F)
where
    F: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    let _handle = async_std::task::spawn(async {
        if let Err(e) = future.await {
            unimplemented!("Task failed: {:?}", e);
            //            todo!() //error!("Task failed: {:?}", e);
        }
    });
    // TODO: what to do with handle?
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

pub type UdpSender = Sender<(Vec<u8>, SocketAddr)>;
pub type UdpReceiver = Receiver<(bytes::Bytes, SocketAddr)>;

pub fn split_udp_socket(sock: async_std::net::UdpSocket) -> (UdpSender, UdpReceiver) {
    let (tx1, rx2) = async_std::channel::unbounded();
    let (tx2, rx1) = async_std::channel::unbounded();

    let sock = Arc::new(sock);
    let sock1 = sock.clone();

    spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let (n, peer) = sock.recv_from(&mut buf).await?;
            let b = bytes::Bytes::copy_from_slice(&buf[..n]);
            tx2.send((b, peer)).await?
        }
    });

    spawn(async move {
        loop {
            let (buf, dst): (Vec<u8>, SocketAddr) = rx2.recv().await?;
            let n = sock1.send_to(&buf[..], dst).await?;
            assert_eq!(buf.len(), n);
        }
    });

    (tx1, rx1)
}
