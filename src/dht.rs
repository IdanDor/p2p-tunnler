use futures::{Stream, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::utils::{TaskMonitor, spawn};

#[derive(Clone)]
pub struct OpenDht {
    dht: Arc<opendht::OpenDht>,
}

impl OpenDht {
    pub async fn new(
        monitor: TaskMonitor,
        log: slog::Logger,
        listen_port: u16,
        bootstrap_servers: impl tokio::net::ToSocketAddrs,
    ) -> anyhow::Result<OpenDht> {
        let dht = opendht::OpenDht::new(listen_port)?;
        let dht = Arc::new(dht);

        let servers: Vec<SocketAddr> = tokio::net::lookup_host(bootstrap_servers).await?.collect();
        slog::debug!(log, "OpenDHT bootstrapping...");
        if dht.bootstrap(&servers).await.is_err() {
            anyhow::bail!("Failed to bootstrap using {:?}", servers);
        }
        slog::info!(log, "OpenDHT bootstrapping done");

        let dht2 = dht.clone();
        spawn(monitor, log, "OpenDHT tick loop", async move {
            while let Some(next) = dht2.tick() {
                tokio::time::sleep(next).await;
            }
            anyhow::bail!("OpenDHT tick loop ended")
        });

        Ok(OpenDht { dht })
    }

    pub fn get(&self, key: Vec<u8>) -> impl Stream<Item = Vec<u8>> {
        self.dht.get(&key[..]).boxed()
    }

    pub fn listen(&self, key: Vec<u8>) -> Box<dyn Stream<Item = Vec<u8>> + Send + Unpin> {
        Box::new(self.dht.listen(&key[..]))
    }

    pub async fn put(&self, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
        self.dht.put(key, value).await?;
        Ok(())
    }
}
