mod app;
mod candidates;
mod config;
mod crypto;
mod dht;
mod keygen;
mod message;
mod nat;
mod probe;
mod service;
mod stun;
mod transport;
mod utils;

fn main() -> anyhow::Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(app::run())
}
