use async_std::prelude::*;
use async_trait::async_trait;
use clap::{Args, Parser, Subcommand};
use config::Config;
use serde::Deserialize;
use slog::debug;
use std::ffi::OsStr;
use std::path::PathBuf;
use wireguard_uapi::RouteSocket;

use crate::api;
use crate::api::*;
use crate::wg_device::WireguardDev;

#[derive(Parser, Debug)]
#[command(version, about, long_about=None)]
pub struct CliConfig {
    #[arg(
        short = 'f',
        long = "ifnames",
        value_delimiter = ',',
        help = "Restrict to thses devices [default: all]"
    )]
    pub interfaces: Vec<String>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    #[command(alias="gen", about="Generate and print a new secret and public key", long_about=None)]
    Generate,

    #[command(about="Run a stun IP test to get current IP", long_about=None)]
    Stun {
        #[command(flatten)]
        flags: StunFlags,
    },

    #[command(about="Connect to opendht network", long_about=None)]
    Dht {
        #[command(flatten)]
        flags: DhtFlags,
    },

    #[command(about="Run service", long_about=None)]
    Run(RunCommand),
}

#[derive(Args, Debug)]
pub struct StunFlags {
    #[arg(
        long = "stun_addr",
        default_value = "stun.wtfismyip.com:3478",
        help = "Stun server:ip to work with"
    )]
    pub stun_addr: String,
}

#[derive(Args, Debug)]
pub struct DhtFlags {
    #[arg(
        long = "bootstrap_ip",
        default_value = "bootstrap.jami.net:4222",
        help = "OpenDHT server:ip to bootstrap with"
    )]
    pub bootstrap_ip: String,
    #[arg(
        short = 'P',
        long = "port",
        default_value = "4222",
        help = "OpenDHT listen port"
    )]
    pub opendht_port: u16,
}

#[derive(Args, Debug)]
pub struct RunCommand {
    #[command(flatten)]
    pub stun_flags: StunFlags,

    #[command(flatten)]
    pub dht_flags: DhtFlags,

    #[arg(
        default_value = "./tunnels.yaml",
        help = "YAML config file describing connections, .yaml is appended if not given"
    )]
    tunnels: Vec<PathBuf>,

    #[arg(skip)]
    pub connections: Vec<P2PConnection>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct P2PConnection {
    pub secret_key: String,
    pub peers: Vec<Peer>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Peer {
    pub local_port: u16,
    pub public_key: String,
    pub name: Option<String>,
}

pub struct GlobalConfig {
    log: slog::Logger,
    pub inner: CliConfig,
}

impl GlobalConfig {
    pub fn new(log: slog::Logger) -> anyhow::Result<GlobalConfig> {
        let mut cli = CliConfig::parse();

        if let Command::Run(ref mut command) = cli.command {
            for tun in command.tunnels.iter() {
                let mut tun = tun.clone();
                if tun.extension() != Some(&OsStr::new("yaml")) {
                    tun.add_extension("yaml");
                }

                let connection: P2PConnection = Config::builder()
                    .add_source(config::File::from(tun))
                    .build()?
                    .try_deserialize()?;

                debug!(log, "Tunnels configuration {:?}", connection);
                command.connections.push(connection);
            }
        }
        // let matches = clap::App::new("wiregurad-p2p")
        //     .arg(clap::Arg::with_name("interfaces")
        //         .short("i")
        //         .long("ifnames")
        //         .takes_value(true)
        //         .help("Restrict to these devices [default: all]"))
        //     .arg(clap::Arg::with_name("opendht_port")
        //         .short("P")
        //         .default_value("4222")
        //         .help("OpenDHt listen port"))
        //     .get_matches();

        // let interfaces = matches.value_of("interfaces").map(|ifnames| {
        //     ifnames.split(',').map(String::from).collect()
        // });

        // let opendht_port = matches.value_of("opendht_port").unwrap();
        // let opendht_port = str::parse(opendht_port)?;

        Ok(GlobalConfig { log, inner: cli })
    }
}

#[async_trait]
impl api::ConfigApi for GlobalConfig {
    fn get_wireguard_devices(
        &self,
    ) -> anyhow::Result<Box<dyn Stream<Item = (Box<dyn WireguardDevice>, DeviceConfig)> + Unpin>>
    {
        if !self.inner.interfaces.is_empty() {
            let vec: Result<Vec<_>, _> = self
                .inner
                .interfaces
                .iter()
                .map(|ifname| WireguardDev::new(ifname.to_string()).map(|d| d.as_trait()))
                .collect();
            let it = vec?.into_iter().map(|dev| (dev, DeviceConfig {}));
            let s = futures::stream::iter(it);
            return Ok(Box::new(s));
        }

        debug!(self.log, "RouteSocket::connect()...");
        let mut c = RouteSocket::connect()?;
        debug!(self.log, "RouteSocket::connect() done.");

        let vec: anyhow::Result<Vec<Box<dyn WireguardDevice>>>;
        vec = c
            .list_device_names()?
            .into_iter()
            .map(|ifname| WireguardDev::new(ifname).map(|d| d.as_trait()))
            .collect();
        debug!(
            self.log,
            "Found {:?} devices.",
            vec.as_ref().map(|v| v.len())
        );

        let it = vec?.into_iter().map(|dev| (dev, DeviceConfig {}));

        let stream = futures::stream::iter(it);
        Ok(Box::new(stream))
    }
}
