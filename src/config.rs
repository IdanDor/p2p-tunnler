use clap::{Args, Parser, Subcommand};
use config::Config;
use serde::Deserialize;
use std::ffi::OsStr;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(version, about, long_about=None)]
pub struct CliConfig {
    #[arg(
        short,
        long,
        help = "Set verbosity to debug instead of info",
        global = true
    )]
    pub verbose: bool,
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
        long,
        default_value = "stun.wtfismyip.com:3478",
        help = "Stun server:ip to work with"
    )]
    pub stun_addr: String,
}

#[derive(Args, Debug)]
pub struct DhtFlags {
    #[arg(
        long,
        default_value = "bootstrap.jami.net:4222",
        help = "OpenDHT server:ip to bootstrap with"
    )]
    pub bootstrap_addr: String,
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

impl CliConfig {
    pub fn new() -> anyhow::Result<CliConfig> {
        let mut cli = CliConfig::parse();

        if let Command::Run(ref mut command) = cli.command {
            for tun in command.tunnels.iter() {
                let mut tun = tun.clone();
                if tun.extension() != Some(OsStr::new("yaml")) {
                    tun.add_extension("yaml");
                }

                let connection: P2PConnection = Config::builder()
                    .add_source(config::File::from(tun))
                    .build()?
                    .try_deserialize()?;

                command.connections.push(connection);
            }
        }

        Ok(cli)
    }
}
