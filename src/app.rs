use futures::stream::StreamExt;
use slog::{Drain, Level, LevelFilter};

use crate::candidates::{StunSetup, start_stun_candidates};
use crate::config::{CliConfig, Command};
use crate::keygen;
use crate::service;
use crate::transport::open_internet_socket;
use crate::utils::TaskMonitor;

pub async fn run() -> anyhow::Result<()> {
    let config = CliConfig::new()?;
    let log = create_logger(config.verbose);

    match config.command {
        Command::Generate { flags } => keygen::generate(&log, &flags),
        Command::Stun { flags } => run_stun(&log, &flags).await,
        Command::Dht { flags } => run_dht_diagnostic(&log, &flags).await,
        Command::Run(command) => service::run(&log, &command).await,
    }
}

fn create_logger(verbose: bool) -> slog::Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let level = if verbose { Level::Debug } else { Level::Info };
    slog::Logger::root(LevelFilter::new(drain, level).fuse(), slog::o!())
}

async fn run_stun(log: &slog::Logger, flags: &crate::config::StunFlags) -> anyhow::Result<()> {
    let log = log.new(slog::o!("dev" => "stun"));
    let (socket, local_port) = open_internet_socket(&log, 0).await?;
    let (monitor, _failures) = TaskMonitor::new();
    let (to_internet, from_internet) =
        crate::utils::split_udp_socket(monitor.clone(), log.clone(), socket);
    let mut candidates = start_stun_candidates(
        monitor,
        &log,
        flags,
        StunSetup {
            to_internet,
            from_internet,
            local_port,
            gather_ipv6: true,
            nat_mapping: None,
            run_once: true,
        },
    )
    .await?;

    slog::info!(
        log,
        "Got public address result {:?}",
        candidates.recv().await
    );
    // Let the asynchronous terminal drain flush the final result before this
    // short-lived diagnostic command exits.
    std::thread::sleep(std::time::Duration::from_secs(2));
    Ok(())
}

async fn run_dht_diagnostic(
    log: &slog::Logger,
    flags: &crate::config::DhtFlags,
) -> anyhow::Result<()> {
    let (monitor, _failures) = TaskMonitor::new();
    let dht = service::start_dht(log, monitor, flags).await?;
    let key = [9, 9, 9];
    let value = [1, 1, 1, 2];
    dht.put(&key, &value).await?;
    slog::debug!(log, "put done: {:?}", value);

    let mut values = dht.get(key.to_vec());
    while let Some(value) = values.next().await {
        slog::debug!(log, "{:?}", value);
    }
    Ok(())
}
