use anyhow::{Context, anyhow, bail};
use crab_nat::{
    GatewayAddress, InternetProtocol, PortMapping, PortMappingOptions, PortMappingType,
    TimeoutConfig, natpmp,
};
use igd_next::{PortMappingProtocol, SearchOptions};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::num::NonZeroU16;
use std::sync::mpsc;
use std::time::Duration;

const MAPPING_LIFETIME_SECONDS: u32 = 7_200;
const MAPPING_RENEWAL_MINIMUM: Duration = Duration::from_secs(60);
const GATEWAY_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(4);
const MAPPING_TIMEOUT: TimeoutConfig = TimeoutConfig {
    initial_timeout: Duration::from_millis(250),
    max_retries: 2,
    max_retry_timeout: Some(Duration::from_secs(1)),
};

#[derive(Clone, Copy, Debug)]
pub struct Mapping {
    pub external_addr: SocketAddr,
    pub method: Method,
}

#[derive(Clone, Copy, Debug)]
pub enum Method {
    Pcp,
    NatPmp,
    UpnpIgd,
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Method::Pcp => write!(f, "PCP"),
            Method::NatPmp => write!(f, "NAT-PMP"),
            Method::UpnpIgd => write!(f, "UPnP IGD"),
        }
    }
}

/// Creates and maintains a UDP mapping in a detached worker thread.
///
/// The mapping stays owned by the worker so it can be renewed without any
/// privileged host operation. If the process is not shut down cleanly, the
/// router expires the mapping after its requested lease time.
pub async fn map_udp_port(log: slog::Logger, port: u16) -> anyhow::Result<Mapping> {
    let port = NonZeroU16::new(port).context("Cannot request a NAT mapping for UDP port 0")?;
    let (sender, receiver) = mpsc::sync_channel(1);

    std::thread::Builder::new()
        .name("p2p-tunnler-nat-map".to_string())
        .spawn(move || mapping_worker(log, port, sender))
        .context("Failed to start NAT mapping worker")?;

    async_std::task::spawn_blocking(move || {
        receiver
            .recv()
            .map_err(|_| anyhow!("NAT mapping worker stopped before returning a result"))?
    })
    .await
}

fn mapping_worker(
    log: slog::Logger,
    port: NonZeroU16,
    sender: mpsc::SyncSender<anyhow::Result<Mapping>>,
) {
    match try_pcp_natpmp(port) {
        Ok((mapping, runtime, lease)) => {
            let _ = sender.send(Ok(mapping));
            renew_pcp_natpmp(log, runtime, lease);
        }
        Err(pcp_error) => match try_upnp_igd(port) {
            Ok((mapping, gateway, local_addr)) => {
                let _ = sender.send(Ok(mapping));
                renew_upnp_igd(log, gateway, mapping.external_addr.port(), local_addr);
            }
            Err(upnp_error) => {
                let _ = sender.send(Err(anyhow!(
                    "No PCP/NAT-PMP or UPnP IGD mapping was available; PCP/NAT-PMP: {pcp_error:#}; UPnP IGD: {upnp_error:#}"
                )));
            }
        },
    }
}

fn try_pcp_natpmp(
    port: NonZeroU16,
) -> anyhow::Result<(Mapping, tokio::runtime::Runtime, PortMapping)> {
    let (gateway, client) = default_ipv4_gateway_and_client()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .context("Failed to initialize the PCP/NAT-PMP runtime")?;
    let gateway = GatewayAddress::IpV4(gateway);
    let options = PortMappingOptions {
        external_port: Some(port),
        lifetime_seconds: Some(MAPPING_LIFETIME_SECONDS),
        timeout_config: Some(MAPPING_TIMEOUT),
    };

    let mapping: PortMapping = runtime.block_on(async {
        match PortMapping::new(
            gateway,
            IpAddr::V4(client),
            InternetProtocol::Udp,
            port,
            options,
        )
        .await
        {
            Ok(mapping) => Ok(mapping),
            // A PCP timeout/error does not prove that NAT-PMP is unavailable,
            // so deliberately attempt the older protocol as a second step.
            Err(_) => natpmp::port_mapping(gateway, InternetProtocol::Udp, port, options)
                .await
                .map_err(anyhow::Error::from),
        }
    })?;

    let external_ip: IpAddr = runtime.block_on(async {
        match mapping.mapping_type() {
            PortMappingType::Pcp { external_ip, .. } => Ok(external_ip),
            PortMappingType::NatPmp => natpmp::external_address(gateway, Some(MAPPING_TIMEOUT))
                .await
                .map(IpAddr::V4)
                .map_err(anyhow::Error::from),
        }
    })?;

    let method = match mapping.mapping_type() {
        PortMappingType::Pcp { .. } => Method::Pcp,
        PortMappingType::NatPmp => Method::NatPmp,
    };
    Ok((
        Mapping {
            external_addr: SocketAddr::new(external_ip, mapping.external_port().get()),
            method,
        },
        runtime,
        mapping,
    ))
}

fn renew_pcp_natpmp(log: slog::Logger, runtime: tokio::runtime::Runtime, mut mapping: PortMapping) {
    loop {
        let renewal_delay =
            Duration::from_secs(u64::from(mapping.lifetime()) / 2).max(MAPPING_RENEWAL_MINIMUM);
        std::thread::sleep(renewal_delay);

        if let Err(error) = runtime.block_on(mapping.renew()) {
            slog::error!(log, "NAT mapping renewal failed"; "error" => format!("{error:#}"));
            return;
        }
        slog::debug!(log, "NAT mapping renewed"; "method" => format!("{:?}", mapping.mapping_type()));
    }
}

fn try_upnp_igd(port: NonZeroU16) -> anyhow::Result<(Mapping, igd_next::Gateway, SocketAddr)> {
    let (_, client) = default_ipv4_gateway_and_client()?;
    let local_addr = SocketAddr::new(IpAddr::V4(client), port.get());
    let gateway = igd_next::search_gateway(SearchOptions {
        timeout: Some(GATEWAY_DISCOVERY_TIMEOUT),
        single_search_timeout: Some(GATEWAY_DISCOVERY_TIMEOUT),
        ..Default::default()
    })
    .context("UPnP IGD discovery failed")?;

    let external_addr = gateway
        .get_any_address(
            PortMappingProtocol::UDP,
            local_addr,
            MAPPING_LIFETIME_SECONDS,
            "p2p-tunnler",
        )
        .context("UPnP IGD port mapping failed")?;
    Ok((
        Mapping {
            external_addr,
            method: Method::UpnpIgd,
        },
        gateway,
        local_addr,
    ))
}

fn renew_upnp_igd(
    log: slog::Logger,
    gateway: igd_next::Gateway,
    external_port: u16,
    local_addr: SocketAddr,
) {
    loop {
        std::thread::sleep(Duration::from_secs(u64::from(MAPPING_LIFETIME_SECONDS) / 2));
        if let Err(error) = gateway.add_port(
            PortMappingProtocol::UDP,
            external_port,
            local_addr,
            MAPPING_LIFETIME_SECONDS,
            "p2p-tunnler",
        ) {
            slog::error!(log, "UPnP IGD mapping renewal failed"; "error" => format!("{error:#}"));
            return;
        }
        slog::debug!(log, "UPnP IGD mapping renewed"; "external_port" => external_port);
    }
}

fn default_ipv4_gateway_and_client() -> anyhow::Result<(Ipv4Addr, Ipv4Addr)> {
    let route_table = std::fs::read_to_string("/proc/net/route")
        .context("Failed to read /proc/net/route while discovering the IPv4 gateway")?;
    let gateway = parse_default_ipv4_gateway(&route_table)
        .context("No default IPv4 gateway was found in /proc/net/route")?;

    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.connect(SocketAddr::new(IpAddr::V4(gateway), crab_nat::GATEWAY_PORT))?;
    let IpAddr::V4(client) = socket.local_addr()?.ip() else {
        bail!("The default route did not select an IPv4 address")
    };
    Ok((gateway, client))
}

fn parse_default_ipv4_gateway(route_table: &str) -> Option<Ipv4Addr> {
    route_table.lines().skip(1).find_map(|line| {
        let mut fields = line.split_whitespace();
        let _interface = fields.next()?;
        let destination = fields.next()?;
        let gateway = fields.next()?;
        let flags = u16::from_str_radix(fields.next()?, 16).ok()?;
        if destination != "00000000" || flags & 0x2 == 0 {
            return None;
        }
        let gateway = u32::from_str_radix(gateway, 16).ok()?;
        Some(Ipv4Addr::from(gateway.to_le_bytes()))
    })
}

#[cfg(test)]
mod tests {
    use super::parse_default_ipv4_gateway;

    #[test]
    fn parses_the_default_ipv4_gateway() {
        let routes = "Iface\tDestination\tGateway\tFlags\n\
            wlan0\t00000000\t0101A8C0\t0003\n\
            wlan0\t0001A8C0\t00000000\t0001\n";

        assert_eq!(
            parse_default_ipv4_gateway(routes).unwrap().to_string(),
            "192.168.1.1"
        );
    }
}
