//! The `monitor` subcommand: its arguments, merged with the
//! configuration file, and dispatch to live capture or replay.

use super::config::MonitorConfig;
use super::net::IpPrefix;
use super::{live, replay};
use anyhow::{Result, bail};
use std::path::PathBuf;
use std::time::Duration;

/// Arguments of `security-daemon monitor`.
#[derive(clap::Args, Debug, Clone, Default)]
pub struct MonitorArgs {
    /// TOML configuration file; options given here override it.
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,
    /// Interface to capture on; repeat to watch several, such as a LAN
    /// interface and a VPN's (needs `CAP_NET_RAW`, dropped once capture
    /// starts).
    #[arg(long = "iface", value_name = "NAME", conflicts_with = "pcap")]
    pub interfaces: Vec<String>,
    /// Replay a pcap capture file instead of capturing live.
    #[arg(long, value_name = "FILE")]
    pub pcap: Option<PathBuf>,
    /// Another network to treat as local, such as the rest of a home
    /// network; may be repeated. A live interface's own are always local.
    #[arg(long = "local-network", value_name = "PREFIX")]
    pub local_networks: Vec<IpPrefix>,
    /// Stop live capture after this many seconds.
    #[arg(long, conflicts_with = "pcap")]
    pub duration_secs: Option<u64>,
}

/// Where frames come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// Live capture on network interfaces.
    Interfaces {
        /// The interfaces' names, at least one.
        names: Vec<String>,
        /// Stop after this long; run until killed if `None`.
        duration: Option<Duration>,
    },
    /// A pcap file, replayed with its own timestamps.
    PcapFile(PathBuf),
}

/// Everything a monitor run needs, resolved from arguments and file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorOptions {
    /// Where frames come from.
    pub source: Source,
    /// Networks to treat as local besides a live interface's own.
    pub extra_local_networks: Vec<IpPrefix>,
}

impl MonitorOptions {
    /// Merges `args` over `file`: a pcap file or interfaces named on the
    /// command line win over the file's interfaces, and local networks
    /// from both apply.
    pub fn resolve(args: MonitorArgs, file: MonitorConfig) -> Result<Self> {
        let interfaces = if args.interfaces.is_empty() { file.interfaces } else { args.interfaces };
        let source = match args.pcap {
            Some(path) => Source::PcapFile(path),
            None if interfaces.is_empty() => {
                bail!("say what to monitor: --iface, --pcap, or `interfaces` in the config file")
            }
            None => Source::Interfaces {
                names: interfaces,
                duration: args.duration_secs.map(Duration::from_secs),
            },
        };
        let mut extra_local_networks = file.local_networks;
        extra_local_networks.extend(args.local_networks);
        Ok(Self {
            source,
            extra_local_networks,
        })
    }
}

/// Runs `security-daemon monitor`.
pub fn run(args: MonitorArgs) -> Result<()> {
    let file = match &args.config {
        Some(path) => MonitorConfig::load(path)?,
        None => MonitorConfig::default(),
    };
    let options = MonitorOptions::resolve(args, file)?;
    match &options.source {
        Source::Interfaces { names, duration } => live::run(names, *duration, &options.extra_local_networks),
        Source::PcapFile(path) => replay::run(path, &options.extra_local_networks),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix(text: &str) -> IpPrefix {
        text.parse().unwrap()
    }

    #[test]
    fn interfaces_on_the_command_line_override_the_files() {
        let args = MonitorArgs {
            interfaces: vec!["wlo1".into(), "tailscale0".into()],
            duration_secs: Some(5),
            ..MonitorArgs::default()
        };
        let file = MonitorConfig {
            interfaces: vec!["enp4s0".into()],
            local_networks: vec![],
        };

        let options = MonitorOptions::resolve(args, file).unwrap();

        assert_eq!(
            options.source,
            Source::Interfaces {
                names: vec!["wlo1".into(), "tailscale0".into()],
                duration: Some(Duration::from_secs(5))
            }
        );
    }

    #[test]
    fn a_pcap_file_wins_over_the_files_interface_and_networks_merge() {
        let args = MonitorArgs {
            pcap: Some("cap.pcap".into()),
            local_networks: vec![prefix("10.0.0.0/8")],
            ..MonitorArgs::default()
        };
        let file = MonitorConfig {
            interfaces: vec!["enp4s0".into()],
            local_networks: vec![prefix("192.168.1.0/24")],
        };

        let options = MonitorOptions::resolve(args, file).unwrap();

        assert_eq!(options.source, Source::PcapFile("cap.pcap".into()));
        assert_eq!(options.extra_local_networks, vec![prefix("192.168.1.0/24"), prefix("10.0.0.0/8")]);
    }

    #[test]
    fn nothing_to_monitor_is_an_error() {
        assert!(MonitorOptions::resolve(MonitorArgs::default(), MonitorConfig::default()).is_err());
    }
}
