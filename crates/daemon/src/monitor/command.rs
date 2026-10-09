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
    /// Interface to capture on (needs `CAP_NET_RAW`, dropped once capture
    /// starts).
    #[arg(long, conflicts_with = "pcap")]
    pub iface: Option<String>,
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
    /// Live capture on a network interface.
    Interface {
        /// The interface's name.
        name: String,
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
    /// Merges `args` over `file`: a pcap file or interface named on the
    /// command line wins over the file's interface, and local networks
    /// from both apply.
    pub fn resolve(args: MonitorArgs, file: MonitorConfig) -> Result<Self> {
        let source = match (args.pcap, args.iface.or(file.interface)) {
            (Some(path), _) => Source::PcapFile(path),
            (None, Some(name)) => Source::Interface {
                name,
                duration: args.duration_secs.map(Duration::from_secs),
            },
            (None, None) => bail!("say what to monitor: --iface, --pcap, or `interface` in the config file"),
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
        Source::Interface { name, duration } => live::run(name, *duration, &options.extra_local_networks),
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
    fn the_command_line_interface_overrides_the_file() {
        let args = MonitorArgs {
            iface: Some("wlo1".into()),
            duration_secs: Some(5),
            ..MonitorArgs::default()
        };
        let file = MonitorConfig {
            interface: Some("enp4s0".into()),
            local_networks: vec![],
        };

        let options = MonitorOptions::resolve(args, file).unwrap();

        assert_eq!(
            options.source,
            Source::Interface {
                name: "wlo1".into(),
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
            interface: Some("enp4s0".into()),
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
