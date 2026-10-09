//! The monitor's configuration file.

use super::net::IpPrefix;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

/// Settings read from a TOML file; command-line options override them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MonitorConfig {
    /// Interfaces to capture on.
    pub interfaces: Vec<String>,
    /// Networks to treat as local besides the interface's own.
    pub local_networks: Vec<IpPrefix>,
}

/// The file as written, before its values are parsed.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    #[serde(default)]
    interfaces: Vec<String>,
    #[serde(default)]
    local_networks: Vec<String>,
}

impl MonitorConfig {
    /// Reads and parses the file at `path`.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("in {}", path.display()))
    }

    /// Parses TOML `text`. Unknown keys are errors, so a misspelt setting
    /// is reported rather than silently ignored.
    pub fn parse(text: &str) -> Result<Self> {
        let file: ConfigFile = toml::from_str(text)?;
        let local_networks = file
            .local_networks
            .iter()
            .map(|prefix| prefix.parse().context("in local_networks"))
            .collect::<Result<_>>()?;
        Ok(Self {
            interfaces: file.interfaces,
            local_networks,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_interfaces_and_local_networks() {
        let config = MonitorConfig::parse(
            r#"
            interfaces = ["enp4s0", "tailscale0"]
            local_networks = ["192.168.1.0/24", "2001:db8:1::/48"]
            "#,
        )
        .unwrap();

        assert_eq!(config.interfaces, ["enp4s0", "tailscale0"]);
        assert_eq!(config.local_networks.len(), 2);
    }

    #[test]
    fn the_example_configuration_parses() {
        let example = include_str!("../../monitor.example.toml");

        assert_eq!(MonitorConfig::parse(example).unwrap().interfaces, ["enp4s0", "tailscale0"]);
    }

    #[test]
    fn an_empty_file_is_all_defaults() {
        assert_eq!(MonitorConfig::parse("").unwrap(), MonitorConfig::default());
    }

    #[test]
    fn misspelt_keys_and_bad_prefixes_are_errors() {
        assert!(MonitorConfig::parse(r#"interfaces = ["eth0"]
interfce = "eth1""#).is_err());
        let bad = MonitorConfig::parse(r#"local_networks = ["10.0.0.0/40"]"#).unwrap_err();
        assert!(format!("{bad:#}").contains("local_networks"), "{bad:#}");
    }
}
