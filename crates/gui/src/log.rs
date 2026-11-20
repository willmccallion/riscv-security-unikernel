//! The event log: what each row records, and how each kind is shown.

use eframe::egui::Color32;
use sec_core::security::alert::{Alert, AlertReason};
use sec_core::security::mgmt::{Ack, ManagementMessageType, MgmtOutcome};
use std::fmt;
use std::net::Ipv4Addr;

const ORANGE: Color32 = Color32::from_rgb(255, 80, 0);
const MAGENTA: Color32 = Color32::from_rgb(255, 0, 255);

/// Something worth a row in the event log.
#[derive(Clone, Debug)]
pub enum LogEvent {
    /// A security alert from the kernel.
    Alert(Alert),
    /// The kernel's answer to a mgmt command.
    Ack(Ack),
    /// An alert report this dashboard cannot decode, such as one from a
    /// newer kernel, of this many bytes.
    UnreadableAlert(usize),
    /// The operator banned this address from the packet inspector.
    ManualBan(Ipv4Addr),
    /// A BPF program did not compile.
    CompileFailed,
}

/// Where a logged event came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// One address.
    Host(Ipv4Addr),
    /// A whole subnet, by its network address and prefix length.
    Subnet {
        /// The subnet's first address.
        network: Ipv4Addr,
        /// Its prefix length, under 32.
        prefix_len: u8,
    },
    /// The kernel itself.
    Kernel,
    /// This dashboard.
    Local,
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Host(ip) => write!(f, "{ip}"),
            Self::Subnet {
                network,
                prefix_len,
            } => write!(f, "{network}/{prefix_len}"),
            Self::Kernel => write!(f, "Kernel"),
            Self::Local => write!(f, "Localhost"),
        }
    }
}

/// How a row looks: a short tag, its text and its colour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Description {
    /// The badge, such as `FIREWALL`.
    pub tag: &'static str,
    /// The text after the badge.
    pub detail: String,
    /// The colour of the badge and accent bar.
    pub color: Color32,
}

impl LogEvent {
    /// Where the event came from.
    pub const fn source(&self) -> Source {
        match self {
            Self::Alert(alert) if alert.meta.prefix_len < 32 => Source::Subnet {
                network: alert.meta.src_ip,
                prefix_len: alert.meta.prefix_len,
            },
            Self::Alert(alert) => Source::Host(alert.meta.src_ip),
            Self::Ack(_) | Self::UnreadableAlert(_) => Source::Kernel,
            Self::ManualBan(_) | Self::CompileFailed => Source::Local,
        }
    }

    /// Whether the event records a packet that passed, which the
    /// alerts-only view hides.
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Alert(alert) if alert.reason == AlertReason::Pass)
    }

    /// How the event's row looks.
    pub fn describe(&self) -> Description {
        match self {
            Self::Alert(alert) => describe_alert(alert, self.source()),
            Self::Ack(ack) => describe_ack(*ack),
            Self::UnreadableAlert(len) => Description {
                tag: "UNREADABLE",
                detail: format!("alert report of {len} bytes"),
                color: ORANGE,
            },
            Self::ManualBan(ip) => Description {
                tag: "BAN",
                detail: format!("manual ban of {ip}"),
                color: MAGENTA,
            },
            Self::CompileFailed => Description {
                tag: "BPF",
                detail: "compilation failed".to_string(),
                color: Color32::RED,
            },
        }
    }
}

fn describe_alert(alert: &Alert, source: Source) -> Description {
    let measured = alert.meta.value;
    let (tag, color, detail) = match alert.reason {
        AlertReason::Ddos => (
            "DDoS",
            Color32::YELLOW,
            format!("High Volume from {source}"),
        ),
        AlertReason::Firewall => (
            "FIREWALL",
            Color32::RED,
            format!("Blocked Port access from {source}"),
        ),
        AlertReason::Malware => (
            "MALWARE",
            Color32::RED,
            format!("Signature Match from {source}"),
        ),
        AlertReason::Bpf => (
            "BPF",
            Color32::LIGHT_BLUE,
            format!("Custom Filter Drop from {source}"),
        ),
        AlertReason::Heuristic => (
            "HEURISTIC",
            MAGENTA,
            format!("Anomaly Detected from {source}"),
        ),
        AlertReason::Flow => (
            "FLOW",
            Color32::LIGHT_BLUE,
            format!("New Connection from {source}"),
        ),
        AlertReason::Pass => (
            "PASS",
            Color32::from_gray(140),
            format!("Allowed from {source}"),
        ),
        AlertReason::MgmtAuthFail => (
            "MGMT AUTH",
            ORANGE,
            format!("Rejected unsigned/replayed mgmt packet from {source}"),
        ),
        AlertReason::BpfTimeout => (
            "BPF TIMEOUT",
            ORANGE,
            format!("Installed program hit cycle budget from {source}"),
        ),
        AlertReason::SourceSurge => (
            "SURGE",
            Color32::YELLOW,
            format!("~{measured} distinct sources in one interval (spoofed flood?)"),
        ),
        AlertReason::SubnetFlood => (
            "SUBNET",
            Color32::YELLOW,
            format!("{source} banned at ~{measured} pps"),
        ),
        AlertReason::PortScan => (
            "SCAN",
            Color32::YELLOW,
            format!("{source} banned after trying {measured} ports"),
        ),
        AlertReason::MalformedIp => (
            "MALFORMED",
            MAGENTA,
            format!("Invalid IPv4 header from {source}"),
        ),
        AlertReason::IpFragment => (
            "FRAGMENT",
            MAGENTA,
            format!("IPv4 fragment dropped from {source}"),
        ),
    };
    Description { tag, detail, color }
}

fn describe_ack(ack: Ack) -> Description {
    let command = match ManagementMessageType::from_u8(ack.command) {
        Some(ManagementMessageType::BlockPort) => "block port",
        Some(ManagementMessageType::AddDpiPattern) => "add DPI pattern",
        Some(ManagementMessageType::UploadBpfProgram) => "upload BPF program",
        Some(ManagementMessageType::BanIp) => "ban IP",
        Some(ManagementMessageType::UnblockPort) => "unblock port",
        Some(ManagementMessageType::RemoveDpiPattern) => "remove DPI pattern",
        Some(ManagementMessageType::UnloadBpfProgram) => "unload BPF program",
        Some(ManagementMessageType::UnbanIp) => "unban IP",
        None => "unknown command",
    };
    let (outcome, color) = match ack.outcome {
        MgmtOutcome::Applied => ("applied", Color32::GREEN),
        MgmtOutcome::TableFull => ("rejected: table full", ORANGE),
        MgmtOutcome::Invalid => ("rejected: invalid", ORANGE),
        MgmtOutcome::Refused => ("refused", ORANGE),
    };
    Description {
        tag: "MGMT",
        detail: format!("#{} {command}: {outcome}", ack.seq),
        color,
    }
}

/// One row of the event log.
#[derive(Clone, Debug)]
pub struct LogEntry {
    /// Tells rows apart, so a selection survives new rows arriving.
    pub id: u64,
    /// Seconds since the dashboard started.
    pub timestamp: f64,
    /// What happened.
    pub event: LogEvent,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sec_core::security::alert::AlertMeta;

    fn alert(reason: AlertReason) -> Alert {
        Alert {
            reason,
            meta: AlertMeta {
                src_ip: Ipv4Addr::new(192, 168, 1, 50),
                dst_ip: Ipv4Addr::new(10, 0, 0, 1),
                src_port: 1234,
                dst_port: 80,
                protocol: 6,
                packet_len: 512,
                prefix_len: 32,
                value: 0,
            },
        }
    }

    #[test]
    fn every_alert_reason_has_its_own_tag() {
        let mut tags = std::collections::HashSet::new();
        for reason in AlertReason::ALL {
            let description = LogEvent::Alert(alert(reason)).describe();

            assert!(
                tags.insert(description.tag),
                "{reason:?} shares tag {}",
                description.tag
            );
        }
    }

    #[test]
    fn a_subnet_alert_comes_from_its_prefix_and_shows_its_measurement() {
        let mut subnet = alert(AlertReason::SubnetFlood);
        subnet.meta.prefix_len = 24;
        subnet.meta.value = 4_200;
        let event = LogEvent::Alert(subnet);

        let description = event.describe();

        assert_eq!(event.source().to_string(), "192.168.1.50/24");
        assert_eq!(description.detail, "192.168.1.50/24 banned at ~4200 pps");
    }

    #[test]
    fn a_host_alert_comes_from_its_address() {
        let event = LogEvent::Alert(alert(AlertReason::Firewall));

        assert_eq!(event.source(), Source::Host(Ipv4Addr::new(192, 168, 1, 50)));
    }

    #[test]
    fn only_passed_packets_are_hidden_from_the_alerts_view() {
        assert!(LogEvent::Alert(alert(AlertReason::Pass)).is_pass());
        assert!(!LogEvent::Alert(alert(AlertReason::Ddos)).is_pass());
        assert!(!LogEvent::CompileFailed.is_pass());
    }

    #[test]
    fn an_ack_names_its_command_and_outcome() {
        let ack = Ack {
            seq: 7,
            command: ManagementMessageType::BlockPort as u8,
            outcome: MgmtOutcome::TableFull,
        };

        let description = LogEvent::Ack(ack).describe();

        assert_eq!(description.detail, "#7 block port: rejected: table full");
    }
}
