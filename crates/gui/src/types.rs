//! Type definitions and constants for the security dashboard GUI.
//!
//! This module provides the core data structures used for communication
//! between the GUI and the security kernel, including network statistics,
//! log entries, and command types.

use crate::log::LogEvent;
use sec_core::config::{IP_ADDR, MANAGEMENT_PORT, TELEMETRY_PORT};
use sec_core::security::mgmt::{Command, MgmtOutcome};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};

/// UDP address for sending management commands to the security kernel.
pub const MGMT_ADDR: SocketAddr = SocketAddr::V4(SocketAddrV4::new(IP_ADDR, MANAGEMENT_PORT));

/// Local address for receiving telemetry and alerts from the kernel.
pub const LISTEN_ADDR: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, TELEMETRY_PORT));

/// Network statistics tracked by the security kernel.
///
/// All counters are atomic to allow lock-free updates from the background
/// network task while being read by the GUI thread.
#[derive(Default)]
pub struct NetStats {
    /// Current packets per second that passed all security checks.
    pub passed: AtomicU64,
    /// Current packets per second dropped by DDoS mitigation.
    pub ddos: AtomicU64,
    /// Current packets per second blocked by firewall rules.
    pub firewall: AtomicU64,
    /// Current packets per second dropped due to malware signatures.
    pub malware: AtomicU64,
    /// Current packets per second dropped by BPF filters.
    pub bpf: AtomicU64,
    /// Current packets per second dropped by heuristic analysis.
    pub heuristic: AtomicU64,
    /// Current number of active network flows being tracked.
    pub flows: AtomicU64,
    /// Management-plane packets observed in the last interval
    /// (authenticated dispatches plus auth failures). Tracked
    /// separately from `passed` so a mgmt-auth-fail flood can't
    /// inflate the user-traffic counter.
    pub mgmt: AtomicU64,

    /// Cumulative count of all packets that passed security checks.
    pub total_passed: AtomicU64,
    /// Cumulative count of all packets dropped by security mechanisms.
    pub total_dropped: AtomicU64,

    /// Unix timestamp of the last telemetry update from the kernel.
    pub last_seen: AtomicU64,
}

impl NetStats {
    /// The counters as they are now.
    pub fn snapshot(&self) -> StatsSnapshot {
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        StatsSnapshot {
            passed: load(&self.passed),
            dropped: load(&self.ddos)
                + load(&self.firewall)
                + load(&self.malware)
                + load(&self.bpf)
                + load(&self.heuristic),
            flows: load(&self.flows),
            mgmt: load(&self.mgmt),
            total_passed: load(&self.total_passed),
            total_dropped: load(&self.total_dropped),
        }
    }
}

/// One reading of [`NetStats`], with the drop counters summed as the
/// kernel's `IntervalStats::drops` does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatsSnapshot {
    /// Packets per second that passed every check.
    pub passed: u64,
    /// Packets per second dropped, for any reason.
    pub dropped: u64,
    /// Flows being tracked.
    pub flows: u64,
    /// Mgmt packets per second.
    pub mgmt: u64,
    /// Packets passed since the dashboard started.
    pub total_passed: u64,
    /// Packets dropped since the dashboard started.
    pub total_dropped: u64,
}

/// Traffic generation mode for testing security mechanisms.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TrafficMode {
    /// No traffic generation.
    Idle,
    /// Generate normal HTTP traffic patterns.
    Normal,
    /// Generate high-volume DDoS attack traffic.
    DDoS,
    /// Generate mixed traffic with periodic attacks and anomalies.
    Live,
}

/// Log display mode.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum LogMode {
    /// Show only intercepted/blocked packets.
    Alerts,
    /// Show all packets including allowed ones.
    All,
}

/// Commands that can be sent from the GUI to the background network task.
pub enum GuiCommand {
    /// Change the traffic generation mode.
    SetMode(TrafficMode),
    /// Seal and send a command to the kernel's management plane; its
    /// outcome comes back as a [`UiEvent::CommandStatus`] for `id`.
    Mgmt {
        /// Identifies the command in the status event.
        id: CommandId,
        /// The command to send.
        command: Box<Command>,
    },
}

/// Identifies one mgmt command so its ack can be matched back to the UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CommandId(pub u64);

/// Why a mgmt command was not sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotSentReason {
    /// The kernel would reject the command outright.
    InvalidCommand,
    /// No telemetry has announced the kernel's boot epoch yet.
    KernelNotSeen,
    /// No local interface address routes to the kernel, so there is
    /// nowhere to ask it to send its reply.
    NoReplyAddress,
    /// The socket refused the packet.
    SendFailed(std::io::ErrorKind),
}

/// What the GUI knows about a mgmt command it issued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandStatus {
    /// Sent; no ack yet.
    Pending,
    /// The kernel applied it.
    Applied,
    /// The kernel refused it, for the given reason.
    Rejected(MgmtOutcome),
    /// Not sent, for the given reason.
    NotSent(NotSentReason),
    /// Sent, but no ack arrived in time.
    NoAck,
}

/// Messages from the network task to the UI.
pub enum UiEvent {
    /// Something for the event log.
    Log(LogEvent),
    /// A mgmt command's status changed.
    CommandStatus {
        /// The command whose status changed.
        id: CommandId,
        /// Its new status.
        status: CommandStatus,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_snapshot_sums_every_drop_counter_and_nothing_else() {
        let stats = NetStats::default();
        for (counter, value) in [
            (&stats.passed, 1),
            (&stats.ddos, 10),
            (&stats.firewall, 20),
            (&stats.malware, 30),
            (&stats.bpf, 40),
            (&stats.heuristic, 50),
            (&stats.mgmt, 7),
        ] {
            counter.store(value, Ordering::Relaxed);
        }

        let snapshot = stats.snapshot();

        assert_eq!(snapshot.dropped, 150);
        assert_eq!(snapshot.passed, 1);
        assert_eq!(snapshot.mgmt, 7);
    }
}
