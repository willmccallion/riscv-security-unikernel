//! Type definitions and constants for the security dashboard GUI.
//!
//! This module provides the core data structures used for communication
//! between the GUI and the security kernel, including network statistics,
//! log entries, and command types.

use crate::log::LogEvent;
use sec_core::config::{IP_ADDR, MANAGEMENT_PORT, TELEMETRY_PORT};
use sec_core::security::mgmt::{Command, MgmtOutcome};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::AtomicU64;

/// UDP address for sending management commands to the security kernel.
pub const MGMT_ADDR: SocketAddr = SocketAddr::V4(SocketAddrV4::new(IP_ADDR, MANAGEMENT_PORT));

/// Local address for receiving telemetry and alerts from the kernel.
pub const LISTEN_ADDR: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, TELEMETRY_PORT));

/// Network statistics tracked by the security kernel.
///
/// All counters are atomic to allow lock-free updates from the background
/// network task while being read by the GUI thread.
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
