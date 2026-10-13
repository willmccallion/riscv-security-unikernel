//! Type definitions and constants for the security dashboard GUI.
//!
//! This module provides the core data structures used for communication
//! between the GUI and the security kernel, including network statistics,
//! log entries, and command types.

use eframe::egui;
use sec_core::security::mgmt::MgmtOutcome;
use std::sync::atomic::AtomicU64;

/// UDP address for sending management commands to the security kernel.
pub const MGMT_ADDR: &str = "192.168.100.2:1337";

/// Local address for receiving telemetry and alerts from the kernel.
pub const LISTEN_ADDR: &str = "0.0.0.0:8888";

/// Represents a single security event or alert logged by the kernel.
///
/// Carries the fixed-size metadata record the kernel ships in alert
/// packets — source/destination addresses, ports, protocol, and the
/// observed packet length. Inbound payload bytes are deliberately not
/// echoed by the kernel, so none are stored here.
#[derive(Clone, Debug)]
pub struct LogEntry {
    /// Time elapsed since application start in seconds.
    pub timestamp: f64,
    /// Source IP address that triggered the event.
    pub src_ip: String,
    /// Destination IP address recorded by the kernel.
    pub dst_ip: String,
    /// Source port of the packet (0 if unknown).
    pub src_port: u16,
    /// Destination port of the packet (0 if unknown).
    pub dst_port: u16,
    /// IP protocol number (6 = TCP, 17 = UDP, ...).
    pub protocol: u8,
    /// Total observed packet length in bytes (saturated to `u16::MAX`).
    pub packet_len: u16,
    /// A detector's measurement behind the alert, if it carried one.
    pub measured: Option<u32>,
    /// Human-readable description of the security event.
    pub msg: String,
    /// Color code for UI display based on event severity.
    pub color: egui::Color32,
}

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
    pub fw: AtomicU64,
    /// Current packets per second dropped due to malware signatures.
    pub mal: AtomicU64,
    /// Current packets per second dropped by BPF filters.
    pub bpf: AtomicU64,
    /// Current packets per second dropped by heuristic analysis.
    pub heur: AtomicU64,
    /// Current memory usage in bytes.
    pub memory: AtomicU64,
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
        command: MgmtCommand,
    },
}

/// Identifies one mgmt command so its ack can be matched back to the UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CommandId(pub u64);

/// What the GUI knows about a mgmt command it issued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandStatus {
    /// Sent; no ack yet.
    Pending,
    /// The kernel applied it.
    Applied,
    /// The kernel refused it, for the given reason.
    Rejected(MgmtOutcome),
    /// Not sent: no telemetry has announced the kernel's boot epoch yet.
    NotSent,
    /// Sent, but no ack arrived in time.
    NoAck,
}

/// Messages from the network task to the UI.
pub enum UiEvent {
    /// An entry for the event log.
    Log(LogEntry),
    /// A mgmt command's status changed.
    CommandStatus {
        /// The command whose status changed.
        id: CommandId,
        /// Its new status.
        status: CommandStatus,
    },
}

/// A management-plane command. `traffic.rs` seals every one with the
/// pre-shared MAC key and a monotonic counter before it goes on the wire.
pub enum MgmtCommand {
    /// Ban an IP address in the kernel's penalty box.
    BanIp(std::net::Ipv4Addr),
    /// Install a firewall rule blocking the given destination port.
    BlockPort(u16),
    /// Add a DPI signature pattern (capped to 32 bytes at the kernel).
    AddDpiPattern(Vec<u8>),
    /// Upload a compiled BPF program (7 bytes per instruction, 64 max).
    UploadBpf(Vec<u8>),
    /// Lift a ban on an IP address.
    UnbanIp(std::net::Ipv4Addr),
    /// Remove a firewall rule.
    UnblockPort(u16),
    /// Remove a runtime-added DPI signature.
    RemoveDpiPattern(Vec<u8>),
    /// Uninstall the BPF program.
    UnloadBpf,
}
