//! Type definitions and constants for the security dashboard GUI.
//!
//! This module provides the core data structures used for communication
//! between the GUI and the security kernel, including network statistics,
//! log entries, and command types.

use eframe::egui;
use std::sync::atomic::AtomicU64;

/// UDP address for sending management commands to the security kernel.
pub const MGMT_ADDR: &str = "192.168.100.2:1337";

/// Target address for generating test traffic.
pub const TARGET_ADDR: &str = "192.168.100.2:80";

/// Local address for receiving telemetry and alerts from the kernel.
pub const LISTEN_ADDR: &str = "0.0.0.0:8888";

/// Represents a single security event or alert logged by the kernel.
///
/// Each entry contains metadata about the event including source IP,
/// destination port, timestamp, and the raw packet payload for inspection.
#[derive(Clone, Debug)]
pub struct LogEntry {
    /// Time elapsed since application start in seconds.
    pub timestamp: f64,
    /// Source IP address that triggered the event.
    pub src_ip: String,
    /// Human-readable description of the security event.
    pub msg: String,
    /// Raw packet payload captured for analysis.
    pub payload: Vec<u8>,
    /// Destination port of the packet.
    pub dst_port: u16,
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
    /// Current packets per second dropped by eBPF filters.
    pub bpf: AtomicU64,
    /// Current packets per second dropped by heuristic analysis.
    pub heur: AtomicU64,
    /// Current memory usage in bytes.
    pub memory: AtomicU64,
    /// Current number of active network flows being tracked.
    pub flows: AtomicU64,

    /// Cumulative count of all packets that passed security checks.
    pub total_passed: AtomicU64,
    /// Cumulative count of all packets dropped by security mechanisms.
    pub total_dropped: AtomicU64,

    /// Unix timestamp of the last telemetry update from the kernel.
    pub last_seen: AtomicU64,
}

/// Traffic generation mode for testing security mechanisms.
#[derive(Clone, Copy, PartialEq)]
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

/// Commands that can be sent from the GUI to the background network task.
pub enum GuiCommand {
    /// Change the traffic generation mode.
    SetMode(TrafficMode),
    /// Send raw bytes to the kernel management interface.
    SendBytes(Vec<u8>),
    /// Manually ban an IP address in the kernel's penalty box.
    BanIp(String),
}
