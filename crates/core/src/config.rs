//! Kernel configuration constants.
//!
//! This module defines system-wide configuration values including
//! network identity, security thresholds, and memory layout parameters.

/// Kernel version string displayed at boot.
pub const KERNEL_VERSION: &str = "v1.0.0";

/// MAC address assigned to the network interface.
pub const MAC_ADDR: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

/// IPv4 address assigned to the network interface.
pub const IP_ADDR: [u8; 4] = [192, 168, 100, 2];

/// Maximum packets per second allowed by the rate limiter.
pub const RATE_LIMIT_PPS: u64 = 10_000;

/// Threshold for heavy hitter detection in the Count-Min Sketch.
///
/// IPs exceeding this packet count within a measurement window
/// are automatically banned.
pub const HEAVY_HITTER_THRESHOLD: u16 = 100;

/// UDP port number for management interface commands.
pub const MANAGEMENT_PORT: u16 = 1337;

/// UDP port number for telemetry broadcasts.
pub const TELEMETRY_PORT: u16 = 8888;

/// Starting address of the heap memory region.
#[allow(dead_code)]
pub const HEAP_START: usize = 0x8000_0000;

/// Size of the heap memory region in bytes (64 KB).
///
/// This defines the total allocatable memory for dynamic allocations.
/// The heap starts at `HEAP_START` and extends for this many bytes.
/// Exceeding this limit will cause allocation failures.
#[allow(dead_code)]
pub const HEAP_SIZE: usize = 64 * 1024;

/// Total system memory size in bytes (64 KB).
///
/// Used for memory usage calculations and reporting.
pub const TOTAL_MEMORY_SIZE: usize = 64 * 1024;

/// Telemetry report interval in CPU cycles.
///
/// Statistics are reported to the control plane after this many
/// cycles have elapsed since the last report.
pub const TELEMETRY_INTERVAL_CYCLES: usize = 1_000_000_000;

/// Flow expiration timeout in CPU cycles.
///
/// Flows that have not been seen within this period are pruned
/// from the flow table.
pub const FLOW_TIMEOUT_CYCLES: usize = 10_000_000;

/// IP ban duration in CPU cycles.
///
/// Default duration for automatic IP bans when heavy hitter
/// threshold is exceeded.
pub const IP_BAN_DURATION_CYCLES: usize = 10_000_000_000;

/// Token bucket initial capacity.
///
/// Number of tokens available at startup for the rate limiter.
pub const TOKEN_BUCKET_CAPACITY: usize = 50;

/// Default blocked port (Telnet).
///
/// Port 23 is blocked by default as a security measure.
pub const DEFAULT_BLOCKED_PORT: u16 = 23;

/// Maximum number of eBPF program instructions.
pub const MAX_BPF_PROGRAM_SIZE: usize = 64;

/// Sampling rate for flow logging.
///
/// Only log new flows when (cycle_count & FLOW_LOG_SAMPLE_MASK) == 0
/// to prevent log flooding.
pub const FLOW_LOG_SAMPLE_MASK: usize = 0x0F;

/// Alert sampling rate for DDoS alerts.
///
/// Only send alerts every N packets to prevent alert flooding.
pub const DDOS_ALERT_SAMPLE_RATE: u64 = 50;

/// Magic header for IP spoofing detection in test packets.
///
/// Packets with this 4-byte header followed by a source IP are
/// recognized as test packets with spoofed source addresses.
pub const SPOOF_DETECTION_MAGIC: [u8; 4] = [0xAE, 0x61, 0x73, 0x00];

/// Offset to spoofed source IP in test packets.
pub const SPOOF_DETECTION_IP_OFFSET: usize = 46;

/// Minimum packet length required for spoofing detection.
pub const SPOOF_DETECTION_MIN_LEN: usize = 50;
