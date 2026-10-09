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

/// Time-source units per data-plane token in the global rate limiter:
/// 100k packets per second on a 1 GHz cycle counter.
pub const RATE_LIMIT_TOKEN_COST_CYCLES: u64 = 10_000;

/// Columns per row of the heavy-hitter Count-Min Sketch.
pub const CMS_WIDTH: usize = 128;

/// Rows (independent hashes) of the heavy-hitter Count-Min Sketch.
pub const CMS_DEPTH: usize = 4;

/// Threshold for heavy hitter detection in the Count-Min Sketch.
///
/// IPs exceeding this packet count within a measurement window
/// are automatically banned.
pub const HEAVY_HITTER_THRESHOLD: u16 = 100;

/// UDP port number for management interface commands.
pub const MANAGEMENT_PORT: u16 = 1337;

/// Mgmt packets that may arrive in one burst before the mgmt plane's own
/// rate limit applies.
pub const MGMT_BUCKET_CAPACITY: u64 = 16;

/// Time-source units per mgmt token: about 100 packets per second at
/// 1 GHz. Bounds the MAC-verification work an unauthenticated flood to
/// the mgmt port can cause.
pub const MGMT_TOKEN_COST_CYCLES: u64 = 10_000_000;

/// Alerts that may go out in one burst before the alert rate limit applies.
pub const ALERT_BUCKET_CAPACITY: u64 = 32;

/// Time-source units per alert token: about 1000 alerts per second at 1 GHz.
///
/// Keeps a flood of dropped traffic from becoming an equal flood of alerts
/// on the mgmt network; drop counters in telemetry still count every packet.
pub const ALERT_TOKEN_COST_CYCLES: u64 = 1_000_000;

/// UDP port number for telemetry broadcasts.
pub const TELEMETRY_PORT: u16 = 8888;

/// Total system memory size in bytes (64 KB).
///
/// Used for memory usage calculations and reporting.
pub const TOTAL_MEMORY_SIZE: usize = 64 * 1024;

/// Telemetry report interval in CPU cycles.
///
/// Statistics are reported to the control plane after this many
/// cycles have elapsed since the last report.
pub const TELEMETRY_INTERVAL_CYCLES: usize = 1_000_000_000;

/// Count-Min Sketch reset interval in CPU cycles.
///
/// The heavy-hitter sketch is wiped on this cadence to bound
/// false-positive growth from hash collisions and to define the
/// sliding window over which `HEAVY_HITTER_THRESHOLD` applies.
/// Decoupled from telemetry so that operators can tune reporting
/// frequency without changing the detector's effective window.
pub const CMS_RESET_INTERVAL_CYCLES: usize = 1_000_000_000;

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
/// Only log new flows when (`cycle_count` & `FLOW_LOG_SAMPLE_MASK`) == 0
/// to prevent log flooding.
pub const FLOW_LOG_SAMPLE_MASK: usize = 0x0F;

/// Alert sampling rate for DDoS alerts.
///
/// Only send alerts every N packets to prevent alert flooding.
pub const DDOS_ALERT_SAMPLE_RATE: u64 = 50;

