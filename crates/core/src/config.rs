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

/// Columns per row of the kernel's heavy-hitter Count-Min Sketch.
///
/// 1024 x 3 (6 KB) keeps legitimate sources from being flagged up to
/// about 200k packets per second of total traffic in the sketch-lab study,
/// where the previous 128 x 4 failed at 20k.
pub const CMS_WIDTH: usize = 1024;

/// Rows (independent hashes) of the kernel's heavy-hitter Count-Min Sketch.
pub const CMS_DEPTH: usize = 3;

/// Columns per row of the kernel's subnet (/24 and /16) Count-Min Sketch.
pub const PREFIX_SKETCH_WIDTH: usize = 256;

/// Rows of the kernel's subnet Count-Min Sketch. A legitimate subnet is
/// banned only if it shares every row's counter with an attacking one, so
/// each row cuts those collateral bans 256-fold.
pub const PREFIX_SKETCH_DEPTH: usize = 3;

/// Estimated packets per second above which a /24 is banned. Only traffic
/// from sources that passed their own heavy-hitter check counts.
pub const SUBNET_24_THRESHOLD: u16 = 1_000;

/// Estimated packets per second above which a /16 is banned.
pub const SUBNET_16_THRESHOLD: u16 = 5_000;

/// Registers in the virtual HyperLogLog pool that estimates each source's
/// distinct destination ports (one byte each).
pub const PORT_SCAN_POOL_REGISTERS: usize = 1024;

/// Registers of that pool each source reads its estimate from.
pub const PORT_SCAN_REGISTERS_PER_SOURCE: usize = 32;

/// Estimated distinct ports per window above which a source becomes a
/// port-scan suspect.
pub const PORT_SCAN_NOMINATE_PORTS: f64 = 24.0;

/// Distinct ports a suspect must try after its nomination, counted
/// exactly, to be banned as a scanner; with the ports before nomination,
/// a scan is caught at about 64 ports in all.
pub const PORT_SCAN_CONFIRM_PORTS: usize = 40;

/// Suspects tracked exactly at once (two bytes per confirming port each).
pub const PORT_SCAN_CANDIDATES: usize = 8;

/// Detection intervals per port-scan window (five seconds).
pub const PORT_SCAN_WINDOW_INTERVALS: u32 = 10;

/// HyperLogLog registers counting distinct sources per detection interval
/// (one byte each; about 6.5% error at 256).
pub const SOURCE_COUNTER_REGISTERS: usize = 256;

/// A detection interval with this many times the usual number of distinct
/// sources is reported as a surge, typical of a flood from spoofed
/// addresses.
pub const SOURCE_SURGE_FACTOR: f64 = 4.0;

/// Distinct sources per detection interval below which no surge is
/// reported, however sharp the rise.
pub const SOURCE_SURGE_MINIMUM: f64 = 1000.0;

/// Estimated rate, in packets per second, above which a source is
/// banned as a heavy hitter. See [`CMS_DECAY_INTERVAL_CYCLES`].
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

/// How often the heavy-hitter sketch halves its counters, in CPU cycles.
///
/// Half a second at 1 GHz. A source sending steadily at `r` packets per
/// second peaks at about `r` just before each halving (`c = c/2 + r/2`),
/// so [`HEAVY_HITTER_THRESHOLD`] reads as packets per second, and a
/// burst is not forgotten just because it straddles a boundary.
pub const CMS_DECAY_INTERVAL_CYCLES: usize = 500_000_000;

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

/// Maximum number of BPF program instructions.
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

