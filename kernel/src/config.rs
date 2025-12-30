pub const KERNEL_VERSION: &str = "v1.0.0";

// Network identity
pub const MAC_ADDR: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
pub const IP_ADDR: [u8; 4] = [192, 168, 100, 2];

// Security thresholds
pub const RATE_LIMIT_PPS: u64 = 10_000;
pub const HEAVY_HITTER_THRESHOLD: u16 = 100;
pub const MANAGEMENT_PORT: u16 = 1337;

// Memory layout
#[allow(dead_code)]
pub const HEAP_START: usize = 0x8000_0000;
#[allow(dead_code)]
pub const HEAP_SIZE: usize = 64 * 1024; // 64KB
