//! DDoS (Distributed Denial of Service) mitigation mechanisms.
//!
//! Implements multiple techniques for detecting and mitigating DDoS attacks:
//! - Count-Min Sketch for heavy hitter detection
//! - Penalty box for IP address banning
//! - Token bucket rate limiting

use core::arch::asm;

/// Width of the Count-Min Sketch hash table.
const CMS_WIDTH: usize = 128;

/// Depth (number of hash functions) in the Count-Min Sketch.
const CMS_DEPTH: usize = 4;

/// Entry in the penalty box tracking a banned IP address.
#[derive(Copy, Clone)]
struct BanEntry {
    /// Banned IP address in network byte order.
    ip: u32,
    /// Cycle count when the ban expires.
    expiry: usize,
}

/// Penalty box for tracking banned IP addresses.
///
/// Maintains a fixed-size table of banned IPs with expiration times.
/// When the table is full, new bans overwrite the oldest entries.
pub struct PenaltyBox {
    /// Array of ban entries, limited to 16 for memory efficiency.
    entries: [BanEntry; 16],
}

impl PenaltyBox {
    /// Creates a new empty penalty box.
    pub const fn new() -> Self {
        Self {
            entries: [BanEntry { ip: 0, expiry: 0 }; 16],
        }
    }

    /// Bans an IP address for a specified duration.
    ///
    /// If the penalty box is full, the oldest entry is overwritten.
    ///
    /// # Arguments
    ///
    /// * `ip_bytes` - IP address as 4 bytes in network byte order
    /// * `duration_cycles` - Ban duration in CPU cycles
    pub fn ban(&mut self, ip_bytes: &[u8], duration_cycles: usize) {
        let ip = u32::from_be_bytes([ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]]);
        let now: usize = get_time();

        for i in 0..16 {
            if self.entries[i].expiry < now {
                self.entries[i] = BanEntry {
                    ip,
                    expiry: now + duration_cycles,
                };
                return;
            }
        }
        self.entries[0] = BanEntry {
            ip,
            expiry: now + duration_cycles,
        };
    }

    /// Checks if an IP address is currently banned.
    ///
    /// Searches the penalty box for an active ban entry matching the
    /// provided IP address. A ban is considered active if its expiration
    /// time is greater than the current cycle count.
    ///
    /// # Arguments
    ///
    /// * `ip_bytes` - IP address as 4 bytes in network byte order
    ///
    /// # Returns
    ///
    /// True if the IP is banned and the ban has not expired, false otherwise
    pub fn is_banned(&self, ip_bytes: &[u8]) -> bool {
        let ip = u32::from_be_bytes([ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]]);
        let now: usize = get_time();

        for i in 0..16 {
            if self.entries[i].ip == ip && self.entries[i].expiry > now {
                return true;
            }
        }
        false
    }
}

/// Count-Min Sketch data structure for approximate frequency counting.
///
/// Uses multiple hash functions to track packet counts per IP address
/// with bounded memory. Provides probabilistic guarantees on count accuracy
/// while using constant memory regardless of the number of unique IPs.
pub struct CountMinSketch {
    /// Two-dimensional array: depth rows, width columns.
    matrix: [[u16; CMS_WIDTH]; CMS_DEPTH],
}

impl CountMinSketch {
    /// Creates a new empty Count-Min Sketch.
    pub const fn new() -> Self {
        Self {
            matrix: [[0; CMS_WIDTH]; CMS_DEPTH],
        }
    }

    /// Inserts a data item and returns its estimated count.
    ///
    /// Hashes the data with multiple hash functions and increments
    /// the corresponding counters. Returns the minimum count across
    /// all hash functions as an estimate of the true count.
    ///
    /// # Arguments
    ///
    /// * `data` - Data to count (typically an IP address)
    ///
    /// # Returns
    ///
    /// Estimated count of this item (minimum across all hash functions)
    pub fn insert(&mut self, data: &[u8]) -> u16 {
        let mut min = u16::MAX;
        for i in 0..CMS_DEPTH {
            let mut hash: u32 = 0xDEAD_BEEF + i as u32;
            for &b in data {
                hash = hash.wrapping_add(b as u32);
                hash = hash.wrapping_add(hash << 10);
                hash ^= hash >> 6;
            }
            hash = hash.wrapping_add(hash << 3);
            hash ^= hash >> 11;
            hash = hash.wrapping_add(hash << 15);
            let idx = (hash as usize) % CMS_WIDTH;

            self.matrix[i][idx] = self.matrix[i][idx].saturating_add(1);
            if self.matrix[i][idx] < min {
                min = self.matrix[i][idx];
            }
        }
        min
    }

    /// Resets all counters to zero.
    ///
    /// Called periodically to clear the sketch for a new measurement window.
    pub fn reset(&mut self) {
        for row in self.matrix.iter_mut() {
            for val in row.iter_mut() {
                *val = 0;
            }
        }
    }
}

/// Token bucket rate limiter.
///
/// Implements a token bucket algorithm to limit the rate of packet
/// processing. Tokens are refilled at a fixed rate, and each packet
/// consumes one token. Packets are dropped when no tokens are available.
pub struct TokenBucket {
    /// Current number of available tokens.
    tokens: u64,
    /// Maximum number of tokens (bucket capacity).
    capacity: u64,
    /// Last cycle count when tokens were refilled.
    last_cycle: usize,
    /// Cycle cost per token (inverse of refill rate).
    cost: usize,
}

impl TokenBucket {
    /// Creates a new token bucket with the specified capacity and refill rate.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum number of tokens
    /// * `cost` - Cycle cost per token (higher = slower refill)
    pub const fn new(capacity: u64, cost: usize) -> Self {
        Self {
            tokens: capacity,
            capacity,
            last_cycle: 0,
            cost,
        }
    }

    /// Checks if a packet is allowed and consumes a token if available.
    ///
    /// Refills tokens based on elapsed cycles since the last check,
    /// then consumes one token if available.
    ///
    /// # Returns
    ///
    /// True if a token was available and consumed, false otherwise
    pub fn allow(&mut self) -> bool {
        let now: usize = get_time();
        let delta = now.wrapping_sub(self.last_cycle);
        if delta >= self.cost {
            let refill = (delta / self.cost) as u64;
            self.tokens = (self.tokens + refill).min(self.capacity);
            self.last_cycle = now;
        }
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

/// Reads the current cycle count for timing operations.
///
/// # Returns
///
/// Current CPU cycle count
fn get_time() -> usize {
    unsafe {
        let c: usize;
        asm!("csrr {}, mcycle", out(reg) c);
        c
    }
}
