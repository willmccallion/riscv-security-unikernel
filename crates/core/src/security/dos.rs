//! DDoS (Distributed Denial of Service) mitigation mechanisms.
//!
//! Implements multiple techniques for detecting and mitigating DDoS attacks:
//! - Count-Min Sketch for heavy hitter detection
//! - Penalty box for IP address banning
//! - Token bucket rate limiting
//!
//! The time-sensitive structures ([`PenaltyBox`], [`TokenBucket`]) are
//! time-source agnostic: callers pass a `now` value (cycles on the
//! RISC-V unikernel, nanoseconds on the Linux daemon) alongside the
//! duration/cost constants, which must share the same unit.

/// Width of the Count-Min Sketch hash table.
const CMS_WIDTH: usize = 128;

/// Depth (number of hash functions) in the Count-Min Sketch.
const CMS_DEPTH: usize = 4;

/// Entry in the penalty box tracking a banned IP address.
#[derive(Copy, Clone, Debug)]
struct BanEntry {
    /// Banned IP address in network byte order.
    ip: u32,
    /// Time-source value at which the ban expires.
    expiry: u64,
}

/// Penalty box for tracking banned IP addresses.
///
/// Maintains a fixed-size table of banned IPs with expiration times.
/// When the table is full, new bans overwrite the oldest entries.
#[derive(Debug)]
pub struct PenaltyBox {
    /// Array of ban entries, limited to 16 for memory efficiency.
    entries: [BanEntry; 16],
    /// Round-robin pointer for eviction when every slot is still active.
    /// Without this, every overflow ban lands in slot 0, so an attacker
    /// who learns the table is full can pin one IP and watch every
    /// subsequent ban evict it (audit HIGH-3).
    next_evict: usize,
}

impl Default for PenaltyBox {
    fn default() -> Self {
        Self::new()
    }
}

impl PenaltyBox {
    /// Creates a new empty penalty box.
    pub const fn new() -> Self {
        Self {
            entries: [BanEntry { ip: 0, expiry: 0 }; 16],
            next_evict: 0,
        }
    }

    /// Bans an IP address until `now + duration`.
    ///
    /// If the penalty box is full, the oldest expired entry is
    /// overwritten; if none are expired, the entry at index 0 is
    /// replaced.
    ///
    /// # Arguments
    ///
    /// * `ip_bytes` - IP address as 4 bytes in network byte order.
    /// * `duration` - Ban duration in time-source units.
    /// * `now`      - Current time-source value.
    pub fn ban(&mut self, ip_bytes: &[u8], duration: u64, now: u64) {
        let ip = u32::from_be_bytes([ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]]);

        for i in 0..16 {
            if self.entries[i].expiry < now {
                self.entries[i] = BanEntry {
                    ip,
                    expiry: now + duration,
                };
                return;
            }
        }
        let idx = self.next_evict;
        self.next_evict = (self.next_evict + 1) % 16;
        self.entries[idx] = BanEntry {
            ip,
            expiry: now + duration,
        };
    }

    /// Checks if an IP address is currently banned.
    ///
    /// # Arguments
    ///
    /// * `ip_bytes` - IP address as 4 bytes in network byte order.
    /// * `now` - Current time-source value; bans with `expiry > now` are
    ///   considered active.
    ///
    /// # Returns
    ///
    /// `true` if the IP is banned and the ban has not expired.
    pub fn is_banned(&self, ip_bytes: &[u8], now: u64) -> bool {
        let ip = u32::from_be_bytes([ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]]);

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
#[derive(Debug)]
pub struct CountMinSketch {
    /// Two-dimensional array: depth rows, width columns.
    matrix: [[u16; CMS_WIDTH]; CMS_DEPTH],
    /// Per-boot secret mixed into every hash function. Without it, an
    /// attacker with source access can precompute a 4-way collision
    /// against a victim IP and force legitimate low-volume clients to
    /// trip the heavy-hitter threshold. Same class of bug as a
    /// fixed-salt SYN cookie; the kernel seeds this from `mcycle ^ MAC`
    /// via [`Self::reseed`] during init.
    seed: u32,
}

impl Default for CountMinSketch {
    fn default() -> Self {
        Self::new()
    }
}

impl CountMinSketch {
    /// Creates a new empty Count-Min Sketch with a deterministic seed.
    ///
    /// Kernel code should call [`Self::reseed`] after construction with
    /// a per-boot secret; tests and benches intentionally use this
    /// fixed-seed constructor so their collision geometry is stable.
    pub const fn new() -> Self {
        Self {
            matrix: [[0; CMS_WIDTH]; CMS_DEPTH],
            seed: 0,
        }
    }

    /// Mixes a per-boot secret into every hash function so offline
    /// collision-search against the sketch has to guess the seed.
    ///
    /// Safe to call before the sketch has seen any data; calling it
    /// after would invalidate existing counts, so callers should
    /// reseed once during init and not again.
    pub fn reseed(&mut self, seed: u64) {
        self.seed = (seed as u32) ^ ((seed >> 32) as u32);
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
            let mut hash: u32 = self.seed ^ (0xDEAD_BEEF + i as u32);
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
        for row in &mut self.matrix {
            for val in row.iter_mut() {
                *val = 0;
            }
        }
    }
}

/// Token bucket rate limiter.
///
/// Implements a token bucket algorithm to limit the rate of packet
/// processing. Tokens are refilled at a fixed rate based on elapsed
/// time-source ticks; each packet consumes one token.
#[derive(Debug)]
pub struct TokenBucket {
    /// Current number of available tokens.
    tokens: u64,
    /// Maximum number of tokens (bucket capacity).
    capacity: u64,
    /// Time-source value at the last refill.
    last_time: u64,
    /// Cost (in time-source units) per token refilled.
    cost: u64,
}

impl TokenBucket {
    /// Creates a new token bucket with the specified capacity and refill cost.
    ///
    /// # Arguments
    ///
    /// * `capacity` - Maximum number of tokens.
    /// * `cost`     - Time-source units per token (higher = slower refill).
    pub const fn new(capacity: u64, cost: u64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            last_time: 0,
            cost,
        }
    }

    /// Checks if a packet is allowed and consumes a token if available.
    ///
    /// Refills tokens based on time-source units elapsed since the last
    /// call, then consumes one token if available.
    ///
    /// # Arguments
    ///
    /// * `now` - Current time-source value.
    ///
    /// # Returns
    ///
    /// `true` if a token was available and consumed, `false` otherwise.
    pub fn allow(&mut self, now: u64) -> bool {
        let delta = now.wrapping_sub(self.last_time);
        if self.cost > 0 && delta >= self.cost {
            let refill = delta / self.cost;
            self.tokens = (self.tokens + refill).min(self.capacity);
            self.last_time = now;
        }
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod token_bucket_tests {
    use super::TokenBucket;

    #[test]
    fn starts_full() {
        let mut b = TokenBucket::new(5, 10);
        for _ in 0..5 {
            assert!(b.allow(0));
        }
        assert!(!b.allow(0), "6th packet at same tick must be denied");
    }

    #[test]
    fn refills_over_time() {
        let mut b = TokenBucket::new(5, 10);
        for _ in 0..5 {
            assert!(b.allow(0));
        }
        // 30 ticks elapsed → delta 30, cost 10 → 3 new tokens.
        assert!(b.allow(30));
        assert!(b.allow(30));
        assert!(b.allow(30));
        assert!(!b.allow(30));
    }

    #[test]
    fn refill_saturates_at_capacity() {
        let mut b = TokenBucket::new(5, 10);
        for _ in 0..5 {
            assert!(b.allow(0));
        }
        // Huge elapsed time — refill would be billions, must clamp to capacity.
        assert!(b.allow(u64::MAX / 2));
        for _ in 0..4 {
            assert!(b.allow(u64::MAX / 2));
        }
        assert!(!b.allow(u64::MAX / 2));
    }

    #[test]
    fn cost_zero_never_refills() {
        // Guard against division by zero. The bucket is usable up to
        // its starting capacity and then permanently empty.
        let mut b = TokenBucket::new(3, 0);
        assert!(b.allow(0));
        assert!(b.allow(100));
        assert!(b.allow(u64::MAX));
        assert!(!b.allow(u64::MAX));
    }

    #[test]
    fn wraparound_elapsed_is_handled() {
        // `now.wrapping_sub(last_time)` must tolerate the clock source
        // rolling. Seed last_time near u64::MAX, then call with a small
        // `now` — delta wraps to a positive refill amount, not to zero.
        let mut b = TokenBucket::new(1, 10);
        assert!(b.allow(u64::MAX - 5));
        assert!(!b.allow(u64::MAX - 5));
        // 10 ticks after u64::MAX - 5 = wraps to 4.
        assert!(b.allow(4));
    }

    #[test]
    fn denies_when_drained_without_elapsed_time() {
        let mut b = TokenBucket::new(2, 100);
        assert!(b.allow(50));
        assert!(b.allow(50));
        // 50 ticks later — delta 0 from last_time (which is still 0
        // because refill never ran), cost 100, so no refill yet.
        assert!(!b.allow(50));
    }
}
