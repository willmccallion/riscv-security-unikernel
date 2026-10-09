//! Count-Min Sketch: approximate per-item counts in fixed memory.

/// Width of the Count-Min Sketch hash table.
const CMS_WIDTH: usize = 128;

/// Depth (number of hash functions) in the Count-Min Sketch.
const CMS_DEPTH: usize = 4;

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
    pub const fn reseed(&mut self, seed: u64) {
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
