//! Count-Min Sketch: approximate per-item counts in fixed memory.

use crate::security::hash::siphash24;

/// Width of the Count-Min Sketch hash table.
const CMS_WIDTH: usize = 128;

/// Depth (number of hash functions) in the Count-Min Sketch.
const CMS_DEPTH: usize = 4;

/// Count-Min Sketch data structure for approximate frequency counting.
///
/// Each item maps to one counter per row; its estimate is the smallest of
/// those counters, which never undercounts and overcounts only by what
/// collides with it. Rows are indexed by one keyed SipHash of the item
/// (Kirsch–Mitzenmacher double hashing), so without the key an attacker
/// cannot choose sources that collide with a victim and push its estimate
/// over the heavy-hitter threshold.
#[derive(Debug)]
pub struct CountMinSketch {
    rows: [[u16; CMS_WIDTH]; CMS_DEPTH],
    key: [u8; 16],
}

impl CountMinSketch {
    /// Creates an empty sketch whose hashing is keyed with `key`.
    pub const fn new(key: [u8; 16]) -> Self {
        Self {
            rows: [[0; CMS_WIDTH]; CMS_DEPTH],
            key,
        }
    }

    /// Counts one occurrence of `item` and returns its new estimate.
    pub fn insert(&mut self, item: &[u8]) -> u16 {
        let mut min = u16::MAX;
        for (row, column) in self.rows.iter_mut().zip(positions(&self.key, item)) {
            row[column] = row[column].saturating_add(1);
            min = min.min(row[column]);
        }
        min
    }

    /// Resets all counters to zero.
    pub const fn reset(&mut self) {
        self.rows = [[0; CMS_WIDTH]; CMS_DEPTH];
    }
}

/// The column `item` maps to in each row: `h1 + i·h2` from the two halves
/// of one keyed hash, which behaves like independent hashes per row.
fn positions(key: &[u8; 16], item: &[u8]) -> [usize; CMS_DEPTH] {
    let hash = siphash24(key, item);
    let h1 = hash as u32 as usize;
    let h2 = ((hash >> 32) as u32 | 1) as usize;
    let mut columns = [0; CMS_DEPTH];
    for (i, column) in columns.iter_mut().enumerate() {
        *column = h1.wrapping_add(i.wrapping_mul(h2)) % CMS_WIDTH;
    }
    columns
}
