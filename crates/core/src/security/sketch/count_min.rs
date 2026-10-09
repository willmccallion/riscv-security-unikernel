//! Count-Min Sketch: approximate per-item counts in fixed memory.

use crate::security::hash::siphash24;

/// Count-Min Sketch data structure for approximate frequency counting.
///
/// Each item maps to one counter per row; its estimate is the smallest of
/// those counters, which never undercounts and overcounts only by what
/// collides with it. With `WIDTH` columns and `DEPTH` rows over a stream
/// of `n` items, an estimate exceeds the true count by more than
/// `e·n / WIDTH` with probability at most `e^-DEPTH`.
///
/// Rows are indexed by one keyed SipHash of the item (Kirsch–Mitzenmacher
/// double hashing), so without the key an attacker cannot choose sources
/// that collide with a victim and push its estimate over a threshold.
#[derive(Debug)]
pub struct CountMinSketch<const WIDTH: usize, const DEPTH: usize> {
    rows: [[u16; WIDTH]; DEPTH],
    key: [u8; 16],
}

impl<const WIDTH: usize, const DEPTH: usize> CountMinSketch<WIDTH, DEPTH> {
    const NON_EMPTY: () = assert!(WIDTH > 0 && DEPTH > 0, "sketch needs at least one counter");

    /// Bytes of counters the sketch holds.
    pub const MEMORY_BYTES: usize = WIDTH * DEPTH * size_of::<u16>();

    /// Creates an empty sketch whose hashing is keyed with `key`.
    pub const fn new(key: [u8; 16]) -> Self {
        let () = Self::NON_EMPTY;
        Self {
            rows: [[0; WIDTH]; DEPTH],
            key,
        }
    }

    /// Counts one occurrence of `item` and returns its new estimate.
    ///
    /// Uses conservative update: only the item's counters that sit at its
    /// current estimate are raised. The estimate is still never below the
    /// true count, but counters shared with other items grow far less, so
    /// estimates are much tighter than with [`Self::insert_classic`].
    pub fn insert(&mut self, item: &[u8]) -> u16 {
        let columns = self.positions(item);
        let estimate = self.estimate_at(&columns).saturating_add(1);
        for (row, column) in self.rows.iter_mut().zip(columns) {
            row[column] = row[column].max(estimate);
        }
        estimate
    }

    /// Counts one occurrence of `item` by incrementing every one of its
    /// counters, the textbook update. Kept for comparison with
    /// [`Self::insert`].
    pub fn insert_classic(&mut self, item: &[u8]) -> u16 {
        let columns = self.positions(item);
        for (row, column) in self.rows.iter_mut().zip(columns) {
            row[column] = row[column].saturating_add(1);
        }
        self.estimate_at(&columns)
    }

    /// The current estimate for `item`, without counting it.
    pub fn estimate(&self, item: &[u8]) -> u16 {
        self.estimate_at(&self.positions(item))
    }

    fn estimate_at(&self, columns: &[usize; DEPTH]) -> u16 {
        self.rows
            .iter()
            .zip(columns)
            .map(|(row, &column)| row[column])
            .min()
            .unwrap_or(0)
    }

    /// Resets all counters to zero.
    pub const fn reset(&mut self) {
        self.rows = [[0; WIDTH]; DEPTH];
    }

    /// The column `item` maps to in each row: `h1 + i·h2` from the two
    /// halves of one keyed hash, which behaves like independent hashes per
    /// row.
    fn positions(&self, item: &[u8]) -> [usize; DEPTH] {
        let hash = siphash24(&self.key, item);
        let h1 = hash as u32 as usize;
        let h2 = ((hash >> 32) as u32 | 1) as usize;
        let mut columns = [0; DEPTH];
        for (i, column) in columns.iter_mut().enumerate() {
            *column = h1.wrapping_add(i.wrapping_mul(h2)) % WIDTH;
        }
        columns
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimate_matches_insert_and_does_not_count() {
        let mut cms = CountMinSketch::<64, 3>::new([1; 16]);
        for _ in 0..5 {
            let _ = cms.insert(b"a");
        }

        assert_eq!(cms.estimate(b"a"), 5);
        assert_eq!(cms.estimate(b"a"), 5);
    }

    #[test]
    fn unseen_item_in_an_empty_sketch_estimates_zero() {
        let cms = CountMinSketch::<64, 3>::new([1; 16]);

        assert_eq!(cms.estimate(b"never"), 0);
    }

    #[test]
    fn conservative_update_is_never_looser_than_classic() {
        const DISTINCT: u16 = 37;
        const INSERTS: u16 = 200;
        let mut conservative = CountMinSketch::<8, 2>::new([3; 16]);
        let mut classic = CountMinSketch::<8, 2>::new([3; 16]);
        for i in 0..INSERTS {
            let item = (i % DISTINCT).to_be_bytes();
            let _ = conservative.insert(&item);
            let _ = classic.insert_classic(&item);
        }

        for k in 0..DISTINCT {
            let item = k.to_be_bytes();
            let truth = (0..INSERTS).filter(|i| i % DISTINCT == k).count();
            let tight = usize::from(conservative.estimate(&item));
            assert!(truth <= tight, "conservative undercounted item {k}");
            assert!(tight <= usize::from(classic.estimate(&item)), "item {k}");
        }
    }

    #[test]
    fn memory_is_width_times_depth_counters() {
        assert_eq!(CountMinSketch::<1024, 3>::MEMORY_BYTES, 6144);
    }
}
