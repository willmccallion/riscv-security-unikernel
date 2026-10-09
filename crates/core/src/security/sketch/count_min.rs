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
/// Each row's column comes from its own slice of one keyed 64-bit SipHash
/// of the item, so rows are independent and, without the key, an attacker
/// cannot choose sources that collide with a victim and push its estimate
/// over a threshold. `WIDTH` must therefore be a power of two with
/// `DEPTH · log2(WIDTH) <= 64`.
#[derive(Debug)]
pub struct CountMinSketch<const WIDTH: usize, const DEPTH: usize> {
    rows: [[u16; WIDTH]; DEPTH],
    key: [u8; 16],
}

impl<const WIDTH: usize, const DEPTH: usize> CountMinSketch<WIDTH, DEPTH> {
    const COLUMN_BITS: u32 = WIDTH.trailing_zeros();
    const VALID: () = assert!(
        WIDTH.is_power_of_two() && DEPTH > 0 && DEPTH as u32 * WIDTH.trailing_zeros() <= 64,
        "WIDTH must be a power of two and one 64-bit hash must cover every row"
    );

    /// Bytes of counters the sketch holds.
    pub const MEMORY_BYTES: usize = WIDTH * DEPTH * size_of::<u16>();

    /// Creates an empty sketch whose hashing is keyed with `key`.
    pub const fn new(key: [u8; 16]) -> Self {
        let () = Self::VALID;
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

    /// Halves every counter, so old traffic fades out exponentially
    /// instead of vanishing all at once at a window boundary.
    pub fn decay(&mut self) {
        for counter in self.rows.iter_mut().flatten() {
            *counter >>= 1;
        }
    }

    /// The column `item` maps to in each row: consecutive `log2(WIDTH)`-bit
    /// slices of one keyed hash.
    ///
    /// Deriving rows as `h1 + i·h2` instead would make any two items that
    /// share `h1` and `h2` modulo `WIDTH` collide in every row at once, a
    /// `1/WIDTH²` chance per pair no matter how many rows there are.
    fn positions(&self, item: &[u8]) -> [usize; DEPTH] {
        let mut hash = siphash24(&self.key, item);
        let mut columns = [0; DEPTH];
        for column in &mut columns {
            *column = (hash as usize) & (WIDTH - 1);
            hash = hash.checked_shr(Self::COLUMN_BITS).unwrap_or(0);
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
    fn decay_halves_estimates() {
        let mut cms = CountMinSketch::<64, 3>::new([1; 16]);
        for _ in 0..90 {
            let _ = cms.insert(b"a");
        }

        cms.decay();

        assert_eq!(cms.estimate(b"a"), 45);
    }

    #[test]
    fn a_burst_straddling_a_decay_still_accumulates() {
        let mut cms = CountMinSketch::<64, 3>::new([1; 16]);
        for _ in 0..90 {
            let _ = cms.insert(b"a");
        }
        cms.decay();
        let mut estimate = 0;
        for _ in 0..90 {
            estimate = cms.insert(b"a");
        }

        assert_eq!(estimate, 135);
    }

    #[test]
    fn rows_collide_independently() {
        const ITEMS: usize = 2000;
        let cms = CountMinSketch::<16, 4>::new([5; 16]);
        let mut columns = [[0u8; 4]; ITEMS];
        for (i, slot) in columns.iter_mut().enumerate() {
            *slot = cms.positions(&(i as u32).to_be_bytes()).map(|c| c as u8);
        }

        let mut full_collisions = 0;
        for a in 0..ITEMS {
            for b in a + 1..ITEMS {
                full_collisions += usize::from(columns[a] == columns[b]);
            }
        }

        // About 2M pairs: ~30 expected if rows are independent (1/16^4 each),
        // ~7800 if rows were derived as h1 + i*h2 (1/16^2 each).
        assert!(full_collisions < 200, "{full_collisions} pairs collide in every row");
    }

    #[test]
    fn memory_is_width_times_depth_counters() {
        assert_eq!(CountMinSketch::<1024, 3>::MEMORY_BYTES, 6144);
    }
}
