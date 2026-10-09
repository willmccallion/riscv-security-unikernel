//! The sketch configurations under study, behind one object-safe trait so
//! each experiment can sweep sizes that are const generic parameters.

use sec_core::security::scan::PortScanDetector;
use sec_core::security::sketch::{CountMinSketch, VirtualHyperLogLog};

/// How a sketch counts an occurrence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Update {
    /// Increment every counter of the item.
    Classic,
    /// Raise only the counters at the item's current estimate.
    Conservative,
}

/// How a sketch forgets old traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aging {
    /// Clear every counter every `intervals` decay intervals.
    Reset { intervals: u32 },
    /// Halve every counter every interval.
    Decay,
}

/// A frequency sketch the experiments can drive.
pub trait FrequencySketch {
    /// Counts one occurrence and returns the item's new estimate.
    fn insert(&mut self, item: &[u8]) -> u16;
    /// The current estimate for `item`.
    fn estimate(&self, item: &[u8]) -> u16;
    /// Called once per decay interval; ages counts per the sketch's [`Aging`].
    fn end_interval(&mut self, interval: u32);
    /// Bytes of counters held.
    fn memory_bytes(&self) -> usize;
    /// Columns per row.
    fn width(&self) -> usize;
    /// Rows.
    fn depth(&self) -> usize;
}

/// A Count-Min Sketch with a fixed update rule and aging policy.
pub struct Cms<const W: usize, const D: usize> {
    sketch: Box<CountMinSketch<W, D>>,
    update: Update,
    aging: Aging,
    key: [u8; 16],
}

impl<const W: usize, const D: usize> Cms<W, D> {
    /// A fresh sketch keyed with `key`.
    pub fn new(update: Update, aging: Aging, key: [u8; 16]) -> Self {
        Self {
            sketch: Box::new(CountMinSketch::new(key)),
            update,
            aging,
            key,
        }
    }
}

impl<const W: usize, const D: usize> FrequencySketch for Cms<W, D> {
    fn insert(&mut self, item: &[u8]) -> u16 {
        match self.update {
            Update::Classic => self.sketch.insert_classic(item),
            Update::Conservative => self.sketch.insert(item),
        }
    }

    fn estimate(&self, item: &[u8]) -> u16 {
        self.sketch.estimate(item)
    }

    fn end_interval(&mut self, interval: u32) {
        match self.aging {
            Aging::Decay => self.sketch.decay(),
            Aging::Reset { intervals } => {
                if (interval + 1).is_multiple_of(intervals) {
                    *self.sketch = CountMinSketch::new(self.key);
                }
            }
        }
    }

    fn memory_bytes(&self) -> usize {
        CountMinSketch::<W, D>::MEMORY_BYTES
    }

    fn width(&self) -> usize {
        W
    }

    fn depth(&self) -> usize {
        D
    }
}

/// Builds one boxed [`Cms`] per listed `(width, depth)` pair.
#[macro_export]
macro_rules! sketches {
    ($update:expr, $aging:expr, $key:expr, $(($w:literal, $d:literal)),+ $(,)?) => {
        vec![$(
            Box::new($crate::sketches::Cms::<$w, $d>::new($update, $aging, $key))
                as Box<dyn $crate::sketches::FrequencySketch>
        ),+]
    };
}

/// A port-scan detector the experiments can drive.
pub trait ScanDetector {
    /// Records a connection attempt; returns whether `source` is now
    /// judged to be scanning.
    fn observe(&mut self, source: [u8; 4], port: u16) -> bool;
    /// Bytes of state held.
    fn memory_bytes(&self) -> usize;
}

impl ScanDetector for Box<PortScanDetector> {
    fn observe(&mut self, source: [u8; 4], port: u16) -> bool {
        PortScanDetector::observe(self, source, port).is_some()
    }

    fn memory_bytes(&self) -> usize {
        size_of::<PortScanDetector>()
    }
}

/// A virtual HyperLogLog that judges a source to be scanning as soon as
/// its estimate passes 64 ports, with no confirmation.
pub struct VhllThreshold<const POOL: usize, const PER_FLOW: usize> {
    estimates: Box<VirtualHyperLogLog<POOL, PER_FLOW>>,
}

impl<const POOL: usize, const PER_FLOW: usize> VhllThreshold<POOL, PER_FLOW> {
    /// A fresh detector keyed with `key`.
    pub fn new(key: [u8; 16]) -> Self {
        Self {
            estimates: Box::new(VirtualHyperLogLog::new(key)),
        }
    }
}

impl<const POOL: usize, const PER_FLOW: usize> ScanDetector for VhllThreshold<POOL, PER_FLOW> {
    fn observe(&mut self, source: [u8; 4], port: u16) -> bool {
        self.estimates.insert(&source, &port.to_be_bytes())
            && self.estimates.estimate(&source) > 64.0
    }

    fn memory_bytes(&self) -> usize {
        POOL
    }
}
