//! Probabilistic data structures that summarise a packet stream in fixed
//! memory, trading exact answers for bounded error.

mod count_min;
mod hyperloglog;

pub use count_min::CountMinSketch;
pub use hyperloglog::HyperLogLog;
