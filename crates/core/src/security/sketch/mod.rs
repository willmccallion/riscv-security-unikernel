//! Probabilistic data structures that summarise a packet stream in fixed
//! memory, trading exact answers for bounded error.

mod count_min;

pub use count_min::CountMinSketch;
