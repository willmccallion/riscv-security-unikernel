//! Hardware device drivers.
//!
//! This module provides drivers for hardware devices including UART
//! for console output and VirtIO for network interface access.

/// UART driver for serial console output.
pub mod uart;

/// VirtIO network device driver.
pub mod virtio;

/// VirtIO entropy device driver.
pub mod virtio_rng;

mod virtio_mmio;
