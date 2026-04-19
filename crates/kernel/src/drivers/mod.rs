//! Hardware device drivers.
//!
//! This module provides drivers for hardware devices including UART
//! for console output and VirtIO for network interface access.

/// UART driver for serial console output.
pub mod uart;

/// VirtIO network device driver.
pub mod virtio;

/// Unified network device interface.
///
/// Exports the primary network device driver as a generic NetDevice type
/// to allow easy swapping of implementations.
pub mod net_device {
    pub use super::virtio::VirtioNet as NetDevice;
}
