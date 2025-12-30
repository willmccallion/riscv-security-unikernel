// Always load uart
pub mod uart;

// RISC-V driver
pub mod virtio;

// Unified export
pub mod net_device {
    pub use super::virtio::VirtioNet as NetDevice;
}
