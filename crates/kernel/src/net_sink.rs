//! Bridges `sec-core`'s [`PacketSink`] to the VirtIO-Net driver.
//!
//! [`PacketSink`]: sec_core::net::PacketSink

use crate::drivers::net_device::NetDevice;
use sec_core::net::PacketSink;

/// Zero-sized sink wrapping the global [`NetDevice`] singleton.
#[derive(Debug, Default, Clone, Copy)]
pub struct VirtioNetSink;

impl PacketSink for VirtioNetSink {
    #[inline(always)]
    fn send(&mut self, frame: &[u8]) {
        NetDevice::send(frame);
    }
}
