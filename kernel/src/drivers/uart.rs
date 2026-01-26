//! UART (Universal Asynchronous Receiver-Transmitter) driver.
//!
//! Provides low-level access to the serial console for kernel logging
//! and debugging output. This driver writes directly to memory-mapped
//! UART registers.

use core::fmt;

/// Base memory address of the UART device.
const UART_BASE: usize = 0x1000_0000;

/// Transmit Holding Register offset.
const THR: isize = 0;

/// UART device driver.
///
/// Provides methods for writing bytes to the serial console.
/// The driver accesses the UART through memory-mapped I/O registers.
pub struct Uart {
    base: *mut u8,
}

impl Uart {
    /// Creates a new UART driver instance.
    ///
    /// The driver is initialized to use the standard QEMU/RISC-V
    /// UART base address.
    pub fn new() -> Self {
        Self {
            base: UART_BASE as *mut u8,
        }
    }

    /// Writes a single byte to the UART transmit register.
    ///
    /// # Arguments
    ///
    /// * `byte` - Byte to transmit
    pub fn write_byte(&self, byte: u8) {
        unsafe {
            self.base.offset(THR).write_volatile(byte);
        }
    }
}

impl fmt::Write for Uart {
    /// Writes a string to the UART by writing each byte sequentially.
    ///
    /// # Arguments
    ///
    /// * `s` - String to write
    ///
    /// # Returns
    ///
    /// Always returns Ok(()) as UART writes are fire-and-forget
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            self.write_byte(byte);
        }
        Ok(())
    }
}

/// Global UART instance for use with the kprint! macro.
///
/// This is a zero-sized type that creates a new Uart instance
/// on each write operation, allowing the kprint! macro to work
/// without requiring a global mutable Uart instance.
pub struct GlobalUart;

impl fmt::Write for GlobalUart {
    /// Writes a string using a temporary Uart instance.
    ///
    /// # Arguments
    ///
    /// * `s` - String to write
    fn write_str(&mut self, s: &str) -> fmt::Result {
        Uart::new().write_str(s)
    }
}

/// Macro for printing to the kernel console.
///
/// Formats the arguments and writes them to the UART. This is the
/// kernel equivalent of the standard library's print! macro.
#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => ({
        use ::core::fmt::Write;
        let _ = write!($crate::drivers::uart::GlobalUart, $($arg)*);
    });
}

/// Macro for printing a line to the kernel console.
///
/// Formats the arguments, appends a newline, and writes to the UART.
/// This is the kernel equivalent of the standard library's println! macro.
#[macro_export]
macro_rules! kprintln {
    () => ($crate::kprint!("\n"));
    ($($arg:tt)*) => ($crate::kprint!("{}\n", format_args!($($arg)*)));
}
