//! Kernel panic handler.
//!
//! Provides a custom panic handler that logs panic information
//! to the UART console and enters an infinite loop to halt execution.

use crate::kprintln;
use core::panic::PanicInfo;

/// Panic handler called when the kernel encounters an unrecoverable error.
///
/// Logs the panic information to the console and halts the system
/// by entering an infinite loop. This prevents undefined behavior
/// and allows debugging via serial console output.
///
/// # Arguments
///
/// * `info` - Panic information including message and location
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    kprintln!("\n\x1b[31m[KERNEL PANIC]\x1b[0m {:?}", info);
    loop {}
}
