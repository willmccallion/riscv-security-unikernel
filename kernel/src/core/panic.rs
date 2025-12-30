use crate::kprintln;
use core::panic::PanicInfo;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    kprintln!("\n\x1b[31m[KERNEL PANIC]\x1b[0m {:?}", info);
    loop {}
}
