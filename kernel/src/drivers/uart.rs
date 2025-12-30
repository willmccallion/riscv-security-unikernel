use core::fmt;

const UART_BASE: usize = 0x1000_0000;
const THR: isize = 0;

pub struct Uart {
    base: *mut u8,
}

impl Uart {
    pub fn new() -> Self {
        Self {
            base: UART_BASE as *mut u8,
        }
    }

    pub fn write_byte(&self, byte: u8) {
        unsafe {
            self.base.offset(THR).write_volatile(byte);
        }
    }
}

impl fmt::Write for Uart {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            self.write_byte(byte);
        }
        Ok(())
    }
}

pub struct GlobalUart;
impl fmt::Write for GlobalUart {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        Uart::new().write_str(s)
    }
}

#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => ({
        use ::core::fmt::Write;
        let _ = write!($crate::drivers::uart::GlobalUart, $($arg)*);
    });
}

#[macro_export]
macro_rules! kprintln {
    () => ($crate::kprint!("\n"));
    ($($arg:tt)*) => ($crate::kprint!("{}\n", format_args!($($arg)*)));
}
