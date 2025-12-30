use crate::kprintln;

pub struct FirewallState {
    blocked_ports: [u16; 16],
    count: usize,
}

impl FirewallState {
    pub const fn new() -> Self {
        Self {
            blocked_ports: [0; 16],
            count: 0,
        }
    }

    pub fn block_port(&mut self, port: u16) {
        if self.count < 16 {
            self.blocked_ports[self.count] = port;
            self.count += 1;
            kprintln!("\x1b[36m[SDN]\x1b[0m Rule Added: BLOCK Port {}", port);
        }
    }

    pub fn is_blocked(&self, port: u16) -> bool {
        for i in 0..self.count {
            if self.blocked_ports[i] == port {
                return true;
            }
        }
        false
    }
}
