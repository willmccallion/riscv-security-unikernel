//! Firewall rule management.
//!
//! Maintains a list of blocked destination ports and provides
//! fast lookup for packet filtering decisions.

use crate::kprintln;

/// Firewall state tracking blocked ports.
///
/// Maintains a fixed-size array of blocked port numbers for
/// efficient O(n) lookup where n is the number of blocked ports.
pub struct FirewallState {
    /// Array of blocked port numbers.
    blocked_ports: [u16; 16],
    /// Number of ports currently blocked.
    count: usize,
}

impl FirewallState {
    /// Creates a new empty firewall state.
    pub const fn new() -> Self {
        Self {
            blocked_ports: [0; 16],
            count: 0,
        }
    }

    /// Blocks a destination port.
    ///
    /// Adds the port to the blocked list if there is space.
    /// Logs the action to the console.
    ///
    /// # Arguments
    ///
    /// * `port` - Port number to block
    pub fn block_port(&mut self, port: u16) {
        if self.count < 16 {
            self.blocked_ports[self.count] = port;
            self.count += 1;
            kprintln!("\x1b[36m[SDN]\x1b[0m Rule Added: BLOCK Port {}", port);
        }
    }

    /// Checks if a port is blocked.
    ///
    /// # Arguments
    ///
    /// * `port` - Port number to check
    ///
    /// # Returns
    ///
    /// True if the port is in the blocked list, false otherwise
    pub fn is_blocked(&self, port: u16) -> bool {
        for i in 0..self.count {
            if self.blocked_ports[i] == port {
                return true;
            }
        }
        false
    }
}
