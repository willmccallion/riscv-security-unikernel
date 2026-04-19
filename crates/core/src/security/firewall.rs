//! Firewall rule management.
//!
//! Maintains a list of blocked destination ports and provides
//! fast lookup for packet filtering decisions.

/// Firewall state tracking blocked ports.
///
/// Maintains a fixed-size array of blocked port numbers for
/// efficient O(n) lookup where n is the number of blocked ports.
#[derive(Debug)]
pub struct FirewallState {
    /// Array of blocked port numbers.
    blocked_ports: [u16; 16],
    /// Number of ports currently blocked.
    count: usize,
}

impl Default for FirewallState {
    fn default() -> Self {
        Self::new()
    }
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
    /// Adds the port to the blocked list if there is space. Silently
    /// ignores the request if the table is already full (caller may
    /// instead observe state via [`Self::is_blocked`]).
    ///
    /// # Arguments
    ///
    /// * `port` - Port number to block
    pub fn block_port(&mut self, port: u16) {
        if self.count < 16 {
            self.blocked_ports[self.count] = port;
            self.count += 1;
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
