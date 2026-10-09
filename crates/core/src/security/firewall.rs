//! Firewall rule management.
//!
//! Maintains a list of blocked destination ports and provides
//! fast lookup for packet filtering decisions.

/// Reasons a [`FirewallState::block_port`] call may be rejected, so the
/// mgmt dispatcher can report the failure in the command's ack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallError {
    /// The 16-slot table is already full.
    Full,
}

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
    /// Duplicates are no-ops that return `Ok(())`: without dedup an
    /// authenticated attacker could spam the same port 16 times and
    /// permanently wedge the table against further legitimate blocks.
    ///
    /// # Errors
    ///
    /// Returns [`FirewallError::Full`] if the 16-slot table is full
    /// and `port` is not already present. Callers must surface the
    /// error rather than discard it.
    pub fn block_port(&mut self, port: u16) -> Result<(), FirewallError> {
        for i in 0..self.count {
            if self.blocked_ports[i] == port {
                return Ok(());
            }
        }
        if self.count >= 16 {
            return Err(FirewallError::Full);
        }
        self.blocked_ports[self.count] = port;
        self.count += 1;
        Ok(())
    }

    /// Removes `port` from the blocked list. Unblocking a port that is not
    /// blocked is a no-op. Does not preserve the order of the others.
    pub fn unblock_port(&mut self, port: u16) {
        let Some(i) = self.blocked_ports[..self.count].iter().position(|&p| p == port) else {
            return;
        };
        self.count -= 1;
        self.blocked_ports[i] = self.blocked_ports[self.count];
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
