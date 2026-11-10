//! Firewall rule management.
//!
//! Maintains a list of blocked destination ports and provides
//! fast lookup for packet filtering decisions.

/// How many ports can be blocked at once.
pub const MAX_BLOCKED_PORTS: usize = 16;

/// Reasons a [`FirewallState::block_port`] call may be rejected, so the
/// mgmt dispatcher can report the failure in the command's ack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallError {
    /// [`MAX_BLOCKED_PORTS`] ports are already blocked.
    Full,
}

/// Firewall state tracking blocked ports.
///
/// Maintains a fixed-size array of blocked port numbers for
/// efficient O(n) lookup where n is the number of blocked ports.
#[derive(Debug)]
pub struct FirewallState {
    /// Array of blocked port numbers.
    blocked_ports: [u16; MAX_BLOCKED_PORTS],
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
            blocked_ports: [0; MAX_BLOCKED_PORTS],
            count: 0,
        }
    }

    /// Blocks a destination port.
    ///
    /// Duplicates are no-ops that return `Ok(())`: without dedup an
    /// authenticated attacker could spam the same port until the table
    /// was full and wedge it against further legitimate blocks.
    ///
    /// # Errors
    ///
    /// Returns [`FirewallError::Full`] if the table is full and `port` is
    /// not already present. Callers must surface the error rather than
    /// discard it.
    pub fn block_port(&mut self, port: u16) -> Result<(), FirewallError> {
        if self.is_blocked(port) {
            return Ok(());
        }
        if self.count >= MAX_BLOCKED_PORTS {
            return Err(FirewallError::Full);
        }
        self.blocked_ports[self.count] = port;
        self.count += 1;
        Ok(())
    }

    /// Removes `port` from the blocked list. Unblocking a port that is not
    /// blocked is a no-op. Does not preserve the order of the others.
    pub fn unblock_port(&mut self, port: u16) {
        let Some(i) = self.blocked_ports[..self.count]
            .iter()
            .position(|&p| p == port)
        else {
            return;
        };
        self.count -= 1;
        self.blocked_ports[i] = self.blocked_ports[self.count];
    }

    /// Checks if a port is blocked.
    pub fn is_blocked(&self, port: u16) -> bool {
        self.blocked_ports[..self.count].contains(&port)
    }
}
