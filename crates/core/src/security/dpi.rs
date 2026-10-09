//! Deep Packet Inspection (DPI) engine.
//!
//! Implements pattern matching for detecting malware signatures and
//! attack patterns in packet payloads. Uses the Aho-Corasick algorithm
//! for efficient multi-pattern matching and supports dynamic rule addition.

/// Maximum number of nodes in the Aho-Corasick automaton.
const MAX_NODES: usize = 128;

/// Reasons an `AhoCorasick::insert` may fail.
///
/// Returned to callers so they can surface a real error instead of
/// silently dropping the pattern. A trie that's quietly full will
/// answer `scan` with `false` for every newly-added signature, which
/// is indistinguishable from "no match" — exactly what an attacker
/// who can flood the trie wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DpiError {
    /// The trie has reached its node capacity; the pattern was not
    /// added in full and `scan` will not detect it.
    TrieFull,
}

/// Node in the Aho-Corasick trie structure.
#[derive(Copy, Clone, Debug)]
struct Node {
    /// Index of the first child node.
    child: u16,
    /// Index of the next sibling node.
    sibling: u16,
    /// Byte value for the edge to this node.
    byte: u8,
    /// Failure link index for Aho-Corasick algorithm.
    fail: u16,
    /// True if this node represents the end of a pattern.
    is_match: bool,
}

impl Node {
    /// Creates an empty node with all fields zeroed.
    const fn empty() -> Self {
        Self {
            child: 0,
            sibling: 0,
            byte: 0,
            fail: 0,
            is_match: false,
        }
    }
}

/// Aho-Corasick automaton for multi-pattern string matching.
///
/// Builds a finite automaton from a set of patterns and can efficiently
/// search for all patterns in a single pass over the input text.
/// Uses failure links to handle pattern overlaps efficiently.
#[derive(Debug)]
pub struct AhoCorasick {
    /// Array of all nodes in the automaton.
    nodes: [Node; MAX_NODES],
    /// Number of nodes currently in use.
    count: usize,
    /// Queue buffer for BFS traversal during construction.
    queue: [u16; MAX_NODES],
}

impl Default for AhoCorasick {
    fn default() -> Self {
        Self::new()
    }
}

impl AhoCorasick {
    /// Creates a new empty Aho-Corasick automaton.
    pub const fn new() -> Self {
        Self {
            nodes: [Node::empty(); MAX_NODES],
            count: 1,
            queue: [0; MAX_NODES],
        }
    }

    /// Inserts a pattern into the automaton.
    ///
    /// Builds the trie structure by adding nodes for each byte in the pattern.
    /// The automaton must be built with `build()` after all patterns are inserted.
    ///
    /// # Arguments
    ///
    /// * `pattern` - Byte pattern to add
    ///
    /// # Returns
    ///
    /// `Ok(())` if every byte of the pattern was added; `Err(DpiError::TrieFull)`
    /// if node capacity was hit partway through. On failure the trie is left
    /// in a consistent state but the pattern's terminal node is not marked,
    /// so `scan` will not match it. Callers must surface the error rather
    /// than discard it.
    pub fn insert(&mut self, pattern: &[u8]) -> Result<(), DpiError> {
        let mut curr = 0;
        for &b in pattern {
            let mut found = false;
            let mut child = self.nodes[curr].child;

            while child != 0 {
                if self.nodes[child as usize].byte == b {
                    curr = child as usize;
                    found = true;
                    break;
                }
                child = self.nodes[child as usize].sibling;
            }

            if !found {
                if self.count >= MAX_NODES {
                    return Err(DpiError::TrieFull);
                }
                let new_node_idx = self.count;
                self.count += 1;

                self.nodes[new_node_idx].byte = b;
                self.nodes[new_node_idx].sibling = self.nodes[curr].child;
                self.nodes[curr].child = new_node_idx as u16;

                curr = new_node_idx;
            }
        }
        self.nodes[curr].is_match = true;
        Ok(())
    }

    /// Builds the failure links for the automaton.
    ///
    /// This must be called after all patterns are inserted and before
    /// using `scan()`. Constructs failure links using BFS traversal to
    /// enable efficient pattern matching with overlaps.
    pub const fn build(&mut self) {
        let mut head = 0;
        let mut tail = 0;

        let mut child = self.nodes[0].child;
        while child != 0 {
            self.nodes[child as usize].fail = 0;
            self.queue[tail] = child;
            tail += 1;
            child = self.nodes[child as usize].sibling;
        }

        while head < tail {
            let u = self.queue[head] as usize;
            head += 1;

            let mut v = self.nodes[u].child;
            while v != 0 {
                let byte = self.nodes[v as usize].byte;
                let mut f = self.nodes[u].fail as usize;

                loop {
                    let mut next_state = 0;
                    let mut temp = self.nodes[f].child;
                    while temp != 0 {
                        if self.nodes[temp as usize].byte == byte {
                            next_state = temp as usize;
                            break;
                        }
                        temp = self.nodes[temp as usize].sibling;
                    }

                    if next_state != 0 {
                        self.nodes[v as usize].fail = next_state as u16;
                        if self.nodes[next_state].is_match {
                            self.nodes[v as usize].is_match = true;
                        }
                        break;
                    }

                    if f == 0 {
                        self.nodes[v as usize].fail = 0;
                        break;
                    }
                    f = self.nodes[f].fail as usize;
                }

                self.queue[tail] = v;
                tail += 1;
                v = self.nodes[v as usize].sibling;
            }
        }
    }

    /// Scans text for any matching patterns.
    ///
    /// Traverses the automaton following transitions and failure links
    /// to find all pattern matches in a single pass.
    ///
    /// # Arguments
    ///
    /// * `text` - Text to search for patterns
    ///
    /// # Returns
    ///
    /// True if any pattern matches, false otherwise
    pub fn scan(&self, text: &[u8]) -> bool {
        let mut curr = 0;
        for &b in text {
            loop {
                let mut next_state = 0;
                let mut child = self.nodes[curr].child;
                while child != 0 {
                    if self.nodes[child as usize].byte == b {
                        next_state = child as usize;
                        break;
                    }
                    child = self.nodes[child as usize].sibling;
                }

                if next_state != 0 {
                    curr = next_state;
                    break;
                }

                if curr == 0 {
                    break;
                }
                curr = self.nodes[curr].fail as usize;
            }

            if self.nodes[curr].is_match {
                return true;
            }
        }
        false
    }
}

/// Why a [`DynamicRules::add`] call was rejected.
///
/// None is fatal: the existing rules keep running, and the mgmt ack tells
/// the operator their command was not applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynRulesError {
    /// The 8-slot table is already full.
    Full,
    /// The submitted pattern is longer than 32 bytes.
    TooLong,
    /// The submitted pattern has zero length. Accepting one would
    /// store a pattern whose effective match-width is zero; `check`
    /// then calls `slice::windows(0)`, which the standard library
    /// defines as a panic. Rejecting at add-time turns a crashable
    /// mgmt command into a visible error.
    Empty,
}

/// Dynamic rules storage for runtime-added DPI patterns.
///
/// Maintains a fixed-size array of byte patterns that can be added
/// at runtime via the management interface. Uses simple substring
/// matching for pattern detection.
#[derive(Debug)]
pub struct DynamicRules {
    /// Array of pattern byte arrays, limited to 8 patterns.
    pub patterns: [[u8; 32]; 8],
    /// Length of each pattern in bytes.
    pub lengths: [usize; 8],
    /// Number of active patterns.
    pub count: usize,
}

impl Default for DynamicRules {
    fn default() -> Self {
        Self::new()
    }
}

impl DynamicRules {
    /// Creates a new empty dynamic rules structure.
    pub const fn new() -> Self {
        Self {
            patterns: [[0; 32]; 8],
            lengths: [0; 8],
            count: 0,
        }
    }

    /// Adds a new pattern to the dynamic rules.
    ///
    /// Patterns are limited to 32 bytes and there can be at most 8
    /// active patterns. The previous version of this function
    /// returned `()` and silently dropped on overflow, so an operator
    /// adding a 9th pattern saw no error and believed it was loaded.
    /// Now an `Err` is returned so the caller can surface the
    /// rejection.
    ///
    /// # Errors
    ///
    /// Returns [`DynRulesError::Empty`] if the pattern is zero-length
    /// (would crash `check` via `slice::windows(0)`),
    /// [`DynRulesError::TooLong`] if the pattern is longer than 32
    /// bytes, or [`DynRulesError::Full`] if the 8-slot table is
    /// already full.
    pub fn add(&mut self, pattern: &[u8]) -> Result<(), DynRulesError> {
        if pattern.is_empty() {
            return Err(DynRulesError::Empty);
        }
        if pattern.len() > 32 {
            return Err(DynRulesError::TooLong);
        }
        // Dedup: without this an authenticated attacker can spam the
        // same pattern 8 times and wedge the table against further
        // legitimate signatures.
        for i in 0..self.count {
            if self.lengths[i] == pattern.len() && &self.patterns[i][..pattern.len()] == pattern {
                return Ok(());
            }
        }
        if self.count >= 8 {
            return Err(DynRulesError::Full);
        }
        self.patterns[self.count][..pattern.len()].copy_from_slice(pattern);
        self.lengths[self.count] = pattern.len();
        self.count += 1;
        Ok(())
    }

    /// Removes `pattern` if present. Removing an absent pattern is a no-op.
    /// Does not preserve the order of the others.
    pub fn remove(&mut self, pattern: &[u8]) {
        let Some(i) = (0..self.count)
            .find(|&i| self.lengths[i] == pattern.len() && self.patterns[i][..pattern.len()] == *pattern)
        else {
            return;
        };
        self.count -= 1;
        self.patterns[i] = self.patterns[self.count];
        self.lengths[i] = self.lengths[self.count];
    }

    /// Checks if any dynamic rule matches the payload.
    ///
    /// Uses simple substring search to find pattern matches.
    ///
    /// # Arguments
    ///
    /// * `payload` - Packet payload to check
    ///
    /// # Returns
    ///
    /// True if any pattern matches, false otherwise
    pub fn check(&self, payload: &[u8]) -> bool {
        for i in 0..self.count {
            let pat = &self.patterns[i][0..self.lengths[i]];
            if payload.windows(pat.len()).any(|window| window == pat) {
                return true;
            }
        }
        false
    }
}
