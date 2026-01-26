//! Deep Packet Inspection (DPI) engine.
//!
//! Implements pattern matching for detecting malware signatures and
//! attack patterns in packet payloads. Uses the Aho-Corasick algorithm
//! for efficient multi-pattern matching and supports dynamic rule addition.

/// Maximum number of nodes in the Aho-Corasick automaton.
const MAX_NODES: usize = 128;

/// Node in the Aho-Corasick trie structure.
#[derive(Copy, Clone)]
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
pub struct AhoCorasick {
    /// Array of all nodes in the automaton.
    nodes: [Node; MAX_NODES],
    /// Number of nodes currently in use.
    count: usize,
    /// Queue buffer for BFS traversal during construction.
    queue: [u16; MAX_NODES],
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
    pub fn insert(&mut self, pattern: &[u8]) {
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
                    return;
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
    }

    /// Builds the failure links for the automaton.
    ///
    /// This must be called after all patterns are inserted and before
    /// using `scan()`. Constructs failure links using BFS traversal to
    /// enable efficient pattern matching with overlaps.
    pub fn build(&mut self) {
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

/// Dynamic rules storage for runtime-added DPI patterns.
///
/// Maintains a fixed-size array of byte patterns that can be added
/// at runtime via the management interface. Uses simple substring
/// matching for pattern detection.
pub struct DynamicRules {
    /// Array of pattern byte arrays, limited to 8 patterns.
    pub patterns: [[u8; 32]; 8],
    /// Length of each pattern in bytes.
    pub lengths: [usize; 8],
    /// Number of active patterns.
    pub count: usize,
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
    /// Patterns are limited to 32 bytes and there can be at most 8 patterns.
    /// Longer patterns are truncated, and the table is full after 8 patterns.
    ///
    /// # Arguments
    ///
    /// * `pattern` - Byte pattern to add
    pub fn add(&mut self, pattern: &[u8]) {
        if self.count < 8 && pattern.len() <= 32 {
            for i in 0..pattern.len() {
                self.patterns[self.count][i] = pattern[i];
            }
            self.lengths[self.count] = pattern.len();
            self.count += 1;
        }
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
