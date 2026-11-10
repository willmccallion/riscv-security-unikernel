//! Deep Packet Inspection (DPI) engine.
//!
//! Implements pattern matching for detecting malware signatures and
//! attack patterns in packet payloads. Uses the Aho-Corasick algorithm
//! for efficient multi-pattern matching and supports dynamic rule addition.

use crate::security::mgmt::mgmt_packet::add_dpi::MAX_PATTERN_LEN;
use core::num::NonZeroU8;

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
    /// # Errors
    ///
    /// `DpiError::TrieFull` if node capacity runs out partway through. The
    /// trie stays consistent, but the pattern's terminal node is not
    /// marked, so `scan` will not match it: callers must surface the error.
    pub fn insert(&mut self, pattern: &[u8]) -> Result<(), DpiError> {
        let mut curr = 0;
        for &byte in pattern {
            curr = match self.child(curr, byte) {
                Some(next) => next,
                None => self.add_child(curr, byte)?,
            };
        }
        self.nodes[curr].is_match = true;
        Ok(())
    }

    /// The child of `node` along `byte`, if the trie has one.
    const fn child(&self, node: usize, byte: u8) -> Option<usize> {
        let mut child = self.nodes[node].child;
        while child != 0 {
            if self.nodes[child as usize].byte == byte {
                return Some(child as usize);
            }
            child = self.nodes[child as usize].sibling;
        }
        None
    }

    /// Adds a child of `node` along `byte` and returns it.
    const fn add_child(&mut self, node: usize, byte: u8) -> Result<usize, DpiError> {
        if self.count >= MAX_NODES {
            return Err(DpiError::TrieFull);
        }
        let added = self.count;
        self.count += 1;
        self.nodes[added].byte = byte;
        self.nodes[added].sibling = self.nodes[node].child;
        self.nodes[node].child = added as u16;
        Ok(added)
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
            let parent = self.queue[head] as usize;
            head += 1;
            let mut child = self.nodes[parent].child;
            while child != 0 {
                self.link_failure(parent, child as usize);
                self.queue[tail] = child;
                tail += 1;
                child = self.nodes[child as usize].sibling;
            }
        }
    }

    /// Points `node`, a child of `parent`, at the longest proper suffix of
    /// its path that the trie also holds, inheriting that suffix's match.
    const fn link_failure(&mut self, parent: usize, node: usize) {
        let byte = self.nodes[node].byte;
        let mut suffix = self.nodes[parent].fail as usize;
        loop {
            if let Some(next) = self.child(suffix, byte) {
                self.nodes[node].fail = next as u16;
                if self.nodes[next].is_match {
                    self.nodes[node].is_match = true;
                }
                return;
            }
            if suffix == 0 {
                self.nodes[node].fail = 0;
                return;
            }
            suffix = self.nodes[suffix].fail as usize;
        }
    }

    /// Scans text for any matching patterns.
    ///
    /// Traverses the automaton following transitions and failure links
    /// to find all pattern matches in a single pass.
    pub fn scan(&self, text: &[u8]) -> bool {
        let mut curr = 0;
        for &byte in text {
            loop {
                if let Some(next) = self.child(curr, byte) {
                    curr = next;
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

/// The signatures every engine starts with, before any are added at run time.
pub const BUILTIN_SIGNATURES: [&[u8]; 4] = [b"DROP TABLE", b"<script>", b"eval(", b"UNION SELECT"];

/// How many patterns can be added at run time.
pub const MAX_RUNTIME_PATTERNS: usize = 8;

/// Why bytes are not a [`Pattern`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternError {
    /// Longer than [`MAX_PATTERN_LEN`] bytes.
    TooLong,
    /// Zero bytes, which would match nowhere (and `slice::windows(0)` panics).
    Empty,
}

/// [`DynamicRules::add`] found every slot taken; the existing rules keep
/// running, and the mgmt ack tells the operator nothing was added.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RulesFull;

/// A run-time pattern: 1 to [`MAX_PATTERN_LEN`] bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pattern {
    bytes: [u8; MAX_PATTERN_LEN],
    len: NonZeroU8,
}

impl Pattern {
    /// The pattern `bytes` spell.
    ///
    /// # Errors
    ///
    /// [`PatternError::Empty`] or [`PatternError::TooLong`].
    pub fn new(bytes: &[u8]) -> Result<Self, PatternError> {
        if bytes.len() > MAX_PATTERN_LEN {
            return Err(PatternError::TooLong);
        }
        let len = u8::try_from(bytes.len())
            .ok()
            .and_then(NonZeroU8::new)
            .ok_or(PatternError::Empty)?;
        let mut stored = [0; MAX_PATTERN_LEN];
        stored[..bytes.len()].copy_from_slice(bytes);
        Ok(Self { bytes: stored, len })
    }

    /// The pattern's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len.get())]
    }
}

/// Patterns added at run time through the management interface, matched
/// by plain substring search.
#[derive(Debug, Default)]
pub struct DynamicRules {
    patterns: [Option<Pattern>; MAX_RUNTIME_PATTERNS],
}

impl DynamicRules {
    /// Creates a new empty dynamic rules structure.
    pub const fn new() -> Self {
        Self {
            patterns: [None; MAX_RUNTIME_PATTERNS],
        }
    }

    /// Adds `pattern`; adding one already present is a no-op, so repeating
    /// a pattern cannot fill the table.
    ///
    /// # Errors
    ///
    /// [`RulesFull`] when every slot is taken.
    pub fn add(&mut self, pattern: Pattern) -> Result<(), RulesFull> {
        if self.patterns.contains(&Some(pattern)) {
            return Ok(());
        }
        let slot = self
            .patterns
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(RulesFull)?;
        *slot = Some(pattern);
        Ok(())
    }

    /// Removes `pattern` if present. Removing an absent pattern is a no-op.
    pub fn remove(&mut self, pattern: &Pattern) {
        for slot in &mut self.patterns {
            if slot.as_ref() == Some(pattern) {
                *slot = None;
            }
        }
    }

    /// Whether any run-time pattern occurs in `payload`.
    pub fn check(&self, payload: &[u8]) -> bool {
        self.patterns.iter().flatten().any(|pattern| {
            let pattern = pattern.as_bytes();
            payload
                .windows(pattern.len())
                .any(|window| window == pattern)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_builtin_signatures_fit_in_an_empty_trie() {
        let mut trie = AhoCorasick::new();
        for signature in BUILTIN_SIGNATURES {
            assert_eq!(trie.insert(signature), Ok(()));
        }
        trie.build();

        assert!(trie.scan(b"id=1 UNION SELECT password"));
    }

    #[test]
    fn a_pattern_of_the_maximum_length_is_accepted() {
        let longest = [b'x'; MAX_PATTERN_LEN];

        let pattern = Pattern::new(&longest);

        assert_eq!(pattern.map(|p| p.as_bytes().len()), Ok(MAX_PATTERN_LEN));
    }
}
