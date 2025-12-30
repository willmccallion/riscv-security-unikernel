const MAX_NODES: usize = 128;

#[derive(Copy, Clone)]
struct Node {
    child: u16,     // First child index
    sibling: u16,   // Next sibling index
    byte: u8,       // The character for this edge
    fail: u16,      // Failure link index
    is_match: bool, // True if this node ends a pattern
}

impl Node {
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

pub struct AhoCorasick {
    nodes: [Node; MAX_NODES],
    count: usize,
    queue: [u16; MAX_NODES],
}

impl AhoCorasick {
    pub const fn new() -> Self {
        Self {
            nodes: [Node::empty(); MAX_NODES],
            count: 1, // Start at 1, 0 is root
            queue: [0; MAX_NODES],
        }
    }

    pub fn insert(&mut self, pattern: &[u8]) {
        let mut curr = 0; // Root
        for &b in pattern {
            let mut found = false;
            let mut child = self.nodes[curr].child;

            // Scan siblings to find matching child
            while child != 0 {
                if self.nodes[child as usize].byte == b {
                    curr = child as usize;
                    found = true;
                    break;
                }
                child = self.nodes[child as usize].sibling;
            }

            // If not found, create new node
            if !found {
                if self.count >= MAX_NODES {
                    // Out of memory for nodes, silently fail or panic
                    return;
                }
                let new_node_idx = self.count;
                self.count += 1;

                self.nodes[new_node_idx].byte = b;
                // Insert at head of sibling list
                self.nodes[new_node_idx].sibling = self.nodes[curr].child;
                self.nodes[curr].child = new_node_idx as u16;

                curr = new_node_idx;
            }
        }
        self.nodes[curr].is_match = true;
    }

    pub fn build(&mut self) {
        let mut head = 0;
        let mut tail = 0;

        // Enqueue all children of root and set their fail link to root (0)
        let mut child = self.nodes[0].child;
        while child != 0 {
            self.nodes[child as usize].fail = 0;
            self.queue[tail] = child;
            tail += 1;
            child = self.nodes[child as usize].sibling;
        }

        // BFS
        while head < tail {
            let u = self.queue[head] as usize;
            head += 1;

            let mut v = self.nodes[u].child;
            while v != 0 {
                let byte = self.nodes[v as usize].byte;
                let mut f = self.nodes[u].fail as usize;

                // Traverse fail links until we find a transition for 'byte'
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
                        // If fail node is a match, this node is also a match
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

                // Enqueue v
                self.queue[tail] = v;
                tail += 1;
                v = self.nodes[v as usize].sibling;
            }
        }
    }

    pub fn scan(&self, text: &[u8]) -> bool {
        let mut curr = 0;
        for &b in text {
            loop {
                // Check if current node has a child for 'b'
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

pub struct DynamicRules {
    pub patterns: [[u8; 32]; 8], // Max 8 rules, max 32 bytes each
    pub lengths: [usize; 8],
    pub count: usize,
}

impl DynamicRules {
    pub const fn new() -> Self {
        Self {
            patterns: [[0; 32]; 8],
            lengths: [0; 8],
            count: 0,
        }
    }

    pub fn add(&mut self, pattern: &[u8]) {
        if self.count < 8 && pattern.len() <= 32 {
            for i in 0..pattern.len() {
                self.patterns[self.count][i] = pattern[i];
            }
            self.lengths[self.count] = pattern.len();
            self.count += 1;
        }
    }

    pub fn check(&self, payload: &[u8]) -> bool {
        for i in 0..self.count {
            let pat = &self.patterns[i][0..self.lengths[i]];
            // Simple substring search
            if payload.windows(pat.len()).any(|window| window == pat) {
                return true;
            }
        }
        false
    }
}
