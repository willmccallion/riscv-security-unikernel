use core::arch::asm;

const CMS_WIDTH: usize = 128;
const CMS_DEPTH: usize = 4;

// Penalty box
#[derive(Copy, Clone)]
struct BanEntry {
    ip: u32,
    expiry: usize, // Cycle count when ban ends
}

pub struct PenaltyBox {
    entries: [BanEntry; 16], // Track up to 16 banned IPs
}

impl PenaltyBox {
    pub const fn new() -> Self {
        Self {
            entries: [BanEntry { ip: 0, expiry: 0 }; 16],
        }
    }

    pub fn ban(&mut self, ip_bytes: &[u8], duration_cycles: usize) {
        let ip = u32::from_be_bytes([ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]]);
        let now: usize = get_time();

        // Find empty slot or overwrite oldest/expired
        for i in 0..16 {
            if self.entries[i].expiry < now {
                self.entries[i] = BanEntry {
                    ip,
                    expiry: now + duration_cycles,
                };
                return;
            }
        }
        // If full, overwrite the first one
        self.entries[0] = BanEntry {
            ip,
            expiry: now + duration_cycles,
        };
    }

    pub fn is_banned(&self, ip_bytes: &[u8]) -> bool {
        let ip = u32::from_be_bytes([ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]]);
        let now: usize = get_time();

        for i in 0..16 {
            if self.entries[i].ip == ip && self.entries[i].expiry > now {
                return true;
            }
        }
        false
    }
}

pub struct CountMinSketch {
    matrix: [[u16; CMS_WIDTH]; CMS_DEPTH],
}

impl CountMinSketch {
    pub const fn new() -> Self {
        Self {
            matrix: [[0; CMS_WIDTH]; CMS_DEPTH],
        }
    }

    pub fn insert(&mut self, data: &[u8]) -> u16 {
        let mut min = u16::MAX;
        for i in 0..CMS_DEPTH {
            let mut hash: u32 = 0xDEAD_BEEF + i as u32;
            for &b in data {
                hash = hash.wrapping_add(b as u32);
                hash = hash.wrapping_add(hash << 10);
                hash ^= hash >> 6;
            }
            hash = hash.wrapping_add(hash << 3);
            hash ^= hash >> 11;
            hash = hash.wrapping_add(hash << 15);
            let idx = (hash as usize) % CMS_WIDTH;

            self.matrix[i][idx] = self.matrix[i][idx].saturating_add(1);
            if self.matrix[i][idx] < min {
                min = self.matrix[i][idx];
            }
        }
        min
    }

    pub fn reset(&mut self) {
        for row in self.matrix.iter_mut() {
            for val in row.iter_mut() {
                *val = 0;
            }
        }
    }
}

pub struct TokenBucket {
    tokens: u64,
    capacity: u64,
    last_cycle: usize,
    cost: usize,
}

impl TokenBucket {
    pub const fn new(capacity: u64, cost: usize) -> Self {
        Self {
            tokens: capacity,
            capacity,
            last_cycle: 0,
            cost,
        }
    }

    pub fn allow(&mut self) -> bool {
        let now: usize = get_time();
        let delta = now.wrapping_sub(self.last_cycle);
        if delta >= self.cost {
            let refill = (delta / self.cost) as u64;
            self.tokens = (self.tokens + refill).min(self.capacity);
            self.last_cycle = now;
        }
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

fn get_time() -> usize {
    unsafe {
        let c: usize;
        asm!("csrr {}, mcycle", out(reg) c);
        c
    }
}
