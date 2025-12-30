const MAX_FLOWS: usize = 74;

#[derive(Copy, Clone)]
#[repr(align(8))]
pub struct FlowEntry {
    // Group 64-bit fields first to ensure alignment and minimize padding
    pub packet_count: u64,
    pub byte_count: u64,
    pub last_seen: usize, // u64 on riscv64

    // Group 32-bit fields
    pub src_ip: u32,
    pub dst_ip: u32,

    // Group 16-bit fields
    pub src_port: u16,
    pub dst_port: u16,

    // Group 8-bit fields
    pub protocol: u8,
    pub is_active: bool,
}

impl FlowEntry {
    pub const fn empty() -> Self {
        Self {
            packet_count: 0,
            byte_count: 0,
            last_seen: 0,
            src_ip: 0,
            dst_ip: 0,
            src_port: 0,
            dst_port: 0,
            protocol: 0,
            is_active: false,
        }
    }
}

pub struct FlowTable {
    entries: [FlowEntry; MAX_FLOWS],
    pub active_count: usize,
}

impl FlowTable {
    pub const fn new() -> Self {
        Self {
            entries: [FlowEntry::empty(); MAX_FLOWS],
            active_count: 0,
        }
    }

    // Returns true if a new flow was created
    pub fn update(
        &mut self,
        src_ip: &[u8],
        dst_ip: &[u8],
        src_port: u16,
        dst_port: u16,
        proto: u8,
        len: usize,
        now: usize,
    ) -> bool {
        let s_ip = u32::from_be_bytes([src_ip[0], src_ip[1], src_ip[2], src_ip[3]]);
        let d_ip = u32::from_be_bytes([dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]]);

        let mut found_idx = None;
        let mut empty_idx = None;
        let mut oldest_idx = 0;
        let mut oldest_time = usize::MAX;

        for i in 0..MAX_FLOWS {
            let e = &self.entries[i];
            if e.is_active {
                if e.src_ip == s_ip
                    && e.dst_ip == d_ip
                    && e.src_port == src_port
                    && e.dst_port == dst_port
                    && e.protocol == proto
                {
                    found_idx = Some(i);
                    break;
                }
                if e.last_seen < oldest_time {
                    oldest_time = e.last_seen;
                    oldest_idx = i;
                }
            } else if empty_idx.is_none() {
                empty_idx = Some(i);
            }
        }

        if let Some(idx) = found_idx {
            self.entries[idx].packet_count += 1;
            self.entries[idx].byte_count += len as u64;
            self.entries[idx].last_seen = now;
            false // Existing flow
        } else {
            let idx = if let Some(e_idx) = empty_idx {
                self.active_count += 1;
                e_idx
            } else {
                oldest_idx
            };

            self.entries[idx] = FlowEntry {
                packet_count: 1,
                byte_count: len as u64,
                last_seen: now,
                src_ip: s_ip,
                dst_ip: d_ip,
                src_port,
                dst_port,
                protocol: proto,
                is_active: true,
            };
            true // New flow created
        }
    }

    pub fn prune(&mut self, now: usize, timeout: usize) {
        let mut removed = 0;
        for i in 0..MAX_FLOWS {
            if self.entries[i].is_active && (now.wrapping_sub(self.entries[i].last_seen) > timeout)
            {
                self.entries[i].is_active = false;
                removed += 1;
            }
        }
        self.active_count -= removed;
    }
}
