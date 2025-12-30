#[repr(C, packed)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset_flags: u16, // 4 bits offset, 6 bits reserved, 6 bits flags
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

pub const TCP_SYN: u16 = 0x0002;
pub const TCP_ACK: u16 = 0x0010;

impl TcpHeader {
    pub fn new(src: u16, dst: u16, seq: u32, ack: u32, flags: u16) -> Self {
        // Data offset = 5 (20 bytes header), shifted left by 12
        let offset_flags = (5 << 12) | flags;
        Self {
            src_port: src.to_be(),
            dst_port: dst.to_be(),
            seq_num: seq.to_be(),
            ack_num: ack.to_be(),
            data_offset_flags: offset_flags.to_be(),
            window_size: 64240u16.to_be(), // Standard window
            checksum: 0,
            urgent_ptr: 0,
        }
    }
}
