#![cfg_attr(not(test), deny(clippy::indexing_slicing))]
//! Reading classic pcap capture files, as `tcpdump -w` writes them.

use super::decode::LinkType;
use super::time::UnixNanos;
use anyhow::{Context, Result, bail};
use std::io::{ErrorKind, Read};

/// Largest record accepted. Real captures stay far below this; a larger
/// length means a corrupt file, which must not cause a huge allocation.
const MAX_RECORD_LEN: u32 = 256 * 1024;

const MAGIC_MICROS: u32 = 0xA1B2_C3D4;
const MAGIC_NANOS: u32 = 0xA1B2_3C4D;
const PCAPNG_MAGIC: u32 = 0x0A0D_0D0A;

const LINKTYPE_ETHERNET: u32 = 1;
const LINKTYPE_RAW: u32 = 101;
const LINKTYPE_IPV4: u32 = 228;
const LINKTYPE_IPV6: u32 = 229;
const LINKTYPE_LINUX_SLL: u32 = 113;
const LINKTYPE_LINUX_SLL2: u32 = 276;
/// `DLT_RAW` as some systems write it into the file instead of 101.
const DLT_RAW_BSD: u32 = 12;
const DLT_RAW_OPENBSD: u32 = 14;

/// A pcap file being read record by record.
#[derive(Debug)]
pub struct PcapReader<R> {
    reader: R,
    byte_order: ByteOrder,
    resolution: Resolution,
    link_type: LinkType,
}

/// One captured frame's header; its bytes go into the caller's buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    /// When it was captured.
    pub at: UnixNanos,
    /// Its length on the wire, which may exceed what was captured.
    pub wire_len: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ByteOrder {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Resolution {
    Micros,
    Nanos,
}

impl<R: Read> PcapReader<R> {
    /// Reads the file header from `reader`.
    pub fn new(mut reader: R) -> Result<Self> {
        let mut header = [0u8; 24];
        reader.read_exact(&mut header).context("read pcap file header")?;
        let magic_bytes = [header[0], header[1], header[2], header[3]];
        let (byte_order, resolution) = match (u32::from_le_bytes(magic_bytes), u32::from_be_bytes(magic_bytes)) {
            (MAGIC_MICROS, _) => (ByteOrder::Little, Resolution::Micros),
            (MAGIC_NANOS, _) => (ByteOrder::Little, Resolution::Nanos),
            (_, MAGIC_MICROS) => (ByteOrder::Big, Resolution::Micros),
            (_, MAGIC_NANOS) => (ByteOrder::Big, Resolution::Nanos),
            (PCAPNG_MAGIC, _) => bail!("pcapng is not supported; convert with `editcap -F pcap in.pcapng out.pcap`"),
            _ => bail!("not a pcap file"),
        };
        let [.., l0, l1, l2, l3] = header;
        let link = read_u32(byte_order, [l0, l1, l2, l3]) & 0x0FFF_FFFF;
        let link_type = match link {
            LINKTYPE_ETHERNET => LinkType::Ethernet,
            LINKTYPE_RAW | LINKTYPE_IPV4 | LINKTYPE_IPV6 | DLT_RAW_BSD | DLT_RAW_OPENBSD => LinkType::RawIp,
            LINKTYPE_LINUX_SLL => LinkType::LinuxSll,
            LINKTYPE_LINUX_SLL2 => LinkType::LinuxSll2,
            other => bail!("pcap link type {other} is not supported"),
        };
        Ok(Self {
            reader,
            byte_order,
            resolution,
            link_type,
        })
    }

    /// How the file's frames begin.
    pub const fn link_type(&self) -> LinkType {
        self.link_type
    }

    /// Reads the next record's bytes into `frame`, replacing its contents.
    /// Returns `None` at the end of the file.
    pub fn next_record(&mut self, frame: &mut Vec<u8>) -> Result<Option<Record>> {
        let mut header = [0u8; 16];
        if !read_unless_at_end(&mut self.reader, &mut header)? {
            return Ok(None);
        }
        let [s0, s1, s2, s3, f0, f1, f2, f3, c0, c1, c2, c3, w0, w1, w2, w3] = header;
        let order = self.byte_order;
        let seconds = read_u32(order, [s0, s1, s2, s3]);
        let fraction = read_u32(order, [f0, f1, f2, f3]);
        let captured_len = read_u32(order, [c0, c1, c2, c3]);
        let wire_len = read_u32(order, [w0, w1, w2, w3]);
        if captured_len > MAX_RECORD_LEN {
            bail!("pcap record of {captured_len} bytes is implausibly large; the file is corrupt");
        }
        frame.resize(captured_len as usize, 0);
        self.reader.read_exact(frame).context("pcap record is truncated")?;
        let fraction_nanos = match self.resolution {
            Resolution::Micros => u64::from(fraction) * 1_000,
            Resolution::Nanos => u64::from(fraction),
        };
        Ok(Some(Record {
            at: UnixNanos::new(u64::from(seconds) * 1_000_000_000 + fraction_nanos),
            wire_len,
        }))
    }
}

/// Fills `buf`, or returns `false` if the reader was already at its end.
/// Running out partway is an error: the file was cut short.
fn read_unless_at_end(reader: &mut impl Read, buf: &mut [u8]) -> Result<bool> {
    let mut filled = 0;
    while let Some(unfilled) = buf.get_mut(filled..).filter(|rest| !rest.is_empty()) {
        match reader.read(unfilled) {
            Ok(0) if filled == 0 => return Ok(false),
            Ok(0) => bail!("pcap record header is truncated"),
            Ok(n) => filled += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e).context("read pcap record header"),
        }
    }
    Ok(true)
}

const fn read_u32(order: ByteOrder, bytes: [u8; 4]) -> u32 {
    match order {
        ByteOrder::Little => u32::from_le_bytes(bytes),
        ByteOrder::Big => u32::from_be_bytes(bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(magic: u32, link: u32, records: &[(u32, u32, &[u8])], big_endian: bool) -> Vec<u8> {
        let word = |v: u32| if big_endian { v.to_be_bytes() } else { v.to_le_bytes() };
        let half = |v: u16| if big_endian { v.to_be_bytes() } else { v.to_le_bytes() };
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&word(magic));
        bytes.extend_from_slice(&half(2));
        bytes.extend_from_slice(&half(4));
        bytes.extend_from_slice(&[0; 8]);
        bytes.extend_from_slice(&word(65_535));
        bytes.extend_from_slice(&word(link));
        for &(seconds, fraction, data) in records {
            let len = u32::try_from(data.len()).unwrap();
            for v in [seconds, fraction, len, len + 100] {
                bytes.extend_from_slice(&word(v));
            }
            bytes.extend_from_slice(data);
        }
        bytes
    }

    #[test]
    fn reads_little_endian_microsecond_records() {
        let bytes = file(MAGIC_MICROS, LINKTYPE_ETHERNET, &[(7, 250, b"abc"), (8, 0, b"de")], false);
        let mut reader = PcapReader::new(bytes.as_slice()).unwrap();
        let mut frame = Vec::new();

        let first = reader.next_record(&mut frame).unwrap().unwrap();
        let first_bytes = frame.clone();
        let second = reader.next_record(&mut frame).unwrap().unwrap();
        let end = reader.next_record(&mut frame).unwrap();

        assert_eq!(reader.link_type(), LinkType::Ethernet);
        assert_eq!(first.at, UnixNanos::new(7_000_250_000));
        assert_eq!((first_bytes.as_slice(), first.wire_len), (&b"abc"[..], 103));
        assert_eq!((second.at, frame.as_slice()), (UnixNanos::new(8_000_000_000), &b"de"[..]));
        assert_eq!(end, None);
    }

    #[test]
    fn reads_big_endian_nanosecond_raw_ip_files() {
        let bytes = file(MAGIC_NANOS, LINKTYPE_RAW, &[(1, 5, b"x")], true);
        let mut reader = PcapReader::new(bytes.as_slice()).unwrap();

        let record = reader.next_record(&mut Vec::new()).unwrap().unwrap();

        assert_eq!(reader.link_type(), LinkType::RawIp);
        assert_eq!(record.at, UnixNanos::new(1_000_000_005));
    }

    #[test]
    fn rejects_pcapng_unknown_links_and_oversized_records() {
        let pcapng = [0x0A, 0x0D, 0x0D, 0x0A].iter().copied().chain([0; 20]).collect::<Vec<u8>>();
        let unknown = file(MAGIC_MICROS, 147, &[], false);
        let mut huge = file(MAGIC_MICROS, LINKTYPE_ETHERNET, &[], false);
        huge.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0x7F, 0, 0, 0, 0]);

        assert!(PcapReader::new(pcapng.as_slice()).unwrap_err().to_string().contains("pcapng"));
        assert!(PcapReader::new(unknown.as_slice()).is_err());
        assert!(PcapReader::new(huge.as_slice()).unwrap().next_record(&mut Vec::new()).is_err());
    }

    #[test]
    fn a_record_cut_short_is_an_error_not_the_end() {
        let whole = file(MAGIC_MICROS, LINKTYPE_ETHERNET, &[(1, 0, b"abcdef")], false);
        let in_data = &whole[..whole.len() - 2];
        let in_header = &whole[..24 + 5];

        assert!(PcapReader::new(in_data).unwrap().next_record(&mut Vec::new()).is_err());
        assert!(PcapReader::new(in_header).unwrap().next_record(&mut Vec::new()).is_err());
    }
}
