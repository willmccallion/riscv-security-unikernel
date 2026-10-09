#![cfg_attr(not(test), deny(clippy::indexing_slicing))]
//! Reading the TLS handshake from QUIC Initial packets.
//!
//! A QUIC client's first packets carry its TLS ClientHello encrypted with
//! keys derived from the connection ID in the packet's own header
//! (RFC 9001 §5.2). The keys are public by design: Initial protection
//! guards against tampering, not observers, so a monitor can derive them
//! and read the hello's server name just as it would over TCP.

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
use aes_gcm::Aes128Gcm;
use aes_gcm::aead::{Aead, Payload};
use hkdf::Hkdf;
use sha2::Sha256;

/// The longest connection ID QUIC v1 and v2 allow.
const MAX_CONNECTION_ID_LEN: usize = 20;
/// Header protection samples this many bytes of ciphertext.
const SAMPLE_LEN: usize = 16;
/// The AEAD tag at the end of every protected payload.
const TAG_LEN: usize = 16;
/// The sample starts this far after the packet number field begins.
const SAMPLE_OFFSET: usize = 4;

/// Bytes of a client's TLS handshake, at an offset in its CRYPTO stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoData {
    /// Where these bytes sit in the stream.
    pub offset: u64,
    /// The bytes.
    pub bytes: Vec<u8>,
}

/// The QUIC versions whose Initial packets can be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Version {
    /// QUIC version 1 (RFC 9000).
    V1,
    /// QUIC version 2 (RFC 9369).
    V2,
}

impl Version {
    const fn from_wire(version: u32) -> Option<Self> {
        match version {
            0x0000_0001 => Some(Self::V1),
            0x6B33_43CF => Some(Self::V2),
            _ => None,
        }
    }

    const fn initial_salt(self) -> [u8; 20] {
        match self {
            Self::V1 => [
                0x38, 0x76, 0x2C, 0xF7, 0xF5, 0x59, 0x34, 0xB3, 0x4D, 0x17, 0x9A, 0xE6, 0xA4, 0xC8, 0x0C, 0xAD, 0xCC, 0xBB,
                0x7F, 0x0A,
            ],
            Self::V2 => [
                0x0D, 0xED, 0xE3, 0xDE, 0xF7, 0x00, 0xA6, 0xDB, 0x81, 0x93, 0x81, 0xBE, 0x6E, 0x26, 0x9D, 0xCB, 0xF9, 0xBD,
                0x2E, 0xD9,
            ],
        }
    }

    /// The long-header type bits that mark an Initial packet.
    const fn initial_type(self) -> u8 {
        match self {
            Self::V1 => 0b00,
            Self::V2 => 0b01,
        }
    }

    const fn labels(self) -> [&'static str; 3] {
        match self {
            Self::V1 => ["quic key", "quic iv", "quic hp"],
            Self::V2 => ["quicv2 key", "quicv2 iv", "quicv2 hp"],
        }
    }
}

/// The keys protecting a client's Initial packets.
#[derive(Debug, Clone, PartialEq, Eq)]
struct InitialKeys {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

impl InitialKeys {
    /// Derives the client's Initial keys from the destination connection
    /// ID it chose (RFC 9001 §5.2).
    fn derive(version: Version, destination_id: &[u8]) -> Option<Self> {
        let (initial_secret, _) = Hkdf::<Sha256>::extract(Some(&version.initial_salt()), destination_id);
        let client_secret: [u8; 32] = expand_label(&initial_secret, "client in")?;
        let [key, iv, hp] = version.labels();
        Some(Self {
            key: expand_label(&client_secret, key)?,
            iv: expand_label(&client_secret, iv)?,
            hp: expand_label(&client_secret, hp)?,
        })
    }

    /// The five-byte header protection mask for a ciphertext `sample`.
    fn mask(&self, sample: &[u8; SAMPLE_LEN]) -> [u8; 5] {
        let cipher = Aes128::new(GenericArray::from_slice(&self.hp));
        let mut block = GenericArray::clone_from_slice(sample);
        cipher.encrypt_block(&mut block);
        let [m0, m1, m2, m3, m4, ..]: [u8; SAMPLE_LEN] = block.into();
        [m0, m1, m2, m3, m4]
    }
}

/// TLS 1.3's `HKDF-Expand-Label` with an empty context, producing `N`
/// bytes.
fn expand_label<const N: usize>(secret: &[u8], label: &str) -> Option<[u8; N]> {
    let full_label = format!("tls13 {label}");
    let mut info = Vec::with_capacity(4 + full_label.len());
    info.extend_from_slice(&u16::try_from(N).ok()?.to_be_bytes());
    info.push(u8::try_from(full_label.len()).ok()?);
    info.extend_from_slice(full_label.as_bytes());
    info.push(0);
    let mut out = [0u8; N];
    Hkdf::<Sha256>::from_prk(secret).ok()?.expand(&info, &mut out).ok()?;
    Some(out)
}

/// The CRYPTO data in the client Initial packets of a UDP datagram; empty
/// if it holds none or they cannot be decrypted.
pub fn client_initial_crypto(datagram: &[u8]) -> Vec<CryptoData> {
    let mut found = Vec::new();
    let mut rest = datagram;
    while let Some(packet) = LongHeaderPacket::parse(rest) {
        if packet.is_initial
            && let Some(plaintext) = packet.decrypt()
        {
            found.extend(crypto_frames(&plaintext));
        }
        let Some(next) = rest.get(packet.len..) else { break };
        rest = next;
    }
    found
}

/// One long-header packet within a datagram.
struct LongHeaderPacket<'a> {
    /// The whole packet, header and protected payload.
    bytes: &'a [u8],
    /// Its length, so the next coalesced packet can be found.
    len: usize,
    version: Version,
    is_initial: bool,
    destination_id: &'a [u8],
    /// Where the protected packet number begins.
    packet_number_offset: usize,
}

impl<'a> LongHeaderPacket<'a> {
    fn parse(bytes: &'a [u8]) -> Option<Self> {
        let first = *bytes.first()?;
        let is_long_header = first & 0xC0 == 0xC0;
        if !is_long_header {
            return None;
        }
        let version = Version::from_wire(u32::from_be_bytes(bytes.get(1..5)?.try_into().ok()?))?;
        let packet_type = (first >> 4) & 0b11;
        let is_initial = packet_type == version.initial_type();
        let mut offset = 5;
        let destination_len = usize::from(*bytes.get(offset)?);
        if destination_len > MAX_CONNECTION_ID_LEN {
            return None;
        }
        let destination_id = bytes.get(offset + 1..offset + 1 + destination_len)?;
        offset += 1 + destination_len;
        let source_len = usize::from(*bytes.get(offset)?);
        if source_len > MAX_CONNECTION_ID_LEN {
            return None;
        }
        offset += 1 + source_len;
        if is_initial {
            let (token_len, used) = read_varint(bytes.get(offset..)?)?;
            offset += used + usize::try_from(token_len).ok()?;
        }
        let (length, used) = read_varint(bytes.get(offset..)?)?;
        let packet_number_offset = offset + used;
        let len = packet_number_offset.checked_add(usize::try_from(length).ok()?)?;
        Some(Self {
            bytes: bytes.get(..len)?,
            len,
            version,
            is_initial,
            destination_id,
            packet_number_offset,
        })
    }

    /// Removes header protection and decrypts the payload.
    fn decrypt(&self) -> Option<Vec<u8>> {
        let keys = InitialKeys::derive(self.version, self.destination_id)?;
        let pn_offset = self.packet_number_offset;
        let sample_start = pn_offset + SAMPLE_OFFSET;
        let sample: &[u8; SAMPLE_LEN] = self.bytes.get(sample_start..sample_start + SAMPLE_LEN)?.try_into().ok()?;
        let mask = keys.mask(sample);

        let [first_mask, packet_number_mask @ ..] = mask;
        let first = self.bytes.first()? ^ (first_mask & 0x0F);
        let packet_number_len = usize::from(first & 0x03) + 1;
        let mut header = self.bytes.get(..pn_offset + packet_number_len)?.to_vec();
        *header.first_mut()? = first;
        let mut packet_number: u64 = 0;
        for (byte, mask_byte) in header.get_mut(pn_offset..)?.iter_mut().zip(packet_number_mask) {
            *byte ^= mask_byte;
            packet_number = packet_number << 8 | u64::from(*byte);
        }

        let mut nonce = keys.iv;
        for (n, p) in nonce[4..].iter_mut().zip(packet_number.to_be_bytes()) {
            *n ^= p;
        }
        let ciphertext = self.bytes.get(header.len()..)?;
        if ciphertext.len() < TAG_LEN {
            return None;
        }
        let gcm = Aes128Gcm::new_from_slice(&keys.key).ok()?;
        gcm.decrypt(GenericArray::from_slice(&nonce), Payload {
            msg: ciphertext,
            aad: &header,
        })
        .ok()
    }
}

/// The CRYPTO frames in a decrypted Initial payload, skipping the other
/// frames an Initial may carry; stops at any frame it cannot step over.
fn crypto_frames(mut payload: &[u8]) -> Vec<CryptoData> {
    const PADDING: u64 = 0x00;
    const PING: u64 = 0x01;
    const ACK: u64 = 0x02;
    const ACK_ECN: u64 = 0x03;
    const CRYPTO: u64 = 0x06;
    const CONNECTION_CLOSE: u64 = 0x1C;

    let mut found = Vec::new();
    while let Some((frame_type, used)) = read_varint(payload) {
        let Some(after_type) = payload.get(used..) else { break };
        payload = after_type;
        let rest = match frame_type {
            PADDING | PING => Some(payload),
            ACK | ACK_ECN => skip_ack(payload, frame_type == ACK_ECN),
            CRYPTO => read_crypto(payload).map(|(data, rest)| {
                found.push(data);
                rest
            }),
            CONNECTION_CLOSE => skip_connection_close(payload),
            _ => None,
        };
        let Some(rest) = rest else { break };
        payload = rest;
    }
    found
}

fn read_crypto(payload: &[u8]) -> Option<(CryptoData, &[u8])> {
    let (offset, a) = read_varint(payload)?;
    let (len, b) = read_varint(payload.get(a..)?)?;
    let start = a + b;
    let end = start.checked_add(usize::try_from(len).ok()?)?;
    let bytes = payload.get(start..end)?.to_vec();
    Some((CryptoData { offset, bytes }, payload.get(end..)?))
}

fn skip_ack(mut payload: &[u8], with_ecn: bool) -> Option<&[u8]> {
    skip_varints(2, &mut payload)?;
    let (ranges, used) = read_varint(payload)?;
    payload = payload.get(used..)?;
    if ranges > payload.len() as u64 {
        return None;
    }
    skip_varints(1 + 2 * ranges, &mut payload)?;
    if with_ecn {
        skip_varints(3, &mut payload)?;
    }
    Some(payload)
}

/// Steps `payload` past `count` variable-length integers.
fn skip_varints(count: u64, payload: &mut &[u8]) -> Option<()> {
    for _ in 0..count {
        let (_, used) = read_varint(payload)?;
        *payload = payload.get(used..)?;
    }
    Some(())
}

fn skip_connection_close(payload: &[u8]) -> Option<&[u8]> {
    let (_, a) = read_varint(payload)?;
    let (_, b) = read_varint(payload.get(a..)?)?;
    let (reason_len, c) = read_varint(payload.get(a + b..)?)?;
    payload.get(a + b + c + usize::try_from(reason_len).ok()?..)
}

/// Reads a QUIC variable-length integer; returns it and the bytes used.
fn read_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let first = *bytes.first()?;
    let len = 1usize << (first >> 6);
    let encoded = bytes.get(..len)?;
    let value = encoded
        .get(1..)?
        .iter()
        .fold(u64::from(first & 0x3F), |value, &byte| value << 8 | u64::from(byte));
    Some((value, len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::tls::{self, Hello};

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The connection ID of RFC 9001 Appendix A.
    const RFC_DESTINATION_ID: &str = "8394c8f03e515708";

    #[test]
    fn derives_the_rfc_9001_client_initial_keys() {
        let keys = InitialKeys::derive(Version::V1, &hex(RFC_DESTINATION_ID)).unwrap();

        assert_eq!(keys.key.to_vec(), hex("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(keys.iv.to_vec(), hex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(keys.hp.to_vec(), hex("9f50449e04a0e810283a1e9933adedd2"));
    }

    #[test]
    fn derives_the_rfc_9001_intermediate_secrets() {
        let (initial, _) = Hkdf::<Sha256>::extract(Some(&Version::V1.initial_salt()), &hex(RFC_DESTINATION_ID));
        let client: [u8; 32] = expand_label(&initial, "client in").unwrap();

        assert_eq!(initial.to_vec(), hex("7db5df06e7a69e432496adedb00851923595221596ae2ae9fb8115c1e9ed0a44"));
        assert_eq!(client.to_vec(), hex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"));
    }

    #[test]
    fn computes_the_rfc_9001_header_protection_mask() {
        let keys = InitialKeys::derive(Version::V1, &hex(RFC_DESTINATION_ID)).unwrap();
        let sample: [u8; 16] = hex("d1b1c98dd7689fb8ec11d242b123dc9b").try_into().unwrap();

        assert_eq!(keys.mask(&sample).to_vec(), hex("437b9aec36"));
    }

    /// Protects `payload` as a client Initial of `version` sent to
    /// `destination_id`, following RFC 9001 §5 in the sending direction.
    fn protect(version: Version, destination_id: &[u8], packet_number: u32, payload: &[u8]) -> Vec<u8> {
        let keys = InitialKeys::derive(version, destination_id).unwrap();
        let wire_version: u32 = match version {
            Version::V1 => 1,
            Version::V2 => 0x6B33_43CF,
        };
        let mut header = vec![0xC0 | (version.initial_type() << 4) | 0x03];
        header.extend_from_slice(&wire_version.to_be_bytes());
        header.push(u8::try_from(destination_id.len()).unwrap());
        header.extend_from_slice(destination_id);
        header.extend_from_slice(&[0, 0]);
        let length = u16::try_from(4 + payload.len() + TAG_LEN).unwrap() | 0x4000;
        header.extend_from_slice(&length.to_be_bytes());
        let pn_offset = header.len();
        header.extend_from_slice(&packet_number.to_be_bytes());

        let mut nonce = keys.iv;
        for (n, p) in nonce[4..].iter_mut().zip(u64::from(packet_number).to_be_bytes()) {
            *n ^= p;
        }
        let gcm = Aes128Gcm::new_from_slice(&keys.key).unwrap();
        let ciphertext = gcm
            .encrypt(GenericArray::from_slice(&nonce), Payload { msg: payload, aad: &header })
            .unwrap();
        let mut packet = header;
        packet.extend_from_slice(&ciphertext);

        let sample: [u8; 16] = packet[pn_offset + 4..pn_offset + 20].try_into().unwrap();
        let mask = keys.mask(&sample);
        packet[0] ^= mask[0] & 0x0F;
        for i in 0..4 {
            packet[pn_offset + i] ^= mask[1 + i];
        }
        packet
    }

    fn crypto_frame(offset: u64, data: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x06];
        frame.extend_from_slice(&(u16::try_from(offset).unwrap() | 0x4000).to_be_bytes());
        frame.extend_from_slice(&(u16::try_from(data.len()).unwrap() | 0x4000).to_be_bytes());
        frame.extend_from_slice(data);
        frame
    }

    fn reassemble(mut fragments: Vec<CryptoData>) -> Vec<u8> {
        fragments.sort_by_key(|f| f.offset);
        let mut stream = Vec::new();
        for f in fragments {
            assert_eq!(f.offset as usize, stream.len(), "fragments leave a gap");
            stream.extend_from_slice(&f.bytes);
        }
        stream
    }

    #[test]
    fn recovers_a_hello_split_into_shuffled_crypto_frames_across_coalesced_packets() {
        let record = crate::monitor::tls::tests::client_hello(Some("www.youtube.com"), 1500, false);
        let message = &record[5..];
        let (first, second) = message.split_at(900);
        let mut payload_a = vec![0x01];
        payload_a.extend_from_slice(&crypto_frame(450, &first[450..]));
        payload_a.extend_from_slice(&[0x00; 7]);
        payload_a.extend_from_slice(&crypto_frame(0, &first[..450]));
        let payload_b = crypto_frame(900, second);
        let id = hex("0a1b2c3d4e5f6071");
        let mut datagram = protect(Version::V1, &id, 0, &payload_a);
        datagram.extend_from_slice(&protect(Version::V1, &id, 1, &payload_b));

        let fragments = client_initial_crypto(&datagram);

        assert_eq!(fragments.len(), 3);
        let hello = tls::parse_handshake(&reassemble(fragments));
        assert!(matches!(&hello, Hello::Named(name) if name.name == "www.youtube.com"), "{hello:?}");
    }

    #[test]
    fn reads_version_2_initials() {
        let payload = crypto_frame(0, b"hello");

        let fragments = client_initial_crypto(&protect(Version::V2, &hex("1122334455667788"), 3, &payload));

        assert_eq!(fragments, [CryptoData { offset: 0, bytes: b"hello".to_vec() }]);
    }

    #[test]
    fn tampered_short_header_and_unknown_version_packets_yield_nothing() {
        let id = hex("0a1b2c3d4e5f6071");
        let mut tampered = protect(Version::V1, &id, 0, &crypto_frame(0, b"x"));
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let mut unknown_version = protect(Version::V1, &id, 0, &crypto_frame(0, b"x"));
        unknown_version[1..5].copy_from_slice(&0xFACE_B00Cu32.to_be_bytes());

        assert!(client_initial_crypto(&tampered).is_empty());
        assert!(client_initial_crypto(&[0x40, 1, 2, 3]).is_empty());
        assert!(client_initial_crypto(&unknown_version).is_empty());
    }

    #[test]
    fn varints_decode_in_all_four_lengths() {
        assert_eq!(read_varint(&[0x25]), Some((37, 1)));
        assert_eq!(read_varint(&[0x7B, 0xBD]), Some((15_293, 2)));
        assert_eq!(read_varint(&[0x9D, 0x7F, 0x3E, 0x7D]), Some((494_878_333, 4)));
        assert_eq!(
            read_varint(&[0xC2, 0x19, 0x7C, 0x5E, 0xFF, 0x14, 0xE8, 0x8C]),
            Some((151_288_809_941_952_652, 8))
        );
        assert_eq!(read_varint(&[0x7B]), None);
    }

    #[test]
    fn parsing_never_panics_on_any_prefix_or_corruption() {
        let datagram = protect(Version::V1, &hex("0a1b2c3d"), 0, &crypto_frame(0, &[7; 64]));

        for end in 0..=datagram.len() {
            let _ = client_initial_crypto(&datagram[..end]);
        }
        for i in 0..datagram.len() {
            let mut corrupt = datagram.clone();
            corrupt[i] ^= 0x5A;
            let _ = client_initial_crypto(&corrupt);
        }
        let _ = crypto_frames(&[0x02, 0x3F, 0x3F, 0x3F]);
    }
}
