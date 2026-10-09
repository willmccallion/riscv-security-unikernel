//! Hand-rolled SipHash-2-4 keyed pseudo-random function.
//!
//! SipHash is the canonical short-input keyed primitive: small, fast,
//! `no_std`-friendly, and widely deployed (Linux uses it for SYN
//! cookies; the Rust stdlib uses it for `HashMap`). We use it for two
//! purposes inside `sec_core`:
//!
//! - Mgmt-plane MAC (`security::mgmt_auth`) — verifying that a UDP
//!   command came from a holder of the pre-shared key.
//! - Per-boot SYN-cookie keying (`net::stack`) — making the cookie's
//!   sequence number unforgeable to an off-path attacker.
//!
//! 64-bit output is enough for both: forgery probability is 2⁻⁶⁴ per
//! attempt and the mgmt path further requires a strictly increasing
//! counter, so the window for online brute force is one packet wide.

/// SipHash-2-4 keyed PRF.
///
/// `key` is a 128-bit secret split into two little-endian 64-bit
/// halves. `data` is the message to authenticate. Returns the 64-bit
/// keyed digest.
pub const fn siphash24(key: &[u8; 16], data: &[u8]) -> u64 {
    let k0 = u64::from_le_bytes([
        key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
    ]);
    let k1 = u64::from_le_bytes([
        key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15],
    ]);

    let mut v0 = k0 ^ 0x736f_6d65_7073_6575;
    let mut v1 = k1 ^ 0x646f_7261_6e64_6f6d;
    let mut v2 = k0 ^ 0x6c79_6765_6e65_7261;
    let mut v3 = k1 ^ 0x7465_6462_7974_6573;

    let mut i = 0;
    while i + 8 <= data.len() {
        let m = u64::from_le_bytes([
            data[i],
            data[i + 1],
            data[i + 2],
            data[i + 3],
            data[i + 4],
            data[i + 5],
            data[i + 6],
            data[i + 7],
        ]);
        v3 ^= m;
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
        i += 8;
    }

    let mut tail = [0u8; 8];
    let remaining = data.len() - i;
    let mut j = 0;
    while j < remaining {
        tail[j] = data[i + j];
        j += 1;
    }
    tail[7] = (data.len() & 0xFF) as u8;
    let m = u64::from_le_bytes(tail);
    v3 ^= m;
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= m;

    v2 ^= 0xFF;
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);

    v0 ^ v1 ^ v2 ^ v3
}

#[inline(always)]
const fn sipround(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v2 = v2.wrapping_add(*v3);
    *v1 = v1.rotate_left(13);
    *v3 = v3.rotate_left(16);
    *v1 ^= *v0;
    *v3 ^= *v2;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v1);
    *v0 = v0.wrapping_add(*v3);
    *v1 = v1.rotate_left(17);
    *v3 = v3.rotate_left(21);
    *v1 ^= *v2;
    *v3 ^= *v0;
    *v2 = v2.rotate_left(32);
}

/// Longest label [`derive_key`] accepts.
pub const MAX_LABEL_LEN: usize = 31;

/// Derives an independent 128-bit key from `key` for the purpose `label`.
///
/// Lets one secret key several hashes without their outputs being related.
/// Labels longer than [`MAX_LABEL_LEN`] are truncated.
pub const fn derive_key(key: &[u8; 16], label: &[u8]) -> [u8; 16] {
    let len = if label.len() < MAX_LABEL_LEN { label.len() } else { MAX_LABEL_LEN };
    let mut input = [0u8; MAX_LABEL_LEN + 1];
    let mut i = 0;
    while i < len {
        input[i] = label[i];
        i += 1;
    }
    let (labelled, _) = input.split_at(len + 1);
    let lo = siphash24(key, labelled).to_le_bytes();
    input[len] = 1;
    let (labelled, _) = input.split_at(len + 1);
    let hi = siphash24(key, labelled).to_le_bytes();

    let mut out = [0u8; 16];
    let mut j = 0;
    while j < 8 {
        out[j] = lo[j];
        out[8 + j] = hi[j];
        j += 1;
    }
    out
}

/// Constant-time equality check for two byte slices of equal length.
///
/// Avoids early-exit on first mismatch so an attacker measuring reply
/// timing cannot learn how many leading bytes of a forgery are correct.
/// Returns `false` immediately for differing lengths — that asymmetry
/// is acceptable because length is public information.
pub const fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    let mut i = 0;
    while i < a.len() {
        diff |= a[i] ^ b[i];
        i += 1;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SipHash-2-4 official test vector from the reference paper:
    /// key = 00..0f, message = 00..0e, expected output = 0xa129ca6149be45e5.
    #[test]
    fn siphash24_matches_reference_vector() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let msg: [u8; 15] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e,
        ];
        assert_eq!(siphash24(&key, &msg), 0xa129_ca61_49be_45e5);
    }

    #[test]
    fn siphash24_differs_when_key_differs() {
        let k1 = [0u8; 16];
        let mut k2 = [0u8; 16];
        k2[0] = 1;
        let msg = b"abcdefgh";
        assert_ne!(siphash24(&k1, msg), siphash24(&k2, msg));
    }

    #[test]
    fn derived_keys_differ_by_label_and_from_the_input() {
        let key = [9u8; 16];

        let a = derive_key(&key, b"a");
        let b = derive_key(&key, b"b");

        assert_ne!(a, b);
        assert_ne!(a, key);
        assert_ne!(a[..8], a[8..], "halves come from different inputs");
    }

    #[test]
    fn ct_eq_matches_pattern() {
        assert!(ct_eq(b"abcdefgh", b"abcdefgh"));
        assert!(!ct_eq(b"abcdefgh", b"abcdefgi"));
        assert!(!ct_eq(b"abcdefgh", b"abcdefg"));
    }
}
