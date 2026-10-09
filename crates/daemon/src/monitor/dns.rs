//! Reading DNS and mDNS responses for the names they give addresses.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The longest name DNS allows, in its text form.
const MAX_NAME_LEN: usize = 253;
/// Records read from one message; real responses have far fewer.
const MAX_RECORDS: usize = 64;

const FLAG_RESPONSE: u16 = 0x8000;
const OPCODE_MASK: u16 = 0x7800;
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
/// mDNS sets the top bit of the class to mean "flush your cache".
const CLASS_MASK: u16 = 0x7FFF;

/// What a DNS response said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResponse {
    /// The name asked about, if the message carried exactly one question.
    pub question: Option<String>,
    /// Whether the lookup succeeded.
    pub outcome: Outcome,
    /// Addresses the response gave, each with the name it belongs to.
    pub addresses: Vec<NamedAddress>,
}

/// The response code, as far as the monitor cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The lookup succeeded (`NOERROR`).
    Answered,
    /// The name does not exist (`NXDOMAIN`).
    NoSuchName,
    /// Any other failure, by response code.
    Failed(u8),
}

/// An address and the name it was looked up by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedAddress {
    /// The name: the question asked, so a lookup of `youtube.com` names
    /// the address after it rather than after the CDN host a CNAME chain
    /// ended at; or the record's own name when there was no single
    /// question, as in mDNS announcements.
    pub name: String,
    /// The address.
    pub addr: IpAddr,
    /// How long, in seconds, the answer may be cached.
    pub ttl: u32,
}

/// Parses `message` if it is a well-formed standard-query response.
pub fn parse_response(message: &[u8]) -> Option<DnsResponse> {
    let flags = read_u16(message, 2)?;
    let is_response = flags & FLAG_RESPONSE != 0;
    let is_standard_query = flags & OPCODE_MASK == 0;
    if !is_response || !is_standard_query {
        return None;
    }
    let outcome = match flags & 0x0F {
        0 => Outcome::Answered,
        3 => Outcome::NoSuchName,
        code => Outcome::Failed(u8::try_from(code).ok()?),
    };
    let questions = usize::from(read_u16(message, 4)?);
    let records = [6, 8, 10]
        .iter()
        .map(|&offset| read_u16(message, offset).map(usize::from))
        .sum::<Option<usize>>()?;

    let mut offset = 12;
    let mut question = None;
    for _ in 0..questions.min(MAX_RECORDS) {
        let (name, next) = read_name(message, offset)?;
        offset = next + 4;
        question = if questions == 1 { Some(name) } else { None };
    }

    let mut addresses = Vec::new();
    for _ in 0..records.min(MAX_RECORDS) {
        let (owner, next) = read_name(message, offset)?;
        let record_type = read_u16(message, next)?;
        let class = read_u16(message, next + 2)? & CLASS_MASK;
        let ttl = read_u32(message, next + 4)?;
        let data_len = usize::from(read_u16(message, next + 8)?);
        let data = message.get(next + 10..next + 10 + data_len)?;
        offset = next + 10 + data_len;
        let addr = match (record_type, class, data.len()) {
            (TYPE_A, CLASS_IN, 4) => IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])),
            (TYPE_AAAA, CLASS_IN, 16) => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(data).ok()?)),
            _ => continue,
        };
        let name = question.clone().unwrap_or(owner);
        addresses.push(NamedAddress { name, addr, ttl });
    }
    Some(DnsResponse {
        question,
        outcome,
        addresses,
    })
}

/// Reads the possibly compressed name at `offset`; returns it in
/// lowercase dotted form and the offset just past it. Compression
/// pointers must point strictly backwards, so a crafted message cannot
/// make the walk loop.
fn read_name(message: &[u8], offset: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut position = offset;
    let mut after_name = None;
    let mut lowest_jump = offset;
    loop {
        let len = *message.get(position)?;
        match len {
            0 => break,
            l if l & 0xC0 == 0xC0 => {
                let target = usize::from(read_u16(message, position)? & 0x3FFF);
                if target >= lowest_jump {
                    return None;
                }
                if after_name.is_none() {
                    after_name = Some(position + 2);
                }
                lowest_jump = target;
                position = target;
            }
            l if l & 0xC0 == 0 => {
                let label = message.get(position + 1..position + 1 + usize::from(l))?;
                if !label.iter().all(u8::is_ascii_graphic) {
                    return None;
                }
                if !name.is_empty() {
                    name.push('.');
                }
                name.extend(label.iter().map(|b| char::from(b.to_ascii_lowercase())));
                if name.len() > MAX_NAME_LEN {
                    return None;
                }
                position += 1 + usize::from(l);
            }
            _ => return None,
        }
    }
    Some((name, after_name.unwrap_or(position + 1)))
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes.get(offset..offset.checked_add(2)?).map(|b| u16::from_be_bytes([b[0], b[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a response to `question` (if any) with the given records,
    /// each `(owner, type, data)`. Owners are written in full; the answer
    /// owners after the question use a compression pointer to it.
    fn response(rcode: u16, question: Option<&str>, records: &[(Option<&str>, u16, &[u8])]) -> Vec<u8> {
        let mut m = vec![0x12, 0x34];
        m.extend_from_slice(&(0x8180 | rcode).to_be_bytes());
        m.extend_from_slice(&u16::from(question.is_some()).to_be_bytes());
        m.extend_from_slice(&u16::try_from(records.len()).unwrap().to_be_bytes());
        m.extend_from_slice(&[0, 0, 0, 0]);
        if let Some(q) = question {
            m.extend_from_slice(&encode(q));
            m.extend_from_slice(&[0, 1, 0, 1]);
        }
        for (owner, record_type, data) in records {
            match owner {
                Some(owner) => m.extend_from_slice(&encode(owner)),
                None => m.extend_from_slice(&[0xC0, 12]),
            }
            m.extend_from_slice(&record_type.to_be_bytes());
            m.extend_from_slice(&[0x80, 0x01, 0, 0, 0x0E, 0x10]);
            m.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
            m.extend_from_slice(data);
        }
        m
    }

    fn encode(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.') {
            out.push(u8::try_from(label.len()).unwrap());
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    #[test]
    fn names_addresses_after_the_question_through_a_cname_chain() {
        let cname_target = encode("youtube-ui.l.google.com");
        let message = response(
            0,
            Some("WWW.YouTube.com"),
            &[
                (None, 5, &cname_target),
                (Some("youtube-ui.l.google.com"), TYPE_A, &[142, 250, 69, 206]),
                (Some("youtube-ui.l.google.com"), TYPE_AAAA, &[0x26, 0x07, 0xF8, 0xB0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20, 0x0E]),
            ],
        );

        let parsed = parse_response(&message).unwrap();

        assert_eq!(parsed.question.as_deref(), Some("www.youtube.com"));
        assert_eq!(parsed.outcome, Outcome::Answered);
        let names: Vec<(&str, String)> = parsed.addresses.iter().map(|a| (a.name.as_str(), a.addr.to_string())).collect();
        assert_eq!(names, [("www.youtube.com", "142.250.69.206".into()), ("www.youtube.com", "2607:f8b0::200e".into())]);
        assert_eq!(parsed.addresses[0].ttl, 3600);
    }

    #[test]
    fn mdns_announcements_name_addresses_after_their_own_records() {
        let message = response(0, None, &[(Some("Wills-iPhone.local"), TYPE_A, &[192, 168, 1, 40])]);

        let parsed = parse_response(&message).unwrap();

        assert_eq!(parsed.addresses[0].name, "wills-iphone.local");
    }

    #[test]
    fn reports_nonexistent_names() {
        let parsed = parse_response(&response(3, Some("qx7f9a2.example"), &[])).unwrap();

        assert_eq!(parsed.outcome, Outcome::NoSuchName);
        assert!(parsed.addresses.is_empty());
    }

    #[test]
    fn queries_and_other_opcodes_are_not_responses() {
        let mut query = response(0, Some("example.com"), &[]);
        query[2] &= 0x7F;
        let mut notify = response(0, Some("example.com"), &[]);
        notify[2] |= 0x20;

        assert_eq!(parse_response(&query), None);
        assert_eq!(parse_response(&notify), None);
    }

    #[test]
    fn compression_loops_and_forward_pointers_are_rejected() {
        let mut looping = response(0, Some("a.example"), &[]);
        let question_end = looping.len() - 4;
        looping.truncate(question_end - 1);
        looping.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1]);

        assert_eq!(parse_response(&looping), None);
    }

    #[test]
    fn unprintable_labels_are_rejected() {
        let mut message = response(0, Some("evil.example"), &[]);
        message[13] = 0x1B;

        assert_eq!(parse_response(&message), None);
    }

    #[test]
    fn parsing_never_panics_on_any_prefix_of_a_message() {
        let message = response(0, Some("example.com"), &[(None, TYPE_A, &[1, 2, 3, 4])]);

        for end in 0..=message.len() {
            let _ = parse_response(&message[..end]);
        }
    }
}
