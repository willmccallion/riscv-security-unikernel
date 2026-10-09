#![cfg_attr(not(test), deny(clippy::indexing_slicing))]
//! Reading the server name from a TLS ClientHello.
//!
//! A browser names the site it is connecting to in the clear, in the
//! `server_name` extension of the first message it sends, even when its
//! DNS lookups are encrypted. With Encrypted Client Hello the visible
//! name is only a cover name for the real one, so it is reported as such.

/// The longest server name accepted.
const MAX_NAME_LEN: usize = 253;

const CONTENT_HANDSHAKE: u8 = 22;
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const EXTENSION_SERVER_NAME: u16 = 0;
const EXTENSION_ENCRYPTED_CLIENT_HELLO: u16 = 0xFE0D;
const NAME_TYPE_HOST: u8 = 0;

/// The server name a ClientHello carried.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerName {
    /// The name, lowercased.
    pub name: String,
    /// Whether the hello used Encrypted Client Hello, making `name` a
    /// shared cover name rather than the site's.
    pub encrypted_hello: bool,
}

/// What the first bytes of a TLS client stream say so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hello {
    /// A ClientHello naming a server.
    Named(ServerName),
    /// A complete ClientHello without a server name.
    Unnamed,
    /// The start of a ClientHello whose remaining bytes have not arrived;
    /// `needed` is the total stream length required.
    Incomplete {
        /// Bytes of stream needed to read the whole hello.
        needed: usize,
    },
    /// Not a TLS ClientHello.
    NotTls,
}

/// Reads the ClientHello at the start of a client's TLS-over-TCP stream,
/// which wraps handshake messages in records.
pub fn parse_client_hello(stream: &[u8]) -> Hello {
    const RECORD_HEADER: usize = 5;
    let (Some(&content_type), Some(&major)) = (stream.first(), stream.get(1)) else {
        return Hello::Incomplete { needed: RECORD_HEADER };
    };
    if content_type != CONTENT_HANDSHAKE || major != 3 {
        return Hello::NotTls;
    }
    let Some(record_len) = read_u16(stream, 3) else {
        return Hello::Incomplete { needed: RECORD_HEADER };
    };
    let needed = RECORD_HEADER + usize::from(record_len);
    let Some(record) = stream.get(RECORD_HEADER..needed) else {
        return Hello::Incomplete { needed };
    };
    match parse_handshake(record) {
        // A hello spanning several records is rare; only the first is read.
        Hello::Incomplete { .. } => Hello::Unnamed,
        hello => hello,
    }
}

/// Reads the ClientHello handshake message at the start of `stream`,
/// as QUIC carries it in CRYPTO frames, without TLS records.
pub fn parse_handshake(stream: &[u8]) -> Hello {
    const MESSAGE_HEADER: usize = 4;
    let Some(&[message_type, len_high, len_mid, len_low]) = stream.first_chunk::<MESSAGE_HEADER>() else {
        return Hello::Incomplete { needed: MESSAGE_HEADER };
    };
    if message_type != HANDSHAKE_CLIENT_HELLO {
        return Hello::NotTls;
    }
    let body_len = usize::from(len_high) << 16 | usize::from(len_mid) << 8 | usize::from(len_low);
    let needed = MESSAGE_HEADER + body_len;
    let Some(body) = stream.get(MESSAGE_HEADER..needed) else {
        return Hello::Incomplete { needed };
    };
    extensions(body).map_or(Hello::NotTls, server_name)
}

/// The extensions block of a ClientHello body.
fn extensions(body: &[u8]) -> Option<&[u8]> {
    const VERSION_AND_RANDOM: usize = 2 + 32;
    let mut offset = VERSION_AND_RANDOM;
    offset += 1 + usize::from(*body.get(offset)?);
    offset += 2 + usize::from(read_u16(body, offset)?);
    offset += 1 + usize::from(*body.get(offset)?);
    let len = usize::from(read_u16(body, offset)?);
    body.get(offset + 2..offset + 2 + len)
}

fn server_name(mut extensions: &[u8]) -> Hello {
    let mut name = None;
    let mut encrypted_hello = false;
    while let (Some(kind), Some(len)) = (read_u16(extensions, 0), read_u16(extensions, 2)) {
        let Some(data) = extensions.get(4..4 + usize::from(len)) else {
            return Hello::NotTls;
        };
        match kind {
            EXTENSION_SERVER_NAME => name = host_name(data),
            EXTENSION_ENCRYPTED_CLIENT_HELLO => encrypted_hello = true,
            _ => {}
        }
        let Some(rest) = extensions.get(4 + usize::from(len)..) else {
            return Hello::NotTls;
        };
        extensions = rest;
    }
    name.map_or(Hello::Unnamed, |name| Hello::Named(ServerName { name, encrypted_hello }))
}

/// The host name in a `server_name` extension's data.
fn host_name(data: &[u8]) -> Option<String> {
    let list_len = usize::from(read_u16(data, 0)?);
    let list = data.get(2..2 + list_len)?;
    if *list.first()? != NAME_TYPE_HOST {
        return None;
    }
    let len = usize::from(read_u16(list, 1)?);
    let name = list.get(3..3 + len)?;
    let printable = name.iter().all(u8::is_ascii_graphic);
    (printable && !name.is_empty() && name.len() <= MAX_NAME_LEN)
        .then(|| name.iter().map(|b| char::from(b.to_ascii_lowercase())).collect())
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes.get(offset..)?.first_chunk().copied().map(u16::from_be_bytes)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// A ClientHello record for `name` (if any), with a padding extension
    /// of `padding` bytes before it and optionally an ECH extension.
    pub fn client_hello(name: Option<&str>, padding: usize, ech: bool) -> Vec<u8> {
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&0x0015u16.to_be_bytes());
        extensions.extend_from_slice(&u16::try_from(padding).unwrap().to_be_bytes());
        extensions.extend(std::iter::repeat_n(0, padding));
        if let Some(name) = name {
            let n = name.len();
            extensions.extend_from_slice(&EXTENSION_SERVER_NAME.to_be_bytes());
            extensions.extend_from_slice(&u16::try_from(n + 5).unwrap().to_be_bytes());
            extensions.extend_from_slice(&u16::try_from(n + 3).unwrap().to_be_bytes());
            extensions.push(NAME_TYPE_HOST);
            extensions.extend_from_slice(&u16::try_from(n).unwrap().to_be_bytes());
            extensions.extend_from_slice(name.as_bytes());
        }
        if ech {
            extensions.extend_from_slice(&EXTENSION_ENCRYPTED_CLIENT_HELLO.to_be_bytes());
            extensions.extend_from_slice(&[0, 2, 0xAA, 0xBB]);
        }
        let mut body = vec![3, 3];
        body.extend_from_slice(&[0x11; 32]);
        body.push(32);
        body.extend_from_slice(&[0x22; 32]);
        body.extend_from_slice(&[0, 4, 0x13, 0x01, 0x13, 0x02]);
        body.extend_from_slice(&[1, 0]);
        body.extend_from_slice(&u16::try_from(extensions.len()).unwrap().to_be_bytes());
        body.extend_from_slice(&extensions);
        let mut handshake = vec![HANDSHAKE_CLIENT_HELLO];
        handshake.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);
        let mut record = vec![CONTENT_HANDSHAKE, 3, 1];
        record.extend_from_slice(&u16::try_from(handshake.len()).unwrap().to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn reads_the_server_name() {
        let hello = parse_client_hello(&client_hello(Some("WWW.Example.COM"), 10, false));

        assert_eq!(
            hello,
            Hello::Named(ServerName {
                name: "www.example.com".into(),
                encrypted_hello: false
            })
        );
    }

    #[test]
    fn marks_names_from_encrypted_hellos_as_cover_names() {
        let Hello::Named(name) = parse_client_hello(&client_hello(Some("cloudflare-ech.com"), 0, true)) else {
            panic!("no name");
        };

        assert!(name.encrypted_hello);
    }

    #[test]
    fn a_partial_hello_says_how_much_stream_it_needs() {
        let whole = client_hello(Some("example.com"), 1600, false);

        let partial = parse_client_hello(&whole[..1400]);

        assert_eq!(partial, Hello::Incomplete { needed: whole.len() });
    }

    #[test]
    fn reads_a_bare_handshake_message_as_quic_carries_it() {
        let record = client_hello(Some("www.youtube.com"), 30, false);
        let message = &record[5..];

        let partial = parse_handshake(&message[..40]);
        let whole = parse_handshake(message);

        assert_eq!(partial, Hello::Incomplete { needed: message.len() });
        assert!(matches!(whole, Hello::Named(name) if name.name == "www.youtube.com"));
    }

    #[test]
    fn hellos_without_names_and_other_protocols_are_told_apart() {
        assert_eq!(parse_client_hello(&client_hello(None, 4, false)), Hello::Unnamed);
        assert_eq!(parse_client_hello(b"GET / HTTP/1.1\r\n"), Hello::NotTls);
        assert_eq!(parse_client_hello(&[]), Hello::Incomplete { needed: 5 });
    }

    #[test]
    fn parsing_never_panics_on_any_prefix_or_corruption() {
        let hello = client_hello(Some("example.com"), 20, true);

        for end in 0..=hello.len() {
            let _ = parse_client_hello(&hello[..end]);
        }
        for i in 5..hello.len() {
            let mut corrupt = hello.clone();
            corrupt[i] ^= 0xFF;
            let _ = parse_client_hello(&corrupt);
        }
    }
}
