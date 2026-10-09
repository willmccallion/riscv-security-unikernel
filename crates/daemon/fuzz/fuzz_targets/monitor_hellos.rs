//! Any sequence of TCP segments or QUIC CRYPTO fragments, in any order
//! and with any sequence numbers or offsets, reassembles safely.

#![no_main]

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;
use security_daemon::monitor::flows::Endpoint;
use security_daemon::monitor::names::HelloAssembler;
use security_daemon::monitor::quic::CryptoData;
use security_daemon::monitor::time::UnixNanos;
use std::net::{IpAddr, Ipv4Addr};

#[derive(Debug, Arbitrary)]
enum Piece {
    Tcp { client_port: u8, sequence: u32, payload: Vec<u8> },
    Quic { client_port: u8, offset: u64, bytes: Vec<u8> },
    Expire { seconds: u8 },
}

fn endpoint(port: u16) -> Endpoint {
    Endpoint {
        addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        port,
    }
}

fuzz_target!(|pieces: Vec<Piece>| {
    let mut assembler = HelloAssembler::default();
    let server = endpoint(443);
    let mut now = 0u64;
    for piece in pieces {
        let at = UnixNanos::new(now);
        let name = match piece {
            Piece::Tcp { client_port, sequence, payload } => {
                assembler.observe_tcp(endpoint(u16::from(client_port)), server, sequence, &payload, at)
            }
            Piece::Quic { client_port, offset, bytes } => {
                let fragment = CryptoData { offset, bytes };
                assembler.observe_quic(endpoint(u16::from(client_port)), server, &[fragment], at)
            }
            Piece::Expire { seconds } => {
                now += u64::from(seconds) * 1_000_000_000;
                assembler.expire(UnixNanos::new(now));
                None
            }
        };
        if let Some(name) = name {
            assert!(name.name.bytes().all(|b| b.is_ascii_graphic()));
        }
    }
});
