//! Management commands: their wire layout, [`Command`] to parse and encode
//! them, and the outcomes the kernel acks.
//!
//! Offsets in this module are relative to the **body** of an
//! authenticated mgmt packet — i.e. the bytes that
//! [`crate::security::mgmt_auth::MgmtAuth::verify`] returns after
//! stripping the 8-byte counter prefix and the 8-byte MAC suffix.
//! Callers (kernel, daemon, GUI) wrap and unwrap that envelope; the
//! code in here only describes the inner command layout.

use core::net::Ipv4Addr;

use crate::security::dpi::Pattern;
use crate::security::vm::Program;
use mgmt_packet::{MAX_PAYLOAD_LEN, MSG_TYPE_OFFSET, add_dpi, ban_ip, block_port, upload_bpf};

wire_enum! {
    /// Management message type identifiers.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ManagementMessageType {
        /// Block a destination port (firewall rule).
        BlockPort = 0x01,
        /// Add a DPI signature pattern.
        AddDpiPattern = 0x02,
        /// Upload an BPF program.
        UploadBpfProgram = 0x03,
        /// Manually ban an IP address.
        BanIp = 0x04,
        /// Remove a destination port from the firewall.
        UnblockPort = 0x05,
        /// Remove a runtime-added DPI pattern.
        RemoveDpiPattern = 0x06,
        /// Uninstall the BPF program, so every packet skips the filter.
        UnloadBpfProgram = 0x07,
        /// Lift a ban on an IP address.
        UnbanIp = 0x08,
    }
}

wire_enum! {
    /// What happened to an authenticated mgmt command, reported back to the
    /// operator in an ack.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum MgmtOutcome {
        /// The command took effect (including no-op duplicates).
        Applied = 0,
        /// The relevant table is full; nothing changed.
        TableFull = 1,
        /// The body was malformed or named an unknown command.
        Invalid = 2,
        /// Well-formed but refused, e.g. blocking the mgmt port itself.
        Refused = 3,
    }
}

/// An authenticated mgmt command, parsed.
#[allow(
    clippy::large_enum_variant,
    reason = "no allocator to box the program into; one command is alive at a time"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    /// Block a destination port.
    BlockPort(u16),
    /// Remove a port from the firewall.
    UnblockPort(u16),
    /// Add a run-time DPI pattern.
    AddDpiPattern(Pattern),
    /// Remove a run-time DPI pattern.
    RemoveDpiPattern(Pattern),
    /// Install a BPF program in place of any running one.
    UploadBpf(Program),
    /// Remove the BPF program, so every packet skips the filter.
    UnloadBpf,
    /// Ban an address.
    BanIp(Ipv4Addr),
    /// Lift a ban.
    UnbanIp(Ipv4Addr),
}

/// A mgmt body that is not a well-formed command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidCommand;

impl Command {
    /// Parses a verified mgmt body. Bytes past a command's operands are
    /// ignored, and an upload of no instructions unloads the filter.
    ///
    /// # Errors
    ///
    /// [`InvalidCommand`] for an unknown type, a missing or truncated
    /// operand, or a pattern or program the kernel would not accept.
    pub fn parse(body: &[u8]) -> Result<Self, InvalidCommand> {
        let type_byte = *body.get(MSG_TYPE_OFFSET).ok_or(InvalidCommand)?;
        let message_type = ManagementMessageType::from_u8(type_byte).ok_or(InvalidCommand)?;
        Ok(match message_type {
            ManagementMessageType::BlockPort => Self::BlockPort(parse_port(body)?),
            ManagementMessageType::UnblockPort => Self::UnblockPort(parse_port(body)?),
            ManagementMessageType::AddDpiPattern => Self::AddDpiPattern(parse_pattern(body)?),
            ManagementMessageType::RemoveDpiPattern => Self::RemoveDpiPattern(parse_pattern(body)?),
            ManagementMessageType::UploadBpfProgram => parse_upload(body)?,
            ManagementMessageType::UnloadBpfProgram => Self::UnloadBpf,
            ManagementMessageType::BanIp => Self::BanIp(parse_address(body)?),
            ManagementMessageType::UnbanIp => Self::UnbanIp(parse_address(body)?),
        })
    }

    /// The type byte this command is sent under.
    pub const fn message_type(&self) -> ManagementMessageType {
        match self {
            Self::BlockPort(_) => ManagementMessageType::BlockPort,
            Self::UnblockPort(_) => ManagementMessageType::UnblockPort,
            Self::AddDpiPattern(_) => ManagementMessageType::AddDpiPattern,
            Self::RemoveDpiPattern(_) => ManagementMessageType::RemoveDpiPattern,
            Self::UploadBpf(_) => ManagementMessageType::UploadBpfProgram,
            Self::UnloadBpf => ManagementMessageType::UnloadBpfProgram,
            Self::BanIp(_) => ManagementMessageType::BanIp,
            Self::UnbanIp(_) => ManagementMessageType::UnbanIp,
        }
    }

    /// Writes the command's body into `out` and returns it.
    pub fn encode<'b>(&self, out: &'b mut [u8; MAX_PAYLOAD_LEN]) -> &'b [u8] {
        out[MSG_TYPE_OFFSET] = self.message_type() as u8;
        let len = match self {
            Self::BlockPort(port) | Self::UnblockPort(port) => {
                put(out, block_port::PORT_OFFSET, &port.to_be_bytes())
            }
            Self::AddDpiPattern(pattern) | Self::RemoveDpiPattern(pattern) => {
                let bytes = pattern.as_bytes();
                out[add_dpi::LEN_OFFSET] = bytes.len() as u8;
                put(out, add_dpi::PATTERN_OFFSET, bytes)
            }
            Self::UploadBpf(program) => encode_program(program, out),
            Self::UnloadBpf => MSG_TYPE_OFFSET + 1,
            Self::BanIp(ip) | Self::UnbanIp(ip) => put(out, ban_ip::IP_OFFSET, &ip.octets()),
        };
        &out[..len]
    }
}

/// Copies `bytes` into `out` at `offset` and returns where they end.
fn put(out: &mut [u8], offset: usize, bytes: &[u8]) -> usize {
    let end = offset + bytes.len();
    out[offset..end].copy_from_slice(bytes);
    end
}

fn encode_program(program: &Program, out: &mut [u8; MAX_PAYLOAD_LEN]) -> usize {
    let mut end = upload_bpf::INSTR_OFFSET;
    let mut count = 0u8;
    for instruction in program.instructions() {
        end = put(out, end, &instruction.to_bytes());
        count += 1;
    }
    out[upload_bpf::COUNT_OFFSET] = count;
    end
}

fn parse_port(body: &[u8]) -> Result<u16, InvalidCommand> {
    let port = body
        .get(block_port::PORT_OFFSET..block_port::PORT_OFFSET + 2)
        .ok_or(InvalidCommand)?;
    Ok(u16::from_be_bytes([port[0], port[1]]))
}

fn parse_pattern(body: &[u8]) -> Result<Pattern, InvalidCommand> {
    let len = usize::from(*body.get(add_dpi::LEN_OFFSET).ok_or(InvalidCommand)?);
    let bytes = body
        .get(add_dpi::PATTERN_OFFSET..add_dpi::PATTERN_OFFSET + len)
        .ok_or(InvalidCommand)?;
    Pattern::new(bytes).map_err(|_| InvalidCommand)
}

fn parse_address(body: &[u8]) -> Result<Ipv4Addr, InvalidCommand> {
    let octets = body
        .get(ban_ip::IP_OFFSET..)
        .and_then(<[u8]>::first_chunk::<4>)
        .ok_or(InvalidCommand)?;
    Ok(Ipv4Addr::from(*octets))
}

fn parse_upload(body: &[u8]) -> Result<Command, InvalidCommand> {
    let count = usize::from(*body.get(upload_bpf::COUNT_OFFSET).ok_or(InvalidCommand)?);
    let encoded = body
        .get(upload_bpf::INSTR_OFFSET..upload_bpf::INSTR_OFFSET + count * upload_bpf::INSTR_SIZE)
        .ok_or(InvalidCommand)?;
    if encoded.is_empty() {
        return Ok(Command::UnloadBpf);
    }
    Program::decode(encoded)
        .map(Command::UploadBpf)
        .map_err(|_| InvalidCommand)
}

/// The kernel's answer to an authenticated command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ack {
    /// The command's sequence number.
    pub seq: u32,
    /// The command's type byte as sent, which need not be a known type;
    /// 0 for an empty body.
    pub command: u8,
    /// What the command did.
    pub outcome: MgmtOutcome,
}

impl Ack {
    /// The ack's report body.
    pub fn encode(&self) -> [u8; ack_packet::ACK_BODY_LEN] {
        let mut body = [0u8; ack_packet::ACK_BODY_LEN];
        body[0] = ack_packet::ACK_MESSAGE_TYPE;
        body[ack_packet::SEQ_OFFSET..][..4].copy_from_slice(&self.seq.to_be_bytes());
        body[ack_packet::COMMAND_OFFSET] = self.command;
        body[ack_packet::OUTCOME_OFFSET] = self.outcome as u8;
        body
    }

    /// The ack in a report body, if it is a whole ack with a known outcome.
    pub fn decode(body: &[u8]) -> Option<Self> {
        let body = body.first_chunk::<{ ack_packet::ACK_BODY_LEN }>()?;
        if body[0] != ack_packet::ACK_MESSAGE_TYPE {
            return None;
        }
        let seq = &body[ack_packet::SEQ_OFFSET..][..4];
        Some(Self {
            seq: u32::from_be_bytes([seq[0], seq[1], seq[2], seq[3]]),
            command: body[ack_packet::COMMAND_OFFSET],
            outcome: MgmtOutcome::from_u8(body[ack_packet::OUTCOME_OFFSET])?,
        })
    }
}

/// Layout of the ack the kernel sends for every authenticated command.
pub mod ack_packet {
    /// Message-type byte distinguishing acks from alerts.
    pub const ACK_MESSAGE_TYPE: u8 = 0x03;
    /// Offset of the acknowledged command's sequence (big-endian u32).
    pub const SEQ_OFFSET: usize = 1;
    /// Offset of the acknowledged command's type byte (0 if absent).
    pub const COMMAND_OFFSET: usize = 5;
    /// Offset of the [`super::MgmtOutcome`] byte.
    pub const OUTCOME_OFFSET: usize = 6;
    /// Total bytes of ack body on the wire.
    pub const ACK_BODY_LEN: usize = 7;
}

/// Management message format constants.
///
/// All offsets are body-relative — the caller has already validated
/// the auth envelope and stripped the counter + MAC.
pub mod mgmt_packet {
    /// Longest body any command has: a full `UploadBpfProgram`.
    pub const MAX_PAYLOAD_LEN: usize =
        upload_bpf::INSTR_OFFSET + upload_bpf::MAX_INSTR_COUNT * upload_bpf::INSTR_SIZE;
    /// Offset to message type field within the body.
    pub const MSG_TYPE_OFFSET: usize = 0;

    /// `BlockPort` and `UnblockPort` message format.
    pub mod block_port {
        /// Offset to port number (bytes 1-2, big-endian).
        pub const PORT_OFFSET: usize = 1;
    }

    /// `AddDpiPattern` and `RemoveDpiPattern` message format.
    pub mod add_dpi {
        /// Offset to pattern length field.
        pub const LEN_OFFSET: usize = 1;
        /// Offset to pattern data.
        pub const PATTERN_OFFSET: usize = 2;
        /// Maximum pattern length in bytes.
        pub const MAX_PATTERN_LEN: usize = 32;
    }

    /// `UploadBpfProgram` message format.
    pub mod upload_bpf {
        /// Offset to instruction count field.
        pub const COUNT_OFFSET: usize = 1;
        /// Offset to instruction data.
        pub const INSTR_OFFSET: usize = 2;
        /// Size of each instruction in bytes.
        pub const INSTR_SIZE: usize = 7;
        /// Maximum number of instructions.
        pub const MAX_INSTR_COUNT: usize = 64;
    }

    /// `BanIp` and `UnbanIp` message format.
    pub mod ban_ip {
        /// Offset to IP address (bytes 1-4).
        pub const IP_OFFSET: usize = 1;
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::security::vm::{Instruction, Opcode};
    use std::vec;

    fn encoded(command: &Command) -> ([u8; MAX_PAYLOAD_LEN], usize) {
        let mut out = [0u8; MAX_PAYLOAD_LEN];
        let len = command.encode(&mut out).len();
        (out, len)
    }

    fn pattern(bytes: &[u8]) -> Pattern {
        Pattern::new(bytes).expect("a valid pattern")
    }

    fn pass_all() -> Program {
        Program::decode(&Instruction::new(Opcode::Ret, 0, 0, 1).to_bytes()).expect("valid")
    }

    #[test]
    fn each_command_encodes_to_its_wire_layout() {
        let cases: [(Command, &[u8]); 8] = [
            (Command::BlockPort(0x1F90), &[0x01, 0x1F, 0x90]),
            (Command::UnblockPort(0x1F90), &[0x05, 0x1F, 0x90]),
            (
                Command::AddDpiPattern(pattern(b"abc")),
                &[0x02, 3, b'a', b'b', b'c'],
            ),
            (
                Command::RemoveDpiPattern(pattern(b"abc")),
                &[0x06, 3, b'a', b'b', b'c'],
            ),
            (
                Command::UploadBpf(pass_all()),
                &[0x03, 1, 0x0D, 0, 0, 0, 0, 0, 1],
            ),
            (Command::UnloadBpf, &[0x07]),
            (
                Command::BanIp(Ipv4Addr::new(10, 0, 0, 7)),
                &[0x04, 10, 0, 0, 7],
            ),
            (
                Command::UnbanIp(Ipv4Addr::new(10, 0, 0, 7)),
                &[0x08, 10, 0, 0, 7],
            ),
        ];
        for (command, wire) in cases {
            let (out, len) = encoded(&command);

            assert_eq!(&out[..len], wire, "{command:?}");
            assert_eq!(Command::parse(wire), Ok(command));
        }
    }

    #[test]
    fn bytes_past_the_operands_are_ignored() {
        assert_eq!(
            Command::parse(&[0x01, 0x00, 0x50, 0xFF, 0xFF]),
            Ok(Command::BlockPort(80))
        );
    }

    #[test]
    fn an_upload_of_no_instructions_unloads_the_filter() {
        assert_eq!(Command::parse(&[0x03, 0]), Ok(Command::UnloadBpf));
    }

    #[test]
    fn malformed_bodies_are_invalid() {
        let bodies: [&[u8]; 9] = [
            &[],
            &[0xEE],
            &[0x01, 0x00],
            &[0x02, 4, b'a', b'b'],
            &[0x02, 0],
            &[0x04, 10, 0, 0],
            &[0x03],
            &[0x03, 2, 0x0D, 0, 0, 0, 0, 0, 1],
            &[0x03, 1, 0x0D, 0, 0, 0, 0, 0, 9],
        ];
        for body in bodies {
            assert_eq!(Command::parse(body), Err(InvalidCommand), "{body:?}");
        }
    }

    #[test]
    fn an_upload_of_more_instructions_than_a_program_holds_is_invalid() {
        let count = upload_bpf::MAX_INSTR_COUNT + 1;
        let ret = Instruction::new(Opcode::Ret, 0, 0, 1).to_bytes();
        let mut body = vec![0x03, count as u8];
        for _ in 0..count {
            body.extend_from_slice(&ret);
        }

        assert_eq!(Command::parse(&body), Err(InvalidCommand));
    }

    #[test]
    fn a_longest_pattern_and_program_fit_the_body_buffer() {
        let longest = [b'x'; add_dpi::MAX_PATTERN_LEN];
        let ret = Instruction::new(Opcode::Ret, 0, 0, 1).to_bytes();
        let full_program: [u8; upload_bpf::MAX_INSTR_COUNT * upload_bpf::INSTR_SIZE] =
            core::array::from_fn(|i| ret[i % upload_bpf::INSTR_SIZE]);
        let program = Program::decode(&full_program).expect("valid");

        assert_eq!(
            encoded(&Command::AddDpiPattern(pattern(&longest))).1,
            2 + longest.len()
        );
        assert_eq!(encoded(&Command::UploadBpf(program)).1, MAX_PAYLOAD_LEN);
    }
}
