//! Compiling the BPF tab's one-line filters into programs for the kernel.

use sec_core::net::constants::{IpProtocol, ipv4, tcp};
use sec_core::security::vm::{Instruction, Opcode, Program, VmError};
use std::fmt;

/// Why a program did not compile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompileError {
    /// Neither `DROP ALL` nor `BLOCK <protocol> DST <port>`.
    UnknownStatement,
    /// A protocol other than TCP or UDP.
    UnknownProtocol(String),
    /// A port that is not a number from 0 to 65535.
    BadPort(String),
    /// The kernel would refuse the program built; a compiler bug.
    Rejected(VmError),
}

impl fmt::Display for CompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownStatement => {
                write!(f, "expected DROP ALL or BLOCK <TCP|UDP> DST <port>")
            }
            Self::UnknownProtocol(protocol) => {
                write!(f, "unknown protocol {protocol:?}; expected TCP or UDP")
            }
            Self::BadPort(port) => write!(f, "{port:?} is not a port"),
            Self::Rejected(error) => write!(f, "the kernel would refuse it: {error:?}"),
        }
    }
}

/// Compiles a one-line filter into a program the kernel accepts.
///
/// - `DROP ALL` drops every packet.
/// - `BLOCK <TCP|UDP> DST <port>` drops packets of that protocol to a
///   destination port, wherever IPv4 options place the transport header.
///
/// # Errors
///
/// A [`CompileError`] saying what was wrong with `code`.
pub fn compile_bpf(code: &str) -> Result<Program, CompileError> {
    const PROTOCOL_OFFSET: u32 = ipv4::PROTOCOL_OFFSET as u32;
    const VERSION_IHL_OFFSET: u32 = ipv4::VERSION_IHL_OFFSET as u32;
    /// The destination port's offset past the IPv4 header; TCP and UDP
    /// share it.
    const DST_PORT_AFTER_IP_HEADER: u32 = (ipv4::HEADER_OFFSET + tcp::DST_PORT_OFFSET) as u32;
    const PASS_INDEX: u32 = 9;
    const DROP_INDEX: u32 = 10;

    if code.trim() == "DROP ALL" {
        return decode(&Instruction::new(Opcode::Ret, 0, 0, 0).to_bytes());
    }

    let parts: Vec<&str> = code.split_whitespace().collect();
    let ["BLOCK", protocol, "DST", port] = parts.as_slice() else {
        return Err(CompileError::UnknownStatement);
    };
    let protocol = match *protocol {
        "TCP" => IpProtocol::Tcp,
        "UDP" => IpProtocol::Udp,
        other => return Err(CompileError::UnknownProtocol(other.to_string())),
    };
    let port = port
        .parse::<u16>()
        .map_err(|_| CompileError::BadPort((*port).to_string()))?;

    let program = [
        Instruction::new(Opcode::Ldb, 0, 0, PROTOCOL_OFFSET).to_bytes(),
        Instruction::new(Opcode::Ldi, 1, 0, protocol as u32).to_bytes(),
        Instruction::new(Opcode::Eq, 0, 1, 0).to_bytes(),
        Instruction::new(Opcode::Jf, 0, 0, PASS_INDEX).to_bytes(),
        Instruction::new(Opcode::Ldmsh, 4, 0, VERSION_IHL_OFFSET).to_bytes(),
        Instruction::new(Opcode::Ldhx, 2, 4, DST_PORT_AFTER_IP_HEADER).to_bytes(),
        Instruction::new(Opcode::Ldi, 3, 0, u32::from(port)).to_bytes(),
        Instruction::new(Opcode::Eq, 2, 3, 0).to_bytes(),
        Instruction::new(Opcode::Jt, 0, 0, DROP_INDEX).to_bytes(),
        Instruction::new(Opcode::Ret, 0, 0, 1).to_bytes(),
        Instruction::new(Opcode::Ret, 0, 0, 0).to_bytes(),
    ];
    decode(&program.concat())
}

fn decode(encoded: &[u8]) -> Result<Program, CompileError> {
    Program::decode(encoded).map_err(CompileError::Rejected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sec_core::security::vm::{VmAction, execute};

    fn frame(protocol: IpProtocol, dst_port: u16) -> Vec<u8> {
        frame_with_ip_header_words(protocol, dst_port, 5)
    }

    /// A frame whose IPv4 header is `words` four-byte words long, so any
    /// beyond five are options.
    fn frame_with_ip_header_words(protocol: IpProtocol, dst_port: u16, words: u8) -> Vec<u8> {
        let port_at = 14 + usize::from(words) * 4 + 2;
        let mut f = vec![0u8; port_at + 20];
        f[12] = 0x08;
        f[14] = 0x40 | words;
        f[23] = protocol as u8;
        f[port_at..port_at + 2].copy_from_slice(&dst_port.to_be_bytes());
        f
    }

    fn run(code: &str, packet: &[u8]) -> VmAction {
        let program = compile_bpf(code).expect("compiles to a program the kernel accepts");
        execute(&program, packet).expect("program returns")
    }

    #[test]
    fn block_drops_matching_protocol_and_port() {
        let action = run("BLOCK TCP DST 80", &frame(IpProtocol::Tcp, 80));

        assert_eq!(action, VmAction::Drop);
    }

    #[test]
    fn block_drops_a_matching_port_behind_ip_options() {
        for words in [6, 15] {
            let packet = frame_with_ip_header_words(IpProtocol::Tcp, 80, words);

            let action = run("BLOCK TCP DST 80", &packet);

            assert_eq!(action, VmAction::Drop, "IPv4 header of {words} words");
        }
    }

    #[test]
    fn block_passes_another_port_behind_ip_options() {
        let packet = frame_with_ip_header_words(IpProtocol::Tcp, 443, 6);

        let action = run("BLOCK TCP DST 80", &packet);

        assert_eq!(action, VmAction::Pass);
    }

    #[test]
    fn block_passes_other_ports() {
        let action = run("BLOCK TCP DST 80", &frame(IpProtocol::Tcp, 443));

        assert_eq!(action, VmAction::Pass);
    }

    #[test]
    fn block_passes_other_protocols_on_the_same_port() {
        let action = run("BLOCK TCP DST 80", &frame(IpProtocol::Udp, 80));

        assert_eq!(action, VmAction::Pass);
    }

    #[test]
    fn each_mistake_is_named() {
        assert_eq!(
            compile_bpf("BLOCK ICMP DST 80"),
            Err(CompileError::UnknownProtocol("ICMP".to_string()))
        );
        assert_eq!(
            compile_bpf("BLOCK TCP DST 70000"),
            Err(CompileError::BadPort("70000".to_string()))
        );
        assert_eq!(
            compile_bpf("ALLOW ALL"),
            Err(CompileError::UnknownStatement)
        );
        assert_eq!(
            compile_bpf("BLOCK TCP SRC 80"),
            Err(CompileError::UnknownStatement)
        );
    }

    #[test]
    fn drop_all_drops_everything() {
        let action = run("DROP ALL", &frame(IpProtocol::Udp, 1337));

        assert_eq!(action, VmAction::Drop);
    }
}
