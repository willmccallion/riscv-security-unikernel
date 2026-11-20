//! Virtual machine for executing BPF-style packet filters.
//!
//! An operator uploads a program as [`Instruction`]s; [`Program::decode`]
//! checks it once, into operations whose registers, jump targets and
//! return values are all valid, and [`execute`] runs it on each packet.

use crate::security::mgmt::mgmt_packet::upload_bpf::{INSTR_SIZE, MAX_INSTR_COUNT};

wire_enum! {
    /// Opcodes for the virtual machine instruction set.
    #[derive(Copy, Clone, Debug)]
    pub enum Opcode {
        /// No operation.
        Nop = 0x00,
        /// Load byte from packet into register.
        Ldb = 0x01,
        /// Load half-word (u16) from packet into register.
        Ldh = 0x02,
        /// Load word (u32) from packet into register.
        Ldw = 0x03,
        /// Load immediate value into register.
        Ldi = 0x04,
        /// Move value from one register to another.
        Mov = 0x05,
        /// Compare two registers for equality.
        Eq = 0x06,
        /// Compare two registers for greater-than.
        Gt = 0x07,
        /// Bitwise AND operation.
        And = 0x08,
        /// Bitwise OR operation.
        Or = 0x09,
        /// Unconditional jump to instruction index.
        Jmp = 0x0A,
        /// Conditional jump if last comparison was true.
        Jt = 0x0B,
        /// Conditional jump if last comparison was false.
        Jf = 0x0C,
        /// Return with action (0=drop, 1=pass).
        Ret = 0x0D,
        /// Load four times the low nibble of the byte at `imm`: an IPv4
        /// header's length when `imm` is its version/IHL byte.
        Ldmsh = 0x0E,
        /// Load byte at `imm + reg_b` into register.
        Ldbx = 0x0F,
        /// Load half-word (u16) at `imm + reg_b` into register.
        Ldhx = 0x10,
        /// Load word (u32) at `imm + reg_b` into register.
        Ldwx = 0x11,
    }
}

/// Why an uploaded program is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmError {
    /// No instructions; an empty upload removes the filter instead.
    Empty,
    /// More than [`MAX_INSTR_COUNT`] instructions, or bytes that are not
    /// a whole number of instructions.
    BadLength,
    /// The opcode byte is not one the VM defines, so a future opcode cannot
    /// change what an already-uploaded program does.
    InvalidOpcode,
    /// `reg_a` or `reg_b` is outside the 16-register file.
    InvalidRegister,
    /// A jump targets an instruction index past the program's end.
    InvalidJumpTarget,
    /// A `Ret` whose value is neither 0 (drop) nor 1 (pass).
    InvalidAction,
    /// The last instruction is neither `Ret` nor `Jmp`, so execution could
    /// step past the end without choosing an action.
    MissingReturn,
}

/// One instruction as the wire carries it: an opcode, two register
/// operands and a big-endian immediate, unchecked.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Instruction {
    op: u8,
    reg_a: u8,
    reg_b: u8,
    imm: u32,
}

impl Instruction {
    /// An instruction with these fields.
    pub const fn new(op: Opcode, reg_a: u8, reg_b: u8, imm: u32) -> Self {
        Self {
            op: op as u8,
            reg_a,
            reg_b,
            imm,
        }
    }

    /// The instruction's wire bytes.
    pub const fn to_bytes(self) -> [u8; INSTR_SIZE] {
        let imm = self.imm.to_be_bytes();
        [
            self.op, self.reg_a, self.reg_b, imm[0], imm[1], imm[2], imm[3],
        ]
    }

    /// The instruction `bytes` encode.
    pub const fn from_bytes(bytes: &[u8; INSTR_SIZE]) -> Self {
        Self {
            op: bytes[0],
            reg_a: bytes[1],
            reg_b: bytes[2],
            imm: u32::from_be_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]),
        }
    }
}

/// What a program wants the caller to do with the current packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmAction {
    /// Drop the packet and raise the BPF alert.
    Drop,
    /// Allow the packet to continue through the pipeline.
    Pass,
}

/// A program ran out of cycles before returning; callers drop the packet
/// and alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeout;

/// One of the 16 registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Reg(u8);

impl Reg {
    const COUNT: usize = 16;

    const fn new(index: u8) -> Result<Self, VmError> {
        if (index as usize) < Self::COUNT {
            Ok(Self(index))
        } else {
            Err(VmError::InvalidRegister)
        }
    }

    const fn index(self) -> usize {
        // A no-op for any `Reg`; it lets the compiler drop the bounds check.
        self.0 as usize % Self::COUNT
    }
}

/// How many bytes a load reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Width {
    Byte,
    Half,
    Word,
}

/// A checked operation: every register is real, every jump target is inside
/// the program, and every return names an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Nop,
    /// `dst = packet[offset..]`, big-endian, 0 past the end.
    Load {
        width: Width,
        dst: Reg,
        offset: u32,
    },
    /// `dst = packet[offset + index..]`, big-endian, 0 past the end.
    LoadIndexed {
        width: Width,
        dst: Reg,
        offset: u32,
        index: Reg,
    },
    /// Four times the low nibble of the byte at `offset`: an IPv4 header's
    /// length when `offset` is its version/IHL byte.
    LoadHeaderLen {
        dst: Reg,
        offset: u32,
    },
    LoadImm {
        dst: Reg,
        value: u32,
    },
    Mov {
        dst: Reg,
        src: Reg,
    },
    Eq {
        left: Reg,
        right: Reg,
    },
    Gt {
        left: Reg,
        right: Reg,
    },
    And {
        dst: Reg,
        src: Reg,
    },
    Or {
        dst: Reg,
        src: Reg,
    },
    Jmp {
        target: u8,
    },
    JumpIfTrue {
        target: u8,
    },
    JumpIfFalse {
        target: u8,
    },
    Ret(VmAction),
}

impl Op {
    /// `inst` checked against a program of `len` instructions.
    fn decode(inst: Instruction, len: usize) -> Result<Self, VmError> {
        let Some(opcode) = Opcode::from_u8(inst.op) else {
            return Err(VmError::InvalidOpcode);
        };
        let a = Reg::new(inst.reg_a)?;
        let b = Reg::new(inst.reg_b)?;
        let imm = inst.imm;
        let target = match u8::try_from(imm) {
            Ok(target) if usize::from(target) < len => Ok(target),
            _ => Err(VmError::InvalidJumpTarget),
        };
        let load = |width| Self::Load {
            width,
            dst: a,
            offset: imm,
        };
        let load_indexed = |width| Self::LoadIndexed {
            width,
            dst: a,
            offset: imm,
            index: b,
        };
        Ok(match opcode {
            Opcode::Nop => Self::Nop,
            Opcode::Ldb => load(Width::Byte),
            Opcode::Ldh => load(Width::Half),
            Opcode::Ldw => load(Width::Word),
            Opcode::Ldbx => load_indexed(Width::Byte),
            Opcode::Ldhx => load_indexed(Width::Half),
            Opcode::Ldwx => load_indexed(Width::Word),
            Opcode::Ldmsh => Self::LoadHeaderLen {
                dst: a,
                offset: imm,
            },
            Opcode::Ldi => Self::LoadImm { dst: a, value: imm },
            Opcode::Mov => Self::Mov { dst: a, src: b },
            Opcode::Eq => Self::Eq { left: a, right: b },
            Opcode::Gt => Self::Gt { left: a, right: b },
            Opcode::And => Self::And { dst: a, src: b },
            Opcode::Or => Self::Or { dst: a, src: b },
            Opcode::Jmp => Self::Jmp { target: target? },
            Opcode::Jt => Self::JumpIfTrue { target: target? },
            Opcode::Jf => Self::JumpIfFalse { target: target? },
            Opcode::Ret => match imm {
                0 => Self::Ret(VmAction::Drop),
                1 => Self::Ret(VmAction::Pass),
                _ => return Err(VmError::InvalidAction),
            },
        })
    }

    /// Whether execution never continues to the next instruction.
    const fn ends_flow(self) -> bool {
        matches!(self, Self::Ret(_) | Self::Jmp { .. })
    }
}

/// A checked, non-empty program whose last operation returns or jumps, so
/// no run can step past its end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Program {
    ops: [Op; MAX_INSTR_COUNT],
    len: usize,
}

impl Program {
    /// Checks the uploaded instruction bytes `encoded`.
    ///
    /// # Errors
    ///
    /// The [`VmError`] naming the first problem found.
    pub fn decode(encoded: &[u8]) -> Result<Self, VmError> {
        let (instructions, rest) = encoded.as_chunks::<INSTR_SIZE>();
        if !rest.is_empty() || instructions.len() > MAX_INSTR_COUNT {
            return Err(VmError::BadLength);
        }
        let len = instructions.len();
        let mut ops = [Op::Nop; MAX_INSTR_COUNT];
        for (op, bytes) in ops.iter_mut().zip(instructions) {
            *op = Op::decode(Instruction::from_bytes(bytes), len)?;
        }
        match ops[..len].last() {
            None => Err(VmError::Empty),
            Some(last) if !last.ends_flow() => Err(VmError::MissingReturn),
            Some(_) => Ok(Self { ops, len }),
        }
    }
}

/// Runs `program` on `packet`.
///
/// # Errors
///
/// [`Timeout`] when the program has not returned within a fixed budget
/// of instructions.
#[inline(always)]
pub fn execute(program: &Program, packet: &[u8]) -> Result<VmAction, Timeout> {
    /// Instructions a program may execute per packet before it is
    /// treated as a runaway and the packet dropped.
    const MAX_CYCLES: usize = 1000;

    let mut regs = [0u64; Reg::COUNT];
    let mut flag = false;
    let mut pc = 0;
    for _ in 0..MAX_CYCLES {
        // A no-op (pc < len); it lets the compiler drop the bounds check.
        let op = program.ops[pc % MAX_INSTR_COUNT];
        pc += 1;
        match op {
            Op::Nop => {}
            Op::Load { width, dst, offset } => regs[dst.index()] = load(packet, width, offset),
            Op::LoadIndexed {
                width,
                dst,
                offset,
                index,
            } => regs[dst.index()] = load_indexed(packet, width, offset, regs[index.index()]),
            Op::LoadHeaderLen { dst, offset } => {
                regs[dst.index()] = 4 * (load(packet, Width::Byte, offset) & 0x0F);
            }
            Op::LoadImm { dst, value } => regs[dst.index()] = u64::from(value),
            Op::Mov { dst, src } => regs[dst.index()] = regs[src.index()],
            Op::Eq { left, right } => flag = regs[left.index()] == regs[right.index()],
            Op::Gt { left, right } => flag = regs[left.index()] > regs[right.index()],
            Op::And { dst, src } => regs[dst.index()] &= regs[src.index()],
            Op::Or { dst, src } => regs[dst.index()] |= regs[src.index()],
            Op::Jmp { target } => pc = usize::from(target),
            Op::JumpIfTrue { target } if flag => pc = usize::from(target),
            Op::JumpIfFalse { target } if !flag => pc = usize::from(target),
            Op::JumpIfTrue { .. } | Op::JumpIfFalse { .. } => {}
            Op::Ret(action) => return Ok(action),
        }
    }
    Err(Timeout)
}

/// Reads `width` big-endian bytes at `offset + index`, or 0 if any are out
/// of bounds.
fn load_indexed(packet: &[u8], width: Width, offset: u32, index: u64) -> u64 {
    u32::try_from(index)
        .ok()
        .and_then(|index| offset.checked_add(index))
        .map_or(0, |offset| load(packet, width, offset))
}

/// Reads `width` big-endian bytes at `offset`, or 0 if any are out of bounds.
fn load(packet: &[u8], width: Width, offset: u32) -> u64 {
    match width {
        Width::Byte => load_be::<1>(packet, offset),
        Width::Half => load_be::<2>(packet, offset),
        Width::Word => load_be::<4>(packet, offset),
    }
}

/// Reads `N` big-endian bytes at `offset`, or 0 if any are out of bounds.
fn load_be<const N: usize>(packet: &[u8], offset: u32) -> u64 {
    let Some(bytes) = (offset as usize)
        .checked_add(N)
        .and_then(|end| packet.get(offset as usize..end))
    else {
        return 0;
    };
    bytes
        .iter()
        .fold(0, |acc, &byte| (acc << 8) | u64::from(byte))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use Opcode::{
        And, Eq, Gt, Jf, Jmp, Jt, Ldb, Ldbx, Ldh, Ldhx, Ldi, Ldmsh, Ldw, Ldwx, Mov, Nop, Or, Ret,
    };
    use std::{vec, vec::Vec};

    const PACKET: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];

    const fn ins(op: Opcode, reg_a: u8, reg_b: u8, imm: u32) -> Instruction {
        Instruction::new(op, reg_a, reg_b, imm)
    }

    fn encode(instructions: &[Instruction]) -> Vec<u8> {
        instructions.iter().flat_map(|i| i.to_bytes()).collect()
    }

    fn decode(instructions: &[Instruction]) -> Result<Program, VmError> {
        Program::decode(&encode(instructions))
    }

    fn run(instructions: &[Instruction], packet: &[u8]) -> Result<VmAction, Timeout> {
        execute(&decode(instructions).expect("a valid program"), packet)
    }

    /// Whether `prefix` leaves `expected` in r0, checked by comparing it
    /// with r15 and returning pass only on a match.
    fn leaves_in_r0(prefix: &[Instruction], expected: u32) -> bool {
        let pass_at = prefix.len() as u32 + 4;
        let mut program = prefix.to_vec();
        program.extend([
            ins(Ldi, 15, 0, expected),
            ins(Eq, 0, 15, 0),
            ins(Jt, 0, 0, pass_at),
            ins(Ret, 0, 0, 0),
            ins(Ret, 0, 0, 1),
        ]);
        run(&program, &PACKET) == Ok(VmAction::Pass)
    }

    /// Whether `compare` sets the flag, seen through which way `Jt` goes.
    fn sets_flag(compare: &[Instruction]) -> bool {
        let pass_at = compare.len() as u32 + 2;
        let mut program = compare.to_vec();
        program.extend([ins(Jt, 0, 0, pass_at), ins(Ret, 0, 0, 0), ins(Ret, 0, 0, 1)]);
        run(&program, &PACKET) == Ok(VmAction::Pass)
    }

    #[test]
    fn a_register_past_the_sixteenth_is_refused() {
        assert_eq!(
            decode(&[ins(Ldi, 16, 0, 1), ins(Ret, 0, 0, 1)]),
            Err(VmError::InvalidRegister)
        );
        assert_eq!(
            decode(&[ins(Mov, 0, 20, 0), ins(Ret, 0, 0, 1)]),
            Err(VmError::InvalidRegister)
        );
    }

    #[test]
    fn an_opcode_the_vm_does_not_define_is_refused() {
        let unknown = Instruction::from_bytes(&[0xFF, 0, 0, 0, 0, 0, 0]);

        assert_eq!(
            decode(&[unknown, ins(Ret, 0, 0, 1)]),
            Err(VmError::InvalidOpcode)
        );
    }

    #[test]
    fn a_jump_past_the_last_instruction_is_refused() {
        for jump in [Jmp, Jt, Jf] {
            let program = [ins(jump, 0, 0, 2), ins(Ret, 0, 0, 1)];

            assert_eq!(
                decode(&program),
                Err(VmError::InvalidJumpTarget),
                "{jump:?}"
            );
        }
    }

    #[test]
    fn a_return_that_is_neither_drop_nor_pass_is_refused() {
        assert_eq!(decode(&[ins(Ret, 0, 0, 2)]), Err(VmError::InvalidAction));
    }

    #[test]
    fn a_program_that_can_run_past_its_end_is_refused() {
        let ends_in_nop = [ins(Nop, 0, 0, 0)];
        let ends_in_conditional_jump = [ins(Ret, 0, 0, 1), ins(Jt, 0, 0, 0)];

        assert_eq!(decode(&ends_in_nop), Err(VmError::MissingReturn));
        assert_eq!(
            decode(&ends_in_conditional_jump),
            Err(VmError::MissingReturn)
        );
    }

    #[test]
    fn an_empty_program_is_refused() {
        assert_eq!(decode(&[]), Err(VmError::Empty));
    }

    #[test]
    fn bytes_that_are_not_whole_instructions_or_too_many_are_refused() {
        let ret = ins(Ret, 0, 0, 1);
        let mut partial = encode(&[ret]);
        partial.truncate(partial.len() - 1);
        let too_many = encode(&vec![ret; MAX_INSTR_COUNT + 1]);

        assert_eq!(Program::decode(&partial), Err(VmError::BadLength));
        assert_eq!(Program::decode(&too_many), Err(VmError::BadLength));
        assert!(Program::decode(&encode(&vec![ret; MAX_INSTR_COUNT])).is_ok());
    }

    #[test]
    fn an_instruction_survives_the_wire() {
        let instruction = ins(Ldhx, 3, 7, 0xDEAD_BEEF);

        assert_eq!(
            Instruction::from_bytes(&instruction.to_bytes()),
            instruction
        );
    }

    #[test]
    fn ret_returns_its_action() {
        assert_eq!(run(&[ins(Ret, 0, 0, 0)], &PACKET), Ok(VmAction::Drop));
        assert_eq!(run(&[ins(Ret, 0, 0, 1)], &PACKET), Ok(VmAction::Pass));
    }

    #[test]
    fn a_program_that_never_returns_times_out() {
        assert_eq!(run(&[ins(Jmp, 0, 0, 0)], &PACKET), Err(Timeout));
    }

    #[test]
    fn loads_read_big_endian_bytes_at_the_offset() {
        assert!(leaves_in_r0(&[ins(Ldb, 0, 0, 1)], 0x34));
        assert!(leaves_in_r0(&[ins(Ldh, 0, 0, 1)], 0x3456));
        assert!(leaves_in_r0(&[ins(Ldw, 0, 0, 1)], 0x3456_789A));
    }

    #[test]
    fn a_load_that_runs_past_the_packet_reads_zero() {
        for (width, offset) in [(Ldb, 8), (Ldh, 7), (Ldw, 5), (Ldb, u32::MAX)] {
            let program = [ins(Ldi, 0, 0, 0xFF), ins(width, 0, 0, offset)];

            assert!(leaves_in_r0(&program, 0), "{width:?} at {offset}");
        }
    }

    #[test]
    fn indexed_loads_add_the_index_register_to_the_offset() {
        let index = ins(Ldi, 2, 0, 3);

        assert!(leaves_in_r0(&[index, ins(Ldbx, 0, 2, 1)], 0x9A));
        assert!(leaves_in_r0(&[index, ins(Ldhx, 0, 2, 1)], 0x9ABC));
        assert!(leaves_in_r0(&[index, ins(Ldwx, 0, 2, 1)], 0x9ABC_DEF0));
    }

    #[test]
    fn an_indexed_load_whose_address_overflows_reads_zero() {
        let program = [
            ins(Ldi, 0, 0, 0xAA),
            ins(Ldi, 2, 0, u32::MAX),
            ins(Ldwx, 0, 2, u32::MAX),
        ];

        assert!(leaves_in_r0(&program, 0));
    }

    #[test]
    fn ldmsh_loads_four_times_the_low_nibble() {
        assert!(leaves_in_r0(&[ins(Ldmsh, 0, 0, 4)], 4 * 0x0A));
    }

    #[test]
    fn ldi_and_mov_copy_values_between_registers() {
        assert!(leaves_in_r0(&[ins(Ldi, 5, 0, 42), ins(Mov, 0, 5, 0)], 42));
    }

    #[test]
    fn and_and_or_combine_registers_bitwise() {
        let operands = [ins(Ldi, 0, 0, 0b1100), ins(Ldi, 1, 0, 0b1010)];

        assert!(leaves_in_r0(
            &[operands[0], operands[1], ins(And, 0, 1, 0)],
            0b1000
        ));
        assert!(leaves_in_r0(
            &[operands[0], operands[1], ins(Or, 0, 1, 0)],
            0b1110
        ));
    }

    #[test]
    fn eq_sets_the_flag_only_for_equal_values() {
        assert!(sets_flag(&[
            ins(Ldi, 0, 0, 5),
            ins(Ldi, 1, 0, 5),
            ins(Eq, 0, 1, 0)
        ]));
        assert!(!sets_flag(&[
            ins(Ldi, 0, 0, 5),
            ins(Ldi, 1, 0, 6),
            ins(Eq, 0, 1, 0)
        ]));
    }

    #[test]
    fn gt_sets_the_flag_only_when_strictly_greater() {
        assert!(sets_flag(&[
            ins(Ldi, 0, 0, 6),
            ins(Ldi, 1, 0, 5),
            ins(Gt, 0, 1, 0)
        ]));
        assert!(!sets_flag(&[
            ins(Ldi, 0, 0, 5),
            ins(Ldi, 1, 0, 5),
            ins(Gt, 0, 1, 0)
        ]));
    }

    #[test]
    fn conditional_jumps_fall_through_when_not_taken() {
        let flag_clear = ins(Eq, 0, 1, 0);
        let set_one = ins(Ldi, 1, 0, 1);

        assert_eq!(
            run(
                &[
                    set_one,
                    flag_clear,
                    ins(Jt, 0, 0, 4),
                    ins(Ret, 0, 0, 1),
                    ins(Ret, 0, 0, 0)
                ],
                &PACKET
            ),
            Ok(VmAction::Pass)
        );
        assert_eq!(
            run(
                &[
                    flag_clear,
                    ins(Jf, 0, 0, 3),
                    ins(Ret, 0, 0, 1),
                    ins(Ret, 0, 0, 0)
                ],
                &PACKET
            ),
            Ok(VmAction::Pass)
        );
    }

    #[test]
    fn nop_changes_nothing() {
        assert!(leaves_in_r0(&[ins(Ldi, 0, 0, 9), ins(Nop, 0, 0, 0)], 9));
    }
}
