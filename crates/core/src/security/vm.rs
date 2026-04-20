// Virtual machine for executing eBPF-like packet filters.
//
// Implements a simple register-based virtual machine that can execute
// custom bytecode programs on each packet. Provides instructions for
// loading packet data, performing comparisons, and making filtering
// decisions.

/// Opcodes for the virtual machine instruction set.
#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
#[repr(u8)]
pub enum Opcode {
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
    /// No operation.
    Nop = 0x00,
}

impl Opcode {
    /// Returns the opcode for a raw byte, or `None` if the byte is
    /// not a recognised instruction. Used by [`validate`] to reject
    /// programs containing unknown opcodes at upload time so behaviour
    /// is locked to the variants the VM explicitly handles.
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0x00 => Some(Self::Nop),
            0x01 => Some(Self::Ldb),
            0x02 => Some(Self::Ldh),
            0x03 => Some(Self::Ldw),
            0x04 => Some(Self::Ldi),
            0x05 => Some(Self::Mov),
            0x06 => Some(Self::Eq),
            0x07 => Some(Self::Gt),
            0x08 => Some(Self::And),
            0x09 => Some(Self::Or),
            0x0A => Some(Self::Jmp),
            0x0B => Some(Self::Jt),
            0x0C => Some(Self::Jf),
            0x0D => Some(Self::Ret),
            _ => None,
        }
    }
}

/// Reasons a BPF program may be rejected at upload time.
///
/// Returned by [`validate`] when a program contains instructions that would
/// behave unsafely or unpredictably at execution time. Programs that fail
/// validation must never reach [`VM::execute`] — if one does, the masking
/// applied inside `execute` keeps the kernel from panicking, but the
/// behaviour the program describes is undefined and the rejection signals
/// that an attacker is probing the upload path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmError {
    /// `reg_a` or `reg_b` is outside the 16-register file.
    InvalidRegister,
    /// A jump opcode targets an instruction index `>= program.len()`.
    InvalidJumpTarget,
    /// The instruction's opcode byte is not one of the variants the VM
    /// recognises. Without this check, unknown opcodes hit the
    /// catch-all `_ => {}` arm in `execute` and become silent no-ops,
    /// which (a) gives an attacker a fuzz-the-opcodes oracle without
    /// rejection and (b) means a future opcode added at one of the
    /// currently-unused values would silently change the behaviour of
    /// programs uploaded before the addition.
    InvalidOpcode,
}

/// Validates a program before it can be installed.
///
/// The VM has 16 registers but instructions encode register indices as
/// `u8`, so an attacker-supplied program can ask for register 200. Likewise
/// jump targets are `u32` immediates with no inherent bound. Reject both
/// at upload time so a malicious management packet cannot install a
/// program that would otherwise force the executing core into masked
/// fallback behaviour on every packet.
pub fn validate(program: &[Instruction]) -> Result<(), VmError> {
    let len = program.len() as u32;
    for inst in program {
        if Opcode::from_u8(inst.op).is_none() {
            return Err(VmError::InvalidOpcode);
        }
        if inst.reg_a >= 16 || inst.reg_b >= 16 {
            return Err(VmError::InvalidRegister);
        }
        if let 0x0A..=0x0C = inst.op
            && inst.imm >= len
        {
            return Err(VmError::InvalidJumpTarget);
        }
    }
    Ok(())
}

/// Virtual machine instruction encoding.
///
/// Each instruction contains an opcode, two register operands,
/// and an immediate value. The packed representation ensures
/// efficient storage and loading.
#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct Instruction {
    /// Instruction opcode.
    pub op: u8,
    /// First register operand (destination for most instructions).
    pub reg_a: u8,
    /// Second register operand (source for most instructions).
    pub reg_b: u8,
    /// Immediate value (offset, constant, or jump target).
    pub imm: u32,
}

impl Instruction {
    /// Creates a new instruction with the specified fields.
    ///
    /// # Arguments
    ///
    /// * `op` - Opcode value
    /// * `reg_a` - First register index
    /// * `reg_b` - Second register index
    /// * `imm` - Immediate value
    pub const fn new(op: u8, reg_a: u8, reg_b: u8, imm: u32) -> Self {
        Self {
            op,
            reg_a,
            reg_b,
            imm,
        }
    }
}

/// What a program wants the caller to do with the current packet.
///
/// Exists so the caller is not matching on a raw integer. The old
/// contract was "u64; 0 means drop, anything else means pass" — which
/// meant (a) `Ret imm=0xDEADBEEF` was silently treated as pass, and
/// (b) the caller had no way to distinguish "program said pass" from
/// "program forgot to Ret and fell off the end". A two-variant enum
/// makes both cases explicit, and anything outside those variants is
/// a [`VmRuntimeError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmAction {
    /// Drop the packet and raise the eBPF alert.
    Drop,
    /// Allow the packet to continue through the pipeline.
    Pass,
}

/// Runtime failures raised by [`VM::execute`].
///
/// Distinct from [`VmError`], which covers upload-time validation.
/// Returning a dedicated error type (rather than a sentinel `u64`)
/// forces every caller to handle each failure mode explicitly, so an
/// attacker who installs a one-instruction infinite loop (`Jmp 0`) or
/// returns a garbage action code cannot rely on a forgotten branch
/// silently degrading to "pass".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmRuntimeError {
    /// The program burned through `MAX_CYCLES` without reaching a
    /// `Ret`. The packet must be dropped and an alert raised.
    Timeout,
    /// The program executed a `Ret` with an immediate that did not
    /// match any defined [`VmAction`]. Callers must drop-and-alert
    /// rather than assuming pass; the doc-comment on `execute` used to
    /// imply a richer protocol (the `imm` could carry a custom action
    /// code), and any future extension that reads those codes would
    /// silently mis-interpret programs uploaded before the extension
    /// if this case were treated as pass today.
    InvalidAction(u64),
}

/// Virtual machine for executing packet filter programs.
///
/// Maintains 16 general-purpose registers, a program counter,
/// and a comparison flag. Executes instructions sequentially
/// with safety limits to prevent infinite loops.
#[derive(Debug)]
pub struct VM {
    /// Array of 16 general-purpose 64-bit registers.
    regs: [u64; 16],
    /// Program counter (instruction index).
    pc: usize,
    /// Comparison flag set by comparison instructions.
    flag: bool,
}

impl Default for VM {
    fn default() -> Self {
        Self::new()
    }
}

impl VM {
    /// Creates a new virtual machine with all state zeroed.
    pub const fn new() -> Self {
        Self {
            regs: [0; 16],
            pc: 0,
            flag: false,
        }
    }

    /// Executes a program against a packet.
    ///
    /// Runs the instruction sequence until a Ret instruction is encountered
    /// or the maximum cycle limit is reached. Resets all state before execution.
    ///
    /// # Arguments
    ///
    /// * `program` - Slice of instructions to execute
    /// * `packet` - Packet data to process
    ///
    /// # Returns
    ///
    /// `Ok(VmAction::Drop | Pass)` for the two valid outcomes of a
    /// `Ret` instruction (immediate 0 or 1), or `Ok(VmAction::Pass)` if
    /// the program fell off the end without returning (preserves the
    /// historical default for well-formed but Ret-less programs).
    /// `Err(VmRuntimeError::Timeout)` if the program burns through
    /// `MAX_CYCLES`; `Err(VmRuntimeError::InvalidAction(n))` if a `Ret`
    /// carried any other immediate. Callers must treat both errors as
    /// drop + alert.
    #[inline(always)]
    pub fn execute(
        &mut self,
        program: &[Instruction],
        packet: &[u8],
    ) -> Result<VmAction, VmRuntimeError> {
        self.pc = 0;
        self.regs = [0; 16];
        self.flag = false;

        let mut cycles = 0;
        /// Maximum number of instruction cycles before execution is terminated.
        ///
        /// This safety limit prevents infinite loops in malicious or buggy
        /// programs. Programs exceeding this limit will default to passing
        /// the packet, ensuring the kernel remains responsive.
        const MAX_CYCLES: usize = 1000;

        while self.pc < program.len() && cycles < MAX_CYCLES {
            // SAFETY: The while condition `self.pc < program.len()` guarantees
            // the index is in-bounds. get_unchecked avoids a redundant bounds
            // check on every instruction fetch in the hot execution loop.
            let inst = unsafe { *program.get_unchecked(self.pc) };
            self.pc += 1;
            cycles += 1;

            match inst.op {
                0x01 => {
                    let offset = inst.imm as usize;
                    if offset < packet.len() {
                        self.regs[(inst.reg_a as usize) & 0x0F] = packet[offset] as u64;
                    } else {
                        self.regs[(inst.reg_a as usize) & 0x0F] = 0;
                    }
                }
                0x02 => {
                    let offset = inst.imm as usize;
                    if offset + 1 < packet.len() {
                        self.regs[(inst.reg_a as usize) & 0x0F] =
                            ((packet[offset] as u64) << 8) | (packet[offset + 1] as u64);
                    }
                }
                0x03 => {
                    let offset = inst.imm as usize;
                    if offset + 3 < packet.len() {
                        self.regs[(inst.reg_a as usize) & 0x0F] = ((packet[offset] as u64) << 24)
                            | ((packet[offset + 1] as u64) << 16)
                            | ((packet[offset + 2] as u64) << 8)
                            | (packet[offset + 3] as u64);
                    }
                }
                0x04 => {
                    self.regs[(inst.reg_a as usize) & 0x0F] = inst.imm as u64;
                }
                0x05 => {
                    self.regs[(inst.reg_a as usize) & 0x0F] = self.regs[(inst.reg_b as usize) & 0x0F];
                }
                0x06 => {
                    self.flag = self.regs[(inst.reg_a as usize) & 0x0F] == self.regs[(inst.reg_b as usize) & 0x0F];
                }
                0x07 => {
                    self.flag = self.regs[(inst.reg_a as usize) & 0x0F] > self.regs[(inst.reg_b as usize) & 0x0F];
                }
                0x08 => {
                    self.regs[(inst.reg_a as usize) & 0x0F] &= self.regs[(inst.reg_b as usize) & 0x0F];
                }
                0x09 => {
                    self.regs[(inst.reg_a as usize) & 0x0F] |= self.regs[(inst.reg_b as usize) & 0x0F];
                }
                0x0A => {
                    self.pc = inst.imm as usize;
                }
                0x0B if self.flag => {
                    self.pc = inst.imm as usize;
                }
                0x0C if !self.flag => {
                    self.pc = inst.imm as usize;
                }
                0x0D => {
                    return match inst.imm as u64 {
                        0 => Ok(VmAction::Drop),
                        1 => Ok(VmAction::Pass),
                        n => Err(VmRuntimeError::InvalidAction(n)),
                    };
                }
                _ => {}
            }
        }
        // Distinguish "program fell off the end without a Ret" (historically
        // treated as pass) from "cycles exhausted" — the latter is the
        // infinite-loop primitive an attacker wants, and must alert.
        if cycles >= MAX_CYCLES {
            Err(VmRuntimeError::Timeout)
        } else {
            Ok(VmAction::Pass)
        }
    }
}
