//! Virtual machine for executing eBPF-like packet filters.
//!
//! Implements a simple register-based virtual machine that can execute
//! custom bytecode programs on each packet. Provides instructions for
//! loading packet data, performing comparisons, and making filtering
//! decisions.

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

/// Virtual machine instruction encoding.
///
/// Each instruction contains an opcode, two register operands,
/// and an immediate value. The packed representation ensures
/// efficient storage and loading.
#[derive(Copy, Clone)]
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

/// Virtual machine for executing packet filter programs.
///
/// Maintains 16 general-purpose registers, a program counter,
/// and a comparison flag. Executes instructions sequentially
/// with safety limits to prevent infinite loops.
pub struct VM {
    /// Array of 16 general-purpose 64-bit registers.
    regs: [u64; 16],
    /// Program counter (instruction index).
    pc: usize,
    /// Comparison flag set by comparison instructions.
    flag: bool,
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
    /// 0 if packet should be dropped, 1 if packet should pass,
    /// or other action codes as specified by Ret instructions
    #[inline(always)]
    pub fn execute(&mut self, program: &[Instruction], packet: &[u8]) -> u64 {
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
            let inst = unsafe { *program.get_unchecked(self.pc) };
            self.pc += 1;
            cycles += 1;

            match inst.op {
                0x01 => {
                    let offset = inst.imm as usize;
                    if offset < packet.len() {
                        self.regs[inst.reg_a as usize] = packet[offset] as u64;
                    } else {
                        self.regs[inst.reg_a as usize] = 0;
                    }
                }
                0x02 => {
                    let offset = inst.imm as usize;
                    if offset + 1 < packet.len() {
                        self.regs[inst.reg_a as usize] =
                            ((packet[offset] as u64) << 8) | (packet[offset + 1] as u64);
                    }
                }
                0x03 => {
                    let offset = inst.imm as usize;
                    if offset + 3 < packet.len() {
                        self.regs[inst.reg_a as usize] = ((packet[offset] as u64) << 24)
                            | ((packet[offset + 1] as u64) << 16)
                            | ((packet[offset + 2] as u64) << 8)
                            | (packet[offset + 3] as u64);
                    }
                }
                0x04 => {
                    self.regs[inst.reg_a as usize] = inst.imm as u64;
                }
                0x05 => {
                    self.regs[inst.reg_a as usize] = self.regs[inst.reg_b as usize];
                }
                0x06 => {
                    self.flag = self.regs[inst.reg_a as usize] == self.regs[inst.reg_b as usize];
                }
                0x07 => {
                    self.flag = self.regs[inst.reg_a as usize] > self.regs[inst.reg_b as usize];
                }
                0x08 => {
                    self.regs[inst.reg_a as usize] &= self.regs[inst.reg_b as usize];
                }
                0x09 => {
                    self.regs[inst.reg_a as usize] |= self.regs[inst.reg_b as usize];
                }
                0x0A => {
                    self.pc = inst.imm as usize;
                }
                0x0B => {
                    if self.flag {
                        self.pc = inst.imm as usize;
                    }
                }
                0x0C => {
                    if !self.flag {
                        self.pc = inst.imm as usize;
                    }
                }
                0x0D => {
                    return inst.imm as u64;
                }
                _ => {}
            }
        }
        1
    }
}
