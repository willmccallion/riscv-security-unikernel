#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
#[repr(u8)]
pub enum Opcode {
    /// Load byte from packet: [DestReg], [Offset]
    Ldb = 0x01,
    /// Load half-word (u16) from packet: [DestReg], [Offset]
    Ldh = 0x02,
    /// Load word (u32) from packet: [DestReg], [Offset]
    Ldw = 0x03,
    /// Load immediate: [DestReg], [Value (u32)]
    Ldi = 0x04,
    /// Store register to register: [DestReg], [SrcReg]
    Mov = 0x05,
    /// Compare equal: [RegA], [RegB]
    Eq = 0x06,
    /// Compare greater than: [RegA], [RegB]
    Gt = 0x07,
    /// Bitwise AND: [DestReg], [SrcReg]
    And = 0x08,
    /// Bitwise OR: [DestReg], [SrcReg]
    Or = 0x09,
    /// Jump absolute: [InstructionIndex]
    Jmp = 0x0A,
    /// Jump if true (Last Compare): [InstructionIndex]
    Jt = 0x0B,
    /// Jump if false (Last Compare): [InstructionIndex]
    Jf = 0x0C,
    /// Return: [Action] (0 = Drop, 1 = Pass)
    Ret = 0x0D,
    /// No operation
    Nop = 0x00,
}

#[derive(Copy, Clone)]
#[repr(C, packed)]
pub struct Instruction {
    pub op: u8,
    pub reg_a: u8,
    pub reg_b: u8,
    pub imm: u32,
}

impl Instruction {
    pub const fn new(op: u8, reg_a: u8, reg_b: u8, imm: u32) -> Self {
        Self {
            op,
            reg_a,
            reg_b,
            imm,
        }
    }
}

pub struct VM {
    regs: [u64; 16], // 16 General Purpose Registers
    pc: usize,       // Program Counter
    flag: bool,      // Comparison Flag
}

impl VM {
    pub const fn new() -> Self {
        Self {
            regs: [0; 16],
            pc: 0,
            flag: false,
        }
    }

    /// Executes the bytecode against the provided packet
    /// Returns: 0 (Drop), 1 (Pass), or other codes
    #[inline(always)]
    pub fn execute(&mut self, program: &[Instruction], packet: &[u8]) -> u64 {
        self.pc = 0;
        self.regs = [0; 16];
        self.flag = false;

        // Safety limit to prevent infinite loops
        let mut cycles = 0;
        const MAX_CYCLES: usize = 1000;

        while self.pc < program.len() && cycles < MAX_CYCLES {
            let inst = unsafe { *program.get_unchecked(self.pc) };
            self.pc += 1;
            cycles += 1;

            match inst.op {
                0x01 => {
                    // Ldb
                    let offset = inst.imm as usize;
                    if offset < packet.len() {
                        self.regs[inst.reg_a as usize] = packet[offset] as u64;
                    } else {
                        self.regs[inst.reg_a as usize] = 0;
                    }
                }
                0x02 => {
                    // Ldh (Big endian)
                    let offset = inst.imm as usize;
                    if offset + 1 < packet.len() {
                        self.regs[inst.reg_a as usize] =
                            ((packet[offset] as u64) << 8) | (packet[offset + 1] as u64);
                    }
                }
                0x03 => {
                    // Ldw (Big endian)
                    let offset = inst.imm as usize;
                    if offset + 3 < packet.len() {
                        self.regs[inst.reg_a as usize] = ((packet[offset] as u64) << 24)
                            | ((packet[offset + 1] as u64) << 16)
                            | ((packet[offset + 2] as u64) << 8)
                            | (packet[offset + 3] as u64);
                    }
                }
                0x04 => {
                    // Ldi
                    self.regs[inst.reg_a as usize] = inst.imm as u64;
                }
                0x05 => {
                    // Mov
                    self.regs[inst.reg_a as usize] = self.regs[inst.reg_b as usize];
                }
                0x06 => {
                    // Eq
                    self.flag = self.regs[inst.reg_a as usize] == self.regs[inst.reg_b as usize];
                }
                0x07 => {
                    // Gt
                    self.flag = self.regs[inst.reg_a as usize] > self.regs[inst.reg_b as usize];
                }
                0x08 => {
                    // And
                    self.regs[inst.reg_a as usize] &= self.regs[inst.reg_b as usize];
                }
                0x09 => {
                    // Or
                    self.regs[inst.reg_a as usize] |= self.regs[inst.reg_b as usize];
                }
                0x0A => {
                    // Jmp
                    self.pc = inst.imm as usize;
                }
                0x0B => {
                    // Jt
                    if self.flag {
                        self.pc = inst.imm as usize;
                    }
                }
                0x0C => {
                    // Jf
                    if !self.flag {
                        self.pc = inst.imm as usize;
                    }
                }
                0x0D => {
                    // Ret
                    return inst.imm as u64;
                }
                _ => {} // Nop
            }
        }
        1 // Default pass
    }
}
