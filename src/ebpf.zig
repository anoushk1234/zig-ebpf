const std = @import("std");

/// Reference: https://github.com/iovisor/bpf-docs/blob/master/md
/// Maximum number of instructions in an program.
pub const PROG_MAX_INSNS: usize = 1000000;
/// Size of an instructions, in bytes.
pub const INSN_SIZE: usize = 8;
/// Maximum size of an program, in bytes.
pub const PROG_MAX_SIZE: usize = PROG_MAX_INSNS * INSN_SIZE;
/// Stack for the stack, in bytes.
pub const STACK_SIZE: usize = 512;

// op codes.
// See also https://www.kernel.org/doc/Documentation/networking/filter.txt

// Three least significant bits are operation class:
/// BPF operation class: load from immediate.
pub const BPF_LD: u8 = 0x00;
/// BPF operation class: load from register.
pub const BPF_LDX: u8 = 0x01;
/// BPF operation class: store immediate.
pub const BPF_ST: u8 = 0x02;
/// BPF operation class: store value from register.
pub const BPF_STX: u8 = 0x03;
/// BPF operation class: 32 bits arithmetic operation.
pub const BPF_ALU: u8 = 0x04;
/// BPF operation class: jump (64-bit wide operands for comparisons).
pub const BPF_JMP: u8 = 0x05;
/// BPF operation class: jump (32-bit wide operands for comparisons).
pub const BPF_JMP32: u8 = 0x06;
// [ class 6 unused, reserved for future use ]
/// BPF operation class: 64 bits arithmetic operation.
pub const BPF_ALU64: u8 = 0x07;

// For load and store instructions:
// +------------+--------+------------+
// |   3 bits   | 2 bits |   3 bits   |
// |    mode    |  size  | insn class |
// +------------+--------+------------+
// (MSB)                          (LSB)

// Size modifiers:
/// BPF size modifier: word (4 bytes).
pub const BPF_W: u8 = 0x00;
/// BPF size modifier: half-word (2 bytes).
pub const BPF_H: u8 = 0x08;
/// BPF size modifier: byte (1 byte).
pub const BPF_B: u8 = 0x10;
/// BPF size modifier: double word (8 bytes).
pub const BPF_DW: u8 = 0x18;

// Mode modifiers:
/// BPF mode modifier: immediate value.
pub const BPF_IMM: u8 = 0x00;
/// BPF mode modifier: absolute load.
pub const BPF_ABS: u8 = 0x20;
/// BPF mode modifier: indirect load.
pub const BPF_IND: u8 = 0x40;
/// BPF mode modifier: load from / store to memory.
pub const BPF_MEM: u8 = 0x60;
// [ 0x80 reserved ]
// [ 0xa0 reserved ]
/// BPF mode modifier: exclusive add.
pub const BPF_XADD: u8 = 0xc0;

// For arithmetic (BPF_ALU/BPF_ALU64) and jump (BPF_JMP) instructions:
// +----------------+--------+--------+
// |     4 bits     |1 b.|   3 bits   |
// | operation code | src| insn class |
// +----------------+----+------------+
// (MSB)                          (LSB)

// Source modifiers:
/// BPF source operand modifier: 32-bit immediate value.
pub const BPF_K: u8 = 0x00;
/// BPF source operand modifier: `src` register.
pub const BPF_X: u8 = 0x08;

// Operation codes -- BPF_ALU or BPF_ALU64 classes:
/// BPF ALU/ALU64 operation code: addition.
pub const BPF_ADD: u8 = 0x00;
/// BPF ALU/ALU64 operation code: subtraction.
pub const BPF_SUB: u8 = 0x10;
/// BPF ALU/ALU64 operation code: multiplication.
pub const BPF_MUL: u8 = 0x20;
/// BPF ALU/ALU64 operation code: division.
pub const BPF_DIV: u8 = 0x30;
/// BPF ALU/ALU64 operation code: or.
pub const BPF_OR: u8 = 0x40;
/// BPF ALU/ALU64 operation code: and.
pub const BPF_AND: u8 = 0x50;
/// BPF ALU/ALU64 operation code: left shift.
pub const BPF_LSH: u8 = 0x60;
/// BPF ALU/ALU64 operation code: right shift.
pub const BPF_RSH: u8 = 0x70;
/// BPF ALU/ALU64 operation code: negation.
pub const BPF_NEG: u8 = 0x80;
/// BPF ALU/ALU64 operation code: modulus.
pub const BPF_MOD: u8 = 0x90;
/// BPF ALU/ALU64 operation code: exclusive or.
pub const BPF_XOR: u8 = 0xa0;
/// BPF ALU/ALU64 operation code: move.
pub const BPF_MOV: u8 = 0xb0;
/// BPF ALU/ALU64 operation code: sign extending right shift.
pub const BPF_ARSH: u8 = 0xc0;
/// BPF ALU/ALU64 operation code: endianness conversion.
pub const BPF_END: u8 = 0xd0;

// Operation codes -- BPF_JMP or BPF_JMP32 classes:
/// BPF JMP operation code: jump.
pub const BPF_JA: u8 = 0x00;
/// BPF JMP operation code: jump if equal.
pub const BPF_JEQ: u8 = 0x10;
/// BPF JMP operation code: jump if greater than.
pub const BPF_JGT: u8 = 0x20;
/// BPF JMP operation code: jump if greater or equal.
pub const BPF_JGE: u8 = 0x30;
/// BPF JMP operation code: jump if `src` & `reg`.
pub const BPF_JSET: u8 = 0x40;
/// BPF JMP operation code: jump if not equal.
pub const BPF_JNE: u8 = 0x50;
/// BPF JMP operation code: jump if greater than (signed).
pub const BPF_JSGT: u8 = 0x60;
/// BPF JMP operation code: jump if greater or equal (signed).
pub const BPF_JSGE: u8 = 0x70;
/// BPF JMP operation code: helper function call.
pub const BPF_CALL: u8 = 0x80;
/// BPF JMP operation code: return from program.
pub const BPF_EXIT: u8 = 0x90;
/// BPF JMP operation code: jump if lower than.
pub const BPF_JLT: u8 = 0xa0;
/// BPF JMP operation code: jump if lower or equal.
pub const BPF_JLE: u8 = 0xb0;
/// BPF JMP operation code: jump if lower than (signed).
pub const BPF_JSLT: u8 = 0xc0;
/// BPF JMP operation code: jump if lower or equal (signed).
pub const BPF_JSLE: u8 = 0xd0;

// Op codes
// (Following operation names are not “official”, but may be proper to rbpf; Linux kernel only
// combines above flags and does not attribute a name per operation.)

/// BPF opcode: `ldabsb src, dst, imm`.
pub const LD_ABS_B: u8 = BPF_LD | BPF_ABS | BPF_B;
/// BPF opcode: `ldabsh src, dst, imm`.
pub const LD_ABS_H: u8 = BPF_LD | BPF_ABS | BPF_H;
/// BPF opcode: `ldabsw src, dst, imm`.
pub const LD_ABS_W: u8 = BPF_LD | BPF_ABS | BPF_W;
/// BPF opcode: `ldabsdw src, dst, imm`.
pub const LD_ABS_DW: u8 = BPF_LD | BPF_ABS | BPF_DW;
/// BPF opcode: `ldindb src, dst, imm`.
pub const LD_IND_B: u8 = BPF_LD | BPF_IND | BPF_B;
/// BPF opcode: `ldindh src, dst, imm`.
pub const LD_IND_H: u8 = BPF_LD | BPF_IND | BPF_H;
/// BPF opcode: `ldindw src, dst, imm`.
pub const LD_IND_W: u8 = BPF_LD | BPF_IND | BPF_W;
/// BPF opcode: `ldinddw src, dst, imm`.
pub const LD_IND_DW: u8 = BPF_LD | BPF_IND | BPF_DW;

/// BPF opcode: `lddw dst, imm` /// `dst = imm`.
pub const LD_DW_IMM: u8 = BPF_LD | BPF_IMM | BPF_DW;
/// BPF opcode: `ldxb dst, [src + off]` /// `dst = (src + off) as u8`.
pub const LD_B_REG: u8 = BPF_LDX | BPF_MEM | BPF_B;
/// BPF opcode: `ldxh dst, [src + off]` /// `dst = (src + off) as u16`.
pub const LD_H_REG: u8 = BPF_LDX | BPF_MEM | BPF_H;
/// BPF opcode: `ldxw dst, [src + off]` /// `dst = (src + off) as u32`.
pub const LD_W_REG: u8 = BPF_LDX | BPF_MEM | BPF_W;
/// BPF opcode: `ldxdw dst, [src + off]` /// `dst = (src + off) as u64`.
pub const LD_DW_REG: u8 = BPF_LDX | BPF_MEM | BPF_DW;
/// BPF opcode: `stb [dst + off], imm` /// `(dst + offset) as u8 = imm`.
pub const ST_B_IMM: u8 = BPF_ST | BPF_MEM | BPF_B;
/// BPF opcode: `sth [dst + off], imm` /// `(dst + offset) as u16 = imm`.
pub const ST_H_IMM: u8 = BPF_ST | BPF_MEM | BPF_H;
/// BPF opcode: `stw [dst + off], imm` /// `(dst + offset) as u32 = imm`.
pub const ST_W_IMM: u8 = BPF_ST | BPF_MEM | BPF_W;
/// BPF opcode: `stdw [dst + off], imm` /// `(dst + offset) as u64 = imm`.
pub const ST_DW_IMM: u8 = BPF_ST | BPF_MEM | BPF_DW;
/// BPF opcode: `stxb [dst + off], src` /// `(dst + offset) as u8 = src`.
pub const ST_B_REG: u8 = BPF_STX | BPF_MEM | BPF_B;
/// BPF opcode: `stxh [dst + off], src` /// `(dst + offset) as u16 = src`.
pub const ST_H_REG: u8 = BPF_STX | BPF_MEM | BPF_H;
/// BPF opcode: `stxw [dst + off], src` /// `(dst + offset) as u32 = src`.
pub const ST_W_REG: u8 = BPF_STX | BPF_MEM | BPF_W;
/// BPF opcode: `stxdw [dst + off], src` /// `(dst + offset) as u64 = src`.
pub const ST_DW_REG: u8 = BPF_STX | BPF_MEM | BPF_DW;

/// BPF opcode: `stxxaddw [dst + off], src`.
pub const ST_W_XADD: u8 = BPF_STX | BPF_XADD | BPF_W;
/// BPF opcode: `stxxadddw [dst + off], src`.
pub const ST_DW_XADD: u8 = BPF_STX | BPF_XADD | BPF_DW;

/// BPF opcode: `add32 dst, imm` /// `dst += imm`.
pub const ADD32_IMM: u8 = BPF_ALU | BPF_K | BPF_ADD;
/// BPF opcode: `add32 dst, src` /// `dst += src`.
pub const ADD32_REG: u8 = BPF_ALU | BPF_X | BPF_ADD;
/// BPF opcode: `sub32 dst, imm` /// `dst -= imm`.
pub const SUB32_IMM: u8 = BPF_ALU | BPF_K | BPF_SUB;
/// BPF opcode: `sub32 dst, src` /// `dst -= src`.
pub const SUB32_REG: u8 = BPF_ALU | BPF_X | BPF_SUB;
/// BPF opcode: `mul32 dst, imm` /// `dst *= imm`.
pub const MUL32_IMM: u8 = BPF_ALU | BPF_K | BPF_MUL;
/// BPF opcode: `mul32 dst, src` /// `dst *= src`.
pub const MUL32_REG: u8 = BPF_ALU | BPF_X | BPF_MUL;
/// BPF opcode: `div32 dst, imm` /// `dst /= imm`.
pub const DIV32_IMM: u8 = BPF_ALU | BPF_K | BPF_DIV;
/// BPF opcode: `div32 dst, src` /// `dst /= src`.
pub const DIV32_REG: u8 = BPF_ALU | BPF_X | BPF_DIV;
/// BPF opcode: `or32 dst, imm` /// `dst |= imm`.
pub const OR32_IMM: u8 = BPF_ALU | BPF_K | BPF_OR;
/// BPF opcode: `or32 dst, src` /// `dst |= src`.
pub const OR32_REG: u8 = BPF_ALU | BPF_X | BPF_OR;
/// BPF opcode: `and32 dst, imm` /// `dst &= imm`.
pub const AND32_IMM: u8 = BPF_ALU | BPF_K | BPF_AND;
/// BPF opcode: `and32 dst, src` /// `dst &= src`.
pub const AND32_REG: u8 = BPF_ALU | BPF_X | BPF_AND;
/// BPF opcode: `lsh32 dst, imm` /// `dst <<= imm`.
pub const LSH32_IMM: u8 = BPF_ALU | BPF_K | BPF_LSH;
/// BPF opcode: `lsh32 dst, src` /// `dst <<= src`.
pub const LSH32_REG: u8 = BPF_ALU | BPF_X | BPF_LSH;
/// BPF opcode: `rsh32 dst, imm` /// `dst >>= imm`.
pub const RSH32_IMM: u8 = BPF_ALU | BPF_K | BPF_RSH;
/// BPF opcode: `rsh32 dst, src` /// `dst >>= src`.
pub const RSH32_REG: u8 = BPF_ALU | BPF_X | BPF_RSH;
/// BPF opcode: `neg32 dst` /// `dst = -dst`.
pub const NEG32: u8 = BPF_ALU | BPF_NEG;
/// BPF opcode: `mod32 dst, imm` /// `dst %= imm`.
pub const MOD32_IMM: u8 = BPF_ALU | BPF_K | BPF_MOD;
/// BPF opcode: `mod32 dst, src` /// `dst %= src`.
pub const MOD32_REG: u8 = BPF_ALU | BPF_X | BPF_MOD;
/// BPF opcode: `xor32 dst, imm` /// `dst ^= imm`.
pub const XOR32_IMM: u8 = BPF_ALU | BPF_K | BPF_XOR;
/// BPF opcode: `xor32 dst, src` /// `dst ^= src`.
pub const XOR32_REG: u8 = BPF_ALU | BPF_X | BPF_XOR;
/// BPF opcode: `mov32 dst, imm` /// `dst = imm`.
pub const MOV32_IMM: u8 = BPF_ALU | BPF_K | BPF_MOV;
/// BPF opcode: `mov32 dst, src` /// `dst = src`.
pub const MOV32_REG: u8 = BPF_ALU | BPF_X | BPF_MOV;
/// BPF opcode: `arsh32 dst, imm` /// `dst >>= imm (arithmetic)`.
///
/// <https://en.wikipedia.org/wiki/Arithmetic_shift>
pub const ARSH32_IMM: u8 = BPF_ALU | BPF_K | BPF_ARSH;
/// BPF opcode: `arsh32 dst, src` /// `dst >>= src (arithmetic)`.
///
/// <https://en.wikipedia.org/wiki/Arithmetic_shift>
pub const ARSH32_REG: u8 = BPF_ALU | BPF_X | BPF_ARSH;

/// BPF opcode: `le dst` /// `dst = htole<imm>(dst), with imm in {16, 32, 64}`.
pub const LE: u8 = BPF_ALU | BPF_K | BPF_END;
/// BPF opcode: `be dst` /// `dst = htobe<imm>(dst), with imm in {16, 32, 64}`.
pub const BE: u8 = BPF_ALU | BPF_X | BPF_END;

/// BPF opcode: `add64 dst, imm` /// `dst += imm`.
pub const ADD64_IMM: u8 = BPF_ALU64 | BPF_K | BPF_ADD;
/// BPF opcode: `add64 dst, src` /// `dst += src`.
pub const ADD64_REG: u8 = BPF_ALU64 | BPF_X | BPF_ADD;
/// BPF opcode: `sub64 dst, imm` /// `dst -= imm`.
pub const SUB64_IMM: u8 = BPF_ALU64 | BPF_K | BPF_SUB;
/// BPF opcode: `sub64 dst, src` /// `dst -= src`.
pub const SUB64_REG: u8 = BPF_ALU64 | BPF_X | BPF_SUB;
/// BPF opcode: `div64 dst, imm` /// `dst /= imm`.
pub const MUL64_IMM: u8 = BPF_ALU64 | BPF_K | BPF_MUL;
/// BPF opcode: `div64 dst, src` /// `dst /= src`.
pub const MUL64_REG: u8 = BPF_ALU64 | BPF_X | BPF_MUL;
/// BPF opcode: `div64 dst, imm` /// `dst /= imm`.
pub const DIV64_IMM: u8 = BPF_ALU64 | BPF_K | BPF_DIV;
/// BPF opcode: `div64 dst, src` /// `dst /= src`.
pub const DIV64_REG: u8 = BPF_ALU64 | BPF_X | BPF_DIV;
/// BPF opcode: `or64 dst, imm` /// `dst |= imm`.
pub const OR64_IMM: u8 = BPF_ALU64 | BPF_K | BPF_OR;
/// BPF opcode: `or64 dst, src` /// `dst |= src`.
pub const OR64_REG: u8 = BPF_ALU64 | BPF_X | BPF_OR;
/// BPF opcode: `and64 dst, imm` /// `dst &= imm`.
pub const AND64_IMM: u8 = BPF_ALU64 | BPF_K | BPF_AND;
/// BPF opcode: `and64 dst, src` /// `dst &= src`.
pub const AND64_REG: u8 = BPF_ALU64 | BPF_X | BPF_AND;
/// BPF opcode: `lsh64 dst, imm` /// `dst <<= imm`.
pub const LSH64_IMM: u8 = BPF_ALU64 | BPF_K | BPF_LSH;
/// BPF opcode: `lsh64 dst, src` /// `dst <<= src`.
pub const LSH64_REG: u8 = BPF_ALU64 | BPF_X | BPF_LSH;
/// BPF opcode: `rsh64 dst, imm` /// `dst >>= imm`.
pub const RSH64_IMM: u8 = BPF_ALU64 | BPF_K | BPF_RSH;
/// BPF opcode: `rsh64 dst, src` /// `dst >>= src`.
pub const RSH64_REG: u8 = BPF_ALU64 | BPF_X | BPF_RSH;
/// BPF opcode: `neg64 dst, imm` /// `dst = -dst`.
pub const NEG64: u8 = BPF_ALU64 | BPF_NEG;
/// BPF opcode: `mod64 dst, imm` /// `dst %= imm`.
pub const MOD64_IMM: u8 = BPF_ALU64 | BPF_K | BPF_MOD;
/// BPF opcode: `mod64 dst, src` /// `dst %= src`.
pub const MOD64_REG: u8 = BPF_ALU64 | BPF_X | BPF_MOD;
/// BPF opcode: `xor64 dst, imm` /// `dst ^= imm`.
pub const XOR64_IMM: u8 = BPF_ALU64 | BPF_K | BPF_XOR;
/// BPF opcode: `xor64 dst, src` /// `dst ^= src`.
pub const XOR64_REG: u8 = BPF_ALU64 | BPF_X | BPF_XOR;
/// BPF opcode: `mov64 dst, imm` /// `dst = imm`.
pub const MOV64_IMM: u8 = BPF_ALU64 | BPF_K | BPF_MOV;
/// BPF opcode: `mov64 dst, src` /// `dst = src`.
pub const MOV64_REG: u8 = BPF_ALU64 | BPF_X | BPF_MOV;
/// BPF opcode: `arsh64 dst, imm` /// `dst >>= imm (arithmetic)`.
///
/// <https://en.wikipedia.org/wiki/Arithmetic_shift>
pub const ARSH64_IMM: u8 = BPF_ALU64 | BPF_K | BPF_ARSH;
/// BPF opcode: `arsh64 dst, src` /// `dst >>= src (arithmetic)`.
///
/// <https://en.wikipedia.org/wiki/Arithmetic_shift>
pub const ARSH64_REG: u8 = BPF_ALU64 | BPF_X | BPF_ARSH;

/// BPF opcode: `ja +off` /// `PC += off`.
pub const JA: u8 = BPF_JMP | BPF_JA;
/// BPF opcode: `jeq dst, imm, +off` /// `PC += off if dst == imm`.
pub const JEQ_IMM: u8 = BPF_JMP | BPF_K | BPF_JEQ;
/// BPF opcode: `jeq dst, src, +off` /// `PC += off if dst == src`.
pub const JEQ_REG: u8 = BPF_JMP | BPF_X | BPF_JEQ;
/// BPF opcode: `jgt dst, imm, +off` /// `PC += off if dst > imm`.
pub const JGT_IMM: u8 = BPF_JMP | BPF_K | BPF_JGT;
/// BPF opcode: `jgt dst, src, +off` /// `PC += off if dst > src`.
pub const JGT_REG: u8 = BPF_JMP | BPF_X | BPF_JGT;
/// BPF opcode: `jge dst, imm, +off` /// `PC += off if dst >= imm`.
pub const JGE_IMM: u8 = BPF_JMP | BPF_K | BPF_JGE;
/// BPF opcode: `jge dst, src, +off` /// `PC += off if dst >= src`.
pub const JGE_REG: u8 = BPF_JMP | BPF_X | BPF_JGE;
/// BPF opcode: `jlt dst, imm, +off` /// `PC += off if dst < imm`.
pub const JLT_IMM: u8 = BPF_JMP | BPF_K | BPF_JLT;
/// BPF opcode: `jlt dst, src, +off` /// `PC += off if dst < src`.
pub const JLT_REG: u8 = BPF_JMP | BPF_X | BPF_JLT;
/// BPF opcode: `jle dst, imm, +off` /// `PC += off if dst <= imm`.
pub const JLE_IMM: u8 = BPF_JMP | BPF_K | BPF_JLE;
/// BPF opcode: `jle dst, src, +off` /// `PC += off if dst <= src`.
pub const JLE_REG: u8 = BPF_JMP | BPF_X | BPF_JLE;
/// BPF opcode: `jset dst, imm, +off` /// `PC += off if dst & imm`.
pub const JSET_IMM: u8 = BPF_JMP | BPF_K | BPF_JSET;
/// BPF opcode: `jset dst, src, +off` /// `PC += off if dst & src`.
pub const JSET_REG: u8 = BPF_JMP | BPF_X | BPF_JSET;
/// BPF opcode: `jne dst, imm, +off` /// `PC += off if dst != imm`.
pub const JNE_IMM: u8 = BPF_JMP | BPF_K | BPF_JNE;
/// BPF opcode: `jne dst, src, +off` /// `PC += off if dst != src`.
pub const JNE_REG: u8 = BPF_JMP | BPF_X | BPF_JNE;
/// BPF opcode: `jsgt dst, imm, +off` /// `PC += off if dst > imm (signed)`.
pub const JSGT_IMM: u8 = BPF_JMP | BPF_K | BPF_JSGT;
/// BPF opcode: `jsgt dst, src, +off` /// `PC += off if dst > src (signed)`.
pub const JSGT_REG: u8 = BPF_JMP | BPF_X | BPF_JSGT;
/// BPF opcode: `jsge dst, imm, +off` /// `PC += off if dst >= imm (signed)`.
pub const JSGE_IMM: u8 = BPF_JMP | BPF_K | BPF_JSGE;
/// BPF opcode: `jsge dst, src, +off` /// `PC += off if dst >= src (signed)`.
pub const JSGE_REG: u8 = BPF_JMP | BPF_X | BPF_JSGE;
/// BPF opcode: `jslt dst, imm, +off` /// `PC += off if dst < imm (signed)`.
pub const JSLT_IMM: u8 = BPF_JMP | BPF_K | BPF_JSLT;
/// BPF opcode: `jslt dst, src, +off` /// `PC += off if dst < src (signed)`.
pub const JSLT_REG: u8 = BPF_JMP | BPF_X | BPF_JSLT;
/// BPF opcode: `jsle dst, imm, +off` /// `PC += off if dst <= imm (signed)`.
pub const JSLE_IMM: u8 = BPF_JMP | BPF_K | BPF_JSLE;
/// BPF opcode: `jsle dst, src, +off` /// `PC += off if dst <= src (signed)`.
pub const JSLE_REG: u8 = BPF_JMP | BPF_X | BPF_JSLE;

/// BPF opcode: `jeq dst, imm, +off` /// `PC += off if (dst as u32) == imm`.
pub const JEQ_IMM32: u8 = BPF_JMP32 | BPF_K | BPF_JEQ;
/// BPF opcode: `jeq dst, src, +off` /// `PC += off if (dst as u32) == (src as u32)`.
pub const JEQ_REG32: u8 = BPF_JMP32 | BPF_X | BPF_JEQ;
/// BPF opcode: `jgt dst, imm, +off` /// `PC += off if (dst as u32) > imm`.
pub const JGT_IMM32: u8 = BPF_JMP32 | BPF_K | BPF_JGT;
/// BPF opcode: `jgt dst, src, +off` /// `PC += off if (dst as u32) > (src as u32)`.
pub const JGT_REG32: u8 = BPF_JMP32 | BPF_X | BPF_JGT;
/// BPF opcode: `jge dst, imm, +off` /// `PC += off if (dst as u32) >= imm`.
pub const JGE_IMM32: u8 = BPF_JMP32 | BPF_K | BPF_JGE;
/// BPF opcode: `jge dst, src, +off` /// `PC += off if (dst as u32) >= (src as u32)`.
pub const JGE_REG32: u8 = BPF_JMP32 | BPF_X | BPF_JGE;
/// BPF opcode: `jlt dst, imm, +off` /// `PC += off if (dst as u32) < imm`.
pub const JLT_IMM32: u8 = BPF_JMP32 | BPF_K | BPF_JLT;
/// BPF opcode: `jlt dst, src, +off` /// `PC += off if (dst as u32) < (src as u32)`.
pub const JLT_REG32: u8 = BPF_JMP32 | BPF_X | BPF_JLT;
/// BPF opcode: `jle dst, imm, +off` /// `PC += off if (dst as u32) <= imm`.
pub const JLE_IMM32: u8 = BPF_JMP32 | BPF_K | BPF_JLE;
/// BPF opcode: `jle dst, src, +off` /// `PC += off if (dst as u32) <= (src as u32)`.
pub const JLE_REG32: u8 = BPF_JMP32 | BPF_X | BPF_JLE;
/// BPF opcode: `jset dst, imm, +off` /// `PC += off if (dst as u32) & imm`.
pub const JSET_IMM32: u8 = BPF_JMP32 | BPF_K | BPF_JSET;
/// BPF opcode: `jset dst, src, +off` /// `PC += off if (dst as u32) & (src as u32)`.
pub const JSET_REG32: u8 = BPF_JMP32 | BPF_X | BPF_JSET;
/// BPF opcode: `jne dst, imm, +off` /// `PC += off if (dst as u32) != imm`.
pub const JNE_IMM32: u8 = BPF_JMP32 | BPF_K | BPF_JNE;
/// BPF opcode: `jne dst, src, +off` /// `PC += off if (dst as u32) != (src as u32)`.
pub const JNE_REG32: u8 = BPF_JMP32 | BPF_X | BPF_JNE;
/// BPF opcode: `jsgt dst, imm, +off` /// `PC += off if (dst as i32) > imm (signed)`.
pub const JSGT_IMM32: u8 = BPF_JMP32 | BPF_K | BPF_JSGT;
/// BPF opcode: `jsgt dst, src, +off` /// `PC += off if (dst as i32) > (src as i32) (signed)`.
pub const JSGT_REG32: u8 = BPF_JMP32 | BPF_X | BPF_JSGT;
/// BPF opcode: `jsge dst, imm, +off` /// `PC += off if (dst as i32) >= imm (signed)`.
pub const JSGE_IMM32: u8 = BPF_JMP32 | BPF_K | BPF_JSGE;
/// BPF opcode: `jsge dst, src, +off` /// `PC += off if (dst as i32) >= (src as i32) (signed)`.
pub const JSGE_REG32: u8 = BPF_JMP32 | BPF_X | BPF_JSGE;
/// BPF opcode: `jslt dst, imm, +off` /// `PC += off if (dst as i32) < imm (signed)`.
pub const JSLT_IMM32: u8 = BPF_JMP32 | BPF_K | BPF_JSLT;
/// BPF opcode: `jslt dst, src, +off` /// `PC += off if (dst as i32) < (src as i32) (signed)`.
pub const JSLT_REG32: u8 = BPF_JMP32 | BPF_X | BPF_JSLT;
/// BPF opcode: `jsle dst, imm, +off` /// `PC += off if (dst as i32) <= imm (signed)`.
pub const JSLE_IMM32: u8 = BPF_JMP32 | BPF_K | BPF_JSLE;
/// BPF opcode: `jsle dst, src, +off` /// `PC += off if (dst as i32) <= (src as i32) (signed)`.
pub const JSLE_REG32: u8 = BPF_JMP32 | BPF_X | BPF_JSLE;

/// BPF opcode: `call imm` /// helper function call to helper with key `imm`.
pub const CALL: u8 = BPF_JMP | BPF_CALL;
/// BPF opcode: tail call.
pub const TAIL_CALL: u8 = BPF_JMP | BPF_X | BPF_CALL;
/// BPF opcode: `exit` /// `return r0`.
pub const EXIT: u8 = BPF_JMP | BPF_EXIT;

// Used in JIT
/// Mask to extract the operation class from an operation code.
pub const BPF_CLS_MASK: u8 = 0x07;
/// Mask to extract the arithmetic operation code from an instruction operation code.
pub const BPF_ALU_OP_MASK: u8 = 0xf0;

pub const Syscall = *const fn (a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) u64;

pub const Instruction = packed struct {
    op: u8,
    dst: u8,
    src: u8,
    offset: i16,
    // imm stores the data that needs to be stored in reg for ex.
    imm: i32,
    pub fn get_ix(program: []const u8, pc: usize) !Instruction {
        if ((pc + 1) * INSN_SIZE > program.len) {
            return InstructionError.InvalidInstructionSize;
        }
        return Instruction{
            .op = program[INSN_SIZE * pc],
            .dst = program[INSN_SIZE * pc + 1] & 0x0F,
            .src = (program[INSN_SIZE * pc + 1] & 0xF0) >> 4,
            .offset = std.mem.nativeToLittle(i16, std.mem.bytesToValue(i16, program[(INSN_SIZE * pc + 2)..])),
            .imm = std.mem.nativeToLittle(i32, std.mem.bytesToValue(i32, program[(INSN_SIZE * pc + 4)..])),
        };
    }

    pub fn to_array(self: *const Instruction) [INSN_SIZE]u8 {
        return [_]u8{
            self.op,
            @as(u8, self.src) << 4 | self.dst,
            @intCast(self.offset & 0xFF),
            @intCast((self.offset >> 8) & 0xFF),
            @intCast(self.imm & 0xFF),
            @intCast((self.imm >> 8) & 0xFF),
            @intCast((self.imm >> 16) & 0xFF),
            @intCast((self.imm >> 24) & 0xFF),
        };
    }
};

pub const InstructionError = error{
    InvalidInstructionSize,
};
