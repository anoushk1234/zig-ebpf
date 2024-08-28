const std = @import("std");
const ebpf = @import("ebpf.zig");

// Define possible errors that can occur during disassembly
pub const DisassemblerError = error{
    InvalidProgram,
    UnknownOpcode,
    InvalidByteswapSize,
    OutOfMemory,
    InvalidInstructionSize,
};

// Struct to represent a high-level eBPF instruction
pub const HLInsn = struct {
    opcode: u8,
    name: []const u8,
    description: []const u8,
    dst: u8,
    src: u8,
    off: i16,
    imm: i64,
};

// Helper functions to format instruction strings

fn ldabs_str(allocator: std.mem.Allocator, name: []const u8, insn: ebpf.Instruction) ![]const u8 {
    return try std.fmt.allocPrint(allocator, "{s} 0x{x}", .{ name, @as(u32, @bitCast(insn.imm)) });
}

fn ldind_str(allocator: std.mem.Allocator, name: []const u8, insn: ebpf.Instruction) ![]const u8 {
    return try std.fmt.allocPrint(allocator, "{s} r{d}, 0x{x}", .{ name, insn.dst, @as(u32, @bitCast(insn.imm)) });
}

fn ld_reg_str(allocator: std.mem.Allocator, name: []const u8, insn: ebpf.Instruction) ![]const u8 {
    return try std.fmt.allocPrint(allocator, "{s} r{d}, [r{d}+0x{x}]", .{
        name,
        insn.dst,
        insn.src,
        @as(u16, @bitCast(insn.offset)),
    });
}

fn ld_st_imm_str(allocator: std.mem.Allocator, name: []const u8, insn: ebpf.Instruction) ![]const u8 {
    return try std.fmt.allocPrint(allocator, "{s} [r{d}+0x{x}], 0x{x}", .{
        name,
        insn.dst,
        @as(u16, @bitCast(insn.offset)),
        @as(u32, @bitCast(insn.imm)),
    });
}

fn st_reg_str(allocator: std.mem.Allocator, name: []const u8, insn: ebpf.Instruction) ![]const u8 {
    return try std.fmt.allocPrint(allocator, "{s} [r{d}+0x{x}], r{d}", .{
        name,
        insn.dst,
        @as(u16, @bitCast(insn.offset)),
        insn.src,
    });
}

fn alu_imm_str(allocator: std.mem.Allocator, name: []const u8, insn: ebpf.Instruction) ![]const u8 {
    const imm = @as(u32, @bitCast(insn.imm));
    return try std.fmt.allocPrint(allocator, "{s} r{d}, 0x{x}", .{ name, insn.dst, imm });
}

fn alu_reg_str(allocator: std.mem.Allocator, name: []const u8, insn: ebpf.Instruction) ![]const u8 {
    return try std.fmt.allocPrint(allocator, "{s} r{d}, r{d}", .{ name, insn.dst, insn.src });
}

fn byteswap_str(allocator: std.mem.Allocator, name: []const u8, insn: ebpf.Instruction) ![]const u8 {
    const size: u32 = switch (insn.imm) {
        16 => 16,
        32 => 32,
        64 => 64,
        else => return DisassemblerError.InvalidByteswapSize,
    };
    return try std.fmt.allocPrint(allocator, "{s}{d} r{d}", .{ name, size, insn.dst });
}

fn jmp_imm_str(allocator: std.mem.Allocator, name: []const u8, insn: ebpf.Instruction) ![]const u8 {
    return try std.fmt.allocPrint(allocator, "{s} r{d}, 0x{x}, {s}0x{x}", .{
        name,
        insn.dst,
        @as(u32, @bitCast(insn.imm)),
        if (insn.offset >= 0) "+" else "-",
        @abs(insn.offset),
    });
}

fn jmp_reg_str(allocator: std.mem.Allocator, name: []const u8, insn: ebpf.Instruction) ![]const u8 {
    return try std.fmt.allocPrint(allocator, "{s} r{d}, r{d}, {s}0x{x}", .{
        name,
        insn.dst,
        insn.src,
        if (insn.offset >= 0) "+" else "-",
        @abs(insn.offset),
    });
}

// Main function to disassemble eBPF bytecode
pub fn to_insn_vec(allocator: std.mem.Allocator, prog: []const u8) DisassemblerError![]HLInsn {
    if (prog.len % ebpf.INSN_SIZE != 0) {
        return DisassemblerError.InvalidProgram;
    }

    var res = std.ArrayList(HLInsn).init(allocator);
    errdefer {
        for (res.items) |item| {
            allocator.free(item.name);
            allocator.free(item.description);
        }
        res.deinit();
    }

    var insn_ptr: usize = 0;
    while (insn_ptr * ebpf.INSN_SIZE < prog.len) : (insn_ptr += 1) {
        const insn = try ebpf.Instruction.get_ix(prog, insn_ptr);

        var name: []const u8 = undefined;
        var desc: []const u8 = undefined;
        var imm: i64 = @intCast(insn.imm);

        // Decode instruction based on opcode
        switch (insn.op) {
            // BPF_LD class
            ebpf.LD_ABS_W => { // 0x20
                name = "ldabsw";
                desc = try ldabs_str(allocator, name, insn);
            },
            ebpf.LD_ABS_H => { // 0x28
                name = "ldabsh";
                desc = try ldabs_str(allocator, name, insn);
            },
            ebpf.LD_ABS_B => { // 0x30
                name = "ldabsb";
                desc = try ldabs_str(allocator, name, insn);
            },
            ebpf.LD_ABS_DW => { // 0x38
                name = "ldabsdw";
                desc = try ldabs_str(allocator, name, insn);
            },
            ebpf.LD_IND_W => { // 0x40
                name = "ldindw";
                desc = try ldind_str(allocator, name, insn);
            },
            ebpf.LD_IND_H => { // 0x48
                name = "ldindh";
                desc = try ldind_str(allocator, name, insn);
            },
            ebpf.LD_IND_B => { // 0x50
                name = "ldindb";
                desc = try ldind_str(allocator, name, insn);
            },
            ebpf.LD_IND_DW => { // 0x58
                name = "ldinddw";
                desc = try ldind_str(allocator, name, insn);
            },

            ebpf.LD_DW_IMM => { // 0x18
                if (insn_ptr + 1 >= prog.len / ebpf.INSN_SIZE) {
                    return DisassemblerError.InvalidProgram;
                }
                insn_ptr += 1;
                const next_insn = try ebpf.Instruction.get_ix(prog, insn_ptr);
                const imm_u64 = @as(u64, @as(u32, @bitCast(insn.imm))) | (@as(u64, @as(u32, @bitCast(next_insn.imm))) << 32);
                imm = @bitCast(imm_u64);
                name = "lddw";
                desc = try std.fmt.allocPrint(allocator, "{s} r{d}, 0x{x:0>16}", .{ name, insn.dst, imm_u64 });
            },

            // BPF_LDX class
            ebpf.LD_B_REG => { // 0x71
                name = "ldxb";
                desc = try ld_reg_str(allocator, name, insn);
            },
            ebpf.LD_H_REG => { // 0x69
                name = "ldxh";
                desc = try ld_reg_str(allocator, name, insn);
            },
            ebpf.LD_W_REG => { // 0x61
                name = "ldxw";
                desc = try ld_reg_str(allocator, name, insn);
            },
            ebpf.LD_DW_REG => { // 0x79
                name = "ldxdw";
                desc = try ld_reg_str(allocator, name, insn);
            },

            // BPF_ST class
            ebpf.ST_B_IMM => { // 0x72
                name = "stb";
                desc = try ld_st_imm_str(allocator, name, insn);
            },
            ebpf.ST_H_IMM => { // 0x6a
                name = "sth";
                desc = try ld_st_imm_str(allocator, name, insn);
            },
            ebpf.ST_W_IMM => { // 0x62
                name = "stw";
                desc = try ld_st_imm_str(allocator, name, insn);
            },
            ebpf.ST_DW_IMM => { // 0x7a
                name = "stdw";
                desc = try ld_st_imm_str(allocator, name, insn);
            },

            // BPF_STX class
            ebpf.ST_B_REG => { // 0x73
                name = "stxb";
                desc = try st_reg_str(allocator, name, insn);
            },
            ebpf.ST_H_REG => { // 0x6b
                name = "stxh";
                desc = try st_reg_str(allocator, name, insn);
            },
            ebpf.ST_W_REG => { // 0x63
                name = "stxw";
                desc = try st_reg_str(allocator, name, insn);
            },
            ebpf.ST_DW_REG => { // 0x7b
                name = "stxdw";
                desc = try st_reg_str(allocator, name, insn);
            },
            ebpf.ST_W_XADD => { // 0xc3
                name = "stxxaddw";
                desc = try st_reg_str(allocator, name, insn);
            },
            ebpf.ST_DW_XADD => { // 0xdb
                name = "stxxadddw";
                desc = try st_reg_str(allocator, name, insn);
            },

            // BPF_ALU class
            ebpf.ADD32_IMM => { // 0x04
                name = "add32";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.ADD32_REG => { // 0x0c
                name = "add32";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.SUB32_IMM => { // 0x14
                name = "sub32";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.SUB32_REG => { // 0x1c
                name = "sub32";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.MUL32_IMM => { // 0x24
                name = "mul32";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.MUL32_REG => { // 0x2c
                name = "mul32";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.DIV32_IMM => { // 0x34
                name = "div32";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.DIV32_REG => { // 0x3c
                name = "div32";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.OR32_IMM => { // 0x44
                name = "or32";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.OR32_REG => { // 0x4c
                name = "or32";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.AND32_IMM => { // 0x54
                name = "and32";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.AND32_REG => { // 0x5c
                name = "and32";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.LSH32_IMM => { // 0x64
                name = "lsh32";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.LSH32_REG => { // 0x6c
                name = "lsh32";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.RSH32_IMM => { // 0x74
                name = "rsh32";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.RSH32_REG => { // 0x7c
                name = "rsh32";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.NEG32 => { // 0x84
                name = "neg32";
                desc = try std.fmt.allocPrint(allocator, "{s} r{d}", .{ name, insn.dst });
            },
            ebpf.MOD32_IMM => { // 0x94
                name = "mod32";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.MOD32_REG => { // 0x9c
                name = "mod32";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.XOR32_IMM => { // 0xa4
                name = "xor32";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.XOR32_REG => { // 0xac
                name = "xor32";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.MOV32_IMM => { // 0xb4
                name = "mov32";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.MOV32_REG => { // 0xbc
                name = "mov32";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.ARSH32_IMM => { // 0xc4
                name = "arsh32";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.ARSH32_REG => { // 0xcc
                name = "arsh32";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.LE => { // 0xd4
                name = "le";
                desc = try byteswap_str(allocator, name, insn);
            },
            ebpf.BE => { // 0xdc
                name = "be";
                desc = try byteswap_str(allocator, name, insn);
            },

            // BPF_ALU64 class
            ebpf.ADD64_IMM => { // 0x07
                name = "add64";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.ADD64_REG => { // 0x0f
                name = "add64";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.SUB64_IMM => { // 0x17
                name = "sub64";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.SUB64_REG => { // 0x1f
                name = "sub64";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.MUL64_IMM => { // 0x27
                name = "mul64";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.MUL64_REG => { // 0x2f
                name = "mul64";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.DIV64_IMM => { // 0x37
                name = "div64";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.DIV64_REG => { // 0x3f
                name = "div64";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.OR64_IMM => { // 0x47
                name = "or64";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.OR64_REG => { // 0x4f
                name = "or64";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.AND64_IMM => { // 0x57
                name = "and64";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.AND64_REG => { // 0x5f
                name = "and64";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.LSH64_IMM => { // 0x67
                name = "lsh64";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.LSH64_REG => { // 0x6f
                name = "lsh64";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.RSH64_IMM => { // 0x77
                name = "rsh64";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.RSH64_REG => { // 0x7f
                name = "rsh64";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.NEG64 => { // 0x87
                name = "neg64";
                desc = try std.fmt.allocPrint(allocator, "{s} r{d}", .{ name, insn.dst });
            },
            ebpf.MOD64_IMM => { // 0x97
                name = "mod64";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.MOD64_REG => { // 0x9f
                name = "mod64";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.XOR64_IMM => { // 0xa7
                name = "xor64";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.XOR64_REG => { // 0xaf
                name = "xor64";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.MOV64_IMM => { // 0xb7
                name = "mov64";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.MOV64_REG => { // 0xbf
                name = "mov64";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.ARSH64_IMM => { // 0xc7
                name = "arsh64";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.ARSH64_REG => { // 0xcf
                name = "arsh64";
                desc = try alu_reg_str(allocator, name, insn);
            },

            // BPF_JMP class
            ebpf.JA => { // 0x05
                name = "ja";
                desc = try std.fmt.allocPrint(allocator, "{s} {s}0x{x}", .{ name, if (insn.offset >= 0) "+" else "-", @abs(insn.offset) });
            },
            ebpf.JEQ_IMM => { // 0x15
                name = "jeq";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JEQ_REG => { // 0x1d
                name = "jeq";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JGT_IMM => { // 0x25
                name = "jgt";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JGT_REG => { // 0x2d
                name = "jgt";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JGE_IMM => { // 0x35
                name = "jge";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JGE_REG => { // 0x3d
                name = "jge";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JLT_IMM => { // 0xa5
                name = "jlt";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JLT_REG => { // 0xad
                name = "jlt";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JLE_IMM => { // 0xb5
                name = "jle";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JLE_REG => { // 0xbd
                name = "jle";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JSET_IMM => { // 0x45
                name = "jset";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JSET_REG => { // 0x4d
                name = "jset";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JNE_IMM => { // 0x55
                name = "jne";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JNE_REG => { // 0x5d
                name = "jne";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JSGT_IMM => { // 0x65
                name = "jsgt";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JSGT_REG => { // 0x6d
                name = "jsgt";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JSGE_IMM => { // 0x75
                name = "jsge";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JSGE_REG => { // 0x7d
                name = "jsge";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JSLT_IMM => { // 0xc5
                name = "jslt";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JSLT_REG => { // 0xcd
                name = "jslt";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JSLE_IMM => { // 0xd5
                name = "jsle";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JSLE_REG => { // 0xdd
                name = "jsle";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.CALL => { // 0x85
                name = "call";
                desc = try std.fmt.allocPrint(allocator, "{s} 0x{x}", .{ name, @as(u32, @bitCast(insn.imm)) });
            },
            ebpf.TAIL_CALL => { // 0xe5
                name = "tail_call";
                desc = name;
            },
            ebpf.EXIT => { // 0x95
                name = "exit";
                desc = name;
            },

            // BPF_JMP32 class
            ebpf.JEQ_IMM32 => { // 0x16
                name = "jeq32";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JEQ_REG32 => { // 0x1e
                name = "jeq32";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JGT_IMM32 => { // 0x26
                name = "jgt32";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JGT_REG32 => { // 0x2e
                name = "jgt32";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JGE_IMM32 => { // 0x36
                name = "jge32";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JGE_REG32 => { // 0x3e
                name = "jge32";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JLT_IMM32 => { // 0xa6
                name = "jlt32";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JLT_REG32 => { // 0xae
                name = "jlt32";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JLE_IMM32 => { // 0xb6
                name = "jle32";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JLE_REG32 => { // 0xbe
                name = "jle32";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JSET_IMM32 => { // 0x46
                name = "jset32";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JSET_REG32 => { // 0x4e
                name = "jset32";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JNE_IMM32 => { // 0x56
                name = "jne32";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JNE_REG32 => { // 0x5e
                name = "jne32";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JSGT_IMM32 => { // 0x66
                name = "jsgt32";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JSGT_REG32 => { // 0x6e
                name = "jsgt32";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JSGE_IMM32 => { // 0x76
                name = "jsge32";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JSGE_REG32 => { // 0x7e
                name = "jsge32";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JSLT_IMM32 => { // 0xc6
                name = "jslt32";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JSLT_REG32 => { // 0xce
                name = "jslt32";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JSLE_IMM32 => { // 0xd6
                name = "jsle32";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JSLE_REG32 => { // 0xde
                name = "jsle32";
                desc = try jmp_reg_str(allocator, name, insn);
            },

            else => {
                return DisassemblerError.UnknownOpcode;
            },
        }

        try res.append(HLInsn{
            .opcode = insn.op,
            .name = try allocator.dupe(u8, name),
            .description = desc,
            .dst = insn.dst,
            .src = insn.src,
            .off = insn.offset,
            .imm = imm,
        });
    }

    return res.toOwnedSlice();
}
