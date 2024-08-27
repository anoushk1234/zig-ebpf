const std = @import("std");
const ebpf = @import("ebpf.zig");

pub const DisassemblerError = error{
    InvalidProgram,
    UnknownOpcode,
    InvalidByteswapSize,
    OutOfMemory,
    InvalidInstructionSize,
};

pub const HLInsn = struct {
    opcode: u8,
    name: []const u8,
    description: []const u8,
    dst: u8,
    src: u8,
    off: i16,
    imm: i64,
};

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

        switch (insn.op) {
            // BPF_LD class
            ebpf.LD_ABS_W => {
                name = "ldabsw";
                desc = try ldabs_str(allocator, name, insn);
            },
            ebpf.LD_ABS_H => {
                name = "ldabsh";
                desc = try ldabs_str(allocator, name, insn);
            },
            ebpf.LD_ABS_B => {
                name = "ldabsb";
                desc = try ldabs_str(allocator, name, insn);
            },
            ebpf.LD_ABS_DW => {
                name = "ldabsdw";
                desc = try ldabs_str(allocator, name, insn);
            },
            ebpf.LD_IND_B => {
                name = "ldindb";
                desc = try ldind_str(allocator, name, insn);
            },
            ebpf.LD_IND_H => {
                name = "ldindh";
                desc = try ldind_str(allocator, name, insn);
            },
            ebpf.LD_IND_W => {
                name = "ldindw";
                desc = try ldind_str(allocator, name, insn);
            },
            ebpf.LD_IND_DW => {
                name = "ldinddw";
                desc = try ldind_str(allocator, name, insn);
            },

            ebpf.LD_DW_IMM => {
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
            ebpf.LD_B_REG => {
                name = "ldxb";
                desc = try ld_reg_str(allocator, name, insn);
            },
            ebpf.LD_H_REG => {
                name = "ldxh";
                desc = try ld_reg_str(allocator, name, insn);
            },
            ebpf.LD_W_REG => {
                name = "ldxw";
                desc = try ld_reg_str(allocator, name, insn);
            },
            ebpf.LD_DW_REG => {
                name = "ldxdw";
                desc = try ld_reg_str(allocator, name, insn);
            },

            // BPF_ST class
            ebpf.ST_B_IMM => {
                name = "stb";
                desc = try ld_st_imm_str(allocator, name, insn);
            },
            ebpf.ST_H_IMM => {
                name = "sth";
                desc = try ld_st_imm_str(allocator, name, insn);
            },
            ebpf.ST_W_IMM => {
                name = "stw";
                desc = try ld_st_imm_str(allocator, name, insn);
            },
            ebpf.ST_DW_IMM => {
                name = "stdw";
                desc = try ld_st_imm_str(allocator, name, insn);
            },

            // BPF_STX class
            ebpf.ST_B_REG => {
                name = "stxb";
                desc = try st_reg_str(allocator, name, insn);
            },
            ebpf.ST_H_REG => {
                name = "stxh";
                desc = try st_reg_str(allocator, name, insn);
            },
            ebpf.ST_W_REG => {
                name = "stxw";
                desc = try st_reg_str(allocator, name, insn);
            },
            ebpf.ST_DW_REG => {
                name = "stxdw";
                desc = try st_reg_str(allocator, name, insn);
            },
            ebpf.ST_W_XADD => {
                name = "stxxaddw";
                desc = try st_reg_str(allocator, name, insn);
            },
            ebpf.ST_DW_XADD => {
                name = "stxxadddw";
                desc = try st_reg_str(allocator, name, insn);
            },

            // BPF_ALU class
            ebpf.ADD32_IMM => {
                name = "add32";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.ADD32_REG => {
                name = "add32";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.SUB32_IMM => {
                name = "sub32";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.SUB32_REG => {
                name = "sub32";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.MUL32_IMM => {
                name = "mul32";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.MUL32_REG => {
                name = "mul32";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.DIV32_IMM => {
                name = "div32";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.DIV32_REG => {
                name = "div32";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.OR32_IMM => {
                name = "or32";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.OR32_REG => {
                name = "or32";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.AND32_IMM => {
                name = "and32";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.AND32_REG => {
                name = "and32";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.LSH32_IMM => {
                name = "lsh32";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.LSH32_REG => {
                name = "lsh32";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.RSH32_IMM => {
                name = "rsh32";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.RSH32_REG => {
                name = "rsh32";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.NEG32 => {
                name = "neg32";
                desc = try std.fmt.allocPrint(allocator, "{s} r{d}", .{ name, insn.dst });
            },
            ebpf.MOD32_IMM => {
                name = "mod32";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.MOD32_REG => {
                name = "mod32";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.XOR32_IMM => {
                name = "xor32";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.XOR32_REG => {
                name = "xor32";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.MOV32_IMM => {
                name = "mov32";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.MOV32_REG => {
                name = "mov32";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.ARSH32_IMM => {
                name = "arsh32";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.ARSH32_REG => {
                name = "arsh32";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.LE => {
                name = "le";
                desc = try byteswap_str(allocator, name, insn);
            },
            ebpf.BE => {
                name = "be";
                desc = try byteswap_str(allocator, name, insn);
            },

            // BPF_ALU64 class
            ebpf.ADD64_IMM => {
                name = "add64";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.ADD64_REG => {
                name = "add64";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.SUB64_IMM => {
                name = "sub64";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.SUB64_REG => {
                name = "sub64";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.MUL64_IMM => {
                name = "mul64";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.MUL64_REG => {
                name = "mul64";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.DIV64_IMM => {
                name = "div64";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.DIV64_REG => {
                name = "div64";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.OR64_IMM => {
                name = "or64";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.OR64_REG => {
                name = "or64";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.AND64_IMM => {
                name = "and64";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.AND64_REG => {
                name = "and64";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.LSH64_IMM => {
                name = "lsh64";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.LSH64_REG => {
                name = "lsh64";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.RSH64_IMM => {
                name = "rsh64";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.RSH64_REG => {
                name = "rsh64";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.NEG64 => {
                name = "neg64";
                desc = try std.fmt.allocPrint(allocator, "{s} r{d}", .{ name, insn.dst });
            },
            ebpf.MOD64_IMM => {
                name = "mod64";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.MOD64_REG => {
                name = "mod64";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.XOR64_IMM => {
                name = "xor64";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.XOR64_REG => {
                name = "xor64";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.MOV64_IMM => {
                name = "mov64";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.MOV64_REG => {
                name = "mov64";
                desc = try alu_reg_str(allocator, name, insn);
            },
            ebpf.ARSH64_IMM => {
                name = "arsh64";
                desc = try alu_imm_str(allocator, name, insn);
            },
            ebpf.ARSH64_REG => {
                name = "arsh64";
                desc = try alu_reg_str(allocator, name, insn);
            },

            // BPF_JMP class
            ebpf.JA => {
                name = "ja";
                desc = try std.fmt.allocPrint(allocator, "{s} {s}0x{x}", .{ name, if (insn.offset >= 0) "+" else "-", @abs(insn.offset) });
            },
            ebpf.JEQ_IMM => {
                name = "jeq";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JEQ_REG => {
                name = "jeq";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JGT_IMM => {
                name = "jgt";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JGT_REG => {
                name = "jgt";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JGE_IMM => {
                name = "jge";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JGE_REG => {
                name = "jge";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JLT_IMM => {
                name = "jlt";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JLT_REG => {
                name = "jlt";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JLE_IMM => {
                name = "jle";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JLE_REG => {
                name = "jle";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JSET_IMM => {
                name = "jset";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JSET_REG => {
                name = "jset";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JNE_IMM => {
                name = "jne";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JNE_REG => {
                name = "jne";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JSGT_IMM => {
                name = "jsgt";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JSGT_REG => {
                name = "jsgt";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JSGE_IMM => {
                name = "jsge";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JSGE_REG => {
                name = "jsge";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JSLT_IMM => {
                name = "jslt";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JSLT_REG => {
                name = "jslt";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JSLE_IMM => {
                name = "jsle";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JSLE_REG => {
                name = "jsle";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.CALL => {
                name = "call";
                desc = try std.fmt.allocPrint(allocator, "{s} 0x{x}", .{ name, @as(u32, @bitCast(insn.imm)) });
            },
            ebpf.TAIL_CALL => {
                name = "tail_call";
                desc = name;
            },
            ebpf.EXIT => {
                name = "exit";
                desc = name;
            },

            // BPF_JMP32 class
            ebpf.JEQ_IMM32 => {
                name = "jeq32";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JEQ_REG32 => {
                name = "jeq32";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JGT_IMM32 => {
                name = "jgt32";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JGT_REG32 => {
                name = "jgt32";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JGE_IMM32 => {
                name = "jge32";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JGE_REG32 => {
                name = "jge32";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JLT_IMM32 => {
                name = "jlt32";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JLT_REG32 => {
                name = "jlt32";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JLE_IMM32 => {
                name = "jle32";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JLE_REG32 => {
                name = "jle32";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JSET_IMM32 => {
                name = "jset32";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JSET_REG32 => {
                name = "jset32";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JNE_IMM32 => {
                name = "jne32";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JNE_REG32 => {
                name = "jne32";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JSGT_IMM32 => {
                name = "jsgt32";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JSGT_REG32 => {
                name = "jsgt32";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JSGE_IMM32 => {
                name = "jsge32";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JSGE_REG32 => {
                name = "jsge32";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JSLT_IMM32 => {
                name = "jslt32";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JSLT_REG32 => {
                name = "jslt32";
                desc = try jmp_reg_str(allocator, name, insn);
            },
            ebpf.JSLE_IMM32 => {
                name = "jsle32";
                desc = try jmp_imm_str(allocator, name, insn);
            },
            ebpf.JSLE_REG32 => {
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
