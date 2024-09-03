const std = @import("std");
const ebpf = @import("ebpf.zig");
const parse = @import("asm_parser.zig").parse;

/// Represents the type of eBPF instruction
const InstructionType = enum {
    AluBinary,
    AluUnary,
    LoadAbs,
    LoadInd,
    LoadImm,
    LoadReg,
    StoreImm,
    StoreReg,
    JumpUnconditional,
    JumpConditional,
    Call,
    Endian,
    NoOperand,
};

const Operand = @import("asm_parser.zig").Operand;
const Instruction = @import("asm_parser.zig").Instruction;

const InstructionMapEntry = struct { instType: InstructionType, opcode: u8 };
const InstructionMap = std.StringHashMap(InstructionMapEntry);

/// Creates a map of instruction names to their types and opcodes
fn makeInstructionMap() !InstructionMap {
    var result = InstructionMap.init(std.heap.page_allocator);

    const aluBinaryOps = [_]struct { name: []const u8, opc: u8 }{
        .{ .name = "add", .opc = ebpf.BPF_ADD },
        .{ .name = "sub", .opc = ebpf.BPF_SUB },
        .{ .name = "mul", .opc = ebpf.BPF_MUL },
        .{ .name = "div", .opc = ebpf.BPF_DIV },
        .{ .name = "or", .opc = ebpf.BPF_OR },
        .{ .name = "and", .opc = ebpf.BPF_AND },
        .{ .name = "lsh", .opc = ebpf.BPF_LSH },
        .{ .name = "rsh", .opc = ebpf.BPF_RSH },
        .{ .name = "mod", .opc = ebpf.BPF_MOD },
        .{ .name = "xor", .opc = ebpf.BPF_XOR },
        .{ .name = "mov", .opc = ebpf.BPF_MOV },
        .{ .name = "arsh", .opc = ebpf.BPF_ARSH },
    };

    const memSizes = [_]struct { suffix: []const u8, size: u8 }{
        .{ .suffix = "w", .size = ebpf.BPF_W },
        .{ .suffix = "h", .size = ebpf.BPF_H },
        .{ .suffix = "b", .size = ebpf.BPF_B },
        .{ .suffix = "dw", .size = ebpf.BPF_DW },
    };

    const jumpConditions = [_]struct { name: []const u8, condition: u8 }{
        .{ .name = "jeq", .condition = ebpf.BPF_JEQ },
        .{ .name = "jgt", .condition = ebpf.BPF_JGT },
        .{ .name = "jge", .condition = ebpf.BPF_JGE },
        .{ .name = "jlt", .condition = ebpf.BPF_JLT },
        .{ .name = "jle", .condition = ebpf.BPF_JLE },
        .{ .name = "jset", .condition = ebpf.BPF_JSET },
        .{ .name = "jne", .condition = ebpf.BPF_JNE },
        .{ .name = "jsgt", .condition = ebpf.BPF_JSGT },
        .{ .name = "jsge", .condition = ebpf.BPF_JSGE },
        .{ .name = "jslt", .condition = ebpf.BPF_JSLT },
        .{ .name = "jsle", .condition = ebpf.BPF_JSLE },
    };

    // Miscellaneous
    try result.put("exit", InstructionMapEntry{ .instType = .NoOperand, .opcode = ebpf.EXIT });
    try result.put("ja", InstructionMapEntry{ .instType = .JumpUnconditional, .opcode = ebpf.JA });
    try result.put("call", InstructionMapEntry{ .instType = .Call, .opcode = ebpf.CALL });
    try result.put("lddw", InstructionMapEntry{ .instType = .LoadImm, .opcode = ebpf.LD_DW_IMM });

    // AluUnary
    try result.put("neg", InstructionMapEntry{ .instType = .AluUnary, .opcode = ebpf.NEG64 });
    try result.put("neg32", InstructionMapEntry{ .instType = .AluUnary, .opcode = ebpf.NEG32 });
    try result.put("neg64", InstructionMapEntry{ .instType = .AluUnary, .opcode = ebpf.NEG64 });

    // AluBinary
    for (aluBinaryOps) |op| {
        try result.put(op.name, InstructionMapEntry{ .instType = .AluBinary, .opcode = ebpf.BPF_ALU64 | op.opc });
        try result.put(try std.fmt.allocPrint(std.heap.page_allocator, "{s}32", .{op.name}), InstructionMapEntry{ .instType = .AluBinary, .opcode = ebpf.BPF_ALU | op.opc });
        try result.put(try std.fmt.allocPrint(std.heap.page_allocator, "{s}64", .{op.name}), InstructionMapEntry{ .instType = .AluBinary, .opcode = ebpf.BPF_ALU64 | op.opc });
    }

    // LoadAbs, LoadInd, LoadReg, StoreImm, and StoreReg
    for (memSizes) |size| {
        try result.put(try std.fmt.allocPrint(std.heap.page_allocator, "ldabs{s}", .{size.suffix}), InstructionMapEntry{ .instType = .LoadAbs, .opcode = ebpf.BPF_ABS | ebpf.BPF_LD | size.size });
        try result.put(try std.fmt.allocPrint(std.heap.page_allocator, "ldind{s}", .{size.suffix}), InstructionMapEntry{ .instType = .LoadInd, .opcode = ebpf.BPF_IND | ebpf.BPF_LD | size.size });
        try result.put(try std.fmt.allocPrint(std.heap.page_allocator, "ldx{s}", .{size.suffix}), InstructionMapEntry{ .instType = .LoadReg, .opcode = ebpf.BPF_MEM | ebpf.BPF_LDX | size.size });
        try result.put(try std.fmt.allocPrint(std.heap.page_allocator, "st{s}", .{size.suffix}), InstructionMapEntry{ .instType = .StoreImm, .opcode = ebpf.BPF_MEM | ebpf.BPF_ST | size.size });
        try result.put(try std.fmt.allocPrint(std.heap.page_allocator, "stx{s}", .{size.suffix}), InstructionMapEntry{ .instType = .StoreReg, .opcode = ebpf.BPF_STX | ebpf.BPF_MEM | size.size });
    }

    // JumpConditional
    for (jumpConditions) |jmp| {
        try result.put(jmp.name, InstructionMapEntry{ .instType = .JumpConditional, .opcode = ebpf.BPF_JMP | jmp.condition });
        try result.put(try std.fmt.allocPrint(std.heap.page_allocator, "{s}32", .{jmp.name}), InstructionMapEntry{ .instType = .JumpConditional, .opcode = ebpf.BPF_JMP32 | jmp.condition });
    }

    // Endian
    for ([_]u8{ 16, 32, 64 }) |sz| {
        try result.put(try std.fmt.allocPrint(std.heap.page_allocator, "be{d}", .{sz}), InstructionMapEntry{ .instType = .Endian, .opcode = ebpf.BE });
        try result.put(try std.fmt.allocPrint(std.heap.page_allocator, "le{d}", .{sz}), InstructionMapEntry{ .instType = .Endian, .opcode = ebpf.LE });
    }

    return result;
}

/// Creates an eBPF instruction from its components
fn ix(opc: u8, dst: u8, src: u8, off: i16, imm: i32) ebpf.Instruction {
    return ebpf.Instruction{
        .op = opc,
        .dst = dst,
        .src = src,
        .offset = off,
        .imm = imm,
    };
}

/// Encodes a parsed instruction into an eBPF instruction
fn encode(instType: InstructionType, opc: u8, instruction: Instruction) !ebpf.Instruction {
    const operands = instruction.operands;
    switch (instType) {
        .AluBinary => switch (operands[0]) {
            .Register => |reg| {
                if (reg > 10) return AssemblerError.InvalidRegister;
                switch (operands[1]) {
                    .Register => |src_reg| {
                        if (src_reg > 10) return AssemblerError.InvalidRegister;
                        return ix(opc | ebpf.BPF_X, @intCast(reg), @intCast(src_reg), 0, 0);
                    },
                    .Integer => |imm| {
                        return ix(opc | ebpf.BPF_K, @intCast(reg), 0, 0, @intCast(imm));
                    },
                    else => return AssemblerError.InvalidOperands,
                }
            },
            else => return AssemblerError.InvalidOperands,
        },
        .AluUnary => switch (operands[0]) {
            .Register => |reg| {
                if (reg > 10) return AssemblerError.InvalidRegister;
                return ix(opc, @intCast(reg), 0, 0, 0);
            },
            else => return AssemblerError.InvalidOperands,
        },
        .LoadAbs => switch (operands[0]) {
            .Integer => |imm| {
                return ix(opc, 0, 0, 0, @intCast(imm));
            },
            else => return AssemblerError.InvalidOperands,
        },
        .LoadInd => switch (operands[0]) {
            .Register => |reg| {
                if (reg > 10) return AssemblerError.InvalidRegister;
                switch (operands[1]) {
                    .Integer => |off| {
                        return ix(opc, 0, @intCast(reg), 0, @intCast(off));
                    },
                    else => return AssemblerError.InvalidOperands,
                }
            },
            else => return AssemblerError.InvalidOperands,
        },
        .LoadImm => switch (operands[0]) {
            .Register => |reg| {
                if (reg > 10) return AssemblerError.InvalidRegister;
                switch (operands[1]) {
                    .Integer => |imm| {
                        return ix(opc, @intCast(reg), 0, 0, @intCast(imm));
                    },
                    else => return AssemblerError.InvalidOperands,
                }
            },
            else => return AssemblerError.InvalidOperands,
        },
        .LoadReg => switch (operands[0]) {
            .Register => |dst| {
                if (dst > 10) return AssemblerError.InvalidRegister;
                switch (operands[1]) {
                    .Memory => |mem| {
                        if (mem.base > 10) return AssemblerError.InvalidRegister;
                        return ix(opc, @intCast(dst), @intCast(mem.base), @intCast(mem.offset), 0);
                    },
                    else => return AssemblerError.InvalidOperands,
                }
            },
            else => return AssemblerError.InvalidOperands,
        },
        .StoreImm => switch (operands[0]) {
            .Memory => |mem| {
                if (mem.base > 10) return AssemblerError.InvalidRegister;
                switch (operands[1]) {
                    .Integer => |imm| {
                        return ix(opc, @intCast(mem.base), 0, @intCast(mem.offset), @intCast(imm));
                    },
                    else => return AssemblerError.InvalidOperands,
                }
            },
            else => return AssemblerError.InvalidOperands,
        },
        .StoreReg => switch (operands[0]) {
            .Memory => |mem| {
                if (mem.base > 10) return AssemblerError.InvalidRegister;
                switch (operands[1]) {
                    .Register => |src| {
                        if (src > 10) return AssemblerError.InvalidRegister;
                        return ix(opc, @intCast(mem.base), @intCast(src), @intCast(mem.offset), 0);
                    },
                    else => return AssemblerError.InvalidOperands,
                }
            },
            else => return AssemblerError.InvalidOperands,
        },
        .JumpUnconditional => switch (operands[0]) {
            .Integer => |off| {
                return ix(opc, 0, 0, @intCast(off), 0);
            },
            else => return AssemblerError.InvalidOperands,
        },
        .JumpConditional => switch (operands[0]) {
            .Register => |reg| {
                if (reg > 10) return AssemblerError.InvalidRegister;
                switch (operands[1]) {
                    .Register => |src_reg| {
                        if (src_reg > 10) return AssemblerError.InvalidRegister;
                        switch (operands[2]) {
                            .Integer => |off| {
                                return ix(opc | ebpf.BPF_X, @intCast(reg), @intCast(src_reg), @intCast(off), 0);
                            },
                            else => return AssemblerError.InvalidOperands,
                        }
                    },
                    .Integer => |imm| {
                        switch (operands[2]) {
                            .Integer => |off| {
                                return ix(opc | ebpf.BPF_K, @intCast(reg), 0, @intCast(off), @intCast(imm));
                            },
                            else => return AssemblerError.InvalidOperands,
                        }
                    },
                    else => return AssemblerError.InvalidOperands,
                }
            },
            else => return AssemblerError.InvalidOperands,
        },
        .Call => switch (operands[0]) {
            .Integer => |imm| {
                return ix(opc, 0, 0, 0, @intCast(imm));
            },
            else => return AssemblerError.InvalidOperands,
        },
        .Endian => switch (operands[0]) {
            .Register => |reg| {
                if (reg > 10) return AssemblerError.InvalidRegister;
                const size: i32 = switch (opc) {
                    ebpf.BE => blk: {
                        if (std.mem.eql(u8, instruction.name, "be16")) {
                            break :blk 16;
                        } else if (std.mem.eql(u8, instruction.name, "be32")) {
                            break :blk 32;
                        } else if (std.mem.eql(u8, instruction.name, "be64")) {
                            break :blk 64;
                        } else {
                            return AssemblerError.InvalidOperands;
                        }
                    },
                    ebpf.LE => blk: {
                        if (std.mem.eql(u8, instruction.name, "le16")) {
                            break :blk 16;
                        } else if (std.mem.eql(u8, instruction.name, "le32")) {
                            break :blk 32;
                        } else if (std.mem.eql(u8, instruction.name, "le64")) {
                            break :blk 64;
                        } else {
                            return AssemblerError.InvalidOperands;
                        }
                    },
                    else => return AssemblerError.InvalidOperands,
                };
                return ix(opc, @intCast(reg), 0, 0, size);
            },
            else => return AssemblerError.InvalidOperands,
        },
        .NoOperand => return ix(opc, 0, 0, 0, 0),
    }
}

/// Assembles a list of parsed instructions into eBPF bytecode
fn assembleInternal(parsed: []Instruction) ![]ebpf.Instruction {
    var insns = std.ArrayList(ebpf.Instruction).init(std.heap.page_allocator);
    const instructionMap = try makeInstructionMap();

    for (parsed) |instruction| {
        const entry = instructionMap.get(instruction.name) orelse return AssemblerError.InvalidInstruction;
        const inst = try encode(entry.instType, entry.opcode, instruction);
        try insns.append(inst);

        // Special case for lddw
        if (entry.instType == .LoadImm and instruction.operands[1] != Operand.Nil) {
            if (instruction.operands[1] == Operand.Integer) {
                try insns.append(ix(0, 0, 0, 0, @intCast(instruction.operands[1].Integer >> 32)));
            }
        }
    }

    return insns.toOwnedSlice();
}

/// Assembles eBPF assembly source code into bytecode
pub fn assemble(src: []const u8) ![]const u8 {
    const parsed = try parse(src);
    const insns = try assembleInternal(parsed);

    var result = std.ArrayList(u8).init(std.heap.page_allocator);
    for (insns) |instruction| {
        const instr_array = instruction.to_array();
        try result.appendSlice(&instr_array);
    }

    return result.toOwnedSlice();
}

/// Possible errors during assembly
pub const AssemblerError = error{
    InvalidInstruction,
    InvalidOperand,
    OutOfMemory,
    InvalidOperands,
    InvalidRegister,
    MismatchedOperands,
};
