const std = @import("std");
const ebpf = @import("ebpf.zig");
const parse = @import("asm_parser.zig").parse;

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

fn makeInstructionMap() !std.AutoHashMap([]const u8, struct {
    instType: InstructionType,
    opcode: u8,
}) {
    var map = std.AutoHashMap([]const u8, struct {
        instType: InstructionType,
        opcode: u8,
    }).init(std.heap.page_allocator);

    const aluBinaryOps = &[_][]const u8{
        "add", "sub", "mul", "div", "or", "and", "lsh", "rsh", "mod", "xor", "mov", "arsh",
    };
    const aluBinaryOpcodes = &[_]u8{
        ebpf.BPF_ADD, ebpf.BPF_SUB, ebpf.BPF_MUL, ebpf.BPF_DIV, ebpf.BPF_OR,  ebpf.BPF_AND,
        ebpf.BPF_LSH, ebpf.BPF_RSH, ebpf.BPF_MOD, ebpf.BPF_XOR, ebpf.BPF_MOV, ebpf.BPF_ARSH,
    };

    var i: usize = 0;
    for (aluBinaryOps) |op| {
        map.put(op, .{ .instType = .AluBinary, .opcode = aluBinaryOpcodes[i] }) catch unreachable;
        map.put(try std.fmt.allocPrint(std.heap.page_allocator, "{s}32", .{op}), .{ .instType = .AluBinary, .opcode = aluBinaryOpcodes[i] }) catch unreachable;
        map.put(try std.fmt.allocPrint(std.heap.page_allocator, "{s}64", .{op}), .{ .instType = .AluBinary, .opcode = aluBinaryOpcodes[i] }) catch unreachable;
        i += 1;
    }

    const memSizes = &[_][]const u8{ "w", "h", "b", "dw" };
    const memOpcodes = &[_]u8{ ebpf.BPF_W, ebpf.BPF_H, ebpf.BPF_B, ebpf.BPF_DW };

    i = 0;
    for (memSizes) |size| {
        map.put(std.fmt.allocPrint(std.heap.page_allocator, "ldabs{s}", .{size}), .{ .instType = .LoadAbs, .opcode = ebpf.BPF_ABS | ebpf.BPF_LD | memOpcodes[i] }) catch unreachable;
        map.put(std.fmt.allocPrint(std.heap.page_allocator, "ldind{s}", .{size}), .{ .instType = .LoadInd, .opcode = ebpf.BPF_IND | ebpf.BPF_LD | memOpcodes[i] }) catch unreachable;
        map.put(std.fmt.allocPrint(std.heap.page_allocator, "ldx{s}", .{size}), .{ .instType = .LoadReg, .opcode = ebpf.BPF_MEM | ebpf.BPF_LDX | memOpcodes[i] }) catch unreachable;
        map.put(std.fmt.allocPrint(std.heap.page_allocator, "st{s}", .{size}), .{ .instType = .StoreImm, .opcode = ebpf.BPF_MEM | ebpf.BPF_ST | memOpcodes[i] }) catch unreachable;
        map.put(std.fmt.allocPrint(std.heap.page_allocator, "stx{s}", .{size}), .{ .instType = .StoreReg, .opcode = ebpf.BPF_MEM | ebpf.BPF_STX | memOpcodes[i] }) catch unreachable;
        i += 1;
    }

    const jumpConditions = &[_][]const u8{
        "jeq", "jgt", "jge", "jlt", "jle", "jset", "jne", "jsgt", "jsge", "jslt", "jsle",
    };
    const jumpOpcodes = &[_]u8{
        ebpf.BPF_JEQ, ebpf.BPF_JGT,  ebpf.BPF_JGE,  ebpf.BPF_JLT,  ebpf.BPF_JLE,  ebpf.BPF_JSET,
        ebpf.BPF_JNE, ebpf.BPF_JSGT, ebpf.BPF_JSGE, ebpf.BPF_JSLT, ebpf.BPF_JSLE,
    };

    i = 0;
    for (jumpConditions) |cond| {
        map.put(cond, .{ .instType = .JumpConditional, .opcode = ebpf.BPF_JMP | jumpOpcodes[i] }) catch unreachable;
        map.put(std.fmt.allocPrint(std.heap.page_allocator, "{s}32", .{cond}), .{ .instType = .JumpConditional, .opcode = ebpf.BPF_JMP32 | jumpOpcodes[i] }) catch unreachable;
        i += 1;
    }

    map.put("exit", .{ .instType = .NoOperand, .opcode = ebpf.EXIT }) catch unreachable;
    map.put("ja", .{ .instType = .JumpUnconditional, .opcode = ebpf.JA }) catch unreachable;
    map.put("call", .{ .instType = .Call, .opcode = ebpf.CALL }) catch unreachable;
    map.put("lddw", .{ .instType = .LoadImm, .opcode = ebpf.LD_DW_IMM }) catch unreachable;
    map.put("neg", .{ .instType = .AluUnary, .opcode = ebpf.NEG64 }) catch unreachable;
    map.put("neg32", .{ .instType = .AluUnary, .opcode = ebpf.NEG32 }) catch unreachable;
    map.put("neg64", .{ .instType = .AluUnary, .opcode = ebpf.NEG64 }) catch unreachable;

    for ([_]u8{ 16, 32, 64 }) |size| {
        map.put(std.fmt.allocPrint(std.heap.page_allocator, "be{d}", .{size}), .{ .instType = .Endian, .opcode = ebpf.BE }) catch unreachable;
        map.put(std.fmt.allocPrint(std.heap.page_allocator, "le{d}", .{size}), .{ .instType = .Endian, .opcode = ebpf.LE }) catch unreachable;
    }

    return map;
}

fn insn(opc: u8, dst: u8, src: u8, off: i16, imm: i32) ebpf.Instruction {
    return ebpf.Instruction{
        .op = opc,
        .dst = dst,
        .src = src,
        .offset = off,
        .imm = imm,
    };
}

fn encode(instType: InstructionType, opc: u8, operands: [3]Operand) !ebpf.Instruction {
    switch (instType) {
        .AluBinary => switch (operands[0]) {
            .Register => switch (operands[1]) {
                .Register => return insn(opc | ebpf.BPF_X, operands[0].Register, operands[1].Register, 0, 0),
                .Integer => return insn(opc | ebpf.BPF_K, operands[0].Register, 0, 0, @intCast(operands[1].Integer)),
                else => return error.InvalidOperands,
            },
            else => return error.InvalidOperands,
        },
        .AluUnary => switch (operands[0]) {
            .Register => return insn(opc, operands[0].Register, 0, 0, 0),
            else => return error.InvalidOperands,
        },
        .LoadAbs => switch (operands[0]) {
            .Integer => return insn(opc, 0, 0, 0, @intCast(operands[0].Integer)),
            else => return error.InvalidOperands,
        },
        .LoadInd => switch (operands[0]) {
            .Register => switch (operands[1]) {
                .Integer => return insn(opc, 0, operands[0].Register, 0, @intCast(operands[1].Integer)),
                else => return error.InvalidOperands,
            },
            else => return error.InvalidOperands,
        },
        .LoadImm => switch (operands[0]) {
            .Register => switch (operands[1]) {
                .Integer => return insn(opc, operands[0].Register, 0, 0, @intCast(operands[1].Integer)),
                else => return error.InvalidOperands,
            },
            else => return error.InvalidOperands,
        },
        .LoadReg, .StoreReg => switch (operands[0]) {
            .Register => switch (operands[1]) {
                .Memory => return insn(opc, operands[0].Register, operands[1].Memory.base, @intCast(operands[1].Memory.offset), 0),
                else => return error.InvalidOperands,
            },
            else => return error.InvalidOperands,
        },
        .StoreImm => switch (operands[0]) {
            .Memory => switch (operands[1]) {
                .Integer => return insn(opc, operands[0].Memory.base, 0, operands[0].Memory.offset, @intCast(operands[1].Integer)),
                else => return error.InvalidOperands,
            },
            else => return error.InvalidOperands,
        },
        .JumpUnconditional => switch (operands[0]) {
            .Integer => return insn(opc, 0, 0, @intCast(operands[0].Integer), 0),
            else => return error.InvalidOperands,
        },
        .JumpConditional => switch (operands[0]) {
            .Register => switch (operands[1]) {
                .Register => switch (operands[2]) {
                    .Integer => return insn(opc | ebpf.BPF_X, operands[0].Register, operands[1].Register, @intCast(operands[2].Integer), 0),
                    else => return error.InvalidOperands,
                },
                .Integer => switch (operands[2]) {
                    .Integer => return insn(opc | ebpf.BPF_K, operands[0].Register, 0, @intCast(operands[2].Integer), @intCast(operands[1].Integer)),
                    else => return error.InvalidOperands,
                },
                else => return error.InvalidOperands,
            },
            else => return error.InvalidOperands,
        },
        .Call => switch (operands[0]) {
            .Integer => return insn(opc, 0, 0, 0, @intCast(operands[0].Integer)),
            else => return error.InvalidOperands,
        },
        .Endian => switch (operands[0]) {
            .Register => switch (operands[1]) {
                .Integer => return insn(opc, operands[0].Register, 0, 0, @intCast(operands[1].Integer)),
                else => return error.InvalidOperands,
            },
            else => return error.InvalidOperands,
        },
        .NoOperand => return insn(opc, 0, 0, 0, 0),
    }
}

fn assembleInternal(parsed: []Instruction) ![]ebpf.Instruction {
    var insns = std.ArrayList(ebpf.Instruction).init(std.heap.page_allocator);
    const instructionMap = try makeInstructionMap();

    for (parsed) |instruction| {
        const entry = instructionMap.get(instruction.name) orelse return AssemblerError.InvalidInstruction;
        const inst = try encode(entry.instType, entry.opcode, instruction.operands);
        insns.append(inst) catch return AssemblerError.OutOfMemory;

        // Special case for lddw
        if (entry.instType == .LoadImm and instruction.operands[1] != Operand.Nil) {
            if (instruction.operands[1] == Operand.Integer) {
                insns.append(insn(0, 0, 0, 0, @intCast(i32, instruction.operands[1].Integer >> 32))) catch return AssemblerError.OutOfMemory;
            }
        }
    }

    return insns.toOwnedSlice();
}

pub fn assemble(src: []const u8) ![]u8 {
    const parsed = try parse(src);
    const insns = try assembleInternal(parsed);

    var result = std.ArrayList(u8).init(std.heap.page_allocator);
    for (insns) |insn| {
        result.appendSlice(&insn) catch return AssemblerError.OutOfMemory;
    }

    return result.toOwnedSlice();
}

pub const AssemblerError = error{
    InvalidInstruction,
    InvalidOperand,
    OutOfMemory,
    InvalidOperands,
};
