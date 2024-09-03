const std = @import("std");
const expectEqual = std.testing.expectEqual;
const expect = std.testing.expect;
const expectEqualSlices = std.testing.expectEqualSlices;

/// Represents an operand in an eBPF instruction
pub const Operand = union(enum) {
    Register: i64,
    Integer: i64,
    Memory: struct {
        base: i64,
        offset: i64,
    },
    Nil,

    /// Compares two operands for equality
    pub fn eq(a: Operand, b: Operand) bool {
        switch (a) {
            .Register => |a_val| {
                if (b == .Register) {
                    return a_val == b.Register;
                }
            },
            .Integer => |a_val| {
                if (b == .Integer) {
                    return a_val == b.Integer;
                }
            },
            .Memory => |a_val| {
                if (b == .Memory) {
                    return a_val.base == b.Memory.base and a_val.offset == b.Memory.offset;
                }
            },
            .Nil => {
                if (b == .Nil) {
                    return true;
                }
            },
        }
        return false; // If tags do not match
    }
};

/// Represents a parsed eBPF instruction
pub const Instruction = struct {
    name: []const u8,
    operands: [3]Operand,

    /// Compares two instructions for equality
    pub fn eq(a: Instruction, b: Instruction) bool {
        return std.mem.eql(u8, a.name, b.name) and
            a.operands[0].eq(b.operands[0]) and
            a.operands[1].eq(b.operands[1]) and
            a.operands[2].eq(b.operands[2]);
    }
};

/// Parses an identifier from the input
fn parseIdent(input: []const u8) ![]const u8 {
    var i: usize = 0;
    while (i < input.len and (std.ascii.isAlphanumeric(input[i]) or std.ascii.isDigit(input[i]) or input[i] == '_')) : (i += 1) {}
    if (i == 0) return error.InvalidIdentifier;
    return input[0..i];
}

/// Parses an integer from the input
fn parseInteger(input: []const u8) !i64 {
    return std.fmt.parseInt(i64, input, 0);
}

/// Parses a register from the input
fn parseRegister(input: []const u8) !i64 {
    if (input.len < 2 or input[0] != 'r') return error.InvalidRegister;
    return std.fmt.parseInt(i64, input[1..], 0);
}

/// Parses an operand from the input
fn parseOperand(input: []const u8) !Operand {
    if (input.len == 0) return Operand.Nil;
    if (input[0] == 'r') return Operand{ .Register = try parseRegister(input) };
    if (input[0] == '[') {
        const end = std.mem.indexOf(u8, input, "]") orelse return error.InvalidMemoryOperand;
        const base_end = std.mem.indexOf(u8, input[1..end], &[_]u8{'+'}) orelse (std.mem.indexOf(u8, input[1..end], &[_]u8{'-'}) orelse (std.mem.indexOf(u8, input[1..end], "]") orelse end) - 1);
        const base = try parseRegister(input[1 .. 1 + base_end]);
        var offset: i64 = 0;
        if (base_end + 1 < end) {
            const sign: i64 = if (input[1 + base_end] == '-') -1 else 1;
            offset = sign * try parseInteger(input[1 + base_end + 1 .. end]);
        }

        return Operand{ .Memory = .{ .base = base, .offset = offset } };
    }
    return Operand{ .Integer = try parseInteger(input) };
}

/// Parses a single instruction from the input
fn parseInstruction(input: []const u8) !Instruction {
    var tokens = std.mem.split(u8, input, " ");
    const name_token = tokens.next() orelse return error.InvalidToken;
    const name = try parseIdent(name_token);
    var operands: [3]Operand = .{ Operand.Nil, Operand.Nil, Operand.Nil };
    var i: usize = 0;

    // Get the remaining part of the input after the instruction name
    const remaining_input = std.mem.trim(u8, input[name.len..], " ");
    if (remaining_input.len > 0) {
        var operand_tokens = std.mem.split(u8, remaining_input, ",");
        while (operand_tokens.next()) |token| {
            if (i >= operands.len) break;
            operands[i] = try parseOperand(std.mem.trim(u8, token, " "));
            i += 1;
        }
    }

    return Instruction{ .name = name, .operands = operands };
}

/// Parses eBPF assembly source code into a list of instructions
pub fn parse(input: []const u8) ![]Instruction {
    var instructions = std.ArrayList(Instruction).init(std.heap.page_allocator);
    defer instructions.deinit();

    var lines = std.mem.split(u8, input, "\n");
    while (lines.next()) |line| {
        const trimmed_line = std.mem.trim(u8, line, " \t");
        if (trimmed_line.len == 0) continue;
        const instruction = try parseInstruction(trimmed_line);
        try instructions.append(instruction);
    }
    return instructions.toOwnedSlice();
}

/// Possible parsing errors
pub const errors = error{InvalidToken};

test "test_ident" {
    try expectEqual(parseIdent("nop"), "nop");
    try expectEqual(parseIdent("add32"), "add32");
    try expectEqualSlices(u8, try parseIdent("add32*"), "add32");
}

test "test_integer" {
    try expectEqual(parseInteger("0"), 0);
    try expectEqual(parseInteger("42"), 42);
    try expectEqual(parseInteger("+42"), 42);
    try expectEqual(parseInteger("-42"), -42);
    try expectEqual(parseInteger("0x0"), 0);
    try expectEqual(parseInteger("-0x1f"), -31);
}

test "test_register" {
    try expectEqual(parseRegister("r0"), 0);
    try expectEqual(parseRegister("r15"), 15);
}

test "test_operand" {
    try expectEqual(parseOperand("r0"), Operand{ .Register = 0 });
    try expectEqual(parseOperand("r15"), Operand{ .Register = 15 });
    try expectEqual(parseOperand("0"), Operand{ .Integer = 0 });
    try expectEqual(parseOperand("42"), Operand{ .Integer = 42 });
    try expectEqual(parseOperand("[r1+5]"), Operand{ .Memory = .{ .base = 1, .offset = 5 } });
    try expectEqual(parseOperand("[r3+0x1f]"), Operand{ .Memory = .{ .base = 3, .offset = 31 } });
    try expectEqual(parseOperand("[r3-0x1f]"), Operand{ .Memory = .{ .base = 3, .offset = -31 } });
}

test "test_instruction" {
    try expect(Instruction.eq(try parseInstruction("exit"), Instruction{ .name = "exit", .operands = .{ Operand.Nil, Operand.Nil, Operand.Nil } }));
    try expect(Instruction.eq(try parseInstruction("call 2"), Instruction{ .name = "call", .operands = .{ Operand{ .Integer = 2 }, Operand.Nil, Operand.Nil } }));
    try expect(Instruction.eq(try parseInstruction("addi r1, 2"), Instruction{ .name = "addi", .operands = .{ Operand{ .Register = 1 }, Operand{ .Integer = 2 }, Operand.Nil } }));
    try expect(Instruction.eq(try parseInstruction("ldxb r2, [r1+12]"), Instruction{ .name = "ldxb", .operands = .{ Operand{ .Register = 2 }, Operand{ .Memory = .{ .base = 1, .offset = 12 } }, Operand.Nil } }));
    try expect(Instruction.eq(try parseInstruction("lsh r3, 0x8"), Instruction{ .name = "lsh", .operands = .{ Operand{ .Register = 3 }, Operand{ .Integer = 8 }, Operand.Nil } }));
    try expect(Instruction.eq(try parseInstruction("jne r3, 0x8, +37"), Instruction{ .name = "jne", .operands = .{ Operand{ .Register = 3 }, Operand{ .Integer = 8 }, Operand{ .Integer = 37 } } }));
    try expect(Instruction.eq(try parseInstruction("jne r3,0x8,+37"), Instruction{ .name = "jne", .operands = .{ Operand{ .Register = 3 }, Operand{ .Integer = 8 }, Operand{ .Integer = 37 } } }));
}

test "test_empty" {
    try expectEqual(parse(""), &[_]Instruction{});
}

test "test_lsh" {
    try expect(Instruction.eq(try parseInstruction("lsh r3, 0x20"), Instruction{ .name = "lsh", .operands = .{ Operand{ .Register = 3 }, Operand{ .Integer = 0x20 }, Operand.Nil } }));
}

test "test_ja" {
    try expect(Instruction.eq(try parseInstruction("ja +1"), Instruction{ .name = "ja", .operands = .{ Operand{ .Integer = 1 }, Operand.Nil, Operand.Nil } }));
}

test "test_ldxh" {
    try expect(Instruction.eq(try parseInstruction("ldxh r4, [r1+12]"), Instruction{ .name = "ldxh", .operands = .{ Operand{ .Register = 4 }, Operand{ .Memory = .{ .base = 1, .offset = 12 } }, Operand.Nil } }));
}

test "test_tcp_sack" {
    const src =
        \\ldxb r2, [r1+12]
        \\ldxb r3, [r1+13]
        \\lsh r3, 0x8
        \\or r3, r2
        \\mov r0, 0x0
        \\jne r3, 0x8, +37
        \\ldxb r2, [r1+23]
        \\jne r2, 0x6, +35
        \\ldxb r2, [r1+14]
        \\add r1, 0xe
        \\and r2, 0xf
        \\lsh r2, 0x2
        \\add r1, r2
        \\mov r0, 0x0
        \\ldxh r4, [r1+12]
        \\add r1, 0x14
        \\rsh r4, 0x2
        \\and r4, 0x3c
        \\mov r2, r4
        \\add r2, 0xffffffec
        \\mov r5, 0x15
        \\mov r3, 0x0
        \\jgt r5, r4, +20
        \\mov r5, r3
        \\lsh r5, 0x20
        \\arsh r5, 0x20
        \\mov r4, r1
        \\add r4, r5
        \\ldxb r5, [r4]
        \\jeq r5, 0x1, +4
        \\jeq r5, 0x0, +12
        \\mov r6, r3
        \\jeq r5, 0x5, +9
        \\ja +2
        \\add r3, 0x1
        \\mov r6, r3
        \\ldxb r3, [r4+1]
        \\add r3, r6
        \\lsh r3, 0x20
        \\arsh r3, 0x20
        \\jsgt r2, r3, -18
        \\ja +1
        \\mov r0, 0x1
        \\exit
    ;
    const expected = &[_]Instruction{
        Instruction{ .name = "ldxb", .operands = .{ Operand{ .Register = 2 }, Operand{ .Memory = .{ .base = 1, .offset = 12 } }, Operand.Nil } },
        Instruction{ .name = "ldxb", .operands = .{ Operand{ .Register = 3 }, Operand{ .Memory = .{ .base = 1, .offset = 13 } }, Operand.Nil } },
        Instruction{ .name = "lsh", .operands = .{ Operand{ .Register = 3 }, Operand{ .Integer = 8 }, Operand.Nil } },
        Instruction{ .name = "or", .operands = .{ Operand{ .Register = 3 }, Operand{ .Register = 2 }, Operand.Nil } },
        Instruction{ .name = "mov", .operands = .{ Operand{ .Register = 0 }, Operand{ .Integer = 0 }, Operand.Nil } },
        Instruction{ .name = "jne", .operands = .{ Operand{ .Register = 3 }, Operand{ .Integer = 8 }, Operand{ .Integer = 37 } } },
        Instruction{ .name = "ldxb", .operands = .{ Operand{ .Register = 2 }, Operand{ .Memory = .{ .base = 1, .offset = 23 } }, Operand.Nil } },
        Instruction{ .name = "jne", .operands = .{ Operand{ .Register = 2 }, Operand{ .Integer = 6 }, Operand{ .Integer = 35 } } },
        Instruction{ .name = "ldxb", .operands = .{ Operand{ .Register = 2 }, Operand{ .Memory = .{ .base = 1, .offset = 14 } }, Operand.Nil } },
        Instruction{ .name = "add", .operands = .{ Operand{ .Register = 1 }, Operand{ .Integer = 14 }, Operand.Nil } },
        Instruction{ .name = "and", .operands = .{ Operand{ .Register = 2 }, Operand{ .Integer = 15 }, Operand.Nil } },
        Instruction{ .name = "lsh", .operands = .{ Operand{ .Register = 2 }, Operand{ .Integer = 2 }, Operand.Nil } },
        Instruction{ .name = "add", .operands = .{ Operand{ .Register = 1 }, Operand{ .Register = 2 }, Operand.Nil } },
        Instruction{ .name = "mov", .operands = .{ Operand{ .Register = 0 }, Operand{ .Integer = 0 }, Operand.Nil } },
        Instruction{ .name = "ldxh", .operands = .{ Operand{ .Register = 4 }, Operand{ .Memory = .{ .base = 1, .offset = 12 } }, Operand.Nil } },
        Instruction{ .name = "add", .operands = .{ Operand{ .Register = 1 }, Operand{ .Integer = 20 }, Operand.Nil } },
        Instruction{ .name = "rsh", .operands = .{ Operand{ .Register = 4 }, Operand{ .Integer = 2 }, Operand.Nil } },
        Instruction{ .name = "and", .operands = .{ Operand{ .Register = 4 }, Operand{ .Integer = 60 }, Operand.Nil } },
        Instruction{ .name = "mov", .operands = .{ Operand{ .Register = 2 }, Operand{ .Register = 4 }, Operand.Nil } },
        Instruction{ .name = "add", .operands = .{ Operand{ .Register = 2 }, Operand{ .Integer = 4294967276 }, Operand.Nil } },
        Instruction{ .name = "mov", .operands = .{ Operand{ .Register = 5 }, Operand{ .Integer = 21 }, Operand.Nil } },
        Instruction{ .name = "mov", .operands = .{ Operand{ .Register = 3 }, Operand{ .Integer = 0 }, Operand.Nil } },
        Instruction{ .name = "jgt", .operands = .{ Operand{ .Register = 5 }, Operand{ .Register = 4 }, Operand{ .Integer = 20 } } },
        Instruction{ .name = "mov", .operands = .{ Operand{ .Register = 5 }, Operand{ .Register = 3 }, Operand.Nil } },
        Instruction{ .name = "lsh", .operands = .{ Operand{ .Register = 5 }, Operand{ .Integer = 32 }, Operand.Nil } },
        Instruction{ .name = "arsh", .operands = .{ Operand{ .Register = 5 }, Operand{ .Integer = 32 }, Operand.Nil } },
        Instruction{ .name = "mov", .operands = .{ Operand{ .Register = 4 }, Operand{ .Register = 1 }, Operand.Nil } },
        Instruction{ .name = "add", .operands = .{ Operand{ .Register = 4 }, Operand{ .Register = 5 }, Operand.Nil } },
        Instruction{ .name = "ldxb", .operands = .{ Operand{ .Register = 5 }, Operand{ .Memory = .{ .base = 4, .offset = 0 } }, Operand.Nil } },
        Instruction{ .name = "jeq", .operands = .{ Operand{ .Register = 5 }, Operand{ .Integer = 1 }, Operand{ .Integer = 4 } } },
        Instruction{ .name = "jeq", .operands = .{ Operand{ .Register = 5 }, Operand{ .Integer = 0 }, Operand{ .Integer = 12 } } },
        Instruction{ .name = "mov", .operands = .{ Operand{ .Register = 6 }, Operand{ .Register = 3 }, Operand.Nil } },
        Instruction{ .name = "jeq", .operands = .{ Operand{ .Register = 5 }, Operand{ .Integer = 5 }, Operand{ .Integer = 9 } } },
        Instruction{ .name = "ja", .operands = .{ Operand{ .Integer = 2 }, Operand.Nil, Operand.Nil } },
        Instruction{ .name = "add", .operands = .{ Operand{ .Register = 3 }, Operand{ .Integer = 1 }, Operand.Nil } },
        Instruction{ .name = "mov", .operands = .{ Operand{ .Register = 6 }, Operand{ .Register = 3 }, Operand.Nil } },
        Instruction{ .name = "ldxb", .operands = .{ Operand{ .Register = 3 }, Operand{ .Memory = .{ .base = 4, .offset = 1 } }, Operand.Nil } },
        Instruction{ .name = "add", .operands = .{ Operand{ .Register = 3 }, Operand{ .Register = 6 }, Operand.Nil } },
        Instruction{ .name = "lsh", .operands = .{ Operand{ .Register = 3 }, Operand{ .Integer = 32 }, Operand.Nil } },
        Instruction{ .name = "arsh", .operands = .{ Operand{ .Register = 3 }, Operand{ .Integer = 32 }, Operand.Nil } },
        Instruction{ .name = "jsgt", .operands = .{ Operand{ .Register = 2 }, Operand{ .Register = 3 }, Operand{ .Integer = -18 } } },
        Instruction{ .name = "ja", .operands = .{ Operand{ .Integer = 1 }, Operand.Nil, Operand.Nil } },
        Instruction{ .name = "mov", .operands = .{ Operand{ .Register = 0 }, Operand{ .Integer = 1 }, Operand.Nil } },
        Instruction{ .name = "exit", .operands = .{ Operand.Nil, Operand.Nil, Operand.Nil } },
    };
    const actual = try parse(src);
    try expectEqual(actual.len, expected.len);
    var index: u32 = 0;
    for (actual) |ins| {
        try expect(Instruction.eq(ins, expected[index]));
        index += 1;
    }
}
