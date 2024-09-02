const std = @import("std");
const testing = std.testing;
const assembler = @import("zig-ebpf").assembler;

fn expectEqualBytes(expected: []const u8, actual: []const u8) !void {
    try testing.expectEqual(expected.len, actual.len);
    var i: usize = 0;
    while (i < expected.len) : (i += 1) {
        try testing.expectEqual(expected[i], actual[i]);
    }
}

test "assembler - add64" {
    const src = "add64 r1, 0x5";
    const expected = &[_]u8{ 0x07, 0x01, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqualBytes(expected, result);
}

test "assembler - mov64" {
    const src = "mov64 r2, 0x32";
    const expected = &[_]u8{ 0xb7, 0x02, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqualBytes(expected, result);
}

test "assembler - mov64 reg" {
    const src = "mov64 r1, r0";
    const expected = &[_]u8{ 0xbf, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqualBytes(expected, result);
}

test "assembler - be16" {
    const src = "be16 r0";
    const expected = &[_]u8{ 0xdc, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqualBytes(expected, result);
}

test "assembler - neg64" {
    const src = "neg64 r2";
    const expected = &[_]u8{ 0x87, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqualBytes(expected, result);
}

test "assembler - exit" {
    const src = "exit";
    const expected = &[_]u8{ 0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqualBytes(expected, result);
}

test "assembler - full program" {
    const src =
        \\add64 r1, 0x5
        \\mov64 r2, 0x32
        \\mov64 r1, r0
        \\be16 r0
        \\neg64 r2
        \\exit
    ;

    const expected = &[_]u8{
        0x07, 0x01, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
        0xb7, 0x02, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00,
        0xbf, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xdc, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
        0x87, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqualBytes(expected, result);
}

test "assembler - invalid instruction" {
    const src = "invalid r1, 0x5";
    const result = assembler.assemble(src);
    try testing.expectError(assembler.AssemblerError.InvalidInstruction, result);
}

test "assembler - invalid operand" {
    const src = "add64 r1, invalid";
    const result = assembler.assemble(src);
    try testing.expectError(assembler.AssemblerError.InvalidOperand, result);
}

test "assembler - out of memory" {
    const src =
        \\add64 r1, 0x5
        \\mov64 r2, 0x32
        \\mov64 r1, r0
        \\be16 r0
        \\neg64 r2
        \\exit
    ;
    const allocator = std.testing.allocator;
    allocator.free(src);
    const result = assembler.assemble(src);
    try testing.expectError(assembler.AssemblerError.OutOfMemory, result);
}
