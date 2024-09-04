const std = @import("std");
const testing = std.testing;
const assembler = @import("zig-ebpf").assembler;

// Helper function to compare binary data and provide detailed error messages
fn expectEqual(expected: []const u8, actual: []const u8) !void {
    var expected_hex = std.ArrayList(u8).init(std.testing.allocator);
    defer expected_hex.deinit();

    for (expected, 0..) |byte, index| {
        if (index % 8 == 0 and index != 0) {
            try expected_hex.appendSlice("\n");
        }
        try std.fmt.format(expected_hex.writer(), "0x{x:0>2}", .{byte});
        if (index % 8 != 7 and index != expected.len - 1) {
            try expected_hex.appendSlice(", ");
        }
    }

    if (!std.mem.eql(u8, expected_hex.items, actual)) {
        std.debug.print("Mismatch:\nExpected: {s}\nActual:   {s}\n", .{
            expected_hex.items,
            actual,
        });
        return error.TestExpectedEqual;
    }
}

test "assembler - add64" {
    const src = "add64 r1, 0x5";
    const expected = &[_]u8{ 0x07, 0x01, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - mov64" {
    const src = "mov64 r2, 0x32";
    const expected = &[_]u8{ 0xb7, 0x02, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - mov64 reg" {
    const src = "mov64 r1, r0";
    const expected = &[_]u8{ 0xbf, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - be16" {
    const src = "be16 r0";
    const expected = &[_]u8{ 0xdc, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - neg64" {
    const src = "neg64 r2";
    const expected = &[_]u8{ 0x87, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - exit" {
    const src = "exit";
    const expected = &[_]u8{ 0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
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
    try expectEqual(expected, result);
}

test "assembler - invalid instruction" {
    const src = "invalid r1, 0x5";
    const result = assembler.assemble(src);
    try testing.expectError(assembler.AssemblerError.InvalidInstruction, result);
}

test "assembler - ja (jump always)" {
    const src = "ja +5";
    const expected = &[_]u8{ 0x05, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - jeq (jump if equal)" {
    const src = "jeq r1, 0x10, +3";
    const expected = &[_]u8{ 0x15, 0x01, 0x03, 0x00, 0x10, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - call" {
    const src = "call 5";
    const expected = &[_]u8{ 0x85, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - ldxw (load word)" {
    const src = "ldxw r0, [r1+0x10]";
    const expected = &[_]u8{ 0x61, 0x10, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - stxb (store byte)" {
    const src = "stxb [r2+0x5], r1";
    const expected = &[_]u8{ 0x73, 0x12, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - invalid register" {
    const src = "mov64 r11, 0x5";
    const result = assembler.assemble(src);
    try testing.expectError(assembler.AssemblerError.InvalidRegister, result);
}

test "assembler - mismatched operands" {
    const src = "add64 r1";
    const result = assembler.assemble(src);
    try testing.expectError(assembler.AssemblerError.InvalidOperands, result);
}

test "assembler - complex program" {
    const src =
        \\mov64 r6, r1
        \\ldxw r1, [r6+0]
        \\ldxw r2, [r6+4]
        \\ldxw r3, [r6+8]
        \\ldxw r4, [r6+12]
        \\add64 r3, r1
        \\add64 r3, r2
        \\add64 r3, r4
        \\stxw [r6+8], r3
        \\mov64 r0, 0
        \\exit
    ;

    const expected = &[_]u8{
        0xbf, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x61, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x61, 0x62, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x61, 0x63, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x61, 0x64, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0f, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0f, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0f, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x63, 0x36, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - sub64" {
    const src = "sub64 r1, 0x5";
    const expected = &[_]u8{ 0x17, 0x01, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - mul64" {
    const src = "mul64 r2, r3";
    const expected = &[_]u8{ 0x2f, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - div64" {
    const src = "div64 r4, 0x10";
    const expected = &[_]u8{ 0x37, 0x04, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - or64" {
    const src = "or64 r5, r6";
    const expected = &[_]u8{ 0x4f, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - and64" {
    const src = "and64 r7, 0xff";
    const expected = &[_]u8{ 0x57, 0x07, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - lsh64" {
    const src = "lsh64 r8, 4";
    const expected = &[_]u8{ 0x67, 0x08, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - rsh64" {
    const src = "rsh64 r9, r10";
    const expected = &[_]u8{ 0x7f, 0xa9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - mod64" {
    const src = "mod64 r1, 0x3";
    const expected = &[_]u8{ 0x97, 0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - xor64" {
    const src = "xor64 r2, r3";
    const expected = &[_]u8{ 0xaf, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - arsh64" {
    const src = "arsh64 r4, 2";
    const expected = &[_]u8{ 0xc7, 0x04, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - ldabsw" {
    const src = "ldabsw 0x10";
    const expected = &[_]u8{ 0x20, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - ldindw" {
    const src = "ldindw r1, 0x20";
    const expected = &[_]u8{ 0x40, 0x10, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - ldxdw" {
    const src = "ldxdw r2, [r3+0x8]";
    const expected = &[_]u8{ 0x79, 0x32, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - jeq" {
    const src = "jeq r1, 0x10, +5";
    const expected = &[_]u8{ 0x15, 0x01, 0x05, 0x00, 0x10, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - jgt" {
    const src = "jgt r2, r3, +10";
    const expected = &[_]u8{ 0x2d, 0x32, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - jge" {
    const src = "jge r4, 0x20, +15";
    const expected = &[_]u8{ 0x35, 0x04, 0x0f, 0x00, 0x20, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - jset" {
    const src = "jset r5, 0x1, +20";
    const expected = &[_]u8{ 0x45, 0x05, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - jsgt" {
    const src = "jsgt r6, r7, +25";
    const expected = &[_]u8{ 0x6d, 0x76, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - jsge" {
    const src = "jsge r8, 0x30, +30";
    const expected = &[_]u8{ 0x75, 0x08, 0x1e, 0x00, 0x30, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - jeq32" {
    const src =
        \\mov r9, 1
        \\lsh r9, 32
        \\mov32 r0, 0
        \\mov32 r1, 0xa
        \\mov32 r2, 0xb
        \\jeq32 r1, r2, +5
        \\mov32 r0, 1
        \\mov32 r1, 0xb
        \\or r1, r9
        \\jeq32 r1, r2, +1
        \\mov32 r0, 2
        \\exit
    ;

    const expected = &[_]u8{
        0xb7, 0x09, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // mov r9, 1
        0x67, 0x09, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, // lsh r9, 32
        0xb4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov32 r0, 0
        0xb4, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, // mov32 r1, 0xa
        0xb4, 0x02, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, // mov32 r2, 0xb
        0x1d, 0x21, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, // jeq32 r1, r2, +5
        0xb4, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // mov32 r0, 1
        0xb4, 0x01, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, // mov32 r1, 0xb
        0x4f, 0x91, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // or r1, r9
        0x1d, 0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // jeq32 r1, r2, +1
        0xb4, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, // mov32 r0, 2
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - ldxb (load byte)" {
    const src = "ldxb r0, [r1+0x5]";
    const expected = &[_]u8{ 0x71, 0x10, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - jne (jump if not equal)" {
    const src = "jne r1, 0x10, +3";
    const expected = &[_]u8{ 0x55, 0x01, 0x03, 0x00, 0x10, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - jslt (jump if signed less than)" {
    const src = "jslt r2, r3, +5";
    const expected = &[_]u8{ 0xcd, 0x32, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - ldabsb (load absolute byte)" {
    const src = "ldabsb 0x10";
    const expected = &[_]u8{ 0x30, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - ldindb (load indirect byte)" {
    const src = "ldindb r1, 0x20";
    const expected = &[_]u8{ 0x50, 0x10, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00 };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}

test "assembler - complex program with various instructions" {
    const src =
        \\mov r1, 0x1
        \\lsh r1, 32
        \\or r1, 0x2
        \\stxdw [r10-16], r1
        \\ldxdw r2, [r10-16]
        \\mov r3, 0x3
        \\mov r3, 0x4
        \\mov r3, 0x5
        \\add r3, r2
        \\mov r0, r3
        \\exit
    ;

    const expected = &[_]u8{
        0xb7, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // mov r1, 0x1
        0x67, 0x01, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, // lsh r1, 32
        0x47, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, // or r1, 0x2
        0x7b, 0x1a, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, // stxdw [r10-16], r1
        0x79, 0xa2, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, // ldxdw r2, [r10-16]
        0xb7, 0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, // mov r3, 0x3
        0xb7, 0x03, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, // mov r3, 0x4
        0xb7, 0x03, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, // mov r3, 0x5
        0x0f, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // add r3, r2
        0xbf, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r0, r3
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    };
    const result = try assembler.assemble(src);
    defer std.heap.page_allocator.free(result);
    try expectEqual(expected, result);
}
