const std = @import("std");
const ebpf = @import("ebpf.zig");
const interpreter = @import("interpreter.zig");
const expect = std.testing.expect;

pub fn main() !void {}

test "simple_alu64_add" {
    var buffer: [512]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const allocator = fba.allocator();

    //mov64 r0, 0
    //mov64 r1, 2
    //add64 r0, 1
    //add64 r0, r1
    //exit
    const prog = [_]u8{ 183, 0, 0, 0, 0, 0, 0, 0, 183, 1, 0, 0, 2, 0, 0, 0, 7, 0, 0, 0, 1, 0, 0, 0, 15, 16, 0, 0, 0, 0, 0, 0, 149, 0, 0, 0, 0, 0, 0, 0 };
    const mem = [_]u8{ 0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd };
    const mbuff = [_]u8{0} ** 32;

    const result = try interpreter.execute_program(allocator, &prog, &mem, &mbuff);

    try expect(result == 8);
}

test "simple_ja" {
    var pc: usize = 1;
    const prog = [_]u8{
        0xb7, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // mov r0, 1
        0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // ja +1
        0xb7, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, // mov r0, 2
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    };
    const ix = try ebpf.Instruction.get_ix(&prog, pc);
    interpreter.jump(&pc, &ix);
    std.log.warn("jump: {d}", .{pc});
    try expect(pc == 2);
}
