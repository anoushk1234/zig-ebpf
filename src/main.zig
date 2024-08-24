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
