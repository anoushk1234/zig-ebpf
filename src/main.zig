const std = @import("std");
const ebpf = @import("ebpf.zig");
const interpreter = @import("interpreter.zig");
const expect = std.testing.expect;
const syscalls = @import("syscalls.zig");

pub fn main() !void {}

test "simple_alu64_add" {
    var buffer: [512]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const allocator = fba.allocator();

    var syscalls_map = std.AutoHashMap(usize, ebpf.Syscall).init(std.testing.allocator);
    defer syscalls_map.deinit();
    var prog = [_]u8{ 183, 0, 0, 0, 0, 0, 0, 0, 183, 1, 0, 0, 1, 0, 0, 0, 183, 2, 0, 0, 2, 0, 0, 0, 183, 3, 0, 0, 3, 0, 0, 0, 183, 4, 0, 0, 4, 0, 0, 0, 183, 5, 0, 0, 5, 0, 0, 0, 183, 6, 0, 0, 6, 0, 0, 0, 183, 7, 0, 0, 7, 0, 0, 0, 183, 8, 0, 0, 8, 0, 0, 0, 183, 9, 0, 0, 9, 0, 0, 0, 7, 0, 0, 0, 23, 0, 0, 0, 15, 112, 0, 0, 0, 0, 0, 0, 23, 0, 0, 0, 13, 0, 0, 0, 31, 16, 0, 0, 0, 0, 0, 0, 39, 0, 0, 0, 7, 0, 0, 0, 47, 48, 0, 0, 0, 0, 0, 0, 55, 0, 0, 0, 2, 0, 0, 0, 63, 64, 0, 0, 0, 0, 0, 0, 149, 0, 0, 0, 0, 0, 0, 0 };
    const mem = [_]u8{ 0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd };
    const mbuff = [_]u8{0} ** 32;

    const result = try interpreter.execute_program(allocator, &prog, &mem, &mbuff, &syscalls_map);

    std.log.warn("aluadd: {d}", .{result});
    try expect(result == 0x2a);
}

test "simple_syscall_time" {
    var buffer: [512]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const allocator = fba.allocator();

    var syscalls_map = std.AutoHashMap(usize, ebpf.Syscall).init(std.testing.allocator);
    defer syscalls_map.deinit();

    var prog = [_]u8{
        0xb7, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // mov r1, 1
        0xb7, 0x02, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, // mov r2, 2
        0xb7, 0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, // mov r3, 3
        0xb7, 0x04, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, // mov r4, 4
        0xb7, 0x05, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, // mov r5, 5
        0x85, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // call 0
        0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
    };

    const mem = [_]u8{ 0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd };
    const mbuff = [_]u8{0} ** 32;

    try syscalls_map.put(0, &syscalls.gather_bytes);

    const result = try interpreter.execute_program(allocator, &prog, &mem, &mbuff, &syscalls_map);

    std.log.warn("simple_syscall_time: {d}", .{result});
    try expect(result == 0x0102030405);
}
