const std = @import("std");
const interpreter = @import("zig-ebpf").interpreter;
const expect = std.testing.expect;
const syscalls = @import("zig-ebpf").syscalls;
const ebpf = @import("zig-ebpf").ebpf;

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

    // std.log.warn("simple_syscall_time: {d}", .{result});
    try expect(result == 0x0102030405);
}
