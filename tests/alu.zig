const std = @import("std");
const testing = std.testing;
const interpreter = @import("zig-ebpf").interpreter;
const expect = std.testing.expect;
const ebpf = @import("zig-ebpf").ebpf;

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

    // std.log.warn("aluadd: {d}", .{result});
    try expect(result == 0x2a);
}

test "simple_jsle" {
    var buffer: [512]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const allocator = fba.allocator();

    var syscalls_map = std.AutoHashMap(usize, ebpf.Syscall).init(std.testing.allocator);
    defer syscalls_map.deinit();
    var prog = [_]u8{ 183, 0, 0, 0, 0, 0, 0, 0, 183, 1, 0, 0, 254, 255, 255, 255, 101, 1, 4, 0, 255, 255, 255, 255, 183, 0, 0, 0, 1, 0, 0, 0, 183, 1, 0, 0, 0, 0, 0, 0, 101, 1, 1, 0, 255, 255, 255, 255, 183, 0, 0, 0, 2, 0, 0, 0, 149, 0, 0, 0, 0, 0, 0, 0 };

    const mem = [_]u8{ 0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd };
    const mbuff = [_]u8{0} ** 32;

    const result = try interpreter.execute_program(allocator, &prog, &mem, &mbuff, &syscalls_map);

    // std.log.warn("jsgt_imm: {d}", .{result});
    try expect(result == 0x1);
}

test "simple_jeq64_reg" {
    var buffer: [512]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&buffer);
    const allocator = fba.allocator();

    var syscalls_map = std.AutoHashMap(usize, ebpf.Syscall).init(std.testing.allocator);
    defer syscalls_map.deinit();

    var prog = [_]u8{ 183, 9, 0, 0, 1, 0, 0, 0, 103, 9, 0, 0, 32, 0, 0, 0, 183, 0, 0, 0, 0, 0, 0, 0, 183, 1, 0, 0, 10, 0, 0, 0, 183, 2, 0, 0, 11, 0, 0, 0, 29, 33, 5, 0, 0, 0, 0, 0, 183, 0, 0, 0, 1, 0, 0, 0, 183, 1, 0, 0, 11, 0, 0, 0, 79, 145, 0, 0, 0, 0, 0, 0, 29, 33, 1, 0, 0, 0, 0, 0, 183, 0, 0, 0, 2, 0, 0, 0, 149, 0, 0, 0, 0, 0, 0, 0 };
    const mem = [_]u8{ 0xaa, 0xbb, 0x11, 0x22, 0xcc, 0xdd };
    const mbuff = [_]u8{0} ** 32;

    const result = try interpreter.execute_program(allocator, prog[0..], &mem, &mbuff, &syscalls_map);

    std.log.warn("jeq_reg: {d}", .{result});
    try expect(result == 0x2);
}

