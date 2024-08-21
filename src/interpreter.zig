const std = @import("std");
const ebpf = @import("ebpf.zig");

pub fn execute_program(alloc: std.mem.Allocator, program: []u8, mem: []u8, mbuff: []u8) !u64 {
    _ = mbuff;
    _ = mem;
    _ = program;

    const stack: []u8 = try alloc.alloc(u8, ebpf.STACK_SIZE);
    defer alloc.free(stack);

    // R1 -> mem, R10 -> stack
    var reg = []u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, stack.ptr + stack.len};
    _ = reg;

    return 0;
}
