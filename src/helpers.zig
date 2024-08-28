const std = @import("std");
const ebpf = @import("ebpf.zig");

pub fn debug_print_ix(ix: *const ebpf.Instruction) void {
    std.log.warn("Instruction: op = {x}, dst = {d}, src = {d}, offset = {d}, imm = {d}\n", .{ ix.op, ix.dst, ix.src, ix.offset, ix.imm });
}

pub fn debug_print_vm_state(reg: []const u64, pc: usize, src: u8, dst: u8) void {
    std.log.warn("VM State: pc = {}\n", .{pc});
    std.log.warn("Registers:\n", .{});
    for (reg, 0..) |value, index| {
        std.log.warn("  reg[{}] = {d}\n", .{ index, value });
    }
    std.log.warn("src = {d}, dst = {d}\n", .{ src, dst });
}
