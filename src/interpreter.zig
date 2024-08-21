const std = @import("std");
const ebpf = @import("ebpf.zig");

const MemAccessType = enum { store, load };

pub fn execute_program(alloc: std.mem.Allocator, program: []u8, mem: []u8, mbuff: []u8) !u64 {
    const stack: []u8 = try alloc.alloc(u8, ebpf.STACK_SIZE);
    defer alloc.free(stack);

    // R1 -> mem, R10 -> stack
    var reg = []u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, stack.ptr + stack.len };
    var pc = 0;

    while (pc * ebpf.INSN_SIZE < program.len) {
        // if (program[pc + 1] < program.len)
        // load ix
        const ix = ebpf.Instruction{ .op = program[ebpf.INSN_SIZE * pc], .dst = program[ebpf.INSN_SIZE * pc + 1] & 0x0f, .src = (program[ebpf.INSN_SIZE * pc + 1] & 0x0f) >> 4, .offset = std.mem.readInt(u16, program[ebpf.INSN_SIZE + 2 ..]), .imm = std.mem.readInt(i32, program[ebpf.INSN_SIZE + 4 ..]) };
        pc += 1;

        const dst = ix.dst;
        const src = ix.src;
        _ = src;
        switch (ix.op) {
            ebpf.LD_ABS_B => {
                // load data ptr
                const d = mem.ptr + ix.imm;
                // check mem bounds
                check_mem(d, mbuff, mem, pc, MemAccessType.load, 8, stack);
                // return data ptr
                reg[0] = dst;
            },
            else => {
                return VmError.InvalidOpCode;
            },
        }
    }

    return 0;
}
const VmError = error{ OutOfBoundsMemoryAccess, InvalidInstructionAddress, InvalidOpCode };

fn check_mem(addr: u64, mbuf: []u8, mem: []u8, inst_ptr: u64, op_type: MemAccessType, len: u64, stack: []u8) !void {
    _ = op_type;
    _ = inst_ptr;
    // Check if new memory being loaded or stored is trying to access memory out of bounds.
    if (addr + len <= mem.ptr + mem.len and addr <= mem.ptr) {
        return;
    }
    if (addr + len <= mbuf.ptr + mbuf.len and addr <= mbuf.ptr) {
        return;
    }
    if (stack.ptr <= addr and addr + len <= stack.ptr + stack.len) {
        return;
    }
    return VmError.OutOfBoundsMemoryAccess;
}
