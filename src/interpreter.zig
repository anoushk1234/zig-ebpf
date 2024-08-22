const std = @import("std");
const ebpf = @import("ebpf.zig");

const MemAccessType = enum { store, load };

pub fn execute_program(alloc: std.mem.Allocator, program: []u8, mem: []u8, mbuff: []u8) !u64 {
    const stack: []u8 = try alloc.alloc(u8, ebpf.STACK_SIZE);
    defer alloc.free(stack);

    // R1 -> mem, R10 -> stack
    var reg = []u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, stack.ptr + stack.len };
    var pc = 0;

    if (mbuff.len == 0) {
        reg[1] = mbuff.ptr;
    } else if (mem.len == 0) {
        reg[1] = mem.ptr;
    }

    while (pc * ebpf.INSN_SIZE < program.len) {
        // if (program[pc + 1] < program.len)
        // load ix
        const ix = ebpf.Instruction.get_ix(program, pc);
        pc += 1;

        const dst = ix.dst;
        const src = ix.src;
        switch (ix.op) {
            ebpf.LD_ABS_B => {
                // load data ptr
                const d = mem.ptr + ix.imm;
                // check mem bounds
                check_mem(d, mbuff, mem, pc, MemAccessType.load, 8, stack);
                // return data ptr
                reg[0] = dst;
            },
            ebpf.LD_ABS_H => {
                // load data ptr
                const d = mem.ptr + ix.imm;
                // check mem bounds
                check_mem(d, mbuff, mem, pc, MemAccessType.load, 16, stack);
                // return data ptr
                reg[0] = d;
            },
            ebpf.LD_ABS_W => {
                // load data ptr
                const d = mem.ptr + ix.imm;
                // check mem bounds
                check_mem(d, mbuff, mem, pc, MemAccessType.load, 32, stack);
                // return data ptr
                reg[0] = d;
            },
            ebpf.LD_ABS_DW => {
                // load data ptr
                const d = mem.ptr + ix.imm;
                // check mem bounds
                check_mem(d, mbuff, mem, pc, MemAccessType.load, 64, stack);
                // return data ptr
                reg[0] = d;
            },
            ebpf.LD_IND_B => {
                const d = mem.ptr + reg[src] + ix.imm;
                check_mem(d, mbuff, mem, pc, MemAccessType.load, 8, stack);
                reg[0] = d;
            },
            ebpf.LD_IND_H => {
                const d = mem.ptr + reg[src] + ix.imm;
                check_mem(d, mbuff, mem, pc, MemAccessType.load, 16, stack);
                reg[0] = d;
            },
            ebpf.LD_IND_W => {
                const d = mem.ptr + reg[src] + ix.imm;
                check_mem(d, mbuff, mem, pc, MemAccessType.load, 32, stack);
                reg[0] = d;
            },
            ebpf.LD_IND_DW => {
                const d = mem.ptr + reg[src] + ix.imm;
                check_mem(d, mbuff, mem, pc, MemAccessType.load, 64, stack);
                reg[0] = d;
            },
            ebpf.LD_DW_IMM => {
                // Ix ptr already incremented at start of loop
                const next_ix = ebpf.Instruction.get_ix(program, pc);
                pc += 1;

                reg[dst] = ix.imm + ((@as(u64, next_ix.imm)) << 32);
            },
            ebpf.LD_B_REG => {
                const d = reg[src] + (ix.offset * @sizeOf(u8));
                check_mem(d, mbuff, mem, pc, MemAccessType.load, 1, stack);
                reg[dst] = d;
            },

            ebpf.LD_H_REG => {
                const d = reg[src] + (ix.offset * @sizeOf(u8));
                check_mem(d, mbuff, mem, pc, MemAccessType.load, 2, stack);
                reg[dst] = d;
            },
            ebpf.LD_W_REG => {
                const d = reg[src] + (ix.offset * @sizeOf(u8));
                check_mem(d, mbuff, mem, pc, MemAccessType.load, 4, stack);
                reg[dst] = d;
            },
            ebpf.LD_DW_REG => {
                const d = reg[src] + (ix.offset * @sizeOf(u8));
                check_mem(d, mbuff, mem, pc, MemAccessType.load, 8, stack);
                reg[dst] = d;
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
