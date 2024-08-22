const std = @import("std");
const ebpf = @import("ebpf.zig");

const MemAccessType = enum { store, load };
const SHIFT_MASK_64: u64 = 0x3f;

pub fn execute_program(alloc: std.mem.Allocator, program: []const u8, mem: []const u8, mbuff: []const u8) !u64 {
    const stack: []u8 = try alloc.alloc(u8, ebpf.STACK_SIZE);
    defer alloc.free(stack);

    // R1 -> mem, R10 -> stack
    var reg = [11]u64{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, @intFromPtr(stack.ptr + stack.len) };
    var pc: usize = 0;

    if (mbuff.len == 0) {
        reg[1] = @as(u64, @intFromPtr(mbuff.ptr));
    } else if (mem.len == 0) {
        reg[1] = @as(u64, @intFromPtr(mem.ptr));
    }

    while (pc * ebpf.INSN_SIZE < program.len) {
        // if (program[pc + 1] < program.len)
        // load ix
        const ix = try ebpf.Instruction.get_ix(program, pc);
        pc += 1;

        const dst = ix.dst;
        const src = ix.src;
        switch (ix.op) {
            ebpf.LD_ABS_B => {
                // load data ptr
                const d = @as(u64, @intCast(@intFromPtr(mem.ptr))) + @as(u64, @intCast(ix.imm));
                // check mem bounds
                try check_mem(d, mbuff, mem, pc, MemAccessType.load, 8, stack);
                // return data ptr
                reg[0] = dst;
            },
            ebpf.LD_ABS_H => {
                // load data ptr
                const d = @as(u64, @intCast(@intFromPtr(mem.ptr))) + @as(u64, @intCast(ix.imm));
                // check mem bounds
                try check_mem(d, mbuff, mem, pc, MemAccessType.load, 16, stack);
                // return data ptr
                reg[0] = d;
            },
            ebpf.LD_ABS_W => {
                // load data ptr
                const d = @as(u64, @intCast(@intFromPtr(mem.ptr))) + @as(u64, @intCast(ix.imm));
                // check mem bounds
                try check_mem(d, mbuff, mem, pc, MemAccessType.load, 32, stack);
                // return data ptr
                reg[0] = d;
            },
            ebpf.LD_ABS_DW => {
                // load data ptr
                const d = @as(u64, @intCast(@intFromPtr(mem.ptr))) + @as(u64, @intCast(ix.imm));
                // check mem bounds
                try check_mem(d, mbuff, mem, pc, MemAccessType.load, 64, stack);
                // return data ptr
                reg[0] = d;
            },
            ebpf.LD_IND_B => {
                const d = @as(u64, @intCast(@intFromPtr(mem.ptr))) + reg[src] + @as(u64, @intCast(ix.imm));
                // const d = mem.ptr + reg[src] + ix.imm;
                try check_mem(d, mbuff, mem, pc, MemAccessType.load, 8, stack);
                reg[0] = d;
            },
            ebpf.LD_IND_H => {
                const d = @as(u64, @intCast(@intFromPtr(mem.ptr))) + reg[src] + @as(u64, @intCast(ix.imm));
                // const d = mem.ptr + reg[src] + ix.imm;
                try check_mem(d, mbuff, mem, pc, MemAccessType.load, 16, stack);
                reg[0] = d;
            },
            ebpf.LD_IND_W => {
                const d = @as(u64, @intCast(@intFromPtr(mem.ptr))) + reg[src] + @as(u64, @intCast(ix.imm));
                // const d = mem.ptr + reg[src] + ix.imm;
                try check_mem(d, mbuff, mem, pc, MemAccessType.load, 32, stack);
                reg[0] = d;
            },
            ebpf.LD_IND_DW => {
                const d = @as(u64, @intCast(@intFromPtr(mem.ptr))) + reg[src] + @as(u64, @intCast(ix.imm));
                // const d = mem.ptr + reg[src] + ix.imm;
                try check_mem(d, mbuff, mem, pc, MemAccessType.load, 64, stack);
                reg[0] = d;
            },
            ebpf.LD_DW_IMM => {
                // Ix ptr already incremented at start of loop
                const next_ix = try ebpf.Instruction.get_ix(program, pc);
                pc += 1;

                reg[dst] = @as(u64, @intCast(ix.imm)) + ((@as(u64, @intCast(next_ix.imm))) << 32);
            },
            ebpf.LD_B_REG => {
                const d = reg[src] + (ix.offset * @sizeOf(u8));
                try check_mem(d, mbuff, mem, pc, MemAccessType.load, 1, stack);
                reg[dst] = d;
            },

            ebpf.LD_H_REG => {
                const d = reg[src] + (ix.offset * @sizeOf(u8));
                try check_mem(d, mbuff, mem, pc, MemAccessType.load, 2, stack);
                reg[dst] = d;
            },
            ebpf.LD_W_REG => {
                const d = reg[src] + (ix.offset * @sizeOf(u8));
                try check_mem(d, mbuff, mem, pc, MemAccessType.load, 4, stack);
                reg[dst] = d;
            },
            ebpf.LD_DW_REG => {
                const d = reg[src] + (ix.offset * @sizeOf(u8));
                try check_mem(d, mbuff, mem, pc, MemAccessType.load, 8, stack);
                reg[dst] = d;
            },

            // ALU-64
            ebpf.ADD64_IMM => reg[dst] = @addWithOverflow(reg[dst], ix.imm)[0],
            ebpf.ADD64_REG => reg[dst] = @addWithOverflow(reg[dst], reg[src])[0],
            ebpf.SUB64_IMM => reg[dst] = @subWithOverflow(reg[dst], ix.imm)[0],
            ebpf.SUB64_REG => reg[dst] = @subWithOverflow(reg[dst], reg[src])[0],
            ebpf.MUL64_IMM => reg[dst] = @mulWithOverflow(reg[dst], ix.imm)[0],
            ebpf.MUL64_REG => reg[dst] = @mulWithOverflow(reg[src], ix.imm)[0],
            ebpf.DIV64_IMM => {
                if (ix.imm == 0) {
                    reg[dst] = 0;
                } else {
                    reg[dst] /= ix.imm;
                }
            },
            ebpf.DIV64_REG => {
                if (reg[src] == 0) {
                    reg[dst] = 0;
                } else {
                    reg[dst] /= reg[src];
                }
            },
            ebpf.OR64_IMM => reg[dst] |= ix.imm,
            ebpf.OR64_REG => reg[dst] |= reg[src],
            ebpf.AND64_IMM => reg[dst] &= ix.imm,
            ebpf.AND64_REG => reg[dst] &= reg[src],
            ebpf.LSH64_IMM => reg[dst] <<= ix.imm & SHIFT_MASK_64,
            ebpf.LSH64_REG => reg[dst] <<= reg[src] & SHIFT_MASK_64,
            ebpf.RSH64_IMM => reg[dst] >>= ix.imm & SHIFT_MASK_64,
            ebpf.RSH64_REG => reg[dst] >>= reg[src] & SHIFT_MASK_64,
            ebpf.NEG64 => reg[dst] = -(reg[dst]),
            ebpf.MOD64_IMM => {
                if (ix.imm != 0) {
                    reg[dst] %= ix.imm;
                }
            },
            ebpf.MOD64_REG => {
                if (reg[src] != 0) {
                    reg[dst] %= reg[src];
                }
            },
            ebpf.XOR64_IMM => reg[dst] ^= ix.imm,
            ebpf.XOR64_REG => reg[dst] ^= reg[src],
            ebpf.MOV64_IMM => reg[dst] = ix.imm,
            ebpf.MOV64_REG => reg[dst] = reg[src],
            ebpf.ARSH64_IMM => reg[dst] = (reg[dst] >> (ix.imm & SHIFT_MASK_64)),
            ebpf.ARSH64_REG => reg[dst] = (reg[dst] >> (reg[src] & SHIFT_MASK_64)),

            ebpf.BE => {
                switch (ix.imm) {
                    // 16 => reg[dst] = std.mem.readInt(u64, reg[dst], .big),
                    else => {},
                }
            },
            else => {
                return VmError.InvalidOpCode;
            },
        }
    }

    return 0;
}
const VmError = error{ OutOfBoundsMemoryAccess, InvalidInstructionAddress, InvalidOpCode };

fn check_mem(addr: u64, mbuf: []const u8, mem: []const u8, inst_ptr: u64, op_type: MemAccessType, len: u64, stack: []const u8) !void {
    _ = op_type;
    _ = inst_ptr;
    // Check if new memory being loaded or stored is trying to access memory out of bounds.
    if (addr + len <= @intFromPtr(mem.ptr) + mem.len and addr <= @intFromPtr(mem.ptr)) {
        return;
    }
    if (addr + len <= @intFromPtr(mbuf.ptr + mbuf.len) and addr <= @intFromPtr(mbuf.ptr)) {
        return;
    }
    if (@intFromPtr(stack.ptr) <= addr and addr + len <= @intFromPtr(stack.ptr) + stack.len) {
        return;
    }
    return VmError.OutOfBoundsMemoryAccess;
}
