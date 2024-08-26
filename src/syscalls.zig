const std = @import("std");

pub const BPF_KTIME_GETNS_IDX: u32 = 0;
pub const BPF_TRACE_PRINTK_IDX: u32 = 1;

pub fn bpf_ktime_get_ns(_u1: u64, _u2: u64, _u3: u64, _u4: u64, _u5: u64) u64 {
    _ = _u5;
    _ = _u4;
    _ = _u3;
    _ = _u2;
    _ = _u1;

    return @as(u64, @intCast(std.time.nanoTimestamp()));
}
pub fn bpf_trace_printk(_u1: u64, _u2: u64, a3: u64, a4: u64, a5: u64) u64 {
    _ = _u2;
    _ = _u1;
    std.log.info("bpf_trace_printk: 0x{x}, 0x{x}, 0x{x}", .{ a3, a4, a5 });
    return "bpf_trace_printk: 0x, 0x, 0x\n".len + size_arg(a3) + size_arg(a4) + size_arg(a5);
}

pub fn size_arg(x: u64) u64 {
    if (x == 0) {
        return 1;
    } else {
        return @as(u64, @intFromFloat(@floor(std.math.log(f64, 16.0, @as(f64, @floatFromInt(x)))))) + 1;
    }
}
