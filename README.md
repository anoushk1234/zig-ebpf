# eBPF in Zig ⚡️

This is a wip implementation of eBPF in native Zig inspired by Quentin Monnet's [rbpf](https://github.com/qmonnet/rbpf/). This is different from existing zig eBPF libraries as it implements the ISA natively in zig without depending on libbpf or any C modules.

## What works
- [x] 64-bit ALU operations
- [x] Memory operations
- [x] Byteswap operations
- [ ] Branch instructions
- [x] Syscalls
- [ ] JIT Compiler
- [ ] Assembler
- [x] Disassembler
- [ ] Unit Tests & Fuzzing

## Why
Short answer: I was bored

Long answer: I wanted to work on something low level and complex, and also I really like Zig and wanted an excuse to write a large-ish project in it. I was inspired by Quentin Monnet and Solana Labs's work in rbpf and thought there should be a native Zig eBPF implementation. So I wanted to learn, experiment and have some fun in open source.

## Contribution and Feedback
The author of this repo is new to Zig so if you feel there can be some improvements in making the code more idiomatic then PRs are welcome!

Following in the footsteps of rbpf, this project expects new commits to be coveryed by the [Developer's Ceritificate of Origin](https://wiki.linuxfoundation.org/dco).

## License
zig-ebpf is distributed under both MIT License and Apache License(Version 2.0).
 
