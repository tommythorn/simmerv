# Stuff To Do

## Correctness

- The whole CSR handling is very suspect
  The access checks looks broken and we shouldn't have a CSR array but instead
  individually implement CSR registers we support and trap access to everything else.
- Pass all of riscv-test
- Pass all of riscof
- Fix Ubuntu boot (still unclear why it segfaults)
- Fix U-boot boot (still unclear why it crashes)
- Fix Geekbench/rustc/gdb (still unclear why it segfaults crashes)

## Performance

- Idea: keep all registers in unified 128 entry RF, 32 X, 32 F, r[64] is r0 sink.
- Idea: avoid a branch by mapping x0 to a dummy write-only register:
       #[inline(always)]
       fn remap_r0_to_r64(r: u8) {(r + 63 & 63) + 1}
  Using r64 here with the assumption of a unified register file.

- A SW TLB might be helpful, but Takahiro already had something like
  that which I haven't vetted for correctness.

- Block assignments to x0, assert that it's always zero.  Don't blindly write x0 = 0
- Sign extension in parse_format... is insane
- Lookup of instructions return an index!? just to address it again
- Go though all explicit usage of cpu.f[] and look for mistakes
- cpu, work, address -> (address, work), cpu
- lowercase name:
- provide a proper disassembler
- Peripherals should be optimized for i64 access?  If so, how do they
  behave on smaller accesses?  Side effects?
- need to cross check the read/write CSR behavior against Dromajo as it seems suspect
- handle_interrupt to use clz to optimize the lookup
- Do Not Keep the file system image in memory (however this raises the
  question of how to handle this for WASM).
- Sleep in WASM while waiting for input rather than burn cycles (this
  has proven slightly more tricky)

## Code Simplicify

- keep all values i64; it's the natural type for the registers and
  keeping all 64-bit values i64 means less casting around.  However we
  have to be careful about right shifts and relative comparisons, so
  take small steps and test judiciously.

## Features

- Implement the B set
- Implement Svnapot support
- Maybe: implement the Bytedance 64K page proposal?
- Snitch extensions
