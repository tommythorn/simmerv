# Stuff To Do

## Correctness

- CSR handling is still a bit suspect
  The access checks looks broken and we shouldn't have a CSR array but instead
  individually implement CSR registers we support and trap access to everything else.
  need to cross check the read/write CSR behavior against Dromajo

- Go though all explicit usage of cpu.f[] and look for mistakes

- Pass all of riscv-test (status: debug, svnapot, and lots of FP.
  Might punt on debug and svnapot)

- Pass all of riscof
- Fix Ubuntu boot (still unclear why it segfaults)
- Fix U-boot boot (still unclear why it crashes)
- Fix Geekbench/rustc/gdb (still unclear why it segfaults crashes)

## Performance

- Sleep while waiting for input rather than burn cycles (this
  has proven slightly more tricky).  Especially important for WASM

- Do Not Keep the file system image in memory (however this raises the
  question of how to handle this for WASM).

- Block assignments to x0, assert that it's always zero.  Don't blindly write x0 = 0
  Idea: keep all registers in unified 128 entry RF, 32 X, 32 F, r[64] is r0 sink.
- Idea: avoid a branch by mapping x0 to a dummy write-only register:
       #[inline(always)]
       fn remap_r0_to_r64(r: u8) {(r + 63 & 63) + 1}
  Using r64 here with the assumption of a unified register file.

- A SW TLB might be helpful, but Takahiro already had something like
  that which I haven't vetted for correctness.

- Sign extension in parse_format... is insane
- cpu, work, address -> (address, work), cpu
- lowercase instruction names
- provide a proper disassembler
- Peripherals should be optimized for i64 access?  If so, how do they
  behave on smaller accesses?  Side effects?
- handle_interrupt to use clz to optimize the lookup

- Finally, the whole point of this: uop/bb/trace cache


## Code Simplicify

- ONGOING: keep all values i64; it's the natural type for the
  registers and keeping all 64-bit values i64 means less casting
  around.  However we have to be careful about right shifts and
  relative comparisons, so take small steps and test judiciously.

## Features

- Allow for control charactors to be passed through like Ctrl-C, Ctrl-Z etc.
- Checkpoint save & restore
- Implement the B set (Zba and Zicond done)
- Implement Svnapot support
- Maybe: implement the Bytedance 64K page proposal?
- Snitch extensions

## Misc

- Update OpenSBI, Linux to latest
- A more exciting rootfs; look at a Debian subset but it's huge
