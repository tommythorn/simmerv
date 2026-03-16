# Stuff To Do

*Note, this is usually out of date and this file will be removed soon.
For an up-to-date view, look at the current issues on github*.

## Correctness

- Pass all of riscv-test (status: debug, svnapot, and lots of FP.
  Might punt on debug and svnapot for now)

- Pass all of riscof

- Fix U-boot boot (still unclear why it crashes)

## Performance

- Expand the uop cache to bb or trace cache

- Sleep while waiting for input rather than burn cycles (this
  has proven slightly more tricky).  Especially important for WASM

- Do Not Keep the file system image in memory (however this raises the
  question of how to handle this for WASM).

- A SW TLB might be helpful, but Takahiro already had something like
  that which I haven't vetted for correctness.

- provide a proper disassembler

- handle_interrupt to use clz to optimize the lookup

## Features

- Implement the B set (Zba and Zicond done)
- Implement Svnapot support
- RVA23
- Maybe: implement the Bytedance 64K page proposal?

## Misc

- Update OpenSBI, Linux to latest
- A more exciting rootfs; look at a Debian subset but it's huge
