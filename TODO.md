# Stuff To Do

*Note, this is usually out of date and this file will be removed soon.
For an up-to-date view, look at the current issues on github*.

## Correctness

- Priv Spec 1.12 compliance (mcounteren/scounteren, senvcfg, misa WARL,
  PMP stub with 0 entries — all done; remaining gaps are hardwired-zero
  items the spec explicitly permits omitting)

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

- RVA23 (RVA22 is complete).  V (RVV 1.0, VLEN=128) is implemented and gated
  behind `-V`; still missing are Zcb, Zcmop, Zimop, Zfa, Zvbb, Zawrs,
  Zihintntl, the pointer-masking extensions, Sscofpmf overflow interrupts,
  Ss/Smstateen, and (for RVA23S64) the hypervisor extension.  `satp` also
  still refuses Sv48/Sv57 even though the walker implements them.
- Maybe: implement the Bytedance 64K page proposal?

## Misc

- A more exciting rootfs; look at a Debian subset but it's huge
