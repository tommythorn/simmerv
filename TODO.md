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

- RVA23.  See the checklist in README.md, which is kept current -- this entry
  went stale enough to be misleading (it still named `-V`, and listed Zcb,
  Zfa, Zvbb, Zawrs, Zihintntl and Sv48/Sv57 as missing long after they
  landed).  RVA23U64 is complete except pointer masking (`Supm`); what is
  left is RVA23S64: Sscofpmf, Ss/Smstateen and H.
- Maybe: implement the Bytedance 64K page proposal?

## Misc

- A more exciting rootfs; look at a Debian subset but it's huge
