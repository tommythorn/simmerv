# Stuff To Do

## Correctness
- Pass all of riscv-test
- Pass all of riscof

## Performance

- The tick is the biggest problem.  It is absolutely bonkers all the
  stuff that runs every cycle!!  It should only be instruction
  execution with the occasional (say, every 1000th cycle) check on
  peripherals!  No bloddy wonder this is so slow.

  Here's the current state:

```
    fn Emulator::run_program(&mut self) {loop {self.cpu.tick();}}
    fn Cpu::tick(&mut self) {
        let instruction_address = self.pc as u64;
        if let Err(e) = self.run_cpu_tick() {
            self.handle_exception(&e, instruction_address); }
        self.mmu.tick(&mut self.csr[CSR_MIP as usize]);
        self.handle_interrupt(self.pc);
        self.clock = self.clock.wrapping_add(1);
        self.write_csr_raw(CSR_CYCLE, self.clock * 8);}
    fn Cpu::run_cpu_tick(&mut self) -> Result<(), Trap> {
        if self.wfi { .. }
        let original_word = self.fetch()?;
        let instruction_address = self.pc as u64;
        let word = decompress(self.pc, original_word);
        ...
```

  The primary problem here is that we exercise the devices Every
  Single Tick.  What we need is something more of the lines of:

```
    fn Emulator::run_program(&mut self) {self.cpu.run_soc()}

    fn Cpu::run_soc(&mut self) {
        while !self.terminated {
            if !self.waiting_for_interrupt() {
                self.cpu_run(self.clint.mip, &mut cycle, cycle + N_CPU_CYCLES); }
            self.mmu.run(); }

    fn Cpu::run_cpu(&mut self, mip, &mut cycle, limit) {
        self.mip = mip;
        self.handle_interrupt(); // We only service interrupt once per run_cpu
        let mut pc = self.pc;
        while cycle < limit {
            cycle += 1;
            self.csr_cycle = cycle;
            match self.fetch(pc) {
                Ok(insn) => {
                   let (insn, npc) = decompress(pc, insn);
                   let decoded = self.decode(pc, insn)
                   pc = (decoded.operation)(self, pc, insn, npc); }, // Handles traps as well
                Trap(trap) => pc = self.handle_trap(trap, pc),}}
        self.pc = pc;}
```

  This is a huge change so be sure to stage small steps
  - eliminate self.pc (we should never read or set it outside run_cpu); make instruction executer return npc.
    - A lot of test code relies on update_pc which sets self.pc

  - Make instruction handler handle traps directly

  TBD: how does MMU/CLINT/PLIC depend on tick?
  TBD: can we move mmu out of Cpu?
  TBD: do we exit run_cpu when we change priviledge levels, virtual mappings, etc?
  TBD: How do we expose a read-only cycle to everyone (and only cpu can change)? (XXX above is awkward)
  TBD: is it really possible to not update MIP for a long time?

- Idea: keep all registers in unified 128 entry RF, 32 X, 32 F, r[64] is r0 sink.
- Idea: avoid a branch by having parse_format_ map f to f+32, and r0 to r64
       #[inline(always)]
       fn remap_r0_to_r64(r: u8) {(r + 63 & 63) + 1}

- A SW TLB might be helpful, but Takahiro already had something like
  that which I haven't vetted for correctness.

- why is clock advanced at 8X the rate?  I think it's some misunderstanding
  of the relationship between mtime and mcycle
- Block assignments to x0, assert that it's always zero.  Don't blindly write x0 = 0
- Sign extension in parse_format... is insane
- Lookup of instructions return an index!? just to address it again
- Go though all explicit usage of cpu.f[] and look for mistakes
- cpu, work, address -> (address, work), cpu
- lowercase name:
- provide a proper disassembler
- track cycle in the CPU only
- Clint tick -> advance_time(clock)  (should MIP be owned by Clint?)
- Peripherals should be optimized for i64 access?  If so, how do they
  behave on smaller accesses?  Side effects?
- read_csr_raw should return exception if unsupported CSR are accessed
- need to cross check the read/write CSR behavior against Dromajo as it seems suspect
- handle_interrupt to use clz to optimize the lookup
- Do Not Keep the file system image in memory (however this raises the
  question of how to handle this for WASM).

## Code Simplicify

- keep all values i64; it's the natural type for the registers and
  keeping all 64-bit values i64 means less casting around.  However we
  have to be careful about right shifts and relative comparisons, so
  take small steps and test judiciously.

## Features

- Implement the B set
- Implement the Sv
- Maybe: implement the Bytedance 64K page proposal?
