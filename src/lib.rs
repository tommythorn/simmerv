#![allow(clippy::unreadable_literal)]

pub mod bounded;
pub mod cpu;
pub mod csr;
mod dag_decoder;
pub mod default_terminal;
pub mod device;
pub mod fp;
pub mod memory;
pub mod mmu;
pub mod riscv;
pub mod rvc;
pub mod terminal;

use crate::cpu::Cpu;
use crate::terminal::Terminal;
use anyhow::anyhow;
use anyhow::bail;
use fnv::FnvHashMap;
use intmap::IntMap;
use std::collections::BTreeMap;
use xmas_elf::sections::SectionData;
use xmas_elf::symbol_table::Entry;

/// RISC-V emulator. It emulates RISC-V CPU and peripheral devices.
///
/// Sample code to run the emulator.
/// ```ignore
/// // Creates an emulator with arbitary terminal
/// let mut emulator = Emulator::new(Box::new(DefaultTerminal::new()));
/// // Set up program content binary
/// emulator.load_image(program_content);
/// // Set up Filesystem content binary
/// emulator.setup_filesystem(fs_content);
/// // Go!
/// emulator.run();
/// ```
pub struct Emulator {
    pub cpu: Cpu,

    /// Stores mapping from symbol to virtual address
    pub symbol_map: FnvHashMap<String, u64>,

    uop_cache: IntMap<i64, cpu::Uop>,

    /// The address where data will be sent to terminal
    pub tohost_addr: u64,
}

impl Emulator {
    /// Creates a new `Emulator`. [`Terminal`](terminal/trait.Terminal.html)
    /// is internally used for transferring input/output data to/from
    /// `Emulator`.
    ///
    /// # Arguments
    /// * `terminal`
    #[must_use]
    pub fn new(terminal: Box<dyn Terminal>, capacity: usize) -> Self {
        Self {
            cpu: Cpu::new(terminal, capacity),

            symbol_map: FnvHashMap::default(),

            uop_cache: IntMap::new(),

            // These can be updated in load_image()
            tohost_addr: 0, // assuming tohost_addr is non-zero if exists
        }
    }

    /// Runs program set by `load_image()`. Calls `run_test()` if the program
    /// is [`riscv-tests`](https://github.com/riscv/riscv-tests).
    /// Otherwise calls `run_program()`.
    pub fn run(&mut self, trace: bool) {
        if trace {
            self.run_test();
        } else {
            self.run_program();
        }
    }

    /// Runs program set by `load_image()`. The emulator will run forever.
    pub fn run_program(&mut self) {
        loop {
            self.tick(52);
            if self.handle_htif() {
                break;
            }
        }
    }

    /// Method for running [`riscv-tests`](https://github.com/riscv/riscv-tests) program.
    /// The differences from `run_program()` are
    /// * Disassembles every instruction and dumps to terminal
    /// * The emulator stops when the test finishes
    /// * Displays the result message (pass/fail) to terminal
    /// # Panics
    /// It can panic
    #[allow(clippy::cast_possible_truncation)]
    pub fn run_test(&mut self) {
        let mut s = String::new();

        loop {
            let cycle = self.cpu.cycle;
            let insn_addr = self.cpu.pc;
            let insn_word = self.cpu.memop_disass(insn_addr);

            // XXX The disassemble API sucks
            s.clear();
            self.cpu.disassemble(&mut s);
            let exceptional = self.tick(1);

            print!("{cycle:5} {:1} {s:72}", u64::from(self.cpu.mmu.prv));
            if let Ok(word32) = insn_word {
                #[allow(clippy::cast_sign_loss)]
                let (insn, _) = cpu::decompress(word32 as u32);
                if let Some(decoded) = cpu::decode(&self.cpu.decode_dag, insn) {
                    let uop = (decoded.decode)(insn_addr, insn, decoded.execute);
                    if uop.rd.is_x0_dest() || exceptional {
                        println!();
                    } else {
                        println!("{:16x}", self.cpu.read_register(uop.rd));
                    }
                } else {
                    unreachable!("--can't decode {word32:08x}--");
                }
            } else {
                println!("--can't fetch from {insn_addr:08x}--");
            }

            if self.handle_htif() {
                break;
            }
        }
    }

    fn handle_htif(&mut self) -> bool {
        // The insanity: https://github.com/riscv-software-src/riscv-isa-sim/issues/364#issuecomment-607657754
        if self.tohost_addr == 0 {
            return false;
        }
        let tohost = self.cpu.get_mut_mmu().load_phys_u64(self.tohost_addr);
        if tohost == 0 {
            return false;
        }

        let device = tohost >> 56;
        let command = (tohost >> 48) & 0xff;
        let payload = tohost & 0xFFFF_FFFF_FFFF;
        if payload % 2 == 1 {
            // Riscv-tests terminates by writing the result * 2 + 1 to `tohost`
            // Zero means pass, anything else encodes where it failed.
            match payload / 2 {
                0 => println!("Test Passed"),
                exit_code => println!("Test Failed with {exit_code}"),
            }
            return true;
        }

        if device == 0 {
            // System call
            //  magic_mem[0] = which;
            //  magic_mem[1] = arg0;
            //  magic_mem[2] = arg1;
            //  magic_mem[3] = arg2;
            let which = self.cpu.get_mut_mmu().load_phys_u64(payload);
            let arg0 = self.cpu.get_mut_mmu().load_phys_u64(payload + 8);
            let arg1 = self.cpu.get_mut_mmu().load_phys_u64(payload + 16);
            let arg2 = self.cpu.get_mut_mmu().load_phys_u64(payload + 24);
            match which {
                0x40 => {
                    // write
                    assert_eq!(arg0, 1);
                    for i in 0..arg2 {
                        print!("{}", self.cpu.get_mut_mmu().load_phys_u8(arg1 + i) as char);
                    }
                }
                syscall => todo!("System call {syscall}"),
            }
        } else if device == 1 {
            assert_eq!(command, 1); // Command 0 is read a char, not supported
            print!("{}", command as u8 as char);
        }

        // Ack
        let _ = self.cpu.get_mut_mmu().store_phys_u64(self.tohost_addr, 0);
        let _ = self
            .cpu
            .get_mut_mmu()
            .store_phys_u64(self.tohost_addr + 64, 1); // from_host
        false
    }

    /// Runs CPU one cycle
    pub fn tick(&mut self, n: usize) -> bool {
        // XXX We should be able to set this arbitrarily high, but we seem
        // to hit a race condition and a Linux hang beyond this value
        self.cpu.run_soc(n, &mut self.uop_cache)
    }

    /// Sets up program run by the program. This method analyzes the passed
    /// content and configure CPU properly. If the passed contend doesn't
    /// seem ELF file, it panics. This method is expected to be called only
    /// once.
    ///
    /// # Arguments
    /// * `data` Program binary
    /// # Panics
    /// When Existential Angst Hits
    /// # Errors
    /// Elf loading issues are reported as errors
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    #[allow(clippy::verbose_bit_mask)]
    pub fn load_image(
        &mut self,
        name: &str,
        buf: &[u8],
        load_addr: Option<u64>,
        symbols: &mut BTreeMap<String, u64>,
    ) -> anyhow::Result<i64> {
        let elf_file = xmas_elf::ElfFile::new(buf);
        if elf_file.is_err() {
            let Some(load_addr) = load_addr else {
                bail!("Cannot load {name} as binary object as no load address was provided");
            };
            let size = buf.len();
            log::warn!(
                "Assuming the image is a binary and loading it to [{load_addr:#x}:{:#x}]",
                load_addr as usize + size
            );
            // XXX this should be a function
            self.cpu
                .mmu
                .memory
                .slice(load_addr as i64, size)
                .map_err(|()| anyhow!("load_image reaches outside memory"))?
                .copy_from_slice(buf);
            return Ok(load_addr as i64);
        }
        let elf_file = elf_file.map_err(|e| anyhow!(e))?;
        xmas_elf::header::sanity_check(&elf_file).map_err(|e| anyhow!(e))?;
        log::info!("ELF {:?}", elf_file.header.pt2.type_());
        let relocation_offset = match (elf_file.header.pt2.type_().as_type(), load_addr) {
            (xmas_elf::header::Type::SharedObject, Some(load_addr)) => {
                log::info!("Relocating it to {load_addr:#x}");
                load_addr
            }
            _ => 0,
        };
        let ph_iter = elf_file.program_iter();
        log::info!("ELF program headers");
        for sect in ph_iter {
            if !matches!(sect.get_type(), Ok(xmas_elf::program::Type::Load)) {
                log::trace!("Skipping {sect}");
                continue;
            }
            let addr = sect.physical_addr() + relocation_offset;
            let size = sect.mem_size();
            let xmas_elf::program::SegmentData::Undefined(data) =
                sect.get_data(&elf_file).map_err(|e| anyhow!(e))?
            else {
                // XXX error handling
                panic!("didn't find my data");
            };
            log::info!(
                "ELF program data section [{addr:x}, {:x}) (size {size} vs {})",
                addr + size,
                data.len()
            );

            // XXX such an insane stupid way to do this
            let mmu = self.cpu.get_mut_mmu();
            for (j, b) in data.iter().enumerate() {
                assert!(
                    mmu.store_phys_u8(addr + j as u64, *b).is_ok(),
                    "Program doesn't fit in memory: 0x{:016x}",
                    addr + j as u64
                );
            }
        }

        for sect in elf_file.section_iter().skip(1) {
            if let SectionData::SymbolTable64(data) =
                sect.get_data(&elf_file).map_err(|e| anyhow!(e))?
            {
                for datum in data {
                    let name = datum.get_name(&elf_file).map_err(|e| anyhow!(e))?;
                    if !name.is_empty() && datum.info() & 15 == 0 {
                        symbols.insert(name.to_string(), datum.value());
                    }
                }
            }
        }

        Ok((elf_file.header.pt2.entry_point() + relocation_offset) as i64)
    }

    /// Sets up filesystem. Use this method if program (e.g. Linux) uses
    /// filesystem. This method is expected to be called up to only once.
    ///
    /// # Arguments
    /// * `content` File system content binary
    pub fn setup_filesystem(&mut self, content: Vec<u8>) {
        self.cpu.get_mut_mmu().init_disk(content);
    }

    /// Sets up device tree. The emulator has default device tree configuration.
    /// If you want to override it, use this method. This method is expected to
    /// to be called up to only once.
    ///
    /// # Arguments
    /// * `content` DTB content binary
    pub fn setup_dtb(&mut self, content: &[u8]) { self.cpu.get_mut_mmu().init_dtb(content); }

    /// Enables or disables page cache optimization.
    /// Page cache optimization is experimental feature.
    /// See [`Mmu`](./mmu/struct.Mmu.html) for the detail.
    ///
    /// # Arguments
    /// * `enabled`
    pub fn enable_page_cache(&mut self, enabled: bool) {
        self.cpu.get_mut_mmu().enable_page_cache(enabled);
    }

    /// Returns mutable reference to `Terminal`.
    pub fn get_mut_terminal(&mut self) -> &mut Box<dyn Terminal> { self.cpu.get_mut_terminal() }

    /// Returns immutable reference to `Cpu`.
    #[must_use]
    pub const fn get_cpu(&self) -> &Cpu { &self.cpu }

    /// Returns mutable reference to `Cpu`.
    pub const fn get_mut_cpu(&mut self) -> &mut Cpu { &mut self.cpu }

    /// Returns a virtual address corresponding to symbol strings
    ///
    /// # Arguments
    /// * `s` Symbol strings
    #[must_use]
    pub fn get_addredd_of_symbol(&self, s: &String) -> Option<u64> {
        self.symbol_map.get(s).copied()
    }
}
