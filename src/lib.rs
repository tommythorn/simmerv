#![allow(clippy::unreadable_literal)]

pub mod bounded;
pub mod buffered_serial_backend;
pub mod cpu;
pub mod csr;
pub mod device;
pub mod fp;
pub mod generated_riscv_decoder;
pub mod mmu;
pub mod native_fp;
pub mod new_decoder;
pub mod riscv;
pub mod riscv_decoding;
pub mod riscv_insns;
pub mod serial_backend;

use crate::cpu::Cpu;
use crate::device::Dtb;
use crate::device::virtio_block_disk::VirtioBlockDisk;
use crate::mmu::Mmu;
use crate::serial_backend::SerialBackend;
use anyhow::anyhow;
use anyhow::bail;
use fnv::FnvHashMap;
use intmap::IntMap;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use xmas_elf::sections::SectionData;
use xmas_elf::symbol_table::Entry;

/// RISC-V emulator. It emulates RISC-V CPU and peripheral devices.
///
/// Sample code to run the emulator.
/// ```ignore
/// // Creates an emulator with arbitary terminal
/// let mut emulator = Emulator::new(Box::new(BufferedSerialBackend::new()));
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

    uop_cache: IntMap<u64, cpu::Uop>,

    /// The address where data will be sent to terminal
    pub tohost_addr: u64,

    /// Set to `true` to break out of the run loop (e.g. from the exit menu).
    pub exit_flag: Arc<AtomicBool>,

    /// When `true`, log a message to stderr each time a snapshot is written.
    pub verbose: Arc<AtomicBool>,
}

impl Emulator {
    /// Creates a new `Emulator` with the standard `SoC` configuration.
    ///
    /// # Arguments
    /// * `backend` — the serial I/O implementation
    /// * `capacity` — RAM size in bytes
    #[must_use]
    pub fn new(backend: Box<dyn SerialBackend>, capacity: usize) -> Self {
        let mut mmu = Mmu::new();
        // RAM regions must be added before I/O devices so the dispatch fast-path
        // hits on the first iteration.  Primary RAM first, then secondary.
        mmu.add_memory(0x8000_0000, capacity);
        mmu.add_memory(0x7000_0000, 1024 * 1024);
        mmu.attach_uart(backend);

        #[allow(clippy::cast_possible_truncation)]
        let dtb_size = (Mmu::DTB_END - Mmu::DTB_BASE) as usize;
        let mut dtb_data = vec![0u8; dtb_size];
        let dtb_content = include_bytes!("./device/dtb.dtb");
        dtb_data[..dtb_content.len()].copy_from_slice(dtb_content);
        mmu.add_device(Mmu::DTB_BASE..Mmu::DTB_END, Box::new(Dtb::new(dtb_data)));
        mmu.add_device(
            Mmu::VIRTIO_BASE..Mmu::VIRTIO_END,
            Box::new(VirtioBlockDisk::new(Vec::new(), Mmu::VIRTIO_IRQ)),
        );
        Self {
            cpu: Cpu::new(mmu),

            symbol_map: FnvHashMap::default(),

            uop_cache: IntMap::new(),

            // These can be updated in load_image()
            tohost_addr: 0, // assuming tohost_addr is non-zero if exists

            exit_flag: Arc::new(AtomicBool::new(false)),
            verbose: Arc::new(AtomicBool::new(false)),
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
            self.tick(6);
            if self.handle_htif() || self.exit_flag.load(Ordering::Relaxed) {
                break;
            }
        }
    }

    /// Runs program with periodic snapshots written to disk.
    ///
    /// # Arguments
    /// * `interval` — number of ticks between snapshots
    /// * `base` — base filename; snapshots are named `base.0`, `base.1`, etc.
    pub fn run_with_periodic_snapshots(&mut self, interval: usize, base: &str) {
        let mut snap_counter: usize = 0;
        let mut snap_num: usize = 0;
        loop {
            self.tick(6);
            if self.handle_htif() || self.exit_flag.load(Ordering::Relaxed) {
                break;
            }
            snap_counter += 6;
            if snap_counter >= interval {
                snap_counter = 0;
                let path = format!("{base}.{snap_num}");
                snap_num += 1;
                self.write_snapshot_verbose(&path);
            }
        }
    }

    fn write_snapshot_verbose(&self, path: &str) {
        self.write_snapshot(path)
            .unwrap_or_else(|e| eprintln!("snapshot failed: {e}"));
        if self.verbose.load(Ordering::Relaxed) {
            eprintln!("snapshot → {path} [seqno={}]", self.cpu.seqno);
        }
    }

    /// Write a snapshot of the current machine state to `path`.
    ///
    /// The snapshot body is brotli-compressed; the magic is `SIMMERVC2`.
    ///
    /// # Errors
    /// Returns an error if the file cannot be written.
    pub fn write_snapshot(&self, path: &str) -> anyhow::Result<()> {
        let mut state = Vec::new();
        self.cpu.write_state(&mut state);

        let mut data = b"SIMMERVC3".to_vec();
        {
            let params = brotli::enc::BrotliEncoderParams {
                quality: 5,
                ..Default::default()
            };
            brotli::BrotliCompress(&mut state.as_slice(), &mut data, &params)
                .map_err(|e| anyhow!("brotli compress: {e}"))?;
        }
        std::fs::write(path, &data).map_err(|e| anyhow!(e))
    }

    /// Load a snapshot produced by `write_snapshot`.
    ///
    /// The device list is reconstructed from the snapshot — there is no
    /// requirement that the emulator was started with matching devices.
    ///
    /// # Errors
    /// Returns an error if the data is not a valid snapshot or is corrupt.
    pub fn load_snapshot(&mut self, data: &[u8]) -> anyhow::Result<()> {
        if data.len() < 9 || &data[..9] != b"SIMMERVC3" {
            bail!("not a valid snapshot");
        }
        let mut state = Vec::new();
        brotli::BrotliDecompress(&mut &data[9..], &mut state)
            .map_err(|e| anyhow!("brotli decompress: {e}"))?;

        // Reclaim the serial backend before clearing the device list so we can
        // hand it to the freshly-constructed UART during restore.
        let mut uart_backend = self.cpu.mmu.take_uart_backend();

        self.uop_cache.clear();
        self.cpu
            .read_state(&state, |name, range| {
                use crate::device::Dtb;
                use crate::device::plic::Plic;
                use crate::device::uart::Uart;
                use crate::device::virtio_block_disk::VirtioBlockDisk;
                match name {
                    "NS16550A" => uart_backend
                        .take()
                        .map(|b| Box::new(Uart::new(b, 0)) as Box<dyn crate::device::MemoryMapped>),
                    "SiFive PLIC" => {
                        Some(Box::new(Plic::new()) as Box<dyn crate::device::MemoryMapped>)
                    }
                    #[allow(clippy::cast_possible_truncation)]
                    "DTB" => Some(
                        Box::new(Dtb::new(vec![0u8; (range.end - range.start) as usize]))
                            as Box<dyn crate::device::MemoryMapped>,
                    ),
                    "VirtIO Block" => Some(Box::new(VirtioBlockDisk::new(Vec::new(), 1))
                        as Box<dyn crate::device::MemoryMapped>),
                    _ => None,
                }
            })
            .map_err(|()| anyhow!("snapshot corrupt"))
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
            let fflags = self.cpu.fflags;

            // XXX The disassemble API sucks
            s.clear();
            self.cpu.disassemble(&mut s);
            let exceptional = self.tick(1);

            print!("{cycle:5} {:1} {s:72}", u64::from(self.cpu.mmu.prv));
            if let Ok(insn) = insn_word {
                #[allow(clippy::cast_sign_loss)]
                let uop = cpu::decode(insn_addr, insn as u32);
                if !uop.rd.is_x0_dest() && !exceptional {
                    print!("{:16x}", self.cpu.read_register(uop.rd));
                    if self.cpu.fflags != fflags {
                        // XXX Belongs in fp.rs
                        // RISC-V name   bit   Hauser's SoftFP naming
                        //        NV     4     v   invalid
                        //        DZ     3     i   infinite ("divide by zero")
                        //        OF     2     o   overflow
                        //        UF     1     u   uderflow
                        //        NX     0     x   inexact
                        const FLAG_NAMES: [char; 5] = ['x', 'u', 'o', 'i', 'v'];
                        print!(" ");
                        for i in 0..5 {
                            let i = 4 - i;
                            print!(
                                "{}",
                                if self.cpu.fflags >> i & 1 == 0 {
                                    '.'
                                } else {
                                    FLAG_NAMES[i]
                                }
                            );
                        }
                    }
                }
                println!();
            } else {
                println!("--can't fetch from {insn_addr:08x}--");
            }

            if self.handle_htif() || self.exit_flag.load(Ordering::Relaxed) {
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
    ) -> anyhow::Result<u64> {
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
                .dma_slice(load_addr, size)
                .map_err(|()| anyhow!("load_image reaches outside memory"))?
                .copy_from_slice(buf);
            return Ok(load_addr);
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

        Ok(elf_file.header.pt2.entry_point() + relocation_offset)
    }

    /// Sets up filesystem. Use this method if program (e.g. Linux) uses
    /// filesystem. This method is expected to be called up to only once.
    ///
    /// # Arguments
    /// * `content` File system content binary
    pub fn setup_filesystem(&mut self, content: Vec<u8>) {
        self.cpu.get_mut_mmu().replace_device(
            Mmu::VIRTIO_BASE..Mmu::VIRTIO_END,
            Box::new(VirtioBlockDisk::new(content, Mmu::VIRTIO_IRQ)),
        );
    }

    /// Sets up device tree. The emulator has default device tree configuration.
    /// If you want to override it, use this method. This method is expected to
    /// to be called up to only once.
    ///
    /// # Arguments
    /// * `content` DTB content binary
    pub fn setup_dtb(&mut self, content: &[u8]) {
        #[allow(clippy::cast_possible_truncation)]
        let dtb_size = (Mmu::DTB_END - Mmu::DTB_BASE) as usize;
        let mut dtb = Dtb::new(vec![0u8; dtb_size]);
        dtb.load(content);
        self.cpu
            .get_mut_mmu()
            .replace_device(Mmu::DTB_BASE..Mmu::DTB_END, Box::new(dtb));
    }

    /// Enables or disables page cache optimization.
    /// Page cache optimization is experimental feature.
    /// See [`Mmu`](./mmu/struct.Mmu.html) for the detail.
    ///
    /// # Arguments
    /// * `enabled`
    pub fn enable_page_cache(&mut self, enabled: bool) {
        self.cpu.get_mut_mmu().enable_page_cache(enabled);
    }

    /// Returns mutable reference to the serial backend, if any.
    pub fn get_mut_serial_backend(&mut self) -> Option<&mut dyn SerialBackend> {
        self.cpu.get_mut_serial_backend()
    }

    /// Returns mutable reference to the backend (alias for
    /// `get_mut_serial_backend`).
    pub fn get_mut_backend(&mut self) -> Option<&mut dyn SerialBackend> {
        self.get_mut_serial_backend()
    }

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
