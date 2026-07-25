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
pub mod network_backend;
pub mod new_decoder;
pub mod riscv;
pub mod riscv_decoding;
pub mod riscv_insns;
pub mod serial_backend;
pub mod speedometer;
pub mod tlb;
pub mod uop_cache;
pub mod vector;

use crate::cpu::Cpu;
use crate::device::syscon::Syscon;
use crate::device::virtio_block_disk::VirtioBlockDisk;
use crate::device::virtio_net::VirtioNet;
use crate::mmu::Mmu;
use crate::network_backend::DummyNetworkBackend;
use crate::network_backend::NetworkBackend;
use crate::serial_backend::SerialBackend;
use crate::uop_cache::BbCache;
use crate::uop_cache::CacheMode;
use anyhow::anyhow;
use anyhow::bail;
use fnv::FnvHashMap;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use xmas_elf::sections::SectionData;
use xmas_elf::symbol_table::Entry;

/// Returns the physical base address for a DTB placed at the end of RAM,
/// padded to a 4 KiB page boundary.
const fn dtb_end_of_ram(ram_base: u64, ram_size: usize, dtb_len: usize) -> u64 {
    const PAGE: usize = 4096;
    let padded = (dtb_len + PAGE - 1) & !(PAGE - 1);
    ram_base + ram_size as u64 - padded as u64
}

/// Patch the `reg` property of the `memory@80000000` node in a Flattened Device
/// Tree (DTB) blob so that its size matches `memory_bytes`.
///
/// The DTB is expected to use two 32-bit cells for both address and size
/// (`#address-cells = <2>`, `#size-cells = <2>`), which is the format used by
/// all device trees in this project.  The function is a no-op on any blob that
/// does not match the expected structure.
#[allow(clippy::cast_possible_truncation)]
fn patch_dtb_memory(dtb: &mut [u8], memory_bytes: u64) -> anyhow::Result<u64> {
    fn read_u32(data: &[u8], off: usize) -> u32 {
        let bytes: [u8; 4] = data[off..off + 4].try_into().unwrap_or([0; 4]);
        u32::from_be_bytes(bytes)
    }
    fn write_u32(data: &mut [u8], off: usize, val: u32) {
        data[off..off + 4].copy_from_slice(&val.to_be_bytes());
    }

    if dtb.len() < 40 {
        bail!("too short");
    }
    if read_u32(dtb, 0) != 0xd00d_feed {
        bail!("bad magic");
    }

    let mut old = None;
    let off_dt_struct = read_u32(dtb, 8) as usize;
    let off_dt_strings = read_u32(dtb, 12) as usize;

    // Find the offset of the string "reg" in the strings block.
    let reg_nameoff = {
        let strings = &dtb[off_dt_strings..];
        let mut found = None;
        let mut i = 0;
        while i + 4 <= strings.len() {
            if strings[i..].starts_with(b"reg\0") {
                found = Some(i);
                break;
            }
            // Skip to next string.
            while i < strings.len() && strings[i] != 0 {
                i += 1;
            }
            i += 1;
        }
        match found {
            Some(off) => off,
            None => {
                bail!("found no reg");
            }
        }
    };

    // Walk the structure block looking for a node whose name starts with "memory".
    let mut pos = off_dt_struct;
    let mut depth = 0u32;
    let mut memory_depth = 0u32;
    let mut in_memory_node = false;

    loop {
        if pos + 4 > dtb.len() {
            bail!("found not reg here");
        }
        let token = read_u32(dtb, pos);
        pos += 4;
        match token {
            1 => {
                // FDT_BEGIN_NODE: null-terminated name follows, aligned to 4 bytes.
                let name_start = pos;
                while pos < dtb.len() && dtb[pos] != 0 {
                    pos += 1;
                }
                let name = &dtb[name_start..pos];
                pos += 1; // skip null
                pos = (pos + 3) & !3; // align
                depth += 1;
                if name.starts_with(b"memory") {
                    in_memory_node = true;
                    memory_depth = depth;
                }
            }
            2 => {
                // FDT_END_NODE
                if in_memory_node && depth == memory_depth {
                    in_memory_node = false;
                }
                depth = depth.saturating_sub(1);
            }
            3 => {
                // FDT_PROP: len (u32), nameoff (u32), value (len bytes, aligned).
                if pos + 8 > dtb.len() {
                    bail!("found not reg here");
                }
                let len = read_u32(dtb, pos) as usize;
                let nameoff = read_u32(dtb, pos + 4) as usize;
                pos += 8;
                // Patch: memory node, "reg" property, 2-cell address + 2-cell size = 16 bytes.
                if in_memory_node && nameoff == reg_nameoff && len == 16 {
                    if old.is_some() {
                        bail!("multiple memory entries");
                    }

                    let hi = read_u32(dtb, pos + 8);
                    let lo = read_u32(dtb, pos + 12);
                    old = Some(u64::from(hi) << 32 | u64::from(lo));
                    write_u32(dtb, pos + 8, (memory_bytes >> 32) as u32);
                    write_u32(dtb, pos + 12, memory_bytes as u32);
                }
                pos += (len + 3) & !3;
            }
            4 => {} // FDT_NOP
            _ => {
                // FDT_END (9) or unknown
                match old {
                    None => bail!("didn't find memory"),
                    Some(old) => return Ok(old),
                }
            }
        }
    }
}

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

    bb_cache: BbCache,

    /// The address where data will be sent to terminal
    pub tohost_addr: u64,

    /// RAM size in bytes (used to patch the device tree)
    memory_bytes: u64,

    /// Set to `true` to break out of the run loop (e.g. from the exit menu).
    pub exit_flag: Arc<AtomicBool>,

    /// Set by the syscon device when the guest writes the poweroff magic value.
    pub poweroff_flag: Arc<AtomicBool>,

    /// Set by the syscon device when the guest writes the reboot magic value.
    pub reset_flag: Arc<AtomicBool>,

    /// When `true`, print an execution trace line for every instruction.
    pub tracing_flag: Arc<AtomicBool>,

    /// When `true`, log a message to stderr each time a snapshot is written.
    pub verbose: Arc<AtomicBool>,
}

impl Emulator {
    /// Creates a new `Emulator` with the standard `SoC` configuration.
    ///
    /// # Arguments
    /// * `backend` — the serial I/O implementation
    /// * `capacity` — RAM size in bytes
    /// * `cache_entries` — total uop cache entries
    /// * `cache_mode` — direct-mapped or 2-way skew-associative
    ///
    /// # Panics
    /// Will panic if we couldn't patch the memory property of the dtb
    #[must_use]
    pub fn new(
        backend: Box<dyn SerialBackend>,
        capacity: usize,
        cache_entries: usize,
        cache_mode: CacheMode,
    ) -> Self {
        let mut mmu = Mmu::new();
        // RAM regions must be added before I/O devices so the dispatch fast-path
        // hits on the first iteration.  Primary RAM first, then secondary.
        mmu.add_memory(0x8000_0000, capacity);
        mmu.add_memory(0x7000_0000, 1024 * 1024);
        mmu.attach_uart(backend);

        let mut dtb = include_bytes!("./device/dtb.dtb").to_vec();
        let dtb_base = dtb_end_of_ram(0x8000_0000, capacity, dtb.len());
        let usable = dtb_base - 0x8000_0000;
        #[allow(clippy::expect_used)]
        patch_dtb_memory(&mut dtb, usable).expect("can't patch dtb");
        mmu.write_memory_at(dtb_base, &dtb);
        mmu.add_device(
            Mmu::VIRTIO_BASE..Mmu::VIRTIO_END,
            Box::new(VirtioBlockDisk::new(Mmu::VIRTIO_IRQ)),
        );
        mmu.add_device(
            Mmu::NET_BASE..Mmu::NET_END,
            Box::new(VirtioNet::new(Box::new(DummyNetworkBackend), Mmu::NET_IRQ)),
        );
        mmu.add_device(
            Mmu::VIRTIO2_BASE..Mmu::VIRTIO2_END,
            Box::new(VirtioBlockDisk::new(Mmu::VIRTIO2_IRQ)),
        );
        let poweroff_flag = Arc::new(AtomicBool::new(false));
        let reset_flag = Arc::new(AtomicBool::new(false));
        mmu.add_device(
            Mmu::SYSCON_BASE..Mmu::SYSCON_END,
            Box::new(Syscon::new(
                Arc::clone(&poweroff_flag),
                Arc::clone(&reset_flag),
            )),
        );
        let mut emulator = Self {
            cpu: Cpu::new(mmu),

            symbol_map: FnvHashMap::default(),

            bb_cache: BbCache::new(cache_entries, cache_mode),

            // These can be updated in load_image()
            tohost_addr: 0, // assuming tohost_addr is non-zero if exists

            memory_bytes: capacity as u64,

            exit_flag: Arc::new(AtomicBool::new(false)),
            poweroff_flag,
            reset_flag,
            tracing_flag: Arc::new(AtomicBool::new(false)),
            verbose: Arc::new(AtomicBool::new(false)),
        };
        emulator.cpu.set_dtb_base(dtb_base);
        emulator
    }

    /// Enable (or disable) the V vector extension.
    ///
    /// This is a machine-construction switch: it gates vector instruction
    /// decoding, the `misa` V bit and the vector CSRs.  When enabling it we
    /// also patch the built-in device tree's `riscv,isa` string so a guest
    /// kernel sees the extension; the replacement is deliberately the same
    /// length as the original so the blob's structure is untouched.
    pub fn set_vector_enabled(&mut self, on: bool) {
        const OLD: &[u8] = b"rv64imafdcsu\0";
        const NEW: &[u8] = b"rv64imafdcv\0\0";
        self.cpu.set_vector_enabled(on);
        if !on {
            return;
        }
        let dtb = include_bytes!("./device/dtb.dtb");
        if let Some(off) = dtb.windows(OLD.len()).position(|w| w == OLD) {
            let base = self.cpu.dtb_base + off as u64;
            self.cpu.get_mut_mmu().write_memory_at(base, NEW);
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

    fn machine_reset(&mut self) { self.cpu.soft_reset(); }

    /// Runs program set by `load_image()`. The emulator will run forever.
    /// When `tracing_flag` is set, prints a disassembly line for every
    /// instruction.
    pub fn run_program(&mut self) {
        // Arm the cosim store log now that the ELF loader is done (its stores are
        // excluded).
        crate::mmu::STORELOG_ARMED.store(true, Ordering::Relaxed);
        let mut s = String::new();
        loop {
            if self.tracing_flag.load(Ordering::Relaxed) {
                let cycle = self.cpu.cycle;
                let insn_addr = self.cpu.pc;
                let insn_word = self.cpu.memop_disass(insn_addr);
                let fflags = self.cpu.fflags;
                s.clear();
                self.cpu.disassemble(&mut s);
                let exceptional = self.tick_single();
                print!("{cycle:5} {:1} {s:72}", u64::from(self.cpu.mmu.prv));
                if let Ok(insn) = insn_word {
                    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                    let uop = cpu::decode(insn_addr, insn as u32, self.cpu.vector_enabled);
                    if !uop.rd.is_x0_dest() && !exceptional {
                        print!("{:16x}", self.cpu.read_register(uop.rd));
                        if self.cpu.fflags != fflags {
                            const FLAG_NAMES: [char; 5] = ['x', 'u', 'o', 'i', 'v'];
                            print!(" ");
                            for i in (0..5).rev() {
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
                    println!("--can't fetch from {insn_addr:016x}--");
                }
            } else {
                self.tick(600); // 600 is an arbitrary number
            }
            if self.handle_htif()
                || self.exit_flag.load(Ordering::Relaxed)
                || self.poweroff_flag.load(Ordering::Relaxed)
            {
                break;
            }
            if self.reset_flag.swap(false, Ordering::Relaxed) {
                self.machine_reset();
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
            if self.handle_htif()
                || self.exit_flag.load(Ordering::Relaxed)
                || self.poweroff_flag.load(Ordering::Relaxed)
            {
                break;
            }
            if self.reset_flag.swap(false, Ordering::Relaxed) {
                self.machine_reset();
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

        let mut data = b"SIMMERVC8".to_vec();
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
        if data.len() < 9 || &data[..9] != b"SIMMERVC8" {
            bail!("not a valid snapshot");
        }
        let mut state = Vec::new();
        brotli::BrotliDecompress(&mut &data[9..], &mut state)
            .map_err(|e| anyhow!("brotli decompress: {e}"))?;

        // Reclaim backends before clearing the device list so we can hand them
        // to the freshly-constructed devices during restore.
        let mut uart_backend = self.cpu.mmu.take_uart_backend();
        let mut net_backend = self.cpu.mmu.take_net_backend();

        self.bb_cache.clear();
        self.cpu
            .read_state(&state, |name, range| {
                use crate::device::uart::Uart;
                use crate::device::virtio_block_disk::VirtioBlockDisk;
                match name {
                    "NS16550A" => uart_backend
                        .take()
                        .map(|b| Box::new(Uart::new(b, 0)) as Box<dyn crate::device::MemoryMapped>),
                    "VirtIO Block" => {
                        // Two block disks share this name; pick the IRQ from the
                        // saved MMIO window. `restore_state` overwrites it, but
                        // this keeps the fresh device self-consistent.
                        let irq = if range.start == Mmu::VIRTIO2_BASE {
                            Mmu::VIRTIO2_IRQ
                        } else {
                            Mmu::VIRTIO_IRQ
                        };
                        Some(Box::new(VirtioBlockDisk::new(irq))
                            as Box<dyn crate::device::MemoryMapped>)
                    }
                    "VirtIO Net" => {
                        let backend = net_backend
                            .take()
                            .unwrap_or_else(|| Box::new(DummyNetworkBackend));
                        Some(Box::new(VirtioNet::new(backend, Mmu::NET_IRQ))
                            as Box<dyn crate::device::MemoryMapped>)
                    }
                    "Syscon" => Some(Box::new(Syscon::new(
                        Arc::clone(&self.poweroff_flag),
                        Arc::clone(&self.reset_flag),
                    ))
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
                let uop = cpu::decode(insn_addr, insn as u32, self.cpu.vector_enabled);
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
                println!("--can't fetch from {insn_addr:016x}--");
            }

            if self.handle_htif()
                || self.exit_flag.load(Ordering::Relaxed)
                || self.poweroff_flag.load(Ordering::Relaxed)
            {
                break;
            }
            if self.reset_flag.swap(false, Ordering::Relaxed) {
                self.machine_reset();
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
        self.cpu.run_soc(n, &mut self.bb_cache)
    }

    /// Executes exactly one instruction without any block-cache interaction.
    /// Used by the tracing path so that one disassembly line == one retired
    /// instruction.
    pub fn tick_single(&mut self) -> bool {
        let insn_addr = self.cpu.pc;
        if let Err(exc) = self.cpu.step_single() {
            self.cpu.handle_exception(&exc, insn_addr);
            return true;
        }
        false
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
            (xmas_elf::header::Type::Executable, Some(load_addr)) => {
                // Kernel ELFs (e.g. vmlinux) are linked with paddr=0; apply
                // an offset so segments land at the intended physical address.
                let base_paddr = elf_file
                    .program_iter()
                    .filter(|s| matches!(s.get_type(), Ok(xmas_elf::program::Type::Load)))
                    .map(|s| s.physical_addr())
                    .next()
                    .unwrap_or(0);
                let offset = load_addr.wrapping_sub(base_paddr);
                log::info!("Relocating EXEC ELF (paddr base {base_paddr:#x}) to {load_addr:#x}");
                offset
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

    /// MMIO window `(base, end)` and PLIC IRQ for virtio-blk disk `index`.
    /// Two block devices are wired up: index 0 (`/dev/vda`) and index 1
    /// (`/dev/vdb`). Returns `None` for any other index.
    const fn block_disk_slot(index: usize) -> Option<(u64, u64, u32)> {
        match index {
            0 => Some((Mmu::VIRTIO_BASE, Mmu::VIRTIO_END, Mmu::VIRTIO_IRQ)),
            1 => Some((Mmu::VIRTIO2_BASE, Mmu::VIRTIO2_END, Mmu::VIRTIO2_IRQ)),
            _ => None,
        }
    }

    /// Sets up filesystem on block disk 0 (`/dev/vda`). Use this method if the
    /// program (e.g. Linux) uses a filesystem.
    ///
    /// # Arguments
    /// * `content` File system content binary
    pub fn setup_filesystem(&mut self, content: Vec<u8>) { self.setup_filesystem_at(0, content); }

    /// Sets up filesystem on block disk `index` (0 → `/dev/vda`, 1 →
    /// `/dev/vdb`) from an in-memory image. Out-of-range indices are
    /// ignored.
    ///
    /// # Arguments
    /// * `index` Which block device (0 or 1)
    /// * `content` File system content binary
    pub fn setup_filesystem_at(&mut self, index: usize, content: Vec<u8>) {
        let Some((base, end, irq)) = Self::block_disk_slot(index) else {
            return;
        };
        self.cpu.get_mut_mmu().replace_device(
            base..end,
            Box::new(VirtioBlockDisk::new_with_contents(content, irq)),
        );
    }

    /// Attaches a file-backed block device on disk 0 (`/dev/vda`).  Reads and
    /// writes go directly to `file`; the image is never copied into the
    /// emulator's heap.
    ///
    /// Prefer this over `setup_filesystem` on native builds.  The file must
    /// be opened with both read and write access.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn setup_filesystem_file(&mut self, file: std::fs::File) {
        self.setup_filesystem_file_at(0, file);
    }

    /// Attaches a file-backed block device on disk `index` (0 → `/dev/vda`,
    /// 1 → `/dev/vdb`). Out-of-range indices are ignored. Reads and writes go
    /// directly to `file`; the image is never copied into the emulator's heap.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn setup_filesystem_file_at(&mut self, index: usize, file: std::fs::File) {
        let Some((base, end, irq)) = Self::block_disk_slot(index) else {
            return;
        };
        self.cpu.get_mut_mmu().replace_device(
            base..end,
            Box::new(VirtioBlockDisk::new_with_file(file, irq)),
        );
    }

    /// Replaces the network backend.  Call after `new()` to attach a TAP
    /// interface or other backend.
    pub fn setup_network(&mut self, backend: Box<dyn NetworkBackend>) {
        self.cpu.get_mut_mmu().replace_device(
            Mmu::NET_BASE..Mmu::NET_END,
            Box::new(VirtioNet::new(backend, Mmu::NET_IRQ)),
        );
    }

    /// Sets up device tree. The emulator has default device tree configuration.
    /// If you want to override it, use this method. This method is expected to
    /// to be called up to only once.
    ///
    /// # Arguments
    /// * `content` DTB content binary
    ///
    /// # Errors
    /// Failing to patch the dtb will result in an error
    pub fn setup_dtb(&mut self, content: &[u8]) -> anyhow::Result<()> {
        let mut dtb = content.to_vec();
        #[allow(clippy::cast_possible_truncation)]
        let dtb_base = dtb_end_of_ram(0x8000_0000, self.memory_bytes as usize, dtb.len());
        let usable = dtb_base - 0x8000_0000;
        patch_dtb_memory(&mut dtb, usable)?;
        self.cpu.get_mut_mmu().write_memory_at(dtb_base, &dtb);
        self.cpu.set_dtb_base(dtb_base);
        Ok(())
    }

    /// Load a DTB at an explicit address without patching its memory-size
    /// property.
    pub fn setup_dtb_at(&mut self, content: &[u8], addr: u64) {
        self.cpu.get_mut_mmu().write_memory_at(addr, content);
        self.cpu.set_dtb_base(addr);
    }

    /// Set up the `fw_dynamic_info` struct for `OpenSBI` `fw_dynamic` firmware
    /// and place a pointer to it in a2, as required by the `fw_dynamic`
    /// ABI.
    ///
    /// * `kernel_addr` — physical address of the next-stage image (the kernel)
    /// * `info_addr`   — physical address where the struct will be written
    pub fn setup_fw_dynamic(&mut self, kernel_addr: u64, info_addr: u64) {
        // FW_DYNAMIC_INFO_MAGIC_VALUE = 0x4942534f ("OSBI" little-endian)
        const MAGIC: u64 = 0x4942_534f;
        const VERSION: u64 = 2;
        const NEXT_MODE_S: u64 = 1;
        // options: FLAG_NEXT_ADDR_VALID | FLAG_NEXT_MODE_VALID | FLAG_NEXT_ARG1_VALID
        const OPTIONS: u64 = 7;
        let boot_hart: u64 = 0;

        let mut buf = [0u8; 48];
        for (i, &v) in [MAGIC, VERSION, kernel_addr, NEXT_MODE_S, OPTIONS, boot_hart]
            .iter()
            .enumerate()
        {
            buf[i * 8..i * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }
        self.cpu.get_mut_mmu().write_memory_at(info_addr, &buf);
        self.cpu
            .write_register(crate::new_decoder::x(12), info_addr); // a2
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
