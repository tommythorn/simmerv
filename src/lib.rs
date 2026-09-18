#![allow(clippy::unreadable_literal)]

pub mod bounded;
pub mod buffered_serial_backend;
pub mod cpu;
pub mod csr;
pub mod device;
pub mod fdt;
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
#[cfg(feature = "bb-trace")]
pub mod uop_trace;
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

    // Walk the structure block looking for a node whose name starts with
    // "memory".
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
                // FDT_BEGIN_NODE: null-terminated name follows, aligned to 4
                // bytes.
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
                // FDT_PROP: len (u32), nameoff (u32), value (len bytes,
                // aligned).
                if pos + 8 > dtb.len() {
                    bail!("found not reg here");
                }
                let len = read_u32(dtb, pos) as usize;
                let nameoff = read_u32(dtb, pos + 4) as usize;
                pos += 8;
                // Patch: memory node, "reg" property, 2-cell address + 2-cell
                // size = 16 bytes.
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

/// Magic prefix of a snapshot file, bumped whenever the serialised layout
/// changes so an older blob fails cleanly instead of being misparsed.
///
/// Anything that writes, validates, or sniffs a snapshot must use this rather
/// than spelling the bytes out -- three hand-written copies is exactly how the
/// C8 -> C9 bump got missed in `sim`'s `is_snapshot` and in the Ctrl-C test.
pub const SNAPSHOT_MAGIC: &[u8] = b"SIMMERVC11";

/// Where [`Emulator::setup_initrd`] put the ramdisk and the tree it edited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitrdPlacement {
    /// Physical address of the ramdisk's first byte.
    pub start: u64,
    /// One past its last byte; `end - start` is the file's length.
    pub end: u64,
    /// Where the device tree carrying the two properties was placed.
    pub dtb_base: u64,
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

    /// Handle for a streamed base image, kept so that restoring a snapshot can
    /// re-attach it. A snapshot stores a zero-length sentinel for streamed
    /// storage -- the image lives at the URL, not in the snapshot -- and
    /// `restore_state` keeps whatever storage the device already has, so the
    /// device must be *constructed* with this backing for it to survive.
    streamed: Option<crate::device::streamed_disk::StreamedHandle>,

    /// When `true`, print an execution trace line for every instruction.
    pub tracing_flag: Arc<AtomicBool>,

    /// When `true`, log a message to stderr each time a snapshot is written.
    pub verbose: Arc<AtomicBool>,

    /// Set to request an on-demand snapshot (e.g. from the Ctrl-C `s` command).
    /// The run loop writes a snapshot to `snapshot_path` and clears the flag,
    /// without stopping execution.
    pub snapshot_flag: Arc<AtomicBool>,

    /// Destination path for on-demand snapshots requested via `snapshot_flag`.
    pub snapshot_path: String,

    /// The device tree exactly as supplied, before the memory-size patch.
    ///
    /// Kept because the tree has to be rebuildable: `set_rva23_enabled` swaps
    /// the blob, `-d` replaces it, and an initrd placed afterwards must edit
    /// whichever tree is actually in force.  Without this, placing a ramdisk
    /// would mean re-reading a file the emulator was handed a copy of.
    dtb_source: Vec<u8>,

    /// `Some(addr)` when the caller pinned the tree's address (`-d
    /// FILE,0xADDR`), which also suppresses the memory-size patch, matching
    /// `setup_dtb_at`.
    dtb_fixed_addr: Option<u64>,
    /// Stop once this many instructions have been executed, from
    /// `--max-insns`. `None` runs until the guest or the operator stops it.
    max_insns: Option<u64>,
    /// Kernel command line to force into `/chosen/bootargs`, from `--append`.
    /// `None` leaves whatever the tree itself says.
    bootargs: Option<String>,

    /// The tree as actually placed -- patched, with the ramdisk properties
    /// embedded if one was placed.  This is what `--dumpdtb` prints and what
    /// the guest actually reads.
    dtb_effective: Vec<u8>,

    /// The ramdisk extent once placed, so re-placing the tree (an RVA23 swap
    /// after `-d`) can re-embed the properties rather than drop them.
    initrd: Option<(u64, u64)>,

    /// Lowest and highest physical address `load_image` has written, so an
    /// initrd can be shown not to overlap a kernel image.
    image_extent: Option<(u64, u64)>,
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
        // RAM regions must be added before I/O devices so the dispatch
        // fast-path hits on the first iteration.  Primary RAM first,
        // then secondary.
        mmu.add_memory(0x8000_0000, capacity);
        mmu.add_memory(0x7000_0000, 1024 * 1024);
        mmu.attach_uart(backend);

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
            streamed: None,
            tracing_flag: Arc::new(AtomicBool::new(false)),
            verbose: Arc::new(AtomicBool::new(false)),
            snapshot_flag: Arc::new(AtomicBool::new(false)),
            snapshot_path: "snapshot".to_string(),

            dtb_source: include_bytes!("./device/dtb.dtb").to_vec(),
            dtb_fixed_addr: None,
            max_insns: None,
            bootargs: None,
            dtb_effective: Vec::new(),
            initrd: None,
            image_extent: None,
        };
        // The default tree is the emulator's own, so failing to place it is a
        // broken build rather than bad input.
        #[allow(clippy::expect_used)]
        emulator
            .place_device_tree()
            .expect("can't place the default device tree");
        emulator
    }

    /// Enable (or disable) the V vector extension.
    ///
    /// This is a machine-construction switch: it gates decoding of every
    /// RVA23-only encoding, the `misa` V bit and the vector CSRs. When enabling
    /// it we also swap in the RVA23 build of the device tree (`dtb-v.dtb`),
    /// whose cpu node advertises the profile via both `riscv,isa` and
    /// `riscv,isa-extensions` so a modern guest kernel enables vector and
    /// reports the rest through hwprobe. The RVA23 DTB differs in size, so it
    /// is re-placed at the top of RAM and its memory node re-patched.
    #[allow(clippy::cast_possible_truncation, clippy::missing_panics_doc)]
    pub fn set_rva23_enabled(&mut self, on: bool) {
        self.cpu.set_rva23_enabled(on);
        if !on {
            return;
        }
        self.dtb_source = include_bytes!("./device/dtb-v.dtb").to_vec();
        // The RVA23 tree reclaims the top of RAM, so a tree the caller had
        // pinned no longer applies -- same as the old unconditional re-place.
        self.dtb_fixed_addr = None;
        #[allow(clippy::expect_used)]
        self.place_device_tree()
            .expect("can't place the vector device tree");
    }

    /// Set `VLEN` in bits (128, the default, or 256).  RVA23 must also be
    /// enabled for the vector unit to be reachable at all.
    ///
    /// # Panics
    /// If `vlen` is not a supported width.
    pub fn set_vlen(&mut self, vlen: usize) { self.cpu.set_vlen(vlen); }

    /// Widest `satp` MODE the hart accepts: 8 = Sv39 (default), 9 = Sv48,
    /// 10 = Sv57.  See [`crate::cpu::Cpu::max_satp_mode`] for why this is
    /// opt-in rather than simply always allowing the widest.
    pub const fn set_max_satp_mode(&mut self, mode: u64) { self.cpu.set_max_satp_mode(mode); }

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

    /// Honor a pending on-demand snapshot request (Ctrl-C `s`): write a
    /// snapshot to `snapshot_path`, report the outcome, and clear the
    /// request flag. Execution is not interrupted. Does nothing when no
    /// request is pending.
    fn maybe_write_requested_snapshot(&self) {
        if self.snapshot_flag.swap(false, Ordering::Relaxed) {
            match self.write_snapshot(&self.snapshot_path) {
                Ok(()) => {
                    eprintln!(
                        "snapshot → {} [seqno={}]",
                        self.snapshot_path, self.cpu.seqno
                    );
                }
                Err(e) => eprintln!("snapshot failed: {e}"),
            }
        }
    }

    /// Runs program set by `load_image()`. The emulator will run forever.
    /// When `tracing_flag` is set, prints a disassembly line for every
    /// instruction.
    pub fn run_program(&mut self) {
        // Arm the cosim store log now that the ELF loader is done (its stores
        // are excluded).
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
                    let uop = cpu::decode(insn_addr, insn as u32, self.cpu.rva23_enabled);
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
            self.maybe_write_requested_snapshot();
            if self.should_stop() {
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
            self.maybe_write_requested_snapshot();
            if self.should_stop() {
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
    /// The snapshot body is brotli-compressed and prefixed with
    /// [`SNAPSHOT_MAGIC`].
    ///
    /// # Errors
    /// Returns an error if the file cannot be written.
    pub fn write_snapshot(&self, path: &str) -> anyhow::Result<()> {
        let data = self.snapshot_bytes()?;
        std::fs::write(path, &data).map_err(|e| anyhow!(e))
    }

    /// The same bytes `write_snapshot` would write, returned rather than
    /// written -- there is no filesystem in the browser.
    ///
    /// # Errors
    /// Returns an error if compression fails.
    pub fn snapshot_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut state = Vec::new();
        let mut ram = Vec::new();
        self.cpu.write_state(&mut state, &mut ram);

        // Two compressed sections rather than one. RAM is nearly all of the
        // bulk, and keeping it out of the state blob is what lets a restore
        // inflate it straight into the region that will own it.
        let params = brotli::enc::BrotliEncoderParams {
            quality: 5,
            ..Default::default()
        };
        let mut meta = Vec::new();
        brotli::BrotliCompress(&mut state.as_slice(), &mut meta, &params)
            .map_err(|e| anyhow!("brotli compress: {e}"))?;
        drop(state);

        let mut data = SNAPSHOT_MAGIC.to_vec();
        data.extend_from_slice(&(meta.len() as u64).to_le_bytes());
        data.extend_from_slice(&meta);
        drop(meta);
        brotli::BrotliCompress(&mut ram.as_slice(), &mut data, &params)
            .map_err(|e| anyhow!("brotli compress ram: {e}"))?;
        Ok(data)
    }

    /// Load a snapshot produced by `write_snapshot`.
    ///
    /// The device list is reconstructed from the snapshot — there is no
    /// requirement that the emulator was started with matching devices.
    ///
    /// Note that restoring is memory-hungry: the decompressed state carries a
    /// full copy of RAM, and `read_state` copies each region out of it into a
    /// fresh allocation while it is still live, so a 512 MB machine peaks at
    /// about 1.09 GB. That is over what mobile Safari allows a tab, and wasm
    /// linear memory never shrinks back. Releasing the old RAM up front does
    /// *not* fix it -- the regions are still referenced during the restore,
    /// and doing so silently corrupts the restored machine.
    ///
    /// # Errors
    /// Returns an error if the data is not a valid snapshot or is corrupt.
    pub fn load_snapshot(&mut self, data: &[u8]) -> anyhow::Result<()> {
        let Some(body) = data.strip_prefix(SNAPSHOT_MAGIC) else {
            bail!("not a valid snapshot");
        };
        let Some((len_bytes, rest)) = body.split_at_checked(8) else {
            bail!("snapshot truncated");
        };
        let Ok(len_arr) = <[u8; 8]>::try_from(len_bytes) else {
            bail!("snapshot truncated");
        };
        let Ok(meta_len) = usize::try_from(u64::from_le_bytes(len_arr)) else {
            bail!("snapshot metadata too large for this target");
        };
        let Some((meta, ram_section)) = rest.split_at_checked(meta_len) else {
            bail!("snapshot truncated");
        };
        let mut state = Vec::new();
        brotli::BrotliDecompress(&mut &meta[..], &mut state)
            .map_err(|e| anyhow!("brotli decompress: {e}"))?;

        // Reclaim backends before clearing the device list so we can hand them
        // to the freshly-constructed devices during restore.
        let mut uart_backend = self.cpu.mmu.take_uart_backend();
        let mut net_backend = self.cpu.mmu.take_net_backend();
        let streamed = self.streamed.clone();

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
                        // Two block disks share this name; pick the IRQ from
                        // the saved MMIO window.
                        // `restore_state` overwrites it, but
                        // this keeps the fresh device self-consistent.
                        let second = range.start == Mmu::VIRTIO2_BASE;
                        let irq = if second {
                            Mmu::VIRTIO2_IRQ
                        } else {
                            Mmu::VIRTIO_IRQ
                        };
                        // A streamed image is not inside the snapshot, so the
                        // device has to be built with its backing re-attached:
                        // `restore_state` sees the zero-length sentinel and
                        // keeps whatever storage the device already has.
                        Some(match (second, streamed.clone()) {
                            (false, Some(handle)) => {
                                Box::new(VirtioBlockDisk::new_streamed(handle, irq))
                                    as Box<dyn crate::device::MemoryMapped>
                            }
                            _ => Box::new(VirtioBlockDisk::new(irq))
                                as Box<dyn crate::device::MemoryMapped>,
                        })
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
            .map_err(|()| anyhow!("snapshot corrupt"))?;

        // The regions exist but are empty until here. Inflating after `state`
        // is done with means only one copy of RAM is ever live: with a single
        // region the buffer is moved into place rather than copied.
        drop(state);
        // Exact capacity up front: letting it double would hold 256 MB and
        // 512 MB simultaneously at the last realloc.
        let mut ram = Vec::with_capacity(self.cpu.mmu.ram_len());
        brotli::BrotliDecompress(&mut &ram_section[..], &mut ram)
            .map_err(|e| anyhow!("brotli decompress ram: {e}"))?;
        self.cpu
            .get_mut_mmu()
            .install_ram(ram)
            .map_err(|()| anyhow!("snapshot ram does not match its memory map"))
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
                let uop = cpu::decode(insn_addr, insn as u32, self.cpu.rva23_enabled);
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

            if self.should_stop() {
                break;
            }
            if self.reset_flag.swap(false, Ordering::Relaxed) {
                self.machine_reset();
            }
        }
    }

    /// Whether the run loop should stop: the guest asked to (HTIF or the
    /// syscon poweroff), the operator asked to (Ctrl-C `x`), or the instruction
    /// budget from `--max-insns` is spent.
    ///
    /// Factored out because all three run loops have to agree: a budget honored
    /// in only one of them would silently not apply under `-t` or `-S`, and the
    /// condition was already copied three times before the budget existed.
    fn should_stop(&mut self) -> bool {
        if let Some(limit) = self.max_insns
            && self.insns_retired() >= limit
        {
            return true;
        }
        self.handle_htif()
            || self.exit_flag.load(Ordering::Relaxed)
            || self.poweroff_flag.load(Ordering::Relaxed)
    }

    /// Instructions executed since reset.
    ///
    /// `seqno` numbers instructions in program order, so it is the retired
    /// count -- not `cycle`, which the speedometer uses and which overstates
    /// the count whenever the guest sits in `wfi`. That difference is the whole
    /// point of measuring with this rather than with elapsed guest time: a
    /// budget in instructions is the same amount of work on every host, while
    /// the same wall-clock window is not.
    #[must_use]
    pub const fn insns_retired(&self) -> u64 { self.cpu.seqno as u64 }

    /// Stop after `n` instructions. See [`Self::insns_retired`] for why the
    /// budget is counted in instructions.
    pub const fn set_max_insns(&mut self, n: u64) { self.max_insns = Some(n); }

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

    /// Uop cache counters.
    #[must_use]
    pub const fn bb_stats(&self) -> crate::uop_cache::UopCacheStats { self.bb_cache.stats() }

    /// Distribution of stored uop-cache block lengths; see
    /// [`crate::uop_cache::BbCache::inserted_len`].
    #[must_use]
    pub const fn bb_len_histogram(&self) -> &[u64; crate::uop_cache::MAX_BLOCK_LEN + 1] {
        self.bb_cache.inserted_len()
    }

    /// Distribution of *executed* block lengths, weighted by how often each
    /// block ran; see [`crate::uop_cache::BbCache::dyn_len`].
    #[must_use]
    pub const fn bb_dyn_len_histogram(&self) -> &[u64; crate::uop_cache::MAX_BLOCK_LEN + 1] {
        self.bb_cache.dyn_len()
    }

    /// Live directory usage `(live_blocks, stored_uops)`; see
    /// [`crate::uop_cache::BbCache::residency`].
    #[must_use]
    pub fn bb_residency(&self) -> (usize, u64) { self.bb_cache.residency() }

    /// Ring size in uops; see [`crate::uop_cache::BbCache::ring_uops`].
    #[must_use]
    pub const fn bb_ring_uops(&self) -> u64 { self.bb_cache.ring_uops() }

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
            self.record_image_extent(load_addr, load_addr + size as u64);
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
        // Tracked from the program headers, not the file length: `p_memsz`
        // covers `.bss` and exceeds `p_filesz`, so a file's size bounds
        // nothing.
        let mut span: Option<(u64, u64)> = None;
        for sect in ph_iter {
            if !matches!(sect.get_type(), Ok(xmas_elf::program::Type::Load)) {
                log::trace!("Skipping {sect}");
                continue;
            }
            let addr = sect.physical_addr() + relocation_offset;
            let size = sect.mem_size();
            span = Some(match span {
                Some((lo, hi)) => (lo.min(addr), hi.max(addr.saturating_add(size))),
                None => (addr, addr.saturating_add(size)),
            });
            let xmas_elf::program::SegmentData::Undefined(data) =
                sect.get_data(&elf_file).map_err(|e| anyhow!(e))?
            else {
                bail!("{name}: PT_LOAD segment at {addr:#x} has no raw data");
            };
            log::info!(
                "ELF program data section [{addr:x}, {:x}) (size {size} vs {})",
                addr + size,
                data.len()
            );

            // XXX such an insane stupid way to do this
            //
            // Reported rather than asserted: the address comes from the image,
            // so an ELF linked for a different memory map is bad input, not a
            // broken invariant.  Panicking here aborted the process on a
            // mis-linked test binary -- and in wasm that is a trap and a dead
            // page, with nothing said about which address was at fault.
            let mmu = self.cpu.get_mut_mmu();
            for (j, b) in data.iter().enumerate() {
                if mmu.store_phys_u8(addr + j as u64, *b).is_err() {
                    bail!(
                        "{name}: segment [{addr:#x}, {:#x}) does not fit in memory \
                         (no RAM at {:#x})",
                        addr + size,
                        addr + j as u64
                    );
                }
            }
        }

        for sect in elf_file.section_iter().skip(1) {
            if let SectionData::SymbolTable64(data) =
                sect.get_data(&elf_file).map_err(|e| anyhow!(e))?
            {
                for datum in data {
                    let name = datum.get_name(&elf_file).map_err(|e| anyhow!(e))?;
                    // NOTYPE, OBJECT and FUNC; skip SECTION/FILE, whose names
                    // are not addresses anyone wants to look up.
                    //
                    // OBJECT used to be excluded, which silently broke the
                    // riscv-tests `tohost` handshake for any image that
                    // declares it as sized data -- and QEMU's spike machine
                    // *requires* tohost to be an 8-byte symbol, so an ELF
                    // built to satisfy QEMU ran here forever with `tohost`
                    // never found and nothing said about it.
                    if !name.is_empty() && matches!(datum.info() & 15, 0..=2) {
                        symbols.insert(name.to_string(), datum.value());
                    }
                }
            }
        }

        if let Some((lo, hi)) = span {
            self.record_image_extent(lo, hi);
        }
        Ok(elf_file.header.pt2.entry_point() + relocation_offset)
    }

    /// Grow the record of what `load_image` has written, so a ramdisk can be
    /// shown not to land on top of it.
    fn record_image_extent(&mut self, low: u64, high: u64) {
        self.image_extent = Some(match self.image_extent {
            Some((lo, hi)) => (lo.min(low), hi.max(high)),
            None => (low, high),
        });
    }

    /// Lowest and highest physical address written by `load_image` so far.
    #[must_use]
    pub const fn image_extent(&self) -> Option<(u64, u64)> { self.image_extent }

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

    /// Attaches a URL-backed block device on disk `index` (0 → `/dev/vda`,
    /// 1 → `/dev/vdb`). Reads are fetched from `url` via HTTP range requests;
    /// writes are kept in a local copy-on-write overlay and never sent back.
    /// Out-of-range indices are ignored.
    ///
    /// # Errors
    /// Returns an error if the URL cannot be opened as a raw disk image (bad
    /// scheme, compressed image, no range support, or unreachable server).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn setup_filesystem_url_at(&mut self, index: usize, url: &str) -> anyhow::Result<()> {
        let Some((base, end, irq)) = Self::block_disk_slot(index) else {
            return Ok(());
        };
        let disk = VirtioBlockDisk::new_with_url(url, irq)?;
        self.cpu
            .get_mut_mmu()
            .replace_device(base..end, Box::new(disk));
        Ok(())
    }

    /// Attaches a block device on disk 0 whose contents the *host* supplies on
    /// demand, and returns the handle used to feed it.
    ///
    /// Reads of blocks that have not arrived defer rather than block (see
    /// `streamed_disk`), so this is the browser's answer to a disk too large
    /// to download up front: only the blocks actually touched are transferred.
    ///
    /// `total_bytes` is the size of the base image, which the guest needs at
    /// probe time — long before any block has been fetched.
    pub fn setup_filesystem_streamed(
        &mut self,
        total_bytes: u64,
        block_size: u64,
    ) -> crate::device::streamed_disk::StreamedHandle {
        let handle = crate::device::streamed_disk::StreamedStorage::new(total_bytes, block_size);
        self.streamed = Some(handle.clone());
        if let Some((base, end, irq)) = Self::block_disk_slot(0) {
            self.cpu.get_mut_mmu().replace_device(
                base..end,
                Box::new(VirtioBlockDisk::new_streamed(handle.clone(), irq)),
            );
        }
        handle
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
        self.dtb_source = content.to_vec();
        self.dtb_fixed_addr = None;
        self.place_device_tree()?;
        Ok(())
    }

    /// Load a DTB at an explicit address without patching its memory-size
    /// property.
    ///
    /// Placement failures are logged rather than returned: this is the escape
    /// hatch the benchmark harnesses use to pin a frozen layout, and it has
    /// always been infallible at the call sites that matter.
    pub fn setup_dtb_at(&mut self, content: &[u8], addr: u64) {
        self.dtb_source = content.to_vec();
        self.dtb_fixed_addr = Some(addr);
        if let Err(e) = self.place_device_tree() {
            log::error!("can't place device tree at {addr:#x}: {e}");
        }
    }

    /// Force the guest kernel command line, replacing whatever `/chosen`
    /// declares.
    ///
    /// Takes effect on the tree in force, so it must be called after any `-d`
    /// tree has been loaded; the tree is rebuilt and rewritten immediately.
    ///
    /// # Errors
    /// If the tree has no `/chosen` node, if `args` contains a NUL, or if the
    /// rebuilt tree no longer fits where it has to go.
    pub fn set_bootargs(&mut self, args: &str) -> anyhow::Result<()> {
        self.bootargs = Some(args.to_owned());
        self.place_device_tree()?;
        Ok(())
    }

    /// Build and write out the device tree currently in force.
    ///
    /// The single place a tree reaches RAM.  Earlier this logic was copied
    /// across four callers, which is why none of them could rebuild the tree
    /// they had placed -- and why a ramdisk could not be advertised in a tree
    /// that `set_rva23_enabled` or `-d` had since replaced.
    ///
    /// Order matters: everything is validated before the first byte is written,
    /// because the memory writes in this module are not self-checking.
    #[allow(clippy::cast_possible_truncation)] // RAM sizes come from `usize` in the first place
    fn place_device_tree(&mut self) -> anyhow::Result<u64> {
        let mut dtb = self.dtb_source.clone();
        if self.dtb_fixed_addr.is_none() {
            patch_dtb_memory(&mut dtb, self.memory_bytes)?;
        }
        if let Some(ref args) = self.bootargs {
            dtb = fdt::analyze_bootargs_slot(&dtb)?.embed(&dtb, args)?;
        }
        if let Some((start, end)) = self.initrd {
            dtb = fdt::analyze_initrd_slot(&dtb)?.embed(&dtb, start, end)?;
        }

        let base = match self.dtb_fixed_addr {
            Some(addr) => addr,
            None => dtb_end_of_ram(0x8000_0000, self.memory_bytes as usize, dtb.len()),
        };

        let ram_end = 0x8000_0000u64.saturating_add(self.memory_bytes);
        let tree_end = base
            .checked_add(dtb.len() as u64)
            .ok_or_else(|| anyhow!("device tree at {base:#x} has an overflowing footprint"))?;
        if base < 0x8000_0000 || tree_end > ram_end {
            bail!(
                "device tree [{base:#x}, {tree_end:#x}) does not fit in RAM \
                 [0x80000000, {ram_end:#x}); {} byte(s) needed",
                dtb.len()
            );
        }
        if let Some((start, end)) = self.initrd.filter(|&(_, end)| end > base) {
            bail!(
                "ramdisk [{start:#x}, {end:#x}) overlaps the device tree at {base:#x}; \
                 the tree cannot move to make room"
            );
        }

        // `dma_slice` rather than `write_memory_at`: the latter truncates
        // silently past a region's end and does nothing at all when no region
        // matches, so a tree that missed RAM would simply never appear.
        self.cpu
            .get_mut_mmu()
            .dma_slice(base, dtb.len())
            .map_err(|()| {
                anyhow!(
                    "device tree [{base:#x}, {tree_end:#x}) is not wholly inside one memory region"
                )
            })?
            .copy_from_slice(&dtb);

        self.dtb_effective = dtb;
        self.cpu.set_dtb_base(base);
        Ok(base)
    }

    /// Place `content` as the initial ramdisk and advertise it to the guest.
    ///
    /// The ramdisk is put directly below the device tree, at the highest
    /// address that leaves it clear of the tree, and `linux,initrd-start` /
    /// `linux,initrd-end` are inserted into `/chosen` so the kernel finds it.
    /// Call after the tree has been chosen (`set_rva23_enabled`, `setup_dtb`).
    ///
    /// # Errors
    /// If the tree already states a ramdisk address, if the image does not fit
    /// in RAM clear of the tree and of anything already loaded, or if either
    /// extent falls outside a memory region.
    pub fn setup_initrd(&mut self, content: &[u8]) -> anyhow::Result<InitrdPlacement> {
        self.place_initrd(content, None)
    }

    /// As [`Self::setup_initrd`], but at an address the caller chose.
    ///
    /// The tree is still edited and the properties still inserted -- only the
    /// placement is overridden.  Pinning is how a known-good layout is
    /// reproduced exactly, and it must still leave room for the tree, which
    /// grows by a few dozen bytes when the properties are inserted.
    ///
    /// # Errors
    /// As [`Self::setup_initrd`].
    pub fn setup_initrd_at(
        &mut self,
        content: &[u8],
        addr: u64,
    ) -> anyhow::Result<InitrdPlacement> {
        self.place_initrd(content, Some(addr))
    }

    #[allow(clippy::cast_possible_truncation)] // as `place_device_tree`
    fn place_initrd(
        &mut self,
        content: &[u8],
        pinned: Option<u64>,
    ) -> anyhow::Result<InitrdPlacement> {
        const PAGE: u64 = 4096;
        if content.is_empty() {
            bail!("initrd is empty; an empty ramdisk is not a usable image");
        }
        let len = content.len() as u64;

        // How much the tree grows is a function of the tree alone -- how many
        // properties are missing, which names are already interned, the root's
        // `#address-cells` -- and not of the addresses being written.  That is
        // what resolves "the address depends on the tree's size" and "the tree
        // depends on the address" in one pass instead of iterating.
        let mut probe = self.dtb_source.clone();
        if self.dtb_fixed_addr.is_none() {
            patch_dtb_memory(&mut probe, self.memory_bytes)?;
        }
        let growth = fdt::analyze_initrd_slot(&probe)?.growth();
        let base = match self.dtb_fixed_addr {
            Some(addr) => addr,
            None => dtb_end_of_ram(
                0x8000_0000,
                self.memory_bytes as usize,
                probe.len() + growth,
            ),
        };

        // Default placement is flush below the tree; a pinned address is used
        // as given, page-aligned only so the reserved range's leading edge does
        // not half-reserve the page beneath it.
        let start = match pinned {
            Some(addr) => addr & !(PAGE - 1),
            None => base
                .checked_sub(len)
                .map(|s| s & !(PAGE - 1))
                .ok_or_else(|| {
                    anyhow!(
                        "initrd ({len} byte(s)) is larger than the {base:#x} bytes below \
                     the device tree; increase -m"
                    )
                })?,
        };
        let end = start + len;
        if end > base {
            bail!(
                "initrd [{start:#x}, {end:#x}) overlaps the device tree at {base:#x}; \
                 it must end at or below the tree"
            );
        }

        let ram_base = 0x8000_0000u64;
        if start < ram_base {
            bail!(
                "initrd ({len} byte(s)) does not fit in RAM below the device tree at \
                 {base:#x}; it would start at {start:#x}, below RAM at {ram_base:#x}. \
                 Increase -m"
            );
        }
        // Firmware and any other reserved ranges are not ours to overwrite.
        for (rsv_start, rsv_end) in fdt::mem_reserve_ranges(&probe) {
            if start < rsv_end && end > rsv_start {
                bail!(
                    "initrd [{start:#x}, {end:#x}) overlaps reserved memory \
                     [{rsv_start:#x}, {rsv_end:#x}) declared by the device tree"
                );
            }
        }
        // Anything already loaded -- the firmware and the kernel.  The extent
        // is tracked inside `load_image`, which is the only place that
        // knows how far an ELF's segments reach (a file's length does
        // not bound them). `image_extent` is the only honest bound on a
        // loaded kernel: a file's length does not bound the footprint
        // of an ELF's segments.
        if let Some((low, high)) = self
            .image_extent
            .filter(|&(low, high)| start < high && end > low)
        {
            bail!(
                "initrd [{start:#x}, {end:#x}) would overwrite an image already loaded at \
                 [{low:#x}, {high:#x}); the ramdisk goes below the device tree at {base:#x}"
            );
        }

        self.cpu
            .get_mut_mmu()
            .dma_slice(start, content.len())
            .map_err(|()| {
                anyhow!("initrd [{start:#x}, {end:#x}) is not wholly inside one memory region")
            })?
            .copy_from_slice(content);

        self.initrd = Some((start, end));
        if let Err(e) = self.place_device_tree() {
            self.initrd = None;
            return Err(e);
        }

        let dtb_base = self.cpu.dtb_base;
        log::info!(
            "initrd [{start:#x}, {end:#x}) = {len} byte(s), device tree at {dtb_base:#x} \
             (grew {growth} byte(s), address-cells {})",
            fdt::analyze_initrd_slot(&self.dtb_effective)?.addr_cells()
        );
        Ok(InitrdPlacement {
            start,
            end,
            dtb_base,
        })
    }

    /// The device tree as actually placed -- memory-patched, and carrying the
    /// ramdisk properties when one was set up.  This is what the guest reads.
    #[must_use]
    pub fn effective_dtb(&self) -> &[u8] { &self.dtb_effective }

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
        // options: FLAG_NEXT_ADDR_VALID | FLAG_NEXT_MODE_VALID |
        // FLAG_NEXT_ARG1_VALID
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
