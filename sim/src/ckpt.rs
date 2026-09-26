//! Architectural checkpoints: the machine's state in a form another RISC-V
//! implementation can restore with ordinary instructions.
//!
//! A checkpoint is a directory holding three files:
//! - `sim.snap`: this emulator's own snapshot, which Simmerv and the cosim
//!   library restore from;
//! - `state.txt`: registers, CSRs and device registers as `key hex` lines, with
//!   provenance as `#` comments;
//! - `mem.zst`: a zstd stream of `{u64 physical address, 4096 bytes}` records,
//!   one per non-zero page, in address order.
//!
//! Another implementation restores `state.txt` and `mem.zst` through a stub of
//! ordinary instructions and MMIO, which cannot recreate a PLIC interrupt in
//! flight, a UART receive, an LR reservation or a `wfi`. A checkpoint is
//! therefore only taken where none of those is live; see [`quiescent`].

use anyhow::Context;
use anyhow::bail;
use simmerv::Emulator;
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::Path;

const CLINT: u64 = 0x0200_0000;
const PLIC: u64 = 0x0C00_0000;
const UART: u64 = 0x1000_0000;
const MSTATUS_MPRV: u64 = 1 << 17;

/// The CSRs `state.txt` carries, by name.
const CSRS: &[(&str, u16)] = &[
    ("satp", 0x180),
    ("stvec", 0x105),
    ("sepc", 0x141),
    ("scause", 0x142),
    ("stval", 0x143),
    ("sscratch", 0x140),
    ("mtvec", 0x305),
    ("mcause", 0x342),
    ("mtval", 0x343),
    ("mscratch", 0x340),
    ("medeleg", 0x302),
    ("mideleg", 0x303),
    ("mie", 0x304),
    ("mip", 0x344),
    ("mcounteren", 0x306),
    ("scounteren", 0x106),
    ("menvcfg", 0x30A),
    ("senvcfg", 0x10A),
    ("mstateen0", 0x30C),
    ("stimecmp", 0x14D),
    ("mnstatus", 0x744),
    ("mcountinhibit", 0x320),
    ("mstatus", 0x300),
    ("fcsr", 0x003),
    ("mcycle", 0xB00),
    ("minstret", 0xB02),
];

fn mmio(emu: &mut Emulator, pa: u64, size: u64) -> u64 {
    emu.cpu.mmu.load_mmio(pa, size).unwrap_or(0)
}

/// Whether the machine is at a point a restore stub can reproduce exactly: no
/// PLIC source pending (Simmerv's PLIC keeps a claimed source pending until it
/// is completed, so this also excludes a claim in progress), no UART receive
/// data and the divisor latch closed, no LR reservation, no `wfi`, and
/// `mstatus.MPRV` clear (the stub's own loads follow its `mstatus` write).
///
/// The hart must also be below M-mode. The stub enters the checkpoint with an
/// `mret`, which consumes `mepc`, `MPP` and `MPIE`; below M-mode those three
/// are dead, because only M-mode reads them and every way into M-mode is a trap
/// that writes them first.
pub fn quiescent(emu: &mut Emulator) -> bool {
    let pending = mmio(emu, PLIC + 0x1000, 8);
    let lsr = mmio(emu, UART + 5, 1);
    let lcr = mmio(emu, UART + 3, 1);
    let mstatus = emu.cpu.read_csr_m(0x300).unwrap_or(0);
    pending == 0
        && lsr & 1 == 0
        && lcr & 0x80 == 0
        && mstatus & MSTATUS_MPRV == 0
        && emu.cpu.hart_quiescent()
        && emu.cpu.mmu.prv != simmerv::riscv::PrivMode::M
}

/// Write the checkpoint of the current state to `dir`, and continue from it.
///
/// # Errors
/// Fails when the directory or a file cannot be written.
pub fn write(emu: &mut Emulator, dir: &Path, provenance: &str) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir).with_context(|| dir.display().to_string())?;
    emu.cpu.settle_mret_state();

    let mut st = String::new();
    writeln!(st, "# {provenance}")?;
    writeln!(st, "pc {:x}", emu.cpu.read_pc())?;
    writeln!(st, "priv {:x}", u64::from(emu.cpu.mmu.prv))?;
    writeln!(st, "instret {:x}", emu.insns_retired())?;
    for i in 1..64u32 {
        let v = emu
            .cpu
            .read_register(simmerv::bounded::Bounded::<65>::new(i));
        let name = if i < 32 {
            format!("x{i}")
        } else {
            format!("f{}", i - 32)
        };
        writeln!(st, "{name} {v:x}")?;
    }
    for &(name, num) in CSRS {
        if let Some(v) = emu.cpu.read_csr_m(num) {
            writeln!(st, "{name} {v:x}")?;
        }
    }
    for i in 3..16u16 {
        for (name, base) in [("mhpmevent", 0x320), ("mhpmcounter", 0xB00)] {
            if let Some(v) = emu.cpu.read_csr_m(base + i) {
                writeln!(st, "{name}{i} {v:x}")?;
            }
        }
    }
    writeln!(st, "clint.mtime {:x}", mmio(emu, CLINT + 0xBFF8, 8))?;
    writeln!(st, "clint.mtimecmp {:x}", mmio(emu, CLINT + 0x4000, 8))?;
    writeln!(st, "clint.msip {:x}", mmio(emu, CLINT, 4))?;
    for src in 1..64 {
        let p = mmio(emu, PLIC + 4 * src, 4);
        if p != 0 {
            writeln!(st, "plic.prio.{src} {p:x}")?;
        }
    }
    writeln!(st, "plic.enable {:x}", mmio(emu, PLIC + 0x2080, 8))?;
    writeln!(st, "plic.threshold {:x}", mmio(emu, PLIC + 0x20_1000, 4))?;
    for (name, off) in [
        ("uart.ier", 1),
        ("uart.lcr", 3),
        ("uart.mcr", 4),
        ("uart.scr", 7),
    ] {
        writeln!(st, "{name} {:x}", mmio(emu, UART + off, 1))?;
    }
    std::fs::write(dir.join("state.txt"), st)?;

    let f = std::fs::File::create(dir.join("mem.zst"))?;
    let mut z = zstd::stream::Encoder::new(f, 3)?;
    let mut regions: Vec<_> = emu.cpu.mmu.memory.iter().collect();
    regions.sort_by_key(|(r, _)| r.start);
    for (range, bytes) in regions {
        if range.start & 0xfff != 0 {
            bail!("memory region at {:#x} is not page aligned", range.start);
        }
        for (i, page) in bytes.chunks(4096).enumerate() {
            if page.iter().any(|&b| b != 0) {
                z.write_all(&(range.start + 4096 * i as u64).to_le_bytes())?;
                z.write_all(page)?;
                z.write_all(&vec![0; 4096 - page.len()])?;
            }
        }
    }
    z.finish()?;

    // The run continues from its own snapshot, so it goes on exactly as a run
    // restored from this checkpoint does (the uop cache starts cold in both).
    let snap = emu.snapshot_bytes()?;
    std::fs::write(dir.join("sim.snap"), &snap)?;
    emu.load_snapshot(&snap)
}
