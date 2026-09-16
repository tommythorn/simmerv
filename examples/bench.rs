//! Benchmark harness for the emulator core.
//!
//! Three modes, because they answer different questions:
//!
//! * `elf`    — run a bare-metal riscv-tests benchmark (see `benches/`) to
//!   completion, K times, each on a fresh machine.  Deterministic (M-mode, no
//!   timer interrupts) and quick, so it is the right tool for measuring the
//!   uop-cache hit path in isolation.
//! * `linux`  — boot `fw_payload.bin` against a rootfs for a fixed number of
//!   emulated cycles.  Realistic (kernel + userland, iTLB/dTLB pressure, uop
//!   cache conflicts) but only as deterministic as the guest's use of the
//!   wall-clock-derived `mtime`.
//! * `gb5`    — boot the Geekbench 5 initramfs using the same memory layout as
//!   `~/smolrv64/workloads/gb5`'s `ref` target, and run until the console
//!   prints a marker (default: the start of the first GB5 subtest).  This is
//!   the end-to-end number that matters: wall-clock seconds to reach a fixed
//!   point in a real benchmark, so it needs no cycle accounting to interpret.
//! * `gb6`    — the same for the Geekbench 6 initramfs, which pins no address:
//!   the ramdisk is placed by `setup_initrd` and the device tree is the
//!   emulator's own.  It defaults to stopping at the end of the single-core
//!   suite, because it exists to be traced rather than timed.
//!
//! `elf` and `linux` report emulated cycles per second, where a cycle is the
//! emulator's own accounting: one per instruction plus one per block entry.
//!
//! ```text
//! cargo run --release --example bench -- elf benches/dhrystone.riscv 30
//! cargo run --release --example bench -- linux linux/fw_payload.bin \
//!     linux/rootfs-auto-coremark.img 2000
//! cargo run --release --example bench -- gb5
//! cargo run --release --example bench -- gb6
//! ```

use simmerv::Emulator;
use simmerv::serial_backend::DummySerialBackend;
use simmerv::serial_backend::SerialBackend;
use simmerv::uop_cache::CacheMode;
use simmerv::uop_cache::DEFAULT_UOP_ENTRIES;
use simmerv::uop_cache::MAX_BLOCK_LEN;
use simmerv::uop_cache::UopCacheStats;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use std::time::Instant;

// ---------------------------------------------------------------------------
// prof: in-process PC sampling (macOS only)
// ---------------------------------------------------------------------------

/// Everything hot in this emulator is inlined into `step_block`, so a
/// symbol-level profile (what `sample` gives) says only "`step_block`: 96%" and
/// cannot be acted on.  This samples the program counter straight out of the
/// signal context at a fixed rate and dumps the raw PCs; symbolising those
/// afterwards attributes time to source lines *within* the inlined loop.
///
/// Enabled by setting `SIMMERV_PROF` to the output path; off (and so costing
/// nothing) otherwise.  The handler only stores the PC, which is async-signal
/// safe; aggregation happens after the run.
///
/// macOS only: it reads the PC out of Darwin's `ucontext_t` (`__ss.__pc`) and
/// offsets the raw addresses by `_dyld_get_image_vmaddr_slide`.  Neither
/// exists on Linux, so the module is compiled only where it can work; see the
/// stub below.
#[cfg(target_os = "macos")]
mod prof {
    use std::ffi::c_void;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;

    const CAP: usize = 1 << 21;
    static mut PCS: [u64; CAP] = [0; CAP];
    static N: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" {
        fn _dyld_get_image_vmaddr_slide(index: u32) -> isize;
    }

    extern "C" fn handler(_sig: i32, _info: *mut libc::siginfo_t, ctx: *mut c_void) {
        if ctx.is_null() {
            return;
        }
        // SAFETY: `ctx` is the ucontext_t the kernel built for this signal.
        let uc = ctx.cast::<libc::ucontext_t>();
        let pc = unsafe { (*uc).uc_mcontext.as_ref() }.map_or(0, |mc| mc.__ss.__pc);
        let i = N.fetch_add(1, Ordering::Relaxed);
        if i < CAP {
            // SAFETY: `i < CAP`, and the handler is the only writer.
            unsafe { *(&raw mut PCS).cast::<u64>().add(i) = pc };
        }
    }

    /// Install the sampler, if `SIMMERV_PROF` is set.
    pub fn start() {
        if std::env::var_os("SIMMERV_PROF").is_none() {
            return;
        }
        let hz: i32 = std::env::var("SIMMERV_PROF_HZ")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1000);
        // SAFETY: a zeroed sigaction with our handler and
        // SA_SIGINFO|SA_RESTART.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = handler as *const () as usize;
            sa.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
            libc::sigemptyset(&raw mut sa.sa_mask);
            libc::sigaction(libc::SIGPROF, &raw const sa, std::ptr::null_mut());
            // ITIMER_PROF counts CPU time, so the rate does not depend on how
            // many other processes are competing for the machine.
            let it = libc::itimerval {
                it_interval: libc::timeval {
                    tv_sec: 0,
                    tv_usec: 1_000_000 / hz,
                },
                it_value: libc::timeval {
                    tv_sec: 0,
                    tv_usec: 1_000_000 / hz,
                },
            };
            libc::setitimer(libc::ITIMER_PROF, &raw const it, std::ptr::null_mut());
        }
    }

    /// Write `pc` per line to `SIMMERV_PROF`, prefixed by the image slide.
    pub fn dump() {
        let Some(path) = std::env::var_os("SIMMERV_PROF") else {
            return;
        };
        let n = N.load(Ordering::Relaxed).min(CAP);
        let slide = unsafe { _dyld_get_image_vmaddr_slide(0) } as u64;
        let mut out = format!("#slide {slide:#x}\n");
        // SAFETY: `n <= CAP` and nothing is writing any more.
        let pcs = unsafe { std::slice::from_raw_parts((&raw const PCS).cast::<u64>(), n) };
        for pc in pcs {
            out.push_str(&format!("{pc}\n"));
        }
        let _ = std::fs::write(path, out);
    }
}

/// No sampler off macOS.  The harness still builds (and CI is Linux), it just
/// cannot take PC samples; `start`/`dump` become no-ops.
#[cfg(not(target_os = "macos"))]
mod prof {
    pub fn start() {}
    pub fn dump() {}
}

fn new_emulator(ram_bytes: usize) -> Emulator {
    Emulator::new(
        Box::new(DummySerialBackend::new()),
        ram_bytes,
        DEFAULT_UOP_ENTRIES,
        CacheMode::Skew,
    )
}

fn load_binary(emu: &mut Emulator, path: &str, addr: u64) -> anyhow::Result<u64> {
    let data = std::fs::read(path)?;
    let mut symbols = BTreeMap::new();
    let entry = emu.load_image(path, &data, Some(addr), &mut symbols)?;
    if let Some(tohost) = symbols.get("tohost") {
        emu.tohost_addr = *tohost;
    }
    Ok(entry)
}

// ---------------------------------------------------------------------------
// elf: bare-metal micro-benchmarks
// ---------------------------------------------------------------------------

/// One bare-metal run: load `path` into a fresh machine, run to completion,
/// return (cycles, wall).
///
/// The machine is rebuilt per rep because the run ends with the guest's state
/// everywhere; only allocation and the timed region are separate, so the cost
/// of building it stays out of the measurement.
fn run_elf_once(path: &str) -> anyhow::Result<(u64, Duration)> {
    // A bare-metal riscv-tests benchmark needs a few MiB at most; 2 GiB of
    // zeroed RAM would cost more to build than the run costs to execute.
    let mut emu = new_emulator(64 * 1024 * 1024);
    let entry = load_binary(&mut emu, path, 0x8000_0000)?;
    emu.cpu.update_pc(entry);
    let t = Instant::now();
    emu.run_program();
    let wall = t.elapsed();
    Ok((emu.cpu.cycle, wall))
}

fn bench_elf(path: &str, reps: usize) -> anyhow::Result<()> {
    let (cycles, _) = run_elf_once(path)?;
    println!("{path}: {cycles} cycles");

    let mut rates = Vec::with_capacity(reps);
    for _ in 0..reps {
        let (cycles, wall) = run_elf_once(path)?;
        rates.push(cycles as f64 / wall.as_secs_f64() / 1e6);
    }
    rates.sort_by(f64::total_cmp);
    let worst = rates[0];
    let median = rates[rates.len() / 2];
    let best = rates[rates.len() - 1];
    println!("  {reps} reps: median {median:.1} Mc/s  best {best:.1}  worst {worst:.1}");
    Ok(())
}

// ---------------------------------------------------------------------------
// linux: boot a rootfs for a fixed cycle budget
// ---------------------------------------------------------------------------

/// One-line histogram: mean, the cumulative share at a few cut points, and a
/// coarse log-bucketed shape.  Printed rather than plotted because the question
/// is "are blocks big enough in practice", which a mean plus a tail weight
/// answers directly.
fn hist_summary(h: &[u64; MAX_BLOCK_LEN + 1], total: u64) -> String {
    if total == 0 {
        return "(none)".to_string();
    }
    let sum: u64 = (1..=MAX_BLOCK_LEN).map(|i| h[i] * i as u64).sum();
    let cum = |up_to: usize| -> f64 {
        let n: u64 = (1..=up_to).map(|i| h[i]).sum();
        100.0 * n as f64 / total as f64
    };
    // Buckets: 1..=4 exact, then 5-8, 9-16, 17-24, 25-32, 33-48.  The 24-uop
    // edges bracket one slot; the rest show the long tail.
    let bucket = |lo: usize, hi: usize| -> u64 { (lo..=hi).map(|i| h[i]).sum() };
    format!(
        "mean {:.1}  \
         <=4 {:.0}%  <=8 {:.0}%  <=16 {:.0}%  <=24 {:.0}%  \
         |1-4 {}  5-8 {}  9-16 {}  17-24 {}  25-32 {}  33-48 {} (=48 {})",
        sum as f64 / total as f64,
        cum(4),
        cum(8),
        cum(16),
        cum(24),
        bucket(1, 4),
        bucket(5, 8),
        bucket(9, 16),
        bucket(17, 24),
        bucket(25, 32),
        bucket(33, 48),
        h[MAX_BLOCK_LEN],
    )
}

/// Print the cycle rate, uop-cache behaviour and the fence census.
///
/// Shared by every mode that boots a real guest, so the numbers are directly
/// comparable between them: the accounting does not change with the workload,
/// only the workload does.
fn print_census(label: &str, emu: &Emulator, cycles: u64, wall: Duration) {
    let stats = emu.bb_stats();
    let hit = 100.0 * stats.hits as f64 / cycles.max(1) as f64;
    println!(
        "{label}: {cycles} cycles in {:.2}s = {:.1} Mc/s",
        wall.as_secs_f64(),
        cycles as f64 / wall.as_secs_f64() / 1e6,
    );
    println!(
        "  uop$ occ {}/{}  blocks {}  avg_len {:.1}  insns-from-cache {hit:.1}%  \
         cold {}  conflict {}",
        stats.occupied,
        stats.capacity,
        stats.block_hits,
        stats.hits as f64 / stats.block_hits.max(1) as f64,
        stats.cold_misses,
        stats.conflict_misses,
    );
    // The uop cache's own counts.  These are the *drains*, so they differ from
    // the fence census below whenever several fences land between two block
    // entries and coalesce into one flush.
    println!(
        "  uop$ flush:  full {}  asid {}  vpage {}  vpage_asid {}  (capacity {})",
        stats.flush_full,
        stats.flush_asid,
        stats.flush_vpage,
        stats.flush_vpage_asid,
        stats.capacity,
    );

    // ── block-length distributions ────────────────────────────────────────
    //
    // `inserted` counts the blocks stored; `dynamic` counts executions, so it
    // is weighted by how often each block ran.  A block occupies
    // `(len+1)/SLOT_UOPS` slots (the +1 is the `End` sentinel), so the gap
    // between the uops a block stores and the slot capacity it reserves is
    // the internal fragmentation.
    let ins = emu.bb_len_histogram();
    let dyn_h = emu.bb_dyn_len_histogram();
    let dyn_total = dyn_h.iter().sum();
    let (live_blocks, live_uops) = emu.bb_residency();
    let ring = emu.bb_ring_uops();
    let insert_uops: u64 = (1..=MAX_BLOCK_LEN)
        .map(|len| ins[len] * (len as u64 + 1))
        .sum();
    let insert_blocks: u64 = ins.iter().sum();
    println!(
        "  uop$ len (static, per insert):  {}",
        hist_summary(ins, insert_blocks)
    );
    println!(
        "  uop$ len (dynamic, per exec):   {}",
        if dyn_total == 0 {
            "(none -- rebuild with --features bb-hist)".to_string()
        } else {
            hist_summary(dyn_h, dyn_total)
        }
    );
    // `live_blocks` counts directory entries, not slots, and the denominator is
    // the directory -- 4x the old slot count.  A lower percentage here than the
    // slot design reported is not a regression; it is a different unit.
    println!(
        "  uop$ residency:  live blocks {live_blocks}/{}  reachable uops {live_uops} \
         of {ring} ring  ({:.0}% of the store reachable)",
        stats.capacity,
        100.0 * live_uops as f64 / ring.max(1) as f64,
    );
    // Internal fragmentation is gone with the slot quantum: a block occupies
    // exactly `len + 1` uops.  What the store loses instead is uops the
    // directory has dropped that the head has not yet lapped, which is the gap
    // between the two figures above.
    println!("  uop$ stored:  {insert_uops} uops inserted over the run");
    let tlb = emu.cpu.mmu.tlb_stats();
    let sf_total = tlb.sfence_full + tlb.sfence_asid + tlb.sfence_vpage + tlb.sfence_vpage_asid;
    let pct = |n: u64| {
        if sf_total > 0 {
            100.0 * n as f64 / sf_total as f64
        } else {
            0.0
        }
    };
    println!(
        "  sfence.vma {sf_total} total ({:.1}/Mi):  \
         x0,x0 {}  x0,rs2 {}  rs1,x0 {}  rs1,rs2 {}",
        sf_total as f64 / cycles.max(1) as f64 * 1e6,
        format_args!("{} ({:.1}%)", tlb.sfence_full, pct(tlb.sfence_full)),
        format_args!("{} ({:.1}%)", tlb.sfence_asid, pct(tlb.sfence_asid)),
        format_args!("{} ({:.1}%)", tlb.sfence_vpage, pct(tlb.sfence_vpage)),
        format_args!(
            "{} ({:.1}%)",
            tlb.sfence_vpage_asid,
            pct(tlb.sfence_vpage_asid)
        ),
    );
    // SINVAL.VMA is a separate instruction with its own counters; it is not
    // part of the total above, because conflating the two is exactly what made
    // the first census hard to read.
    let si_total = tlb.sinval_full + tlb.sinval_asid + tlb.sinval_vpage + tlb.sinval_vpage_asid;
    println!(
        "  sinval.vma {si_total} total:  x0,x0 {}  x0,rs2 {}  rs1,x0 {}  rs1,rs2 {}",
        tlb.sinval_full, tlb.sinval_asid, tlb.sinval_vpage, tlb.sinval_vpage_asid,
    );
    println!(
        "  svinval bookends:  sfence.w.inval {}  sfence.inval.ir {}",
        tlb.sfence_w_inval, tlb.sfence_inval_ir,
    );
    println!(
        "  satp writes with ASID != 0: {}  distinct ASIDs seen: {}",
        emu.cpu.mmu.satp_asid_nonzero,
        emu.cpu.mmu.distinct_asids(),
    );
}

/// Boot Linux and run for a fixed number of emulated cycles.
fn bench_linux(
    fw: &str,
    fs: &str,
    budget: u64,
    entries: usize,
    mode: CacheMode,
) -> anyhow::Result<()> {
    let mut emu = Emulator::new(
        Box::new(DummySerialBackend::new()),
        2048 * 1024 * 1024,
        entries,
        mode,
    );
    emu.setup_filesystem_at(0, std::fs::read(fs)?);
    let entry = load_binary(&mut emu, fw, 0x8000_0000)?;
    emu.cpu.update_pc(entry);

    let t = Instant::now();
    while emu.cpu.cycle < budget {
        // Same step the real run loop takes, so the device/timer service rate
        // and interrupt latency match a normal boot.
        emu.tick(600);
    }
    let wall = t.elapsed();
    let cycles = emu.cpu.cycle;
    print_census(&format!("linux[{entries}/{mode:?}]"), &emu, cycles, wall);
    Ok(())
}

/// Boot a full Ubuntu system to a console marker and report the same census as
/// `linux`.
///
/// The disk must be file-backed.  `linux` reads its image into a `Vec` and
/// hands that to `VirtioBlockDisk`, which is fine for a 50 MiB coremark rootfs
/// but would put all 10 GiB of a preinstalled server image on the host heap;
/// `setup_filesystem_file_at` backs the device with the file descriptor
/// instead, so the image is never resident.
///
/// This is the mode that matters for the fence census.  `elf` and `linux` are
/// single address spaces that barely switch, so they cannot show what a design
/// actually has to survive; a systemd boot forks, mmaps, tears down page
/// tables and switches ASIDs the way real software does.  The run stops at
/// `ubuntu login:`, i.e. the end of userspace bring-up.
///
/// The image is opened read-write -- that is how `-f` attaches it in `sim` --
/// so the guest's writes persist into it.
fn bench_ubuntu(
    fw: &str,
    img: &str,
    marker: &str,
    max_seconds: f64,
    entries: usize,
    mode: CacheMode,
) -> anyhow::Result<()> {
    // A file-backed disk holds no snapshot to reset, so the machine is built
    // once and the marker is published through a shared flag the loop polls.
    let hit = Arc::new(AtomicBool::new(false));
    let marks = Arc::new(Mutex::new(Vec::new()));
    let t = Instant::now();
    let mut emu = Emulator::new(
        Box::new(SharingTerminal {
            inner: MarkerTerminal::new(marker, t, Arc::clone(&marks)),
            hit: Arc::clone(&hit),
        }),
        2048 * 1024 * 1024,
        entries,
        mode,
    );

    let entry = load_binary(&mut emu, fw, 0x8000_0000)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(img)?;
    emu.setup_filesystem_file_at(0, file);
    emu.cpu.update_pc(entry);

    let mut next_report = 30.0_f64;
    while !hit.load(std::sync::atomic::Ordering::Relaxed) {
        emu.tick(600);
        let elapsed = t.elapsed().as_secs_f64();
        if elapsed > next_report {
            next_report = elapsed + 30.0;
            println!(
                "[bench] {elapsed:7.1}s  {} cycles  {:.1} Mc/s",
                emu.cpu.cycle,
                emu.cpu.cycle as f64 / elapsed / 1e6,
            );
        }
        if elapsed > max_seconds {
            break;
        }
    }
    let wall = t.elapsed();
    if !hit.load(std::sync::atomic::Ordering::Relaxed) {
        println!(
            "  did NOT reach {marker:?} (gave up after {:.1}s)",
            wall.as_secs_f64()
        );
    }
    print_census(
        &format!("ubuntu[{entries}/{mode:?}]"),
        &emu,
        emu.cpu.cycle,
        wall,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// gb5: end-to-end Geekbench 5
// ---------------------------------------------------------------------------

/// Serial backend that echoes the guest console and watches for a marker.
///
/// The run stops the moment the marker appears, so the measured quantity is
/// "host seconds to drive the guest to this point", which needs no cycle
/// accounting to interpret and is what a user of the emulator actually feels.
/// Echoing the console matters for a long run: it is how you tell which
/// subtest was running when a profile was taken.
struct MarkerTerminal {
    needle: Vec<u8>,
    /// Rolling window of the most recently seen bytes, `needle.len()` wide.
    window: Vec<u8>,
    /// Set once the marker has been seen.
    hit: bool,
    /// Console bytes not yet written out, flushed on a newline. Buffering
    /// matters: a write syscall per guest byte is slow enough to distort a
    /// measurement (the CLI's dummy terminal does exactly that).
    pending: Vec<u8>,
    /// When the run started, so a subtest banner can be timestamped as it is
    /// printed. GB5 announces each subtest by name, so the console stream is
    /// also a per-subtest breakdown of the run for free -- which is what makes
    /// a 10-minute A/B worth running: one pair of runs yields nine deltas
    /// instead of one.
    start: Instant,
    marks: Arc<Mutex<Vec<(f64, String)>>>,
}

impl MarkerTerminal {
    fn new(needle: &str, start: Instant, marks: Arc<Mutex<Vec<(f64, String)>>>) -> Self {
        Self {
            needle: needle.as_bytes().to_vec(),
            window: Vec::new(),
            hit: false,
            pending: Vec::new(),
            start,
            marks,
        }
    }
}

impl SerialBackend for MarkerTerminal {
    fn put_byte(&mut self, value: u8) {
        self.window.push(value);
        if self.window.len() > self.needle.len() {
            self.window.remove(0);
        }
        if self.window == self.needle {
            self.hit = true;
        }
        self.pending.push(value);
        if value == b'\n' {
            use std::io::Write as _;
            let _ = std::io::stdout().write_all(&self.pending);
            let _ = std::io::stdout().flush();
            if let Ok(line) = std::str::from_utf8(&self.pending)
                && let Some(name) = line.trim().strip_prefix("Running ")
                && let Ok(mut marks) = self.marks.lock()
            {
                marks.push((self.start.elapsed().as_secs_f64(), name.to_owned()));
            }
            self.pending.clear();
        }
    }
    fn get_input(&mut self) -> u8 { 0 }
    fn put_input(&mut self, _value: u8) {}
    fn get_output(&mut self) -> u8 { 0 }
}

/// Uop-cache state sampled at one instant of a run.
///
/// A long boot yields one aggregate census, which hides the fact that a
/// benchmark's subtests can differ by an order of magnitude in how they treat
/// the cache.  Sampling at each subtest banner turns one number into a table.
/// The histograms are copied out because the cache keeps mutating them.
#[derive(Clone, Default)]
struct CcSnapshot {
    at: f64,
    cycle: u64,
    stats: UopCacheStats,
    ins: Vec<u64>,
    dynh: Vec<u64>,
}

fn take_snapshot(emu: &Emulator, at: f64) -> CcSnapshot {
    CcSnapshot {
        at,
        cycle: emu.cpu.cycle,
        stats: emu.bb_stats(),
        ins: emu.bb_len_histogram().to_vec(),
        dynh: emu.bb_dyn_len_histogram().to_vec(),
    }
}

/// Mean of a `MAX_BLOCK_LEN + 1` histogram, ignoring the unused index 0.
fn hist_mean(h: &[u64]) -> f64 {
    let total: u64 = h.iter().sum();
    if total == 0 {
        return 0.0;
    }
    let sum: u64 = (1..h.len()).map(|i| h[i] * i as u64).sum();
    sum as f64 / total as f64
}

/// Print one line per subtest: what the uop cache did *within* that subtest,
/// derived from consecutive snapshots.
///
/// A `Running X` banner means X starts there, so the work of X is the interval
/// *after* its banner -- interval `j` is labelled with `marks[j - 1]`, not
/// `marks[j]`.  Labelling by the banner at the interval's end instead puts
/// AES-XTS's 170 s under "Text Compression" and makes AES-XTS look free.
fn print_subtest_census(snaps: &[CcSnapshot], marks: &[(f64, String)]) {
    if snaps.len() < 2 {
        return;
    }
    println!(
        "  {:<22} {:>7} {:>12} {:>7} {:>7} {:>10} {:>6} {:>9} {:>10} {:>7}",
        "subtest", "wall", "cycles", "Mc/s", "from$", "blocks", "avg", "cold", "conflict", "dynlen"
    );
    for j in 0..snaps.len() - 1 {
        let (a, b) = (&snaps[j], &snaps[j + 1]);
        // Interval 0 is everything before the first banner: firmware, kernel
        // and init, none of which any banner names.
        let name = marks
            .get(j.wrapping_sub(1))
            .map_or_else(|| "(pre-gb5)".to_string(), |(_, n)| n.clone());
        let wall = b.at - a.at;
        if wall <= 0.0 {
            continue;
        }
        let cycles = b.cycle.saturating_sub(a.cycle);
        let dh = b.stats.hits.saturating_sub(a.stats.hits);
        let db = b.stats.block_hits.saturating_sub(a.stats.block_hits);
        // The dynamic histogram delta gives this subtest's own block-length
        // mix; fall back to the cumulative ratio when uninstrumented.
        let dyn_delta: Vec<u64> = b
            .dynh
            .iter()
            .zip(a.dynh.iter())
            .map(|(y, x)| y.saturating_sub(*x))
            .collect();
        let dynlen = if dyn_delta.iter().sum::<u64>() > 0 {
            hist_mean(&dyn_delta)
        } else {
            dh as f64 / db.max(1) as f64
        };
        println!(
            "  {:<22} {:>6.1}s {:>12} {:>7.1} {:>6.1}% {:>10} {:>6.1} {:>9} {:>10} {:>7.1}",
            name,
            wall,
            cycles,
            cycles as f64 / wall / 1e6,
            100.0 * dh as f64 / cycles.max(1) as f64,
            db,
            dh as f64 / db.max(1) as f64,
            b.stats.cold_misses.saturating_sub(a.stats.cold_misses),
            b.stats
                .conflict_misses
                .saturating_sub(a.stats.conflict_misses),
            dynlen,
        );
    }
}

/// Which Geekbench initramfs to boot.  The arms differ only in how the machine
/// is laid out before the run; what is measured is the same either way.
#[derive(Clone, Copy)]
enum Gb {
    /// Geekbench 5, at the layout `~/smolrv64/workloads/gb5`'s `ref` target
    /// pins: DTB at 0x9ff00000, initrd at 0x96270e00.  Those addresses are an
    /// external contract -- the FPGA harness reproduces them exactly, so the
    /// emulator and the hardware run the same image at the same addresses --
    /// which is why this arm keeps `setup_dtb_at` rather than moving onto
    /// `setup_initrd` like the one below.
    Gb5,
    /// Geekbench 6.  Nothing is pinned: the ramdisk goes wherever
    /// `setup_initrd` puts it, and that call inserts `linux,initrd-start` /
    /// `-end` into the emulator's own tree.  The hand-written `gb6.dtb` that
    /// used to carry those two properties -- and every caller that had to keep
    /// an address in step with it -- is not needed here.
    Gb6,
}

impl Gb {
    const fn name(self) -> &'static str {
        match self {
            Self::Gb5 => "gb5",
            Self::Gb6 => "gb6",
        }
    }

    /// The ramdisk's file name within the workload directory.
    const fn initrd(self) -> &'static str {
        match self {
            Self::Gb5 => "img.Geekbench5.cpio",
            Self::Gb6 => "new-img.gb6.cpio",
        }
    }

    /// The default marker: the last console line before the interesting part.
    const fn marker(self) -> &'static str {
        match self {
            Self::Gb5 => "Running AES-XTS",
            Self::Gb6 => "Multi-Core",
        }
    }
}

/// Boot one of the Geekbench initramfs images and stop when the console prints
/// `marker`, sampling the uop cache at every subtest banner on the way.
///
/// Both suites announce each subtest with a `Running <name>` line, so the
/// console stream is a per-subtest breakdown of the run for free -- which is
/// what makes a whole-suite trace worth capturing rather than a window: one
/// capture replays into a table, instead of one aggregate in which a single
/// subtest dominates every number.
fn bench_gb(
    which: Gb,
    dir: &str,
    marker: &str,
    max_seconds: f64,
    budget: u64,
    entries: usize,
    mode: CacheMode,
) -> anyhow::Result<()> {
    // `Emulator::new` takes ownership of the backend, so the marker is
    // published through a shared flag the run loop can poll.
    let hit = Arc::new(AtomicBool::new(false));
    let marks = Arc::new(Mutex::new(Vec::new()));
    // Started before the machine is built so the subtest timestamps and the
    // total below are on the same clock.
    let t = Instant::now();
    let mut emu = Emulator::new(
        Box::new(SharingTerminal {
            inner: MarkerTerminal::new(marker, t, Arc::clone(&marks)),
            hit: Arc::clone(&hit),
        }),
        2048 * 1024 * 1024,
        entries,
        mode,
    );

    let fw = format!("{dir}/fw_payload.bin");
    let initrd = format!("{dir}/{}", which.initrd());

    // The kernel goes in first: `setup_initrd` places the ramdisk clear of
    // everything already loaded, and that is how it learns what is there.
    let entry = load_binary(&mut emu, &fw, 0x8000_0000)?;
    match which {
        Gb::Gb5 => {
            load_binary(&mut emu, &initrd, 0x9627_0e00)?;
            emu.setup_dtb_at(&std::fs::read(format!("{dir}/gb5.dtb"))?, 0x9ff0_0000);
        }
        Gb::Gb6 => {
            emu.setup_initrd(&std::fs::read(&initrd)?)?;
        }
    }
    emu.cpu.update_pc(entry);

    let mut next_report = 30.0_f64;
    // Snapshot at t=0 and again at each subtest banner, so the loop below can
    // difference consecutive snapshots into a per-subtest census.  The marks
    // vector is behind a mutex, so it is polled on a 10 ms cadence rather than
    // every iteration -- the run loop runs once per 600 cycles, which at GB5's
    // ~380 Mc/s is far too often to take a lock.
    let mut snaps = vec![take_snapshot(&emu, 0.0)];
    let mut seen_marks = 0_usize;
    let mut next_mark_poll = 0.0_f64;
    while !hit.load(std::sync::atomic::Ordering::Relaxed) {
        emu.tick(600);
        let elapsed = t.elapsed().as_secs_f64();
        if elapsed > next_mark_poll {
            next_mark_poll = elapsed + 0.01;
            // A banner is announced as it is written, so a snapshot taken now
            // bounds the subtest it names from below.
            let n_marks = marks.lock().map_or(0, |m| m.len());
            while seen_marks < n_marks {
                snaps.push(take_snapshot(&emu, elapsed));
                // Name the interval that is starting.  Without this a replay of
                // a whole-suite trace reports one aggregate in which Clang is
                // 93% of the misses and 1.4% of the cycles, which is a number
                // rather than a result.
                if let Ok(m) = marks.lock()
                    && let Some((_, name)) = m.get(seen_marks)
                {
                    emu.cpu.trace_mark(name);
                }
                seen_marks += 1;
            }
        }
        if elapsed > next_report {
            next_report = elapsed + 30.0;
            println!(
                "[bench] {elapsed:7.1}s  {} cycles  {:.1} Mc/s",
                emu.cpu.cycle,
                emu.cpu.cycle as f64 / elapsed / 1e6,
            );
        }
        if emu.cpu.cycle >= budget || elapsed > max_seconds {
            break;
        }
    }
    let wall = t.elapsed();
    // The window after the last banner, so the table covers the whole run.
    if let Ok(m) = marks.lock()
        && seen_marks < m.len() + 1
    {
        snaps.push(take_snapshot(&emu, wall.as_secs_f64()));
    }

    println!(
        "{}: {} cycles in {:.1}s = {:.1} Mc/s",
        which.name(),
        emu.cpu.cycle,
        wall.as_secs_f64(),
        emu.cpu.cycle as f64 / wall.as_secs_f64() / 1e6,
    );
    if hit.load(std::sync::atomic::Ordering::Relaxed) {
        println!("  reached marker {marker:?} in {:.1}s", wall.as_secs_f64());
    } else {
        println!(
            "  did NOT reach {marker:?} (gave up after {:.1}s)",
            wall.as_secs_f64()
        );
    }
    // One `mark` line per subtest, with the time spent in that subtest: the
    // banner is printed just before the subtest starts, so the difference
    // between consecutive banners is the subtest's own cost.
    if let Ok(marks) = marks.lock() {
        let mut prev = 0.0_f64;
        for (at, name) in marks.iter() {
            println!("  mark {name:<22} {at:8.1}s  (+{:.1}s)", at - prev);
            prev = *at;
        }
        print_subtest_census(&snaps, &marks);
    }
    // The uop-cache census covers whatever window the marker cut off, so it is
    // only readable alongside the `mark` lines above -- a census taken at
    // "Running Image Compression" is the crypto/text half of the suite, not
    // the suite.
    print_census(
        &format!("{}[{entries}/{mode:?}]", which.name()),
        &emu,
        emu.cpu.cycle,
        wall,
    );
    Ok(())
}

/// Wraps a `MarkerTerminal` and mirrors its hit flag into a shared
/// `AtomicBool`, so the run loop can poll for the marker without reaching into
/// the device.
struct SharingTerminal {
    inner: MarkerTerminal,
    hit: Arc<AtomicBool>,
}

impl SerialBackend for SharingTerminal {
    fn put_byte(&mut self, value: u8) {
        self.inner.put_byte(value);
        if self.inner.hit {
            self.hit.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }
    fn get_input(&mut self) -> u8 { 0 }
    fn put_input(&mut self, _value: u8) {}
    fn get_output(&mut self) -> u8 { 0 }
}

fn main() -> anyhow::Result<()> {
    prof::start();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let r = run(&args);
    prof::dump();
    r
}

fn run(args: &[String]) -> anyhow::Result<()> {
    match args.first().map(String::as_str) {
        Some("elf") => {
            let path = args
                .get(1)
                .map_or("benches/dhrystone.riscv", String::as_str);
            let reps: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(20);
            bench_elf(path, reps)
        }
        Some("linux") => {
            let fw = args.get(1).map_or("linux/fw_payload.bin", String::as_str);
            let fs = args
                .get(2)
                .map_or("linux/rootfs-auto-coremark.img", String::as_str);
            // Millions of emulated cycles.
            let meg: u64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(2000);
            // Same overrides as the `ubuntu`/`gb5` arms, so the replay's model
            // of the cache can be validated against a second index function:
            // `bench linux <fw> <fs> <meg> [entries] [direct|skew]`.
            let entries = args
                .get(4)
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_UOP_ENTRIES);
            let mode = match args.get(5).map(String::as_str) {
                Some("direct") => CacheMode::Direct,
                _ => CacheMode::Skew,
            };
            bench_linux(fw, fs, meg * 1_000_000, entries, mode)
        }
        Some("ubuntu") => {
            let img = args.get(1).map_or(
                "linux/ubuntu-25.04-preinstalled-server-riscv64.img",
                String::as_str,
            );
            let fw = args.get(2).map_or("linux/fw_payload.bin", String::as_str);
            // The last line the console prints before the login prompt, so the
            // run ends at the end of userspace bring-up rather than an idle
            // login screen.
            let marker = args.get(3).map_or("ubuntu login:", String::as_str);
            let secs: f64 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(1800.0);
            // Optional design overrides, so `SLOT_UOPS`/capacity/mapping arms
            // can be swept without a rebuild: `bench ubuntu <img>
            // <fw> <marker> <secs> [entries] [direct|skew]`.
            let entries = args
                .get(5)
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_UOP_ENTRIES);
            let mode = match args.get(6).map(String::as_str) {
                Some("direct") => CacheMode::Direct,
                _ => CacheMode::Skew,
            };
            bench_ubuntu(fw, img, marker, secs, entries, mode)
        }
        Some("gb5" | "gb6") => {
            let which = match args.first().map(String::as_str) {
                Some("gb6") => Gb::Gb6,
                _ => Gb::Gb5,
            };
            let home = std::env::var("HOME").unwrap_or_default();
            let default_dir = format!("{home}/smolrv64/workloads/{}", which.name());
            let dir = args.get(1).map_or(default_dir.as_str(), String::as_str);
            // The marker is where the run stops.  The arms differ here on
            // purpose: GB5's default is its first subtest, which is the
            // end-to-end number the perf work has always quoted, while GB6's
            // is the end of the single-core suite -- an arm added to be traced,
            // and a trace is only worth its hundred gigabytes if it covers a
            // suite rather than its first subtest.
            let marker = args.get(2).map_or_else(|| which.marker(), String::as_str);
            let secs: f64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(600.0);
            // 0 = no cycle cap: run until the marker or the time limit.
            let meg: u64 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(0);
            let budget = if meg == 0 { u64::MAX } else { meg * 1_000_000 };
            // Optional design overrides, mirroring the `ubuntu` arm, so
            // capacity and mapping arms can be swept without a
            // rebuild: `bench gb5 <dir> <marker> <secs>
            // <megacycles> [entries] [direct|skew]`.
            let entries = args
                .get(5)
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_UOP_ENTRIES);
            let mode = match args.get(6).map(String::as_str) {
                Some("direct") => CacheMode::Direct,
                _ => CacheMode::Skew,
            };
            bench_gb(which, dir, marker, secs, budget, entries, mode)
        }
        _ => {
            eprintln!(
                "usage: bench elf    <elf> [reps]\n       \
                        bench linux  <fw> <rootfs> [megacycles] [entries] [direct|skew]\n       \
                        bench ubuntu [img] [fw] [marker] [max_seconds]\n       \
                        bench gb5    [dir] [marker] [max_seconds] [megacycles] [entries] [direct|skew]\n       \
                        bench gb6    [dir] [marker] [max_seconds] [megacycles] [entries] [direct|skew]"
            );
            Ok(())
        }
    }
}
