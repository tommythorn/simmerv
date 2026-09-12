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
//!
//! `elf` and `linux` report emulated cycles per second, where a cycle is the
//! emulator's own accounting: one per instruction plus one per block entry.
//!
//! ```text
//! cargo run --release --example bench -- elf benches/dhrystone.riscv 30
//! cargo run --release --example bench -- linux linux/fw_payload.bin \
//!     linux/rootfs-auto-coremark.img 2000
//! cargo run --release --example bench -- gb5
//! ```

use simmerv::Emulator;
use simmerv::serial_backend::DummySerialBackend;
use simmerv::serial_backend::SerialBackend;
use simmerv::uop_cache::CacheMode;
use simmerv::uop_cache::DEFAULT_UOP_ENTRIES;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

// ---------------------------------------------------------------------------
// prof: in-process PC sampling
// ---------------------------------------------------------------------------

/// Everything hot in this emulator is inlined into `step_block`, so a
/// symbol-level profile (what `sample` gives) says only "step_block: 96%" and
/// cannot be acted on.  This samples the program counter straight out of the
/// signal context at a fixed rate and dumps the raw PCs; symbolising those
/// afterwards attributes time to source lines *within* the inlined loop.
///
/// Enabled by setting `SIMMERV_PROF` to the output path; off (and so costing
/// nothing) otherwise.  The handler only stores the PC, which is async-signal
/// safe; aggregation happens after the run.
mod prof {
    use super::AtomicUsize;
    use super::Ordering;
    use std::ffi::c_void;

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
            sa.sa_sigaction = handler as usize;
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

/// Boot Linux and run for a fixed number of emulated cycles.
fn bench_linux(fw: &str, fs: &str, budget: u64) -> anyhow::Result<()> {
    let mut emu = new_emulator(2048 * 1024 * 1024);
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
    let stats = emu.bb_stats();
    let hit = 100.0 * stats.hits as f64 / cycles.max(1) as f64;
    println!(
        "linux: {cycles} cycles in {:.2}s = {:.1} Mc/s",
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
            if let Ok(line) = std::str::from_utf8(&self.pending) {
                if let Some(name) = line.trim().strip_prefix("Running ") {
                    if let Ok(mut marks) = self.marks.lock() {
                        marks.push((self.start.elapsed().as_secs_f64(), name.to_owned()));
                    }
                }
            }
            self.pending.clear();
        }
    }
    fn get_input(&mut self) -> u8 { 0 }
    fn put_input(&mut self, _value: u8) {}
    fn get_output(&mut self) -> u8 { 0 }
}

/// Boot the GB5 initramfs exactly as `~/smolrv64/workloads/gb5`'s `ref` target
/// does, and stop when the console prints `marker`.
///
/// Addresses are that harness's memory layout (2 GiB; DTB at 0x9ff00000,
/// initrd at 0x96270e00); they are not discoverable from the image, hence
/// spelled out here rather than parameterised.
fn bench_gb5(dir: &str, marker: &str, max_seconds: f64, budget: u64) -> anyhow::Result<()> {
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
        DEFAULT_UOP_ENTRIES,
        CacheMode::Skew,
    );

    let fw = format!("{dir}/fw_payload.bin");
    let initrd = format!("{dir}/img.Geekbench5.cpio");
    let dtb = format!("{dir}/gb5.dtb");

    let entry = load_binary(&mut emu, &fw, 0x8000_0000)?;
    load_binary(&mut emu, &initrd, 0x9627_0e00)?;
    emu.setup_dtb_at(&std::fs::read(&dtb)?, 0x9ff0_0000);
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
        if emu.cpu.cycle >= budget || elapsed > max_seconds {
            break;
        }
    }
    let wall = t.elapsed();

    println!(
        "gb5: {} cycles in {:.1}s = {:.1} Mc/s",
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
    }
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
            bench_linux(fw, fs, meg * 1_000_000)
        }
        Some("gb5") => {
            let home = std::env::var("HOME").unwrap_or_default();
            let default_dir = format!("{home}/smolrv64/workloads/gb5");
            let dir = args.get(1).map_or(default_dir.as_str(), String::as_str);
            // The marker is the last line GB5 prints before it starts timing
            // the first subtest, so everything before it is boot + setup.
            let marker = args.get(2).map_or("Running AES-XTS", String::as_str);
            let secs: f64 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(600.0);
            // 0 = no cycle cap: run until the marker or the time limit.
            let meg: u64 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(0);
            let budget = if meg == 0 { u64::MAX } else { meg * 1_000_000 };
            bench_gb5(dir, marker, secs, budget)
        }
        _ => {
            eprintln!(
                "usage: bench elf   <elf> [reps]\n       \
                        bench linux <fw> <rootfs> [megacycles]\n       \
                        bench gb5   [dir] [marker] [max_seconds] [megacycles]"
            );
            Ok(())
        }
    }
}
