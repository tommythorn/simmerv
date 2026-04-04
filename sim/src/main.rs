mod dummy_terminal;
mod nonblocknoecho;
mod popup_terminal;

use crate::dummy_terminal::DummyTerminal;
use crate::popup_terminal::PopupTerminal;
use anyhow::Context;
use anyhow::anyhow;
use anyhow::bail;
use argh::FromArgs;
use simmerv::Emulator;
use simmerv::serial_backend::SerialBackend;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

#[derive(FromArgs)]
#[allow(clippy::doc_markdown)]
#[allow(clippy::struct_excessive_bools)]
/// Simulate a RISC-V RV64GC System on Chip
struct Args {
    /// file system image files
    #[argh(option, short = 'f')]
    fs: Vec<String>,

    /// device Tree Binary
    #[argh(option, short = 'd')]
    dtb: Option<String>,

    /// no popup terminal
    #[argh(switch, short = 'n')]
    no_terminal: bool,

    /// memory size in megabytes
    #[argh(option, short = 'm')]
    memory_megs: Option<usize>,

    /// run with tracing
    #[argh(switch, short = 't')]
    tracing: bool,

    /// allow ctrl-C to terminate app
    #[argh(switch, short = 'c')]
    ctrlc_breaks: bool,

    /// write a snapshot on exit to the given path
    #[argh(option, short = 'w')]
    write_snapshot: Option<String>,

    /// TAP interface name for networking (Linux only)
    #[argh(option, short = 'T')]
    tap: Option<String>,

    /// enable vmnet shared (NAT) networking (macOS only, requires root)
    #[argh(switch)]
    vmnet: bool,

    /// take periodic snapshots: format "N:base_name" where N is tick interval
    #[argh(option, short = 'S')]
    snapshot_interval: Option<String>,

    /// write riscof signature to this file after run
    #[argh(option)]
    riscof_sigfile: Option<String>,

    /// memory region hint for riscof (accepted but unused)
    #[argh(option)]
    #[allow(dead_code)]
    mem_region: Vec<String>,

    /// signature region start hint for riscof (accepted but unused)
    #[argh(option)]
    #[allow(dead_code)]
    sig_region_start: Option<String>,

    /// set up fw_dynamic_info for OpenSBI fw_dynamic firmware; argument is the
    /// kernel entry address (e.g. 0x80200000)
    #[argh(option)]
    fw_dynamic: Option<String>,

    /// uop cache mode: "direct" or "skew" (default: skew)
    #[argh(option)]
    uop_cache_mode: Option<String>,

    /// total uop cache entries (default: 262144, rounded to power of two)
    #[argh(option)]
    uop_cache_entries: Option<usize>,

    /// memory images, elf or binary blobs, optionally follow by a comma and the
    /// the "0x"-prefixed load address in hex (this is required for binary
    /// blobs)
    #[argh(positional)]
    images: Vec<String>,
}

enum TerminalType {
    PopupTerminal,
    DummyTerminal,
}

fn get_terminal(
    terminal_type: &TerminalType,
    ctrlc_breaks: bool,
    exit_flag: Arc<AtomicBool>,
    snapshot_flag: Arc<AtomicBool>,
    verbose_flag: Arc<AtomicBool>,
    speedometer_flag: Arc<AtomicBool>,
    tracing_flag: Arc<AtomicBool>,
) -> Box<dyn SerialBackend> {
    match terminal_type {
        TerminalType::PopupTerminal => Box::new(PopupTerminal::new(
            ctrlc_breaks,
            exit_flag,
            snapshot_flag,
            verbose_flag,
            speedometer_flag,
            tracing_flag,
        )),
        TerminalType::DummyTerminal => Box::new(DummyTerminal::new()),
    }
}

fn write_snap(emulator: &mut Emulator, path: &str) -> anyhow::Result<()> {
    emulator.write_snapshot(path)?;
    if emulator.verbose.load(Ordering::Relaxed) {
        eprintln!("snapshot → {path} [seqno={}]", emulator.cpu.seqno);
    }
    Ok(())
}

fn is_snapshot(data: &[u8]) -> bool { data.len() >= 9 && data[..9] == *b"SIMMERVC7" }

#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn main() -> anyhow::Result<()> {
    env_logger::init();

    let args: Args = argh::from_env();
    let terminal_type = if args.no_terminal {
        TerminalType::DummyTerminal
    } else {
        TerminalType::PopupTerminal
    };
    let exit_flag = Arc::new(AtomicBool::new(false));
    let snapshot_flag = Arc::new(AtomicBool::new(false));
    let verbose_flag = Arc::new(AtomicBool::new(false));
    let speedometer_flag = Arc::new(AtomicBool::new(false));
    let tracing_flag = Arc::new(AtomicBool::new(args.tracing));
    let mut symbols = BTreeMap::new();
    let memory_megs = args.memory_megs.unwrap_or(2048);
    let cache_mode = match args.uop_cache_mode.as_deref() {
        Some("direct") => simmerv::uop_cache::CacheMode::Direct,
        None | Some("skew") => simmerv::uop_cache::CacheMode::Skew,
        Some(other) => {
            anyhow::bail!("unknown uop cache mode: {other:?} (expected \"direct\" or \"skew\")")
        }
    };
    let cache_entries = args.uop_cache_entries.unwrap_or(262144);
    let mut emulator = Emulator::new(
        get_terminal(
            &terminal_type,
            args.ctrlc_breaks,
            Arc::clone(&exit_flag),
            Arc::clone(&snapshot_flag),
            Arc::clone(&verbose_flag),
            Arc::clone(&speedometer_flag),
            Arc::clone(&tracing_flag),
        ),
        memory_megs * 1024 * 1024,
        cache_entries,
        cache_mode,
    );
    emulator.exit_flag = Arc::clone(&exit_flag);
    emulator.verbose = Arc::clone(&verbose_flag);
    emulator.cpu.speedometer_flag = Arc::clone(&speedometer_flag);
    emulator.tracing_flag = Arc::clone(&tracing_flag);

    if let Some(ref iface) = args.tap {
        #[cfg(target_os = "linux")]
        {
            use simmerv::network_backend::TapBackend;
            emulator.setup_network(Box::new(
                TapBackend::open(iface).with_context(|| format!("opening TAP {iface}"))?,
            ));
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = iface;
            bail!("--tap is only supported on Linux");
        }
    }

    if args.vmnet {
        #[cfg(target_os = "macos")]
        {
            use simmerv::network_backend::VmnetBackend;
            emulator.setup_network(Box::new(VmnetBackend::open()?));
        }
        #[cfg(not(target_os = "macos"))]
        bail!("--vmnet is only supported on macOS");
    }

    let mut img_contents = vec![];
    let mut load_addr = None;
    let mut emu_start = None;
    let mut images = 0;
    let mut loaded_snapshot = false;
    // Path to auto-save on Ctrl-C exit: the loaded snapshot name, or "snapshot".
    let mut auto_snapshot_path = "snapshot".to_string();

    for img_path in args.images {
        img_contents.clear();
        let mut parts_iter = img_path.split(',');
        let filename = parts_iter.next().unwrap_or("");
        let mut img_file = File::open(filename).with_context(|| filename.to_string())?;
        img_file
            .read_to_end(&mut img_contents)
            .with_context(|| filename.to_string())?;

        for part in parts_iter {
            if &part[..2] == "0x" {
                load_addr = Some(u64::from_str_radix(&part[2..], 16)?);
            } else {
                bail!("Unsupported file option {part}");
            }
        }

        // Detect snapshot files by magic header.
        if is_snapshot(&img_contents) {
            emulator
                .load_snapshot(&img_contents)
                .with_context(|| filename.to_string())?;
            loaded_snapshot = true;
            auto_snapshot_path = filename.to_string();
            images += 1;
            load_addr = None;
            continue;
        }

        let entry = emulator
            .load_image(filename, &img_contents, load_addr, &mut symbols)
            .with_context(|| filename.to_string())
            .map_err(|e| anyhow!(e))?;

        images += 1;

        if emu_start.is_none() {
            emu_start = Some(entry);
        }

        if let Some(addr) = symbols.get("tohost") {
            emulator.tohost_addr = *addr;
        }

        load_addr = None;
    }

    if let Some(path) = args.dtb {
        let mut file = File::open(&path).with_context(|| path.to_string())?;
        let mut contents = vec![];
        file.read_to_end(&mut contents)?;
        emulator.setup_dtb(&contents)?;
    }

    for path in args.fs {
        if path.ends_with(".zst") {
            let file = File::open(&path).with_context(|| path.to_string())?;
            emulator.setup_filesystem(zstd::stream::decode_all(file)?);
        } else {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .with_context(|| path.to_string())?;
            emulator.setup_filesystem_file(file);
        }
    }

    if images == 0 {
        bail!("I have nothing to run");
    }

    // Only set the PC if we didn't load a snapshot (snapshot already has PC).
    if !loaded_snapshot {
        emulator.cpu.update_pc(emu_start.unwrap_or(0x8000_0000));
    }

    // fw_dynamic: write the fw_dynamic_info struct and set a2.
    // The struct is placed 512 KiB after the firmware base (0x80080000),
    // safely past the firmware image and well before the kernel at 0x80200000.
    if let Some(ref addr_str) = args.fw_dynamic {
        let kernel_addr = u64::from_str_radix(addr_str.trim_start_matches("0x"), 16)
            .with_context(|| format!("invalid --fw-dynamic address: {addr_str}"))?;
        emulator.setup_fw_dynamic(kernel_addr, 0x8008_0000);
    }

    // Run with optional periodic snapshots, or plain run.
    if let Some(spec) = args.snapshot_interval {
        // Format: "N:base_name"
        let mut parts = spec.splitn(2, ':');
        let interval_str = parts.next().unwrap_or("0");
        let base = parts.next().unwrap_or("snapshot");
        let interval: usize = interval_str
            .parse()
            .with_context(|| format!("invalid snapshot interval: {interval_str}"))?;
        emulator.run_with_periodic_snapshots(interval, base);
    } else {
        emulator.run_program();
    }

    // Write riscof signature: dump physical memory [begin_signature, end_signature)
    // as 32-bit hex.
    if let Some(ref sigfile) = args.riscof_sigfile {
        let begin = symbols
            .get("begin_signature")
            .copied()
            .ok_or_else(|| anyhow!("begin_signature symbol not found"))?;
        let end = symbols
            .get("end_signature")
            .copied()
            .ok_or_else(|| anyhow!("end_signature symbol not found"))?;
        use std::io::Write as _;
        let mut out = File::create(sigfile).with_context(|| sigfile.to_string())?;
        let mut addr = begin;
        while addr < end {
            let word = simmerv::device::dma_read_u32(&mut emulator.cpu.mmu.memory, addr);
            writeln!(out, "{word:08x}")?;
            addr += 4;
        }
    }

    // --write-snapshot always wins; fall back to the auto path on Ctrl-C exit.
    if let Some(path) = args.write_snapshot {
        write_snap(&mut emulator, &path).with_context(|| format!("writing snapshot to {path}"))?;
    } else if snapshot_flag.load(Ordering::Relaxed) {
        write_snap(&mut emulator, &auto_snapshot_path)
            .with_context(|| format!("writing snapshot to {auto_snapshot_path}"))?;
    }

    Ok(())
}
