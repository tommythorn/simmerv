//! Integration test for the interactive Ctrl-C commands:
//!   * `s` requests an on-demand snapshot without stopping execution, and
//!   * `x` exits without writing any snapshot.
//!
//! The terminal layer only sets `snapshot_flag` / `exit_flag`; this test drives
//! the run loop directly through those flags, which is exactly what the menu
//! does.

use simmerv::Emulator;
use simmerv::serial_backend::DummySerialBackend;
use simmerv::uop_cache::CacheMode;
use std::sync::atomic::Ordering;

const RAM_BASE: u64 = 0x8000_0000;
// `jal x0, 0` — an infinite self-loop, so ticking never traps or advances.
const SELF_LOOP: u32 = 0x0000_006f;

fn looping_emulator() -> Emulator {
    let mut emu = Emulator::new(
        Box::new(DummySerialBackend::new()),
        8 * 1024 * 1024,
        1024,
        CacheMode::Skew,
    );
    emu.cpu
        .mmu
        .write_memory_at(RAM_BASE, &SELF_LOOP.to_le_bytes());
    emu.cpu.update_pc(RAM_BASE);
    emu
}

fn temp_path(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("simmerv-{}-{}.snap", tag, std::process::id()))
}

/// Ctrl-C `s`: the run loop writes a snapshot to `snapshot_path`, clears the
/// request flag, and keeps going. We pre-arm `exit_flag` too so `run_program`
/// returns after a single iteration — the snapshot is taken before the loop
/// checks for exit.
#[test]
fn ctrl_c_s_writes_snapshot_mid_run() {
    let path = temp_path("s-writes");
    let _ = std::fs::remove_file(&path);

    let mut emu = looping_emulator();
    emu.snapshot_path = path.to_string_lossy().into_owned();
    emu.snapshot_flag.store(true, Ordering::Relaxed);
    emu.exit_flag.store(true, Ordering::Relaxed);
    emu.run_program();

    assert!(path.exists(), "snapshot file should exist after Ctrl-C s");
    let data = std::fs::read(&path).unwrap_or_default();
    assert!(
        data.starts_with(b"SIMMERVC8"),
        "written file is not a valid snapshot"
    );
    assert!(
        !emu.snapshot_flag.load(Ordering::Relaxed),
        "snapshot request flag should be cleared after servicing"
    );

    let _ = std::fs::remove_file(&path);
}

/// Ctrl-C `x`: only `exit_flag` is set, so the run loop must exit without
/// writing any snapshot.
#[test]
fn ctrl_c_x_exits_without_snapshot() {
    let path = temp_path("x-no-snap");
    let _ = std::fs::remove_file(&path);

    let mut emu = looping_emulator();
    emu.snapshot_path = path.to_string_lossy().into_owned();
    emu.exit_flag.store(true, Ordering::Relaxed);
    emu.run_program();

    assert!(
        !path.exists(),
        "exit must not write a snapshot when only exit_flag is set"
    );
}
