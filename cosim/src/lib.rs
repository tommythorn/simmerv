//! C ABI for using simmerv as a cosimulation reference model.
//!
//! The matching C header is `simmerv_cosim.h`. Keep in sync with
//! [`simmerv::cpu::RetireCapture`]. All `unsafe extern "C"` entry points
//! share the same contract: the caller must pass a ctx returned from
//! `simmerv_create` (or NULL, in which case the call is a no-op / -1).

#![allow(clippy::missing_safety_doc)]

use simmerv::Emulator;
use simmerv::buffered_serial_backend::BufferedSerialBackend;
use simmerv::cpu::RetireCapture;
use simmerv::uop_cache::CacheMode;
use std::ffi::c_int;
use std::slice;

/// Opaque context handle passed across the C ABI.
pub struct SimmervCtx {
    emu: Emulator,
}

/// Create a cosim context. `memory_bytes` is the size of RAM starting at
/// 0x8000_0000 (matches smolrv64's MEM_BASEADDR / MEM_SIZE_LG2). Returns NULL
/// on panic.
#[unsafe(no_mangle)]
pub extern "C" fn simmerv_create(memory_bytes: usize) -> *mut SimmervCtx {
    let result = std::panic::catch_unwind(|| {
        let mut emu = Emulator::new(
            Box::new(BufferedSerialBackend::new()),
            memory_bytes,
            0,
            CacheMode::Direct,
        );
        // Cosim needs deterministic mtime — disable wall-clock advance.
        emu.cpu.mmu.freeze_clint(0);
        Box::new(SimmervCtx { emu })
    });
    match result {
        Ok(ctx) => Box::into_raw(ctx),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Destroy a cosim context. Safe to call on NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn simmerv_destroy(ctx: *mut SimmervCtx) {
    if !ctx.is_null() {
        drop(unsafe { Box::from_raw(ctx) });
    }
}

/// Write a byte buffer into simmerv's physical memory at `phys_addr`.
/// Used to mirror smolrv64's `$readmemh` initialization.
/// Returns 0 on success, -1 on NULL ctx.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn simmerv_write_memory(
    ctx: *mut SimmervCtx,
    phys_addr: u64,
    data: *const u8,
    len: usize,
) -> c_int {
    let Some(ctx) = (unsafe { ctx.as_mut() }) else {
        return -1;
    };
    if data.is_null() || len == 0 {
        return 0;
    }
    let slice = unsafe { slice::from_raw_parts(data, len) };
    ctx.emu.cpu.mmu.write_memory_at(phys_addr, slice);
    0
}

/// Drive simmerv's `mtime` to `value`. Call this on every retirement (after
/// `simmerv_create` has frozen CLINT) so timer interrupts stay in lockstep
/// with the DUT.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn simmerv_set_mtime(ctx: *mut SimmervCtx, value: u64) {
    if let Some(ctx) = unsafe { ctx.as_mut() } {
        ctx.emu.cpu.mmu.write_mtime_csr(value);
    }
}

/// Drive simmerv's `mtimecmp` to `value`. Called alongside `simmerv_set_mtime`
/// on every retirement so MTIP computation stays aligned with the DUT.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn simmerv_set_mtimecmp(ctx: *mut SimmervCtx, value: u64) {
    if let Some(ctx) = unsafe { ctx.as_mut() } {
        ctx.emu.cpu.mmu.write_mtimecmp(value);
    }
}

/// Step one retirement and fill `out` with the observed state.
/// Returns 0 on success, -1 on NULL ctx or NULL out.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn simmerv_step_retire(
    ctx: *mut SimmervCtx,
    out: *mut RetireCapture,
) -> c_int {
    let Some(ctx) = (unsafe { ctx.as_mut() }) else {
        return -1;
    };
    if out.is_null() {
        return -1;
    }
    let cap = ctx.emu.cpu.step_retire();
    unsafe {
        *out = cap;
    }
    0
}

/// Set the reset PC. Call before the first `simmerv_step_retire`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn simmerv_set_pc(ctx: *mut SimmervCtx, pc: u64) {
    if let Some(ctx) = unsafe { ctx.as_mut() } {
        ctx.emu.cpu.update_pc(pc);
    }
}

/// Zero the integer and FP register files.  Matches smolrv64 when rf.hex is
/// all zeros (the Phase 1 convention).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn simmerv_zero_registers(ctx: *mut SimmervCtx) {
    if let Some(ctx) = unsafe { ctx.as_mut() } {
        use simmerv::bounded::Bounded;
        for i in 1..64 {
            ctx.emu.cpu.write_register(Bounded::<65>::new(i), 0);
        }
    }
}

/// Set an architectural register by bank index: 0..31 = integer, 32..63 = FP.
/// `idx == 0` is ignored (x0 is hardwired zero).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn simmerv_write_register(ctx: *mut SimmervCtx, idx: u32, val: u64) {
    if let Some(ctx) = unsafe { ctx.as_mut() } {
        use simmerv::bounded::Bounded;
        if idx > 0 && idx < 64 {
            ctx.emu.cpu.write_register(Bounded::<65>::new(idx), val);
        }
    }
}
