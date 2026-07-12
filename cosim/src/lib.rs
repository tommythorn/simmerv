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

/// Drive simmerv's `mip.SEIP` bit directly. Called on every retirement so
/// supervisor-external-interrupt state tracks the DUT's PLIC output rather
/// than simmerv's own (independent) UART/PLIC state.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn simmerv_set_seip(ctx: *mut SimmervCtx, asserted: bool) {
    if let Some(ctx) = unsafe { ctx.as_mut() } {
        ctx.emu.cpu.mmu.write_seip(asserted);
    }
}

/// Cosim: full interrupt DUT-follow. Call every retirement with `cause` = the
/// DUT's interrupt mcause/scause (MSB set) when it took an interrupt this
/// retire, or 0 when it didn't. simmerv then takes EXACTLY that interrupt at
/// this boundary and never decides interrupts on its own (its mip/mie are
/// retire-stale vs the DUT). Replaces the old per-type stip/seip/mtip "armed"
/// gates. mip/sip stay mirrored normally (mtimecmp/seip/plic_ip) so CSR reads
/// still match.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn simmerv_set_forced_interrupt(ctx: *mut SimmervCtx, cause: u64) {
    if let Some(ctx) = unsafe { ctx.as_mut() } {
        // Driven by the cosim: the DUT owns interrupt-acceptance timing (also
        // disables the standalone one-retire xRET defer; see Cpu::cosim_mode).
        ctx.emu.cpu.cosim_mode = true;
        ctx.emu.cpu.mmu.cosim_inert_devstore = true;
        ctx.emu.cpu.cosim_forced_cause = cause;
    }
}

/// Cosim: force IRQ `irq`'s pending bit in simmerv's PLIC, so claim/pending
/// reads match the DUT whose PLIC is driven by its own Verilog UART.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn simmerv_set_plic_ip(ctx: *mut SimmervCtx, irq: u32, asserted: bool) {
    if let Some(ctx) = unsafe { ctx.as_mut() } {
        ctx.emu.cpu.mmu.write_plic_ip(irq, asserted);
    }
}

/// Cosim: arm the model so the next CSR read of `csrno` returns `value`
/// instead of computing it. One-shot — consumed when matched. Use this
/// for CSRs whose value depends on hardware state the model doesn't
/// reproduce exactly (e.g. `time`, `cycle`, `instret`, externally-driven
/// `mip` bits) so the DUT's read result authoritatively wins.
///
/// Call this from the cosim glue *before* `simmerv_step_retire` whenever
/// the DUT is about to retire a CSRRW/CSRRS/CSRRC/I targeting one of the
/// "external" CSRs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn simmerv_arm_csr_read(ctx: *mut SimmervCtx, csrno: u16, value: u64) {
    if let Some(ctx) = unsafe { ctx.as_mut() } {
        ctx.emu.cpu.armed_csr_read = Some((csrno, value));
    }
}

/// Arm the value the DUT loaded for the instruction about to retire. simmerv
/// consumes it only if its own load for that instruction resolves to MMIO,
/// letting the DUT's device-register read win (device bits are model-specific
/// and side-effecting; the two models cannot be expected to agree). Harmless
/// to arm on non-load or RAM-load retires: the value is dropped at step end.
/// Call before `simmerv_step_retire` whenever the DUT wrote a destination
/// register and did not trap.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn simmerv_arm_load_value(ctx: *mut SimmervCtx, value: u64) {
    if let Some(ctx) = unsafe { ctx.as_mut() } {
        ctx.emu.cpu.armed_load_value = Some(value);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn simmerv_debug_dump(ctx: *mut SimmervCtx, out: *mut u64) {
    if let (Some(ctx), Some(out)) = (unsafe { ctx.as_mut() }, unsafe { out.as_mut() }) {
        let p = out as *mut u64;
        unsafe {
            *p.add(0) = ctx.emu.cpu.mmu.mip;
            *p.add(1) = ctx.emu.cpu.debug_mie();
            *p.add(2) = ctx.emu.cpu.debug_mideleg();
            *p.add(3) = ctx.emu.cpu.debug_menvcfg();
        }
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
    // Drop any unconsumed CSR-read / MMIO-load overrides so they can't bleed
    // into a later retire whose arming the glue legitimately skipped.
    ctx.emu.cpu.armed_csr_read = None;
    ctx.emu.cpu.armed_load_value = None;
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

/// Read an architectural register by bank index: 0..31 = integer, 32..63 = FP.
/// Used by the cosim mismatch dump to recover operand addresses (e.g. a
/// diverging load's base register) from the reference side.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn simmerv_read_register(ctx: *mut SimmervCtx, idx: u32) -> u64 {
    if let Some(ctx) = unsafe { ctx.as_mut() } {
        use simmerv::bounded::Bounded;
        if idx < 64 {
            return ctx.emu.cpu.read_register(Bounded::<65>::new(idx));
        }
    }
    0
}
