//! The RISC-V CPU core, which handles instruction fetching, decoding, and
//! execution.

// It's the nature of emulator code to trigger Clippy's neurosis
#![allow(clippy::unreadable_literal)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]

use crate::csr;
use crate::device::Pack;
use crate::device::Unpack;
use crate::fp;
use crate::generated_riscv_decoder::Op;
use crate::generated_riscv_decoder::decoder;
use crate::mmu::DataAddr;
use crate::mmu::Mmu;
use crate::native_fp;
use crate::new_decoder;
use crate::new_decoder::NODESTREG;
use crate::new_decoder::Reg;
use crate::new_decoder::ZEROREG;
use crate::new_decoder::x;
use crate::riscv;
use crate::serial_backend::SerialBackend;
use crate::speedometer::Speedometer;
use crate::uop_cache::BasicBlock;
use crate::uop_cache::BbCache;
use crate::uop_cache::MAX_BLOCK_LEN;
use crate::vector;
use crate::vector::VectorUnit;
pub use csr::*;
use fp::RoundingMode;
use fp::Sf;
use fp::Sf16;
use fp::Sf32;
use fp::Sf64;
use fp::cvt_i32_sf32;
use fp::cvt_i32_sf64;
use fp::cvt_i64_sf32;
use fp::cvt_i64_sf64;
use fp::cvt_sf32_i32;
use fp::cvt_sf32_i64;
use fp::cvt_sf32_u32;
use fp::cvt_sf32_u64;
use fp::cvt_sf64_i32;
use fp::cvt_sf64_i64;
use fp::cvt_sf64_u32;
use fp::cvt_sf64_u64;
use fp::cvt_u32_sf32;
use fp::cvt_u32_sf64;
use fp::cvt_u64_sf32;
use fp::cvt_u64_sf64;
use log;
use num_traits::FromPrimitive;
use riscv::MemoryAccessType;
use riscv::MemoryAccessType::Execute;
use riscv::MemoryAccessType::Read;
use riscv::MemoryAccessType::Write;
use riscv::PrivMode;
use riscv::Trap;
use riscv::priv_mode_from;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

#[derive(Debug, PartialEq, Eq)]
pub struct Exception {
    pub trap: Trap,
    pub tval: u64,
}

/// One retirement from [`Cpu::step_retire`].
///
/// Covers three cases: an instruction executed successfully, an instruction
/// that trapped, or an interrupt delivered between instructions. Layout is
/// `#[repr(C)]` so the cosim FFI can memcpy it.
#[repr(C)]
#[derive(Default, Clone, Copy, Debug)]
pub struct RetireCapture {
    /// PC of the retiring instruction (trap vector source on trap).
    pub pc: u64,
    /// PC after retire: next instruction, or trap vector if trapped.
    pub next_pc: u64,
    /// Raw instruction word (16 or 32 bits, zero-extended). 0 if no insn
    /// (interrupt-only retire, fetch fault).
    pub insn: u32,
    _pad: u32,
    /// 0 = no writeback, 1 = int register, 2 = fp register.
    pub rd_kind: u8,
    /// 0..31 within `rd_kind`'s register bank. Meaningful only if `rd_kind !=
    /// 0`.
    pub rd_idx: u8,
    /// Privilege mode BEFORE this retirement.
    pub prv: u8,
    /// 1 if this retirement was a trap (instruction exception or interrupt).
    pub trapped: u8,
    /// fcsr[4:0] snapshot AFTER retirement.
    pub fflags: u32,
    /// Writeback value: raw 64 bits. FP single values must be NaN-boxed.
    pub rd_val: u64,
    /// Trap cause register value if `trapped`.
    pub trap_cause: u64,
    /// Trap tval if `trapped`.
    pub trap_tval: u64,
    /// mtime observed at retirement (should match DUT's driven value).
    pub mtime: u64,
    /// Retirement sequence number (simmerv's `seqno` before increment).
    pub seqno: u64,
    /// DEBUG: mepc after retire (for chasing an mepc divergence).
    pub mepc: u64,
}

pub type ExecResult = Result<(u64, u8), Exception>;

/// 16-byte execution result returned in `(rax, rdx)` on x86-64.
///
/// No sret pointer needed. `flags == 0`: ok; `0 < flags < 2^62`: ok with
/// fflags (`flags & 0xFF`); bit 62 set: the instruction redirected the PC;
/// bit 63 set: exception (`val`=tval, `bits[15:8]`=Trap).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecOut {
    pub val: u64,
    pub flags: u64,
}

const EXCEPTION_BIT: u64 = 0x8000_0000_0000_0000;

/// The instruction wrote [`Cpu::pc`] itself, so the block ends here.
///
/// Set by taken branches, jumps, `mret`/`sret`, and CSR writes that let a
/// pending interrupt in.  The block executor used to detect this by reloading
/// `self.pc` and comparing it against the address it had just stored there —
/// about 3% of run time.  Reporting it in a register the caller already holds
/// is free.
///
/// Every write to `Cpu::pc` from instruction execution must set this bit.  A
/// `debug_assert!` in both block executors cross-checks it against the old
/// comparison, so the test suite catches any that get added later.
const REDIRECT_BIT: u64 = 0x4000_0000_0000_0000;

#[allow(clippy::inline_always)]
impl ExecOut {
    #[inline(always)]
    #[must_use]
    pub const fn ok(val: u64) -> Self { Self { val, flags: 0 } }
    #[inline(always)]
    #[must_use]
    #[allow(clippy::cast_lossless)]
    pub const fn ok_ff(val: u64, ff: u8) -> Self {
        Self {
            val,
            flags: ff as u64,
        }
    }
    #[inline(always)]
    #[must_use]
    pub const fn err(trap: Trap, tval: u64) -> Self {
        Self {
            val: tval,
            flags: EXCEPTION_BIT | ((trap as u64) << 8),
        }
    }
    /// Ok, and the instruction has already written [`Cpu::pc`].
    #[inline(always)]
    #[must_use]
    pub const fn redirected(val: u64) -> Self {
        Self {
            val,
            flags: REDIRECT_BIT,
        }
    }
    #[inline(always)]
    #[must_use]
    pub const fn is_err(self) -> bool { self.flags & EXCEPTION_BIT != 0 }
    #[inline(always)]
    #[must_use]
    pub const fn is_redirect(self) -> bool { self.flags & REDIRECT_BIT != 0 }
    #[inline(always)]
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub const fn fflags(self) -> u8 { self.flags as u8 }
    #[inline(always)]
    #[must_use]
    pub fn to_exception(self) -> Exception {
        Exception {
            trap: num_traits::FromPrimitive::from_u64((self.flags >> 8) & 0xFF)
                .unwrap_or(Trap::IllegalInstruction),
            tval: self.val,
        }
    }
    /// Convert a `(value, fflags)` pair (as returned by float helpers) to
    /// `ExecOut`.
    #[inline(always)]
    #[must_use]
    #[allow(clippy::cast_lossless)]
    pub const fn from_wf(wf: (u64, u8)) -> Self {
        Self {
            val: wf.0,
            flags: wf.1 as u64,
        }
    }

    /// Convert a 32-bit word result plus fflags to `ExecOut`.
    ///
    /// RV64 word-result instructions write a sign-extended 32-bit value to the
    /// integer register, even when the source conversion is unsigned.
    #[inline(always)]
    #[must_use]
    #[allow(clippy::cast_lossless)]
    pub const fn from_wf_w(wf: (u64, u8)) -> Self {
        let word = wf.0 & 0xffff_ffff;
        let val = if word & 0x8000_0000 != 0 {
            word | 0xffff_ffff_0000_0000
        } else {
            word
        };
        Self {
            val,
            flags: wf.1 as u64,
        }
    }
}

/// Like `?` but for functions returning `ExecOut`.
macro_rules! etry {
    ($e:expr) => {
        match $e {
            Ok(v) => v,
            Err(e) => return ExecOut::err(e.trap, e.tval),
        }
    };
}

/// The decoded instruction, convenient for execution
// XXX Needs Seqno, ctf_target_opt
// XXX ctf, exceptional, serialize (and more?) should be combined into a classification represented
// as an enum. We also want to easily distinguish ALU, ALUFP, CTF, LOAD, STORE, ATOMIC, SYSTEM, ...?

#[derive(Debug, Clone, Copy)]
pub struct Uop {
    /// Immediate field (imm, csrno, or shift amount)
    pub imm: i32,
    /// The opcode
    pub op: Op,
    /// Destination Register
    pub rd: Reg,
    /// Source Register 1
    pub rs1: Reg,
    /// Source Register 2
    pub rs2: Reg,
    /// Source Register 3
    pub rs3: Reg,
    /// FP Rounding Mode
    pub rm: u8,
    /// Instruction size in bytes (2 or 4); precomputed at decode time.
    pub insn_size: u8,
}

impl Uop {
    const fn get_insn_size(&self) -> u64 { (self.insn_size & 0x7F) as u64 }

    /// Returns true if this is a conditional branch (precomputed at decode time
    /// via bit 7 of `insn_size`).
    #[allow(clippy::inline_always)]
    #[inline(always)]
    #[must_use]
    pub const fn is_branch_flag(&self) -> bool { self.insn_size & 0x80 != 0 }

    const fn _get_insn_size_from_op(&self) -> u64 {
        match self.op {
            Op::CUnimp
            | Op::CAddi4spn
            | Op::CFld
            | Op::CLw
            | Op::CLd
            | Op::CFsd
            | Op::CSw
            | Op::CSd
            | Op::CNop
            | Op::CAddi
            | Op::CAddiw
            | Op::CLi
            | Op::CAddi16sp
            | Op::CLui
            | Op::CSrli
            | Op::CSrai
            | Op::CAndi
            | Op::CSub
            | Op::CXor
            | Op::COr
            | Op::CAnd
            | Op::CSubw
            | Op::CAddw
            | Op::CJ
            | Op::CBeqz
            | Op::CBnez
            | Op::CSlli
            | Op::CFldsp
            | Op::CLwsp
            | Op::CLdsp
            | Op::CJr
            | Op::CMv
            | Op::CEbreak
            | Op::CJalr
            | Op::CAdd
            | Op::CFsdsp
            | Op::CSwsp
            | Op::CSdsp => 2,
            _ => 4,
        }
    }

    #[must_use]
    #[inline]
    pub const fn imm64(&self) -> u64 { self.imm as i64 as u64 }
}

impl PartialEq for Uop {
    fn eq(&self, other: &Self) -> bool {
        self.op == other.op
            && self.rd == other.rd
            && self.rs1 == other.rs1
            && self.rs2 == other.rs2
            && self.rs3 == other.rs3
            && self.imm == other.imm
            && self.rm == other.rm
    }
}

/// Holds information about registers used by an instruction.
#[derive(Debug, PartialEq, Eq)]
pub struct Operands {
    pub s1: u64,
    pub s2: u64,
    pub s3: u64,
}

/// Emulates a RISC-V CPU core
// XXX This structure should be rethought and refactored:
// - there is architectural state (essentially everything up-to and incl. reservation), but mmu.prv
//   is definitely architectural (but pc and rf are special)
// - wfi, seqno, insn_addr, and, insn are artifacts of the VM
//
// Some instructions need no CPU state (except for registers of course)
// Some instructions needs to known instruction address
// Some instructions can [optionally] change the program flow
// Some instructions can raise exceptions
// Some instructions need to read/modify FCSR/FS
// Some instructions needs to read/modify CSRs
// All instructions [potentially] depends of the MMU
// Load/Store/Atomic depends on the MMU (and ?)
//
// How should we model this? Some random ideas:
// - We could partition the instruction set into classes (multisim used alu, load, store, jump,
//   branch, compjump, atomic) along with a "system" boolean. Each class could have it's own
//   operation
/// Describes the uop-cache invalidation needed after an instruction executes.
///
/// SFENCE.VMA can target a single ASID or a single virtual page rather than
/// forcing a full flush, mirroring the selective flush the iTLB already does.
/// M-mode entries (tagged with bit 0 in the key) and kernel-VA entries (whose
/// bits [63:48] are already 0xFFFF due to the global-encoding OR trick) are
/// never affected by the ASID-targeted variants.
#[derive(Default, Clone, Copy)]
pub enum IcacheFlushKind {
    #[default]
    None,
    Full,
    Asid(u16),
    Vpage(u64),
    VpageAsid(u64, u16),
}

// XXX rename ArchState?
// A CPU model legitimately carries many independent boolean micro-arch flags
// (wfi, cosim_mode, ...); they are not a state machine to refactor.
#[allow(clippy::struct_excessive_bools)]
pub struct Cpu {
    // The essential CPU state
    rf: [u64; 65],
    pub pc: u64,

    // This is fcsr disaggregated
    pub frm: RoundingMode,
    pub fflags: u8,
    pub fs: u8,

    // The vector unit and its mstatus.VS field.  `rva23_enabled` is the
    // build-the-machine-as-RVA23 switch: with it clear the decoder rejects
    // every vector encoding and none of this state is reachable.  RVA23
    // mandates V, so the same switch gates the other RVA23-only extensions
    // (Zcb, Zimop, Zcmop, Zfa, Zawrs, Zacas, Zabha, Zvbb, Zvkt).
    pub v: VectorUnit,
    pub vs: u8,
    pub rva23_enabled: bool,

    /// Widest `satp` MODE this hart accepts, as the raw encoding (8 = Sv39,
    /// 9 = Sv48, 10 = Sv57).
    ///
    /// The page-table walker has always handled all three -- it derives the
    /// level count from the mode -- but `satp` only ever accepted Sv39, so the
    /// wider modes were unreachable.  Raising this is deliberately opt-in:
    /// Linux probes `satp` by writing the widest mode first and keeping
    /// whatever sticks, so defaulting to Sv48 would silently move every
    /// existing guest onto a deeper page table (and change the cosim DUT
    /// comparison, since smolrv64 is Sv39-only).
    pub max_satp_mode: u64,

    // Supervisor and CSR
    pub cycle: u64,
    csr: csr::CsrFile,
    reservation: Option<u64>,

    // Wait-For-Interrupt; relax and await further instruction
    // XXX needn't be part of CPU state; is part of fetch
    wfi: bool,

    // True when driven by the cosim harness (the armed-gate setters turn it
    // on). The standalone block executor (run_soc/step_block) only checks
    // interrupts at block/batch boundaries, and a CSR write to
    // sstatus/sie/mstatus/mie is NOT block-terminal — so standalone takes a
    // newly-unmasked interrupt INLINE at the enabling write (see write_csr),
    // otherwise an enable-then-disable window within one block never delivers
    // the pending IRQ and the kernel spins forever. The cosim runs one
    // instruction per step_retire and checks interrupts between every
    // instruction, so it must NOT take them inline: doing so fires a retire
    // earlier than the DUT (which vectors at the next fetch boundary) and
    // diverges. cosim_mode suppresses the inline take.
    pub cosim_mode: bool,

    // Cosim: gate on taking the supervisor timer interrupt (STIP). The DUT's
    // STIP latches as soon as mtime>=stimecmp but it only vectors at the next
    // fetch boundary (registered `pre_intr_pending`, 1 cycle stale); simmerv
    // Cosim: full interrupt DUT-follow. simmerv's mip/mie are retire-stale vs the
    // DUT, so in cosim_mode it does NOT decide interrupts itself -- it takes EXACTLY
    // the interrupt the DUT took this retire and nothing else. The harness sets this
    // each retirement to the DUT's interrupt cause (mcause/scause, MSB set), or 0 if
    // the DUT took no interrupt. handle_interrupt vectors exactly this cause, forced
    // through the enable checks (which are likewise stale). mip/sip stay mirrored
    // normally (mtimecmp/seip/plic_ip) so CSR reads still match. This replaces the
    // old per-type cosim_{stip,seip,mtip}_armed gates with one general rule.
    pub cosim_forced_cause: u64,

    // Cosim CSR-read override. When `Some((csrno, value))`, the next
    // CSR read of `csrno` returns `value` and the override is consumed.
    // Used by cosim glue to force the model's read result for CSRs
    // that depend on hardware state (counters, hardwired IDs, externally-
    // driven mip bits) instead of recomputing them in the model.
    pub armed_csr_read: Option<(u16, u64)>,

    // Cosim override for MMIO loads: device-register reads are model-specific
    // and side-effecting, so the two models cannot be expected to return the
    // same bits. When the DUT retires a register-writing instruction the glue
    // arms its rd_val here; memop_read consumes it ONLY when its own load
    // resolves to MMIO (non-RAM), letting the DUT's value win while simmerv
    // still performs the read for its side effects. RAM loads and non-memory
    // ops never touch it, so it is simply dropped at step end.
    pub armed_load_value: Option<u64>,

    // Giving each instruction a unique sequence number in program order is
    // especially helpful when dealing with out-of-order execution.
    // We can derive instret by maintaining an offset from seqno (as minstret
    // can be written by programs), although we cannot then treat ECALL and
    // EBREAK as committing instructions.
    // XXX needn't be part of CPU state; is part of fetch
    pub seqno: usize,

    // Holds all memory and devices (XXX: this public mmu suggests we need to rethink the API)
    pub mmu: Mmu,

    // Pending uop-cache flush requested by the last executed instruction.
    pub icache_flush: IcacheFlushKind,

    // Hardware performance monitor (mhpmcounter3..15).  The counters count
    // simulator-internal events (uop/bb cache, TLB) whose running totals live
    // outside the Cpu, so step_block mirrors the uop cache's totals into
    // `hpm_bb` and hpm_sync() folds the delta since `hpm_last` into each
    // counter on demand.  All of it is gated on `hpm_active`, which is false
    // until software programs a non-zero selector into some mhpmeventN, so an
    // unmonitored run pays one predictable branch per basic block.
    hpm_bb: crate::uop_cache::UopCacheStats,
    hpm_last: [u64; csr::HPM_LAST + 1],
    hpm_active: bool,
    // Set after a snapshot restore: the uop cache is not part of the snapshot,
    // so the first mirror re-baselines `hpm_last` instead of charging the
    // restored counters with the whole history of whatever cache it lands on.
    hpm_rebase: bool,

    pub speedometer: Speedometer,
    pub speedometer_flag: Arc<AtomicBool>,
    speedometer_next_cycle: u64,

    /// Physical address of the device tree blob, passed to firmware in a1.
    pub dtb_base: u64,
}

pub const CONFIG_SW_MANAGED_A_AND_D: bool = true;
pub const PG_SHIFT: usize = 12; // 4K page size

impl Default for Uop {
    fn default() -> Self {
        Self {
            op: Op::End,
            rd: NODESTREG,
            rs1: ZEROREG,
            rs2: ZEROREG,
            rs3: ZEROREG,
            imm: 0,
            rm: 0,
            insn_size: 4,
        }
    }
}

impl Cpu {
    /// Creates a new `Cpu` around a fully configured `Mmu` (memory allocated,
    /// devices attached).  Use [`Mmu::new`] → [`Mmu::add_memory`] →
    /// [`Mmu::attach_uart`] to build the `Mmu` before calling this.
    #[must_use]
    #[allow(clippy::precedence)]
    pub fn new(mmu: Mmu) -> Self {
        let mut cpu = Self {
            rf: [0; 65],
            frm: RoundingMode::RoundNearestEven,
            fflags: 0,
            fs: 1,

            v: VectorUnit::new(),
            vs: 1,
            rva23_enabled: false,
            max_satp_mode: SatpMode::Sv39 as u64,

            seqno: 0,
            cycle: 0,
            wfi: false,
            cosim_mode: false,
            cosim_forced_cause: 0,
            armed_csr_read: None,
            armed_load_value: None,
            pc: 0,
            csr: CsrFile::new(),
            mmu,
            reservation: None,
            icache_flush: IcacheFlushKind::None,
            hpm_bb: crate::uop_cache::UopCacheStats::default(),
            hpm_last: [0; csr::HPM_LAST + 1],
            hpm_active: false,
            hpm_rebase: false,
            speedometer: Speedometer::new(),
            speedometer_flag: Arc::new(AtomicBool::new(false)),
            speedometer_next_cycle: 0,
            dtb_base: 0,
        };
        cpu.mmu.mstatus = 2 << MSTATUS_UXL_SHIFT | 2 << MSTATUS_SXL_SHIFT | 3 << MSTATUS_MPP_SHIFT;
        cpu
    }

    /// Updates the DTB base address and writes it to a1 (x11) as firmware
    /// expects.
    pub fn set_dtb_base(&mut self, base: u64) {
        self.dtb_base = base;
        self.write_x(x(11), base);
    }

    /// Resets CPU architectural state as if the machine were rebooted.
    /// Memory contents are preserved (warm reset); the firmware re-initialises
    /// them on its own.
    pub fn soft_reset(&mut self) {
        self.rf = [0; 65];
        self.fflags = 0;
        self.fs = 1;
        self.v = VectorUnit::new();
        self.vs = 1;
        self.wfi = false;
        self.pc = 0x8000_0000;
        self.csr = CsrFile::new();
        self.reservation = None;
        self.icache_flush = IcacheFlushKind::Full;
        self.hpm_bb = crate::uop_cache::UopCacheStats::default();
        self.hpm_last = [0; csr::HPM_LAST + 1];
        self.hpm_active = false;
        self.hpm_rebase = true;
        self.mmu.prv = PrivMode::M;
        self.mmu.mip = 0;
        self.mmu.satp = 0;
        self.mmu.mstatus = 2 << MSTATUS_UXL_SHIFT | 2 << MSTATUS_SXL_SHIFT | 3 << MSTATUS_MPP_SHIFT;
        self.mmu.flush_tlb();
        self.write_x(x(11), self.dtb_base);
    }

    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn read_x(&self, r: Reg) -> u64 { self.rf[r] }

    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn write_x(&mut self, r: Reg, v: u64) {
        debug_assert_ne!(r.get(), 0);
        self.rf[r] = v;
    }

    /// Reads Program counter
    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub const fn read_pc(&self) -> u64 { self.pc }

    /// Updates Program Counter
    ///
    /// # Arguments
    /// * `value`
    pub const fn update_pc(&mut self, value: u64) { self.pc = value & !1; }

    /// Reads integer register
    ///
    /// # Arguments
    /// * `reg` Register number. Must be 0-31
    #[must_use]
    pub fn read_register(&self, reg: Reg) -> u64 { self.rf[reg] }

    #[must_use]
    pub const fn debug_mie(&self) -> u64 { self.csr.mie }
    #[must_use]
    pub const fn debug_mideleg(&self) -> u64 { self.csr.mideleg }
    #[must_use]
    pub const fn debug_menvcfg(&self) -> u64 { self.csr.menvcfg }
    #[must_use]
    pub const fn debug_stimecmp(&self) -> u64 { self.csr.stimecmp }
    pub fn write_register(&mut self, reg: Reg, value: u64) { self.write_x(reg, value); }

    /// Checks that float instructions are enabled and
    /// that the rounding mode is legal; do not dirty the FP state
    const fn check_float_access_ro(&self, rm: u8) -> Result<(), Exception> {
        if self.fs == 0 || rm == 5 || rm == 6 {
            Err(Exception {
                trap: Trap::IllegalInstruction,
                tval: 0,
            })
        } else {
            Ok(())
        }
    }

    /// True for the CSRs that belong to the vector unit, which are
    /// inaccessible without V and when `mstatus.VS` is Off.
    const fn is_vector_csr(csr: Csr) -> bool {
        matches!(
            csr,
            Csr::Vstart | Csr::Vxsat | Csr::Vxrm | Csr::Vcsr | Csr::Vl | Csr::Vtype | Csr::Vlenb
        )
    }

    /// `mstatus.VS` as architecturally exposed. Without the V extension the
    /// field is hardwired to 0 (Off, WARL), so software never observes stale
    /// vector state. The kernel's syscall path gates `riscv_v_vstate_discard`
    /// on `sstatus.VS != Off`, not on `has_vector()`, so a nonzero VS here
    /// sends it into vector code that then executes an illegal V instruction.
    const fn exposed_vs(&self) -> u8 { if self.rva23_enabled { self.vs } else { 0 } }

    /// Turn the RVA23 extension set on or off.  This is a machine-construction
    /// switch rather than architectural state: it gates instruction decoding,
    /// the `misa` V bit and the vector CSRs.
    /// Set `VLEN`, in bits.  Must be 128 or 256 -- see
    /// [`crate::vector::MAX_VLEN`].  Only meaningful with RVA23 enabled.
    ///
    /// # Panics
    /// If `vlen` is not a supported width.
    pub fn set_vlen(&mut self, vlen: usize) {
        assert!(
            vlen == vector::VLEN || vlen == vector::MAX_VLEN,
            "unsupported VLEN {vlen} (expected {} or {})",
            vector::VLEN,
            vector::MAX_VLEN
        );
        self.v.vlenb = vlen / 8;
        // Widening changes VLMAX, so any vtype the guest already set is no
        // longer the one it asked for.  Reset the unit rather than leave it
        // describing the old width.
        self.v.vtype = 0;
        self.v.vl = 0;
        self.v.vstart = 0;
        self.v.vrf = [0; vector::MAX_VRF_BYTES];
    }

    /// Set the widest accepted `satp` MODE.  See [`Cpu::max_satp_mode`].
    pub const fn set_max_satp_mode(&mut self, mode: u64) { self.max_satp_mode = mode; }

    /// Virtual-address width implied by [`Cpu::max_satp_mode`]: 39, 48 or 57.
    const fn va_bits(&self) -> u32 {
        // max_satp_mode is one of Sv39/Sv48/Sv57, so the difference is 0..=2.
        #[allow(clippy::cast_possible_truncation)]
        let steps = (self.max_satp_mode - SatpMode::Sv39 as u64) as u32;
        39 + 9 * steps
    }

    pub const fn set_rva23_enabled(&mut self, on: bool) {
        self.rva23_enabled = on;
        let v_bit = 1u64 << (b'V' - b'A');
        if on {
            self.csr.misa |= v_bit;
            self.vs = 1;
        } else {
            self.csr.misa &= !v_bit;
            self.vs = 0;
        }
        // Previously decoded blocks were decoded under the old setting.
        self.icache_flush = IcacheFlushKind::Full;
    }

    /// Checks that float instructions are enabled and
    /// that the rounding mode is legal; dirty the FP state
    fn check_float_access_and_dirty(&mut self, rm: u8) -> Result<(), Exception> {
        self.check_float_access_ro(rm)?;
        self.fs = 3;
        native_fp::fflags_clear();
        // XXX set native rounding mode
        Ok(())
    }

    /// Dirty FP state AFTER a value actually reaches an f-register. FP loads
    /// use this (not `check_float_access_and_dirty`) so a load that
    /// page-faults -- which writes no f-reg -- does not spuriously set
    /// `mstatus.FS` = Dirty. (cosim caught REF dirtying FS on a faulting
    /// user FLD while the DUT, which only dirties at load completion, did not.)
    pub(crate) const fn mark_fp_dirty(&mut self) { self.fs = 3; }

    /// Runs program N cycles. Fetch, decode, and execution are completed in a
    /// cycle so far.
    #[allow(clippy::cast_sign_loss)]
    pub fn run_soc(&mut self, cpu_steps: usize, bb: &mut BbCache) -> bool {
        if self.speedometer_flag.load(Ordering::Relaxed)
            && self.cycle >= self.speedometer_next_cycle
        {
            // XXX Using cycle as instret is misleading in the presence of wfi
            if self.speedometer.last_time.elapsed().as_secs() >= 1 {
                let _ = self
                    .speedometer
                    .update(self.cycle, self.mmu.tlb_stats(), bb.stats());
            }
            // Re-arm: check at most ~10M emulated cycles from now
            self.speedometer_next_cycle = self.cycle.wrapping_add(10_000_000);
        }

        let mut steps_done: usize = 0;
        while steps_done < cpu_steps {
            match self.step_block(bb) {
                Ok(n) => {
                    steps_done += n as usize;
                    if self.wfi {
                        break;
                    }
                }
                Err((exc, fault_addr)) => {
                    self.handle_exception(&exc, fault_addr);
                    return true;
                }
            }
        }
        self.mmu.service(self.cycle);
        // Sstc: drive STIP from stimecmp when menvcfg.STCE is set
        if self.csr.menvcfg & MENVCFG_STCE != 0 {
            if self.mmu.read_mtime_csr() >= self.csr.stimecmp {
                self.mmu.mip |= MIP_STIP;
            } else {
                self.mmu.mip &= !MIP_STIP;
            }
        }
        self.handle_interrupt();

        false
    }

    #[inline]
    const fn is_block_terminal(op: Op, imm: i32) -> bool {
        matches!(
            op,
            Op::Ecall
                | Op::Ebreak
                | Op::CEbreak
                | Op::Mret
                | Op::Sret
                | Op::FenceI
                | Op::SfenceVma
                | Op::SinvalVma
                | Op::Wfi
        ) || matches!(
            op,
            Op::Csrrw | Op::Csrrs | Op::Csrrc | Op::Csrrwi | Op::Csrrsi | Op::Csrrci
        ) && imm == 0x180_i32 // CSR_SATP
    }

    #[allow(clippy::inline_always)]
    #[inline(always)]
    const fn is_branch(op: Op) -> bool {
        matches!(
            op,
            Op::Beq | Op::Bne | Op::Blt | Op::Bge | Op::Bltu | Op::Bgeu | Op::CBeqz | Op::CBnez
        )
    }

    /// Execute one block (either from cache or freshly decoded).
    #[allow(
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation,
        clippy::too_many_lines
    )]
    fn step_block(&mut self, bb: &mut BbCache) -> Result<u32, (Exception, u64)> {
        // Apply any pending icache flush.
        match self.icache_flush {
            IcacheFlushKind::None => {}
            IcacheFlushKind::Full => {
                log::trace!("uop cache flush");
                bb.clear();
            }
            IcacheFlushKind::Asid(asid) => bb.flush_asid(asid),
            IcacheFlushKind::Vpage(page_addr) => bb.flush_vpage(page_addr),
            IcacheFlushKind::VpageAsid(page_addr, asid) => {
                bb.flush_vpage_asid(page_addr, asid);
            }
        }
        self.icache_flush = IcacheFlushKind::None;

        // Mirror the uop cache's running totals so the HPM counters can be
        // read from deep inside execution, where `bb` is not reachable. Taken
        // before this block's probe, so a counter read is exact as of the
        // start of the block containing the read.
        if self.hpm_active {
            self.hpm_bb = bb.stats();
            if self.hpm_rebase {
                self.hpm_rebase = false;
                for i in csr::HPM_FIRST..=csr::HPM_LAST {
                    self.hpm_last[i] = self.hpm_source(self.csr.mhpmevent[i]);
                }
            }
        }

        self.cycle = self.cycle.wrapping_add(1);

        // WFI fast-path
        if self.wfi {
            if self.mmu.mip & self.csr.mie != 0 {
                self.wfi = false;
            }
            return Ok(1);
        }

        let block_start = self.pc;

        // Tag M-mode cache entries with bit 0 to distinguish M-mode physical
        // addresses from S/U-mode virtual addresses that share the same value.
        // Valid fetch addresses are always 2-byte aligned so bit 0 is free.
        //
        // For S/U-mode, fold the current ASID into bits [63:48] so that
        // entries for different address spaces don't alias.  Kernel VAs in
        // Sv39/Sv48 already have bits [63:48] = 0xFFFF, so the OR is a no-op
        // there — kernel entries are effectively ASID-global, matching the
        // G-bit behaviour of the iTLB.
        let cache_key = if self.mmu.prv == PrivMode::M {
            block_start | 1
        } else {
            let asid = (self.mmu.satp >> SATP_ASID_SHIFT) & SATP_ASID_MASK;
            block_start | (asid << 48)
        };

        // ── Cache hit path ────────────────────────────────────────────────
        if let Some(slot) = bb.probe(cache_key) {
            // Read len/truncated: temporary borrows of bb.data, released immediately
            // since `u8` and `bool` are Copy.
            let mut n_executed: u32 = 0;
            let mut untaken_branches: u64 = 0;
            let mut exception: Option<(Exception, u64)> = None;
            let cached_block = bb.block_at(slot);
            for uop in cached_block {
                let uop = *uop;
                if uop.op == Op::End {
                    break;
                }
                // uop is a local copy; cached_block borrows bb immutably but
                // bb is not mutated inside this loop, so NLL is satisfied.
                let cur_insn_addr = self.pc;
                let expected_next = cur_insn_addr + uop.get_insn_size();
                self.pc = expected_next;

                let s1 = self.read_x(uop.rs1);
                let s2 = self.read_x(uop.rs2);
                let s3 = self.read_x(uop.rs3);
                let out = execute_fast(self, &uop, s1, s2, s3, cur_insn_addr);
                if out.is_err() {
                    exception = Some((out.to_exception(), cur_insn_addr));
                    break;
                }
                self.write_x(uop.rd, out.val);
                let ff = out.fflags();
                if ff != 0 {
                    self.add_to_fflags(ff);
                }
                n_executed += 1;

                // `out` is already in registers, so asking it whether the PC
                // moved is free; reloading `self.pc` to compare was not.
                // One-directional on purpose: every instruction that moves the
                // PC must set the bit, but setting it when the PC happens not
                // to move is harmless -- a `jalr` whose target is simply the
                // next instruction just ends the block early.
                debug_assert!(
                    out.is_redirect() || self.pc == expected_next,
                    "{:?} at {cur_insn_addr:#x} wrote pc without REDIRECT_BIT",
                    uop.op
                );
                if out.is_redirect() {
                    // Taken branch, jump, xret, or an interrupt let in by a CSR
                    // write: the instruction set the PC itself, so stop here.
                    break;
                } else if uop.is_branch_flag() {
                    untaken_branches += 1;
                }
            }
            bb.untaken_branches += untaken_branches;
            bb.insn_hits += u64::from(n_executed);
            bb.block_hits += 1;
            // Batch seqno update (only used for snapshots, not CSRs)
            self.seqno = self.seqno.wrapping_add(n_executed as usize);
            // Extra cycles for instructions beyond the first.
            self.cycle = self
                .cycle
                .wrapping_add(u64::from(n_executed).saturating_sub(1));
            if let Some(err) = exception {
                return Err(err);
            }
            return Ok(n_executed);
        }

        // ── Cache miss: build and execute the block ───────────────────────
        //
        // Build and execute are fused so the block can stop at the first
        // *taken* branch.  Decoding ahead blindly to MAX_BLOCK_LEN stores a
        // tail that control flow never reaches: on a Linux boot the average
        // block stored ~30 uops and executed ~9 of them, so most of the decode
        // work, and most of the slot, was spent on instructions that would be
        // skipped every time the block ran.  Not-taken branches still extend
        // the block, which is the case the old policy was betting on.
        let page_end = (block_start & !0xFFF) + 0x1000;
        let mut block = BasicBlock::default();
        let mut fetch_pc = block_start;
        let mut i = 0usize;
        let mut n_executed: u32 = 0;
        let mut exception: Option<(Exception, u64)> = None;

        loop {
            if i >= MAX_BLOCK_LEN {
                break;
            }

            // Page boundary check (skip for i == 0).
            if i > 0 && fetch_pc >= page_end {
                break;
            }

            // Fetch instruction (4 bytes; actual size determined after decode).
            let insn = match self.memop_code(fetch_pc) {
                Ok(v) => v as u32,
                Err(e) => {
                    if i == 0 {
                        return Err((e, fetch_pc));
                    }
                    break;
                }
            };

            let insn_size = if insn & 3 == 3 { 4u64 } else { 2u64 };

            // Skip 4-byte instruction straddling page boundary (not for i==0).
            if i > 0 && insn_size == 4 && fetch_pc + 4 > page_end {
                break;
            }

            let uop = decode(fetch_pc, insn, self.rva23_enabled);

            if matches!(uop.op, Op::CUnimp | Op::End) {
                if i == 0 {
                    return Err((
                        Exception {
                            trap: Trap::IllegalInstruction,
                            tval: u64::from(insn),
                        },
                        fetch_pc,
                    ));
                }
                break;
            }

            let cur_insn_addr = self.pc;
            let expected_next = cur_insn_addr + uop.get_insn_size();
            self.pc = expected_next;

            let s1 = self.read_x(uop.rs1);
            let s2 = self.read_x(uop.rs2);
            let s3 = self.read_x(uop.rs3);
            let out = new_execute(self, &uop, s1, s2, s3, cur_insn_addr);
            if out.is_err() {
                // Leave the faulting uop out of the block and do not cache it
                // (below): the prefix already retired, and the fault will be
                // taken again the next time control reaches it.
                exception = Some((out.to_exception(), cur_insn_addr));
                break;
            }
            self.write_x(uop.rd, out.val);
            let ff = out.fflags();
            if ff != 0 {
                self.add_to_fflags(ff);
            }
            n_executed += 1;

            block.uops[i] = uop;
            i += 1;
            fetch_pc += insn_size;

            debug_assert!(
                out.is_redirect() || self.pc == expected_next,
                "{:?} at {cur_insn_addr:#x} wrote pc without REDIRECT_BIT",
                uop.op
            );
            // A taken branch, jump or xret ends the block: nothing after it in
            // program order is reachable from here.
            if out.is_redirect() || Self::is_block_terminal(uop.op, uop.imm) {
                break;
            }
        }

        if let Some(err) = exception {
            // Do not cache blocks that raised an exception.
            return Err(err);
        }

        // Cache the complete block.
        bb.insert(cache_key, &block);
        self.cycle = self
            .cycle
            .wrapping_add(u64::from(n_executed).saturating_sub(1));
        Ok(n_executed)
    }

    /// Fetch, decode, and execute exactly one instruction without any cache
    /// interaction. Used by the tracing path so that exactly one instruction
    /// retires per call.
    ///
    /// # Errors
    /// Returns an [`Exception`] if the instruction faults (illegal instruction,
    /// page fault, etc.).
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    pub fn step_single(&mut self) -> Result<(), Exception> {
        // Apply any pending icache flush (no cache to flush, but clear the flag).
        self.icache_flush = IcacheFlushKind::None;

        self.cycle = self.cycle.wrapping_add(1);

        if self.wfi {
            if self.mmu.mip & self.csr.mie != 0 {
                self.wfi = false;
            }
            return Ok(());
        }

        let insn_addr = self.pc;
        let insn = self.memop_code(insn_addr)? as u32;
        self.pc += if insn & 3 == 3 { 4 } else { 2 };
        let uop = decode(insn_addr, insn, self.rva23_enabled);
        if matches!(uop.op, Op::CUnimp | Op::End) {
            return Err(Exception {
                trap: Trap::IllegalInstruction,
                tval: u64::from(insn),
            });
        }
        self.seqno = self.seqno.wrapping_add(1);
        let s1 = self.read_x(uop.rs1);
        let s2 = self.read_x(uop.rs2);
        let s3 = self.read_x(uop.rs3);
        let out = new_execute(self, &uop, s1, s2, s3, insn_addr);
        if out.is_err() {
            return Err(out.to_exception());
        }
        self.write_x(uop.rd, out.val);
        let ff = out.fflags();
        if ff != 0 {
            self.add_to_fflags(ff);
        }
        Ok(())
    }

    /// Cosim sibling of [`Cpu::step_single`]: advances exactly one retirement
    /// (either an instruction or a taken interrupt) and returns a
    /// [`RetireCapture`] describing it. Must be paired with externally
    /// driven mtime (see [`Mmu::freeze_clint`]).
    #[allow(
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation,
        clippy::too_many_lines
    )]
    pub fn step_retire(&mut self) -> RetireCapture {
        let mut cap = RetireCapture {
            pc: self.pc,
            prv: u64::from(self.mmu.prv) as u8,
            mtime: self.mmu.read_mtime_csr(),
            seqno: self.seqno as u64,
            ..RetireCapture::default()
        };

        self.mmu.service(self.cycle);
        if self.csr.menvcfg & MENVCFG_STCE != 0 {
            if self.mmu.read_mtime_csr() >= self.csr.stimecmp {
                self.mmu.mip |= MIP_STIP;
            } else {
                self.mmu.mip &= !MIP_STIP;
            }
        }

        let pc_before_int = self.pc;
        self.handle_interrupt();
        if self.pc != pc_before_int {
            cap.trapped = 1;
            cap.trap_cause = match self.mmu.prv {
                PrivMode::M => self.csr.mcause,
                PrivMode::S | PrivMode::U => self.csr.scause,
            };
            cap.trap_tval = match self.mmu.prv {
                PrivMode::M => self.csr.mtval,
                PrivMode::S | PrivMode::U => self.csr.stval,
            };
            cap.next_pc = self.pc;
            cap.mepc = self.csr.mepc;
            return cap;
        }

        self.icache_flush = IcacheFlushKind::None;
        self.cycle = self.cycle.wrapping_add(1);

        if self.wfi {
            if self.mmu.mip & self.csr.mie != 0 {
                self.wfi = false;
            }
            cap.next_pc = self.pc;
            cap.mepc = self.csr.mepc;
            return cap;
        }

        let insn_addr = self.pc;
        let insn = match self.memop_code(insn_addr) {
            Ok(w) => w as u32,
            Err(exc) => {
                cap.trapped = 1;
                cap.trap_cause = get_trap_cause(&exc);
                cap.trap_tval = exc.tval;
                self.handle_exception(&exc, insn_addr);
                cap.next_pc = self.pc;
                cap.mepc = self.csr.mepc;
                return cap;
            }
        };
        cap.insn = insn;
        self.pc += if insn & 3 == 3 { 4 } else { 2 };
        let uop = decode(insn_addr, insn, self.rva23_enabled);
        if matches!(uop.op, Op::CUnimp | Op::End) {
            let exc = Exception {
                trap: Trap::IllegalInstruction,
                tval: u64::from(insn),
            };
            cap.trapped = 1;
            cap.trap_cause = get_trap_cause(&exc);
            cap.trap_tval = exc.tval;
            self.handle_exception(&exc, insn_addr);
            cap.next_pc = self.pc;
            cap.mepc = self.csr.mepc;
            return cap;
        }
        self.seqno = self.seqno.wrapping_add(1);
        let s1 = self.read_x(uop.rs1);
        let s2 = self.read_x(uop.rs2);
        let s3 = self.read_x(uop.rs3);
        let result = new_execute(self, &uop, s1, s2, s3, insn_addr);
        if result.is_err() {
            let mut exc = result.to_exception();
            // mtval convention: the sharded-OoO (probe) core reports mtval=0 on
            // illegal-instruction -- carrying the raw insn bits to the (non-speculative)
            // commit point in an OoO pipeline is real cost, and tval=0 is spec-conformant.
            // Force 0 here to match it (overrides any insn set by new_execute's checks).
            // (Legacy smolrv64 inner core used the insn word; its cosim would differ here.)
            if matches!(exc.trap, Trap::IllegalInstruction) {
                exc.tval = 0;
            }
            cap.trapped = 1;
            cap.trap_cause = get_trap_cause(&exc);
            cap.trap_tval = exc.tval;
            self.handle_exception(&exc, insn_addr);
            cap.next_pc = self.pc;
            cap.mepc = self.csr.mepc;
            return cap;
        }
        self.write_x(uop.rd, result.val);
        let ff = result.fflags();
        if ff != 0 {
            self.add_to_fflags(ff);
        }

        let rd = uop.rd;
        if !rd.is_x0_dest() {
            let idx = rd.get();
            if idx < 32 {
                cap.rd_kind = 1;
                cap.rd_idx = idx;
            } else {
                cap.rd_kind = 2;
                cap.rd_idx = idx - 32;
            }
            cap.rd_val = self.read_x(rd);
        }
        cap.fflags = u32::from(self.fflags);
        cap.next_pc = self.pc;
        cap.mepc = self.csr.mepc;
        cap
    }

    #[allow(clippy::cast_sign_loss)]
    fn handle_interrupt(&mut self) {
        use self::Trap::MachineExternalInterrupt;
        use self::Trap::MachineSoftwareInterrupt;
        use self::Trap::MachineTimerInterrupt;
        use self::Trap::SupervisorExternalInterrupt;
        use self::Trap::SupervisorSoftwareInterrupt;
        use self::Trap::SupervisorTimerInterrupt;
        // Cosim DUT-follow: simmerv's mip/mie are retire-stale vs the DUT, so it does
        // NOT decide interrupts itself -- it takes EXACTLY the interrupt the DUT took
        // this retire (cosim_forced_cause), forced through handle_trap's enable checks
        // (likewise stale). 0 -> the DUT took none -> take none.
        if self.cosim_mode {
            if self.cosim_forced_cause == 0 {
                return;
            }
            let trap_type = match self.cosim_forced_cause & 0xff {
                1 => SupervisorSoftwareInterrupt,
                3 => MachineSoftwareInterrupt,
                5 => SupervisorTimerInterrupt,
                7 => MachineTimerInterrupt,
                9 => SupervisorExternalInterrupt,
                11 => MachineExternalInterrupt,
                13 => Trap::CounterOverflowInterrupt,
                _ => return,
            };
            let trap = Exception {
                trap: trap_type,
                tval: 0,
            };
            if self.handle_trap(&trap, self.pc, true) {
                self.wfi = false;
                self.reservation = None;
            }
            return;
        }

        // Standalone: autonomous interrupt taking from mip & mie.
        let minterrupt = self.mmu.mip & self.csr.mie;
        if minterrupt == 0 {
            return;
        }

        // XXX This is terribly inefficient
        for (intr, trap_type) in [
            (MIP_MEIP, MachineExternalInterrupt),
            (MIP_MSIP, MachineSoftwareInterrupt),
            (MIP_MTIP, MachineTimerInterrupt),
            (MIP_SEIP, SupervisorExternalInterrupt),
            (MIP_SSIP, SupervisorSoftwareInterrupt),
            (MIP_STIP, SupervisorTimerInterrupt),
            (csr::MIP_LCOFIP, Trap::CounterOverflowInterrupt),
        ] {
            let trap = Exception {
                trap: trap_type,
                tval: 0,
            };
            if minterrupt & intr != 0 && self.handle_trap(&trap, self.pc, true) {
                self.wfi = false;
                self.reservation = None;
                return;
            }
        }
    }

    pub fn handle_exception(&mut self, exception: &Exception, insn_addr: u64) {
        if matches!(exception.trap, Trap::IllegalInstruction) {
            log::info!("Illegal instruction {insn_addr:016x}");
        }
        self.handle_trap(exception, insn_addr, false);
    }

    #[allow(clippy::similar_names, clippy::too_many_lines)]
    #[allow(clippy::cast_sign_loss)]
    fn handle_trap(&mut self, exc: &Exception, insn_addr: u64, is_interrupt: bool) -> bool {
        let current_priv_encoding = u64::from(self.mmu.prv);
        let cause = get_trap_cause(exc);

        // First, determine which privilege mode should handle the trap.
        // @TODO: Check if this logic is correct
        let mdeleg = if is_interrupt {
            self.csr.mideleg
        } else {
            self.csr.medeleg
        };
        let sdeleg = if is_interrupt {
            self.csr.sideleg
        } else {
            self.csr.sedeleg
        };
        let pos = cause & 63;

        let mut new_priv_mode = if (mdeleg >> pos) & 1 == 0 {
            PrivMode::M
        } else if (sdeleg >> pos) & 1 == 0 {
            PrivMode::S
        } else {
            PrivMode::U
        };

        // A trap never transitions to a less-privileged mode than the one in which it
        // occurred: medeleg/sedeleg lower an *exception* handler from M toward the
        // current mode, but never below it.  In particular a fault taken in M-mode --
        // e.g. an MPRV load/store page fault while OpenSBI accesses S/U memory on
        // behalf of the kernel -- is handled in M-mode regardless of
        // medeleg[cause].  (An interrupt expresses the same rule by staying
        // pending instead; that is the `new_priv_encoding <
        // current_priv_encoding` check further below.)
        if !is_interrupt && u64::from(new_priv_mode) < current_priv_encoding {
            new_priv_mode = self.mmu.prv;
        }

        // Cosim DUT-follow: a forced interrupt was already validated takeable by the
        // DUT, and simmerv's enable bits are retire-stale -- so skip the reject
        // checks entirely.
        if is_interrupt && !self.cosim_mode {
            let new_priv_encoding = u64::from(new_priv_mode);
            // Second, ignore the interrupt if it's disabled by some conditions

            let current_status = match self.mmu.prv {
                PrivMode::M => self.read_csr_raw(Csr::Mstatus),
                PrivMode::S => self.read_csr_raw(Csr::Sstatus),
                PrivMode::U => self.csr.ustatus,
            };

            let ie = match new_priv_mode {
                PrivMode::M => self.csr.mie,
                PrivMode::S => self.read_csr_raw(Csr::Sie),
                PrivMode::U => self.read_csr_raw(Csr::Uie),
            };

            let current_mie = (current_status >> 3) & 1;
            let current_sie = (current_status >> 1) & 1;
            let current_uie = current_status & 1;

            let msie = (ie >> 3) & 1;
            let ssie = (ie >> 1) & 1;
            let usie = ie & 1;

            let mtie = (ie >> 7) & 1;
            let stie = (ie >> 5) & 1;
            let utie = (ie >> 4) & 1;

            let meie = (ie >> 11) & 1;
            let seie = (ie >> 9) & 1;
            let ueie = (ie >> 8) & 1;

            // 1. Interrupt is always enabled if new privilege level is higher
            // than current privilege level
            // 2. Interrupt is always disabled if new privilege level is lower
            // than current privilege level
            // 3. Interrupt is enabled if xIE in xstatus is 1 where x is privilege level
            // and new privilege level equals to current privilege level

            if new_priv_encoding < current_priv_encoding
                || current_priv_encoding == new_priv_encoding
                    && 0 == match self.mmu.prv {
                        PrivMode::M => current_mie,
                        PrivMode::S => current_sie,
                        PrivMode::U => current_uie,
                    }
            {
                return false;
            }

            // Interrupt can be maskable by xie csr register
            // where x is a new privilege mode.

            match exc.trap {
                Trap::UserSoftwareInterrupt if usie == 0 => {
                    return false;
                }
                Trap::SupervisorSoftwareInterrupt if ssie == 0 => {
                    return false;
                }
                Trap::MachineSoftwareInterrupt if msie == 0 => {
                    return false;
                }
                Trap::UserTimerInterrupt if utie == 0 => {
                    return false;
                }
                Trap::SupervisorTimerInterrupt if stie == 0 => {
                    return false;
                }
                Trap::MachineTimerInterrupt if mtie == 0 => {
                    return false;
                }
                Trap::UserExternalInterrupt if ueie == 0 => {
                    return false;
                }
                Trap::SupervisorExternalInterrupt if seie == 0 => {
                    return false;
                }
                Trap::MachineExternalInterrupt if meie == 0 => {
                    return false;
                }
                _ => {}
            }
        }

        // So, this trap should be taken

        // Sscofpmf: charge everything counted so far to the mode we are
        // leaving, before the *INH filtering switches meaning.
        self.hpm_sync_if_active();
        self.mmu.update_priv_mode(new_priv_mode);
        let csr_epc_address = match self.mmu.prv {
            PrivMode::M => Csr::Mepc,
            PrivMode::S => Csr::Sepc,
            PrivMode::U => Csr::Uepc,
        };
        let csr_cause_address = match self.mmu.prv {
            PrivMode::M => Csr::Mcause,
            PrivMode::S => Csr::Scause,
            PrivMode::U => Csr::Ucause,
        };
        let csr_tval_address = match self.mmu.prv {
            PrivMode::M => Csr::Mtval,
            PrivMode::S => Csr::Stval,
            PrivMode::U => Csr::Utval,
        };
        self.pc = match self.mmu.prv {
            PrivMode::M => self.read_csr_raw(Csr::Mtvec),
            PrivMode::S => self.read_csr_raw(Csr::Stvec),
            PrivMode::U => self.read_csr_raw(Csr::Utvec),
        };

        self.write_csr_raw(csr_epc_address, insn_addr);
        self.write_csr_raw(csr_cause_address, cause);
        self.write_csr_raw(csr_tval_address, if is_interrupt { 0 } else { exc.tval });

        // Add 4 * cause if tvec has vector type address
        if self.pc & 3 != 0 {
            self.pc = (self.pc & !3) + 4 * (cause & 0xffff);
        }

        match self.mmu.prv {
            PrivMode::M => {
                let status = self.read_csr_raw(Csr::Mstatus);
                let mie = (status >> 3) & 1;
                // clear MIE[3], override MPIE[7] with MIE[3], override MPP[12:11] with current
                // privilege encoding
                let new_status = (status & !0x1888) | (mie << 7) | (current_priv_encoding << 11);
                self.write_csr_raw(Csr::Mstatus, new_status);
            }
            PrivMode::S => {
                let status = self.read_csr_raw(Csr::Sstatus);
                let sie = (status >> 1) & 1;
                // clear SIE[1], override SPIE[5] with SIE[1], override SPP[8] with current
                // privilege encoding
                let new_status =
                    (status & !0x122) | (sie << 5) | ((current_priv_encoding & 1) << 8);
                self.write_csr_raw(Csr::Sstatus, new_status);
            }
            PrivMode::U => {
                panic!("Not implemented yet");
            }
        }
        true
    }

    #[allow(clippy::cast_lossless)]
    /// Running total of the event source selected by an `mhpmevent` value.
    /// Every source is monotonic, so a counter is just the accumulated delta.
    ///
    /// The Sscofpmf/Smcntrpmf privilege-inhibit bits in `sel` are ignored: the
    /// counters run in every mode.  See the `hpm` note in
    /// `write_csr`/`Mcountinhibit` for the filtering that is honoured.
    const fn hpm_source(&self, sel: u64) -> u64 {
        let bb = &self.hpm_bb;
        match sel & csr::MHPMEVENT_SEL_MASK {
            csr::HPM_EV_BB_MISS => bb.cold_misses.wrapping_add(bb.conflict_misses),
            csr::HPM_EV_BB_COLD_MISS => bb.cold_misses,
            csr::HPM_EV_BB_CONFLICT_MISS => bb.conflict_misses,
            csr::HPM_EV_BB_HIT => bb.block_hits,
            csr::HPM_EV_BB_FLUSH => bb
                .flush_full
                .wrapping_add(bb.flush_asid)
                .wrapping_add(bb.flush_vpage)
                .wrapping_add(bb.flush_vpage_asid),
            csr::HPM_EV_ITLB_MISS => self.mmu.tlb_stats().itlb_misses,
            csr::HPM_EV_DTLB_MISS => self.mmu.tlb_stats().dtlb_misses,
            csr::HPM_EV_CYCLES | csr::HPM_EV_INSTRET => self.cycle,
            // HPM_EV_NONE and any selector the platform doesn't implement read
            // as a counter that never advances.
            _ => 0,
        }
    }

    /// Sscofpmf `*INH` bit that silences a counter in `prv`.
    const fn hpm_inhibit_bit(prv: PrivMode) -> u64 {
        match prv {
            PrivMode::M => csr::MHPMEVENT_MINH,
            PrivMode::S => csr::MHPMEVENT_SINH,
            PrivMode::U => csr::MHPMEVENT_UINH,
        }
    }

    /// Folds the events seen since the last call into each running counter,
    /// attributing them to the privilege mode in effect over that window.
    ///
    /// Called from every path that observes a counter, perturbs one, or leaves
    /// the current privilege mode -- that last one is what makes the `*INH`
    /// filtering meaningful, since the delta accumulated here is charged
    /// wholesale to `self.mmu.prv`.  Counters are exact as of the start of the
    /// current basic block (see the mirror in `step_block`).
    fn hpm_sync(&mut self) {
        let inhibit = Self::hpm_inhibit_bit(self.mmu.prv);
        let mut overflowed = false;
        for i in csr::HPM_FIRST..=csr::HPM_LAST {
            let event = self.csr.mhpmevent[i];
            let raw = self.hpm_source(event);
            let running = self.csr.mcountinhibit & (1 << i) == 0 && event & inhibit == 0;
            if running {
                let delta = raw.wrapping_sub(self.hpm_last[i]);
                let old = self.csr.mhpmcounter[i];
                let new = old.wrapping_add(delta);
                self.csr.mhpmcounter[i] = new;
                // Wrapping past all-ones sets OF and requests LCOFI, but only
                // on the 0->1 edge: while OF stays set the counter keeps
                // counting and the interrupt stays quiet. Software (the perf
                // handler, via SBI COUNTER_START) clears OF to re-arm.
                if new < old && event & csr::MHPMEVENT_OF == 0 {
                    self.csr.mhpmevent[i] |= csr::MHPMEVENT_OF;
                    overflowed = true;
                }
            }
            self.hpm_last[i] = raw;
        }
        if overflowed {
            self.mmu.mip |= csr::MIP_LCOFIP;
        }
    }

    /// `hpm_sync` on the paths that only need it when a counter is programmed
    /// (privilege transitions, `scountovf` reads).
    fn hpm_sync_if_active(&mut self) {
        if self.hpm_active {
            self.hpm_sync();
        }
    }

    /// Reads `hpmcounter<idx>` / `mhpmcounter<idx>`, bringing it up to date
    /// first.  Counters past `HPM_LAST` are hardwired 0.
    fn read_hpm_counter(&mut self, idx: usize) -> u64 {
        if idx > csr::HPM_LAST {
            return 0;
        }
        self.hpm_sync();
        self.csr.mhpmcounter[idx]
    }

    /// Recomputes the `hpm_active` gate after an `mhpmevent` write.
    fn hpm_refresh_active(&mut self) {
        self.hpm_active = (csr::HPM_FIRST..=csr::HPM_LAST)
            .any(|i| self.csr.mhpmevent[i] & csr::MHPMEVENT_SEL_MASK != csr::HPM_EV_NONE);
    }

    /// Smstateen: below M-mode, access to the state a `mstateen` bit guards
    /// traps unless that bit is set.
    ///
    /// Only two gates are live here.  `mstateen0.ENVCFG` guards `senvcfg`, and
    /// `mstateen0.SE0` guards `sstateen0`; `mstateen1..3` are hardwired zero,
    /// so their `SE0` denies `sstateen1..3` -- which gate nothing simmerv
    /// implements, so there is nothing there to reach anyway.
    const fn stateen_denies(&self, csr: Csr) -> bool {
        if matches!(self.mmu.prv, PrivMode::M) {
            return false;
        }
        match csr {
            Csr::Senvcfg => self.csr.mstateen0 & csr::MSTATEEN0_ENVCFG == 0,
            Csr::Sstateen0 => self.csr.mstateen0 & csr::MSTATEEN0_SE0 == 0,
            // Gated by mstateen1..3.SE0, all hardwired zero.
            Csr::Sstateen1 | Csr::Sstateen2 | Csr::Sstateen3 => true,
            _ => false,
        }
    }

    fn has_csr_access_privilege(&self, csrno: u16) -> Option<Csr> {
        let csr = FromPrimitive::from_u16(csrno)?;

        if !csr::legal(csr) {
            log::warn!("** {csr:?} isn't implemented"); // XXX Ok, fine, it's useful for debugging but ....
            return None;
        }

        let privilege = (csrno >> 8) & 3;
        if u64::from(privilege) > { u64::from(self.mmu.prv) } {
            log::warn!("** Lacking priviledge for {csr:?}");
            return None;
        }

        Some(csr)
    }

    // XXX This is still so far from complete; copy the logic from Dromajo and
    // review each CSR.  Do Not Blanket allow reads and writes from unsupported
    // CSRs
    #[allow(clippy::cast_sign_loss)]
    fn read_csr(&mut self, csrno: u16) -> Result<u64, Exception> {
        use PrivMode::S;

        let illegal = Err(Exception {
            trap: Trap::IllegalInstruction,
            tval: 0,
        });

        // Cosim override: if the DUT armed a value for this CSR's next
        // read, return it (after privilege checks below) and consume
        // the entry. Privilege checks still apply so behavioral traps
        // remain consistent with the model.
        let armed = match self.armed_csr_read {
            Some((c, _)) if c == csrno => self.armed_csr_read.take().map(|(_, v)| v),
            _ => None,
        };

        // PMP: pmpcfg0-15 (0x3A0-0x3AF) and pmpaddr0-63 (0x3B0-0x3EF) — M-mode only.
        // The DUTs (SmolRV64, probe) implement 0 PMP entries: reads return 0, writes
        // ignored. A nonzero readback would make OpenSBI see PMP present and attempt
        // root-domain hart isolation, which the DUTs (no PMP) skip -> boot divergence.
        if matches!(csrno, 0x3A0..=0x3EF) {
            if u64::from(self.mmu.prv) < 3 {
                return illegal;
            }
            return Ok(0);
        }

        // Zihpm: hpmcounter3-31 (0xC03-0xC1F, U-mode), mhpmcounter3-31 (0xB03-0xB1F,
        // M-mode), mhpmevent3-31 (0x323-0x33F, M-mode). Counters HPM_FIRST..=HPM_LAST
        // are implemented and count the events named in csr::HPM_EV_*; the rest are
        // hardwired 0 (which is also how OpenSBI discovers how many exist -- it
        // writes a value and checks the read-back). These count at a model-specific
        // rate, so in cosim the DUT arms its read value and the two models agree.
        if matches!(csrno, 0xC03..=0xC1F) {
            if self.mmu.prv != PrivMode::M {
                let bit = 1u32 << (csrno - 0xC00);
                if self.csr.mcounteren & bit == 0 {
                    return illegal;
                }
                if self.mmu.prv == PrivMode::U && self.csr.scounteren & bit == 0 {
                    return illegal;
                }
            }
            return Ok(armed.unwrap_or_else(|| self.read_hpm_counter(csrno as usize - 0xC00)));
        }
        if matches!(csrno, 0xB03..=0xB1F) {
            if u64::from(self.mmu.prv) < 3 {
                return illegal;
            }
            return Ok(armed.unwrap_or_else(|| self.read_hpm_counter(csrno as usize - 0xB00)));
        }
        if matches!(csrno, 0x323..=0x33F) {
            if u64::from(self.mmu.prv) < 3 {
                return illegal;
            }
            let idx = csrno as usize - 0x320;
            let event = if idx <= csr::HPM_LAST {
                self.csr.mhpmevent[idx]
            } else {
                0
            };
            return Ok(armed.unwrap_or(event));
        }

        let Some(csr) = self.has_csr_access_privilege(csrno) else {
            return illegal;
        };

        if Self::is_vector_csr(csr) && (!self.rva23_enabled || self.vs == 0) {
            return illegal;
        }

        if self.stateen_denies(csr) {
            return illegal;
        }

        match csr {
            Csr::Fflags | Csr::Frm | Csr::Fcsr => self.check_float_access_ro(0)?,
            Csr::Cycle | Csr::Time | Csr::Instret if self.mmu.prv != PrivMode::M => {
                let bit = 1u32 << (csrno & 0x1f);
                if self.csr.mcounteren & bit == 0 {
                    return illegal;
                }
                if self.mmu.prv == PrivMode::U && self.csr.scounteren & bit == 0 {
                    return illegal;
                }
            }
            // Bring OF up to date so a counter that overflowed since the
            // last sync is visible to the handler.
            Csr::Scountovf => self.hpm_sync_if_active(),
            Csr::Satp => {
                if self.mmu.prv == S && self.mmu.mstatus & MSTATUS_TVM != 0 {
                    return illegal;
                }
                return Ok(self.mmu.satp);
            }
            // Sstc: stimecmp is only accessible from S-mode when menvcfg.STCE=1
            Csr::Stimecmp if self.mmu.prv == S && self.csr.menvcfg & MENVCFG_STCE == 0 => {
                return illegal;
            }
            _ => {}
        }
        Ok(armed.unwrap_or_else(|| self.read_csr_raw(csr)))
    }

    #[allow(clippy::cast_sign_loss)]
    fn write_csr(&mut self, csrno: u16, value: u64) -> Result<(), Exception> {
        let illegal = Err(Exception {
            trap: Trap::IllegalInstruction,
            tval: 0,
        });

        // PMP: pmpcfg0-15 and pmpaddr0-63 — M-mode only, 0 entries implemented:
        // writes silently ignored (matches the DUTs; see the read side).
        if matches!(csrno, 0x3A0..=0x3EF) {
            if u64::from(self.mmu.prv) < 3 {
                return illegal;
            }
            return Ok(());
        }

        // Zihpm: hpmcounter3-31 are read-only. mhpmcounter/mhpmevent are
        // writable for the implemented counters and ignored above HPM_LAST --
        // OpenSBI sizes the PMU by writing each one and checking the read-back,
        // so "ignored" is what makes counters 16-31 not exist.
        if matches!(csrno, 0xC03..=0xC1F) {
            return illegal; // read-only
        }
        if matches!(csrno, 0xB03..=0xB1F) {
            if u64::from(self.mmu.prv) < 3 {
                return illegal;
            }
            let idx = csrno as usize - 0xB00;
            if idx <= csr::HPM_LAST {
                // Settle the events counted so far, then take the new base.
                self.hpm_sync();
                self.csr.mhpmcounter[idx] = value;
            }
            return Ok(());
        }
        if matches!(csrno, 0x323..=0x33F) {
            if u64::from(self.mmu.prv) < 3 {
                return illegal;
            }
            let idx = csrno as usize - 0x320;
            if idx <= csr::HPM_LAST {
                // Charge the old event up to now, then re-base on the new one
                // so the switch doesn't credit this counter with the new
                // source's entire history.
                self.hpm_sync();
                self.csr.mhpmevent[idx] = value;
                self.hpm_last[idx] = self.hpm_source(value);
                self.hpm_refresh_active();
            }
            return Ok(());
        }

        let Some(csr) = self.has_csr_access_privilege(csrno) else {
            return illegal;
        };

        if (csrno >> 10) & 3 == 3 {
            log::warn!("Write attempted to Read Only CSR {csrno:03x}");
            return illegal;
        }

        if Self::is_vector_csr(csr) && (!self.rva23_enabled || self.vs == 0) {
            return illegal;
        }

        if self.stateen_denies(csr) {
            return illegal;
        }

        match csr {
            Csr::Fflags | Csr::Frm | Csr::Fcsr => self.check_float_access_and_dirty(0)?,
            Csr::Cycle => {
                log::info!("** deny cycle writing");
                return illegal;
            }
            // The inhibit bit decides whether a counter accrues, so settle
            // every counter against the OLD mask before it changes. This is
            // the start/stop that SBI_PMU_COUNTER_START/STOP bottoms out in.
            Csr::Mcountinhibit => self.hpm_sync(),
            // Sstc: stimecmp is only accessible from S-mode when menvcfg.STCE=1
            Csr::Stimecmp
                if self.mmu.prv == PrivMode::S && self.csr.menvcfg & MENVCFG_STCE == 0 =>
            {
                return illegal;
            }
            Csr::Satp => {
                if self.mmu.prv == PrivMode::S && self.mmu.mstatus & MSTATUS_TVM != 0 {
                    return illegal;
                }

                // WARL: silently ignore writes selecting a mode this hart
                // does not implement.  Sv48/Sv57 are accepted only when
                // `max_satp_mode` has been raised -- see the field docs.
                let mode = (value >> SATP_MODE_SHIFT) & SATP_MODE_MASK;
                if mode != SatpMode::Bare as u64
                    && !(SatpMode::Sv39 as u64..=self.max_satp_mode).contains(&mode)
                {
                    return Ok(());
                }

                // satp.ASID is WARL; this hart implements 10 ASID bits (matches
                // smolrv64 TLB_ASID_BITS=10). Zero the unimplemented high ASID
                // bits so reads-back match the DUT (Linux probes ASID width by
                // writing all-1s and reading back).
                let impl_asid_bits = 10u64;
                let asid_keep = ((1u64 << impl_asid_bits) - 1) << SATP_ASID_SHIFT;
                let value = value & !((SATP_ASID_MASK << SATP_ASID_SHIFT) & !asid_keep);
                let old_satp = self.mmu.satp;
                self.mmu.satp = value;
                // Both the TLBs and the uop cache are ASID-tagged -- entries
                // carry the ASID and a lookup only matches its own -- so
                // switching to a *different* ASID cannot alias and needs no
                // flush at all, however much the PPN moves.  That is the
                // common case: a context switch.
                //
                // What does need one:
                //   * a MODE change, which reinterprets every entry;
                //   * a PPN change that keeps the same ASID, i.e. software reusing an ASID for
                //     a different address space.  The spec obliges it to announce that with
                //     SFENCE.VMA, so this is belt-and-braces, but it is rare enough to be free.
                let field = |v: u64, sh: u64, m: u64| (v >> sh) & m;
                let mode_changed = field(old_satp, SATP_MODE_SHIFT, SATP_MODE_MASK)
                    != field(value, SATP_MODE_SHIFT, SATP_MODE_MASK);
                let same_asid = field(old_satp, SATP_ASID_SHIFT, SATP_ASID_MASK)
                    == field(value, SATP_ASID_SHIFT, SATP_ASID_MASK);
                let ppn_changed = field(old_satp, SATP_PPN_SHIFT, SATP_PPN_MASK)
                    != field(value, SATP_PPN_SHIFT, SATP_PPN_MASK);
                if mode_changed || (ppn_changed && same_asid) {
                    self.mmu.flush_tlb();
                    self.icache_flush = IcacheFlushKind::Full;
                }
                return Ok(());
            }
            _ => {}
        }

        self.write_csr_raw(csr, value);
        // Standalone: deliver a newly-unmasked interrupt AT the enabling write.
        // The block executor only checks interrupts at block/batch boundaries,
        // and these CSR writes are not block-terminal, so a local_irq_enable /
        // local_irq_disable window within one block would otherwise pass with
        // the pending IRQ never delivered -> the kernel spins forever waiting
        // for the handler's side effect. Under cosim this must be skipped: the
        // per-retire loop already checks interrupts between instructions, and
        // taking one inline fires it a retire earlier than smolrv64 (which
        // vectors at the next fetch boundary) and diverges.
        if !self.cosim_mode && matches!(csr, Csr::Sstatus | Csr::Sie | Csr::Mstatus | Csr::Mie) {
            self.handle_interrupt();
        }
        Ok(())
    }

    // SSTATUS, SIE, and SIP are subsets of MSTATUS, MIE, and MIP
    #[allow(clippy::cast_sign_loss)]
    fn read_csr_raw(&self, csr: Csr) -> u64 {
        match csr {
            // Instret (0xC02) must alias Minstret (0xB02): the SBI PMU hands
            // S-mode counter 2 as "CSR_CYCLE + 2" and Linux reads it directly,
            // so leaving it out here made perf's "instructions" a stuck-at-0
            // counter. IPC is therefore exactly 1 -- see the XXX in run_soc.
            Csr::Cycle | Csr::Mcycle | Csr::Minstret | Csr::Instret => self.cycle,
            Csr::Fcsr => self.read_fcsr(),
            Csr::Fflags => u64::from(self.read_fflags()),
            Csr::Frm => self.read_frm() as u64,
            Csr::Mcause => self.csr.mcause,
            Csr::Medeleg => self.csr.medeleg,
            Csr::Mepc => self.csr.mepc,
            Csr::Mhartid => self.csr.mhartid,
            // Match smolrv64's hardwired implementation IDs. These are
            // implementation-defined; simmerv adopts the DUT's values so
            // cosim doesn't diverge on reads of marchid/mimpid.
            Csr::Marchid => 9,
            Csr::Mimpid => 0x2025_0907,
            Csr::Mideleg => self.csr.mideleg,
            Csr::Mie => self.csr.mie,
            Csr::Mip => self.mmu.mip,
            Csr::Misa => self.csr.misa,
            Csr::Mscratch => self.csr.mscratch,
            Csr::Mstatus => {
                let mut mstatus = self.mmu.mstatus & !(1u64 << 63);
                mstatus &= !(MSTATUS_FS | MSTATUS_VS);
                mstatus |= u64::from(self.fs) << MSTATUS_FS_SHIFT;
                mstatus |= u64::from(self.exposed_vs()) << MSTATUS_VS_SHIFT;
                if self.fs == 3 || self.exposed_vs() == 3 {
                    mstatus |= 1 << 63;
                }
                mstatus
            }
            Csr::Mtval => self.csr.mtval,
            Csr::Mtvec => self.csr.mtvec,
            Csr::Satp => self.mmu.satp,
            Csr::Scause => self.csr.scause,
            Csr::Sedeleg => self.csr.sedeleg,
            Csr::Sepc => self.csr.sepc,
            Csr::Sideleg => self.csr.sideleg,
            Csr::Sie => self.csr.mie & self.csr.mideleg,
            Csr::Sip => self.mmu.mip & self.csr.mideleg,
            Csr::Sscratch => self.csr.sscratch,
            Csr::Sstatus => {
                let mut mstatus = self.mmu.mstatus & !(1u64 << 63);
                mstatus &= !(MSTATUS_FS | MSTATUS_VS);
                mstatus &= 0x8000_0003_000d_e162;
                mstatus |= u64::from(self.fs) << MSTATUS_FS_SHIFT;
                mstatus |= u64::from(self.exposed_vs()) << MSTATUS_VS_SHIFT;
                if self.fs == 3 || self.exposed_vs() == 3 {
                    mstatus |= 1 << 63;
                }
                mstatus
            }
            Csr::Stval => self.csr.stval,
            Csr::Stvec => self.csr.stvec,
            Csr::Stimecmp => self.csr.stimecmp,
            Csr::Mcounteren => u64::from(self.csr.mcounteren),
            Csr::Mcountinhibit => self.csr.mcountinhibit,
            Csr::Mcyclecfg => self.csr.mcyclecfg,
            Csr::Minstretcfg => self.csr.minstretcfg,
            // Sscofpmf: shadow of mhpmevent3-31.OF. Outside M-mode a bit
            // reads 0 unless mcounteren delegates that counter, so S-mode only
            // learns about overflows of counters it may read.
            Csr::Scountovf => {
                let mut ovf = 0u64;
                let mut i = csr::HPM_FIRST;
                while i <= csr::HPM_LAST {
                    if self.csr.mhpmevent[i] & csr::MHPMEVENT_OF != 0 {
                        ovf |= 1 << i;
                    }
                    i += 1;
                }
                if matches!(self.mmu.prv, PrivMode::M) {
                    ovf
                } else {
                    ovf & u64::from(self.csr.mcounteren)
                }
            }
            Csr::Scounteren => u64::from(self.csr.scounteren),
            Csr::Senvcfg => self.csr.senvcfg,
            Csr::Mstateen0 => self.csr.mstateen0,
            // mstateen1..3 and sstateen0..3 gate only state simmerv does not
            // implement, so they read zero via the catch-all below.
            Csr::Menvcfg => self.csr.menvcfg,
            Csr::Pmpcfg0 => self.csr.pmpcfg0,
            Csr::Pmpaddr0 => self.csr.pmpaddr0,
            Csr::Time => self.mmu.read_mtime_csr(),
            Csr::Ustatus => self.csr.ustatus,
            Csr::Vstart => self.v.vstart,
            Csr::Vxsat => u64::from(self.v.vxsat),
            Csr::Vxrm => u64::from(self.v.vxrm),
            Csr::Vcsr => self.v.vcsr(),
            Csr::Vl => self.v.vl,
            Csr::Vtype => self.v.vtype,
            Csr::Vlenb => self.v.vlenb as u64,
            _ => 0,
        }
    }

    // Legalize a value stored into a VA-holding CSR (mepc/sepc/mtval/stval) to
    // match the DUT, which stores these 40-bit Sv39-compressed (low 39 + a
    // non-canonical flag) -- see probe/va_codec.vh.  Canonical addresses are
    // exact; a non-canonical one is WARL-legalized to {25{~va[38]}, va[38:0]}
    // (still non-canonical, faults identically, but not bit-for-bit verbatim).
    // Applying it here covers BOTH the trap handler and architectural CSRW,
    // since both route through write_csr_raw.
    ///
    /// The width follows [`Cpu::max_satp_mode`]: compressing an Sv48 or Sv57
    /// address into 39 bits would corrupt a perfectly legal `sepc`, so a hart
    /// configured for the wider modes legalizes at the wider width.
    const fn legalize_va(&self, v: u64) -> u64 {
        let n = self.va_bits();
        let sign = (v >> (n - 1)) & 1;
        let top = !0u64 << n;
        let sext_top = if sign == 1 { top } else { 0u64 };
        if (v & top) == sext_top {
            v // canonical: stored exactly
        } else {
            let lo = v & !top;
            let new_top = if sign == 1 { 0u64 } else { top };
            new_top | lo
        }
    }

    fn write_csr_raw(&mut self, csr: Csr, value: u64) {
        match csr {
            Csr::Mcycle => self.cycle = value,
            Csr::Fcsr => self.write_fcsr(value),
            Csr::Fflags => self.write_fflags((value & 31) as u8),
            Csr::Frm => self.write_frm(
                FromPrimitive::from_u64(value & 7).unwrap_or(RoundingMode::RoundNearestEven),
            ),
            Csr::Mcause => self.csr.mcause = value,
            Csr::Medeleg => self.csr.medeleg = value,
            Csr::Mepc => self.csr.mepc = self.legalize_va(value),
            Csr::Mhartid => self.csr.mhartid = value,
            // Sscofpmf: bit 13 (LCOFIP) is delegatable in addition to the
            // standard SSIP/STIP/SEIP (0x222). The DUT stores mideleg unmasked
            // and the firmware writes 0x2222.
            Csr::Mideleg => self.csr.mideleg = value & 0x2222,
            Csr::Mie => self.csr.mie = value,
            Csr::Mip => self.mmu.mip = value,
            Csr::Mscratch => self.csr.mscratch = value,
            Csr::Mstatus => {
                let mask = MSTATUS_MASK & !(MSTATUS_VS | MSTATUS_UXL_MASK | MSTATUS_SXL_MASK);
                self.mmu.mstatus = value & mask | self.mmu.mstatus & !mask;
                self.fs = ((value >> MSTATUS_FS_SHIFT) & 3) as u8;
                // Without V the VS field is hardwired to zero (WARL).
                if self.rva23_enabled {
                    self.vs = ((value >> MSTATUS_VS_SHIFT) & 3) as u8;
                }
            }
            Csr::Mtval => self.csr.mtval = self.legalize_va(value),
            Csr::Mtvec => self.csr.mtvec = value,
            Csr::Scause => self.csr.scause = value,
            Csr::Sedeleg => self.csr.sedeleg = value,
            Csr::Sepc => self.csr.sepc = self.legalize_va(value),
            Csr::Sideleg => self.csr.sideleg = value,
            // SIE mask includes LCOFIE (bit 13) to match the DUT (csr_mie & 0x2222).
            Csr::Sie => self.csr.mie = self.csr.mie & !0x2222 | value & 0x2222,
            // 0x2222: SSIP/STIP/SEIP plus Sscofpmf's LCOFIP -- the perf
            // overflow handler clears it with csr_clear(CSR_SIP, BIT(13)).
            Csr::Sip => self.mmu.mip = value & 0x2222 | self.mmu.mip & !0x2222,
            Csr::Sscratch => self.csr.sscratch = value,
            Csr::Sstatus => {
                // UXL[33:32] is read-only WARL (=2 on this RV64 hart): writable
                // sstatus mask excludes it, matching the Mstatus-write masking.
                let mask = 0x8000_0003_000d_e162 & !MSTATUS_UXL_MASK;
                self.mmu.mstatus &= !mask;
                self.mmu.mstatus |= value & mask;
                self.fs = ((value >> MSTATUS_FS_SHIFT) & 3) as u8;
                if self.rva23_enabled {
                    self.vs = ((value >> MSTATUS_VS_SHIFT) & 3) as u8;
                }
            }
            Csr::Stval => self.csr.stval = self.legalize_va(value),
            Csr::Stvec => self.csr.stvec = value,
            Csr::Stimecmp => {
                self.csr.stimecmp = value;
                // Clear STIP immediately; service() will re-set it if needed
                self.mmu.mip &= !MIP_STIP;
            }
            Csr::Mcounteren => self.csr.mcounteren = (value & 0xFFFF_FFFF) as u32,
            // smolrv64 implements 13 HPM counters; mcountinhibit is WARL masked
            // to those (bit 1/TM hardwired 0): HPM_INHIBIT_MASK = 0xfffd.
            Csr::Mcountinhibit => self.csr.mcountinhibit = value & 0xfffd,
            // Smcntrpmf: mcyclecfg/minstretcfg store the privilege-inhibit
            // filter bits; the DUT keeps them as plain 64-bit RW registers.
            Csr::Mcyclecfg => self.csr.mcyclecfg = value,
            Csr::Minstretcfg => self.csr.minstretcfg = value,
            Csr::Scounteren => self.csr.scounteren = (value & 0xFFFF_FFFF) as u32,
            Csr::Menvcfg => self.csr.menvcfg = value,
            Csr::Senvcfg => self.csr.senvcfg = value,
            // WARL: keep only the bits that gate state we actually have.  The
            // other stateen registers are read-only zero and fall through to
            // the write catch-all.
            Csr::Mstateen0 => self.csr.mstateen0 = value & csr::MSTATEEN0_MASK,
            Csr::Misa => {} // read-only WARL; extension set is fixed
            Csr::Pmpcfg0 => self.csr.pmpcfg0 = value, // verbatim, matching the DUT
            Csr::Pmpaddr0 => self.csr.pmpaddr0 = value,
            Csr::Time => self.mmu.write_mtime_csr(value), // XXX SHOULD trap
            Csr::Ustatus => self.csr.ustatus = value,
            // Writing any vector CSR makes the vector state dirty.
            Csr::Vstart => {
                self.v.vstart = value & (self.v.vlenb as u64 * 8 - 1);
                self.vs = 3;
            }
            Csr::Vxsat => {
                self.v.vxsat = value & 1 != 0;
                self.vs = 3;
            }
            Csr::Vxrm => {
                self.v.vxrm = (value & 3) as u8;
                self.vs = 3;
            }
            Csr::Vcsr => {
                self.v.set_vcsr(value);
                self.vs = 3;
            }
            _ => log::warn!("We are ignoring writes to {csr:?}"),
        }
    }

    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    pub fn disassemble(&mut self, s: &mut String) {
        let addr = self.pc;
        let Ok(insn) = self.memop_disass(addr) else {
            let _ = write!(s, "{addr:016x} <inaccessible>");
            return;
        };

        let Uop {
            op,
            rd,
            rs1,
            rs2,
            imm,
            ..
        } = decode(addr, insn as u32, self.rva23_enabled);

        let op = format!("{op:?}").to_lowercase(); // XXX More clever CAdd -> c.add

        let _ = write!(s, "{addr:016x} ");
        if insn % 4 == 3 {
            let _ = write!(s, "{insn:08x} {op:11} {rd}, {rs1}, {rs2}, {imm:016x}"); // ,{rs3}
            return;
        }
        let insn = insn & 0xffff;
        let op = &op[1..];
        let _ = write!(s, "{insn:04x}     c.{op:9} {rd}, {rs1}, {rs2}, {imm:016x}");
    }

    /// Returns mutable `Mmu`
    pub const fn get_mut_mmu(&mut self) -> &mut Mmu { &mut self.mmu }

    // --- Snapshot ---

    /// Serialises CPU architectural state (registers, PC, CSRs, cycle, MMU).
    ///
    /// Format:
    ///   [65×8 B] integer + FP register file (rf[0..65])
    ///   [8 B] pc
    ///   [1 B] frm
    ///   [1 B] fflags
    ///   [1 B] fs
    ///   [8 B] cycle
    ///   [1 B] wfi
    ///   [1 B] reservation flag (0=None, 1=Some) + [8 B] value
    ///   [20×8 B] CSR fields (fixed order, see `read_state`)
    ///   [1 B] vs (mstatus.VS) + [1 B] `rva23_enabled`
    ///   [4×8 B] vtype, vl, vstart, vcsr
    ///   [32·`MAX_VLENB` B] the vector register file, then [8 B] `vlenb`
    ///   [? B] MMU state (via `Mmu::write_state`)
    pub fn write_state(&self, out: &mut Vec<u8>) {
        {
            let mut w = Pack::new(out);
            for &r in &self.rf {
                w.u64(r);
            }
            w.u64(self.pc);
            w.u8(self.frm as u8);
            w.u8(self.fflags);
            w.u8(self.fs);
            w.u64(self.cycle);
            w.bool(self.wfi);
            match self.reservation {
                None => {
                    w.u8(0);
                    w.u64(0);
                }
                Some(v) => {
                    w.u8(1);
                    w.u64(v);
                }
            }
            let c = &self.csr;
            for &v in &[
                c.mcause,
                c.medeleg,
                c.mepc,
                c.mhartid,
                c.mideleg,
                c.mie,
                c.misa,
                c.mscratch,
                c.mtval,
                c.mtvec,
                c.scause,
                c.sedeleg,
                c.sepc,
                c.sideleg,
                c.sscratch,
                c.stval,
                c.stvec,
                c.ustatus,
                c.menvcfg,
                c.stimecmp,
                u64::from(c.mcounteren),
                u64::from(c.scounteren),
                c.senvcfg,
            ] {
                w.u64(v);
            }
            // HPM: the counters and their selectors are architectural state.
            // `hpm_last` is not -- the uop cache it baselines against is not in
            // the snapshot, so read_state re-bases instead (see hpm_rebase).
            w.u64(c.mcountinhibit);
            for i in csr::HPM_FIRST..=csr::HPM_LAST {
                w.u64(c.mhpmcounter[i]);
                w.u64(c.mhpmevent[i]);
            }
            w.u8(self.vs);
            w.bool(self.rva23_enabled);
            w.u64(self.v.vtype);
            w.u64(self.v.vl);
            w.u64(self.v.vstart);
            w.u64(self.v.vcsr());
            w.raw(&self.v.vrf);
            w.u64(self.v.vlenb as u64);
        }
        self.mmu.write_state(out);
    }

    /// Restores CPU state from a blob produced by `write_state`.
    ///
    /// # Errors
    /// Returns `Err(())` on truncation or malformed data.
    /// # Panics
    /// Will not panic on well-formed input; the inner `unwrap` calls on
    /// fixed-size slice conversions are infallible after the length check.
    #[allow(clippy::missing_panics_doc, clippy::result_unit_err)]
    pub fn read_state(
        &mut self,
        data: &[u8],
        make_device: impl FnMut(
            &str,
            std::ops::Range<u64>,
        ) -> Option<Box<dyn crate::device::MemoryMapped>>,
    ) -> Result<(), ()> {
        let mut r = Unpack::new(data);

        for reg in &mut self.rf {
            *reg = r.u64()?;
        }
        self.pc = r.u64()?;
        self.frm = match r.u8()? {
            0 => RoundingMode::RoundNearestEven,
            1 => RoundingMode::RoundTowardsZero,
            2 => RoundingMode::RoundDown,
            3 => RoundingMode::RoundUp,
            4 => RoundingMode::RoundNearestMagnitude,
            5 => RoundingMode::Reserved5,
            6 => RoundingMode::Reserved6,
            7 => RoundingMode::Dynamic,
            _ => return Err(()),
        };
        self.fflags = r.u8()?;
        self.fs = r.u8()?;
        self.cycle = r.u64()?;
        self.wfi = r.bool()?;
        self.reservation = if r.u8()? == 0 {
            let _ = r.u64()?;
            None
        } else {
            Some(r.u64()?)
        };
        let c = &mut self.csr;
        for field in [
            &mut c.mcause,
            &mut c.medeleg,
            &mut c.mepc,
            &mut c.mhartid,
            &mut c.mideleg,
            &mut c.mie,
            &mut c.misa,
            &mut c.mscratch,
            &mut c.mtval,
            &mut c.mtvec,
            &mut c.scause,
            &mut c.sedeleg,
            &mut c.sepc,
            &mut c.sideleg,
            &mut c.sscratch,
            &mut c.stval,
            &mut c.stvec,
            &mut c.ustatus,
            &mut c.menvcfg,
            &mut c.stimecmp,
        ] {
            *field = r.u64()?;
        }
        c.mcounteren = (r.u64()? & 0xFFFF_FFFF) as u32;
        c.scounteren = (r.u64()? & 0xFFFF_FFFF) as u32;
        c.senvcfg = r.u64()?;
        c.mcountinhibit = r.u64()?;
        for i in csr::HPM_FIRST..=csr::HPM_LAST {
            c.mhpmcounter[i] = r.u64()?;
            c.mhpmevent[i] = r.u64()?;
        }
        self.hpm_bb = crate::uop_cache::UopCacheStats::default();
        self.hpm_last = [0; csr::HPM_LAST + 1];
        self.hpm_rebase = true;
        self.hpm_refresh_active();
        self.vs = r.u8()?;
        self.rva23_enabled = r.bool()?;
        self.v.vtype = r.u64()?;
        self.v.vl = r.u64()?;
        self.v.vstart = r.u64()?;
        let vcsr = r.u64()?;
        self.v.set_vcsr(vcsr);
        self.v.vrf.copy_from_slice(r.raw(vector::MAX_VRF_BYTES)?);
        // A width, always 16 or 32; fits usize on every target.
        #[allow(clippy::cast_possible_truncation)]
        {
            self.v.vlenb = r.u64()? as usize;
        }
        self.icache_flush = IcacheFlushKind::Full;
        self.mmu.read_state(r.remaining(), make_device)
    }

    /// Returns mutable reference to the serial backend, if any.
    pub fn get_mut_serial_backend(&mut self) -> Option<&mut dyn SerialBackend> {
        self.mmu.get_mut_serial_backend()
    }

    pub(crate) fn read_frm(&self) -> RoundingMode {
        debug_assert_ne!(self.fs, 0);
        self.frm
    }

    fn write_frm(&mut self, frm: RoundingMode) {
        debug_assert_ne!(self.fs, 0);
        self.fs = 3;
        self.frm = frm;
    }

    fn read_fflags(&self) -> u8 {
        debug_assert_ne!(self.fs, 0);
        self.fflags
    }

    fn write_fflags(&mut self, fflags: u8) {
        debug_assert_ne!(self.fs, 0);
        debug_assert_eq!(fflags & !31, 0);
        self.fs = 3;
        self.fflags = fflags;
    }

    /// Accumulate non-zero fflags
    #[allow(clippy::inline_always)]
    #[inline(always)]
    pub(crate) fn add_to_fflags(&mut self, fflags: u8) {
        debug_assert_ne!(fflags, 0);
        debug_assert_ne!(self.fs, 0);
        debug_assert_eq!(fflags & !31, 0);
        self.fs = 3;
        self.fflags |= fflags;
    }

    #[allow(clippy::precedence)]
    fn read_fcsr(&self) -> u64 {
        debug_assert_ne!(self.fs, 0);
        debug_assert_eq!(self.fflags & !31, 0);
        u64::from(self.fflags) | (self.frm as u64) << 5
    }

    #[allow(clippy::cast_sign_loss)]
    fn write_fcsr(&mut self, v: u64) {
        debug_assert_ne!(self.fs, 0);
        self.write_fflags((v & 31) as u8);
        // We must refuse to write illegal values FRM
        if let Some(frm) = FromPrimitive::from_u64((v >> 5) & 7) {
            self.write_frm(frm);
        }
    }

    fn get_rm(&self, insn_rm_field: u8) -> RoundingMode {
        if insn_rm_field == 7 {
            self.frm
        } else {
            let Some(rm) = FromPrimitive::from_u8(insn_rm_field) else {
                unreachable!("decoding should raised illegal exception on rm {insn_rm_field}");
            };
            rm
        }
    }

    /// Fetch a 4-byte instruction word from `va`.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn memop_code(&mut self, va: u64) -> Result<u64, Exception> {
        // A 4-byte instruction can straddle a page boundary only if the low
        // 12 bits are 0xFFE.  Fetch the low halfword first: a compressed
        // instruction (bits[1:0] != 0b11) needs no more, so we must NOT touch
        // (and possibly fault on) the next page.  Only a genuine 32-bit
        // instruction reads the upper halfword, which may legitimately fault.
        if va & 0xfff > 0x1000 - 4 {
            let lo = self.memop_slow(Execute, va, 0, 2, false)?;
            if lo & 3 != 3 {
                return Ok(lo);
            }
            let hi = self.memop_slow(Execute, va + 2, 0, 2, false)?;
            return Ok(lo | (hi << 16));
        }

        let pa = self.mmu.translate_code_address(va)?;

        let Ok(slice) = self.mmu.dma_slice(pa, 4) else {
            return self.mmu.load_mmio(pa, 4).map_err(|()| Exception {
                trap: Trap::InstructionAccessFault,
                tval: va,
            });
        };

        Ok(u64::from(u32::from_le_bytes([
            slice[0], slice[1], slice[2], slice[3],
        ])))
    }

    /// Fetch a 4-byte instruction word for disassembly (side-effect-free).
    /// # Errors
    /// Usual memory exceptions
    pub fn memop_disass(&mut self, baseva: u64) -> Result<u64, Exception> {
        if baseva & 0xfff > 0x1000 - 4 {
            return self.memop_slow(Execute, baseva, 0, 4, true);
        }
        let pa = self.mmu.translate_code_address(baseva)?;
        let Ok(slice) = self.mmu.dma_slice(pa, 4) else {
            return Ok(0);
        };
        Ok(u64::from(u32::from_le_bytes([
            slice[0], slice[1], slice[2], slice[3],
        ])))
    }

    /// Vector element load. Like [`memop_read`](Self::memop_read), but an
    /// element that crosses a 4 KiB page boundary is byte-split (each byte
    /// translated on its own) instead of trapped as address-misaligned. Real
    /// vector hardware handles page-crossing element accesses, and the M-mode
    /// misaligned-access emulation cannot decode a vector instruction — so a
    /// trap here surfaces as a fatal, unrecoverable exception in the guest.
    pub(crate) fn memop_read_vector(&mut self, va: u64, size: u64) -> Result<u64, Exception> {
        if va & 0xfff > 0x1000 - size {
            return self.memop_slow(Read, va, 0, size, false);
        }
        self.memop_read(va, 0, size)
    }

    /// Vector element store; see
    /// [`memop_read_vector`](Self::memop_read_vector).
    pub(crate) fn memop_write_vector(
        &mut self,
        va: u64,
        v: u64,
        size: u64,
    ) -> Result<(), Exception> {
        self.reservation = None;
        if va & 0xfff > 0x1000 - size {
            self.memop_slow(Write, va, v, size, false)?;
            return Ok(());
        }
        self.memop_write(va, 0, v, size)
    }

    /// Data load.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    pub(crate) fn memop_read(
        &mut self,
        baseva: u64,
        offset: u64,
        size: u64,
    ) -> Result<u64, Exception> {
        let va = baseva.wrapping_add(offset);

        if va & 0xfff > 0x1000 - size {
            // smolrv64 traps page-crossing data accesses (single dTLB xlate)
            // as misaligned when paging is active below M-mode; firmware
            // emulates them. Match that instead of silently byte-splitting.
            if self.mmu.page_cross_access_traps() {
                return Err(Exception {
                    trap: Trap::LoadAddressMisaligned,
                    tval: va,
                });
            }
            return self.memop_slow(Read, va, 0, size, false);
        }

        let addr = self.mmu.translate_data_address(va, Read, false)?;

        let is_mmio = addr.mem_idx == DataAddr::NO_RAM;
        let result =
            if is_mmio {
                // Perform the MMIO read for its side effects, then let the DUT's
                // armed value win (device-register bits are model-specific).
                let model_val = self.mmu.load_mmio(addr.pa, size).map_err(|()| Exception {
                    trap: Trap::LoadAccessFault,
                    tval: va,
                })?;
                self.armed_load_value.take().map_or(model_val, |v| {
                let mask = if size >= 8 {
                    u64::MAX
                } else {
                    (1u64 << (size * 8)) - 1
                };
                let vv = v & mask;
                // COSIM DIAGNOSTIC: the DUT's MMIO read value differs from simmerv's
                // own model -> the DUT device returned something wrong (and the cosim
                // silently follows it). Capped so a poll loop can't flood. mtime is
                // synced to dut each retire so it won't show; expect only the culprit.
                if vv != (model_val & mask) {
                    use std::sync::atomic::{AtomicU64, Ordering};
                    static N: AtomicU64 = AtomicU64::new(0);
                    let i = N.fetch_add(1, Ordering::Relaxed);
                    if i < 200 {
                        eprintln!(
                            "MMIO-DIVERGE#{i} pc={:#x} pa={:#x} sz={size} model={:#x} dut={:#x}",
                            self.pc, addr.pa, model_val & mask, vv
                        );
                    }
                }
                vv
            })
            } else {
                // SAFETY: `host_page` points at the mapped page inside a RAM
                // region (`mem_idx != NO_RAM`), the offset is masked to within
                // that page, and the caller has already rejected accesses that
                // would cross its end. Reading through the pointer rather than
                // indexing `Mmu::memory` is the entire point: it drops a
                // dependent load out of the chain of every load.
                let p = unsafe { addr.host_page.add(va as usize & 0xfff) };
                unsafe {
                    // `from_le` keeps the previous byte-wise assembly's
                    // explicit little-endian semantics; it is a no-op on every
                    // host this targets.
                    match size {
                        1 => u64::from(p.read()),
                        2 => u64::from(u16::from_le(p.cast::<u16>().read_unaligned())),
                        4 => u64::from(u32::from_le(p.cast::<u32>().read_unaligned())),
                        _ => u64::from_le(p.cast::<u64>().read_unaligned()),
                    }
                }
            };

        Ok(result)
    }

    /// Data store. Clears any load-reservation.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    pub(crate) fn memop_write(
        &mut self,
        baseva: u64,
        offset: u64,
        v: u64,
        size: u64,
    ) -> Result<(), Exception> {
        self.reservation = None;
        let va = baseva.wrapping_add(offset);

        if va & 0xfff > 0x1000 - size {
            if self.mmu.page_cross_access_traps() {
                return Err(Exception {
                    trap: Trap::StoreAddressMisaligned,
                    tval: va,
                });
            }
            self.memop_slow(Write, va, v, size, false)?;
            return Ok(());
        }

        let addr = self.mmu.translate_data_address(va, Write, false)?;

        // cosim store-stream log (VIRTUAL address -> frame-allocation-independent)
        if crate::mmu::storelog_active() {
            let m = if size >= 8 {
                u64::MAX
            } else {
                (1u64 << (size * 8)) - 1
            };
            eprintln!("ST {va:016x} {size} {:016x}", v & m);
        }

        if addr.mem_idx != DataAddr::NO_RAM {
            // SAFETY: as in `memop_read`.
            let p = unsafe { addr.host_page.add(va as usize & 0xfff) };
            unsafe {
                match size {
                    1 => p.write(v as u8),
                    2 => p.cast::<u16>().write_unaligned((v as u16).to_le()),
                    4 => p.cast::<u32>().write_unaligned((v as u32).to_le()),
                    _ => p.cast::<u64>().write_unaligned(v.to_le()),
                }
            }
            return Ok(());
        }

        self.mmu
            .store_mmio(addr.pa, v, size)
            .map_err(|()| Exception {
                trap: Trap::StoreAccessFault,
                tval: va,
            })
    }

    // Slow path where we either span multiple pages and/or access outside memory
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    fn memop_slow(
        &mut self,
        access: MemoryAccessType,
        va: u64,
        mut v: u64,
        size: u64,
        side_effect_free: bool,
    ) -> Result<u64, Exception> {
        let trap = match access {
            Read => Trap::LoadAccessFault,
            Write => Trap::StoreAccessFault,
            Execute => Trap::InstructionAccessFault,
        };

        let mut r: u64 = 0;
        for i in 0..size {
            let pa = self
                .mmu
                .translate_address(va + i, access, side_effect_free)?;

            let mut b = 0;
            if let Ok(slice) = self.mmu.dma_slice(pa, 1) {
                match access {
                    Write => slice[0] = v as u8,
                    Read | Execute => b = slice[0],
                }
            } else {
                if side_effect_free {
                    return Ok(0);
                }

                match access {
                    Write => {
                        if self.mmu.store_mmio_u8(pa, v as u8).is_err() {
                            return Err(Exception { trap, tval: va + i });
                        }
                    }
                    Read | Execute => {
                        let Ok(w) = self.mmu.load_mmio_u8(pa) else {
                            return Err(Exception { trap, tval: va + i });
                        };
                        b = w;
                    }
                }
            }
            r |= u64::from(b) << (i * 8);
            v >>= 8;
        }
        if access == Write { Ok(0) } else { Ok(r) }
    }

    /// For a given instruction word, find which registers it may read and
    /// write.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` if the instruction word is illegal or cannot be
    /// decoded.
    pub fn get_register_info(&self, addr: u64, insn: u32) -> anyhow::Result<Uop> {
        Ok(decode(addr, insn, self.rva23_enabled))
    }
}

// XXX Not sure where to keep this
#[must_use]
pub const fn sext32(x: u32) -> u64 { x as i32 as u64 }

#[must_use]
pub const fn get_trap_cause(exc: &Exception) -> u64 {
    let interrupt_bit = 0x8000_0000_0000_0000_u64;
    if (exc.trap as u64) < (Trap::UserSoftwareInterrupt as u64) {
        exc.trap as u64
    } else {
        exc.trap as u64 - Trap::UserSoftwareInterrupt as u64 + interrupt_bit
    }
}

#[must_use]
pub fn decode(a: u64, word: u32, rva23: bool) -> Uop {
    let mut uop = decoder(a, word, &mut new_decoder::Decoder { rva23 });
    let size: u8 = if word & 3 == 3 { 4 } else { 2 };
    let branch_flag: u8 = if Cpu::is_branch(uop.op) { 0x80 } else { 0 };
    uop.insn_size = size | branch_flag;
    uop
}

/// Perform a CSR write and build the result, flagging the case where the write
/// redirected the PC.
///
/// A write to `sstatus`/`sie`/`mstatus`/`mie` can unmask an already-pending
/// interrupt, which `write_csr` delivers inline — moving the PC to the trap
/// vector.  That has to reach the block executor as [`REDIRECT_BIT`], or it
/// would carry on executing the rest of the block from the vector address.
///
/// Comparing the PC to spot it is exactly what the executor's hot loop no
/// longer does, but here it is fine: CSR writes are a fraction of a percent of
/// instructions.
#[inline]
fn csr_write_out(cpu: &mut Cpu, csrno: u16, value: u64, res: u64) -> ExecOut {
    let pc_before = cpu.pc;
    if let Err(e) = cpu.write_csr(csrno, value) {
        return ExecOut::err(e.trap, e.tval);
    }
    if cpu.pc == pc_before {
        ExecOut::ok(res)
    } else {
        ExecOut::redirected(res)
    }
}

/// Inline fast path for the most common ops (integer ALU, branches, jumps,
/// loads and stores).  Avoids the function-call overhead of `new_execute` for
/// the great majority of instructions.
#[allow(clippy::inline_always)]
#[inline(always)]
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::too_many_lines
)]
fn execute_fast(cpu: &mut Cpu, uop: &Uop, s1: u64, s2: u64, s3: u64, insn_addr: u64) -> ExecOut {
    match uop.op {
        // Lui / Auipc
        Op::Lui | Op::CLui => ExecOut::ok(uop.imm64()),
        Op::Auipc => ExecOut::ok(insn_addr.wrapping_add(uop.imm64())),
        // Jumps
        Op::Jal | Op::CJ => {
            let tmp = cpu.pc;
            cpu.pc = insn_addr.wrapping_add(uop.imm64());
            ExecOut::redirected(tmp)
        }
        Op::Jalr | Op::CJr | Op::CJalr => {
            let tmp = cpu.pc;
            cpu.pc = s1.wrapping_add(uop.imm64()) & !1;
            ExecOut::redirected(tmp)
        }
        // Branches
        Op::Beq | Op::CBeqz => {
            if s1 == s2 {
                cpu.pc = insn_addr.wrapping_add(uop.imm64());
                ExecOut::redirected(0)
            } else {
                ExecOut::ok(0)
            }
        }
        Op::Bne | Op::CBnez => {
            if s1 == s2 {
                ExecOut::ok(0)
            } else {
                cpu.pc = insn_addr.wrapping_add(uop.imm64());
                ExecOut::redirected(0)
            }
        }
        Op::Blt => {
            if (s1 as i64) < s2 as i64 {
                cpu.pc = insn_addr.wrapping_add(uop.imm64());
                ExecOut::redirected(0)
            } else {
                ExecOut::ok(0)
            }
        }
        Op::Bge => {
            if (s1 as i64) >= s2 as i64 {
                cpu.pc = insn_addr.wrapping_add(uop.imm64());
                ExecOut::redirected(0)
            } else {
                ExecOut::ok(0)
            }
        }
        Op::Bltu => {
            if s1 < s2 {
                cpu.pc = insn_addr.wrapping_add(uop.imm64());
                ExecOut::redirected(0)
            } else {
                ExecOut::ok(0)
            }
        }
        Op::Bgeu => {
            if s1 >= s2 {
                cpu.pc = insn_addr.wrapping_add(uop.imm64());
                ExecOut::redirected(0)
            } else {
                ExecOut::ok(0)
            }
        }
        // Integer immediate
        Op::Addi | Op::CAddi | Op::CAddi4spn | Op::CLi | Op::CAddi16sp => {
            ExecOut::ok(s1.wrapping_add(uop.imm64()))
        }
        Op::Slti => ExecOut::ok(u64::from((s1 as i64) < uop.imm as i64)),
        Op::Sltiu => ExecOut::ok(u64::from(s1 < uop.imm64())),
        Op::Xori => ExecOut::ok(s1 ^ uop.imm64()),
        Op::Ori => ExecOut::ok(s1 | uop.imm64()),
        Op::Andi | Op::CAndi => ExecOut::ok(s1 & uop.imm64()),
        Op::Slli | Op::CSlli => ExecOut::ok(s1 << uop.imm as u32),
        Op::Srli | Op::CSrli => ExecOut::ok(s1 >> uop.imm as u32),
        Op::Srai | Op::CSrai => ExecOut::ok(((s1 as i64) >> uop.imm as u32) as u64),
        // Integer register
        Op::Add | Op::CAdd | Op::CMv => ExecOut::ok(s1.wrapping_add(s2)),
        Op::Sub | Op::CSub => ExecOut::ok(s1.wrapping_sub(s2)),
        Op::Sll => ExecOut::ok(s1.wrapping_shl(s2 as u32)),
        Op::Slt => ExecOut::ok(u64::from((s1 as i64) < s2 as i64)),
        Op::Sltu => ExecOut::ok(u64::from(s1 < s2)),
        Op::Xor | Op::CXor => ExecOut::ok(s1 ^ s2),
        Op::Srl => ExecOut::ok(s1.wrapping_shr(s2 as u32)),
        Op::Sra => ExecOut::ok((s1 as i64).wrapping_shr(s2 as u32) as u64),
        Op::Or | Op::COr => ExecOut::ok(s1 | s2),
        Op::And | Op::CAnd => ExecOut::ok(s1 & s2),
        // RV64I word ops
        Op::Addiw | Op::CAddiw => ExecOut::ok(sext32(s1.wrapping_add(uop.imm64()) as u32)),
        Op::Slliw => ExecOut::ok(((s1 as i32) << (uop.imm & 31) as u32) as u64),
        Op::Srliw => ExecOut::ok(sext32((s1 as u32) >> (uop.imm & 31) as u32)),
        Op::Sraiw => ExecOut::ok(((s1 as i32) >> (uop.imm & 31) as u32) as u64),
        Op::Addw | Op::CAddw => ExecOut::ok(sext32(s1.wrapping_add(s2) as u32)),
        Op::Subw | Op::CSubw => ExecOut::ok(sext32(s1.wrapping_sub(s2) as u32)),
        Op::Sllw => ExecOut::ok(sext32((s1 as u32).wrapping_shl(s2 as u32))),
        Op::Srlw => ExecOut::ok(sext32((s1 as u32).wrapping_shr(s2 as u32))),
        Op::Sraw => ExecOut::ok((s1 as i32).wrapping_shr(s2 as u32) as u64),
        // RV32M/RV64M integer multiply
        Op::Mul => ExecOut::ok(s1.wrapping_mul(s2)),
        Op::Mulw => ExecOut::ok((s1 as i32).wrapping_mul(s2 as i32) as u64),
        // Integer loads and stores — about a third of a Linux workload's
        // dynamic instructions, and previously the largest group still
        // reaching `new_execute`.  Worth only ~1%: the fall-through is a tail
        // call into a single jump table, not a second dispatch, so what this
        // buys is the call itself, not the decode.
        Op::Lb => ExecOut::ok(etry!(cpu.memop_read(s1, uop.imm64(), 1)) as i8 as u64),
        Op::Lbu => ExecOut::ok(etry!(cpu.memop_read(s1, uop.imm64(), 1))),
        Op::Lh => ExecOut::ok(etry!(cpu.memop_read(s1, uop.imm64(), 2)) as i16 as u64),
        Op::Lhu => ExecOut::ok(etry!(cpu.memop_read(s1, uop.imm64(), 2))),
        Op::Lw | Op::CLw | Op::CLwsp => {
            ExecOut::ok(etry!(cpu.memop_read(s1, uop.imm64(), 4)) as i32 as u64)
        }
        Op::Lwu => ExecOut::ok(etry!(cpu.memop_read(s1, uop.imm64(), 4))),
        Op::Ld | Op::CLd | Op::CLdsp => ExecOut::ok(etry!(cpu.memop_read(s1, uop.imm64(), 8))),
        Op::Sb => {
            etry!(cpu.memop_write(s1, uop.imm64(), s2, 1));
            ExecOut::ok(0)
        }
        Op::Sh => {
            etry!(cpu.memop_write(s1, uop.imm64(), s2, 2));
            ExecOut::ok(0)
        }
        Op::Sw | Op::CSw | Op::CSwsp => {
            etry!(cpu.memop_write(s1, uop.imm64(), s2, 4));
            ExecOut::ok(0)
        }
        Op::Sd | Op::CSd | Op::CSdsp => {
            etry!(cpu.memop_write(s1, uop.imm64(), s2, 8));
            ExecOut::ok(0)
        }
        // Everything else: float, CSR, atomic, vector, etc.
        _ => new_execute(cpu, uop, s1, s2, s3, insn_addr),
    }
}

#[allow(
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    // EBREAK and C.EBREAK intentionally share the same Breakpoint{tval:pc} body
    // but live in the compressed- and base-op sections respectively.
    clippy::match_same_arms
)]
fn new_execute(cpu: &mut Cpu, uop: &Uop, s1: u64, s2: u64, s3: u64, insn_addr: u64) -> ExecOut {
    match uop.op {
        // NOTE (cosim gating gap): the Zicbom (CboInval/Clean/Flush) ops are
        // no-ops on this coherent functional model, and we do not gate them on
        // menvcfg.CBIE/CBCFE.  A spec-correct DUT traps these (illegal instr)
        // when the enable bits are clear; we never do.  Safe only because
        // OpenSBI sets menvcfg before S-mode.  See MENVCFG_STCE in csr.rs.
        Op::CNop
        | Op::SfenceWInval
        | Op::SfenceInvalIr
        | Op::CboInval
        | Op::CboClean
        | Op::CboFlush
        | Op::PrefetchI
        | Op::PrefetchR
        | Op::PrefetchW => ExecOut::ok(0),
        Op::CEbreak => ExecOut::err(Trap::Breakpoint, insn_addr),

        Op::Lui | Op::CLui => ExecOut::ok(uop.imm64()),
        Op::Auipc => ExecOut::ok(insn_addr.wrapping_add(uop.imm64())),
        Op::Jal | Op::CJ => {
            let tmp = cpu.pc;
            cpu.pc = insn_addr.wrapping_add(uop.imm64());
            ExecOut::redirected(tmp)
        }
        Op::Jalr | Op::CJr | Op::CJalr => {
            let tmp = cpu.pc;
            cpu.pc = s1.wrapping_add(uop.imm64()) & !1;
            ExecOut::redirected(tmp)
        }
        Op::Beq | Op::CBeqz => {
            if s1 == s2 {
                cpu.pc = insn_addr.wrapping_add(uop.imm64());
                ExecOut::redirected(0)
            } else {
                ExecOut::ok(0)
            }
        }
        Op::Bne | Op::CBnez => {
            if s1 == s2 {
                ExecOut::ok(0)
            } else {
                cpu.pc = insn_addr.wrapping_add(uop.imm64());
                ExecOut::redirected(0)
            }
        }
        Op::Blt => {
            if (s1 as i64) < s2 as i64 {
                cpu.pc = insn_addr.wrapping_add(uop.imm64());
                ExecOut::redirected(0)
            } else {
                ExecOut::ok(0)
            }
        }
        Op::Bge => {
            if (s1 as i64) >= s2 as i64 {
                cpu.pc = insn_addr.wrapping_add(uop.imm64());
                ExecOut::redirected(0)
            } else {
                ExecOut::ok(0)
            }
        }
        Op::Bltu => {
            if s1 < s2 {
                cpu.pc = insn_addr.wrapping_add(uop.imm64());
                ExecOut::redirected(0)
            } else {
                ExecOut::ok(0)
            }
        }
        Op::Bgeu => {
            if s1 >= s2 {
                cpu.pc = insn_addr.wrapping_add(uop.imm64());
                ExecOut::redirected(0)
            } else {
                ExecOut::ok(0)
            }
        }
        Op::Lb => ExecOut::ok(etry!(cpu.memop_read(s1, uop.imm64(), 1)) as i8 as u64),
        Op::Lh => ExecOut::ok(etry!(cpu.memop_read(s1, uop.imm64(), 2)) as i16 as u64),
        Op::Lw | Op::CLw | Op::CLwsp => {
            ExecOut::ok(etry!(cpu.memop_read(s1, uop.imm64(), 4)) as i32 as u64)
        }
        Op::Lbu => ExecOut::ok(etry!(cpu.memop_read(s1, uop.imm64(), 1))),
        Op::Lhu => ExecOut::ok(etry!(cpu.memop_read(s1, uop.imm64(), 2))),
        Op::Sb => {
            etry!(cpu.memop_write(s1, uop.imm64(), s2, 1));
            ExecOut::ok(0)
        }
        Op::Sh => {
            etry!(cpu.memop_write(s1, uop.imm64(), s2, 2));
            ExecOut::ok(0)
        }
        Op::Sw | Op::CSw | Op::CSwsp => {
            etry!(cpu.memop_write(s1, uop.imm64(), s2, 4));
            ExecOut::ok(0)
        }
        Op::Addi | Op::CAddi | Op::CAddi4spn | Op::CLi | Op::CAddi16sp => {
            ExecOut::ok(s1.wrapping_add(uop.imm64()))
        }
        Op::Slti => ExecOut::ok(u64::from((s1 as i64) < uop.imm as i64)),
        Op::Sltiu => ExecOut::ok(u64::from(s1 < uop.imm64())),
        Op::Xori => ExecOut::ok(s1 ^ uop.imm64()),
        Op::Ori => ExecOut::ok(s1 | uop.imm64()),
        Op::Andi | Op::CAndi => ExecOut::ok(s1 & uop.imm64()),
        // RV32I SLLI subsumed by RV64I
        // RV32I SRLI subsumed by RV64I
        // RV32I SRAI subsumed by RV64I
        Op::Add | Op::CAdd | Op::CMv => ExecOut::ok(s1.wrapping_add(s2)),
        Op::Sub | Op::CSub => ExecOut::ok(s1.wrapping_sub(s2)),
        Op::Sll => ExecOut::ok(s1.wrapping_shl(s2 as u32)),
        Op::Slt => ExecOut::ok(u64::from((s1 as i64) < s2 as i64)),
        Op::Sltu => ExecOut::ok(u64::from(s1 < s2)),
        Op::Xor | Op::CXor => ExecOut::ok(s1 ^ s2),
        Op::Srl => ExecOut::ok(s1.wrapping_shr(s2 as u32)),
        Op::Sra => ExecOut::ok((s1 as i64).wrapping_shr(s2 as u32) as u64),
        Op::Or | Op::COr => ExecOut::ok(s1 | s2),
        Op::And | Op::CAnd => ExecOut::ok(s1 & s2),
        Op::Fence => {
            if uop.imm == 0x0100000f_u32 as i32 {
                // PAUSE instruction hint
                // Nothing to do here, but it would be interesting to see
                // it used.
                log::trace!("pause isn't yet implemented");
            }
            // Fence memory ops (we are currently TSO already)
            ExecOut::ok(0)
        }
        Op::FenceTso => {
            // Fence memory ops (we are currently TSO already)
            ExecOut::ok(0)
        }
        Op::Ecall => ExecOut::err(
            match cpu.mmu.prv {
                PrivMode::U => Trap::EnvironmentCallFromUMode,
                PrivMode::S => Trap::EnvironmentCallFromSMode,
                PrivMode::M => Trap::EnvironmentCallFromMMode,
            },
            uop.imm64(),
        ),
        // Breakpoint mtval is 0 or the pc per spec (never the instruction word).
        // The sharded-OoO (probe) core reports the pc, like Spike, so match that.
        // (Legacy smolrv64 inner core reported 0 -- its cosim would now differ here.)
        Op::Ebreak => ExecOut::err(Trap::Breakpoint, insn_addr),
        // RV64I
        Op::Lwu => {
            let v = etry!(cpu.memop_read(s1, uop.imm64(), 4));
            ExecOut::ok(v)
        }
        Op::Ld | Op::CLd | Op::CLdsp => {
            let v = etry!(cpu.memop_read(s1, uop.imm64(), 8));
            ExecOut::ok(v)
        }
        Op::Sd | Op::CSd | Op::CSdsp => {
            etry!(cpu.memop_write(s1, uop.imm64(), s2, 8));
            ExecOut::ok(0)
        }
        Op::Slli | Op::CSlli => ExecOut::ok(s1 << uop.imm as u32),
        Op::Srli | Op::CSrli => ExecOut::ok(s1 >> uop.imm as u32),
        Op::Srai | Op::CSrai => ExecOut::ok(((s1 as i64) >> uop.imm as u32) as u64),
        Op::Addiw | Op::CAddiw => ExecOut::ok(sext32(s1.wrapping_add(uop.imm64()) as u32)),
        Op::Slliw => ExecOut::ok(((s1 as i32) << (uop.imm & 31) as u32) as u64),
        Op::Srliw => ExecOut::ok(sext32((s1 as u32) >> (uop.imm & 31) as u32)),
        Op::Sraiw => ExecOut::ok(((s1 as i32) >> (uop.imm & 31) as u32) as u64),
        Op::Addw | Op::CAddw => ExecOut::ok(sext32(s1.wrapping_add(s2) as u32)),
        Op::Subw | Op::CSubw => ExecOut::ok(sext32(s1.wrapping_sub(s2) as u32)),
        Op::Sllw => ExecOut::ok(sext32((s1 as u32).wrapping_shl(s2 as u32))),
        Op::Srlw => ExecOut::ok(sext32((s1 as u32).wrapping_shr(s2 as u32))),
        Op::Sraw => ExecOut::ok((s1 as i32).wrapping_shr(s2 as u32) as u64),
        // RV32/RV64 Zifencei
        Op::FenceI => {
            cpu.reservation = None;
            cpu.icache_flush = IcacheFlushKind::Full;
            ExecOut::ok(0)
        }
        // RV32/RV64 Zicsr
        Op::Csrrw => {
            let res = if uop.rd.is_x0_dest() {
                0
            } else {
                etry!(cpu.read_csr(uop.imm as u16))
            };
            csr_write_out(cpu, uop.imm as u16, s1, res)
        }
        Op::Csrrs => {
            let data = etry!(cpu.read_csr(uop.imm as u16));
            if uop.rs1.get() == 0 {
                ExecOut::ok(data)
            } else {
                csr_write_out(cpu, uop.imm as u16, data | s1, data)
            }
        }
        Op::Csrrc => {
            let data = etry!(cpu.read_csr(uop.imm as u16));
            if uop.rs1.get() == 0 {
                ExecOut::ok(data)
            } else {
                csr_write_out(cpu, uop.imm as u16, data & !s1, data)
            }
        }
        Op::Csrrwi => {
            let res = if uop.rd.is_x0_dest() {
                0
            } else {
                etry!(cpu.read_csr(uop.imm as u16))
            };
            csr_write_out(cpu, uop.imm as u16, uop.rs1.get() as u64, res)
        }
        Op::Csrrsi => {
            let data = etry!(cpu.read_csr(uop.imm as u16));
            if uop.rs1.get() == 0 {
                ExecOut::ok(data)
            } else {
                csr_write_out(cpu, uop.imm as u16, data | uop.rs1.get() as u64, data)
            }
        }
        Op::Csrrci => {
            let data = etry!(cpu.read_csr(uop.imm as u16));
            if uop.rs1.get() == 0 {
                ExecOut::ok(data)
            } else {
                csr_write_out(cpu, uop.imm as u16, data & !(uop.rs1.get() as u64), data)
            }
        }
        // RV32M
        Op::Mul => ExecOut::ok(s1.wrapping_mul(s2)),
        Op::Mulh => ExecOut::ok(((i128::from(s1 as i64) * i128::from(s2 as i64)) >> 64) as u64),
        Op::Mulhsu => ExecOut::ok(((s1 as i64 as u128).wrapping_mul(u128::from(s2)) >> 64) as u64),
        Op::Mulhu => ExecOut::ok((u128::from(s1).wrapping_mul(u128::from(s2)) >> 64) as u64),
        Op::Div => ExecOut::ok(if s2 == 0 {
            !0
        } else if s1 as i64 == i64::MIN && s2 as i64 == -1 {
            s1
        } else {
            (s1 as i64).wrapping_div(s2 as i64) as u64
        }),
        Op::Divu => ExecOut::ok(if s2 == 0 { !0 } else { s1.wrapping_div(s2) }),
        Op::Rem => ExecOut::ok(if s2 == 0 {
            s1
        } else if s1 as i64 == i64::MIN && s2 as i64 == -1 {
            0
        } else {
            (s1 as i64).wrapping_rem(s2 as i64) as u64
        }),
        Op::Remu => ExecOut::ok(match s2 {
            0 => s1,
            _ => s1.wrapping_rem(s2),
        }),
        // RV64M
        Op::Mulw => ExecOut::ok((s1 as i32).wrapping_mul(s2 as i32) as u64),
        Op::Divw => {
            let (s1, s2) = (s1 as i32, s2 as i32);
            ExecOut::ok(if s2 == 0 {
                !0
            } else if s1 == i32::MIN && s2 == -1 {
                s1 as u64
            } else {
                s1.wrapping_div(s2) as u64
            })
        }
        Op::Divuw => ExecOut::ok(if s2 as u32 == 0 {
            !0
        } else {
            sext32((s1 as u32).wrapping_div(s2 as u32))
        }),
        Op::Remw => {
            let (s1, s2) = (s1 as i32, s2 as i32);
            ExecOut::ok(if s2 == 0 {
                s1 as u64
            } else if s1 == i32::MIN && s2 == -1 {
                0
            } else {
                s1.wrapping_rem(s2) as u64
            })
        }
        Op::Remuw => ExecOut::ok(match s2 as u32 {
            0 => s1 as i32 as u64,
            _ => sext32((s1 as u32).wrapping_rem(s2 as u32)),
        }),
        // RV32A
        Op::LrW => {
            let data = sext32(etry!(cpu.mmu.load_virt_u32(s1)));
            let pa = etry!(cpu.mmu.translate_address(s1, MemoryAccessType::Read, false));
            cpu.reservation = Some(pa);
            ExecOut::ok(data)
        }
        Op::ScW => {
            let pa = etry!(
                cpu.mmu
                    .translate_address(s1, MemoryAccessType::Write, false)
            );
            let res = if cpu.reservation == Some(pa) {
                etry!(cpu.mmu.store_virt_u32(s1, s2 as u32));
                0
            } else {
                1
            };
            cpu.reservation = None;
            ExecOut::ok(res)
        }
        Op::AmoswapW => {
            let tmp = etry!(cpu.mmu.load_virt_u32(s1));
            etry!(cpu.mmu.store_virt_u32(s1, s2 as u32));
            ExecOut::ok(sext32(tmp))
        }
        Op::AmoaddW => {
            let tmp = etry!(cpu.mmu.load_virt_u32(s1));
            etry!(cpu.mmu.store_virt_u32(s1, tmp.wrapping_add(s2 as u32)));
            ExecOut::ok(sext32(tmp))
        }
        Op::AmoxorW => {
            let tmp = etry!(cpu.mmu.load_virt_u32(s1));
            etry!(cpu.mmu.store_virt_u32(s1, s2 as u32 ^ tmp));
            ExecOut::ok(sext32(tmp))
        }
        Op::AmoandW => {
            let tmp = etry!(cpu.mmu.load_virt_u32(s1));
            etry!(cpu.mmu.store_virt_u32(s1, s2 as u32 & tmp));
            ExecOut::ok(sext32(tmp))
        }
        Op::AmoorW => {
            let tmp = etry!(cpu.mmu.load_virt_u32(s1));
            etry!(cpu.mmu.store_virt_u32(s1, s2 as u32 | tmp));
            ExecOut::ok(sext32(tmp))
        }
        Op::AmominW => {
            let tmp = etry!(cpu.mmu.load_virt_u32(s1));
            etry!(
                cpu.mmu
                    .store_virt_u32(s1, (s2 as i32).min(tmp as i32) as u32)
            );
            ExecOut::ok(sext32(tmp))
        }
        Op::AmomaxW => {
            let tmp = etry!(cpu.mmu.load_virt_u32(s1));
            etry!(
                cpu.mmu
                    .store_virt_u32(s1, (s2 as i32).max(tmp as i32) as u32)
            );
            ExecOut::ok(sext32(tmp))
        }
        Op::AmominuW => {
            let tmp = etry!(cpu.mmu.load_virt_u32(s1));
            etry!(cpu.mmu.store_virt_u32(s1, (s2 as u32).min(tmp)));
            ExecOut::ok(sext32(tmp))
        }
        Op::AmomaxuW => {
            let tmp = etry!(cpu.mmu.load_virt_u32(s1));
            etry!(cpu.mmu.store_virt_u32(s1, (s2 as u32).max(tmp)));
            ExecOut::ok(sext32(tmp))
        }
        // RV64A
        Op::LrD => {
            let data = etry!(cpu.mmu.load_virt_u64(s1));
            let pa = etry!(cpu.mmu.translate_address(s1, MemoryAccessType::Read, false));
            cpu.reservation = Some(pa);
            ExecOut::ok(data)
        }
        Op::ScD => {
            let pa = etry!(
                cpu.mmu
                    .translate_address(s1, MemoryAccessType::Write, false)
            );
            let res = if cpu.reservation == Some(pa) {
                etry!(cpu.mmu.store_virt_u64(s1, s2));
                0
            } else {
                1
            };
            cpu.reservation = None;
            ExecOut::ok(res)
        }
        Op::AmoswapD => {
            let tmp = etry!(cpu.mmu.load_virt_u64(s1));
            etry!(cpu.mmu.store_virt_u64(s1, s2));
            cpu.reservation = None;
            ExecOut::ok(tmp)
        }
        Op::AmoaddD => {
            let tmp = etry!(cpu.mmu.load_virt_u64(s1));
            etry!(cpu.mmu.store_virt_u64(s1, tmp.wrapping_add(s2)));
            cpu.reservation = None;
            ExecOut::ok(tmp)
        }
        Op::AmoxorD => {
            let tmp = etry!(cpu.mmu.load_virt_u64(s1));
            etry!(cpu.mmu.store_virt_u64(s1, tmp ^ s2));
            cpu.reservation = None;
            ExecOut::ok(tmp)
        }
        Op::AmoandD => {
            let tmp = etry!(cpu.mmu.load_virt_u64(s1));
            etry!(cpu.mmu.store_virt_u64(s1, tmp & s2));
            cpu.reservation = None;
            ExecOut::ok(tmp)
        }
        Op::AmoorD => {
            let tmp = etry!(cpu.mmu.load_virt_u64(s1));
            etry!(cpu.mmu.store_virt_u64(s1, tmp | s2));
            cpu.reservation = None;
            ExecOut::ok(tmp)
        }
        Op::AmominD => {
            let tmp = etry!(cpu.mmu.load_virt_u64(s1));
            etry!(
                cpu.mmu
                    .store_virt_u64(s1, (s2 as i64).min(tmp as i64) as u64)
            );
            cpu.reservation = None;
            ExecOut::ok(tmp)
        }
        Op::AmomaxD => {
            let tmp = etry!(cpu.mmu.load_virt_u64(s1));
            etry!(
                cpu.mmu
                    .store_virt_u64(s1, (s2 as i64).max(tmp as i64) as u64)
            );
            cpu.reservation = None;
            ExecOut::ok(tmp)
        }
        Op::AmominuD => {
            let tmp = etry!(cpu.mmu.load_virt_u64(s1));
            etry!(cpu.mmu.store_virt_u64(s1, s2.min(tmp)));
            cpu.reservation = None;
            ExecOut::ok(tmp)
        }
        Op::AmomaxuD => {
            let tmp = etry!(cpu.mmu.load_virt_u64(s1));
            etry!(cpu.mmu.store_virt_u64(s1, s2.max(tmp)));
            cpu.reservation = None;
            ExecOut::ok(tmp)
        }
        // RV32F
        Op::Flw => {
            // ro-check may trap (FP off); the load may page-fault. Dirty FS only AFTER the
            // value reaches the f-reg -- a faulting load writes nothing, so must not dirty.
            etry!(cpu.check_float_access_ro(0));
            let v = etry!(cpu.memop_read(s1, uop.imm64(), 4)) | fp::NAN_BOX_F32;
            cpu.mark_fp_dirty();
            ExecOut::ok(v)
        }
        Op::Fsw => {
            // FP store READS an f-reg (does not modify FP state) -> access-check only, no
            // FS-dirty.
            etry!(cpu.check_float_access_ro(0));
            etry!(cpu.memop_write(s1, uop.imm64(), s2, 4));
            ExecOut::ok(0)
        }
        Op::Flh => {
            etry!(cpu.check_float_access_ro(0));
            let v = etry!(cpu.memop_read(s1, uop.imm64(), 2)) | fp::NAN_BOX_F16;
            cpu.mark_fp_dirty();
            ExecOut::ok(v)
        }
        Op::Fsh => {
            // FP store READS an f-reg (does not modify FP state) -> access-check only, no
            // FS-dirty.
            etry!(cpu.check_float_access_ro(0));
            etry!(cpu.memop_write(s1, uop.imm64(), s2, 2));
            ExecOut::ok(0)
        }
        Op::FmaddS => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(Sf32::fma(s1, s2, s3, cpu.get_rm(uop.rm)))
        }
        Op::FmsubS => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(Sf32::fma(s1, s2, s3 ^ Sf32::SIGN_MASK, cpu.get_rm(uop.rm)))
        }
        Op::FnmsubS => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(Sf32::fma(s1 ^ Sf32::SIGN_MASK, s2, s3, cpu.get_rm(uop.rm)))
        }
        Op::FnmaddS => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(Sf32::fma(
                s1 ^ Sf32::SIGN_MASK,
                s2,
                s3 ^ Sf32::SIGN_MASK,
                cpu.get_rm(uop.rm),
            ))
        }
        Op::FaddS => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(Sf32::fadd(s1, s2, cpu.get_rm(uop.rm)))
        }
        Op::FsubS => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(Sf32::fsub(s1, s2, cpu.get_rm(uop.rm)))
        }
        Op::FmulS => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(Sf32::fmul(s1, s2, cpu.get_rm(uop.rm)))
        }
        Op::FdivS => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(Sf32::fdiv(s1, s2, cpu.get_rm(uop.rm)))
        }
        Op::FsqrtS => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(Sf32::fsqrt(s1, cpu.get_rm(uop.rm)))
        }
        Op::FsgnjS => {
            etry!(cpu.check_float_access_and_dirty(0));
            let rs1_bits = Sf32::unbox(s1);
            let rs2_bits = Sf32::unbox(s2);
            let sign_bit = rs2_bits & 0x80000000;
            ExecOut::ok(fp::NAN_BOX_F32 | sign_bit | rs1_bits & 0x7fffffff)
        }
        Op::FsgnjnS => {
            etry!(cpu.check_float_access_and_dirty(0));
            let rs1_bits = Sf32::unbox(s1);
            let rs2_bits = Sf32::unbox(s2);
            let sign_bit = !rs2_bits & 0x80000000;
            ExecOut::ok(fp::NAN_BOX_F32 | sign_bit | rs1_bits & 0x7fffffff)
        }
        Op::FsgnjxS => {
            etry!(cpu.check_float_access_and_dirty(0));
            let rs1_bits = Sf32::unbox(s1);
            let rs2_bits = Sf32::unbox(s2);
            let sign_bit = rs2_bits & 0x80000000;
            ExecOut::ok(fp::NAN_BOX_F32 | (sign_bit ^ rs1_bits))
        }
        Op::FminS => {
            etry!(cpu.check_float_access_and_dirty(0));
            ExecOut::from_wf(Sf32::min(s1, s2))
        }
        Op::FmaxS => {
            etry!(cpu.check_float_access_and_dirty(0));
            ExecOut::from_wf(Sf32::max(s1, s2))
        }
        Op::FcvtWS => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf_w(cvt_sf32_i32(s1, cpu.get_rm(uop.rm)))
        }
        Op::FcvtWuS => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf_w(cvt_sf32_u32(s1, cpu.get_rm(uop.rm)))
        }
        Op::FmvXW => {
            // FMV.X.W READS an f-reg (does not modify FP state) -> access-check only, no
            // FS-dirty.
            etry!(cpu.check_float_access_ro(0));
            ExecOut::ok(s1 as i32 as u64)
        }
        Op::FmvXH => {
            // FMV.X.H READS an f-reg (does not modify FP state) -> access-check only, no
            // FS-dirty.
            etry!(cpu.check_float_access_ro(0));
            ExecOut::ok(Sf16::unbox(s1) as i16 as u64)
        }
        Op::FeqS => {
            etry!(cpu.check_float_access_and_dirty(0));
            ExecOut::from_wf(Sf32::feq(s1, s2))
        }
        Op::FltS => {
            etry!(cpu.check_float_access_and_dirty(0));
            ExecOut::from_wf(Sf32::flt(s1, s2))
        }
        Op::FleS => {
            etry!(cpu.check_float_access_and_dirty(0));
            ExecOut::from_wf(Sf32::fle(s1, s2))
        }
        Op::FclassS => {
            // FCLASS READS an f-reg, writes an x-reg (no FP-state change) -> no FS-dirty.
            etry!(cpu.check_float_access_ro(0));
            ExecOut::ok(1 << Sf32::fclass(s1) as usize)
        }
        Op::FcvtSW => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(cvt_i32_sf32(s1, cpu.get_rm(uop.rm)))
        }
        Op::FcvtSWu => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(cvt_u32_sf32(s1, cpu.get_rm(uop.rm)))
        }
        Op::FmvWX => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::ok(fp::NAN_BOX_F32 | s1)
        }
        Op::FmvHX => {
            etry!(cpu.check_float_access_and_dirty(0));
            ExecOut::ok(fp::NAN_BOX_F16 | (s1 & 0xFFFF))
        }
        // RV64F
        Op::FcvtLS => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(cvt_sf32_i64(s1, cpu.get_rm(uop.rm)))
        }
        Op::FcvtLuS => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(cvt_sf32_u64(s1, cpu.get_rm(uop.rm)))
        }
        Op::FcvtSL => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(cvt_i64_sf32(s1, cpu.get_rm(uop.rm)))
        }
        Op::FcvtSLu => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(cvt_u64_sf32(s1, cpu.get_rm(uop.rm)))
        }
        // RV32D
        Op::Fld | Op::CFld | Op::CFldsp => {
            etry!(cpu.check_float_access_ro(0));
            let v = etry!(cpu.memop_read(s1, uop.imm64(), 8));
            cpu.mark_fp_dirty();
            ExecOut::ok(v)
        }
        Op::Fsd | Op::CFsd | Op::CFsdsp => {
            // FP store READS an f-reg (does not modify FP state) -> access-check only, no
            // FS-dirty.
            etry!(cpu.check_float_access_ro(0));
            etry!(cpu.mmu.store64(s1.wrapping_add(uop.imm64()), s2));
            ExecOut::ok(0)
        }
        Op::FmaddD => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(Sf64::fma(s1, s2, s3, cpu.get_rm(uop.rm)))
        }
        Op::FmsubD => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(Sf64::fma(s1, s2, s3 ^ Sf64::SIGN_MASK, cpu.get_rm(uop.rm)))
        }
        Op::FnmsubD => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(Sf64::fma(s1 ^ Sf64::SIGN_MASK, s2, s3, cpu.get_rm(uop.rm)))
        }
        Op::FnmaddD => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(Sf64::fma(
                s1 ^ Sf64::SIGN_MASK,
                s2,
                s3 ^ Sf64::SIGN_MASK,
                cpu.get_rm(uop.rm),
            ))
        }
        Op::FaddD => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(Sf64::fadd(s1, s2, cpu.get_rm(uop.rm)))
        }
        Op::FsubD => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(Sf64::fsub(s1, s2, cpu.get_rm(uop.rm)))
        }
        Op::FmulD => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(Sf64::fmul(s1, s2, cpu.get_rm(uop.rm)))
        }
        Op::FdivD => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(Sf64::fdiv(s1, s2, cpu.get_rm(uop.rm)))
        }
        Op::FsqrtD => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(Sf64::fsqrt(s1, cpu.get_rm(uop.rm)))
        }
        Op::FsgnjD => {
            etry!(cpu.check_float_access_and_dirty(0));
            let rs1_bits = s1;
            let rs2_bits = s2;
            let sign_bit = rs2_bits & 0x8000000000000000;
            ExecOut::ok(sign_bit | (rs1_bits & 0x7fffffffffffffff))
        }
        Op::FsgnjnD => {
            etry!(cpu.check_float_access_and_dirty(0));
            let rs1_bits = s1;
            let rs2_bits = s2;
            let sign_bit = !rs2_bits & 0x8000000000000000;
            ExecOut::ok(sign_bit | (rs1_bits & 0x7fffffffffffffff))
        }
        Op::FsgnjxD => {
            etry!(cpu.check_float_access_and_dirty(0));
            let rs1_bits = s1;
            let rs2_bits = s2;
            let sign_bit = rs2_bits & 0x8000000000000000;
            ExecOut::ok(sign_bit ^ rs1_bits)
        }
        Op::FminD => {
            etry!(cpu.check_float_access_and_dirty(0));
            ExecOut::from_wf(Sf64::min(s1, s2))
        }
        Op::FmaxD => {
            etry!(cpu.check_float_access_and_dirty(0));
            ExecOut::from_wf(Sf64::max(s1, s2))
        }
        Op::FcvtSD => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(fp::fcvt_s_d(s1, cpu.get_rm(uop.rm)))
        }
        Op::FcvtDS => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(fp::fcvt_d_s(s1))
        }
        Op::FcvtSH => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(fp::fcvt_s_h(s1))
        }
        Op::FcvtHS => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(fp::fcvt_h_s(s1, cpu.get_rm(uop.rm)))
        }
        Op::FcvtDH => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(fp::fcvt_d_h(s1))
        }
        Op::FcvtHD => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(fp::fcvt_h_d(s1, cpu.get_rm(uop.rm)))
        }
        Op::FeqD => {
            etry!(cpu.check_float_access_and_dirty(0));
            ExecOut::from_wf(Sf64::feq(s1, s2))
        }
        Op::FltD => {
            etry!(cpu.check_float_access_and_dirty(0));
            ExecOut::from_wf(Sf64::flt(s1, s2))
        }
        Op::FleD => {
            etry!(cpu.check_float_access_and_dirty(0));
            ExecOut::from_wf(Sf64::fle(s1, s2))
        }
        Op::FclassD => {
            // FCLASS READS an f-reg, writes an x-reg (no FP-state change) -> no FS-dirty.
            etry!(cpu.check_float_access_ro(0));
            ExecOut::ok(1 << Sf64::fclass(s1) as usize)
        }
        Op::FcvtWD | Op::FcvtWuD => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            if uop.op == Op::FcvtWD {
                ExecOut::from_wf_w(cvt_sf64_i32(s1, cpu.get_rm(uop.rm)))
            } else {
                ExecOut::from_wf_w(cvt_sf64_u32(s1, cpu.get_rm(uop.rm)))
            }
        }
        Op::FcvtDW => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(cvt_i32_sf64(s1, cpu.get_rm(uop.rm)))
        }
        Op::FcvtDWu => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(cvt_u32_sf64(s1, cpu.get_rm(uop.rm)))
        }
        // RV64D
        Op::FcvtLD => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(cvt_sf64_i64(s1, cpu.get_rm(uop.rm)))
        }
        Op::FcvtLuD => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(cvt_sf64_u64(s1, cpu.get_rm(uop.rm)))
        }
        Op::FmvXD => {
            // FMV.X.D READS an f-reg (does not modify FP state) -> access-check only, no
            // FS-dirty.
            etry!(cpu.check_float_access_ro(0));
            ExecOut::ok(s1)
        }
        Op::FmvDX => {
            // FMV.D.X WRITES an f-reg -> dirties FS.
            etry!(cpu.check_float_access_and_dirty(0));
            ExecOut::ok(s1)
        }
        Op::FcvtDL => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(cvt_i64_sf64(s1, cpu.get_rm(uop.rm)))
        }
        Op::FcvtDLu => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(cvt_u64_sf64(s1, cpu.get_rm(uop.rm)))
        }
        // Remaining (all system-level) that weren't listed in the instr-table
        Op::Dret => todo!("Handling dret requires handling all of debug mode"),
        Op::Mret => {
            cpu.pc = etry!(cpu.read_csr(Csr::Mepc as u16));
            let status = cpu.read_csr_raw(Csr::Mstatus);

            let mpie = (status >> 7) & 1;
            let mpp = (status >> 11) & 3;
            let mprv = match priv_mode_from(mpp) {
                PrivMode::M => (status >> 17) & 1,
                _ => 0,
            };
            // Override MIE[3] with MPIE[7], set MPIE[7] to 1, set MPP[12:11] to 0
            // and override MPRV[17]
            let new_status = (status & !0x21888) | (mprv << 17) | (mpie << 3) | (1 << 7);
            cpu.write_csr_raw(Csr::Mstatus, new_status);
            cpu.hpm_sync_if_active();
            cpu.mmu.update_priv_mode(priv_mode_from(mpp));
            ExecOut::redirected(0)
        }
        Op::Sret => {
            if cpu.mmu.prv == PrivMode::U
                || cpu.mmu.prv == PrivMode::S && cpu.mmu.mstatus & MSTATUS_TSR != 0
            {
                return ExecOut::err(Trap::IllegalInstruction, 0);
            }

            cpu.pc = etry!(cpu.read_csr(Csr::Sepc as u16));
            let status = cpu.read_csr_raw(Csr::Sstatus);
            let spie = (status >> 5) & 1;
            let spp = (status >> 8) & 1;
            let mprv = match priv_mode_from(spp) {
                PrivMode::M => (status >> 17) & 1,
                _ => 0,
            };
            // Override SIE[1] with SPIE[5], set SPIE[5] to 1, set SPP[8] to 0,
            // and override MPRV[17]
            let new_status = (status & !0x20122) | (mprv << 17) | (spie << 1) | (1 << 5);
            cpu.write_csr_raw(Csr::Sstatus, new_status);
            cpu.hpm_sync_if_active();
            cpu.mmu.update_priv_mode(priv_mode_from(spp));
            ExecOut::redirected(0)
        }
        Op::SfenceVma | Op::SinvalVma => {
            if cpu.mmu.prv == PrivMode::U
                || cpu.mmu.prv == PrivMode::S && cpu.mmu.mstatus & MSTATUS_TVM != 0
            {
                return ExecOut::err(Trap::IllegalInstruction, 0);
            }

            let rs1_val = cpu.read_x(uop.rs1);
            let rs2_val = cpu.read_x(uop.rs2);
            #[allow(clippy::cast_possible_truncation)]
            match (rs1_val != 0, rs2_val != 0) {
                (false, false) => cpu.mmu.flush_tlb(),
                (true, false) => cpu.mmu.flush_tlb_vpage((rs1_val >> PG_SHIFT) as u32),
                (false, true) => cpu.mmu.flush_tlb_asid(rs2_val as u16),
                (true, true) => cpu
                    .mmu
                    .flush_tlb_vpage_asid((rs1_val >> PG_SHIFT) as u32, rs2_val as u16),
            }
            cpu.reservation = None;
            cpu.icache_flush = match (rs1_val != 0, rs2_val != 0) {
                (false, false) => IcacheFlushKind::Full,
                (true, false) => IcacheFlushKind::Vpage(rs1_val),
                (false, true) => IcacheFlushKind::Asid(rs2_val as u16),
                (true, true) => IcacheFlushKind::VpageAsid(rs1_val, rs2_val as u16),
            };
            ExecOut::ok(0)
        }
        Op::Wfi => {
            /*
             * "When TW=1, if WFI is executed in S- mode, and it does
             * not complete within an implementation-specific, bounded
             * time limit, the WFI instruction causes an illegal
             * instruction trap."
             */
            if cpu.mmu.prv == PrivMode::U
                || cpu.mmu.prv == PrivMode::S && cpu.mmu.mstatus & MSTATUS_TW != 0
            {
                return ExecOut::err(Trap::IllegalInstruction, 0);
            }
            // WFI retires as a NOP in cosim — smolrv64 does the same (see
            // smolrv64.v S_RF: "treat as NOP (no real sleep in simulation)").
            // Keeping a wfi-pause here would desync cosim, and mtime is driven
            // externally anyway so pausing buys nothing.
            ExecOut::ok(0)
        }
        // Zba -- AKA, my only favorite extension
        Op::AddUw => ExecOut::ok(s2.wrapping_add(s1 & 0xffffffff)),
        Op::Sh1add => ExecOut::ok(s2.wrapping_add(s1 << 1)),
        Op::Sh1addUw => ExecOut::ok(s2.wrapping_add((s1 & 0xffffffff) << 1)),
        Op::Sh2add => ExecOut::ok(s2.wrapping_add(s1 << 2)),
        Op::Sh2addUw => ExecOut::ok(s2.wrapping_add((s1 & 0xffffffff) << 2)),
        Op::Sh3add => ExecOut::ok(s2.wrapping_add(s1 << 3)),
        Op::Sh3addUw => ExecOut::ok(s2.wrapping_add((s1 & 0xffffffff) << 3)),
        Op::SlliUw => ExecOut::ok((s1 & 0xffffffff) << uop.imm as u32),
        // Zicond extension
        Op::CzeroEqz => ExecOut::ok(if s2 == 0 { 0 } else { s1 }),
        Op::CzeroNez => ExecOut::ok(if s2 != 0 { 0 } else { s1 }),
        // Zbb — base integer bit manipulation
        Op::Andn => ExecOut::ok(s1 & !s2),
        Op::Orn => ExecOut::ok(s1 | !s2),
        Op::Xnor => ExecOut::ok(!s1 ^ s2),
        Op::Clz => ExecOut::ok(s1.leading_zeros() as u64),
        Op::Clzw => ExecOut::ok((s1 as u32).leading_zeros() as u64),
        Op::Ctz => ExecOut::ok(s1.trailing_zeros() as u64),
        Op::Ctzw => ExecOut::ok((s1 as u32).trailing_zeros() as u64),
        Op::Cpop => ExecOut::ok(s1.count_ones() as u64),
        Op::Cpopw => ExecOut::ok((s1 as u32).count_ones() as u64),
        Op::Max => ExecOut::ok((s1 as i64).max(s2 as i64) as u64),
        Op::Maxu => ExecOut::ok(s1.max(s2)),
        Op::Min => ExecOut::ok((s1 as i64).min(s2 as i64) as u64),
        Op::Minu => ExecOut::ok(s1.min(s2)),
        Op::OrcB => {
            let mut r = 0;
            for i in 0..8 {
                if s1 >> (i * 8) & 0xff != 0 {
                    r |= 0xff << (i * 8);
                }
            }
            ExecOut::ok(r)
        }
        Op::Rev8 => ExecOut::ok(s1.swap_bytes()),
        Op::Rol => ExecOut::ok(s1.rotate_left((s2 & 63) as u32)),
        Op::Rolw => ExecOut::ok((s1 as u32).rotate_left((s2 & 31) as u32) as i32 as u64),
        Op::Ror => ExecOut::ok(s1.rotate_right((s2 & 63) as u32)),
        Op::Rori => ExecOut::ok(s1.rotate_right((uop.imm & 63) as u32)),
        Op::Roriw => ExecOut::ok((s1 as u32).rotate_right((uop.imm & 31) as u32) as i32 as u64),
        Op::Rorw => ExecOut::ok((s1 as u32).rotate_right((s2 & 31) as u32) as i32 as u64),
        Op::SextB => ExecOut::ok(s1 as i8 as i64 as u64),
        Op::SextH => ExecOut::ok(s1 as i16 as i64 as u64),
        Op::ZextH => ExecOut::ok(s1 & 0xffff),
        // Zbs — single-bit instructions
        Op::Bclr => ExecOut::ok(s1 & !(1 << (s2 & 63))),
        Op::Bclri => ExecOut::ok(s1 & !(1u64 << (uop.imm & 63) as u32)),
        Op::Bext => ExecOut::ok((s1 >> (s2 & 63)) & 1),
        Op::Bexti => ExecOut::ok((s1 >> (uop.imm & 63) as u32) & 1),
        Op::Binv => ExecOut::ok(s1 ^ (1 << (s2 & 63))),
        Op::Binvi => ExecOut::ok(s1 ^ (1u64 << (uop.imm & 63) as u32)),
        Op::Bset => ExecOut::ok(s1 | (1 << (s2 & 63))),
        Op::Bseti => ExecOut::ok(s1 | (1u64 << (uop.imm & 63) as u32)),
        Op::Clmul => {
            let mut r = 0;
            for i in 0..64 {
                if (s2 >> i) & 1 == 1 {
                    r ^= s1 << i;
                }
            }
            ExecOut::ok(r)
        }
        Op::Clmulh => {
            let mut r = 0;
            for i in 1..64 {
                if (s2 >> i) & 1 == 1 {
                    r ^= s1 >> (64 - i);
                }
            }
            ExecOut::ok(r)
        }
        Op::Clmulr => {
            let mut r = 0;
            for i in 0..64 {
                if (s2 >> i) & 1 == 1 {
                    r ^= s1 >> (63 - i);
                }
            }
            ExecOut::ok(r)
        }
        // Zicboz — zero a 64-byte cache block (cache-block-aligned address in rs1)
        Op::CboZero => {
            // NOTE (cosim gating gap): not gated on menvcfg.CBZE.  A spec-correct
            // DUT traps cbo.zero (illegal instr) when CBZE is clear; we always
            // execute it.  Safe only because OpenSBI sets menvcfg before S-mode.
            // See MENVCFG_STCE in csr.rs.
            let base = s1 & !63;
            for i in 0..8u64 {
                etry!(cpu.memop_write(base, i * 8, 0, 8));
            }
            ExecOut::ok(0)
        }
        // V — every vector encoding funnels through one dispatcher, which
        // re-derives its operands from the instruction word kept in `imm`.
        Op::Vsetvli
        | Op::Vsetivli
        | Op::Vsetvl
        | Op::Vload8
        | Op::Vload16
        | Op::Vload32
        | Op::Vload64
        | Op::Vstore8
        | Op::Vstore16
        | Op::Vstore32
        | Op::Vstore64
        | Op::VopIvv
        | Op::VopFvv
        | Op::VopMvv
        | Op::VopIvi
        | Op::VopIvx
        | Op::VopFvf
        | Op::VopMvx => vector::execute(cpu, uop.op, uop.imm as u32, s1, s2),
        // End is the sentinel for unrecognised 32-bit instructions; CUnimp for compressed.
        // ---------------- Zabha: byte and halfword AMOs ----------------
        Op::AmoswapB => amo_narrow(cpu, s1, s2, 1, |_, s| s),
        Op::AmoaddB => amo_narrow(cpu, s1, s2, 1, u64::wrapping_add),
        Op::AmoxorB => amo_narrow(cpu, s1, s2, 1, |o, s| o ^ s),
        Op::AmoandB => amo_narrow(cpu, s1, s2, 1, |o, s| o & s),
        Op::AmoorB => amo_narrow(cpu, s1, s2, 1, |o, s| o | s),
        Op::AmominB => amo_narrow(cpu, s1, s2, 1, |o, s| amo_min_s(o, s, 1)),
        Op::AmomaxB => amo_narrow(cpu, s1, s2, 1, |o, s| amo_max_s(o, s, 1)),
        Op::AmominuB => amo_narrow(cpu, s1, s2, 1, |o, s| amo_min_u(o, s, 1)),
        Op::AmomaxuB => amo_narrow(cpu, s1, s2, 1, |o, s| amo_max_u(o, s, 1)),
        Op::AmoswapH => amo_narrow(cpu, s1, s2, 2, |_, s| s),
        Op::AmoaddH => amo_narrow(cpu, s1, s2, 2, u64::wrapping_add),
        Op::AmoxorH => amo_narrow(cpu, s1, s2, 2, |o, s| o ^ s),
        Op::AmoandH => amo_narrow(cpu, s1, s2, 2, |o, s| o & s),
        Op::AmoorH => amo_narrow(cpu, s1, s2, 2, |o, s| o | s),
        Op::AmominH => amo_narrow(cpu, s1, s2, 2, |o, s| amo_min_s(o, s, 2)),
        Op::AmomaxH => amo_narrow(cpu, s1, s2, 2, |o, s| amo_max_s(o, s, 2)),
        Op::AmominuH => amo_narrow(cpu, s1, s2, 2, |o, s| amo_min_u(o, s, 2)),
        Op::AmomaxuH => amo_narrow(cpu, s1, s2, 2, |o, s| amo_max_u(o, s, 2)),

        // ---------------- Zacas ----------------
        // s3 is rd read back as a source: for a CAS it supplies the comparand.
        Op::AmocasB => amo_cas(cpu, s1, s2, s3, 1),
        Op::AmocasH => amo_cas(cpu, s1, s2, s3, 2),
        Op::AmocasW => amo_cas(cpu, s1, s2, s3, 4),
        Op::AmocasD => amo_cas(cpu, s1, s2, s3, 8),
        Op::AmocasQ => {
            // rd and rs2 name even/odd register pairs; the uop's three source
            // slots cannot reach the odd halves, so the decoder passed the raw
            // register numbers through the immediate.
            let rd = (uop.imm & 31) as usize;
            let rs2 = ((uop.imm >> 8) & 31) as usize;
            // An x0 pair reads as zero and is never written back.
            let cmp_hi = if rd == 0 { 0 } else { cpu.rf[rd + 1] };
            let swap_hi = if rs2 == 0 { 0 } else { cpu.rf[rs2 + 1] };
            // amocas.q is 16-byte aligned, so both halves share a page: if the
            // first access translates, the second cannot fault part-way and
            // leave memory half-updated.
            let old_lo = etry!(cpu.memop_read(s1, 0, 8));
            let old_hi = etry!(cpu.memop_read(s1, 8, 8));
            if old_lo == s3 && old_hi == cmp_hi {
                etry!(cpu.memop_write(s1, 0, s2, 8));
                etry!(cpu.memop_write(s1, 8, swap_hi, 8));
            }
            cpu.reservation = None;
            if rd != 0 {
                cpu.rf[rd + 1] = old_hi;
            }
            ExecOut::ok(old_lo)
        }

        // ---------------- Zfa ----------------
        Op::FliS => {
            etry!(cpu.check_float_access_and_dirty(0));
            ExecOut::ok(fp::NAN_BOX_F32 | FLI_S[(uop.imm & 31) as usize])
        }
        Op::FliD => {
            etry!(cpu.check_float_access_and_dirty(0));
            ExecOut::ok(FLI_D[(uop.imm & 31) as usize])
        }
        // fminm/fmaxm differ from fmin/fmax only in NaN handling: any NaN
        // operand (not just two) yields the canonical NaN.
        Op::FminmS => {
            etry!(cpu.check_float_access_and_dirty(0));
            ExecOut::from_wf(minmax_m::<Sf32>(s1, s2, false))
        }
        Op::FmaxmS => {
            etry!(cpu.check_float_access_and_dirty(0));
            ExecOut::from_wf(minmax_m::<Sf32>(s1, s2, true))
        }
        Op::FminmD => {
            etry!(cpu.check_float_access_and_dirty(0));
            ExecOut::from_wf(minmax_m::<Sf64>(s1, s2, false))
        }
        Op::FmaxmD => {
            etry!(cpu.check_float_access_and_dirty(0));
            ExecOut::from_wf(minmax_m::<Sf64>(s1, s2, true))
        }
        // fleq/fltq are the quiet comparisons: unlike fle/flt they signal only
        // for a signalling NaN, not for any NaN.
        Op::FleqS => {
            etry!(cpu.check_float_access_and_dirty(0));
            ExecOut::from_wf(compare_q::<Sf32>(s1, s2, false))
        }
        Op::FltqS => {
            etry!(cpu.check_float_access_and_dirty(0));
            ExecOut::from_wf(compare_q::<Sf32>(s1, s2, true))
        }
        Op::FleqD => {
            etry!(cpu.check_float_access_and_dirty(0));
            ExecOut::from_wf(compare_q::<Sf64>(s1, s2, false))
        }
        Op::FltqD => {
            etry!(cpu.check_float_access_and_dirty(0));
            ExecOut::from_wf(compare_q::<Sf64>(s1, s2, true))
        }
        Op::FroundS => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(fround_s(s1, cpu.get_rm(uop.rm), false))
        }
        Op::FroundnxS => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(fround_s(s1, cpu.get_rm(uop.rm), true))
        }
        Op::FroundD => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(fround_d(s1, cpu.get_rm(uop.rm), false))
        }
        Op::FroundnxD => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(fround_d(s1, cpu.get_rm(uop.rm), true))
        }
        Op::FcvtmodWD => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(fcvtmod_w_d(s1))
        }

        // These RVA23 encodings are recognised by the decoder but never reach
        // execution: each is a shorter spelling of an instruction we already
        // have, so `new_decoder` rewrites it to that op (Zcb), or to a nop
        // (Zcmop, Zawrs) or a write of zero (Zimop).  Trapping keeps the
        // failure loud should one ever be constructed by mistake.
        Op::CLbu
        | Op::CLhu
        | Op::CLh
        | Op::CSb
        | Op::CSh
        | Op::CMul
        | Op::CZextB
        | Op::CSextB
        | Op::CZextH
        | Op::CSextH
        | Op::CZextW
        | Op::CNot
        | Op::CMop
        | Op::MopR
        | Op::MopRr
        | Op::WrsNto
        | Op::WrsSto => ExecOut::err(Trap::IllegalInstruction, 0),

        Op::End | Op::Unimp | Op::CUnimp => ExecOut::err(Trap::IllegalInstruction, 0),
    }
}

/// Sign-extend the low `size` bytes of `v` to 64 bits.
const fn sext_n(v: u64, size: u64) -> u64 {
    let sh = 64 - size * 8;
    ((v << sh) as i64 >> sh) as u64
}

/// Zero-extend (i.e. truncate to) the low `size` bytes of `v`.
const fn zext_n(v: u64, size: u64) -> u64 {
    let sh = 64 - size * 8;
    (v << sh) >> sh
}

const fn amo_min_s(a: u64, b: u64, size: u64) -> u64 {
    if (sext_n(a, size) as i64) < (sext_n(b, size) as i64) {
        a
    } else {
        b
    }
}
const fn amo_max_s(a: u64, b: u64, size: u64) -> u64 {
    if (sext_n(a, size) as i64) > (sext_n(b, size) as i64) {
        a
    } else {
        b
    }
}
const fn amo_min_u(a: u64, b: u64, size: u64) -> u64 {
    if zext_n(a, size) < zext_n(b, size) {
        a
    } else {
        b
    }
}
const fn amo_max_u(a: u64, b: u64, size: u64) -> u64 {
    if zext_n(a, size) > zext_n(b, size) {
        a
    } else {
        b
    }
}

/// A Zabha byte or halfword AMO.  Like the .w and .d forms, the value returned
/// in rd is the *original* memory contents, sign-extended to XLEN.
fn amo_narrow(
    cpu: &mut Cpu,
    addr: u64,
    src: u64,
    size: u64,
    f: impl FnOnce(u64, u64) -> u64,
) -> ExecOut {
    let old = etry!(cpu.memop_read(addr, 0, size));
    let new = f(old, src);
    etry!(cpu.memop_write(addr, 0, new, size));
    cpu.reservation = None;
    ExecOut::ok(sext_n(old, size))
}

/// A Zacas compare-and-swap of `size` bytes.  The store happens only on a
/// match, but rd is written with the original contents either way.
fn amo_cas(cpu: &mut Cpu, addr: u64, swap: u64, cmp: u64, size: u64) -> ExecOut {
    let old = etry!(cpu.memop_read(addr, 0, size));
    if old == zext_n(cmp, size) {
        etry!(cpu.memop_write(addr, 0, swap, size));
    }
    cpu.reservation = None;
    ExecOut::ok(sext_n(old, size))
}

/// Zfa fminm/fmaxm.  Identical to fmin/fmax except that a NaN in *either*
/// operand produces the canonical NaN rather than the other operand.
fn minmax_m<S: Sf>(a: u64, b: u64, want_max: bool) -> (u64, u8)
where
    <S as Sf>::F: PartialOrd,
{
    let (ua, ub) = (S::unbox(a), S::unbox(b));
    if S::is_nan(ua) || S::is_nan(ub) {
        let flags = if S::is_signan(ua) || S::is_signan(ub) {
            fp::fflag::INVALIDOP
        } else {
            0
        };
        return (S::qnan(), flags);
    }
    if want_max { S::max(a, b) } else { S::min(a, b) }
}

/// Zfa fleq/fltq: the quiet comparisons.  Only a signalling NaN raises the
/// invalid flag; a quiet NaN simply compares false.
fn compare_q<S: Sf>(a: u64, b: u64, less_than: bool) -> (u64, u8) {
    let (ua, ub) = (S::unbox(a), S::unbox(b));
    if S::is_nan(ua) || S::is_nan(ub) {
        let flags = if S::is_signan(ua) || S::is_signan(ub) {
            fp::fflag::INVALIDOP
        } else {
            0
        };
        return (0, flags);
    }
    // Neither operand is NaN, so the signalling comparison cannot raise and its
    // ordering logic can be reused verbatim.
    if less_than {
        S::flt(a, b)
    } else {
        S::fle(a, b)
    }
}

/// Shared body of fround/froundnx: round to an integral value *in the same
/// format*.  `nx` selects froundnx, which raises inexact when the value
/// actually changed; fround never does.
///
/// `integral_exp` is the biased exponent at and above which every value is
/// already an integer.  Returning those unchanged is not just an optimisation:
/// it keeps the round-trip through i64 below in range.
fn fround_generic<S: Sf>(
    a: u64,
    rm: RoundingMode,
    nx: bool,
    integral_exp: u64,
    to_int: fn(u64, RoundingMode) -> (u64, u8),
    from_int: fn(u64, RoundingMode) -> (u64, u8),
) -> (u64, u8) {
    let ua = S::unbox(a);
    if S::is_nan(ua) {
        let flags = if S::is_signan(ua) {
            fp::fflag::INVALIDOP
        } else {
            0
        };
        return (S::qnan(), flags);
    }
    if S::exp(ua) >= integral_exp {
        // Infinities land here too, and are likewise returned unchanged.
        return (S::nanbox(ua), 0);
    }
    let (i, _) = to_int(a, rm);
    let (r, _) = from_int(i, rm);
    // The round trip through an integer loses the sign of a zero result, but
    // fround(-0.3) must be -0.0, so restore it from the input.
    let r = if r & S::MASKSIGN == 0 {
        S::nanbox(ua & S::SIGN_MASK)
    } else {
        S::nanbox(r)
    };
    let flags = if nx && r != S::nanbox(ua) {
        fp::fflag::INEXACT
    } else {
        0
    };
    (r, flags)
}

fn fround_s(a: u64, rm: RoundingMode, nx: bool) -> (u64, u8) {
    // f32: bias 127, 23 mantissa bits.
    fround_generic::<Sf32>(a, rm, nx, 127 + 23, fp::cvt_sf32_i64, fp::cvt_i64_sf32)
}

fn fround_d(a: u64, rm: RoundingMode, nx: bool) -> (u64, u8) {
    // f64: bias 1023, 52 mantissa bits.
    fround_generic::<Sf64>(a, rm, nx, 1023 + 52, fp::cvt_sf64_i64, fp::cvt_i64_sf64)
}

/// Zfa fcvtmod.w.d: truncate toward zero, then take the result modulo 2^32 and
/// sign-extend, instead of saturating the way fcvt.w.d does.  (This is exactly
/// JavaScript's `ToInt32`.)  The rounding mode is architecturally fixed at rtz.
///
/// NaN and infinity produce zero and raise invalid; everything else wraps
/// silently, raising only inexact when a fractional part was discarded.
// The truncating casts below are the point of the instruction, not an
// oversight: taking the value modulo 2^32 is exactly a truncation to u32.  The
// exponent cast is likewise safe, as it holds an 11-bit field.
#[allow(clippy::cast_possible_truncation)]
fn fcvtmod_w_d(a: u64) -> (u64, u8) {
    if Sf64::exp(a) == Sf64::EXP_MASK {
        // NaN or infinity.
        return (0, fp::fflag::INVALIDOP);
    }
    let exp = Sf64::exp(a);
    let mant = Sf64::mant(a);
    let negative = Sf64::sign(a) != 0;

    // Subnormals and zero: magnitude below 1, so the integral part is zero.
    if exp == 0 {
        return (0, if mant == 0 { 0 } else { fp::fflag::INEXACT });
    }
    let significand = mant | (1 << 52);
    // Value is significand * 2^(exp - 1023 - 52).
    let shift = i64::from(exp as i32 - 1023 - 52);

    let (low32, inexact) = if shift >= 0 {
        // Already an integer.  Anything shifted past bit 31 vanishes mod 2^32.
        let v = if shift >= 32 {
            0
        } else {
            (significand << shift) as u32
        };
        (v, false)
    } else {
        let rshift = -shift;
        if rshift >= 64 {
            // Magnitude below 1.
            (0, significand != 0)
        } else {
            let dropped = significand & ((1u64 << rshift) - 1);
            ((significand >> rshift) as u32, dropped != 0)
        }
    };

    let wrapped = if negative {
        low32.wrapping_neg()
    } else {
        low32
    };
    let flags = if inexact { fp::fflag::INEXACT } else { 0 };
    // Sign-extend the 32-bit result into the destination register.
    (i64::from(wrapped as i32) as u64, flags)
}

/// The 32 constants selectable by Zfa's fli, in encoding order.
const FLI_D: [u64; 32] = [
    0xbff0_0000_0000_0000, //  0  -1.0
    0x0010_0000_0000_0000, //  1  minimum positive normal
    0x3ef0_0000_0000_0000, //  2  2^-16
    0x3f00_0000_0000_0000, //  3  2^-15
    0x3f70_0000_0000_0000, //  4  2^-8
    0x3f80_0000_0000_0000, //  5  2^-7
    0x3fb0_0000_0000_0000, //  6  0.0625
    0x3fc0_0000_0000_0000, //  7  0.125
    0x3fd0_0000_0000_0000, //  8  0.25
    0x3fd4_0000_0000_0000, //  9  0.3125
    0x3fd8_0000_0000_0000, // 10  0.375
    0x3fdc_0000_0000_0000, // 11  0.4375
    0x3fe0_0000_0000_0000, // 12  0.5
    0x3fe4_0000_0000_0000, // 13  0.625
    0x3fe8_0000_0000_0000, // 14  0.75
    0x3fec_0000_0000_0000, // 15  0.875
    0x3ff0_0000_0000_0000, // 16  1.0
    0x3ff4_0000_0000_0000, // 17  1.25
    0x3ff8_0000_0000_0000, // 18  1.5
    0x3ffc_0000_0000_0000, // 19  1.75
    0x4000_0000_0000_0000, // 20  2.0
    0x4004_0000_0000_0000, // 21  2.5
    0x4008_0000_0000_0000, // 22  3.0
    0x4010_0000_0000_0000, // 23  4.0
    0x4020_0000_0000_0000, // 24  8.0
    0x4030_0000_0000_0000, // 25  16.0
    0x4060_0000_0000_0000, // 26  128.0
    0x4070_0000_0000_0000, // 27  256.0
    0x40e0_0000_0000_0000, // 28  32768.0
    0x40f0_0000_0000_0000, // 29  65536.0
    0x7ff0_0000_0000_0000, // 30  +inf
    0x7ff8_0000_0000_0000, // 31  canonical NaN
];

const FLI_S: [u64; 32] = [
    0xbf80_0000, //  0  -1.0
    0x0080_0000, //  1  minimum positive normal
    0x3780_0000, //  2  2^-16
    0x3800_0000, //  3  2^-15
    0x3b80_0000, //  4  2^-8
    0x3c00_0000, //  5  2^-7
    0x3d80_0000, //  6  0.0625
    0x3e00_0000, //  7  0.125
    0x3e80_0000, //  8  0.25
    0x3ea0_0000, //  9  0.3125
    0x3ec0_0000, // 10  0.375
    0x3ee0_0000, // 11  0.4375
    0x3f00_0000, // 12  0.5
    0x3f20_0000, // 13  0.625
    0x3f40_0000, // 14  0.75
    0x3f60_0000, // 15  0.875
    0x3f80_0000, // 16  1.0
    0x3fa0_0000, // 17  1.25
    0x3fc0_0000, // 18  1.5
    0x3fe0_0000, // 19  1.75
    0x4000_0000, // 20  2.0
    0x4020_0000, // 21  2.5
    0x4040_0000, // 22  3.0
    0x4080_0000, // 23  4.0
    0x4100_0000, // 24  8.0
    0x4180_0000, // 25  16.0
    0x4300_0000, // 26  128.0
    0x4380_0000, // 27  256.0
    0x4700_0000, // 28  32768.0
    0x4780_0000, // 29  65536.0
    0x7f80_0000, // 30  +inf
    0x7fc0_0000, // 31  canonical NaN
];

#[cfg(test)]
mod test_cpu {
    use super::*;
    use crate::mmu::Mmu;
    use crate::serial_backend::DummySerialBackend;

    // Primary RAM base — matches the address used in Emulator::new.
    const MEMORY_BASE: u64 = 0x8000_0000;

    fn create_cpu() -> Cpu {
        let mut mmu = Mmu::new();
        mmu.add_memory(MEMORY_BASE, 8 * 1024 * 1024);
        mmu.attach_uart(Box::new(DummySerialBackend::new()));
        Cpu::new(mmu)
    }

    #[test]
    fn initialize() { let _cpu = create_cpu(); }

    #[test]
    fn decode_fcvt_xf_preserves_rounding_mode() {
        let uop = decode(MEMORY_BASE, 0xc010_1053, false);
        assert_eq!(uop.op, Op::FcvtWuS);
        assert_eq!(uop.rm, RoundingMode::RoundTowardsZero as u8);
    }

    #[test]
    fn update_pc() {
        let mut cpu = create_cpu();
        assert_eq!(0, cpu.read_pc());
        cpu.update_pc(1);
        assert_eq!(0, cpu.read_pc());
        cpu.update_pc(0xffffffffffffffff);
        assert_eq!(0xfffffffffffffffe, cpu.read_pc());
    }

    #[test]
    #[allow(clippy::match_wild_err_arm)]
    fn tick() {
        let mut cpu = create_cpu();
        cpu.update_pc(MEMORY_BASE);

        // Write non-compressed "addi x1, x1, 1" instruction
        match cpu.get_mut_mmu().store_virt_u32(MEMORY_BASE, 0x00108093) {
            Ok(()) => {}
            Err(_e) => panic!("Failed to store"),
        }
        // Write compressed "addi x8, x0, 8" instruction
        match cpu.get_mut_mmu().store_virt_u32(MEMORY_BASE + 4, 0x20) {
            Ok(()) => {}
            Err(_e) => panic!("Failed to store"),
        }

        // Use step_single for precise single-instruction execution.
        if let Err(exc) = cpu.step_single() {
            cpu.handle_exception(&exc, MEMORY_BASE);
        }

        assert_eq!(MEMORY_BASE + 4, cpu.read_pc());
        assert_eq!(1, cpu.read_register(x(1)));

        if let Err(exc) = cpu.step_single() {
            cpu.handle_exception(&exc, MEMORY_BASE + 4);
        }

        assert_eq!(MEMORY_BASE + 6, cpu.read_pc());
        assert_eq!(8, cpu.read_register(x(8)));
    }

    /// Assemble-verified encodings used by the vector tests below.
    const VSETVLI_T0_A0_E32M2: u32 = 0x0d15_72d7; // vsetvli t0, a0, e32, m2, ta, ma
    const VADD_VV_V4_V8_V12: u32 = 0x0286_0257; // vadd.vv v4, v8, v12
    const VLE32_V0_A1: u32 = 0x0205_e007; // vle32.v v0, (a1)

    fn vector_cpu() -> Cpu {
        let mut cpu = create_cpu();
        cpu.set_rva23_enabled(true);
        cpu
    }

    /// Run one instruction at `MEMORY_BASE`.
    fn run_one(cpu: &mut Cpu, insn: u32) -> Result<(), Exception> {
        cpu.get_mut_mmu()
            .store_virt_u32(MEMORY_BASE, insn)
            .expect("store instruction");
        cpu.update_pc(MEMORY_BASE);
        cpu.step_single()
    }

    #[test]
    fn vector_decoding_is_gated_by_the_runtime_flag() {
        // Without V every vector encoding is an unknown instruction...
        for insn in [VSETVLI_T0_A0_E32M2, VADD_VV_V4_V8_V12, VLE32_V0_A1] {
            assert_eq!(
                decode(MEMORY_BASE, insn, false).op,
                Op::Unimp,
                "{insn:08x} must not decode without -V"
            );
        }
        // ...and with it they decode into their encoding groups.
        assert_eq!(
            decode(MEMORY_BASE, VSETVLI_T0_A0_E32M2, true).op,
            Op::Vsetvli
        );
        assert_eq!(decode(MEMORY_BASE, VADD_VV_V4_V8_V12, true).op, Op::VopIvv);
        assert_eq!(decode(MEMORY_BASE, VLE32_V0_A1, true).op, Op::Vload32);

        // A gated-off vector instruction traps rather than executing.
        let mut cpu = create_cpu();
        assert_eq!(
            run_one(&mut cpu, VADD_VV_V4_V8_V12).unwrap_err().trap,
            Trap::IllegalInstruction
        );
    }

    /// The rest of the RVA23 profile rides on the same switch as V, and the Zcb
    /// members in particular must decode to the plain instruction they
    /// abbreviate.
    #[test]
    fn rva23_encodings_are_gated_and_alias_correctly() {
        // c.zext.w a4 -- the instruction that aborted the RVA23 Ubuntu userland
        // before Zcb was implemented.
        const C_ZEXT_W_A4: u32 = 0x9f71;
        const C_NOT_A4: u32 = 0x9f75;
        const C_MUL_S0_S1: u32 = 0x9c45;
        const C_LBU_S0_S1: u32 = 0x8080;
        const C_MOP_1: u32 = 0x6081;
        const MOP_R_0: u32 = 0x81c0_4073;
        const WRS_NTO: u32 = 0x00d0_0073;
        const AMOCAS_W: u32 = 0x2800_202f;
        const AMOADD_B: u32 = 0x0000_002f;
        const FLI_D_1P0: u32 = 0xf218_0053;

        for insn in [
            C_ZEXT_W_A4,
            C_NOT_A4,
            C_MUL_S0_S1,
            C_LBU_S0_S1,
            C_MOP_1,
            MOP_R_0,
            WRS_NTO,
            AMOCAS_W,
            AMOADD_B,
            FLI_D_1P0,
        ] {
            assert_eq!(
                decode(MEMORY_BASE, insn, false).op,
                Op::Unimp,
                "{insn:08x} must not decode without --rva23"
            );
        }

        // Zcb aliases: same op, and the same register named as both source and
        // destination.
        let uop = decode(MEMORY_BASE, C_ZEXT_W_A4, true);
        assert_eq!(uop.op, Op::AddUw, "c.zext.w is add.uw rd, rd, x0");
        assert_eq!(uop.rs1, x(14), "c.zext.w a4 reads a4");
        assert_eq!(uop.rs2, ZEROREG, "c.zext.w must add zero");
        assert_eq!(uop.get_insn_size(), 2, "still a 16-bit instruction");

        let uop = decode(MEMORY_BASE, C_NOT_A4, true);
        assert_eq!(uop.op, Op::Xori);
        assert_eq!(uop.imm, -1, "c.not is xori rd, rd, -1");

        assert_eq!(decode(MEMORY_BASE, C_MUL_S0_S1, true).op, Op::Mul);
        let uop = decode(MEMORY_BASE, C_LBU_S0_S1, true);
        assert_eq!(uop.op, Op::Lbu);
        assert_eq!(uop.rs1, x(9), "base register is s1");
        assert_eq!(uop.imm, 0);

        // Zcmop and Zawrs retire as nops; Zimop writes zero to a real rd.
        assert_eq!(decode(MEMORY_BASE, C_MOP_1, true).op, Op::CNop);
        assert_eq!(decode(MEMORY_BASE, WRS_NTO, true).op, Op::CNop);
        let uop = decode(MEMORY_BASE, MOP_R_0, true);
        assert_eq!(uop.op, Op::CNop);
        assert!(uop.rd.is_x0_dest(), "mop.r.0 x0, x0 writes nothing");

        assert_eq!(decode(MEMORY_BASE, AMOCAS_W, true).op, Op::AmocasW);
        assert_eq!(decode(MEMORY_BASE, AMOADD_B, true).op, Op::AmoaddB);
        let uop = decode(MEMORY_BASE, FLI_D_1P0, true);
        assert_eq!(uop.op, Op::FliD);
        assert_eq!(FLI_D[uop.imm as usize], 1.0f64.to_bits(), "fli.d index 16");
    }

    /// A c.zext.w must actually clear the high half, and Zimop must land a
    /// zero.
    #[test]
    fn rva23_executes() {
        let mut cpu = vector_cpu();
        cpu.write_register(x(14), 0xdead_beef_0000_00ff);
        run_one(&mut cpu, 0x9f71).expect("c.zext.w a4");
        assert_eq!(cpu.read_register(x(14)), 0x0000_00ff);

        // mop.r.0 a0, a0 -- rd is written with zero whatever the source held.
        cpu.write_register(x(10), 0x1234);
        run_one(&mut cpu, 0x81c0_4073 | (10 << 7) | (10 << 15)).expect("mop.r.0");
        assert_eq!(cpu.read_register(x(10)), 0);
    }

    #[test]
    fn vsetvli_clamps_avl_to_vlmax() {
        let mut cpu = vector_cpu();
        // e32/m2 over VLEN=128 holds 2 * 128/32 = 8 elements, so an AVL of 100
        // is clamped and the written vtype reads back verbatim.
        cpu.write_register(x(10), 100);
        run_one(&mut cpu, VSETVLI_T0_A0_E32M2).expect("vsetvli");
        assert_eq!(cpu.v.vl, 8);
        assert_eq!(cpu.v.vtype, 0xd1);
        assert_eq!(cpu.read_register(x(5)), 8, "vsetvli writes vl to rd");
        assert_eq!(cpu.vs, 3, "a vector instruction dirties mstatus.VS");

        // An AVL below VLMAX is taken as-is.
        cpu.write_register(x(10), 3);
        run_one(&mut cpu, VSETVLI_T0_A0_E32M2).expect("vsetvli");
        assert_eq!(cpu.v.vl, 3);
    }

    #[test]
    fn vadd_vv_respects_vl_and_leaves_the_tail_alone() {
        let mut cpu = vector_cpu();
        cpu.write_register(x(10), 3);
        run_one(&mut cpu, VSETVLI_T0_A0_E32M2).expect("vsetvli");
        assert_eq!(cpu.v.vl, 3);

        for i in 0..8 {
            cpu.v.eset(8, i, 4, 100 + i as u64);
            cpu.v.eset(12, i, 4, 1000 * (i as u64 + 1));
            cpu.v.eset(4, i, 4, 0xdead_beef);
        }
        run_one(&mut cpu, VADD_VV_V4_V8_V12).expect("vadd.vv");

        for i in 0..3 {
            assert_eq!(
                cpu.v.eget(4, i, 4),
                100 + i as u64 + 1000 * (i as u64 + 1),
                "element {i}"
            );
        }
        for i in 3..8 {
            assert_eq!(cpu.v.eget(4, i, 4), 0xdead_beef, "tail element {i}");
        }
    }

    #[test]
    fn vle32_loads_vl_elements_from_memory() {
        let mut cpu = vector_cpu();
        cpu.write_register(x(10), 4);
        run_one(&mut cpu, VSETVLI_T0_A0_E32M2).expect("vsetvli");

        let data = MEMORY_BASE + 0x1000;
        for i in 0..4u64 {
            cpu.get_mut_mmu()
                .store_virt_u32(data + i * 4, 0x1000_0000 + i as u32)
                .expect("store");
        }
        cpu.write_register(x(11), data);
        for i in 0..4 {
            cpu.v.eset(0, i, 4, 0);
        }
        run_one(&mut cpu, VLE32_V0_A1).expect("vle32.v");
        for i in 0..4u64 {
            assert_eq!(cpu.v.eget(0, i as usize, 4), 0x1000_0000 + i);
        }
    }

    #[test]
    fn vector_csrs_are_unreachable_without_the_extension() {
        // csrr t0, vlenb  ==  csrrs t0, 0xc22, x0
        let read_vlenb: u32 = 0xc220_22f3;
        let mut cpu = create_cpu();
        assert_eq!(
            run_one(&mut cpu, read_vlenb).unwrap_err().trap,
            Trap::IllegalInstruction,
            "vlenb must not be readable without V"
        );

        let mut cpu = vector_cpu();
        run_one(&mut cpu, read_vlenb).expect("vlenb readable with V");
        assert_eq!(cpu.read_register(x(5)), crate::vector::VLENB as u64);
    }

    #[test]
    fn smstateen_gates_senvcfg_below_machine_mode() {
        // csrr t0, senvcfg  ==  csrrs t0, 0x10a, x0
        let read_senvcfg: u32 = 0x10a0_22f3;

        // M-mode is never gated, whatever mstateen0 says.
        let mut cpu = create_cpu();
        cpu.csr.mstateen0 = 0;
        run_one(&mut cpu, read_senvcfg).expect("M-mode access is not gated");

        // Below M-mode the ENVCFG bit decides.  Default is permissive.
        let mut cpu = create_cpu();
        cpu.mmu.update_priv_mode(PrivMode::S);
        run_one(&mut cpu, read_senvcfg).expect("senvcfg readable while ENVCFG is set");

        cpu.csr.mstateen0 &= !crate::csr::MSTATEEN0_ENVCFG;
        assert_eq!(
            run_one(&mut cpu, read_senvcfg).unwrap_err().trap,
            Trap::IllegalInstruction,
            "clearing mstateen0.ENVCFG must deny S-mode access to senvcfg"
        );

        // Writes go through the same gate.
        // csrw senvcfg, t0  ==  csrrw x0, 0x10a, t0
        let write_senvcfg: u32 = 0x10a2_9073;
        assert_eq!(
            run_one(&mut cpu, write_senvcfg).unwrap_err().trap,
            Trap::IllegalInstruction,
            "the gate must apply to writes too"
        );
    }

    #[test]
    fn fp_load_dirties_fs_only_on_success() {
        // Regression for 44f628f: a page-faulting FP load writes no f-reg, so it must
        // NOT dirty mstatus.FS; a successful FP load does. (Pre-fix,
        // check_float_access_and_dirty set fs=3 BEFORE memop_read, so even a
        // FAULTING load dirtied FS -> diverged from the cosim DUT on the
        // kernel's sstatus read.) Encoding: FLD f0, 0(x1) = 0x0000_b007.

        // faulting: an address past the end of RAM makes memop_read return a
        // LoadAccessFault before any f-reg write. (create_cpu maps 8 MiB at
        // MEMORY_BASE.)
        let mut cpu = create_cpu();
        cpu.fs = 1; // FP enabled, Initial (not Dirty)
        cpu.write_register(x(1), MEMORY_BASE + 8 * 1024 * 1024); // first byte past RAM -> fault
        cpu.get_mut_mmu()
            .store_virt_u32(MEMORY_BASE, 0x0000_b007)
            .expect("store FLD");
        cpu.update_pc(MEMORY_BASE);
        assert!(
            cpu.step_single().is_err(),
            "load past end of RAM should fault"
        );
        assert_eq!(cpu.fs, 1, "a faulting FP load must NOT dirty mstatus.FS");

        // success: an aligned in-range address completes the load -> FS goes Dirty.
        let mut cpu = create_cpu();
        cpu.fs = 1;
        cpu.write_register(x(1), MEMORY_BASE + 0x40);
        cpu.get_mut_mmu()
            .store_virt_u32(MEMORY_BASE, 0x0000_b007)
            .expect("store FLD");
        cpu.update_pc(MEMORY_BASE);
        assert!(cpu.step_single().is_ok(), "aligned FLD should succeed");
        assert_eq!(cpu.fs, 3, "a successful FP load dirties mstatus.FS");
    }

    #[test]
    #[allow(clippy::match_wild_err_arm)]
    fn step_single() {
        let mut cpu = create_cpu();
        cpu.update_pc(MEMORY_BASE);
        // write non-compressed "addi a0, a0, 12" instruction
        match cpu.get_mut_mmu().store_virt_u32(MEMORY_BASE, 0xc50513) {
            Ok(()) => {}
            Err(_e) => panic!("Failed to store"),
        }
        assert_eq!(MEMORY_BASE, cpu.read_pc());
        assert_eq!(0, cpu.read_register(x(10)));
        if let Err(exc) = cpu.step_single() {
            cpu.handle_exception(&exc, MEMORY_BASE);
        }
        assert_eq!(MEMORY_BASE + 4, cpu.read_pc());
        // "addi a0, a0, a12" instruction writes 12 to a0 register.
        assert_eq!(12, cpu.read_register(x(10)));
    }

    #[test]
    #[allow(clippy::match_wild_err_arm)]
    fn interrupt() {
        let mut bb = BbCache::new(256, crate::uop_cache::CacheMode::Direct);
        let handler_vector = 0x10000000;
        let mut cpu = create_cpu();
        // Write non-compressed "addi x0, x0, 1" instruction
        match cpu.get_mut_mmu().store_virt_u32(MEMORY_BASE, 0x00100013) {
            Ok(()) => {}
            Err(_e) => panic!("Failed to store"),
        }
        cpu.update_pc(MEMORY_BASE);

        // Machine timer interrupt but mie in mstatus is not enabled yet
        cpu.csr.mie = MIP_MTIP;
        cpu.mmu.mip |= MIP_MTIP;
        cpu.write_csr_raw(Csr::Mtvec, handler_vector);

        cpu.run_soc(1, &mut bb);

        // Interrupt isn't caught because mie is disabled
        assert_eq!(MEMORY_BASE + 4, cpu.read_pc());

        cpu.update_pc(MEMORY_BASE);
        // Enable mie in mstatus
        cpu.write_csr_raw(Csr::Mstatus, 0x8);

        cpu.run_soc(1, &mut bb);

        // Interrupt happened and moved to handler
        assert_eq!(handler_vector, cpu.read_pc());

        // CSR Cause register holds the reason what caused the interrupt
        assert_eq!(0x8000000000000007, cpu.read_csr_raw(Csr::Mcause));
        assert_eq!(0, cpu.read_csr_raw(Csr::Mtval));

        // @TODO: Test post CSR status register
        // @TODO: Test xIE bit in CSR status register
        // @TODO: Test privilege levels
        // @TODO: Test delegation
        // @TODO: Test vector type handlers
    }

    #[test]
    #[allow(clippy::match_wild_err_arm)]
    fn exception() {
        let mut bb = BbCache::new(256, crate::uop_cache::CacheMode::Direct);
        let handler_vector = 0x10000000;
        let mut cpu = create_cpu();
        // Write ECALL instruction
        match cpu.get_mut_mmu().store_virt_u32(MEMORY_BASE, 0x00000073) {
            Ok(()) => {}
            Err(_e) => panic!("Failed to store"),
        }
        cpu.write_csr_raw(Csr::Mtvec, handler_vector);
        cpu.update_pc(MEMORY_BASE);

        cpu.run_soc(1, &mut bb);

        // Interrupt happened and moved to handler
        assert_eq!(handler_vector, cpu.read_pc());

        // CSR Cause register holds the reason what caused the trap
        assert_eq!(0xb, cpu.read_csr_raw(Csr::Mcause));

        // @TODO: Test post CSR status register
        // @TODO: Test privilege levels
        // @TODO: Test delegation
        // @TODO: Test vector type handlers
    }

    #[test]
    #[allow(clippy::match_wild_err_arm)]
    fn hardocded_zero() {
        let mut cpu = create_cpu();
        cpu.update_pc(MEMORY_BASE);

        // Write non-compressed "addi x0, x0, 1" instruction
        match cpu.get_mut_mmu().store_virt_u32(MEMORY_BASE, 0x00100013) {
            Ok(()) => {}
            Err(_e) => panic!("Failed to store"),
        }
        // Write non-compressed "addi x1, x1, 1" instruction
        match cpu
            .get_mut_mmu()
            .store_virt_u32(MEMORY_BASE + 4, 0x00108093)
        {
            Ok(()) => {}
            Err(_e) => panic!("Failed to store"),
        }

        // Test x0
        assert_eq!(0, cpu.read_register(x(0)));
        if let Err(exc) = cpu.step_single() {
            cpu.handle_exception(&exc, MEMORY_BASE);
        }
        // x0 is still zero because it's hardcoded zero
        assert_eq!(0, cpu.read_register(x(0)));

        // Test x1
        assert_eq!(0, cpu.read_register(x(1)));
        if let Err(exc) = cpu.step_single() {
            cpu.handle_exception(&exc, MEMORY_BASE + 4);
        }
        // x1 is not hardcoded zero
        assert_eq!(1, cpu.read_register(x(1)));
    }
}
#[cfg(test)]
mod size_check2 {
    use super::*;
    #[test]
    fn uop_size() {
        assert_eq!(std::mem::size_of::<Uop>(), 12, "Uop should be 12 bytes");
    }
}
