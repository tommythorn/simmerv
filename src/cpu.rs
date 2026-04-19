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
use crate::fp::fflag::DIVIDEZERO;
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
pub use csr::*;
use fp::RoundingMode;
use fp::Sf;
use fp::Sf16;
use fp::Sf32;
use fp::Sf64;
use fp::cvt_i32_sf32;
use fp::cvt_i64_sf32;
use fp::cvt_u32_sf32;
use fp::cvt_u64_sf32;
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
/// No sret pointer needed. `flags == 0`: ok; `0 < flags < 2^63`: ok with
/// fflags (`flags & 0xFF`); bit 63 set: exception (`val`=tval,
/// `bits[15:8]`=Trap).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecOut {
    pub val: u64,
    pub flags: u64,
}

const EXCEPTION_BIT: u64 = 0x8000_0000_0000_0000;

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
    #[inline(always)]
    #[must_use]
    pub const fn is_err(self) -> bool { self.flags & EXCEPTION_BIT != 0 }
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
pub struct Cpu {
    // The essential CPU state
    rf: [u64; 65],
    pub pc: u64,

    // This is fcsr disaggregated
    pub frm: RoundingMode,
    pub fflags: u8,
    pub fs: u8,

    // Supervisor and CSR
    pub cycle: u64,
    csr: csr::CsrFile,
    reservation: Option<u64>,

    // Wait-For-Interrupt; relax and await further instruction
    // XXX needn't be part of CPU state; is part of fetch
    wfi: bool,

    // Skip the interrupt check for exactly one retire. Set by xRET so the
    // MRET/SRET-target instruction retires before any newly-enabled pending
    // interrupt fires. Matches smolrv64's interrupt-acceptance timing.
    defer_interrupt: bool,

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

            seqno: 0,
            cycle: 0,
            wfi: false,
            defer_interrupt: false,
            pc: 0,
            csr: CsrFile::new(),
            mmu,
            reservation: None,
            icache_flush: IcacheFlushKind::None,
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
        self.wfi = false;
        self.pc = 0x8000_0000;
        self.csr = CsrFile::new();
        self.reservation = None;
        self.icache_flush = IcacheFlushKind::Full;
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

    /// Checks that float instructions are enabled and
    /// that the rounding mode is legal; dirty the FP state
    fn check_float_access_and_dirty(&mut self, rm: u8) -> Result<(), Exception> {
        self.check_float_access_ro(rm)?;
        self.fs = 3;
        native_fp::fflags_clear();
        // XXX set native rounding mode
        Ok(())
    }

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
            for uop in &cached_block.uops {
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

                if self.pc != expected_next {
                    // PC deviated — taken branch or jump, exit early.
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

        // ── Cache miss: build basic block ─────────────────────────────────
        let page_end = (block_start & !0xFFF) + 0x1000;
        let mut block = BasicBlock::default();
        let mut fetch_pc = block_start;
        let mut i = 0usize;

        loop {
            if i >= MAX_BLOCK_LEN {
                break;
            }

            // Page boundary check (skip for i == 0).
            if i > 0 && fetch_pc >= page_end {
                break;
            }

            // Fetch instruction (4 bytes; actual size determined after decode).
            let insn_result = self.memop_code(fetch_pc);
            let insn = match insn_result {
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

            let uop = decode(fetch_pc, insn);

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

            block.uops[i] = uop;
            i += 1;
            fetch_pc += insn_size;

            if Self::is_block_terminal(uop.op, uop.imm) {
                break;
            }
        }

        // ── Execute the freshly-decoded block ─────────────────────────────
        let mut n_executed: u32 = 0;
        let mut exception: Option<(Exception, u64)> = None;
        for uop in block.uops {
            if uop.op == Op::End {
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
                exception = Some((out.to_exception(), cur_insn_addr));
                break;
            }
            self.write_x(uop.rd, out.val);
            let ff = out.fflags();
            if ff != 0 {
                self.add_to_fflags(ff);
            }
            n_executed += 1;

            if self.pc != expected_next {
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
        let uop = decode(insn_addr, insn);
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
        // xRET defers interrupt acceptance by one retire (matches smolrv64).
        if self.defer_interrupt {
            self.defer_interrupt = false;
        } else {
            self.handle_interrupt();
        }
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
        let uop = decode(insn_addr, insn);
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
            let exc = result.to_exception();
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
        ] {
            let trap = Exception {
                trap: trap_type,
                tval: self.pc,
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

        let new_priv_mode = if (mdeleg >> pos) & 1 == 0 {
            PrivMode::M
        } else if (sdeleg >> pos) & 1 == 0 {
            PrivMode::S
        } else {
            PrivMode::U
        };

        if is_interrupt {
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
        self.write_csr_raw(csr_tval_address, exc.tval);

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
    fn read_csr(&self, csrno: u16) -> Result<u64, Exception> {
        use PrivMode::S;

        let illegal = Err(Exception {
            trap: Trap::IllegalInstruction,
            tval: 0,
        });

        // PMP: pmpcfg0-15 (0x3A0-0x3AF) and pmpaddr0-63 (0x3B0-0x3EF) — M-mode only,
        // hardwired to zero (0 PMP entries implemented).
        if matches!(csrno, 0x3A0..=0x3EF) {
            if u64::from(self.mmu.prv) < 3 {
                return illegal;
            }
            return Ok(0);
        }

        // Zihpm: hpmcounter3-31 (0xC03-0xC1F, U-mode), mhpmcounter3-31 (0xB03-0xB1F,
        // M-mode), mhpmevent3-31 (0x323-0x33F, M-mode) — all return 0.
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
            return Ok(0);
        }
        if matches!(csrno, 0xB03..=0xB1F | 0x323..=0x33F) {
            if u64::from(self.mmu.prv) < 3 {
                return illegal;
            }
            return Ok(0);
        }

        let Some(csr) = self.has_csr_access_privilege(csrno) else {
            return illegal;
        };

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
        Ok(self.read_csr_raw(csr))
    }

    #[allow(clippy::cast_sign_loss)]
    fn write_csr(&mut self, csrno: u16, value: u64) -> Result<(), Exception> {
        let illegal = Err(Exception {
            trap: Trap::IllegalInstruction,
            tval: 0,
        });

        // PMP: pmpcfg0-15 and pmpaddr0-63 — M-mode only, writes silently ignored
        // (0 PMP entries implemented; all accesses permitted).
        if matches!(csrno, 0x3A0..=0x3EF) {
            return if u64::from(self.mmu.prv) < 3 {
                illegal
            } else {
                Ok(())
            };
        }

        // Zihpm: hpmcounter3-31 are read-only; mhpmcounter/mhpmevent writes are
        // silently ignored.
        if matches!(csrno, 0xC03..=0xC1F) {
            return illegal; // read-only
        }
        if matches!(csrno, 0xB03..=0xB1F | 0x323..=0x33F) {
            return if u64::from(self.mmu.prv) < 3 {
                illegal
            } else {
                Ok(())
            };
        }

        let Some(csr) = self.has_csr_access_privilege(csrno) else {
            return illegal;
        };

        if (csrno >> 10) & 3 == 3 {
            log::warn!("Write attempted to Read Only CSR {csrno:03x}");
            return illegal;
        }

        match csr {
            Csr::Fflags | Csr::Frm | Csr::Fcsr => self.check_float_access_and_dirty(0)?,
            Csr::Cycle => {
                log::info!("** deny cycle writing");
                return illegal;
            }
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

                if !matches!(
                    FromPrimitive::from_u64((value >> SATP_MODE_SHIFT) & SATP_MODE_MASK),
                    Some(SatpMode::Bare | SatpMode::Sv39)
                ) {
                    // WARL: silently ignore writes with unsupported modes
                    return Ok(());
                }

                let old_satp = self.mmu.satp;
                self.mmu.satp = value;
                // Only flush TLBs if MODE or PPN changed (not on ASID-only changes)
                let mode_ppn_mask = !((SATP_ASID_MASK) << SATP_ASID_SHIFT);
                if (old_satp & mode_ppn_mask) != (value & mode_ppn_mask) {
                    self.mmu.flush_tlb();
                    self.icache_flush = IcacheFlushKind::Full;
                }
                return Ok(());
            }
            _ => {}
        }

        self.write_csr_raw(csr, value);
        if matches!(csr, Csr::Sstatus | Csr::Sie | Csr::Mstatus | Csr::Mie) {
            self.handle_interrupt();
        }
        Ok(())
    }

    // SSTATUS, SIE, and SIP are subsets of MSTATUS, MIE, and MIP
    #[allow(clippy::cast_sign_loss)]
    fn read_csr_raw(&self, csr: Csr) -> u64 {
        match csr {
            Csr::Cycle | Csr::Mcycle | Csr::Minstret => self.cycle,
            Csr::Fcsr => self.read_fcsr(),
            Csr::Fflags => u64::from(self.read_fflags()),
            Csr::Frm => self.read_frm() as u64,
            Csr::Mcause => self.csr.mcause,
            Csr::Medeleg => self.csr.medeleg,
            Csr::Mepc => self.csr.mepc,
            Csr::Mhartid => self.csr.mhartid,
            Csr::Mideleg => self.csr.mideleg,
            Csr::Mie => self.csr.mie,
            Csr::Mip => self.mmu.mip,
            Csr::Misa => self.csr.misa,
            Csr::Mscratch => self.csr.mscratch,
            Csr::Mstatus => {
                let mut mstatus = self.mmu.mstatus & !(1u64 << 63);
                mstatus &= !MSTATUS_FS;
                mstatus |= u64::from(self.fs) << MSTATUS_FS_SHIFT;
                if self.fs == 3 {
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
                mstatus &= !MSTATUS_FS;
                mstatus |= u64::from(self.fs) << MSTATUS_FS_SHIFT;
                mstatus &= 0x8000_0003_000d_e162;
                if self.fs == 3 {
                    mstatus |= 1 << 63;
                }
                mstatus
            }
            Csr::Stval => self.csr.stval,
            Csr::Stvec => self.csr.stvec,
            Csr::Stimecmp => self.csr.stimecmp,
            Csr::Mcounteren => u64::from(self.csr.mcounteren),
            Csr::Scounteren => u64::from(self.csr.scounteren),
            Csr::Senvcfg => self.csr.senvcfg,
            Csr::Menvcfg => self.csr.menvcfg,
            Csr::Time => self.mmu.read_mtime_csr(),
            Csr::Ustatus => self.csr.ustatus,
            _ => 0,
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
            Csr::Mepc => self.csr.mepc = value,
            Csr::Mhartid => self.csr.mhartid = value,
            Csr::Mideleg => self.csr.mideleg = value & 0x222,
            Csr::Mie => self.csr.mie = value,
            Csr::Mip => self.mmu.mip = value,
            Csr::Mscratch => self.csr.mscratch = value,
            Csr::Mstatus => {
                let mask = MSTATUS_MASK & !(MSTATUS_VS | MSTATUS_UXL_MASK | MSTATUS_SXL_MASK);
                self.mmu.mstatus = value & mask | self.mmu.mstatus & !mask;
                self.fs = ((value >> MSTATUS_FS_SHIFT) & 3) as u8;
            }
            Csr::Mtval => self.csr.mtval = value,
            Csr::Mtvec => self.csr.mtvec = value,
            Csr::Scause => self.csr.scause = value,
            Csr::Sedeleg => self.csr.sedeleg = value,
            Csr::Sepc => self.csr.sepc = value,
            Csr::Sideleg => self.csr.sideleg = value,
            Csr::Sie => self.csr.mie = self.csr.mie & !0x222 | value & 0x222,
            Csr::Sip => self.mmu.mip = value & 0x222 | self.mmu.mip & !0x222,
            Csr::Sscratch => self.csr.sscratch = value,
            Csr::Sstatus => {
                self.mmu.mstatus &= !0x8000_0003_000d_e162;
                self.mmu.mstatus |= value & 0x8000_0003_000d_e162;
                self.fs = ((value >> MSTATUS_FS_SHIFT) & 3) as u8;
            }
            Csr::Stval => self.csr.stval = value,
            Csr::Stvec => self.csr.stvec = value,
            Csr::Stimecmp => {
                self.csr.stimecmp = value;
                // Clear STIP immediately; service() will re-set it if needed
                self.mmu.mip &= !MIP_STIP;
            }
            Csr::Mcounteren => self.csr.mcounteren = (value & 0xFFFF_FFFF) as u32,
            Csr::Scounteren => self.csr.scounteren = (value & 0xFFFF_FFFF) as u32,
            Csr::Menvcfg => self.csr.menvcfg = value,
            Csr::Senvcfg => self.csr.senvcfg = value,
            Csr::Misa => {} // read-only WARL; extension set is fixed
            Csr::Time => self.mmu.write_mtime_csr(value), // XXX SHOULD trap
            Csr::Ustatus => self.csr.ustatus = value,
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
        } = decode(addr, insn as u32);

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
        self.icache_flush = IcacheFlushKind::Full;
        self.mmu.read_state(r.remaining(), make_device)
    }

    /// Returns mutable reference to the serial backend, if any.
    pub fn get_mut_serial_backend(&mut self) -> Option<&mut dyn SerialBackend> {
        self.mmu.get_mut_serial_backend()
    }

    fn read_frm(&self) -> RoundingMode {
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
    fn add_to_fflags(&mut self, fflags: u8) {
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
        // 12 bits are 0xFFE or 0xFFF.  Handle that (rare) case via the slow path.
        if va & 0xfff > 0x1000 - 4 {
            return self.memop_slow(Execute, va, 0, 4, false);
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

    /// Data load.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    fn memop_read(&mut self, baseva: u64, offset: u64, size: u64) -> Result<u64, Exception> {
        let va = baseva.wrapping_add(offset);

        if va & 0xfff > 0x1000 - size {
            return self.memop_slow(Read, va, 0, size, false);
        }

        let addr = self.mmu.translate_data_address(va, Read, false)?;

        if addr.mem_idx != DataAddr::NO_RAM {
            let off = addr.page_byte_offset as usize | (va as usize & 0xfff);
            let mem = &self.mmu.memory[addr.mem_idx as usize].1;
            return Ok(match size {
                1 => u64::from(mem[off]),
                2 => u64::from(u16::from_le_bytes([mem[off], mem[off + 1]])),
                4 => u64::from(u32::from_le_bytes([
                    mem[off],
                    mem[off + 1],
                    mem[off + 2],
                    mem[off + 3],
                ])),
                _ => u64::from_le_bytes([
                    mem[off],
                    mem[off + 1],
                    mem[off + 2],
                    mem[off + 3],
                    mem[off + 4],
                    mem[off + 5],
                    mem[off + 6],
                    mem[off + 7],
                ]),
            });
        }

        self.mmu.load_mmio(addr.pa, size).map_err(|()| Exception {
            trap: Trap::LoadAccessFault,
            tval: va,
        })
    }

    /// Data store. Clears any load-reservation.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    fn memop_write(
        &mut self,
        baseva: u64,
        offset: u64,
        v: u64,
        size: u64,
    ) -> Result<(), Exception> {
        self.reservation = None;
        let va = baseva.wrapping_add(offset);

        if va & 0xfff > 0x1000 - size {
            self.memop_slow(Write, va, v, size, false)?;
            return Ok(());
        }

        let addr = self.mmu.translate_data_address(va, Write, false)?;

        if addr.mem_idx != DataAddr::NO_RAM {
            let off = addr.page_byte_offset as usize | (va as usize & 0xfff);
            let mem = &mut self.mmu.memory[addr.mem_idx as usize].1;
            match size {
                1 => mem[off] = v as u8,
                2 => mem[off..off + 2].copy_from_slice(&(v as u16).to_le_bytes()),
                4 => mem[off..off + 4].copy_from_slice(&(v as u32).to_le_bytes()),
                _ => mem[off..off + 8].copy_from_slice(&v.to_le_bytes()),
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
        Ok(decode(addr, insn))
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
pub fn decode(a: u64, word: u32) -> Uop {
    let mut uop = decoder(a, word, &mut new_decoder::Decoder {});
    let size: u8 = if word & 3 == 3 { 4 } else { 2 };
    let branch_flag: u8 = if Cpu::is_branch(uop.op) { 0x80 } else { 0 };
    uop.insn_size = size | branch_flag;
    uop
}

fn with_fflags<A>(a: A) -> (A, u8) { (a, native_fp::fflags_raised()) }

/// Inline fast path for the most common ops (integer ALU, branches, jumps).
/// Avoids the function-call overhead of `new_execute` for ~70% of instructions.
#[allow(clippy::inline_always)]
#[inline(always)]
#[allow(clippy::cast_possible_truncation, clippy::cast_lossless)]
fn execute_fast(cpu: &mut Cpu, uop: &Uop, s1: u64, s2: u64, s3: u64, insn_addr: u64) -> ExecOut {
    match uop.op {
        // Lui / Auipc
        Op::Lui | Op::CLui => ExecOut::ok(uop.imm64()),
        Op::Auipc => ExecOut::ok(insn_addr.wrapping_add(uop.imm64())),
        // Jumps
        Op::Jal | Op::CJ => {
            let tmp = cpu.pc;
            cpu.pc = insn_addr.wrapping_add(uop.imm64());
            ExecOut::ok(tmp)
        }
        Op::Jalr | Op::CJr | Op::CJalr => {
            let tmp = cpu.pc;
            cpu.pc = s1.wrapping_add(uop.imm64()) & !1;
            ExecOut::ok(tmp)
        }
        // Branches
        Op::Beq | Op::CBeqz => {
            if s1 == s2 {
                cpu.pc = insn_addr.wrapping_add(uop.imm64());
            }
            ExecOut::ok(0)
        }
        Op::Bne | Op::CBnez => {
            if s1 != s2 {
                cpu.pc = insn_addr.wrapping_add(uop.imm64());
            }
            ExecOut::ok(0)
        }
        Op::Blt => {
            if (s1 as i64) < s2 as i64 {
                cpu.pc = insn_addr.wrapping_add(uop.imm64());
            }
            ExecOut::ok(0)
        }
        Op::Bge => {
            if (s1 as i64) >= s2 as i64 {
                cpu.pc = insn_addr.wrapping_add(uop.imm64());
            }
            ExecOut::ok(0)
        }
        Op::Bltu => {
            if s1 < s2 {
                cpu.pc = insn_addr.wrapping_add(uop.imm64());
            }
            ExecOut::ok(0)
        }
        Op::Bgeu => {
            if s1 >= s2 {
                cpu.pc = insn_addr.wrapping_add(uop.imm64());
            }
            ExecOut::ok(0)
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
        // Everything else: memory, float, CSR, atomic, etc.
        _ => new_execute(cpu, uop, s1, s2, s3, insn_addr),
    }
}

#[allow(
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::cast_lossless
)]
fn new_execute(cpu: &mut Cpu, uop: &Uop, s1: u64, s2: u64, s3: u64, insn_addr: u64) -> ExecOut {
    match uop.op {
        Op::CNop
        | Op::SfenceWInval
        | Op::SfenceInvalIr
        | Op::CboInval
        | Op::CboClean
        | Op::CboFlush
        | Op::PrefetchI
        | Op::PrefetchR
        | Op::PrefetchW => ExecOut::ok(0),
        Op::CEbreak => ExecOut::err(Trap::Breakpoint, 0x9002),

        Op::Lui | Op::CLui => ExecOut::ok(uop.imm64()),
        Op::Auipc => ExecOut::ok(insn_addr.wrapping_add(uop.imm64())),
        Op::Jal | Op::CJ => {
            let tmp = cpu.pc;
            cpu.pc = insn_addr.wrapping_add(uop.imm64());
            ExecOut::ok(tmp)
        }
        Op::Jalr | Op::CJr | Op::CJalr => {
            let tmp = cpu.pc;
            cpu.pc = s1.wrapping_add(uop.imm64()) & !1;
            ExecOut::ok(tmp)
        }
        Op::Beq | Op::CBeqz => {
            if s1 == s2 {
                cpu.pc = insn_addr.wrapping_add(uop.imm64());
            }
            ExecOut::ok(0)
        }
        Op::Bne | Op::CBnez => {
            if s1 != s2 {
                cpu.pc = insn_addr.wrapping_add(uop.imm64());
            }
            ExecOut::ok(0)
        }
        Op::Blt => {
            if (s1 as i64) < s2 as i64 {
                cpu.pc = insn_addr.wrapping_add(uop.imm64());
            }
            ExecOut::ok(0)
        }
        Op::Bge => {
            if (s1 as i64) >= s2 as i64 {
                cpu.pc = insn_addr.wrapping_add(uop.imm64());
            }
            ExecOut::ok(0)
        }
        Op::Bltu => {
            if s1 < s2 {
                cpu.pc = insn_addr.wrapping_add(uop.imm64());
            }
            ExecOut::ok(0)
        }
        Op::Bgeu => {
            if s1 >= s2 {
                cpu.pc = insn_addr.wrapping_add(uop.imm64());
            }
            ExecOut::ok(0)
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
        Op::Ebreak => ExecOut::err(Trap::Breakpoint, 0x00100073),
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
            etry!(cpu.write_csr(uop.imm as u16, s1));

            ExecOut::ok(res)
        }
        Op::Csrrs => {
            let data = etry!(cpu.read_csr(uop.imm as u16));
            if uop.rs1.get() != 0 {
                etry!(cpu.write_csr(uop.imm as u16, data | s1));
            }
            ExecOut::ok(data)
        }
        Op::Csrrc => {
            let data = etry!(cpu.read_csr(uop.imm as u16));
            if uop.rs1.get() != 0 {
                etry!(cpu.write_csr(uop.imm as u16, data & !s1));
            }
            ExecOut::ok(data)
        }
        Op::Csrrwi => {
            let res = if uop.rd.is_x0_dest() {
                0
            } else {
                etry!(cpu.read_csr(uop.imm as u16))
            };
            etry!(cpu.write_csr(uop.imm as u16, uop.rs1.get() as u64));

            ExecOut::ok(res)
        }
        Op::Csrrsi => {
            let data = etry!(cpu.read_csr(uop.imm as u16));
            if uop.rs1.get() != 0 {
                etry!(cpu.write_csr(uop.imm as u16, data | uop.rs1.get() as u64));
            }
            ExecOut::ok(data)
        }
        Op::Csrrci => {
            let data = etry!(cpu.read_csr(uop.imm as u16));
            if uop.rs1.get() != 0 {
                etry!(cpu.write_csr(uop.imm as u16, data & !(uop.rs1.get() as u64)));
            }
            ExecOut::ok(data)
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
            etry!(cpu.check_float_access_and_dirty(0));
            ExecOut::ok(etry!(cpu.memop_read(s1, uop.imm64(), 4)) | fp::NAN_BOX_F32)
        }
        Op::Fsw => {
            etry!(cpu.check_float_access_and_dirty(0));
            etry!(cpu.memop_write(s1, uop.imm64(), s2, 4));
            ExecOut::ok(0)
        }
        Op::Flh => {
            etry!(cpu.check_float_access_and_dirty(0));
            ExecOut::ok(etry!(cpu.memop_read(s1, uop.imm64(), 2)) | fp::NAN_BOX_F16)
        }
        Op::Fsh => {
            etry!(cpu.check_float_access_and_dirty(0));
            etry!(cpu.memop_write(s1, uop.imm64(), s2, 2));
            ExecOut::ok(0)
        }
        Op::FmaddS => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(Sf32::map3(s1, s2, s3, f32::mul_add))
        }
        Op::FmsubS => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(Sf32::map3(s1, s2, s3, |a, b, c| a.mul_add(b, -c)))
        }
        Op::FnmsubS => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(Sf32::map3(s1, s2, s3, |a, b, c| -a.mul_add(b, -c)))
        }
        Op::FnmaddS => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(Sf32::map3(s1, s2, s3, |a, b, c| -a.mul_add(b, c)))
        }
        Op::FaddS => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            //ExecOut::from_wf(Sf32::map2(s1, s2, |a, b| a + b))
            ExecOut::from_wf(Sf32::fadd(s1, s2, cpu.get_rm(uop.rm)))
        }
        Op::FsubS => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(Sf32::fsub(s1, s2, cpu.get_rm(uop.rm)))
        }
        Op::FmulS => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(Sf32::map2(s1, s2, |a, b| a * b))
        }
        Op::FdivS => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            if s2 == 0 {
                ExecOut::ok_ff(0xffffffff7f800000, DIVIDEZERO) // INFINITY
            } else if s2 == 0x8000000000000000 {
                ExecOut::ok_ff(0xffffffffff800000, DIVIDEZERO) // NEG_INFINITY
            } else {
                ExecOut::from_wf(Sf32::map2(s1, s2, |a, b| a / b))
            }
        }
        Op::FsqrtS => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(Sf32::map1(s1, f32::sqrt))
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
            ExecOut::ok(Sf32::to_float(s1) as i32 as u64)
        }
        Op::FcvtWuS => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::ok(u64::from(Sf32::to_float(s1) as u32))
        }
        Op::FmvXW => {
            etry!(cpu.check_float_access_and_dirty(0));
            ExecOut::ok(s1 as i32 as u64)
        }
        Op::FmvXH => {
            etry!(cpu.check_float_access_and_dirty(0));
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
            etry!(cpu.check_float_access_and_dirty(0));
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
            ExecOut::ok(Sf32::to_float(s1) as i64 as u64)
        }
        Op::FcvtLuS => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::ok(Sf32::to_float(s1) as u64)
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
            etry!(cpu.check_float_access_and_dirty(0));
            let v = etry!(cpu.memop_read(s1, uop.imm64(), 8));
            ExecOut::ok(v)
        }
        Op::Fsd | Op::CFsd | Op::CFsdsp => {
            etry!(cpu.check_float_access_and_dirty(0));
            etry!(cpu.mmu.store64(s1.wrapping_add(uop.imm64()), s2));
            ExecOut::ok(0)
        }
        Op::FmaddD => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(Sf64::map3(s1, s2, s3, f64::mul_add))
        }
        Op::FmsubD => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(Sf64::map3(s1, s2, s3, |a, b, c| a.mul_add(b, -c)))
        }
        Op::FnmsubD => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(Sf64::map3(s1, s2, s3, |a, b, c| -a.mul_add(b, -c)))
        }
        Op::FnmaddD => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(Sf64::map3(s1, s2, s3, |a, b, c| -a.mul_add(b, c)))
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
            ExecOut::from_wf(Sf64::map2(s1, s2, |a, b| a * b))
        }
        Op::FdivD => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            if s2 == 0 {
                ExecOut::ok_ff(f64::INFINITY as u64, DIVIDEZERO) // XXX??
            } else if s2 == 0x8000000000000000 {
                ExecOut::ok_ff(f64::NEG_INFINITY as u64, DIVIDEZERO) // XXX??
            } else {
                ExecOut::from_wf(Sf64::map2(s1, s2, |a, b| a / b))
            }
        }
        Op::FsqrtD => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(Sf64::map1(s1, f64::sqrt))
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
            ExecOut::from_wf(with_fflags(Sf32::from_float(Sf64::to_float(s1) as f32)))
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
            etry!(cpu.check_float_access_and_dirty(0));
            ExecOut::ok(1 << Sf64::fclass(s1) as usize)
        }
        Op::FcvtWD | Op::FcvtWuD => {
            // XXX They are not the same
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(with_fflags(Sf64::to_float(s1) as i32 as u64))
        }
        Op::FcvtDW => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(with_fflags(Sf64::from_float(f64::from(s1 as i32))))
        }
        Op::FcvtDWu => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(with_fflags(Sf64::from_float(f64::from(s1 as u32))))
        }
        // RV64D
        Op::FcvtLD => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(with_fflags(Sf64::to_float(s1) as i64 as u64))
        }
        Op::FcvtLuD => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            ExecOut::from_wf(with_fflags(Sf64::to_float(s1) as u64))
        }
        Op::FmvXD | Op::FmvDX => {
            etry!(cpu.check_float_access_and_dirty(0));
            ExecOut::ok(s1)
        }
        Op::FcvtDL => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            #[allow(clippy::cast_precision_loss)]
            ExecOut::from_wf(with_fflags(Sf64::from_float(s1 as i64 as f64)))
        }
        Op::FcvtDLu => {
            etry!(cpu.check_float_access_and_dirty(uop.rm));
            #[allow(clippy::cast_precision_loss)]
            ExecOut::from_wf(with_fflags(Sf64::from_float(s1 as f64)))
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
            cpu.mmu.update_priv_mode(priv_mode_from(mpp));
            cpu.defer_interrupt = true;
            ExecOut::ok(0)
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
            cpu.mmu.update_priv_mode(priv_mode_from(spp));
            cpu.defer_interrupt = true;
            ExecOut::ok(0)
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
            let base = s1 & !63;
            for i in 0..8u64 {
                etry!(cpu.memop_write(base, i * 8, 0, 8));
            }
            ExecOut::ok(0)
        }
        // End is the sentinel for unrecognised 32-bit instructions; CUnimp for compressed.
        Op::End | Op::Unimp | Op::CUnimp => ExecOut::err(Trap::IllegalInstruction, 0),
    }
}

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
