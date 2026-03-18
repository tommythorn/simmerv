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
use intmap::IntMap;
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

pub type ExecResult = Result<(u64, u8), Exception>;

/// The decoded instruction, convenient for execution
// XXX Needs Seqno, ctf_target_opt
// XXX ctf, exceptional, serialize (and more?) should be combined into a classification represented
// as an enum. We also want to easily distinguish ALU, ALUFP, CTF, LOAD, STORE, ATOMIC, SYSTEM, ...?

#[derive(Debug, Clone, Copy)]
pub struct Uop {
    /// Immediate field (imm, csrno, or shift amount)
    pub imm: u64,
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
}

impl Uop {
    const fn get_insn_size(&self) -> u64 {
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
// - there is architectural state (essentially everything up-to and incl.
//   reservation), but mmu.prv is definitely architectural (but pc and rf are
//   special)
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
// - We could partition the instruction set into classes (multisim used alu,
//   load, store, jump, branch, compjump, atomic) along with a "system" boolean.
//   Each class could have it's own operation
//
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

    // Giving each instruction a unique sequence number in program order is
    // especially helpful when dealing with out-of-order execution.
    // We can derive instret by maintaining an offset from seqno (as minstret
    // can be written by programs), although we cannot then treat ECALL and
    // EBREAK as committing instructions.
    // XXX needn't be part of CPU state; is part of fetch
    pub seqno: usize,

    // Holds all memory and devices (XXX: this public mmu suggests we need to rethink the API)
    pub mmu: Mmu,

    // HACK to allow instructions to communicate this to the fetch engine
    pub flush_icache: bool,

    pub speedometer: Speedometer,
    pub speedometer_flag: Arc<AtomicBool>,
}

pub const CONFIG_SW_MANAGED_A_AND_D: bool = true;
pub const PG_SHIFT: usize = 12; // 4K page size

impl Default for Uop {
    fn default() -> Self {
        Self {
            op: Op::Unimp,
            rd: NODESTREG,
            rs1: ZEROREG,
            rs2: ZEROREG,
            rs3: ZEROREG,
            imm: 0,
            rm: 0,
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
            pc: 0,
            csr: CsrFile::new(),
            mmu,
            reservation: None,
            flush_icache: false,
            speedometer: Speedometer::new(),
            speedometer_flag: Arc::new(AtomicBool::new(false)),
        };
        cpu.mmu.mstatus = 2 << MSTATUS_UXL_SHIFT | 2 << MSTATUS_SXL_SHIFT | 3 << MSTATUS_MPP_SHIFT;
        cpu.write_x(x(11), Mmu::DTB_BASE); // start of DTB
        cpu
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
        self.flush_icache = true;
        self.mmu.prv = PrivMode::M;
        self.mmu.mip = 0;
        self.mmu.satp = 0;
        self.mmu.mstatus = 2 << MSTATUS_UXL_SHIFT | 2 << MSTATUS_SXL_SHIFT | 3 << MSTATUS_MPP_SHIFT;
        self.mmu.clear_page_cache();
        self.write_x(x(11), Mmu::DTB_BASE);
    }

    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn read_x(&self, r: Reg) -> u64 { self.rf[r] }

    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn write_x(&mut self, r: Reg, v: u64) {
        assert_ne!(r.get(), 0);
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
    pub fn run_soc(&mut self, cpu_steps: usize, uop_cache: &mut IntMap<u64, Uop>) -> bool {
        if self.speedometer_flag.load(Ordering::Relaxed)
            && self.speedometer.last_time.elapsed().as_secs() >= 1
        {
            // XXX Using cycle as instret is misleading in the presence of wfi
            let _ = self.speedometer.update(self.cycle);
        }

        for _ in 0..cpu_steps {
            let insn_addr = self.pc;
            if let Err(exc) = self.step_cpu(uop_cache) {
                self.handle_exception(&exc, insn_addr);
                return true;
            }

            if self.wfi {
                break;
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

    // It's here, the One Key Function.  This is where it all happens!
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    fn step_cpu(&mut self, uop_cache: &mut IntMap<u64, Uop>) -> Result<(), Exception> {
        self.cycle = self.cycle.wrapping_add(1);
        if self.wfi {
            if self.mmu.mip & self.csr.mie != 0 {
                self.wfi = false;
            }
            return Ok(());
        }

        if self.flush_icache {
            log::trace!("uop cache flush");
            uop_cache.clear();
            self.flush_icache = false;
        }

        self.seqno = self.seqno.wrapping_add(1);
        let insn_addr = self.pc;

        // Tag M-mode cache entries with bit 0 to distinguish M-mode physical
        // addresses from S/U-mode virtual addresses that share the same value.
        // Valid fetch addresses are always 2-byte aligned so bit 0 is free.
        let cache_key = if self.mmu.prv == PrivMode::M {
            insn_addr | 1
        } else {
            insn_addr
        };

        if let Some(uop) = uop_cache.get(cache_key) {
            self.pc += uop.get_insn_size();

            let ops = Operands {
                s1: self.read_x(uop.rs1),
                s2: self.read_x(uop.rs2),
                s3: self.read_x(uop.rs3),
            };
            let (res, fflags) = new_execute(self, uop, &ops)?;

            self.write_x(uop.rd, res);
            self.add_to_fflags(fflags);
        } else {
            // XXX For full correctness we mustn't fail if we _can_ fetch 16-bit
            // _and_ it turns out to be a legal instruction.
            let insn = self.memop(Execute, insn_addr, 0, 0, 4)? as u32;
            self.pc += if insn & 3 == 3 { 4 } else { 2 };
            let uop = decode(insn_addr, insn);
            if matches!(uop.op, Op::CUnimp | Op::Unimp) {
                return Err(Exception {
                    trap: Trap::IllegalInstruction,
                    tval: u64::from(insn),
                });
            }

            uop_cache.insert(cache_key, uop);

            let ops = Operands {
                s1: self.read_x(uop.rs1),
                s2: self.read_x(uop.rs2),
                s3: self.read_x(uop.rs3),
            };
            let (res, fflags) = new_execute(self, &uop, &ops)?;
            self.write_x(uop.rd, res);
            self.add_to_fflags(fflags);
        }

        Ok(())
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

    fn handle_exception(&mut self, exception: &Exception, insn_addr: u64) {
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

        // Zihpm: hpmcounter3-31 (0xC03-0xC1F, U-mode), mhpmcounter3-31 (0xB03-0xB1F,
        // M-mode), mhpmevent3-31 (0x323-0x33F, M-mode) — all return 0.
        if matches!(csrno, 0xC03..=0xC1F) {
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
                    Some(SatpMode::Bare | SatpMode::Sv39 | SatpMode::Sv48 | SatpMode::Sv57)
                ) {
                    log::warn!("wrote illegal value {value:x} to satp");
                    return illegal;
                }

                self.mmu.satp = value;
                self.mmu.clear_page_cache();
                self.flush_icache = true;
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
                let mut mstatus = self.mmu.mstatus;
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
                let mut mstatus = self.mmu.mstatus;
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
            Csr::Menvcfg => self.csr.menvcfg = value,
            Csr::Senvcfg => {} // U-mode env config; no Sstc-relevant bits for now
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

        let _ = write!(s, "{addr:08x} ");
        if insn % 4 == 3 {
            let _ = write!(s, "{insn:08x} {op:11} {rd}, {rs1}, {rs2}, {imm:08x}"); // ,{rs3}
            return;
        }
        let insn = insn & 0xffff;
        let op = &op[1..];
        let _ = write!(s, "{insn:04x}     c.{op:9} {rd}, {rs1}, {rs2}, {imm:08x}");
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
                c.mcause, c.medeleg, c.mepc, c.mhartid, c.mideleg, c.mie, c.misa, c.mscratch,
                c.mtval, c.mtvec, c.scause, c.sedeleg, c.sepc, c.sideleg, c.sscratch, c.stval,
                c.stvec, c.ustatus, c.menvcfg, c.stimecmp,
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
        self.flush_icache = true;
        self.mmu.read_state(r.remaining(), make_device)
    }

    /// Returns mutable reference to the serial backend, if any.
    pub fn get_mut_serial_backend(&mut self) -> Option<&mut dyn SerialBackend> {
        self.mmu.get_mut_serial_backend()
    }

    fn read_frm(&self) -> RoundingMode {
        assert_ne!(self.fs, 0);
        self.frm
    }

    fn write_frm(&mut self, frm: RoundingMode) {
        assert_ne!(self.fs, 0);
        self.fs = 3;
        self.frm = frm;
    }

    fn read_fflags(&self) -> u8 {
        assert_ne!(self.fs, 0);
        self.fflags
    }

    fn write_fflags(&mut self, fflags: u8) {
        assert_ne!(self.fs, 0);
        assert_eq!(fflags & !31, 0);
        self.fs = 3;
        self.fflags = fflags;
    }

    fn add_to_fflags(&mut self, fflags: u8) {
        if fflags != 0 {
            assert_ne!(self.fs, 0);
            assert_eq!(fflags & !31, 0);
            self.fs = 3;
            self.fflags |= fflags;
        }
    }

    #[allow(clippy::precedence)]
    fn read_fcsr(&self) -> u64 {
        assert_ne!(self.fs, 0);
        assert_eq!(self.fflags & !31, 0);
        u64::from(self.fflags) | (self.frm as u64) << 5
    }

    #[allow(clippy::cast_sign_loss)]
    fn write_fcsr(&mut self, v: u64) {
        assert_ne!(self.fs, 0);
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

    fn memop(
        &mut self,
        access: MemoryAccessType,
        baseva: u64,
        offset: u64,
        v: u64,
        size: u64,
    ) -> Result<u64, Exception> {
        if access == MemoryAccessType::Write {
            self.reservation = None;
        }

        self.memop_general(access, baseva, offset, v, size, false)
    }

    /// # Errors
    /// Usual memory exceptions
    pub fn memop_disass(&mut self, baseva: u64) -> Result<u64, Exception> {
        self.memop_general(Execute, baseva, 0, 0, 4, true)
    }

    // Memory access
    // - does virtual -> physical address translation
    // - directly handles exception
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    fn memop_general(
        &mut self,
        access: MemoryAccessType,
        baseva: u64,
        offset: u64,
        v: u64,
        size: u64,
        side_effect_free: bool,
    ) -> Result<u64, Exception> {
        let va = baseva.wrapping_add(offset);

        if va & 0xfff > 0x1000 - size {
            // Slow path. All bytes aren't in the same page so not contigious
            // in memory
            return self.memop_slow(access, va, v, size, side_effect_free);
        }

        let pa = self.mmu.translate_address(va, access, side_effect_free)?;

        let Ok(slice) = self.mmu.dma_slice(pa, size as usize) else {
            return self.memop_slow(access, va, v, size, side_effect_free);
        };

        match access {
            Write => {
                slice.copy_from_slice(&u64::to_le_bytes(v)[0..size as usize]);
                Ok(0)
            }
            Read | Execute => {
                // Unsigned, sign extension is the job of the consumer
                let mut buf = [0; 8];
                buf[0..size as usize].copy_from_slice(slice);
                Ok(u64::from_le_bytes(buf))
            }
        }
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

const fn get_trap_cause(exc: &Exception) -> u64 {
    let interrupt_bit = 0x8000_0000_0000_0000_u64;
    if (exc.trap as u64) < (Trap::UserSoftwareInterrupt as u64) {
        exc.trap as u64
    } else {
        exc.trap as u64 - Trap::UserSoftwareInterrupt as u64 + interrupt_bit
    }
}

#[must_use]
pub fn decode(a: u64, word: u32) -> Uop { decoder(a, word, &mut new_decoder::Decoder {}) }

fn with_fflags<A>(a: A) -> (A, u8) { (a, native_fp::fflags_raised()) }

#[allow(
    clippy::too_many_lines,
    clippy::cast_possible_truncation,
    clippy::cast_lossless
)]
fn new_execute(cpu: &mut Cpu, uop: &Uop, ops: &Operands) -> ExecResult {
    match uop.op {
        Op::CNop
        | Op::SfenceWInval
        | Op::SfenceInvalIr
        | Op::CboInval
        | Op::CboClean
        | Op::CboFlush
        | Op::PrefetchI
        | Op::PrefetchR
        | Op::PrefetchW => Ok((0, 0)),
        Op::CEbreak => Err(Exception {
            trap: Trap::Breakpoint,
            tval: 0x9002,
        }),

        Op::Lui | Op::Auipc | Op::CLui => Ok((uop.imm, 0)),
        Op::Jal | Op::CJ => {
            let tmp = cpu.pc;
            cpu.pc = uop.imm;
            Ok((tmp, 0))
        }
        Op::Jalr | Op::CJr | Op::CJalr => {
            let tmp = cpu.pc;
            cpu.pc = ops.s1.wrapping_add(uop.imm) & !1;
            Ok((tmp, 0))
        }
        Op::Beq | Op::CBeqz => {
            if ops.s1 == ops.s2 {
                cpu.pc = uop.imm;
            }
            Ok((0, 0))
        }
        Op::Bne | Op::CBnez => {
            if ops.s1 != ops.s2 {
                cpu.pc = uop.imm;
            }
            Ok((0, 0))
        }
        Op::Blt => {
            if (ops.s1 as i64) < ops.s2 as i64 {
                cpu.pc = uop.imm;
            }
            Ok((0, 0))
        }
        Op::Bge => {
            if (ops.s1 as i64) >= ops.s2 as i64 {
                cpu.pc = uop.imm;
            }
            Ok((0, 0))
        }
        Op::Bltu => {
            if ops.s1 < ops.s2 {
                cpu.pc = uop.imm;
            }
            Ok((0, 0))
        }
        Op::Bgeu => {
            if ops.s1 >= ops.s2 {
                cpu.pc = uop.imm;
            }
            Ok((0, 0))
        }
        Op::Lb => Ok((cpu.memop(Read, ops.s1, uop.imm, 0, 1)? as i8 as u64, 0)),
        Op::Lh => Ok((cpu.memop(Read, ops.s1, uop.imm, 0, 2)? as i16 as u64, 0)),
        Op::Lw | Op::CLw | Op::CLwsp => {
            Ok((cpu.memop(Read, ops.s1, uop.imm, 0, 4)? as i32 as u64, 0))
        }
        Op::Lbu => Ok((cpu.memop(Read, ops.s1, uop.imm, 0, 1)?, 0)),
        Op::Lhu => Ok((cpu.memop(Read, ops.s1, uop.imm, 0, 2)?, 0)),
        Op::Sb => {
            let _ = cpu.memop(Write, ops.s1, uop.imm, ops.s2, 1)?;
            Ok((0, 0))
        }
        Op::Sh => {
            let _ = cpu.memop(Write, ops.s1, uop.imm, ops.s2, 2)?;
            Ok((0, 0))
        }
        Op::Sw | Op::CSw | Op::CSwsp => {
            let _ = cpu.memop(Write, ops.s1, uop.imm, ops.s2, 4)?;
            Ok((0, 0))
        }
        Op::Addi | Op::CAddi | Op::CAddi4spn | Op::CLi | Op::CAddi16sp => {
            Ok((ops.s1.wrapping_add(uop.imm), 0))
        }
        Op::Slti => Ok((u64::from((ops.s1 as i64) < uop.imm as i64), 0)),
        Op::Sltiu => Ok((u64::from(ops.s1 < uop.imm), 0)),
        Op::Xori => Ok((ops.s1 ^ uop.imm, 0)),
        Op::Ori => Ok((ops.s1 | uop.imm, 0)),
        Op::Andi | Op::CAndi => Ok((ops.s1 & uop.imm, 0)),
        // RV32I SLLI subsumed by RV64I
        // RV32I SRLI subsumed by RV64I
        // RV32I SRAI subsumed by RV64I
        Op::Add | Op::CAdd | Op::CMv => Ok((ops.s1.wrapping_add(ops.s2), 0)),
        Op::Sub | Op::CSub => Ok((ops.s1.wrapping_sub(ops.s2), 0)),
        Op::Sll => Ok((ops.s1.wrapping_shl(ops.s2 as u32), 0)),
        Op::Slt => Ok((u64::from((ops.s1 as i64) < ops.s2 as i64), 0)),
        Op::Sltu => Ok((u64::from(ops.s1 < ops.s2), 0)),
        Op::Xor | Op::CXor => Ok((ops.s1 ^ ops.s2, 0)),
        Op::Srl => Ok(((ops.s1.wrapping_shr(ops.s2 as u32)), 0)),
        Op::Sra => Ok(((ops.s1 as i64).wrapping_shr(ops.s2 as u32) as u64, 0)),
        Op::Or | Op::COr => Ok((ops.s1 | ops.s2, 0)),
        Op::And | Op::CAnd => Ok((ops.s1 & ops.s2, 0)),
        Op::Fence => {
            if uop.imm == 0x0100000f {
                // PAUSE instruction hint
                // Nothing to do here, but it would be interesting to see
                // it used.
                log::trace!("pause isn't yet implemented");
            }
            // Fence memory ops (we are currently TSO already)
            Ok((0, 0))
        }
        Op::FenceTso => {
            // Fence memory ops (we are currently TSO already)
            Ok((0, 0))
        }
        Op::Ecall => Err(Exception {
            trap: match cpu.mmu.prv {
                PrivMode::U => Trap::EnvironmentCallFromUMode,
                PrivMode::S => Trap::EnvironmentCallFromSMode,
                PrivMode::M => Trap::EnvironmentCallFromMMode,
            },
            tval: uop.imm,
        }),
        Op::Ebreak => Err(Exception {
            trap: Trap::Breakpoint,
            tval: 0x00100073,
        }),
        // RV64I
        Op::Lwu => {
            let v = cpu.memop(Read, ops.s1, uop.imm, 0, 4)?;
            Ok((v, 0))
        }
        Op::Ld | Op::CLd | Op::CLdsp => {
            let v = cpu.memop(Read, ops.s1, uop.imm, 0, 8)?;
            Ok((v, 0))
        }
        Op::Sd | Op::CSd | Op::CSdsp => {
            let _ = cpu.memop(Write, ops.s1, uop.imm, ops.s2, 8)?;
            Ok((0, 0))
        }
        Op::Slli | Op::CSlli => Ok((ops.s1 << uop.imm, 0)),
        Op::Srli | Op::CSrli => Ok((ops.s1 >> uop.imm, 0)),
        Op::Srai | Op::CSrai => Ok((((ops.s1 as i64) >> uop.imm) as u64, 0)),
        Op::Addiw | Op::CAddiw => Ok((sext32(ops.s1.wrapping_add(uop.imm) as u32), 0)),
        Op::Slliw => Ok((((ops.s1 as i32) << (uop.imm & 31)) as u64, 0)),
        Op::Srliw => Ok((sext32((ops.s1 as u32) >> (uop.imm & 31)), 0)),
        Op::Sraiw => Ok((((ops.s1 as i32) >> (uop.imm & 31)) as u64, 0)),
        Op::Addw | Op::CAddw => Ok((sext32(ops.s1.wrapping_add(ops.s2) as u32), 0)),
        Op::Subw | Op::CSubw => Ok((sext32(ops.s1.wrapping_sub(ops.s2) as u32), 0)),
        Op::Sllw => Ok((sext32((ops.s1 as u32).wrapping_shl(ops.s2 as u32)), 0)),
        Op::Srlw => Ok((sext32((ops.s1 as u32).wrapping_shr(ops.s2 as u32)), 0)),
        Op::Sraw => Ok(((ops.s1 as i32).wrapping_shr(ops.s2 as u32) as u64, 0)),
        // RV32/RV64 Zifencei
        Op::FenceI => {
            // Flush any cached instructions.  We have none so far.
            cpu.reservation = None;
            // HACK
            cpu.flush_icache = true;
            Ok((0, 0))
        }
        // RV32/RV64 Zicsr
        Op::Csrrw => {
            let res = if uop.rd.is_x0_dest() {
                0
            } else {
                cpu.read_csr(uop.imm as u16)?
            };
            cpu.write_csr(uop.imm as u16, ops.s1)?;

            Ok((res, 0))
        }
        Op::Csrrs => {
            let data = cpu.read_csr(uop.imm as u16)?;
            if uop.rs1.get() != 0 {
                cpu.write_csr(uop.imm as u16, data | ops.s1)?;
            }
            Ok((data, 0))
        }
        Op::Csrrc => {
            let data = cpu.read_csr(uop.imm as u16)?;
            if uop.rs1.get() != 0 {
                cpu.write_csr(uop.imm as u16, data & !ops.s1)?;
            }
            Ok((data, 0))
        }
        Op::Csrrwi => {
            let res = if uop.rd.is_x0_dest() {
                0
            } else {
                cpu.read_csr(uop.imm as u16)?
            };
            cpu.write_csr(uop.imm as u16, uop.rs1.get() as u64)?;

            Ok((res, 0))
        }
        Op::Csrrsi => {
            let data = cpu.read_csr(uop.imm as u16)?;
            if uop.rs1.get() != 0 {
                cpu.write_csr(uop.imm as u16, data | uop.rs1.get() as u64)?;
            }
            Ok((data, 0))
        }
        Op::Csrrci => {
            let data = cpu.read_csr(uop.imm as u16)?;
            if uop.rs1.get() != 0 {
                cpu.write_csr(uop.imm as u16, data & !(uop.rs1.get() as u64))?;
            }
            Ok((data, 0))
        }
        // RV32M
        Op::Mul => Ok((ops.s1.wrapping_mul(ops.s2), 0)),
        Op::Mulh => Ok((
            ((i128::from(ops.s1 as i64) * i128::from(ops.s2 as i64)) >> 64) as u64,
            0,
        )),
        Op::Mulhsu => Ok((
            ((ops.s1 as i64 as u128).wrapping_mul(u128::from(ops.s2)) >> 64) as u64,
            0,
        )),
        Op::Mulhu => Ok((
            (u128::from(ops.s1).wrapping_mul(u128::from(ops.s2)) >> 64) as u64,
            0,
        )),
        Op::Div => Ok((
            if ops.s2 == 0 {
                !0
            } else if ops.s1 as i64 == i64::MIN && ops.s2 as i64 == -1 {
                ops.s1
            } else {
                (ops.s1 as i64).wrapping_div(ops.s2 as i64) as u64
            },
            0,
        )),
        Op::Divu => Ok((
            if ops.s2 == 0 {
                !0
            } else {
                ops.s1.wrapping_div(ops.s2)
            },
            0,
        )),
        Op::Rem => Ok((
            if ops.s2 == 0 {
                ops.s1
            } else if ops.s1 as i64 == i64::MIN && ops.s2 as i64 == -1 {
                0
            } else {
                (ops.s1 as i64).wrapping_rem(ops.s2 as i64) as u64
            },
            0,
        )),
        Op::Remu => Ok((
            match ops.s2 {
                0 => ops.s1,
                _ => ops.s1.wrapping_rem(ops.s2),
            },
            0,
        )),
        // RV64M
        Op::Mulw => Ok(((ops.s1 as i32).wrapping_mul(ops.s2 as i32) as u64, 0)),
        Op::Divw => {
            let (s1, s2) = (ops.s1 as i32, ops.s2 as i32);
            Ok((
                if s2 == 0 {
                    !0
                } else if s1 == i32::MIN && s2 == -1 {
                    s1 as u64
                } else {
                    s1.wrapping_div(s2) as u64
                },
                0,
            ))
        }
        Op::Divuw => Ok((
            if ops.s2 as u32 == 0 {
                !0
            } else {
                sext32((ops.s1 as u32).wrapping_div(ops.s2 as u32))
            },
            0,
        )),
        Op::Remw => {
            let (s1, s2) = (ops.s1 as i32, ops.s2 as i32);
            Ok((
                if s2 == 0 {
                    s1 as u64
                } else if s1 == i32::MIN && s2 == -1 {
                    0
                } else {
                    s1.wrapping_rem(s2) as u64
                },
                0,
            ))
        }
        Op::Remuw => Ok((
            match ops.s2 as u32 {
                0 => ops.s1 as i32 as u64,
                _ => sext32((ops.s1 as u32).wrapping_rem(ops.s2 as u32)),
            },
            0,
        )),
        // RV32A
        Op::LrW => {
            let data = sext32(cpu.mmu.load_virt_u32(ops.s1)?);
            let pa = cpu
                .mmu
                .translate_address(ops.s1, MemoryAccessType::Read, false)?;
            cpu.reservation = Some(pa);
            Ok((data, 0))
        }
        Op::ScW => {
            let pa = cpu
                .mmu
                .translate_address(ops.s1, MemoryAccessType::Write, false)?;
            let res = if cpu.reservation == Some(pa) {
                cpu.mmu.store_virt_u32(ops.s1, ops.s2 as u32)?;
                0
            } else {
                1
            };
            cpu.reservation = None;
            Ok((res, 0))
        }
        Op::AmoswapW => {
            let tmp = cpu.mmu.load_virt_u32(ops.s1)?;
            cpu.mmu.store_virt_u32(ops.s1, ops.s2 as u32)?;
            Ok((sext32(tmp), 0))
        }
        Op::AmoaddW => {
            let tmp = cpu.mmu.load_virt_u32(ops.s1)?;
            cpu.mmu
                .store_virt_u32(ops.s1, tmp.wrapping_add(ops.s2 as u32))?;
            Ok((sext32(tmp), 0))
        }
        Op::AmoxorW => {
            let tmp = cpu.mmu.load_virt_u32(ops.s1)?;
            cpu.mmu.store_virt_u32(ops.s1, ops.s2 as u32 ^ tmp)?;
            Ok((sext32(tmp), 0))
        }
        Op::AmoandW => {
            let tmp = cpu.mmu.load_virt_u32(ops.s1)?;
            cpu.mmu.store_virt_u32(ops.s1, ops.s2 as u32 & tmp)?;
            Ok((sext32(tmp), 0))
        }
        Op::AmoorW => {
            let tmp = cpu.mmu.load_virt_u32(ops.s1)?;
            cpu.mmu.store_virt_u32(ops.s1, ops.s2 as u32 | tmp)?;
            Ok((sext32(tmp), 0))
        }
        Op::AmominW => {
            let tmp = cpu.mmu.load_virt_u32(ops.s1)?;
            cpu.mmu
                .store_virt_u32(ops.s1, (ops.s2 as i32).min(tmp as i32) as u32)?;
            Ok((sext32(tmp), 0))
        }
        Op::AmomaxW => {
            let tmp = cpu.mmu.load_virt_u32(ops.s1)?;
            cpu.mmu
                .store_virt_u32(ops.s1, (ops.s2 as i32).max(tmp as i32) as u32)?;
            Ok((sext32(tmp), 0))
        }
        Op::AmominuW => {
            let tmp = cpu.mmu.load_virt_u32(ops.s1)?;
            cpu.mmu.store_virt_u32(ops.s1, (ops.s2 as u32).min(tmp))?;
            Ok((sext32(tmp), 0))
        }
        Op::AmomaxuW => {
            let tmp = cpu.mmu.load_virt_u32(ops.s1)?;
            cpu.mmu.store_virt_u32(ops.s1, (ops.s2 as u32).max(tmp))?;
            Ok((sext32(tmp), 0))
        }
        // RV64A
        Op::LrD => {
            let data = cpu.mmu.load_virt_u64(ops.s1)?;
            let pa = cpu
                .mmu
                .translate_address(ops.s1, MemoryAccessType::Read, false)?;
            cpu.reservation = Some(pa);
            Ok((data, 0))
        }
        Op::ScD => {
            let pa = cpu
                .mmu
                .translate_address(ops.s1, MemoryAccessType::Write, false)?;
            let res = if cpu.reservation == Some(pa) {
                cpu.mmu.store_virt_u64(ops.s1, ops.s2)?;
                0
            } else {
                1
            };
            cpu.reservation = None;
            Ok((res, 0))
        }
        Op::AmoswapD => {
            let tmp = cpu.mmu.load_virt_u64(ops.s1)?;
            cpu.mmu.store_virt_u64(ops.s1, ops.s2)?;
            cpu.reservation = None;
            Ok((tmp, 0))
        }
        Op::AmoaddD => {
            let tmp = cpu.mmu.load_virt_u64(ops.s1)?;
            cpu.mmu.store_virt_u64(ops.s1, tmp.wrapping_add(ops.s2))?;
            cpu.reservation = None;
            Ok((tmp, 0))
        }
        Op::AmoxorD => {
            let tmp = cpu.mmu.load_virt_u64(ops.s1)?;
            cpu.mmu.store_virt_u64(ops.s1, tmp ^ ops.s2)?;
            cpu.reservation = None;
            Ok((tmp, 0))
        }
        Op::AmoandD => {
            let tmp = cpu.mmu.load_virt_u64(ops.s1)?;
            cpu.mmu.store_virt_u64(ops.s1, tmp & ops.s2)?;
            cpu.reservation = None;
            Ok((tmp, 0))
        }
        Op::AmoorD => {
            let tmp = cpu.mmu.load_virt_u64(ops.s1)?;
            cpu.mmu.store_virt_u64(ops.s1, tmp | ops.s2)?;
            cpu.reservation = None;
            Ok((tmp, 0))
        }
        Op::AmominD => {
            let tmp = cpu.mmu.load_virt_u64(ops.s1)?;
            cpu.mmu
                .store_virt_u64(ops.s1, (ops.s2 as i64).min(tmp as i64) as u64)?;
            cpu.reservation = None;
            Ok((tmp, 0))
        }
        Op::AmomaxD => {
            let tmp = cpu.mmu.load_virt_u64(ops.s1)?;
            cpu.mmu
                .store_virt_u64(ops.s1, (ops.s2 as i64).max(tmp as i64) as u64)?;
            cpu.reservation = None;
            Ok((tmp, 0))
        }
        Op::AmominuD => {
            let tmp = cpu.mmu.load_virt_u64(ops.s1)?;
            cpu.mmu.store_virt_u64(ops.s1, ops.s2.min(tmp))?;
            cpu.reservation = None;
            Ok((tmp, 0))
        }
        Op::AmomaxuD => {
            let tmp = cpu.mmu.load_virt_u64(ops.s1)?;
            cpu.mmu.store_virt_u64(ops.s1, ops.s2.max(tmp))?;
            cpu.reservation = None;
            Ok((tmp, 0))
        }
        // RV32F
        Op::Flw => {
            cpu.check_float_access_and_dirty(0)?;
            Ok((cpu.memop(Read, ops.s1, uop.imm, 0, 4)? | fp::NAN_BOX_F32, 0))
        }
        Op::Fsw => {
            cpu.check_float_access_and_dirty(0)?;
            cpu.reservation = None;
            let _ = cpu.memop(Write, ops.s1, uop.imm, ops.s2, 4)?;
            Ok((0, 0))
        }
        Op::Flh => {
            cpu.check_float_access_and_dirty(0)?;
            Ok((cpu.memop(Read, ops.s1, uop.imm, 0, 2)? | fp::NAN_BOX_F16, 0))
        }
        Op::Fsh => {
            cpu.check_float_access_and_dirty(0)?;
            cpu.reservation = None;
            let _ = cpu.memop(Write, ops.s1, uop.imm, ops.s2, 2)?;
            Ok((0, 0))
        }
        Op::FmaddS => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(Sf32::map3(ops.s1, ops.s2, ops.s3, |a, b, c| {
                a.mul_add(b, c)
            }))
        }
        Op::FmsubS => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(Sf32::map3(ops.s1, ops.s2, ops.s3, |a, b, c| {
                a.mul_add(b, -c)
            }))
        }
        Op::FnmsubS => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(Sf32::map3(ops.s1, ops.s2, ops.s3, |a, b, c| {
                -a.mul_add(b, -c)
            }))
        }
        Op::FnmaddS => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(Sf32::map3(ops.s1, ops.s2, ops.s3, |a, b, c| {
                -a.mul_add(b, c)
            }))
        }
        Op::FaddS => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            //Ok(Sf32::map2(ops.s1, ops.s2, |a, b| a + b))
            Ok(Sf32::fadd(ops.s1, ops.s2, cpu.get_rm(uop.rm)))
        }
        Op::FsubS => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(Sf32::fsub(ops.s1, ops.s2, cpu.get_rm(uop.rm)))
        }
        Op::FmulS => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(Sf32::map2(ops.s1, ops.s2, |a, b| a * b))
        }
        Op::FdivS => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            if ops.s2 == 0 {
                Ok((0xffffffff7f800000, DIVIDEZERO)) // INFINITY
            } else if ops.s2 == 0x8000000000000000 {
                Ok((0xffffffffff800000, DIVIDEZERO)) // NEG_INFINITY
            } else {
                Ok(Sf32::map2(ops.s1, ops.s2, |a, b| a / b))
            }
        }
        Op::FsqrtS => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(Sf32::map1(ops.s1, f32::sqrt))
        }
        Op::FsgnjS => {
            cpu.check_float_access_and_dirty(0)?;
            let rs1_bits = Sf32::unbox(ops.s1);
            let rs2_bits = Sf32::unbox(ops.s2);
            let sign_bit = rs2_bits & 0x80000000;
            Ok((fp::NAN_BOX_F32 | sign_bit | rs1_bits & 0x7fffffff, 0))
        }
        Op::FsgnjnS => {
            cpu.check_float_access_and_dirty(0)?;
            let rs1_bits = Sf32::unbox(ops.s1);
            let rs2_bits = Sf32::unbox(ops.s2);
            let sign_bit = !rs2_bits & 0x80000000;
            Ok((fp::NAN_BOX_F32 | sign_bit | rs1_bits & 0x7fffffff, 0))
        }
        Op::FsgnjxS => {
            cpu.check_float_access_and_dirty(0)?;
            let rs1_bits = Sf32::unbox(ops.s1);
            let rs2_bits = Sf32::unbox(ops.s2);
            let sign_bit = rs2_bits & 0x80000000;
            Ok((fp::NAN_BOX_F32 | (sign_bit ^ rs1_bits), 0))
        }
        Op::FminS => {
            cpu.check_float_access_and_dirty(0)?;
            Ok(Sf32::min(ops.s1, ops.s2))
        }
        Op::FmaxS => {
            cpu.check_float_access_and_dirty(0)?;
            Ok(Sf32::max(ops.s1, ops.s2))
        }
        Op::FcvtWS => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok((Sf32::to_float(ops.s1) as i32 as u64, 0))
        }
        Op::FcvtWuS => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok((u64::from(Sf32::to_float(ops.s1) as u32), 0))
        }
        Op::FmvXW => {
            cpu.check_float_access_and_dirty(0)?;
            Ok((ops.s1 as i32 as u64, 0))
        }
        Op::FmvXH => {
            cpu.check_float_access_and_dirty(0)?;
            Ok((Sf16::unbox(ops.s1) as i16 as u64, 0))
        }
        Op::FeqS => {
            cpu.check_float_access_and_dirty(0)?;
            Ok(Sf32::feq(ops.s1, ops.s2))
        }
        Op::FltS => {
            cpu.check_float_access_and_dirty(0)?;
            Ok(Sf32::flt(ops.s1, ops.s2))
        }
        Op::FleS => {
            cpu.check_float_access_and_dirty(0)?;
            Ok(Sf32::fle(ops.s1, ops.s2))
        }
        Op::FclassS => {
            cpu.check_float_access_and_dirty(0)?;
            Ok((1 << Sf32::fclass(ops.s1) as usize, 0))
        }
        Op::FcvtSW => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(cvt_i32_sf32(ops.s1, cpu.get_rm(uop.rm)))
        }
        Op::FcvtSWu => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(cvt_u32_sf32(ops.s1, cpu.get_rm(uop.rm)))
        }
        Op::FmvWX => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok((fp::NAN_BOX_F32 | ops.s1, 0))
        }
        Op::FmvHX => {
            cpu.check_float_access_and_dirty(0)?;
            Ok((fp::NAN_BOX_F16 | (ops.s1 & 0xFFFF), 0))
        }
        // RV64F
        Op::FcvtLS => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok((Sf32::to_float(ops.s1) as i64 as u64, 0))
        }
        Op::FcvtLuS => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok((Sf32::to_float(ops.s1) as u64, 0))
        }
        Op::FcvtSL => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(cvt_i64_sf32(ops.s1, cpu.get_rm(uop.rm)))
        }
        Op::FcvtSLu => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(cvt_u64_sf32(ops.s1, cpu.get_rm(uop.rm)))
        }
        // RV32D
        Op::Fld | Op::CFld | Op::CFldsp => {
            cpu.check_float_access_and_dirty(0)?;
            let v = cpu.memop(Read, ops.s1, uop.imm, 0, 8)?;
            Ok((v, 0))
        }
        Op::Fsd | Op::CFsd | Op::CFsdsp => {
            cpu.check_float_access_and_dirty(0)?;
            cpu.mmu.store64(ops.s1.wrapping_add(uop.imm), ops.s2)?;
            Ok((0, 0))
        }
        Op::FmaddD => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(Sf64::map3(ops.s1, ops.s2, ops.s3, |a, b, c| {
                a.mul_add(b, c)
            }))
        }
        Op::FmsubD => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(Sf64::map3(ops.s1, ops.s2, ops.s3, |a, b, c| {
                a.mul_add(b, -c)
            }))
        }
        Op::FnmsubD => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(Sf64::map3(ops.s1, ops.s2, ops.s3, |a, b, c| {
                -a.mul_add(b, -c)
            }))
        }
        Op::FnmaddD => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(Sf64::map3(ops.s1, ops.s2, ops.s3, |a, b, c| {
                -a.mul_add(b, c)
            }))
        }
        Op::FaddD => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(Sf64::fadd(ops.s1, ops.s2, cpu.get_rm(uop.rm)))
        }
        Op::FsubD => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(Sf64::fsub(ops.s1, ops.s2, cpu.get_rm(uop.rm)))
        }
        Op::FmulD => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(Sf64::map2(ops.s1, ops.s2, |a, b| a * b))
        }
        Op::FdivD => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            if ops.s2 == 0 {
                Ok((f64::INFINITY as u64, DIVIDEZERO)) // XXX??
            } else if ops.s2 == 0x8000000000000000 {
                Ok((f64::NEG_INFINITY as u64, DIVIDEZERO)) // XXX??
            } else {
                Ok(Sf64::map2(ops.s1, ops.s2, |a, b| a / b))
            }
        }
        Op::FsqrtD => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(Sf64::map1(ops.s1, f64::sqrt))
        }
        Op::FsgnjD => {
            cpu.check_float_access_and_dirty(0)?;
            let rs1_bits = ops.s1;
            let rs2_bits = ops.s2;
            let sign_bit = rs2_bits & 0x8000000000000000;
            Ok((sign_bit | (rs1_bits & 0x7fffffffffffffff), 0))
        }
        Op::FsgnjnD => {
            cpu.check_float_access_and_dirty(0)?;
            let rs1_bits = ops.s1;
            let rs2_bits = ops.s2;
            let sign_bit = !rs2_bits & 0x8000000000000000;
            Ok((sign_bit | (rs1_bits & 0x7fffffffffffffff), 0))
        }
        Op::FsgnjxD => {
            cpu.check_float_access_and_dirty(0)?;
            let rs1_bits = ops.s1;
            let rs2_bits = ops.s2;
            let sign_bit = rs2_bits & 0x8000000000000000;
            Ok((sign_bit ^ rs1_bits, 0))
        }
        Op::FminD => {
            cpu.check_float_access_and_dirty(0)?;
            Ok(Sf64::min(ops.s1, ops.s2))
        }
        Op::FmaxD => {
            cpu.check_float_access_and_dirty(0)?;
            Ok(Sf64::max(ops.s1, ops.s2))
        }
        Op::FcvtSD => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(with_fflags(Sf32::from_float(Sf64::to_float(ops.s1) as f32)))
        }
        Op::FcvtDS => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(fp::fcvt_d_s(ops.s1))
        }
        Op::FcvtSH => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(fp::fcvt_s_h(ops.s1))
        }
        Op::FcvtHS => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(fp::fcvt_h_s(ops.s1, cpu.get_rm(uop.rm)))
        }
        Op::FcvtDH => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(fp::fcvt_d_h(ops.s1))
        }
        Op::FcvtHD => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(fp::fcvt_h_d(ops.s1, cpu.get_rm(uop.rm)))
        }
        Op::FeqD => {
            cpu.check_float_access_and_dirty(0)?;
            Ok(Sf64::feq(ops.s1, ops.s2))
        }
        Op::FltD => {
            cpu.check_float_access_and_dirty(0)?;
            Ok(Sf64::flt(ops.s1, ops.s2))
        }
        Op::FleD => {
            cpu.check_float_access_and_dirty(0)?;
            Ok(Sf64::fle(ops.s1, ops.s2))
        }
        Op::FclassD => {
            cpu.check_float_access_and_dirty(0)?;
            Ok((1 << Sf64::fclass(ops.s1) as usize, 0))
        }
        Op::FcvtWD | Op::FcvtWuD => {
            // XXX They are not the same
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(with_fflags(Sf64::to_float(ops.s1) as i32 as u64))
        }
        Op::FcvtDW => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(with_fflags(Sf64::from_float(f64::from(ops.s1 as i32))))
        }
        Op::FcvtDWu => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(with_fflags(Sf64::from_float(f64::from(ops.s1 as u32))))
        }
        // RV64D
        Op::FcvtLD => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(with_fflags(Sf64::to_float(ops.s1) as i64 as u64))
        }
        Op::FcvtLuD => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(with_fflags(Sf64::to_float(ops.s1) as u64))
        }
        Op::FmvXD | Op::FmvDX => {
            cpu.check_float_access_and_dirty(0)?;
            Ok((ops.s1, 0))
        }
        Op::FcvtDL => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            #[allow(clippy::cast_precision_loss)]
            Ok(with_fflags(Sf64::from_float(ops.s1 as i64 as f64)))
        }
        Op::FcvtDLu => {
            cpu.check_float_access_and_dirty(uop.rm)?;
            #[allow(clippy::cast_precision_loss)]
            Ok(with_fflags(Sf64::from_float(ops.s1 as f64)))
        }
        // Remaining (all system-level) that weren't listed in the instr-table
        Op::Dret => todo!("Handling dret requires handling all of debug mode"),
        Op::Mret => {
            cpu.pc = cpu.read_csr(Csr::Mepc as u16)?;
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
            cpu.handle_interrupt();
            Ok((0, 0))
        }
        Op::Sret => {
            if cpu.mmu.prv == PrivMode::U
                || cpu.mmu.prv == PrivMode::S && cpu.mmu.mstatus & MSTATUS_TSR != 0
            {
                return Err(Exception {
                    trap: Trap::IllegalInstruction,
                    tval: 0,
                });
            }

            cpu.pc = cpu.read_csr(Csr::Sepc as u16)?;
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
            cpu.handle_interrupt();
            Ok((0, 0))
        }
        Op::SfenceVma => {
            if cpu.mmu.prv == PrivMode::U
                || cpu.mmu.prv == PrivMode::S && cpu.mmu.mstatus & MSTATUS_TVM != 0
            {
                return Err(Exception {
                    trap: Trap::IllegalInstruction,
                    tval: 0,
                });
            }

            cpu.mmu.clear_page_cache();
            cpu.reservation = None;

            // HACK
            cpu.flush_icache = true;

            Ok((0, 0))
        }
        // Svinval — sinval.vma is ordered like sfence.vma; the fence ops are no-ops in emulation
        Op::SinvalVma => {
            if cpu.mmu.prv == PrivMode::U
                || cpu.mmu.prv == PrivMode::S && cpu.mmu.mstatus & MSTATUS_TVM != 0
            {
                return Err(Exception {
                    trap: Trap::IllegalInstruction,
                    tval: 0,
                });
            }
            cpu.mmu.clear_page_cache();
            cpu.reservation = None;
            cpu.flush_icache = true;
            Ok((0, 0))
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
                return Err(Exception {
                    trap: Trap::IllegalInstruction,
                    tval: 0,
                });
            }
            cpu.wfi = true;
            Ok((0, 0))
        }
        // Zba -- AKA, my only favorite extension
        Op::AddUw => Ok((ops.s2.wrapping_add(ops.s1 & 0xffffffff), 0)),
        Op::Sh1add => Ok((ops.s2.wrapping_add(ops.s1 << 1), 0)),
        Op::Sh1addUw => Ok((ops.s2.wrapping_add((ops.s1 & 0xffffffff) << 1), 0)),
        Op::Sh2add => Ok((ops.s2.wrapping_add(ops.s1 << 2), 0)),
        Op::Sh2addUw => Ok((ops.s2.wrapping_add((ops.s1 & 0xffffffff) << 2), 0)),
        Op::Sh3add => Ok((ops.s2.wrapping_add(ops.s1 << 3), 0)),
        Op::Sh3addUw => Ok((ops.s2.wrapping_add((ops.s1 & 0xffffffff) << 3), 0)),
        Op::SlliUw => Ok(((ops.s1 & 0xffffffff) << uop.imm, 0)),
        // Zicond extension
        Op::CzeroEqz => Ok((if ops.s2 == 0 { 0 } else { ops.s1 }, 0)),
        Op::CzeroNez => Ok((if ops.s2 != 0 { 0 } else { ops.s1 }, 0)),
        // Zbb — base integer bit manipulation
        Op::Andn => Ok((ops.s1 & !ops.s2, 0)),
        Op::Orn => Ok((ops.s1 | !ops.s2, 0)),
        Op::Xnor => Ok((!ops.s1 ^ ops.s2, 0)),
        Op::Clz => Ok((ops.s1.leading_zeros() as u64, 0)),
        Op::Clzw => Ok(((ops.s1 as u32).leading_zeros() as u64, 0)),
        Op::Ctz => Ok((ops.s1.trailing_zeros() as u64, 0)),
        Op::Ctzw => Ok(((ops.s1 as u32).trailing_zeros() as u64, 0)),
        Op::Cpop => Ok((ops.s1.count_ones() as u64, 0)),
        Op::Cpopw => Ok(((ops.s1 as u32).count_ones() as u64, 0)),
        Op::Max => Ok(((ops.s1 as i64).max(ops.s2 as i64) as u64, 0)),
        Op::Maxu => Ok((ops.s1.max(ops.s2), 0)),
        Op::Min => Ok(((ops.s1 as i64).min(ops.s2 as i64) as u64, 0)),
        Op::Minu => Ok((ops.s1.min(ops.s2), 0)),
        Op::OrcB => {
            let mut r = 0;
            for i in 0..8 {
                if ops.s1 >> (i * 8) & 0xff != 0 {
                    r |= 0xff << (i * 8);
                }
            }
            Ok((r, 0))
        }
        Op::Rev8 => Ok((ops.s1.swap_bytes(), 0)),
        Op::Rol => Ok((ops.s1.rotate_left((ops.s2 & 63) as u32), 0)),
        Op::Rolw => Ok((
            (ops.s1 as u32).rotate_left((ops.s2 & 31) as u32) as i32 as u64,
            0,
        )),
        Op::Ror => Ok((ops.s1.rotate_right((ops.s2 & 63) as u32), 0)),
        Op::Rori => Ok((ops.s1.rotate_right((uop.imm & 63) as u32), 0)),
        Op::Roriw => Ok((
            (ops.s1 as u32).rotate_right((uop.imm & 31) as u32) as i32 as u64,
            0,
        )),
        Op::Rorw => Ok((
            (ops.s1 as u32).rotate_right((ops.s2 & 31) as u32) as i32 as u64,
            0,
        )),
        Op::SextB => Ok((ops.s1 as i8 as i64 as u64, 0)),
        Op::SextH => Ok((ops.s1 as i16 as i64 as u64, 0)),
        Op::ZextH => Ok((ops.s1 & 0xffff, 0)),
        // Zbs — single-bit instructions
        Op::Bclr => Ok((ops.s1 & !(1 << (ops.s2 & 63)), 0)),
        Op::Bclri => Ok((ops.s1 & !(1 << (uop.imm & 63)), 0)),
        Op::Bext => Ok(((ops.s1 >> (ops.s2 & 63)) & 1, 0)),
        Op::Bexti => Ok(((ops.s1 >> (uop.imm & 63)) & 1, 0)),
        Op::Binv => Ok((ops.s1 ^ (1 << (ops.s2 & 63)), 0)),
        Op::Binvi => Ok((ops.s1 ^ (1 << (uop.imm & 63)), 0)),
        Op::Bset => Ok((ops.s1 | (1 << (ops.s2 & 63)), 0)),
        Op::Bseti => Ok((ops.s1 | (1 << (uop.imm & 63)), 0)),
        Op::Clmul => {
            let mut r = 0;
            for i in 0..64 {
                if (ops.s2 >> i) & 1 == 1 {
                    r ^= ops.s1 << i;
                }
            }
            Ok((r, 0))
        }
        Op::Clmulh => {
            let mut r = 0;
            for i in 1..64 {
                if (ops.s2 >> i) & 1 == 1 {
                    r ^= ops.s1 >> (64 - i);
                }
            }
            Ok((r, 0))
        }
        Op::Clmulr => {
            let mut r = 0;
            for i in 0..64 {
                if (ops.s2 >> i) & 1 == 1 {
                    r ^= ops.s1 >> (63 - i);
                }
            }
            Ok((r, 0))
        }
        // Zicboz — zero a 64-byte cache block (cache-block-aligned address in rs1)
        Op::CboZero => {
            let base = ops.s1 & !63;
            for i in 0..8u64 {
                cpu.memop(Write, base, i * 8, 0, 8)?;
            }
            Ok((0, 0))
        }
        // Last one is a sentiel and must always be this illegal instruction
        Op::Unimp | Op::CUnimp => Err(Exception {
            trap: Trap::IllegalInstruction,
            tval: 0,
        }),
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
        let mut uop_cache = IntMap::new();
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

        cpu.run_soc(1, &mut uop_cache);

        assert_eq!(MEMORY_BASE + 4, cpu.read_pc());
        assert_eq!(1, cpu.read_register(x(1)));

        cpu.run_soc(1, &mut uop_cache);

        assert_eq!(MEMORY_BASE + 6, cpu.read_pc());
        assert_eq!(8, cpu.read_register(x(8)));
    }

    #[test]
    #[allow(clippy::match_wild_err_arm)]
    fn step_cpu() {
        let mut uop_cache = IntMap::new();
        let mut cpu = create_cpu();
        cpu.update_pc(MEMORY_BASE);
        // write non-compressed "addi a0, a0, 12" instruction
        match cpu.get_mut_mmu().store_virt_u32(MEMORY_BASE, 0xc50513) {
            Ok(()) => {}
            Err(_e) => panic!("Failed to store"),
        }
        assert_eq!(MEMORY_BASE, cpu.read_pc());
        assert_eq!(0, cpu.read_register(x(10)));
        if let Err(exc) = cpu.step_cpu(&mut uop_cache) {
            cpu.handle_exception(&exc, MEMORY_BASE);
        }
        assert_eq!(MEMORY_BASE + 4, cpu.read_pc());
        // "addi a0, a0, a12" instruction writes 12 to a0 register.
        assert_eq!(12, cpu.read_register(x(10)));
    }

    #[test]
    #[allow(clippy::match_wild_err_arm)]
    fn interrupt() {
        let mut uop_cache = IntMap::new();
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

        cpu.run_soc(1, &mut uop_cache);

        // Interrupt isn't caught because mie is disabled
        assert_eq!(MEMORY_BASE + 4, cpu.read_pc());

        cpu.update_pc(MEMORY_BASE);
        // Enable mie in mstatus
        cpu.write_csr_raw(Csr::Mstatus, 0x8);

        cpu.run_soc(1, &mut uop_cache);

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
        let mut uop_cache = IntMap::new();
        let handler_vector = 0x10000000;
        let mut cpu = create_cpu();
        // Write ECALL instruction
        match cpu.get_mut_mmu().store_virt_u32(MEMORY_BASE, 0x00000073) {
            Ok(()) => {}
            Err(_e) => panic!("Failed to store"),
        }
        cpu.write_csr_raw(Csr::Mtvec, handler_vector);
        cpu.update_pc(MEMORY_BASE);

        cpu.run_soc(1, &mut uop_cache);

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
        let mut uop_cache = IntMap::new();

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
        cpu.run_soc(1, &mut uop_cache); // Execute  "addi x0, x0, 1"
        // x0 is still zero because it's hardcoded zero
        assert_eq!(0, cpu.read_register(x(0)));

        // Test x1
        assert_eq!(0, cpu.read_register(x(1)));
        cpu.run_soc(1, &mut uop_cache); // Execute  "addi x1, x1, 1"
        // x1 is not hardcoded zero
        assert_eq!(1, cpu.read_register(x(1)));
    }
}
