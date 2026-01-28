//! The RISC-V CPU core, which handles instruction fetching, decoding, and
//! execution.

// It's the nature of emulator code to trigger Clippy's neurosis
#![allow(clippy::unreadable_literal)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]

use crate::bounded::Bounded;
use crate::csr;
use crate::dag_decoder;
use crate::fp;
use crate::fp::fflag::DIVIDEZERO;
use crate::mmu::Mmu;
use crate::native_fp;
use crate::riscv;
use crate::rvc;
use crate::terminal;
use anyhow::bail;
pub use csr::*;
use fp::RoundingMode;
use fp::Sf;
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
use terminal::Terminal;

pub type Reg = Bounded<65>;

#[derive(Debug, PartialEq, Eq)]
pub struct Exception {
    pub trap: Trap,
    pub tval: u64,
}

pub type ExecResult = Result<(u64, u8), Exception>;
pub type ExecFn = fn(cpu: &mut Cpu, uop: &Uop, ops: Operands) -> ExecResult;
pub type DecodeFn = fn(addr: u64, word: u32, exec: ExecFn) -> Uop;

/// The decoded instruction, convenient for execution
// XXX Needs Seqno, ctf_target_opt
// XXX ctf, exceptional, serialize (and more?) should be combined into a classification represented
// as an enum. We also want to easily distinguish ALU, ALUFP, CTF, LOAD, STORE, ATOMIC, SYSTEM, ...?
#[derive(Debug, Clone, Copy)]
pub struct Uop {
    /// Destination Register
    pub rd: Reg,
    /// Source Register 1
    pub rs1: Reg,
    /// Source Register 2
    pub rs2: Reg,
    /// Source Register 3
    pub rs3: Reg,
    /// Immediate field (imm, csrno, or shift amount)
    pub imm: u64,
    /// FP Rounding Mode
    pub rm: u8,
    /// May change the Control Flow
    pub ctf: bool,
    /// May throw exception (ecall/ebreak are guaranteed to)
    pub exceptional: bool,
    /// Serialized instructions cannot execute out-of-order and
    /// almost certainly change system state
    pub serialize: bool,
    /// Size of the original instruction
    pub insn_size: u8,
    /// Execute function for this instruction
    pub execute: ExecFn,
}

impl PartialEq for Uop {
    fn eq(&self, other: &Self) -> bool {
        self.rd == other.rd
            && self.rs1 == other.rs1
            && self.rs2 == other.rs2
            && self.rs3 == other.rs3
            && self.imm == other.imm
            && self.rm == other.rm
            && self.ctf == other.ctf
            && self.exceptional == other.exceptional
            && self.serialize == other.serialize
            && self.insn_size == other.insn_size
        /* && self.execute == other.execute sadly */
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
// - wfi, seqno, insn_addr, insn, and decode_dag are artifacts of the VM
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
    csr: Box<[u64]>, // XXX this should be replaced with individual registers
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

    // Decoding table
    // XXX needn't be part of CPU state; is part of decode
    pub decode_dag: Vec<u16>,
}

#[allow(clippy::type_complexity)]
/// Instruction specification
#[derive(Debug)]
pub struct RVInsnSpec {
    pub name: &'static str,
    pub mask: u32,
    pub bits: u32,
    pub decode: DecodeFn,
    pub disassemble: fn(s: &mut String, cpu: &Cpu, address: u64, word: u32, evaluate: bool),
    pub execute: ExecFn, // Still stored here for passing to decode
}

struct FormatB {
    rs1: Reg,
    rs2: Reg,
    imm: u64,
}

struct FormatCSR {
    csr: u16,
    rs1: Reg,
    rd: Reg,
}

struct FormatI {
    rd: Reg,
    rs1: Reg,
    imm: u64,
}

struct FormatJ {
    rd: Reg,
    imm: u64,
}

#[derive(Debug)]
struct FormatR {
    rd: Reg,
    funct3: usize,
    rs1: Reg,
    rs2: Reg,
}

struct FormatRShift {
    rd: Reg,
    rs1: Reg,
    imm: u8,
}

struct FormatS {
    rs1: Reg,
    rs2: Reg,
    imm: u64,
}

struct FormatU {
    rd: Reg,
    imm: u64,
}

// has rs3
struct FormatR2 {
    rd: Reg,
    rm: u8,
    rs1: Reg,
    rs2: Reg,
    rs3: Reg,
}

pub const CONFIG_SW_MANAGED_A_AND_D: bool = false;
pub const PG_SHIFT: usize = 12; // 4K page size
const ZEROREG: Reg = Reg::new(0);
const NODESTREG: Reg = Reg::new(64);
const INSTRUCTION_NUM: usize = 173;

impl Reg {
    #[must_use]
    pub const fn is_x0_dest(self) -> bool { self.get() == 64 }
}

// Default Uop needs a default execute function
fn default_execute(_cpu: &mut Cpu, _uop: &Uop, _ops: Operands) -> ExecResult { unreachable!() }

impl Default for Uop {
    fn default() -> Self {
        Self {
            rd: NODESTREG,
            rs1: ZEROREG,
            rs2: ZEROREG,
            rs3: ZEROREG,
            imm: 0,
            rm: 0,
            ctf: false,
            exceptional: false,
            serialize: false,
            insn_size: 0,
            execute: default_execute,
        }
    }
}

impl Cpu {
    /// Creates a new `Cpu`.
    ///
    /// # Arguments
    /// * `Terminal` (for the UART)
    /// * memory `capacity`
    // XXX This is not great.  We should instead give given an MMIO object and
    // a memory device. This file shouldn't even need to know about
    // "terminals" and the memory object needn't be a single contigous range.
    #[must_use]
    #[allow(clippy::precedence)]
    pub fn new(terminal: Box<dyn Terminal>, capacity: usize) -> Self {
        let mut patterns = Vec::new();
        for (p, insn) in INSTRUCTIONS[0..INSTRUCTION_NUM - 1].iter().enumerate() {
            patterns.push((insn.mask & !3, insn.bits & !3, p));
        }

        let mut mmu = Mmu::new(terminal);
        mmu.init_memory(capacity);

        let mut cpu = Self {
            rf: [0; 65],
            frm: RoundingMode::RoundNearestEven,
            fflags: 0,
            fs: 1,

            seqno: 0,
            cycle: 0,
            wfi: false,
            pc: 0,
            csr: vec![0; 4096].into_boxed_slice(), // XXX MUST GO AWAY SOON
            mmu,
            reservation: None,
            flush_icache: false,
            decode_dag: dag_decoder::new(&patterns),
        };
        log::info!("FDT is {} entries", cpu.decode_dag.len());
        cpu.csr[Csr::Misa as usize] = 1 << 63; // RV64
        for c in "SUIMAFDC".bytes() {
            cpu.csr[Csr::Misa as usize] |= 1 << (c as usize - 65);
        }
        cpu.mmu.mstatus = 2 << MSTATUS_UXL_SHIFT | 2 << MSTATUS_SXL_SHIFT | 3 << MSTATUS_MPP_SHIFT;
        cpu.write_x(x(11), 0x1020); // start of DTB (XXX could put that elsewhere);
        cpu
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
        self.handle_interrupt();

        false
    }

    // It's here, the One Key Function.  This is where it all happens!
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    fn step_cpu(&mut self, uop_cache: &mut IntMap<u64, Uop>) -> Result<(), Exception> {
        self.cycle = self.cycle.wrapping_add(1);
        if self.wfi {
            if self.mmu.mip & self.read_csr_raw(Csr::Mie) != 0 {
                self.wfi = false;
            }
            return Ok(());
        }

        if self.flush_icache {
            log::debug!("uop cache flush");
            uop_cache.clear();
            self.flush_icache = false;
        }

        self.seqno = self.seqno.wrapping_add(1);
        let insn_addr = self.pc;

        // XXX refactoring needed
        if let Some(uop) = uop_cache.get(insn_addr) {
            //log::debug!("uop cache {insn_addr:x} hit");

            self.pc += u64::from(uop.insn_size);

            let ops = Operands {
                s1: self.read_x(uop.rs1),
                s2: self.read_x(uop.rs2),
                s3: self.read_x(uop.rs3),
            };
            let (res, fflags) = (uop.execute)(self, uop, ops)?;
            self.write_x(uop.rd, res);
            self.add_to_fflags(fflags);
        } else {
            // XXX For full correctness we mustn't fail if we _can_ fetch 16-bit
            // _and_ it turns out to be a legal instruction.
            let word = self.memop(Execute, insn_addr, 0, 0, 4)?;

            let (insn, insn_size) = decompress(word as u32);
            self.pc += u64::from(insn_size);

            let Some(decoded) = decode(&self.decode_dag, insn) else {
                return Err(Exception {
                    trap: Trap::IllegalInstruction,
                    tval: word,
                });
            };

            let mut uop = (decoded.decode)(insn_addr, insn, decoded.execute);
            uop.insn_size = insn_size;
            uop_cache.insert(insn_addr, uop);

            let ops = Operands {
                s1: self.read_x(uop.rs1),
                s2: self.read_x(uop.rs2),
                s3: self.read_x(uop.rs3),
            };
            let (res, fflags) = (uop.execute)(self, &uop, ops)?;
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
        let minterrupt = self.mmu.mip & self.read_csr_raw(Csr::Mie);
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
            self.read_csr_raw(Csr::Mideleg)
        } else {
            self.read_csr_raw(Csr::Medeleg)
        };
        let sdeleg = if is_interrupt {
            self.read_csr_raw(Csr::Sideleg)
        } else {
            self.read_csr_raw(Csr::Sedeleg)
        };
        let pos = cause & 0xffff;

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
                PrivMode::U => self.read_csr_raw(Csr::Ustatus),
            };

            let ie = match new_priv_mode {
                PrivMode::M => self.read_csr_raw(Csr::Mie),
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
                Trap::UserSoftwareInterrupt => {
                    if usie == 0 {
                        return false;
                    }
                }
                Trap::SupervisorSoftwareInterrupt => {
                    if ssie == 0 {
                        return false;
                    }
                }
                Trap::MachineSoftwareInterrupt => {
                    if msie == 0 {
                        return false;
                    }
                }
                Trap::UserTimerInterrupt => {
                    if utie == 0 {
                        return false;
                    }
                }
                Trap::SupervisorTimerInterrupt => {
                    if stie == 0 {
                        return false;
                    }
                }
                Trap::MachineTimerInterrupt => {
                    if mtie == 0 {
                        return false;
                    }
                }
                Trap::UserExternalInterrupt => {
                    if ueie == 0 {
                        return false;
                    }
                }
                Trap::SupervisorExternalInterrupt => {
                    if seie == 0 {
                        return false;
                    }
                }
                Trap::MachineExternalInterrupt => {
                    if meie == 0 {
                        return false;
                    }
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
        let csr_tvec_address = match self.mmu.prv {
            PrivMode::M => Csr::Mtvec,
            PrivMode::S => Csr::Stvec,
            PrivMode::U => Csr::Utvec,
        };

        self.write_csr_raw(csr_epc_address, insn_addr);
        self.write_csr_raw(csr_cause_address, cause);
        self.write_csr_raw(csr_tval_address, exc.tval);
        self.pc = self.read_csr_raw(csr_tvec_address);

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

        let Some(csr) = self.has_csr_access_privilege(csrno) else {
            return illegal;
        };

        match csr {
            Csr::Fflags | Csr::Frm | Csr::Fcsr => self.check_float_access_ro(0)?,
            Csr::Satp => {
                if self.mmu.prv == S && self.mmu.mstatus & MSTATUS_TVM != 0 {
                    return illegal;
                }
            }
            _ => {}
        }
        Ok(self.read_csr_raw(csr))
    }

    #[allow(clippy::cast_sign_loss)]
    fn write_csr(&mut self, csrno: u16, value: u64) -> Result<(), Exception> {
        let mut value = value;
        let illegal = Err(Exception {
            trap: Trap::IllegalInstruction,
            tval: 0,
        });

        let Some(csr) = self.has_csr_access_privilege(csrno) else {
            return illegal;
        };

        if (csrno >> 10) & 3 == 3 {
            log::warn!("Write attempted to Read Only CSR {csrno:03x}");
            return illegal;
        }

        match csr {
            Csr::Mstatus => {
                let mask = MSTATUS_MASK & !(MSTATUS_VS | MSTATUS_UXL_MASK | MSTATUS_SXL_MASK);
                value = value & mask | self.mmu.mstatus & !mask;
            }
            Csr::Fflags | Csr::Frm | Csr::Fcsr => self.check_float_access_and_dirty(0)?,
            Csr::Cycle => {
                log::info!("** deny cycle writing");
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
            }
            _ => {}
        }

        self.write_csr_raw(csr, value);
        Ok(())
    }

    // SSTATUS, SIE, and SIP are subsets of MSTATUS, MIE, and MIP
    #[allow(clippy::cast_sign_loss)]
    fn read_csr_raw(&self, csr: Csr) -> u64 {
        match csr {
            Csr::Fflags => u64::from(self.read_fflags()),
            Csr::Frm => self.read_frm() as u64,
            Csr::Fcsr => self.read_fcsr(),
            Csr::Sstatus => {
                let mut sstatus = self.mmu.mstatus;
                sstatus &= !MSTATUS_FS;
                sstatus |= u64::from(self.fs) << MSTATUS_FS_SHIFT;
                sstatus &= 0x8000_0003_000d_e162;
                if self.fs == 3 {
                    sstatus |= 1 << 63;
                }
                sstatus
            }
            Csr::Mstatus => {
                let mut mstatus = self.mmu.mstatus;
                mstatus &= !MSTATUS_FS;
                mstatus |= u64::from(self.fs) << MSTATUS_FS_SHIFT;
                if self.fs == 3 {
                    mstatus |= 1 << 63;
                }
                mstatus
            }
            Csr::Sie => self.csr[Csr::Mie as usize] & self.csr[Csr::Mideleg as usize],
            Csr::Sip => self.mmu.mip & self.csr[Csr::Mideleg as usize],
            Csr::Mip => self.mmu.mip,
            Csr::Time => self.mmu.get_clint().read_mtime(),
            Csr::Cycle | Csr::Mcycle | Csr::Minstret => self.cycle,
            Csr::Satp => self.mmu.satp,
            _ => self.csr[csr as usize],
        }
    }

    fn write_csr_raw(&mut self, csr: Csr, value: u64) {
        match csr {
            Csr::Misa => {} // Not writable
            Csr::Fflags => self.write_fflags((value & 31) as u8),
            Csr::Frm => self.write_frm(
                FromPrimitive::from_u64(value & 7).unwrap_or(RoundingMode::RoundNearestEven),
            ),
            Csr::Fcsr => self.write_fcsr(value),
            Csr::Sstatus => {
                self.mmu.mstatus &= !0x8000_0003_000d_e162;
                self.mmu.mstatus |= value & 0x8000_0003_000d_e162;
                self.fs = ((value >> MSTATUS_FS_SHIFT) & 3) as u8;
            }
            Csr::Sie => {
                self.csr[Csr::Mie as usize] &= !0x222;
                self.csr[Csr::Mie as usize] |= value & 0x222;
            }
            Csr::Sip => {
                let mask = 0x222;
                self.mmu.mip = value & mask | self.mmu.mip & !mask;
            }
            Csr::Mip => {
                let mask = !0; // XXX 0x555 was too restrictive?? Stopped Ubuntu booting
                self.mmu.mip = value & mask | self.mmu.mip & !mask;
            }
            Csr::Mideleg => {
                self.csr[Csr::Mideleg as usize] = value & 0x222;
            }
            Csr::Mstatus => {
                self.mmu.mstatus = value;
                self.fs = ((value >> MSTATUS_FS_SHIFT) & 3) as u8;
            }
            Csr::Time => {
                // XXX This should trap actually
                self.mmu.get_mut_clint().write_mtime(value);
            }
            Csr::Satp => {
                self.mmu.satp = value;
                self.mmu.clear_page_cache();
            }
            /* Csr::Cycle | */ Csr::Mcycle => self.cycle = value,
            _ => {
                self.csr[csr as usize] = value;
            }
        }
    }

    /// Disassembles an instruction pointed by Program Counter and
    /// and return the [possibly] writeback register
    #[allow(clippy::cast_sign_loss)]
    pub fn disassemble_insn(&self, s: &mut String, addr: u64, mut word32: u32, eval: bool) {
        let (insn, _) = decompress(word32);
        let Some(decoded) = decode(&self.decode_dag, insn) else {
            let _ = write!(s, "{addr:16x} {word32:8x} Illegal instruction");
            return;
        };

        let asm = decoded.name.to_lowercase();

        if word32 % 4 == 3 {
            let _ = write!(s, "{addr:16x} {word32:08x} {asm:7} ");
        } else {
            word32 &= 0xffff;
            let _ = write!(s, "{addr:16x} {word32:04x}     {asm:7} ");
        }
        (decoded.disassemble)(s, self, addr, insn, eval);
    }

    #[allow(clippy::cast_sign_loss)]
    pub fn disassemble(&mut self, s: &mut String) {
        let Ok(word32) = self.memop_disass(self.pc) else {
            let _ = write!(s, "{:016x} <inaccessible>", self.pc);
            return;
        };

        self.disassemble_insn(s, self.pc, (word32 & 0xFFFFFFFF) as u32, true);
    }

    /// Returns mutable `Mmu`
    pub const fn get_mut_mmu(&mut self) -> &mut Mmu { &mut self.mmu }

    /// Returns mutable `Terminal`
    pub fn get_mut_terminal(&mut self) -> &mut Box<dyn Terminal> {
        self.mmu.get_mut_uart().get_mut_terminal()
    }

    fn read_f(&self, r: Reg) -> u64 {
        assert!(32 <= r.get() && r.get() < 64);
        assert_ne!(self.fs, 0);
        self.rf[r]
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

        let Ok(slice) = self.mmu.memory.slice(pa, size as usize) else {
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
            if let Ok(slice) = self.mmu.memory.slice(pa, 1) {
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

#[inline]
#[must_use]
pub const fn decompress(insn: u32) -> (u32, u8) {
    if insn & 3 == 3 {
        (insn, 4)
    } else {
        let insn = rvc::RVC64_EXPANDED[insn as usize & 0xffff];
        (insn, 2)
    }
}

#[must_use]
pub const fn decode(fdt: &[u16], word: u32) -> Option<&RVInsnSpec> {
    let inst = &INSTRUCTIONS[dag_decoder::patmatch(fdt, word)];
    if word & inst.mask == inst.bits {
        Some(inst)
    } else {
        None
    }
}

/// Generate a source integer `Reg`
/// # Panics
/// Trying to name a register > 31
#[must_use]
pub fn x(r: u32) -> Reg {
    assert!(r < 32);
    Reg::new(r)
}

/// Generate a destination integer `Reg`
/// # Panics
/// Trying to name a register > 31
#[must_use]
pub fn xd(r: u32) -> Reg {
    assert!(r < 32);
    // Remap x0 to the dummy location 64.  This turns the write into
    // branch-free code, but the real payoff will come later when we
    // amortize this
    Reg::new(((r + 63) & 63) + 1)
}

/// Generate a source or destination floating point `Reg`
/// # Panics
/// Trying to name a register > 31
#[must_use]
pub fn f(r: u32) -> Reg {
    assert!(r < 32);
    Reg::new(r + 32)
}

#[allow(clippy::cast_sign_loss, clippy::cast_lossless)]
fn parse_format_b(word: u32) -> FormatB {
    let iword = word as i32;
    FormatB {
        rs1: x((word >> 15) & 0x1f), // [19:15]
        rs2: x((word >> 20) & 0x1f), // [24:20]
        imm: (iword >> 31 << 12 | // imm[31:12] = [31]
            ((iword << 4) & 0x0000_0800) | // imm[11] = [7]
            ((iword >> 20) & 0x0000_07e0) | // imm[10:5] = [30:25]
            ((iword >> 7) & 0x0000_001e)) as u64, // imm[4:1] = [11:8]
    }
}

fn disassemble_b(s: &mut String, cpu: &Cpu, address: u64, word: u32, evaluate: bool) {
    let f = parse_format_b(word);
    *s += get_register_name(f.rs1);
    if evaluate && f.rs1.get() != 0 {
        let _ = write!(s, ":{:x}", cpu.read_x(f.rs1));
    }
    let _ = write!(s, ", {}", get_register_name(f.rs2));
    if evaluate && f.rs2.get() != 0 {
        let _ = write!(s, ":{:x}", cpu.read_x(f.rs2));
    }
    let _ = write!(s, ", {:x}", address.wrapping_add(f.imm));
}

fn decode_empty(_addr: u64, _word: u32, execute: ExecFn) -> Uop {
    Uop {
        execute,
        ..Uop::default()
    }
}

fn decode_b(addr: u64, word: u32, execute: ExecFn) -> Uop {
    let f = parse_format_b(word);
    Uop {
        rs1: f.rs1,
        rs2: f.rs2,
        imm: addr.wrapping_add(f.imm),
        ctf: true,
        execute,
        ..Uop::default()
    }
}

fn parse_format_csr(word: u32) -> FormatCSR {
    FormatCSR {
        csr: ((word >> 20) & 0xfff) as u16, // [31:20]
        rs1: x((word >> 15) & 0x1f),        // [19:15], also uimm
        rd: xd((word >> 7) & 0x1f),         // [11:7]
    }
}

#[allow(clippy::option_if_let_else)] // Clippy is loosing it
fn disassemble_csr(s: &mut String, cpu: &Cpu, _address: u64, word: u32, evaluate: bool) {
    let f = parse_format_csr(word);
    *s += get_register_name(f.rd);
    let _ = write!(s, ", ");

    let csr: Option<Csr> = FromPrimitive::from_u16(f.csr);
    let csr_s = if let Some(csr) = csr {
        format!("{csr}").to_lowercase()
    } else {
        format!("csr{:03x}", f.csr)
    };

    if evaluate {
        let _ = match FromPrimitive::from_u16(f.csr) {
            Some(csr) => {
                write!(s, "{csr_s}:{:x}", cpu.read_csr_raw(csr))
            }
            None => {
                write!(s, "{csr_s}")
            }
        };
    } else {
        let _ = write!(s, "{csr_s}");
    }

    let _ = write!(s, ", {}", get_register_name(f.rs1));
    if evaluate && f.rs1.get() != 0 {
        let _ = write!(s, ":{:x}", cpu.read_x(f.rs1));
    }
}

#[allow(clippy::option_if_let_else)] // Clippy is loosing it
fn disassemble_csri(s: &mut String, cpu: &Cpu, _address: u64, word: u32, evaluate: bool) {
    let f = parse_format_csr(word);
    *s += get_register_name(f.rd);
    let _ = write!(s, ", ");

    let csr: Option<Csr> = FromPrimitive::from_u16(f.csr);
    let csr_s = if let Some(csr) = csr {
        format!("{csr}").to_lowercase()
    } else {
        format!("csr{:03x}", f.csr)
    };

    if evaluate {
        let _ = match FromPrimitive::from_u16(f.csr) {
            Some(csr) => {
                write!(s, "{csr_s}:{:x}", cpu.read_csr_raw(csr))
            }
            None => {
                write!(s, "{csr_s}")
            }
        };
    } else {
        let _ = write!(s, "{csr_s}");
    }

    let _ = write!(s, ", {}", f.rs1.get());
}

fn decode_csr(_addr: u64, word: u32, execute: ExecFn) -> Uop {
    let f = parse_format_csr(word);
    Uop {
        rd: f.rd,
        rs1: f.rs1,
        imm: u64::from(f.csr),
        serialize: true,
        execute,
        ..Uop::default()
    }
}

fn decode_csri(_addr: u64, word: u32, execute: ExecFn) -> Uop {
    let f = parse_format_csr(word); // uimm is not a register read
    Uop {
        rd: f.rd,
        rs1: f.rs1,
        imm: u64::from(f.csr),
        serialize: true,
        execute,
        ..Uop::default()
    }
}

#[allow(clippy::cast_lossless)]
fn parse_format_i(word: u32) -> FormatI {
    FormatI {
        rd: xd((word >> 7) & 0x1f),        // [11:7]
        rs1: x((word >> 15) & 0x1f),       // [19:15]
        imm: ((word as i32) >> 20) as u64, // [31:20]
    }
}

#[allow(clippy::cast_lossless)]
fn parse_format_i_fx(word: u32) -> FormatI {
    FormatI {
        rd: f((word >> 7) & 0x1f),         // [11:7]
        rs1: x((word >> 15) & 0x1f),       // [19:15]
        imm: ((word as i32) >> 20) as u64, // [31:20]
    }
}

fn disassemble_i(s: &mut String, cpu: &Cpu, _address: u64, word: u32, evaluate: bool) {
    let f = parse_format_i(word);
    *s += get_register_name(f.rd);
    let _ = write!(s, ", {}", get_register_name(f.rs1));
    if evaluate && f.rs1.get() != 0 {
        let _ = write!(s, ":{:x}", cpu.read_x(f.rs1));
    }
    let _ = write!(s, ", {:x}", f.imm);
}

fn disassemble_i_mem(s: &mut String, cpu: &Cpu, _address: u64, word: u32, evaluate: bool) {
    let f = parse_format_i(word);
    *s += get_register_name(f.rd);
    let _ = write!(s, ", {:x}({}", f.imm, get_register_name(f.rs1));
    if evaluate && f.rs1.get() != 0 {
        let _ = write!(s, ":{:x}", cpu.read_x(f.rs1));
    }
    *s += ")";
}

fn decode_i(_addr: u64, word: u32, execute: ExecFn) -> Uop {
    let f = parse_format_i(word);
    Uop {
        rd: f.rd,
        rs1: f.rs1,
        imm: f.imm,
        execute,
        ..Uop::default()
    }
}

fn decode_i_fx(_addr: u64, word: u32, execute: ExecFn) -> Uop {
    let f = parse_format_i_fx(word);
    Uop {
        rd: f.rd,
        rs1: f.rs1,
        imm: f.imm,
        execute,
        ..Uop::default()
    }
}

#[allow(clippy::cast_lossless)]
fn parse_format_j(word: u32) -> FormatJ {
    let iword = word as i32;
    FormatJ {
        rd: xd((word >> 7) & 0x1f), // [11:7]
        imm: (iword >> 31 << 20 | // imm[31:20] = [31]
             (iword & 0x000f_f000) | // imm[19:12] = [19:12]
             ((iword & 0x0010_0000) >> 9) | // imm[11] = [20]
             ((iword & 0x7fe0_0000) >> 20)) as u64, // imm[10:1] = [30:21]
    }
}

fn disassemble_j(s: &mut String, _cpu: &Cpu, address: u64, word: u32, _evaluate: bool) {
    let f = parse_format_j(word);
    *s += get_register_name(f.rd);
    let _ = write!(s, ", {:x}", address.wrapping_add(f.imm));
}

fn decode_j(addr: u64, word: u32, execute: ExecFn) -> Uop {
    let f = parse_format_j(word);
    Uop {
        rd: f.rd,
        ctf: true,
        imm: addr.wrapping_add(f.imm),
        execute,
        ..Uop::default()
    }
}

fn parse_format_r(word: u32) -> FormatR {
    FormatR {
        rd: xd((word >> 7) & 0x1f),          // [11:7]
        funct3: ((word >> 12) & 7) as usize, // [14:12]
        rs1: x((word >> 15) & 0x1f),         // [19:15]
        rs2: x((word >> 20) & 0x1f),         // [24:20]
    }
}

#[allow(clippy::cast_possible_truncation)]
fn parse_format_r_shift(word: u32) -> FormatRShift {
    FormatRShift {
        rd: xd((word >> 7) & 0x1f),     // [11:7]
        rs1: x((word >> 15) & 0x1f),    // [19:15]
        imm: (word >> 20) as u8 & 0x3f, // [25:20]
    }
}

fn parse_format_r_xf(word: u32) -> FormatR {
    FormatR {
        rd: xd((word >> 7) & 0x1f),          // [11:7]
        funct3: ((word >> 12) & 7) as usize, // [14:12]
        rs1: f((word >> 15) & 0x1f),         // [19:15]
        rs2: x((word >> 20) & 0x1f),         // [24:20]
    }
}

fn parse_format_r_xff(word: u32) -> FormatR {
    FormatR {
        rd: xd((word >> 7) & 0x1f),          // [11:7]
        funct3: ((word >> 12) & 7) as usize, // [14:12]
        rs1: f((word >> 15) & 0x1f),         // [19:15]
        rs2: f((word >> 20) & 0x1f),         // [24:20]
    }
}

fn parse_format_r_fx(word: u32) -> FormatR {
    FormatR {
        rd: f((word >> 7) & 0x1f),           // [11:7]
        funct3: ((word >> 12) & 7) as usize, // [14:12]
        rs1: x((word >> 15) & 0x1f),         // [19:15]
        rs2: x((word >> 20) & 0x1f),         // [24:20]
    }
}

fn parse_format_r_fff(word: u32) -> FormatR {
    FormatR {
        rd: f((word >> 7) & 0x1f),           // [11:7]
        funct3: ((word >> 12) & 7) as usize, // [14:12]
        rs1: f((word >> 15) & 0x1f),         // [19:15]
        rs2: f((word >> 20) & 0x1f),         // [24:20]
    }
}

fn disassemble_r(s: &mut String, cpu: &Cpu, _address: u64, word: u32, evaluate: bool) {
    let f = parse_format_r(word);
    *s += get_register_name(f.rd);
    let _ = write!(s, ", ");
    *s += get_register_name(f.rs1);
    if evaluate && f.rs1.get() != 0 {
        let _ = write!(s, ":{:x}", cpu.read_x(f.rs1));
    }
    let _ = write!(s, ", {}", get_register_name(f.rs2));
    if evaluate && f.rs2.get() != 0 {
        let _ = write!(s, ":{:x}", cpu.read_x(f.rs2));
    }
}

fn decode_r(_addr: u64, word: u32, execute: ExecFn) -> Uop {
    let f = parse_format_r(word);
    Uop {
        rd: f.rd,
        rs1: f.rs1,
        rs2: f.rs2,
        execute,
        ..Uop::default()
    }
}

fn decode_r_xf(_addr: u64, word: u32, execute: ExecFn) -> Uop {
    let f = parse_format_r_xf(word);
    Uop {
        rd: f.rd,
        rs1: f.rs1,
        execute,
        ..Uop::default()
    }
}

fn decode_r_xff(_addr: u64, word: u32, execute: ExecFn) -> Uop {
    let f = parse_format_r_xff(word);
    Uop {
        rd: f.rd,
        rs1: f.rs1,
        rs2: f.rs2,
        execute,
        ..Uop::default()
    }
}

fn decode_r_fx(_addr: u64, word: u32, execute: ExecFn) -> Uop {
    let f = parse_format_r_fx(word);
    #[allow(clippy::cast_possible_truncation)]
    Uop {
        rd: f.rd,
        rs1: f.rs1,
        rm: (f.funct3 & 7) as u8,
        execute,
        ..Uop::default()
    }
}

fn decode_r_fff(_addr: u64, word: u32, execute: ExecFn) -> Uop {
    let f = parse_format_r_fff(word);
    #[allow(clippy::cast_possible_truncation)]
    Uop {
        rd: f.rd,
        rs1: f.rs1,
        rs2: f.rs2,
        rm: (f.funct3 & 7) as u8,
        execute,
        ..Uop::default()
    }
}

fn disassemble_ri(s: &mut String, cpu: &Cpu, _address: u64, word: u32, evaluate: bool) {
    let f = parse_format_r(word);
    *s += get_register_name(f.rd);
    let _ = write!(s, ", ");
    *s += get_register_name(f.rs1);
    if evaluate && f.rs1.get() != 0 {
        let _ = write!(s, ":{:x}", cpu.read_x(f.rs1));
    }
    let shamt = (word >> 20) & 63;
    let _ = write!(s, ", {shamt}");
}

fn decode_r_shift(_addr: u64, word: u32, execute: ExecFn) -> Uop {
    let f = parse_format_r_shift(word);
    Uop {
        rd: f.rd,
        rs1: f.rs1,
        imm: u64::from(f.imm),
        execute,
        ..Uop::default()
    }
}

fn disassemble_r_f(s: &mut String, cpu: &Cpu, _address: u64, word: u32, evaluate: bool) {
    let f = parse_format_r(word);
    let _ = write!(s, "{}, ", get_register_name(f.rd));
    *s += get_register_name(f.rs1);
    if evaluate && f.rs1.get() != 0 {
        let _ = write!(s, ":{:x}", cpu.read_x(f.rs1));
    }
    let _ = write!(s, ", {}", get_register_name(f.rs2));
    if evaluate && f.rs2.get() != 0 {
        let _ = write!(s, ":{:x}", cpu.read_x(f.rs2));
    }
}

fn parse_format_r2_ffff(word: u32) -> FormatR2 {
    FormatR2 {
        rd: f((word >> 7) & 0x1f),    // [11:7]
        rm: ((word >> 12) & 7) as u8, // [14:12]
        rs1: f((word >> 15) & 0x1f),  // [19:15]
        rs2: f((word >> 20) & 0x1f),  // [24:20]
        rs3: f((word >> 27) & 0x1f),  // [31:27]
    }
}

fn disassemble_r2_ffff(s: &mut String, cpu: &Cpu, _address: u64, word: u32, evaluate: bool) {
    let f = parse_format_r2_ffff(word);
    *s += get_register_name(f.rd);
    let _ = write!(s, ", {}", get_register_name(f.rs1));
    if evaluate {
        let _ = write!(s, ":{:x}", cpu.read_f(f.rs1));
    }
    let _ = write!(s, ", {}", get_register_name(f.rs2));
    if evaluate {
        let _ = write!(s, ":{:x}", cpu.read_f(f.rs2));
    }
    let _ = write!(s, ", {}", get_register_name(f.rs3));
    if evaluate {
        let _ = write!(s, ":{:x}", cpu.read_f(f.rs3));
    }
}

fn decode_r2_ffff(_addr: u64, word: u32, execute: ExecFn) -> Uop {
    let f = parse_format_r2_ffff(word);
    Uop {
        rd: f.rd,
        rs1: f.rs1,
        rs2: f.rs2,
        rs3: f.rs3,
        rm: f.rm,
        execute,
        ..Uop::default()
    }
}

#[allow(clippy::cast_lossless)]
fn parse_format_s(word: u32) -> FormatS {
    FormatS {
        rs1: x((word >> 15) & 0x1f), // [19:15]
        rs2: x((word >> 20) & 0x1f), // [24:20]
        imm: (
            // XXX fix this mess
            match word & 0x80000000 {
                                0x80000000 => 0xfffff000,
                                _ => 0
                        } | // imm[31:12] = [31]
                        ((word >> 20) & 0xfe0) | // imm[11:5] = [31:25]
                        ((word >> 7) & 0x1f)
            // imm[4:0] = [11:7]
        ) as i32 as u64,
    }
}

#[allow(clippy::cast_lossless)]
fn parse_format_s_xf(word: u32) -> FormatS {
    FormatS {
        rs1: x((word >> 15) & 0x1f), // [19:15]
        rs2: f((word >> 20) & 0x1f), // [24:20]
        imm: (
            // XXX fix this mess
            match word & 0x80000000 {
                                0x80000000 => 0xfffff000,
                                _ => 0
                        } | // imm[31:12] = [31]
                        ((word >> 20) & 0xfe0) | // imm[11:5] = [31:25]
                        ((word >> 7) & 0x1f)
            // imm[4:0] = [11:7]
        ) as i32 as u64,
    }
}

fn disassemble_s(s: &mut String, cpu: &Cpu, _address: u64, word: u32, evaluate: bool) {
    let f = parse_format_s(word);
    *s += get_register_name(f.rs2);
    if evaluate && f.rs2.get() != 0 {
        let _ = write!(s, ":{:x}", cpu.read_x(f.rs2));
    }
    let _ = write!(s, ", {:x}({}", f.imm, get_register_name(f.rs1));
    if evaluate && f.rs1.get() != 0 {
        let _ = write!(s, ":{:x}", cpu.read_x(f.rs1));
    }
    *s += ")";
}

fn decode_s(_addr: u64, word: u32, execute: ExecFn) -> Uop {
    let f = parse_format_s(word);
    Uop {
        rs1: f.rs1,
        rs2: f.rs2,
        imm: f.imm,
        execute,
        ..Uop::default()
    }
}

fn decode_s_xf(_addr: u64, word: u32, execute: ExecFn) -> Uop {
    let f = parse_format_s_xf(word);
    Uop {
        rs1: f.rs1,
        rs2: f.rs2,
        imm: f.imm,
        execute,
        ..Uop::default()
    }
}

#[allow(clippy::cast_lossless)]
fn parse_format_u(word: u32) -> FormatU {
    FormatU {
        rd: xd((word >> 7) & 31), // [11:7]
        imm: (word & 0xfffff000) as i32 as u64,
    }
}

fn disassemble_u(s: &mut String, _cpu: &Cpu, _address: u64, word: u32, _evaluate: bool) {
    let f = parse_format_u(word);
    *s += get_register_name(f.rd);
    let _ = write!(s, ", {:x}", f.imm);
}

#[allow(clippy::ptr_arg)] // Clippy can't tell that we can't change the function type
const fn disassemble_empty(
    _s: &mut String,
    _cpu: &Cpu,
    _address: u64,
    _word: u32,
    _evaluate: bool,
) {
}

fn disassemble_jalr(s: &mut String, cpu: &Cpu, _address: u64, word: u32, evaluate: bool) {
    let f = parse_format_i(word);
    *s += get_register_name(f.rd);
    let _ = write!(s, ", {:x}({}", f.imm, get_register_name(f.rs1));
    if evaluate && f.rs1.get() != 0 {
        let _ = write!(s, ":{:x}", cpu.read_x(f.rs1));
    }
    *s += ")";
}

fn decode_u(_addr: u64, word: u32, execute: ExecFn) -> Uop {
    let f = parse_format_u(word);
    Uop {
        rd: f.rd,
        imm: f.imm,
        execute,
        ..Uop::default()
    }
}

fn decode_auipc(addr: u64, word: u32, execute: ExecFn) -> Uop {
    let f = parse_format_u(word);
    Uop {
        rd: f.rd,
        imm: addr.wrapping_add(f.imm),
        execute,
        ..Uop::default()
    }
}

fn decode_serialized(_addr: u64, _word: u32, execute: ExecFn) -> Uop {
    Uop {
        ctf: true,
        serialize: true,
        execute,
        ..Uop::default()
    }
}

fn decode_exceptional(_addr: u64, _word: u32, execute: ExecFn) -> Uop {
    Uop {
        ctf: true,
        exceptional: true,
        serialize: true,
        execute,
        ..Uop::default()
    }
}

// XXX Could also just implement Display for Reg...
const fn get_register_name(num: Reg) -> &'static str {
    [
        "x0", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4",
        "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
        "t5", "t6", "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "f10", "f11",
        "f12", "f13", "f14", "f15", "f16", "f17", "f18", "f19", "f20", "f21", "f22", "f23", "f24",
        "f25", "f26", "f27", "f28", "f29", "f30", "f31", "x0",
    ][num.get() as usize]
}

impl Cpu {
    /// For a given instruction word, find which registers it may read and
    /// write.
    ///
    /// # Errors
    ///
    /// Returns `Err(())` if the instruction word is illegal or cannot be
    /// decoded.
    pub fn get_register_info(&self, addr: u64, insn: u32) -> anyhow::Result<Uop> {
        let (insn, _) = decompress(insn);
        let Some(decoded) = decode(&self.decode_dag, insn) else {
            bail!("Illegal instruction");
        };

        Ok((decoded.decode)(addr, insn, default_execute))
    }
}

fn with_fflags<A>(a: A) -> (A, u8) { (a, native_fp::fflags_raised()) }

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::float_cmp,
    clippy::cast_lossless
)]
const INSTRUCTIONS: [RVInsnSpec; INSTRUCTION_NUM] = [
    // RV32I
    RVInsnSpec {
        name: "LUI",
        mask: 0x0000007f,
        bits: 0x00000037,
        decode: decode_u,
        disassemble: disassemble_u,
        execute: |_cpu, uop, _ops| Ok((uop.imm, 0)),
    },
    RVInsnSpec {
        name: "AUIPC",
        mask: 0x0000007f,
        bits: 0x00000017,
        decode: decode_auipc,
        disassemble: disassemble_u,
        execute: |_cpu, uop, _ops| Ok((uop.imm, 0)),
    },
    RVInsnSpec {
        name: "JAL",
        mask: 0x0000007f,
        bits: 0x0000006f,
        decode: decode_j,
        disassemble: disassemble_j,
        execute: |cpu, uop, _ops| {
            let tmp = cpu.pc;
            cpu.pc = uop.imm;
            Ok((tmp, 0))
        },
    },
    RVInsnSpec {
        name: "JALR",
        mask: 0x0000707f,
        bits: 0x00000067,
        decode: decode_i,
        disassemble: disassemble_jalr,
        execute: |cpu, uop, ops| {
            let tmp = cpu.pc;
            cpu.pc = ops.s1.wrapping_add(uop.imm) & !1;
            Ok((tmp, 0))
        },
    },
    RVInsnSpec {
        name: "BEQ",
        mask: 0x0000707f,
        bits: 0x00000063,
        decode: decode_b,
        disassemble: disassemble_b,
        execute: |cpu, uop, ops| {
            if ops.s1 == ops.s2 {
                cpu.pc = uop.imm;
            }
            Ok((0, 0))
        },
    },
    RVInsnSpec {
        name: "BNE",
        mask: 0x0000707f,
        bits: 0x00001063,
        decode: decode_b,
        disassemble: disassemble_b,
        execute: |cpu, uop, ops| {
            if ops.s1 != ops.s2 {
                cpu.pc = uop.imm;
            }
            Ok((0, 0))
        },
    },
    RVInsnSpec {
        name: "BLT",
        mask: 0x0000707f,
        bits: 0x00004063,
        decode: decode_b,
        disassemble: disassemble_b,
        execute: |cpu, uop, ops| {
            if (ops.s1 as i64) < ops.s2 as i64 {
                cpu.pc = uop.imm;
            }
            Ok((0, 0))
        },
    },
    RVInsnSpec {
        name: "BGE",
        mask: 0x0000707f,
        bits: 0x00005063,
        decode: decode_b,
        disassemble: disassemble_b,
        execute: |cpu, uop, ops| {
            if (ops.s1 as i64) >= ops.s2 as i64 {
                cpu.pc = uop.imm;
            }
            Ok((0, 0))
        },
    },
    RVInsnSpec {
        name: "BLTU",
        mask: 0x0000707f,
        bits: 0x00006063,
        decode: decode_b,
        disassemble: disassemble_b,
        execute: |cpu, uop, ops| {
            if ops.s1 < ops.s2 {
                cpu.pc = uop.imm;
            }
            Ok((0, 0))
        },
    },
    RVInsnSpec {
        name: "BGEU",
        mask: 0x0000707f,
        bits: 0x00007063,
        decode: decode_b,
        disassemble: disassemble_b,
        execute: |cpu, uop, ops| {
            if ops.s1 >= ops.s2 {
                cpu.pc = uop.imm;
            }
            Ok((0, 0))
        },
    },
    RVInsnSpec {
        name: "LB",
        mask: 0x0000707f,
        bits: 0x00000003,
        decode: decode_i,
        disassemble: disassemble_i_mem,
        execute: |cpu, uop, ops| Ok((cpu.memop(Read, ops.s1, uop.imm, 0, 1)? as i8 as u64, 0)),
    },
    RVInsnSpec {
        name: "LH",
        mask: 0x0000707f,
        bits: 0x00001003,
        decode: decode_i,
        disassemble: disassemble_i_mem,
        execute: |cpu, uop, ops| Ok((cpu.memop(Read, ops.s1, uop.imm, 0, 2)? as i16 as u64, 0)),
    },
    RVInsnSpec {
        name: "LW",
        mask: 0x0000707f,
        bits: 0x00002003,
        decode: decode_i,
        disassemble: disassemble_i_mem,
        execute: |cpu, uop, ops| Ok((cpu.memop(Read, ops.s1, uop.imm, 0, 4)? as i32 as u64, 0)),
    },
    RVInsnSpec {
        name: "LBU",
        mask: 0x0000707f,
        bits: 0x00004003,
        decode: decode_i,
        disassemble: disassemble_i_mem,
        execute: |cpu, uop, ops| Ok((cpu.memop(Read, ops.s1, uop.imm, 0, 1)?, 0)),
    },
    RVInsnSpec {
        name: "LHU",
        mask: 0x0000707f,
        bits: 0x00005003,
        decode: decode_i,
        disassemble: disassemble_i_mem,
        execute: |cpu, uop, ops| Ok((cpu.memop(Read, ops.s1, uop.imm, 0, 2)?, 0)),
    },
    RVInsnSpec {
        name: "SB",
        mask: 0x0000707f,
        bits: 0x00000023,
        decode: decode_s,
        disassemble: disassemble_s,
        execute: |cpu, uop, ops| {
            let _ = cpu.memop(Write, ops.s1, uop.imm, ops.s2, 1)?;
            Ok((0, 0))
        },
    },
    RVInsnSpec {
        name: "SH",
        mask: 0x0000707f,
        bits: 0x00001023,
        decode: decode_s,
        disassemble: disassemble_s,
        execute: |cpu, uop, ops| {
            let _ = cpu.memop(Write, ops.s1, uop.imm, ops.s2, 2)?;
            Ok((0, 0))
        },
    },
    RVInsnSpec {
        name: "SW",
        mask: 0x0000707f,
        bits: 0x00002023,
        decode: decode_s,
        disassemble: disassemble_s,
        execute: |cpu, uop, ops| {
            let _ = cpu.memop(Write, ops.s1, uop.imm, ops.s2, 4)?;
            Ok((0, 0))
        },
    },
    RVInsnSpec {
        name: "ADDI",
        mask: 0x0000707f,
        bits: 0x00000013,
        decode: decode_i,
        disassemble: disassemble_i,
        execute: |_cpu, uop, ops| Ok((ops.s1.wrapping_add(uop.imm), 0)),
    },
    RVInsnSpec {
        name: "SLTI",
        mask: 0x0000707f,
        bits: 0x00002013,
        decode: decode_i,
        disassemble: disassemble_i,
        execute: |_cpu, uop, ops| Ok((u64::from((ops.s1 as i64) < uop.imm as i64), 0)),
    },
    RVInsnSpec {
        name: "SLTIU",
        mask: 0x0000707f,
        bits: 0x00003013,
        decode: decode_i,
        disassemble: disassemble_i,
        execute: |_cpu, uop, ops| Ok((u64::from(ops.s1 < uop.imm), 0)),
    },
    RVInsnSpec {
        name: "XORI",
        mask: 0x0000707f,
        bits: 0x00004013,
        decode: decode_i,
        disassemble: disassemble_i,
        execute: |_cpu, uop, ops| Ok((ops.s1 ^ uop.imm, 0)),
    },
    RVInsnSpec {
        name: "ORI",
        mask: 0x0000707f,
        bits: 0x00006013,
        decode: decode_i,
        disassemble: disassemble_i,
        execute: |_cpu, uop, ops| Ok((ops.s1 | uop.imm, 0)),
    },
    RVInsnSpec {
        name: "ANDI",
        mask: 0x0000707f,
        bits: 0x00007013,
        decode: decode_i,
        disassemble: disassemble_i,
        execute: |_cpu, uop, ops| Ok((ops.s1 & uop.imm, 0)),
    },
    // RV32I SLLI subsumed by RV64I
    // RV32I SRLI subsumed by RV64I
    // RV32I SRAI subsumed by RV64I
    RVInsnSpec {
        name: "ADD",
        mask: 0xfe00707f,
        bits: 0x00000033,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| Ok((ops.s1.wrapping_add(ops.s2), 0)),
    },
    RVInsnSpec {
        name: "SUB",
        mask: 0xfe00707f,
        bits: 0x40000033,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| Ok((ops.s1.wrapping_sub(ops.s2), 0)),
    },
    RVInsnSpec {
        name: "SLL",
        mask: 0xfe00707f,
        bits: 0x00001033,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| Ok((ops.s1.wrapping_shl(ops.s2 as u32), 0)),
    },
    RVInsnSpec {
        name: "SLT",
        mask: 0xfe00707f,
        bits: 0x00002033,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| Ok((u64::from((ops.s1 as i64) < ops.s2 as i64), 0)),
    },
    RVInsnSpec {
        name: "SLTU",
        mask: 0xfe00707f,
        bits: 0x00003033,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| Ok((u64::from(ops.s1 < ops.s2), 0)),
    },
    RVInsnSpec {
        name: "XOR",
        mask: 0xfe00707f,
        bits: 0x00004033,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| Ok((ops.s1 ^ ops.s2, 0)),
    },
    RVInsnSpec {
        name: "SRL",
        mask: 0xfe00707f,
        bits: 0x00005033,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| Ok(((ops.s1.wrapping_shr(ops.s2 as u32)), 0)),
    },
    RVInsnSpec {
        name: "SRA",
        mask: 0xfe00707f,
        bits: 0x40005033,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| Ok(((ops.s1 as i64).wrapping_shr(ops.s2 as u32) as u64, 0)),
    },
    RVInsnSpec {
        name: "OR",
        mask: 0xfe00707f,
        bits: 0x00006033,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| Ok((ops.s1 | ops.s2, 0)),
    },
    RVInsnSpec {
        name: "AND",
        mask: 0xfe00707f,
        bits: 0x00007033,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| Ok((ops.s1 & ops.s2, 0)),
    },
    RVInsnSpec {
        name: "FENCE",
        mask: 0xf000707f,
        bits: 0x0000000f,
        decode: decode_serialized,
        disassemble: disassemble_empty,
        execute: |_cpu, uop, _ops| {
            if uop.imm == 0x0100000f {
                // PAUSE instruction hint
                // Nothing to do here, but it would be interesting to see
                // it used.
                log::trace!("pause isn't yet implemented");
            }
            // Fence memory ops (we are currently TSO already)
            Ok((0, 0))
        },
    },
    RVInsnSpec {
        name: "FENCE.TSO",
        mask: 0xf000707f,
        bits: 0x8000000f,
        decode: decode_serialized,
        disassemble: disassemble_empty,
        execute: |_cpu, _uop, _ops| {
            // Fence memory ops (we are currently TSO already)
            Ok((0, 0))
        },
    },
    RVInsnSpec {
        name: "ECALL",
        mask: 0xffffffff,
        bits: 0x00000073,
        decode: decode_exceptional,
        disassemble: disassemble_empty,
        execute: |cpu, uop, _ops| {
            Err(Exception {
                trap: match cpu.mmu.prv {
                    PrivMode::U => Trap::EnvironmentCallFromUMode,
                    PrivMode::S => Trap::EnvironmentCallFromSMode,
                    PrivMode::M => Trap::EnvironmentCallFromMMode,
                },
                tval: uop.imm,
            })
        },
    },
    RVInsnSpec {
        name: "EBREAK",
        mask: 0xffffffff,
        bits: 0x00100073,
        decode: decode_exceptional,
        disassemble: disassemble_empty,
        execute: |_cpu, _uop, _ops| {
            Err(Exception {
                trap: Trap::Breakpoint,
                tval: 0x00100073,
            })
        },
    },
    // RV64I
    RVInsnSpec {
        name: "LWU",
        mask: 0x0000707f,
        bits: 0x00006003,
        decode: decode_i,
        disassemble: disassemble_i_mem,
        execute: |cpu, uop, ops| {
            let v = cpu.memop(Read, ops.s1, uop.imm, 0, 4)?;
            Ok((v, 0))
        },
    },
    RVInsnSpec {
        name: "LD",
        mask: 0x0000707f,
        bits: 0x00003003,
        decode: decode_i,
        disassemble: disassemble_i_mem,
        execute: |cpu, uop, ops| {
            let v = cpu.memop(Read, ops.s1, uop.imm, 0, 8)?;
            Ok((v, 0))
        },
    },
    RVInsnSpec {
        name: "SD",
        mask: 0x0000707f,
        bits: 0x00003023,
        decode: decode_s,
        disassemble: disassemble_s,
        execute: |cpu, uop, ops| {
            let _ = cpu.memop(Write, ops.s1, uop.imm, ops.s2, 8)?;
            Ok((0, 0))
        },
    },
    RVInsnSpec {
        name: "SLLI",
        mask: 0xfc00707f, // RV64I version!
        bits: 0x00001013,
        decode: decode_r_shift,
        disassemble: disassemble_ri,
        execute: |_cpu, uop, ops| Ok((ops.s1 << uop.imm, 0)),
    },
    RVInsnSpec {
        name: "SRLI",
        mask: 0xfc00707f,
        bits: 0x00005013,
        decode: decode_r_shift,
        disassemble: disassemble_ri,
        execute: |_cpu, uop, ops| Ok((ops.s1 >> uop.imm, 0)),
    },
    RVInsnSpec {
        name: "SRAI",
        mask: 0xfc00707f,
        bits: 0x40005013,
        decode: decode_r_shift,
        disassemble: disassemble_ri,
        execute: |_cpu, uop, ops| Ok((((ops.s1 as i64) >> uop.imm) as u64, 0)),
    },
    RVInsnSpec {
        name: "ADDIW",
        mask: 0x0000707f,
        bits: 0x0000001b,
        decode: decode_i,
        disassemble: disassemble_i,
        execute: |_cpu, uop, ops| Ok((sext32(ops.s1.wrapping_add(uop.imm) as u32), 0)),
    },
    RVInsnSpec {
        name: "SLLIW",
        mask: 0xfe00707f,
        bits: 0x0000101b,
        decode: decode_r_shift,
        disassemble: disassemble_ri,
        execute: |_cpu, uop, ops| Ok((((ops.s1 as i32) << (uop.imm & 31)) as u64, 0)),
    },
    RVInsnSpec {
        name: "SRLIW",
        mask: 0xfe00707f,
        bits: 0x0000501b,
        decode: decode_r_shift,
        disassemble: disassemble_ri,
        execute: |_cpu, uop, ops| Ok((sext32((ops.s1 as u32) >> (uop.imm & 31)), 0)),
    },
    RVInsnSpec {
        name: "SRAIW",
        mask: 0xfe00707f,
        bits: 0x4000501b,
        decode: decode_r_shift,
        disassemble: disassemble_ri,
        execute: |_cpu, uop, ops| Ok((((ops.s1 as i32) >> (uop.imm & 31)) as u64, 0)),
    },
    RVInsnSpec {
        name: "ADDW",
        mask: 0xfe00707f,
        bits: 0x0000003b,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| Ok((sext32(ops.s1.wrapping_add(ops.s2) as u32), 0)),
    },
    RVInsnSpec {
        name: "SUBW",
        mask: 0xfe00707f,
        bits: 0x4000003b,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| Ok((sext32(ops.s1.wrapping_sub(ops.s2) as u32), 0)),
    },
    RVInsnSpec {
        name: "SLLW",
        mask: 0xfe00707f,
        bits: 0x0000103b,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| Ok((sext32((ops.s1 as u32).wrapping_shl(ops.s2 as u32)), 0)),
    },
    RVInsnSpec {
        name: "SRLW",
        mask: 0xfe00707f,
        bits: 0x0000503b,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| Ok((sext32((ops.s1 as u32).wrapping_shr(ops.s2 as u32)), 0)),
    },
    RVInsnSpec {
        name: "SRAW",
        mask: 0xfe00707f,
        bits: 0x4000503b,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| Ok(((ops.s1 as i32).wrapping_shr(ops.s2 as u32) as u64, 0)),
    },
    // RV32/RV64 Zifencei
    RVInsnSpec {
        name: "FENCE.I",
        mask: 0xffffffff,
        bits: 0x0000100f,
        decode: decode_empty,
        disassemble: disassemble_empty,
        execute: |cpu, _uop, _ops| {
            // Flush any cached instructions.  We have none so far.
            cpu.reservation = None;
            // HACK
            cpu.flush_icache = true;
            Ok((0, 0))
        },
    },
    // RV32/RV64 Zicsr
    RVInsnSpec {
        name: "CSRRW",
        mask: 0x0000707f,
        bits: 0x00001073,
        decode: decode_csr,
        disassemble: disassemble_csr,
        execute: |cpu, uop, ops| {
            let res = if uop.rd.is_x0_dest() {
                0
            } else {
                cpu.read_csr(uop.imm as u16)?
            };
            cpu.write_csr(uop.imm as u16, ops.s1)?;

            Ok((res, 0))
        },
    },
    RVInsnSpec {
        name: "CSRRS",
        mask: 0x0000707f,
        bits: 0x00002073,
        decode: decode_csr,
        disassemble: disassemble_csr,
        execute: |cpu, uop, ops| {
            let data = cpu.read_csr(uop.imm as u16)?;
            if uop.rs1.get() != 0 {
                cpu.write_csr(uop.imm as u16, data | ops.s1)?;
            }
            Ok((data, 0))
        },
    },
    RVInsnSpec {
        name: "CSRRC",
        mask: 0x0000707f,
        bits: 0x00003073,
        decode: decode_csr,
        disassemble: disassemble_csr,
        execute: |cpu, uop, ops| {
            let data = cpu.read_csr(uop.imm as u16)?;
            if uop.rs1.get() != 0 {
                cpu.write_csr(uop.imm as u16, data & !ops.s1)?;
            }
            Ok((data, 0))
        },
    },
    RVInsnSpec {
        name: "CSRRWI",
        mask: 0x0000707f,
        bits: 0x00005073,
        decode: decode_csri,
        disassemble: disassemble_csri,
        execute: |cpu, uop, _ops| {
            let res = if uop.rd.is_x0_dest() {
                0
            } else {
                cpu.read_csr(uop.imm as u16)?
            };
            cpu.write_csr(uop.imm as u16, uop.rs1.get() as u64)?;

            Ok((res, 0))
        },
    },
    RVInsnSpec {
        name: "CSRRSI",
        mask: 0x0000707f,
        bits: 0x00006073,
        decode: decode_csri,
        disassemble: disassemble_csri,
        execute: |cpu, uop, _ops| {
            let data = cpu.read_csr(uop.imm as u16)?;
            if uop.rs1.get() != 0 {
                cpu.write_csr(uop.imm as u16, data | uop.rs1.get() as u64)?;
            }
            Ok((data, 0))
        },
    },
    RVInsnSpec {
        name: "CSRRCI",
        mask: 0x0000707f,
        bits: 0x00007073,
        decode: decode_csri,
        disassemble: disassemble_csri,
        execute: |cpu, uop, _ops| {
            let data = cpu.read_csr(uop.imm as u16)?;
            if uop.rs1.get() != 0 {
                cpu.write_csr(uop.imm as u16, data & !(uop.rs1.get() as u64))?;
            }
            Ok((data, 0))
        },
    },
    // RV32M
    RVInsnSpec {
        name: "MUL",
        mask: 0xfe00707f,
        bits: 0x02000033,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| Ok((ops.s1.wrapping_mul(ops.s2), 0)),
    },
    RVInsnSpec {
        name: "MULH",
        mask: 0xfe00707f,
        bits: 0x02001033,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| {
            Ok((
                ((i128::from(ops.s1 as i64) * i128::from(ops.s2 as i64)) >> 64) as u64,
                0,
            ))
        },
    },
    RVInsnSpec {
        name: "MULHSU",
        mask: 0xfe00707f,
        bits: 0x02002033,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| {
            Ok((
                ((ops.s1 as i64 as u128).wrapping_mul(u128::from(ops.s2)) >> 64) as u64,
                0,
            ))
        },
    },
    RVInsnSpec {
        name: "MULHU",
        mask: 0xfe00707f,
        bits: 0x02003033,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| {
            Ok((
                (u128::from(ops.s1).wrapping_mul(u128::from(ops.s2)) >> 64) as u64,
                0,
            ))
        },
    },
    RVInsnSpec {
        name: "DIV",
        mask: 0xfe00707f,
        bits: 0x02004033,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| {
            Ok((
                if ops.s2 == 0 {
                    !0
                } else if ops.s1 as i64 == i64::MIN && ops.s2 as i64 == -1 {
                    ops.s1
                } else {
                    (ops.s1 as i64).wrapping_div(ops.s2 as i64) as u64
                },
                0,
            ))
        },
    },
    RVInsnSpec {
        name: "DIVU",
        mask: 0xfe00707f,
        bits: 0x02005033,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| {
            Ok((
                if ops.s2 == 0 {
                    !0
                } else {
                    ops.s1.wrapping_div(ops.s2)
                },
                0,
            ))
        },
    },
    RVInsnSpec {
        name: "REM",
        mask: 0xfe00707f,
        bits: 0x02006033,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| {
            Ok((
                if ops.s2 == 0 {
                    ops.s1
                } else if ops.s1 as i64 == i64::MIN && ops.s2 as i64 == -1 {
                    0
                } else {
                    (ops.s1 as i64).wrapping_rem(ops.s2 as i64) as u64
                },
                0,
            ))
        },
    },
    RVInsnSpec {
        name: "REMU",
        mask: 0xfe00707f,
        bits: 0x02007033,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| {
            Ok((
                match ops.s2 {
                    0 => ops.s1,
                    _ => ops.s1.wrapping_rem(ops.s2),
                },
                0,
            ))
        },
    },
    // RV64M
    RVInsnSpec {
        name: "MULW",
        mask: 0xfe00707f,
        bits: 0x0200003b,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| Ok(((ops.s1 as i32).wrapping_mul(ops.s2 as i32) as u64, 0)),
    },
    RVInsnSpec {
        name: "DIVW",
        mask: 0xfe00707f,
        bits: 0x0200403b,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| {
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
        },
    },
    RVInsnSpec {
        name: "DIVUW",
        mask: 0xfe00707f,
        bits: 0x0200503b,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| {
            Ok((
                if ops.s2 as u32 == 0 {
                    !0
                } else {
                    sext32((ops.s1 as u32).wrapping_div(ops.s2 as u32))
                },
                0,
            ))
        },
    },
    RVInsnSpec {
        name: "REMW",
        mask: 0xfe00707f,
        bits: 0x0200603b,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| {
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
        },
    },
    RVInsnSpec {
        name: "REMUW",
        mask: 0xfe00707f,
        bits: 0x0200703b,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| {
            Ok((
                match ops.s2 as u32 {
                    0 => ops.s1 as i32 as u64,
                    _ => sext32((ops.s1 as u32).wrapping_rem(ops.s2 as u32)),
                },
                0,
            ))
        },
    },
    // RV32A
    RVInsnSpec {
        name: "LR.W",
        mask: 0xf9f0707f,
        bits: 0x1000202f,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            let data = sext32(cpu.mmu.load_virt_u32(ops.s1)?);
            let pa = cpu
                .mmu
                .translate_address(ops.s1, MemoryAccessType::Read, false)?;
            cpu.reservation = Some(pa);
            Ok((data, 0))
        },
    },
    RVInsnSpec {
        name: "SC.W",
        mask: 0xf800707f,
        bits: 0x1800202f,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
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
        },
    },
    RVInsnSpec {
        name: "AMOSWAP.W",
        mask: 0xf800707f,
        bits: 0x0800202f,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            let tmp = cpu.mmu.load_virt_u32(ops.s1)?;
            cpu.mmu.store_virt_u32(ops.s1, ops.s2 as u32)?;
            Ok((sext32(tmp), 0))
        },
    },
    RVInsnSpec {
        name: "AMOADD.W",
        mask: 0xf800707f,
        bits: 0x0000202f,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            let tmp = cpu.mmu.load_virt_u32(ops.s1)?;
            cpu.mmu
                .store_virt_u32(ops.s1, tmp.wrapping_add(ops.s2 as u32))?;
            Ok((sext32(tmp), 0))
        },
    },
    RVInsnSpec {
        name: "AMOXOR.W",
        mask: 0xf800707f,
        bits: 0x2000202f,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            let tmp = cpu.mmu.load_virt_u32(ops.s1)?;
            cpu.mmu.store_virt_u32(ops.s1, ops.s2 as u32 ^ tmp)?;
            Ok((sext32(tmp), 0))
        },
    },
    RVInsnSpec {
        name: "AMOAND.W",
        mask: 0xf800707f,
        bits: 0x6000202f,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            let tmp = cpu.mmu.load_virt_u32(ops.s1)?;
            cpu.mmu.store_virt_u32(ops.s1, ops.s2 as u32 & tmp)?;
            Ok((sext32(tmp), 0))
        },
    },
    RVInsnSpec {
        name: "AMOOR.W",
        mask: 0xf800707f,
        bits: 0x4000202f,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            let tmp = cpu.mmu.load_virt_u32(ops.s1)?;
            cpu.mmu.store_virt_u32(ops.s1, ops.s2 as u32 | tmp)?;
            Ok((sext32(tmp), 0))
        },
    },
    RVInsnSpec {
        name: "AMOMIN.W",
        mask: 0xf800707f,
        bits: 0x8000202f,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            let tmp = cpu.mmu.load_virt_u32(ops.s1)?;
            cpu.mmu
                .store_virt_u32(ops.s1, (ops.s2 as i32).min(tmp as i32) as u32)?;
            Ok((sext32(tmp), 0))
        },
    },
    RVInsnSpec {
        name: "AMOMAX.W",
        mask: 0xf800707f,
        bits: 0xa000202f,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            let tmp = cpu.mmu.load_virt_u32(ops.s1)?;
            cpu.mmu
                .store_virt_u32(ops.s1, (ops.s2 as i32).max(tmp as i32) as u32)?;
            Ok((sext32(tmp), 0))
        },
    },
    RVInsnSpec {
        name: "AMOMINU.W",
        mask: 0xf800707f,
        bits: 0xc000202f,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            let tmp = cpu.mmu.load_virt_u32(ops.s1)?;
            cpu.mmu.store_virt_u32(ops.s1, (ops.s2 as u32).min(tmp))?;
            Ok((sext32(tmp), 0))
        },
    },
    RVInsnSpec {
        name: "AMOMAXU.W",
        mask: 0xf800707f,
        bits: 0xe000202f,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            let tmp = cpu.mmu.load_virt_u32(ops.s1)?;
            cpu.mmu.store_virt_u32(ops.s1, (ops.s2 as u32).max(tmp))?;
            Ok((sext32(tmp), 0))
        },
    },
    // RV64A
    RVInsnSpec {
        name: "LR.D",
        mask: 0xf9f0707f,
        bits: 0x1000302f,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            let data = cpu.mmu.load_virt_u64(ops.s1)?;
            let pa = cpu
                .mmu
                .translate_address(ops.s1, MemoryAccessType::Read, false)?;
            cpu.reservation = Some(pa);
            Ok((data, 0))
        },
    },
    RVInsnSpec {
        name: "SC.D",
        mask: 0xf800707f,
        bits: 0x1800302f,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
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
        },
    },
    RVInsnSpec {
        name: "AMOSWAP.D",
        mask: 0xf800707f,
        bits: 0x0800302f,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            let tmp = cpu.mmu.load_virt_u64(ops.s1)?;
            cpu.mmu.store_virt_u64(ops.s1, ops.s2)?;
            cpu.reservation = None;
            Ok((tmp, 0))
        },
    },
    RVInsnSpec {
        name: "AMOADD.D",
        mask: 0xf800707f,
        bits: 0x0000302f,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            let tmp = cpu.mmu.load_virt_u64(ops.s1)?;
            cpu.mmu.store_virt_u64(ops.s1, tmp.wrapping_add(ops.s2))?;
            cpu.reservation = None;
            Ok((tmp, 0))
        },
    },
    RVInsnSpec {
        name: "AMOXOR.D",
        mask: 0xf800707f,
        bits: 0x2000302f,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            let tmp = cpu.mmu.load_virt_u64(ops.s1)?;
            cpu.mmu.store_virt_u64(ops.s1, tmp ^ ops.s2)?;
            cpu.reservation = None;
            Ok((tmp, 0))
        },
    },
    RVInsnSpec {
        name: "AMOAND.D",
        mask: 0xf800707f,
        bits: 0x6000302f,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            let tmp = cpu.mmu.load_virt_u64(ops.s1)?;
            cpu.mmu.store_virt_u64(ops.s1, tmp & ops.s2)?;
            cpu.reservation = None;
            Ok((tmp, 0))
        },
    },
    RVInsnSpec {
        name: "AMOOR.D",
        mask: 0xf800707f,
        bits: 0x4000302f,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            let tmp = cpu.mmu.load_virt_u64(ops.s1)?;
            cpu.mmu.store_virt_u64(ops.s1, tmp | ops.s2)?;
            cpu.reservation = None;
            Ok((tmp, 0))
        },
    },
    RVInsnSpec {
        name: "AMOMIN.D",
        mask: 0xf800707f,
        bits: 0x8000302f,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            let tmp = cpu.mmu.load_virt_u64(ops.s1)?;
            cpu.mmu
                .store_virt_u64(ops.s1, (ops.s2 as i64).min(tmp as i64) as u64)?;
            cpu.reservation = None;
            Ok((tmp, 0))
        },
    },
    RVInsnSpec {
        name: "AMOMAX.D",
        mask: 0xf800707f,
        bits: 0xa000302f,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            let tmp = cpu.mmu.load_virt_u64(ops.s1)?;
            cpu.mmu
                .store_virt_u64(ops.s1, (ops.s2 as i64).max(tmp as i64) as u64)?;
            cpu.reservation = None;
            Ok((tmp, 0))
        },
    },
    RVInsnSpec {
        name: "AMOMINU.D",
        mask: 0xf800707f,
        bits: 0xc000302f,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            let tmp = cpu.mmu.load_virt_u64(ops.s1)?;
            cpu.mmu.store_virt_u64(ops.s1, ops.s2.min(tmp))?;
            cpu.reservation = None;
            Ok((tmp, 0))
        },
    },
    RVInsnSpec {
        name: "AMOMAXU.D",
        mask: 0xf800707f,
        bits: 0xe000302f,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            let tmp = cpu.mmu.load_virt_u64(ops.s1)?;
            cpu.mmu.store_virt_u64(ops.s1, ops.s2.max(tmp))?;
            cpu.reservation = None;
            Ok((tmp, 0))
        },
    },
    // RV32F
    RVInsnSpec {
        name: "FLW",
        mask: 0x0000707f,
        bits: 0x00002007,
        decode: decode_i_fx,
        disassemble: disassemble_i_mem,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(0)?;
            Ok((cpu.memop(Read, ops.s1, uop.imm, 0, 4)? | fp::NAN_BOX_F32, 0))
        },
    },
    RVInsnSpec {
        name: "FSW",
        mask: 0x0000707f,
        bits: 0x00002027,
        decode: decode_s_xf,
        disassemble: disassemble_s,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(0)?;
            cpu.reservation = None;
            let _ = cpu.memop(Write, ops.s1, uop.imm, ops.s2, 4)?;
            Ok((0, 0))
        },
    },
    RVInsnSpec {
        name: "FMADD.S",
        mask: 0x0600007f,
        bits: 0x00000043,
        decode: decode_r2_ffff,
        disassemble: disassemble_r2_ffff,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(Sf32::map3(ops.s1, ops.s2, ops.s3, |a, b, c| {
                a.mul_add(b, c)
            }))
        },
    },
    RVInsnSpec {
        name: "FMSUB.S",
        mask: 0x0600007f,
        bits: 0x00000047,
        decode: decode_r2_ffff,
        disassemble: disassemble_r2_ffff,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(Sf32::map3(ops.s1, ops.s2, ops.s3, |a, b, c| {
                a.mul_add(b, -c)
            }))
        },
    },
    RVInsnSpec {
        name: "FNMSUB.S",
        mask: 0x0600007f,
        bits: 0x0000004b,
        decode: decode_r2_ffff,
        disassemble: disassemble_r2_ffff,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(Sf32::map3(ops.s1, ops.s2, ops.s3, |a, b, c| {
                -a.mul_add(b, -c)
            }))
        },
    },
    RVInsnSpec {
        name: "FNMADD.S",
        mask: 0x0600007f,
        bits: 0x0000004f,
        decode: decode_r2_ffff,
        disassemble: disassemble_r2_ffff,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(Sf32::map3(ops.s1, ops.s2, ops.s3, |a, b, c| {
                -a.mul_add(b, c)
            }))
        },
    },
    RVInsnSpec {
        name: "FADD.S",
        mask: 0xfe00007f,
        bits: 0x00000053,
        decode: decode_r_fff,
        disassemble: disassemble_r,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            //Ok(Sf32::map2(ops.s1, ops.s2, |a, b| a + b))
            Ok(Sf32::fadd(ops.s1, ops.s2, cpu.get_rm(uop.rm)))
        },
    },
    RVInsnSpec {
        name: "FSUB.S",
        mask: 0xfe00007f,
        bits: 0x08000053,
        decode: decode_r_fff,
        disassemble: disassemble_r,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(Sf32::fsub(ops.s1, ops.s2, cpu.get_rm(uop.rm)))
        },
    },
    RVInsnSpec {
        name: "FMUL.S",
        mask: 0xfe00007f,
        bits: 0x10000053,
        decode: decode_r_fff,
        disassemble: disassemble_r,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(Sf32::map2(ops.s1, ops.s2, |a, b| a * b))
        },
    },
    RVInsnSpec {
        name: "FDIV.S",
        mask: 0xfe00007f,
        bits: 0x18000053,
        decode: decode_r_fff,
        disassemble: disassemble_r,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            if ops.s2 == 0 {
                Ok((0xffffffff7f800000u64, DIVIDEZERO)) // INFINITY
            } else if ops.s2 == 0x8000000000000000u64 {
                Ok((0xffffffffff800000u64, DIVIDEZERO)) // NEG_INFINITY
            } else {
                Ok(Sf32::map2(ops.s1, ops.s2, |a, b| a / b))
            }
        },
    },
    RVInsnSpec {
        name: "FSQRT.S",
        mask: 0xfff0007f,
        bits: 0x58000053,
        decode: decode_r_fff,
        disassemble: disassemble_r,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(Sf32::map1(ops.s1, f32::sqrt))
        },
    },
    RVInsnSpec {
        name: "FSGNJ.S",
        mask: 0xfe00707f,
        bits: 0x20000053,
        decode: decode_r_fff,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            cpu.check_float_access_and_dirty(0)?;
            let rs1_bits = Sf32::unbox(ops.s1);
            let rs2_bits = Sf32::unbox(ops.s2);
            let sign_bit = rs2_bits & 0x80000000;
            Ok((fp::NAN_BOX_F32 | sign_bit | rs1_bits & 0x7fffffff, 0))
        },
    },
    RVInsnSpec {
        name: "FSGNJN.S",
        mask: 0xfe00707f,
        bits: 0x20001053,
        decode: decode_r_fff,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            cpu.check_float_access_and_dirty(0)?;
            let rs1_bits = Sf32::unbox(ops.s1);
            let rs2_bits = Sf32::unbox(ops.s2);
            let sign_bit = !rs2_bits & 0x80000000;
            Ok((fp::NAN_BOX_F32 | sign_bit | rs1_bits & 0x7fffffff, 0))
        },
    },
    RVInsnSpec {
        name: "FSGNJX.S",
        mask: 0xfe00707f,
        bits: 0x20002053,
        decode: decode_r_fff,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            cpu.check_float_access_and_dirty(0)?;
            let rs1_bits = Sf32::unbox(ops.s1);
            let rs2_bits = Sf32::unbox(ops.s2);
            let sign_bit = rs2_bits & 0x80000000;
            Ok((fp::NAN_BOX_F32 | (sign_bit ^ rs1_bits), 0))
        },
    },
    RVInsnSpec {
        name: "FMIN.S",
        mask: 0xfe00707f,
        bits: 0x28000053,
        decode: decode_r_fff,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            cpu.check_float_access_and_dirty(0)?;
            Ok(Sf32::min(ops.s1, ops.s2))
        },
    },
    RVInsnSpec {
        name: "FMAX.S",
        mask: 0xfe00707f,
        bits: 0x28001053,
        decode: decode_r_fff,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            cpu.check_float_access_and_dirty(0)?;
            Ok(Sf32::max(ops.s1, ops.s2))
        },
    },
    RVInsnSpec {
        name: "FCVT.W.S",
        mask: 0xfff0007f,
        bits: 0xc0000053,
        decode: decode_r_xf,
        disassemble: disassemble_r,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok((Sf32::to_float(ops.s1) as i32 as u64, 0))
        },
    },
    RVInsnSpec {
        name: "FCVT.WU.S",
        mask: 0xfff0007f,
        bits: 0xc0100053,
        decode: decode_r_xf,
        disassemble: disassemble_r,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok((u64::from(Sf32::to_float(ops.s1) as u32), 0))
        },
    },
    RVInsnSpec {
        name: "FMV.X.W",
        mask: 0xfff0707f,
        bits: 0xe0000053,
        decode: decode_r_xf,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            cpu.check_float_access_and_dirty(0)?;
            Ok((ops.s1 as i32 as u64, 0))
        },
    },
    RVInsnSpec {
        name: "FEQ.S",
        mask: 0xfe00707f,
        bits: 0xa0002053,
        decode: decode_r_xff,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            cpu.check_float_access_and_dirty(0)?;
            Ok(Sf32::feq(ops.s1, ops.s2))
        },
    },
    RVInsnSpec {
        name: "FLT.S",
        mask: 0xfe00707f,
        bits: 0xa0001053,
        decode: decode_r_xff,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            cpu.check_float_access_and_dirty(0)?;
            Ok(Sf32::flt(ops.s1, ops.s2))
        },
    },
    RVInsnSpec {
        name: "FLE.S",
        mask: 0xfe00707f,
        bits: 0xa0000053,
        decode: decode_r_xff,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            cpu.check_float_access_and_dirty(0)?;
            Ok(Sf32::fle(ops.s1, ops.s2))
        },
    },
    RVInsnSpec {
        name: "FCLASS.S",
        mask: 0xfff0707f,
        bits: 0xe0001053,
        decode: decode_r_xf,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            cpu.check_float_access_and_dirty(0)?;
            Ok((1 << Sf32::fclass(ops.s1) as usize, 0))
        },
    },
    RVInsnSpec {
        name: "FCVT.S.W",
        mask: 0xfff0007f,
        bits: 0xd0000053,
        decode: decode_r_fx,
        disassemble: disassemble_r,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(cvt_i32_sf32(ops.s1, cpu.get_rm(uop.rm)))
        },
    },
    RVInsnSpec {
        name: "FCVT.S.WU",
        mask: 0xfff0007f,
        bits: 0xd0100053,
        decode: decode_r_fx,
        disassemble: disassemble_r,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(cvt_u32_sf32(ops.s1, cpu.get_rm(uop.rm)))
        },
    },
    RVInsnSpec {
        name: "FMV.W.X",
        mask: 0xfff0707f,
        bits: 0xf0000053,
        decode: decode_r_fx,
        disassemble: disassemble_r_f,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok((fp::NAN_BOX_F32 | ops.s1, 0))
        },
    },
    // RV64F
    RVInsnSpec {
        name: "FCVT.L.S",
        mask: 0xfff0007f,
        bits: 0xc0200053,
        decode: decode_r_xf,
        disassemble: disassemble_r,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok((Sf32::to_float(ops.s1) as i64 as u64, 0))
        },
    },
    RVInsnSpec {
        name: "FCVT.LU.S",
        mask: 0xfff0007f,
        bits: 0xc0300053,
        decode: decode_r_xf,
        disassemble: disassemble_r,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok((Sf32::to_float(ops.s1) as u64, 0))
        },
    },
    RVInsnSpec {
        name: "FCVT.S.L",
        mask: 0xfff0007f,
        bits: 0xd0200053,
        decode: decode_r_fx,
        disassemble: disassemble_r,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(cvt_i64_sf32(ops.s1, cpu.get_rm(uop.rm)))
        },
    },
    RVInsnSpec {
        name: "FCVT.S.LU",
        mask: 0xfff0007f,
        bits: 0xd0300053,
        decode: decode_r_fx,
        disassemble: disassemble_r,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(cvt_u64_sf32(ops.s1, cpu.get_rm(uop.rm)))
        },
    },
    // RV32D
    RVInsnSpec {
        name: "FLD",
        mask: 0x0000707f,
        bits: 0x00003007,
        decode: decode_i_fx,
        disassemble: disassemble_i,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(0)?;
            let v = cpu.memop(Read, ops.s1, uop.imm, 0, 8)?;
            Ok((v, 0))
        },
    },
    RVInsnSpec {
        name: "FSD",
        mask: 0x0000707f,
        bits: 0x00003027,
        decode: decode_s_xf,
        disassemble: disassemble_s,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(0)?;
            cpu.mmu.store64(ops.s1.wrapping_add(uop.imm), ops.s2)?;
            Ok((0, 0))
        },
    },
    RVInsnSpec {
        name: "FMADD.D",
        mask: 0x0600007f,
        bits: 0x02000043,
        decode: decode_r2_ffff,
        disassemble: disassemble_r2_ffff,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(Sf64::map3(ops.s1, ops.s2, ops.s3, |a, b, c| {
                a.mul_add(b, c)
            }))
        },
    },
    RVInsnSpec {
        name: "FMSUB.D",
        mask: 0x0600007f,
        bits: 0x02000047,
        decode: decode_r2_ffff,
        disassemble: disassemble_r2_ffff,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(Sf64::map3(ops.s1, ops.s2, ops.s3, |a, b, c| {
                a.mul_add(b, -c)
            }))
        },
    },
    RVInsnSpec {
        name: "FNMSUB.D",
        mask: 0x0600007f,
        bits: 0x0200004b,
        decode: decode_r2_ffff,
        disassemble: disassemble_r2_ffff,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(Sf64::map3(ops.s1, ops.s2, ops.s3, |a, b, c| {
                -a.mul_add(b, -c)
            }))
        },
    },
    RVInsnSpec {
        name: "FNMADD.D",
        mask: 0x0600007f,
        bits: 0x0200004f,
        decode: decode_r2_ffff,
        disassemble: disassemble_r2_ffff,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(Sf64::map3(ops.s1, ops.s2, ops.s3, |a, b, c| {
                -a.mul_add(b, c)
            }))
        },
    },
    RVInsnSpec {
        name: "FADD.D",
        mask: 0xfe00007f,
        bits: 0x02000053,
        decode: decode_r_fff,
        disassemble: disassemble_r,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(Sf64::fadd(ops.s1, ops.s2, cpu.get_rm(uop.rm)))
        },
    },
    RVInsnSpec {
        name: "FSUB.D",
        mask: 0xfe00007f,
        bits: 0x0a000053,
        decode: decode_r_fff,
        disassemble: disassemble_r,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(Sf64::fsub(ops.s1, ops.s2, cpu.get_rm(uop.rm)))
        },
    },
    RVInsnSpec {
        name: "FMUL.D",
        mask: 0xfe00007f,
        bits: 0x12000053,
        decode: decode_r_fff,
        disassemble: disassemble_r,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(Sf64::map2(ops.s1, ops.s2, |a, b| a * b))
        },
    },
    RVInsnSpec {
        name: "FDIV.D",
        mask: 0xfe00007f,
        bits: 0x1a000053,
        decode: decode_r_fff,
        disassemble: disassemble_r,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            if ops.s2 == 0 {
                Ok((f64::INFINITY as u64, DIVIDEZERO)) // XXX??
            } else if ops.s2 == 0x8000000000000000u64 {
                Ok((f64::NEG_INFINITY as u64, DIVIDEZERO)) // XXX??
            } else {
                Ok(Sf64::map2(ops.s1, ops.s2, |a, b| a / b))
            }
        },
    },
    RVInsnSpec {
        name: "FSQRT.D",
        mask: 0xfff0007f,
        bits: 0x5a000053,
        decode: decode_r_fff,
        disassemble: disassemble_r,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(Sf64::map1(ops.s1, f64::sqrt))
        },
    },
    RVInsnSpec {
        name: "FSGNJ.D",
        mask: 0xfe00707f,
        bits: 0x22000053,
        decode: decode_r_fff,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            cpu.check_float_access_and_dirty(0)?;
            let rs1_bits = ops.s1;
            let rs2_bits = ops.s2;
            let sign_bit = rs2_bits & 0x8000000000000000u64;
            Ok((sign_bit | (rs1_bits & 0x7fffffffffffffff), 0))
        },
    },
    RVInsnSpec {
        name: "FSGNJN.D",
        mask: 0xfe00707f,
        bits: 0x22001053,
        decode: decode_r_fff,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            cpu.check_float_access_and_dirty(0)?;
            let rs1_bits = ops.s1;
            let rs2_bits = ops.s2;
            let sign_bit = !rs2_bits & 0x8000000000000000u64;
            Ok((sign_bit | (rs1_bits & 0x7fffffffffffffff), 0))
        },
    },
    RVInsnSpec {
        name: "FSGNJX.D",
        mask: 0xfe00707f,
        bits: 0x22002053,
        decode: decode_r_fff,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            cpu.check_float_access_and_dirty(0)?;
            let rs1_bits = ops.s1;
            let rs2_bits = ops.s2;
            let sign_bit = rs2_bits & 0x8000000000000000u64;
            Ok((sign_bit ^ rs1_bits, 0))
        },
    },
    RVInsnSpec {
        name: "FMIN.D",
        mask: 0xfe00707f,
        bits: 0x2A000053,
        decode: decode_r_fff,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            cpu.check_float_access_and_dirty(0)?;
            Ok(Sf64::min(ops.s1, ops.s2))
        },
    },
    RVInsnSpec {
        name: "FMAX.D",
        mask: 0xfe00707f,
        bits: 0x2A001053,
        decode: decode_r_fff,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            cpu.check_float_access_and_dirty(0)?;
            Ok(Sf64::max(ops.s1, ops.s2))
        },
    },
    RVInsnSpec {
        name: "FCVT.S.D",
        mask: 0xfff0007f,
        bits: 0x40100053,
        decode: decode_r_fff,
        disassemble: disassemble_r,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(with_fflags(Sf32::from_float(Sf64::to_float(ops.s1) as f32)))
        },
    },
    RVInsnSpec {
        name: "FCVT.D.S",
        mask: 0xfff0007f,
        bits: 0x42000053,
        decode: decode_r_fff,
        disassemble: disassemble_r,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(fp::fcvt_d_s(ops.s1))
        },
    },
    RVInsnSpec {
        name: "FEQ.D",
        mask: 0xfe00707f,
        bits: 0xa2002053,
        decode: decode_r_xff,
        disassemble: disassemble_empty,
        execute: |cpu, _uop, ops| {
            cpu.check_float_access_and_dirty(0)?;
            Ok(Sf64::feq(ops.s1, ops.s2))
        },
    },
    RVInsnSpec {
        name: "FLT.D",
        mask: 0xfe00707f,
        bits: 0xa2001053,
        decode: decode_r_xff,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            cpu.check_float_access_and_dirty(0)?;
            Ok(Sf64::flt(ops.s1, ops.s2))
        },
    },
    RVInsnSpec {
        name: "FLE.D",
        mask: 0xfe00707f,
        bits: 0xa2000053,
        decode: decode_r_xff,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            cpu.check_float_access_and_dirty(0)?;
            Ok(Sf64::fle(ops.s1, ops.s2))
        },
    },
    RVInsnSpec {
        name: "FCLASS.D",
        mask: 0xfff0707f,
        bits: 0xe2001053,
        decode: decode_r_xf,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            cpu.check_float_access_and_dirty(0)?;
            Ok((1 << Sf64::fclass(ops.s1) as usize, 0))
        },
    },
    RVInsnSpec {
        name: "FCVT.W.D",
        mask: 0xfff0007f,
        bits: 0xc2000053,
        decode: decode_r_xf,
        disassemble: disassemble_r,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(with_fflags(Sf64::to_float(ops.s1) as i32 as u64))
        },
    },
    RVInsnSpec {
        name: "FCVT.WU.D",
        mask: 0xfff0007f,
        bits: 0xc2100053,
        decode: decode_r_xf,
        disassemble: disassemble_r,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(with_fflags(Sf64::to_float(ops.s1) as i32 as u64))
        },
    },
    RVInsnSpec {
        name: "FCVT.D.W",
        mask: 0xfff0007f,
        bits: 0xd2000053,
        decode: decode_r_fx,
        disassemble: disassemble_r,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(with_fflags(Sf64::from_float(f64::from(ops.s1 as i32))))
        },
    },
    RVInsnSpec {
        name: "FCVT.D.WU",
        mask: 0xfff0007f,
        bits: 0xd2100053,
        decode: decode_r_fx,
        disassemble: disassemble_r,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(with_fflags(Sf64::from_float(f64::from(ops.s1 as u32))))
        },
    },
    // RV64D
    RVInsnSpec {
        name: "FCVT.L.D",
        mask: 0xfff0007f,
        bits: 0xc2200053,
        decode: decode_r_xf,
        disassemble: disassemble_r,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(with_fflags(Sf64::to_float(ops.s1) as i64 as u64))
        },
    },
    RVInsnSpec {
        name: "FCVT.LU.D",
        mask: 0xfff0007f,
        bits: 0xc2300053,
        decode: decode_r_xf,
        disassemble: disassemble_r,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(with_fflags(Sf64::to_float(ops.s1) as u64))
        },
    },
    RVInsnSpec {
        name: "FMV.X.D",
        mask: 0xfff0707f,
        bits: 0xe2000053,
        decode: decode_r_xf,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            cpu.check_float_access_and_dirty(0)?;
            Ok((ops.s1, 0))
        },
    },
    RVInsnSpec {
        name: "FCVT.D.L",
        mask: 0xfff0007f,
        bits: 0xd2200053,
        decode: decode_r_fx,
        disassemble: disassemble_r,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(with_fflags(Sf64::from_float(ops.s1 as i64 as f64)))
        },
    },
    RVInsnSpec {
        name: "FCVT.D.LU",
        mask: 0xfff0007f,
        bits: 0xd2300053,
        decode: decode_r_fx,
        disassemble: disassemble_r,
        execute: |cpu, uop, ops| {
            cpu.check_float_access_and_dirty(uop.rm)?;
            Ok(with_fflags(Sf64::from_float(ops.s1 as f64)))
        },
    },
    RVInsnSpec {
        name: "FMV.D.X",
        mask: 0xfff0707f,
        bits: 0xf2000053,
        decode: decode_r_fx,
        disassemble: disassemble_r,
        execute: |cpu, _uop, ops| {
            cpu.check_float_access_and_dirty(0)?;
            Ok((ops.s1, 0))
        },
    },
    // Remaining (all system-level) that weren't listed in the instr-table
    RVInsnSpec {
        name: "DRET",
        mask: 0xffffffff,
        bits: 0x7b200073,
        decode: decode_exceptional,
        disassemble: disassemble_empty,
        execute: |_cpu, _uop, _ops| todo!("Handling dret requires handling all of debug mode"),
    },
    RVInsnSpec {
        name: "MRET",
        mask: 0xffffffff,
        bits: 0x30200073,
        decode: decode_exceptional,
        disassemble: disassemble_empty,
        execute: |cpu, _uop, _ops| {
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
            Ok((0, 0))
        },
    },
    RVInsnSpec {
        name: "SRET",
        mask: 0xffffffff,
        bits: 0x10200073,
        decode: decode_exceptional,
        disassemble: disassemble_empty,
        execute: |cpu, _uop, _ops| {
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
            Ok((0, 0))
        },
    },
    RVInsnSpec {
        name: "SFENCE.VMA",
        mask: 0xfe007fff,
        bits: 0x12000073,
        decode: decode_serialized,
        disassemble: disassemble_empty,
        execute: |cpu, _uop, _ops| {
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
        },
    },
    RVInsnSpec {
        name: "WFI",
        mask: 0xffffffff,
        bits: 0x10500073,
        decode: decode_serialized,
        disassemble: disassemble_empty,
        execute: |cpu, _uop, _ops| {
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
        },
    },
    // Zba -- AKA, my only favorite extension
    RVInsnSpec {
        name: "ADD.UW",
        mask: 0xfe00707f,
        bits: 0x0800003b,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| Ok((ops.s2.wrapping_add(ops.s1 & 0xffffffff), 0)),
    },
    RVInsnSpec {
        name: "SH1ADD",
        mask: 0xfe00707f,
        bits: 0x20002033,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| Ok((ops.s2.wrapping_add(ops.s1 << 1), 0)),
    },
    RVInsnSpec {
        name: "SH1ADD.UW",
        mask: 0xfe00707f,
        bits: 0x2000203b,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| Ok((ops.s2.wrapping_add((ops.s1 & 0xffffffff) << 1), 0)),
    },
    RVInsnSpec {
        name: "SH2ADD",
        mask: 0xfe00707f,
        bits: 0x20004033,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| Ok((ops.s2.wrapping_add(ops.s1 << 2), 0)),
    },
    RVInsnSpec {
        name: "SH2ADD.UW",
        mask: 0xfe00707f,
        bits: 0x2000403b,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| Ok((ops.s2.wrapping_add((ops.s1 & 0xffffffff) << 2), 0)),
    },
    RVInsnSpec {
        name: "SH3ADD",
        mask: 0xfe00707f,
        bits: 0x20006033,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| Ok((ops.s2.wrapping_add(ops.s1 << 3), 0)),
    },
    RVInsnSpec {
        name: "SH3ADD.UW",
        mask: 0xfe00707f,
        bits: 0x2000603b,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| Ok((ops.s2.wrapping_add((ops.s1 & 0xffffffff) << 3), 0)),
    },
    RVInsnSpec {
        name: "SLLI.UW",
        mask: 0xfe00707f,
        bits: 0x0800101b,
        decode: decode_r_shift,
        disassemble: disassemble_r,
        execute: |_cpu, uop, ops| Ok(((ops.s1 & 0xffffffff) << uop.imm, 0)),
    },
    // Zicond extension
    RVInsnSpec {
        name: "CZERO.EQZ",
        mask: 0xfe00707f,
        bits: 0x0e005033,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| Ok((if ops.s2 == 0 { 0 } else { ops.s1 }, 0)),
    },
    RVInsnSpec {
        name: "CZERO.NEZ",
        mask: 0xfe00707f,
        bits: 0x0e007033,
        decode: decode_r,
        disassemble: disassemble_r,
        execute: |_cpu, _uop, ops| Ok((if ops.s2 != 0 { 0 } else { ops.s1 }, 0)),
    },
    // Last one is a sentiel and must always be this illegal instruction
    RVInsnSpec {
        name: "INVALID",
        mask: 0,
        bits: 0,
        decode: decode_exceptional,
        disassemble: disassemble_empty,
        execute: |_cpu, _uop, _ops| {
            Err(Exception {
                trap: Trap::IllegalInstruction,
                tval: 0,
            })
        },
    },
];

#[cfg(test)]
mod test_cpu {
    use super::*;
    use crate::mmu::MEMORY_BASE;
    use crate::terminal::DummyTerminal;

    fn create_cpu() -> Cpu { Cpu::new(Box::new(DummyTerminal::new()), 8) }

    #[test]
    fn initialize() { let _cpu = create_cpu(); }

    #[test]
    fn update_pc() {
        let mut cpu = create_cpu();
        assert_eq!(0, cpu.read_pc());
        cpu.update_pc(1);
        assert_eq!(0, cpu.read_pc());
        cpu.update_pc(0xffffffffffffffffu64);
        assert_eq!(0xfffffffffffffffeu64, cpu.read_pc());
    }

    #[test]
    fn decode_sh2add() {
        let cpu = create_cpu();
        //    10894:       20e74633                sh2add  a2,a4,a4
        match decode(&cpu.decode_dag, 0x20e74633) {
            Some(inst) => assert_eq!(inst.name, "SH2ADD"),
            _err => panic!("Failed to decode"),
        }
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
    fn decode_test() {
        let cpu = create_cpu();
        // 0x13 is addi instruction
        match decode(&cpu.decode_dag, 0x13) {
            Some(inst) => assert_eq!(inst.name, "ADDI"),
            None => panic!("Failed to decode"),
        }
        // .decode() returns error for invalid word data.
        assert!(
            decode(&cpu.decode_dag, 0x0).is_none(),
            "Unexpectedly succeeded in decoding"
        );
    }

    #[test]
    #[allow(clippy::match_wild_err_arm)]
    fn test_decompress() {
        let cpu = create_cpu();
        // .decompress() doesn't directly return an instruction but
        // it returns decompressed word. Then you need to call .decode().
        match decode(&cpu.decode_dag, decompress(0x20).0) {
            Some(inst) => assert_eq!(inst.name, "ADDI"),
            None => panic!("Failed to decode"),
        }
    }

    #[test]
    #[allow(clippy::match_wild_err_arm)]
    fn wfi() {
        let mut uop_cache = IntMap::new();
        let wfi_instruction = 0x10500073;
        let mut cpu = create_cpu();
        // Just in case
        match decode(&cpu.decode_dag, wfi_instruction) {
            Some(inst) => assert_eq!(inst.name, "WFI"),
            None => panic!("Failed to decode"),
        }
        cpu.update_pc(MEMORY_BASE);
        // write WFI instruction
        match cpu
            .get_mut_mmu()
            .store_virt_u32(MEMORY_BASE, wfi_instruction)
        {
            Ok(()) => {}
            Err(_e) => panic!("Failed to store"),
        }
        cpu.run_soc(1, &mut uop_cache);
        assert_eq!(MEMORY_BASE + 4, cpu.read_pc());
        for _i in 0..10 {
            // Until interrupt happens, .tick() does nothing
            cpu.run_soc(1, &mut uop_cache);
            assert_eq!(MEMORY_BASE + 4, cpu.read_pc());
        }
        // Machine timer interrupt
        cpu.write_csr_raw(Csr::Mie, MIP_MTIP);
        cpu.mmu.mip |= MIP_MTIP;
        cpu.write_csr_raw(Csr::Mstatus, 0x8);
        cpu.write_csr_raw(Csr::Mtvec, 0x0);
        cpu.run_soc(1, &mut uop_cache);
        // Interrupt happened and moved to handler
        assert_eq!(0, cpu.read_pc());
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
        cpu.write_csr_raw(Csr::Mie, MIP_MTIP);
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
