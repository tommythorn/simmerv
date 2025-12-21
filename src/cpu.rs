#![allow(clippy::unreadable_literal)]
#![allow(clippy::cast_possible_wrap)]

use crate::bounded::Bounded;
use crate::csr;
use crate::dag_decoder;
use crate::fp;
use crate::mmu::Mmu;
use crate::riscv;
use crate::rvc;
use crate::terminal;
pub use csr::*;
use fp::RoundingMode;
use fp::Sf;
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
use terminal::Terminal;

pub const CONFIG_SW_MANAGED_A_AND_D: bool = false;

pub const PG_SHIFT: usize = 12; // 4K page size

pub type Reg = Bounded<65>;
impl Reg {
    #[must_use]
    pub const fn is_x0_dest(self) -> bool { self.get() == 64 }
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
    // Remap x0 to the burn location 64.  This turns the write
    // into branch-free code, but the real payoff will come later
    // when we amortize this
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

/// Emulates a RISC-V CPU core
pub struct Cpu {
    // The essential CPU state
    rf: [i64; 65],
    pc: i64,
    frm_: RoundingMode, // XXX make this accessor functions on fcsr
    fflags_: u8,        // XXX make this accessor functions on fcsr
    fs: u8,             // XXX This is redundant and usage is suspect

    // Supervisor and CSR
    pub cycle: u64,
    csr: Box<[u64]>, // XXX this should be replaced with individual registers
    reservation: Option<u64>,

    // Wait-For-Interrupt; relax and await further instruction
    wfi: bool,

    // Important for sanity: uniquely name each executed insn
    // You can derive instret from this except sane people
    // could consider ECALL and EBREAK as committing.
    pub seqno: usize,

    // This is used for reporting exceptions
    pub insn_addr: i64,
    pub insn: u32,

    // Holds all memory and devices (XXX: this public mmu suggests we need to rethink the API)
    pub mmu: Mmu,

    // Decoding table
    decode_dag: Vec<u16>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Exception {
    pub trap: Trap,
    pub tval: i64,
}

const fn get_trap_cause(exc: &Exception) -> u64 {
    let interrupt_bit = 0x8000_0000_0000_0000_u64;
    if (exc.trap as u64) < (Trap::UserSoftwareInterrupt as u64) {
        exc.trap as u64
    } else {
        exc.trap as u64 - Trap::UserSoftwareInterrupt as u64 + interrupt_bit
    }
}

impl Cpu {
    /// Creates a new `Cpu`.
    ///
    /// # Arguments
    /// * `Terminal`
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
            frm_: RoundingMode::RoundNearestEven,
            fflags_: 0,
            fs: 1,

            seqno: 0,
            cycle: 0,
            wfi: false,
            pc: 0,
            insn_addr: 0,
            insn: 0,
            csr: vec![0; 4096].into_boxed_slice(), // XXX MUST GO AWAY SOON
            mmu,
            reservation: None,
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
    fn read_x(&self, r: Reg) -> i64 { self.rf[r] }

    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn write_x(&mut self, r: Reg, v: i64) {
        assert_ne!(r.get(), 0);
        self.rf[r] = v;
    }

    /// Reads Program counter
    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub const fn read_pc(&self) -> i64 { self.pc }

    /// Updates Program Counter
    ///
    /// # Arguments
    /// * `value`
    pub const fn update_pc(&mut self, value: i64) { self.pc = value & !1; }

    /// Reads integer register
    ///
    /// # Arguments
    /// * `reg` Register number. Must be 0-31
    #[must_use]
    pub fn read_register(&self, reg: Reg) -> i64 { self.rf[reg] }

    /// Checks that float instructions are enabled and
    /// that the rounding mode is legal (XXX this should be part of format!)
    fn check_float_access(&self, rm: usize) -> Result<(), Exception> {
        if self.fs == 0 || rm == 5 || rm == 6 {
            Err(Exception {
                trap: Trap::IllegalInstruction,
                tval: i64::from(self.insn),
            })
        } else {
            Ok(())
        }
    }

    /// Runs program N cycles. Fetch, decode, and execution are completed in a
    /// cycle so far.
    #[allow(clippy::cast_sign_loss)]
    pub fn run_soc(&mut self, cpu_steps: usize) -> bool {
        for _ in 0..cpu_steps {
            if let Err(exc) = self.step_cpu() {
                self.handle_exception(&exc);
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
    fn step_cpu(&mut self) -> Result<(), Exception> {
        self.cycle = self.cycle.wrapping_add(1);
        if self.wfi {
            if self.mmu.mip & self.read_csr_raw(Csr::Mie) != 0 {
                self.wfi = false;
            }
            return Ok(());
        }

        self.seqno = self.seqno.wrapping_add(1);
        self.insn_addr = self.pc;
        // Exception was triggered
        // XXX For full correctness we mustn't fail if we _can_ fetch 16-bit
        // _and_ it turns out to be a legal instruction.
        let word = self.memop(Execute, self.insn_addr, 0, 0, 4)?;
        self.insn = word as u32;

        let (insn, npc) = decompress(self.insn_addr, word as u32);
        self.pc = npc;
        let Ok(decoded) = decode(&self.decode_dag, insn) else {
            return Err(Exception {
                trap: Trap::IllegalInstruction,
                tval: word,
            });
        };

        (decoded.operation)(self, self.insn_addr, insn)
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

    fn handle_exception(&mut self, exception: &Exception) {
        if matches!(exception.trap, Trap::IllegalInstruction) {
            log::info!(
                "Illegal instruction {:016x} {:x}",
                self.insn_addr,
                self.insn
            );
        }
        self.handle_trap(exception, self.insn_addr, false);
    }

    #[allow(clippy::similar_names, clippy::too_many_lines)]
    #[allow(clippy::cast_sign_loss)]
    fn handle_trap(&mut self, exc: &Exception, insn_addr: i64, is_interrupt: bool) -> bool {
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

        self.write_csr_raw(csr_epc_address, insn_addr as u64);
        self.write_csr_raw(csr_cause_address, cause);
        self.write_csr_raw(csr_tval_address, exc.tval as u64);
        self.pc = self.read_csr_raw(csr_tvec_address) as i64;

        // Add 4 * cause if tvec has vector type address
        if self.pc & 3 != 0 {
            self.pc = (self.pc & !3) + 4 * (cause as i64 & 0xffff);
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
            log::warn!("** {:016x}: {csr:?} isn't implemented", self.insn_addr); // XXX Ok, fine, it's useful for debugging but ....
            return None;
        }

        let privilege = (csrno >> 8) & 3;
        if u64::from(privilege) > { u64::from(self.mmu.prv) } {
            log::warn!("** {:016x}: Lacking priviledge for {csr:?}", self.insn_addr);
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
            tval: i64::from(self.insn), /* XXX we could assign this outside, eliminating the need
                                         * for self.insn here */
        });

        let Some(csr) = self.has_csr_access_privilege(csrno) else {
            return illegal;
        };

        match csr {
            Csr::Fflags | Csr::Frm | Csr::Fcsr => self.check_float_access(0)?,
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
    fn write_csr(&mut self, csrno: u16, mut value: u64) -> Result<(), Exception> {
        let illegal = Err(Exception {
            trap: Trap::IllegalInstruction,
            tval: i64::from(self.insn), /* XXX we could assign this outside, eliminating the need
                                         * for self.insn here */
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
            Csr::Fflags | Csr::Frm | Csr::Fcsr => self.check_float_access(0)?,
            Csr::Cycle => {
                log::info!("** deny cycle writing from {:016x}", self.insn_addr);
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
            Csr::Fcsr => self.read_fcsr() as u64,
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
            Csr::Fcsr => self.write_fcsr(value as i64),
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

    fn _set_fcsr_nv(&mut self) { self.add_to_fflags(0x10); }

    fn set_fcsr_dz(&mut self) { self.add_to_fflags(8); }

    fn _set_fcsr_of(&mut self) { self.add_to_fflags(4); }

    fn _set_fcsr_uf(&mut self) { self.add_to_fflags(2); }

    fn _set_fcsr_nx(&mut self) { self.add_to_fflags(1); }

    /// Disassembles an instruction pointed by Program Counter and
    /// and return the [possibly] writeback register
    #[allow(clippy::cast_sign_loss)]
    pub fn disassemble_insn(&self, s: &mut String, addr: i64, mut word32: u32, eval: bool) -> Reg {
        let (insn, _) = decompress(addr, word32);
        let Ok(decoded) = decode(&self.decode_dag, insn) else {
            let _ = write!(s, "{addr:16x} {word32:8x} Illegal instruction");
            return xd(0);
        };

        let asm = decoded.name.to_lowercase();

        if word32 % 4 == 3 {
            let _ = write!(s, "{addr:16x} {word32:08x} {asm:7} ");
        } else {
            word32 &= 0xffff;
            let _ = write!(s, "{addr:16x}     {word32:04x} {asm:7} ");
        }
        (decoded.disassemble)(s, self, addr, insn, eval)
    }

    #[allow(clippy::cast_sign_loss)]
    pub fn disassemble(&mut self, s: &mut String) -> Reg {
        let Ok(word32) = self.memop_disass(self.pc) else {
            let _ = write!(s, "{:016x} <inaccessible>", self.pc);
            return xd(0);
        };
        self.disassemble_insn(s, self.pc, (word32 & 0xFFFFFFFF) as u32, true)
    }

    /// Returns mutable `Mmu`
    pub const fn get_mut_mmu(&mut self) -> &mut Mmu { &mut self.mmu }

    /// Returns mutable `Terminal`
    pub fn get_mut_terminal(&mut self) -> &mut Box<dyn Terminal> {
        self.mmu.get_mut_uart().get_mut_terminal()
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn read_f32(&self, r: Reg) -> f32 {
        assert_ne!(self.fs, 0);
        f32::from_bits(Sf32::unbox(self.read_f(r)) as u32)
    }

    fn read_f(&self, r: Reg) -> i64 {
        assert!(32 <= r.get() && r.get() < 64);
        assert_ne!(self.fs, 0);
        self.rf[r]
    }

    fn write_f(&mut self, r: Reg, v: i64) {
        assert!(32 <= r.get() && r.get() < 64);
        assert_ne!(self.fs, 0);
        self.rf[r] = v;
        self.fs = 3;
    }

    fn write_f32(&mut self, r: Reg, f: f32) {
        assert!(32 <= r.get() && r.get() < 64);
        self.write_f(r, fp::NAN_BOX_F32 | i64::from(f.to_bits()));
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn read_f64(&self, r: Reg) -> f64 { f64::from_bits(self.read_f(r) as u64) }

    fn write_f64(&mut self, r: Reg, f: f64) { self.write_f(r, f.to_bits() as i64); }

    fn read_frm(&self) -> RoundingMode {
        assert_ne!(self.fs, 0);
        self.frm_
    }

    fn write_frm(&mut self, frm: RoundingMode) {
        assert_ne!(self.fs, 0);
        self.fs = 3;
        self.frm_ = frm;
    }

    fn read_fflags(&self) -> u8 {
        assert_ne!(self.fs, 0);
        self.fflags_
    }

    fn write_fflags(&mut self, fflags: u8) {
        assert_ne!(self.fs, 0);
        self.fs = 3;
        self.fflags_ = fflags & 31;
    }

    fn add_to_fflags(&mut self, fflags: u8) {
        assert_ne!(self.fs, 0);
        self.fs = 3;
        self.fflags_ |= fflags & 31;
    }

    #[allow(clippy::precedence)]
    fn read_fcsr(&self) -> i64 {
        assert_ne!(self.fs, 0);
        i64::from(self.fflags_) | (self.frm_ as i64) << 5
    }

    #[allow(clippy::cast_sign_loss)]
    fn write_fcsr(&mut self, v: i64) {
        assert_ne!(self.fs, 0);
        let frm = (v >> 5) & 7;
        let Some(frm) = FromPrimitive::from_i64(frm) else {
            todo!("What is the appropriate behavior on illegal values?");
        };
        self.write_fflags((v & 31) as u8);
        self.write_frm(frm);
    }

    fn get_rm(&self, insn_rm_field: usize) -> RoundingMode {
        if insn_rm_field == 7 {
            self.frm_
        } else {
            let Some(rm) = FromPrimitive::from_usize(insn_rm_field) else {
                unreachable!();
            };
            rm
        }
    }

    fn memop(
        &mut self,
        access: MemoryAccessType,
        baseva: i64,
        offset: i64,
        v: i64,
        size: i64,
    ) -> Result<i64, Exception> {
        if access == MemoryAccessType::Write {
            self.reservation = None;
        }

        self.memop_general(access, baseva, offset, v, size, false)
    }

    fn memop_disass(&mut self, baseva: i64) -> Result<i64, Exception> {
        self.memop_general(Execute, baseva, 0, 0, 4, true)
    }

    // Memory access
    // - does virtual -> physical address translation
    // - directly handles exception
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    fn memop_general(
        &mut self,
        access: MemoryAccessType,
        baseva: i64,
        offset: i64,
        v: i64,
        size: i64,
        side_effect_free: bool,
    ) -> Result<i64, Exception> {
        let va = baseva.wrapping_add(offset);

        if va & 0xfff > 0x1000 - size {
            // Slow path. All bytes aren't in the same page so not contigious
            // in memory
            return self.memop_slow(access, va, v, size, side_effect_free);
        }

        let pa = self
            .mmu
            .translate_address(va as u64, access, side_effect_free)? as i64;

        let Ok(slice) = self.mmu.memory.slice(pa, size as usize) else {
            return self.memop_slow(access, va, v, size, side_effect_free);
        };

        match access {
            Write => {
                slice.copy_from_slice(&i64::to_le_bytes(v)[0..size as usize]);
                Ok(0)
            }
            Read | Execute => {
                // Unsigned, sign extension is the job of the consumer
                let mut buf = [0; 8];
                buf[0..size as usize].copy_from_slice(slice);
                Ok(i64::from_le_bytes(buf))
            }
        }
    }

    // Slow path where we either span multiple pages and/or access outside memory
    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    fn memop_slow(
        &mut self,
        access: MemoryAccessType,
        va: i64,
        mut v: i64,
        size: i64,
        side_effect_free: bool,
    ) -> Result<i64, Exception> {
        let trap = match access {
            Read => Trap::LoadAccessFault,
            Write => Trap::StoreAccessFault,
            Execute => Trap::InstructionAccessFault,
        };

        let mut r: u64 = 0;
        for i in 0..size {
            let pa = self
                .mmu
                .translate_address((va + i) as u64, access, side_effect_free)?;

            let mut b = 0;
            if let Ok(slice) = self.mmu.memory.slice(pa as i64, 1) {
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
                        if self.mmu.store_mmio_u8(pa as i64, v as u8).is_err() {
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
        if access == Write { Ok(0) } else { Ok(r as i64) }
    }
}

const fn decode(fdt: &[u16], word: u32) -> Result<&Instruction, ()> {
    let inst = &INSTRUCTIONS[dag_decoder::patmatch(fdt, word)];
    if word & inst.mask == inst.bits {
        Ok(inst)
    } else {
        Err(())
    }
}

#[derive(Debug)]
struct Instruction {
    mask: u32,
    bits: u32,
    name: &'static str,
    operation: fn(cpu: &mut Cpu, address: i64, word: u32) -> Result<(), Exception>,
    disassemble: fn(s: &mut String, cpu: &Cpu, address: i64, word: u32, evaluate: bool) -> Reg,
}

#[inline]
const fn decompress(addr: i64, insn: u32) -> (u32, i64) {
    if insn & 3 == 3 {
        (insn, addr.wrapping_add(4))
    } else {
        let insn = rvc::RVC64_EXPANDED[insn as usize & 0xffff];
        (insn, addr.wrapping_add(2))
    }
}

struct FormatB {
    rs1: Reg,
    rs2: Reg,
    imm: i64,
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
            ((iword >> 7) & 0x0000_001e)) as i64, // imm[4:1] = [11:8]
    }
}

fn dump_format_b(s: &mut String, cpu: &Cpu, address: i64, word: u32, evaluate: bool) -> Reg {
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
    xd(0)
}

struct FormatCSR {
    csr: u16,
    rs: Reg,
    rd: Reg,
}

fn parse_format_csr(word: u32) -> FormatCSR {
    FormatCSR {
        csr: ((word >> 20) & 0xfff) as u16, // [31:20]
        rs: x((word >> 15) & 0x1f),         // [19:15], also uimm
        rd: xd((word >> 7) & 0x1f),         // [11:7]
    }
}

#[allow(clippy::option_if_let_else)] // Clippy is loosing it
fn dump_format_csr(s: &mut String, cpu: &Cpu, _address: i64, word: u32, evaluate: bool) -> Reg {
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

    let _ = write!(s, ", {}", get_register_name(f.rs));
    if evaluate && f.rs.get() != 0 {
        let _ = write!(s, ":{:x}", cpu.read_x(f.rs));
    }
    f.rd
}

#[allow(clippy::option_if_let_else)] // Clippy is loosing it
fn dump_format_csri(s: &mut String, cpu: &Cpu, _address: i64, word: u32, evaluate: bool) -> Reg {
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

    let _ = write!(s, ", {}", f.rs.get());
    f.rd
}

struct FormatI {
    rd: Reg,
    rs1: Reg,
    imm: i64,
}

#[allow(clippy::cast_lossless)]
fn parse_format_i(word: u32) -> FormatI {
    FormatI {
        rd: xd((word >> 7) & 0x1f),  // [11:7]
        rs1: x((word >> 15) & 0x1f), // [19:15]
        imm: (
            // XXX fix this mess
            match word & 0x8000_0000 {
                // imm[31:11] = [31]
                0x8000_0000 => 0xffff_f800,
                _ => 0,
            } | ((word >> 20) & 0x0000_07ff)
            // imm[10:0] = [30:20]
        ) as i32 as i64,
    }
}

#[allow(clippy::cast_lossless)]
fn parse_format_i_fx(word: u32) -> FormatI {
    FormatI {
        rd: f((word >> 7) & 0x1f),   // [11:7]
        rs1: x((word >> 15) & 0x1f), // [19:15]
        imm: (
            // XXX fix this mess
            match word & 0x8000_0000 {
                // imm[31:11] = [31]
                0x8000_0000 => 0xffff_f800,
                _ => 0,
            } | ((word >> 20) & 0x0000_07ff)
            // imm[10:0] = [30:20]
        ) as i32 as i64,
    }
}

fn dump_format_i(s: &mut String, cpu: &Cpu, _address: i64, word: u32, evaluate: bool) -> Reg {
    let f = parse_format_i(word);
    *s += get_register_name(f.rd);
    let _ = write!(s, ", {}", get_register_name(f.rs1));
    if evaluate && f.rs1.get() != 0 {
        let _ = write!(s, ":{:x}", cpu.read_x(f.rs1));
    }
    let _ = write!(s, ", {:x}", f.imm);
    f.rd
}

fn dump_format_i_mem(s: &mut String, cpu: &Cpu, _address: i64, word: u32, evaluate: bool) -> Reg {
    let f = parse_format_i(word);
    *s += get_register_name(f.rd);
    let _ = write!(s, ", {:x}({}", f.imm, get_register_name(f.rs1));
    if evaluate && f.rs1.get() != 0 {
        let _ = write!(s, ":{:x}", cpu.read_x(f.rs1));
    }
    *s += ")";
    f.rd
}

struct FormatJ {
    rd: Reg,
    imm: i64,
}

#[allow(clippy::cast_lossless)]
fn parse_format_j(word: u32) -> FormatJ {
    let iword = word as i32;
    FormatJ {
        rd: xd((word >> 7) & 0x1f), // [11:7]
        imm: (iword >> 31 << 20 | // imm[31:20] = [31]
             (iword & 0x000f_f000) | // imm[19:12] = [19:12]
             ((iword & 0x0010_0000) >> 9) | // imm[11] = [20]
             ((iword & 0x7fe0_0000) >> 20)) as i64, // imm[10:1] = [30:21]
    }
}

fn dump_format_j(s: &mut String, _cpu: &Cpu, address: i64, word: u32, _evaluate: bool) -> Reg {
    let f = parse_format_j(word);
    *s += get_register_name(f.rd);
    let _ = write!(s, ", {:x}", address.wrapping_add(f.imm));
    f.rd
}

#[derive(Debug)]
struct FormatR {
    rd: Reg,
    funct3: usize,
    rs1: Reg,
    rs2: Reg,
}

fn parse_format_r(word: u32) -> FormatR {
    FormatR {
        rd: xd((word >> 7) & 0x1f),          // [11:7]
        funct3: ((word >> 12) & 7) as usize, // [14:12]
        rs1: x((word >> 15) & 0x1f),         // [19:15]
        rs2: x((word >> 20) & 0x1f),         // [24:20]
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

fn parse_format_r_ff(word: u32) -> FormatR {
    FormatR {
        rd: f((word >> 7) & 0x1f),           // [11:7]
        funct3: ((word >> 12) & 7) as usize, // [14:12]
        rs1: f((word >> 15) & 0x1f),         // [19:15]
        rs2: f((word >> 20) & 0x1f),         // [24:20]
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

fn dump_format_r(s: &mut String, cpu: &Cpu, _address: i64, word: u32, evaluate: bool) -> Reg {
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
    f.rd
}

fn dump_format_ri(s: &mut String, cpu: &Cpu, _address: i64, word: u32, evaluate: bool) -> Reg {
    let f = parse_format_r(word);
    *s += get_register_name(f.rd);
    let _ = write!(s, ", ");
    *s += get_register_name(f.rs1);
    if evaluate && f.rs1.get() != 0 {
        let _ = write!(s, ":{:x}", cpu.read_x(f.rs1));
    }
    let shamt = (word >> 20) & 63;
    let _ = write!(s, ", {shamt}");
    f.rd
}

fn dump_format_r_f(s: &mut String, cpu: &Cpu, _address: i64, word: u32, evaluate: bool) -> Reg {
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
    f.rd
}

// has rs3
struct FormatR2 {
    rd: Reg,
    rm: usize,
    rs1: Reg,
    rs2: Reg,
    rs3: Reg,
}

fn parse_format_r2_ffff(word: u32) -> FormatR2 {
    FormatR2 {
        rd: f((word >> 7) & 0x1f),       // [11:7]
        rm: ((word >> 12) & 7) as usize, // [14:12]
        rs1: f((word >> 15) & 0x1f),     // [19:15]
        rs2: f((word >> 20) & 0x1f),     // [24:20]
        rs3: f((word >> 27) & 0x1f),     // [31:27]
    }
}

fn dump_format_r2_ffff(s: &mut String, cpu: &Cpu, _address: i64, word: u32, evaluate: bool) -> Reg {
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
    f.rd
}

struct FormatS {
    rs1: Reg,
    rs2: Reg,
    imm: i64,
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
        ) as i32 as i64,
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
        ) as i32 as i64,
    }
}

fn dump_format_s(s: &mut String, cpu: &Cpu, _address: i64, word: u32, evaluate: bool) -> Reg {
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
    xd(0)
}

struct FormatU {
    rd: Reg,
    imm: i64,
}

#[allow(clippy::cast_lossless)]
fn parse_format_u(word: u32) -> FormatU {
    FormatU {
        rd: xd((word >> 7) & 31), // [11:7]
        imm: (word & 0xfffff000) as i32 as i64,
    }
}

fn dump_format_u(s: &mut String, _cpu: &Cpu, _address: i64, word: u32, _evaluate: bool) -> Reg {
    let f = parse_format_u(word);
    *s += get_register_name(f.rd);
    let _ = write!(s, ", {:x}", f.imm);

    f.rd
}

#[allow(clippy::ptr_arg)] // Clippy can't tell that we can't change the function type
fn dump_empty(_s: &mut String, _cpu: &Cpu, _address: i64, _word: u32, _evaluate: bool) -> Reg {
    xd(0)
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

const INSTRUCTION_NUM: usize = 173;

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::float_cmp,
    clippy::cast_lossless
)]
const INSTRUCTIONS: [Instruction; INSTRUCTION_NUM] = [
    // RV32I
    Instruction {
        mask: 0x0000007f,
        bits: 0x00000037,
        name: "LUI",
        operation: |cpu, _address, word| {
            let f = parse_format_u(word);
            cpu.write_x(f.rd, f.imm);
            Ok(())
        },
        disassemble: dump_format_u,
    },
    Instruction {
        mask: 0x0000007f,
        bits: 0x00000017,
        name: "AUIPC",
        operation: |cpu, address, word| {
            let f = parse_format_u(word);
            cpu.write_x(f.rd, address.wrapping_add(f.imm));
            Ok(())
        },
        disassemble: dump_format_u,
    },
    Instruction {
        mask: 0x0000007f,
        bits: 0x0000006f,
        name: "JAL",
        operation: |cpu, address, word| {
            let f = parse_format_j(word);
            cpu.write_x(f.rd, cpu.pc);
            cpu.pc = address.wrapping_add(f.imm);
            Ok(())
        },
        disassemble: dump_format_j,
    },
    Instruction {
        mask: 0x0000707f,
        bits: 0x00000067,
        name: "JALR",
        operation: |cpu, _address, word| {
            let f = parse_format_i(word);
            let tmp = cpu.pc;
            cpu.pc = cpu.read_x(f.rs1).wrapping_add(f.imm) & !1;
            cpu.write_x(f.rd, tmp);
            Ok(())
        },
        disassemble: |s, cpu, _address, word, evaluate| {
            let f = parse_format_i(word);
            *s += get_register_name(f.rd);
            let _ = write!(s, ", {:x}({}", f.imm, get_register_name(f.rs1));
            if evaluate && f.rs1.get() != 0 {
                let _ = write!(s, ":{:x}", cpu.read_x(f.rs1));
            }
            *s += ")";
            f.rd
        },
    },
    Instruction {
        mask: 0x0000707f,
        bits: 0x00000063,
        name: "BEQ",
        operation: |cpu, address, word| {
            let f = parse_format_b(word);
            if cpu.read_x(f.rs1) == cpu.read_x(f.rs2) {
                cpu.pc = address.wrapping_add(f.imm);
            }
            Ok(())
        },
        disassemble: dump_format_b,
    },
    Instruction {
        mask: 0x0000707f,
        bits: 0x00001063,
        name: "BNE",
        operation: |cpu, address, word| {
            let f = parse_format_b(word);
            if cpu.read_x(f.rs1) != cpu.read_x(f.rs2) {
                cpu.pc = address.wrapping_add(f.imm);
            }
            Ok(())
        },
        disassemble: dump_format_b,
    },
    Instruction {
        mask: 0x0000707f,
        bits: 0x00004063,
        name: "BLT",
        operation: |cpu, address, word| {
            let f = parse_format_b(word);
            if cpu.read_x(f.rs1) < cpu.read_x(f.rs2) {
                cpu.pc = address.wrapping_add(f.imm);
            }
            Ok(())
        },
        disassemble: dump_format_b,
    },
    Instruction {
        mask: 0x0000707f,
        bits: 0x00005063,
        name: "BGE",
        operation: |cpu, address, word| {
            let f = parse_format_b(word);
            if cpu.read_x(f.rs1) >= cpu.read_x(f.rs2) {
                cpu.pc = address.wrapping_add(f.imm);
            }
            Ok(())
        },
        disassemble: dump_format_b,
    },
    Instruction {
        mask: 0x0000707f,
        bits: 0x00006063,
        name: "BLTU",
        operation: |cpu, address, word| {
            let f = parse_format_b(word);
            if (cpu.read_x(f.rs1) as u64) < (cpu.read_x(f.rs2) as u64) {
                cpu.pc = address.wrapping_add(f.imm);
            }
            Ok(())
        },
        disassemble: dump_format_b,
    },
    Instruction {
        mask: 0x0000707f,
        bits: 0x00007063,
        name: "BGEU",
        operation: |cpu, address, word| {
            let f = parse_format_b(word);
            if (cpu.read_x(f.rs1) as u64) >= (cpu.read_x(f.rs2) as u64) {
                cpu.pc = address.wrapping_add(f.imm);
            }
            Ok(())
        },
        disassemble: dump_format_b,
    },
    Instruction {
        mask: 0x0000707f,
        bits: 0x00000003,
        name: "LB",
        operation: |cpu, _address, word| {
            let f = parse_format_i(word);
            let s1 = cpu.read_x(f.rs1);
            let v = cpu.memop(Read, s1, f.imm, 0, 1)? as i8 as i64;
            cpu.write_x(f.rd, v);
            Ok(())
        },
        disassemble: dump_format_i_mem,
    },
    Instruction {
        mask: 0x0000707f,
        bits: 0x00001003,
        name: "LH",
        operation: |cpu, _address, word| {
            let f = parse_format_i(word);
            let s1 = cpu.read_x(f.rs1);
            let v = cpu.memop(Read, s1, f.imm, 0, 2)? as i16 as i64;
            cpu.write_x(f.rd, v);
            Ok(())
        },
        disassemble: dump_format_i_mem,
    },
    Instruction {
        mask: 0x0000707f,
        bits: 0x00002003,
        name: "LW",
        operation: |cpu, _address, word| {
            let f = parse_format_i(word);
            let s1 = cpu.read_x(f.rs1);
            let v = cpu.memop(Read, s1, f.imm, 0, 4)?;
            cpu.write_x(f.rd, v as i32 as i64);
            Ok(())
        },
        disassemble: dump_format_i_mem,
    },
    Instruction {
        mask: 0x0000707f,
        bits: 0x00004003,
        name: "LBU",
        operation: |cpu, _address, word| {
            let f = parse_format_i(word);
            let s1 = cpu.read_x(f.rs1);
            let v = cpu.memop(Read, s1, f.imm, 0, 1)?;
            cpu.write_x(f.rd, v);
            Ok(())
        },
        disassemble: dump_format_i_mem,
    },
    Instruction {
        mask: 0x0000707f,
        bits: 0x00005003,
        name: "LHU",
        operation: |cpu, _address, word| {
            let f = parse_format_i(word);
            let s1 = cpu.read_x(f.rs1);
            let v = cpu.memop(Read, s1, f.imm, 0, 2)?;
            cpu.write_x(f.rd, v);
            Ok(())
        },
        disassemble: dump_format_i_mem,
    },
    Instruction {
        mask: 0x0000707f,
        bits: 0x00000023,
        name: "SB",
        operation: |cpu, _address, word| {
            let f = parse_format_s(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            let _ = cpu.memop(Write, s1, f.imm, s2, 1)?;
            Ok(())
        },
        disassemble: dump_format_s,
    },
    Instruction {
        mask: 0x0000707f,
        bits: 0x00001023,
        name: "SH",
        operation: |cpu, _address, word| {
            let f = parse_format_s(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            let _ = cpu.memop(Write, s1, f.imm, s2, 2)?;
            Ok(())
        },
        disassemble: dump_format_s,
    },
    Instruction {
        mask: 0x0000707f,
        bits: 0x00002023,
        name: "SW",
        operation: |cpu, _address, word| {
            let f = parse_format_s(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            let _ = cpu.memop(Write, s1, f.imm, s2, 4)?;
            Ok(())
        },
        disassemble: dump_format_s,
    },
    Instruction {
        mask: 0x0000707f,
        bits: 0x00000013,
        name: "ADDI",
        operation: |cpu, _address, word| {
            let f = parse_format_i(word);
            let s1 = cpu.read_x(f.rs1);
            cpu.write_x(f.rd, s1.wrapping_add(f.imm));
            Ok(())
        },
        disassemble: dump_format_i,
    },
    Instruction {
        mask: 0x0000707f,
        bits: 0x00002013,
        name: "SLTI",
        operation: |cpu, _address, word| {
            let f = parse_format_i(word);
            let s1 = cpu.read_x(f.rs1);
            cpu.write_x(f.rd, i64::from(s1 < f.imm));
            Ok(())
        },
        disassemble: dump_format_i,
    },
    Instruction {
        mask: 0x0000707f,
        bits: 0x00003013,
        name: "SLTIU",
        operation: |cpu, _address, word| {
            let f = parse_format_i(word);
            let s1 = cpu.read_x(f.rs1);
            cpu.write_x(f.rd, i64::from((s1 as u64) < (f.imm as u64)));
            Ok(())
        },
        disassemble: dump_format_i,
    },
    Instruction {
        mask: 0x0000707f,
        bits: 0x00004013,
        name: "XORI",
        operation: |cpu, _address, word| {
            let f = parse_format_i(word);
            let s1 = cpu.read_x(f.rs1);
            cpu.write_x(f.rd, s1 ^ f.imm);
            Ok(())
        },
        disassemble: dump_format_i,
    },
    Instruction {
        mask: 0x0000707f,
        bits: 0x00006013,
        name: "ORI",
        operation: |cpu, _address, word| {
            let f = parse_format_i(word);
            let s1 = cpu.read_x(f.rs1);
            cpu.write_x(f.rd, s1 | f.imm);
            Ok(())
        },
        disassemble: dump_format_i,
    },
    Instruction {
        mask: 0x0000707f,
        bits: 0x00007013,
        name: "ANDI",
        operation: |cpu, _address, word| {
            let f = parse_format_i(word);
            let s1 = cpu.read_x(f.rs1);
            cpu.write_x(f.rd, s1 & f.imm);
            Ok(())
        },
        disassemble: dump_format_i,
    },
    // RV32I SLLI subsumed by RV64I
    // RV32I SRLI subsumed by RV64I
    // RV32I SRAI subsumed by RV64I
    Instruction {
        mask: 0xfe00707f,
        bits: 0x00000033,
        name: "ADD",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            cpu.write_x(f.rd, s1.wrapping_add(s2));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x40000033,
        name: "SUB",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            cpu.write_x(f.rd, s1.wrapping_sub(s2));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x00001033,
        name: "SLL",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            cpu.write_x(f.rd, s1.wrapping_shl(s2 as u32));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x00002033,
        name: "SLT",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            cpu.write_x(f.rd, i64::from(s1 < s2));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x00003033,
        name: "SLTU",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1) as u64;
            let s2 = cpu.read_x(f.rs2) as u64;
            cpu.write_x(f.rd, i64::from(s1 < s2));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x00004033,
        name: "XOR",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            cpu.write_x(f.rd, s1 ^ s2);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x00005033,
        name: "SRL",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1) as u64;
            let s2 = cpu.read_x(f.rs2) as u32;
            cpu.write_x(f.rd, s1.wrapping_shr(s2) as i64);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x40005033,
        name: "SRA",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            cpu.write_x(f.rd, s1.wrapping_shr(s2 as u32));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x00006033,
        name: "OR",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            cpu.write_x(f.rd, s1 | s2);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x00007033,
        name: "AND",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            cpu.write_x(f.rd, s1 & s2);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf000707f,
        bits: 0x0000000f,
        name: "FENCE",
        operation: |_cpu, _address, word| {
            if word == 0x0100000f {
                // Nothing to do here, but it would be interesting to see
                // it used.
                log::trace!("pause isn't yet implemented");
            }
            // Fence memory ops (we are currently TSO already)
            Ok(())
        },
        disassemble: dump_empty,
    },
    Instruction {
        mask: 0xf000707f,
        bits: 0x8000000f,
        name: "FENCE.TSO",
        operation: |_cpu, __address, _word| {
            // Fence memory ops (we are currently TSO already)
            Ok(())
        },
        disassemble: dump_empty,
    },
    Instruction {
        mask: 0xffffffff,
        bits: 0x00000073,
        name: "ECALL",
        operation: |cpu, address, _word| {
            let trap_type = match cpu.mmu.prv {
                PrivMode::U => Trap::EnvironmentCallFromUMode,
                PrivMode::S => Trap::EnvironmentCallFromSMode,
                PrivMode::M => Trap::EnvironmentCallFromMMode,
            };
            Err(Exception {
                trap: trap_type,
                tval: address,
            })
        },
        disassemble: dump_empty,
    },
    Instruction {
        mask: 0xffffffff,
        bits: 0x00100073,
        name: "EBREAK",
        operation: |_cpu, _address, word| {
            Err(Exception {
                trap: Trap::Breakpoint,
                tval: word as i64,
            })
        },
        disassemble: dump_empty,
    },
    // RV64I
    Instruction {
        mask: 0x0000707f,
        bits: 0x00006003,
        name: "LWU",
        operation: |cpu, _address, word| {
            let f = parse_format_i(word);
            let s1 = cpu.read_x(f.rs1);
            let v = cpu.memop(Read, s1, f.imm, 0, 4)?;
            cpu.write_x(f.rd, v);
            Ok(())
        },
        disassemble: dump_format_i_mem,
    },
    Instruction {
        mask: 0x0000707f,
        bits: 0x00003003,
        name: "LD",
        operation: |cpu, _address, word| {
            let f = parse_format_i(word);
            let s1 = cpu.read_x(f.rs1);
            let v = cpu.memop(Read, s1, f.imm, 0, 8)?;
            cpu.write_x(f.rd, v);
            Ok(())
        },
        disassemble: dump_format_i_mem,
    },
    Instruction {
        mask: 0x0000707f,
        bits: 0x00003023,
        name: "SD",
        operation: |cpu, _address, word| {
            let f = parse_format_s(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            let _ = cpu.memop(Write, s1, f.imm, s2, 8)?;
            Ok(())
        },
        disassemble: dump_format_s,
    },
    Instruction {
        mask: 0xfc00707f, // RV64I version!
        bits: 0x00001013,
        name: "SLLI",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let mask = 0x3f;
            let shamt = (word >> 20) & mask;
            let s1 = cpu.read_x(f.rs1);
            cpu.write_x(f.rd, s1 << shamt);
            Ok(())
        },
        disassemble: dump_format_ri,
    },
    Instruction {
        mask: 0xfc00707f,
        bits: 0x00005013,
        name: "SRLI",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let mask = 0x3f;
            let shamt = (word >> 20) & mask;
            let s1 = cpu.read_x(f.rs1);
            cpu.write_x(f.rd, ((s1 as u64) >> shamt) as i64);
            Ok(())
        },
        disassemble: dump_format_ri,
    },
    Instruction {
        mask: 0xfc00707f,
        bits: 0x40005013,
        name: "SRAI",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let mask = 0x3f;
            let shamt = (word >> 20) & mask;
            let s1 = cpu.read_x(f.rs1);
            cpu.write_x(f.rd, s1 >> shamt);
            Ok(())
        },
        disassemble: dump_format_ri,
    },
    Instruction {
        mask: 0x0000707f,
        bits: 0x0000001b,
        name: "ADDIW",
        operation: |cpu, _address, word| {
            let f = parse_format_i(word);
            let s1 = cpu.read_x(f.rs1);
            cpu.write_x(f.rd, i64::from(s1.wrapping_add(f.imm) as i32));
            Ok(())
        },
        disassemble: dump_format_i,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x0000101b,
        name: "SLLIW",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let shamt = f.rs2.get();
            let s1 = cpu.read_x(f.rs1);
            cpu.write_x(f.rd, i64::from((s1 << shamt) as i32));
            Ok(())
        },
        disassemble: dump_format_ri,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x0000501b,
        name: "SRLIW",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let mask = 0x1f;
            let shamt = (word >> 20) & mask;
            let s1 = cpu.read_x(f.rs1);
            cpu.write_x(f.rd, i64::from(((s1 as u32) >> shamt) as i32));
            Ok(())
        },
        disassemble: dump_format_ri,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x4000501b,
        name: "SRAIW",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let shamt = (word >> 20) & 0x1f;
            let s1 = cpu.read_x(f.rs1);
            cpu.write_x(f.rd, i64::from((s1 as i32) >> shamt));
            Ok(())
        },
        disassemble: dump_format_ri,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x0000003b,
        name: "ADDW",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            cpu.write_x(f.rd, i64::from(s1.wrapping_add(s2) as i32));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x4000003b,
        name: "SUBW",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            cpu.write_x(f.rd, i64::from(s1.wrapping_sub(s2) as i32));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x0000103b,
        name: "SLLW",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            cpu.write_x(f.rd, i64::from((s1 as u32).wrapping_shl(s2 as u32) as i32));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x0000503b,
        name: "SRLW",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            cpu.write_x(f.rd, i64::from((s1 as u32).wrapping_shr(s2 as u32) as i32));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x4000503b,
        name: "SRAW",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            cpu.write_x(f.rd, i64::from((s1 as i32).wrapping_shr(s2 as u32)));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    // RV32/RV64 Zifencei
    Instruction {
        mask: 0xffffffff,
        bits: 0x0000100f,
        name: "FENCE.I",
        operation: |cpu, _address, _word| {
            // Flush any cached instrutions.  We have none so far.
            cpu.reservation = None;
            Ok(())
        },
        disassemble: dump_empty,
    },
    // RV32/RV64 Zicsr
    Instruction {
        mask: 0x0000707f,
        bits: 0x00001073,
        name: "CSRRW",
        operation: |cpu, _address, word| {
            let f = parse_format_csr(word);

            let tmp = cpu.read_x(f.rs);
            if f.rd.is_x0_dest() {
                cpu.write_csr(f.csr, tmp as u64)?;
            } else {
                let v = cpu.read_csr(f.csr)? as i64;
                cpu.write_csr(f.csr, tmp as u64)?;
                cpu.write_x(f.rd, v);
            }

            Ok(())
        },
        disassemble: dump_format_csr,
    },
    Instruction {
        mask: 0x0000707f,
        bits: 0x00002073,
        name: "CSRRS",
        operation: |cpu, _address, word| {
            let f = parse_format_csr(word);
            let data = cpu.read_csr(f.csr)? as i64;
            if f.rs.get() != 0 {
                let value = cpu.read_x(f.rs);
                cpu.write_csr(f.csr, (data | value) as u64)?;
            }
            cpu.write_x(f.rd, data);
            Ok(())
        },
        disassemble: dump_format_csr,
    },
    Instruction {
        mask: 0x0000707f,
        bits: 0x00003073,
        name: "CSRRC",
        operation: |cpu, _address, word| {
            let f = parse_format_csr(word);
            let data = cpu.read_csr(f.csr)? as i64;
            if f.rs.get() != 0 {
                let value = cpu.read_x(f.rs);
                cpu.write_csr(f.csr, (data & !value) as u64)?;
            }
            cpu.write_x(f.rd, data);
            Ok(())
        },
        disassemble: dump_format_csr,
    },
    Instruction {
        mask: 0x0000707f,
        bits: 0x00005073,
        name: "CSRRWI",
        operation: |cpu, _address, word| {
            let f = parse_format_csr(word);

            if f.rd.is_x0_dest() {
                cpu.write_csr(f.csr, f.rs.get() as u64)?;
            } else {
                let v = cpu.read_csr(f.csr)? as i64;
                cpu.write_csr(f.csr, f.rs.get() as u64)?;
                cpu.write_x(f.rd, v);
            }

            Ok(())
        },
        disassemble: dump_format_csri,
    },
    Instruction {
        mask: 0x0000707f,
        bits: 0x00006073,
        name: "CSRRSI",
        operation: |cpu, _address, word| {
            let f = parse_format_csr(word);
            let data = cpu.read_csr(f.csr)? as i64;
            if f.rs.get() != 0 {
                cpu.write_csr(f.csr, (data | f.rs.get() as i64) as u64)?;
            }
            cpu.write_x(f.rd, data);
            Ok(())
        },
        disassemble: dump_format_csri,
    },
    Instruction {
        mask: 0x0000707f,
        bits: 0x00007073,
        name: "CSRRCI",
        operation: |cpu, _address, word| {
            let f = parse_format_csr(word);
            let data = cpu.read_csr(f.csr)? as i64;
            if f.rs.get() != 0 {
                cpu.write_csr(f.csr, (data & !(f.rs.get() as i64)) as u64)?;
            }
            cpu.write_x(f.rd, data);
            Ok(())
        },
        disassemble: dump_format_csri,
    },
    // RV32M
    Instruction {
        mask: 0xfe00707f,
        bits: 0x02000033,
        name: "MUL",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            cpu.write_x(f.rd, s1.wrapping_mul(s2));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x02001033,
        name: "MULH",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            cpu.write_x(f.rd, ((i128::from(s1) * i128::from(s2)) >> 64) as i64);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x02002033,
        name: "MULHSU",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            cpu.write_x(
                f.rd,
                ((s1 as u128).wrapping_mul(u128::from(s2 as u64)) >> 64) as i64,
            );
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x02003033,
        name: "MULHU",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = u128::from(cpu.read_x(f.rs1) as u64);
            let s2 = u128::from(cpu.read_x(f.rs2) as u64);
            cpu.write_x(f.rd, (s1.wrapping_mul(s2) >> 64) as i64);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x02004033,
        name: "DIV",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let dividend = cpu.read_x(f.rs1);
            let divisor = cpu.read_x(f.rs2);
            if divisor == 0 {
                cpu.write_x(f.rd, -1);
            } else if dividend == i64::MIN && divisor == -1 {
                cpu.write_x(f.rd, dividend);
            } else {
                cpu.write_x(f.rd, dividend.wrapping_div(divisor));
            }
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x02005033,
        name: "DIVU",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let dividend = cpu.read_x(f.rs1) as u64;
            let divisor = cpu.read_x(f.rs2) as u64;
            if divisor == 0 {
                cpu.write_x(f.rd, -1);
            } else {
                cpu.write_x(f.rd, dividend.wrapping_div(divisor) as i64);
            }
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x02006033,
        name: "REM",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            if s2 == 0 {
                cpu.write_x(f.rd, s1);
            } else if s1 == i64::MIN && s2 == -1 {
                cpu.write_x(f.rd, 0);
            } else {
                cpu.write_x(f.rd, s1.wrapping_rem(s2));
            }
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x02007033,
        name: "REMU",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1) as u64;
            let s2 = cpu.read_x(f.rs2) as u64;
            cpu.write_x(f.rd, match s2 {
                0 => s1 as i64,
                _ => s1.wrapping_rem(s2) as i64,
            });
            Ok(())
        },
        disassemble: dump_format_r,
    },
    // RV64M
    Instruction {
        mask: 0xfe00707f,
        bits: 0x0200003b,
        name: "MULW",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            cpu.write_x(f.rd, i64::from((s1 as i32).wrapping_mul(s2 as i32)));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x0200403b,
        name: "DIVW",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1) as i32;
            let s2 = cpu.read_x(f.rs2) as i32;
            if s2 == 0 {
                cpu.write_x(f.rd, -1);
            } else if s1 == i32::MIN && s2 == -1 {
                cpu.write_x(f.rd, i64::from(s1 as i32));
            } else {
                cpu.write_x(f.rd, i64::from(s1.wrapping_div(s2) as i32));
            }
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x0200503b,
        name: "DIVUW",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1) as u32;
            let s2 = cpu.read_x(f.rs2) as u32;
            if s2 == 0 {
                cpu.write_x(f.rd, -1);
            } else {
                cpu.write_x(f.rd, i64::from(s1.wrapping_div(s2) as i32));
            }
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x0200603b,
        name: "REMW",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1) as i32;
            let s2 = cpu.read_x(f.rs2) as i32;
            if s2 == 0 {
                cpu.write_x(f.rd, i64::from(s1));
            } else if s1 == i32::MIN && s2 == -1 {
                cpu.write_x(f.rd, 0);
            } else {
                cpu.write_x(f.rd, i64::from(s1.wrapping_rem(s2)));
            }
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x0200703b,
        name: "REMUW",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1) as u32;
            let s2 = cpu.read_x(f.rs2) as u32;
            cpu.write_x(f.rd, match s2 {
                0 => i64::from(s1 as i32),
                _ => i64::from(s1.wrapping_rem(s2) as i32),
            });
            Ok(())
        },
        disassemble: dump_format_r,
    },
    // RV32A
    Instruction {
        mask: 0xf9f0707f,
        bits: 0x1000202f,
        name: "LR.W",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let va = cpu.read_x(f.rs1);
            let data = cpu.mmu.load_virt_u32(va as u64)? as i32;
            let pa = cpu
                .mmu
                .translate_address(va as u64, MemoryAccessType::Read, false)?;
            cpu.reservation = Some(pa);
            cpu.write_x(f.rd, i64::from(data));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        bits: 0x1800202f,
        name: "SC.W",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let va = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            let pa = cpu
                .mmu
                .translate_address(va as u64, MemoryAccessType::Read, false)?;
            if cpu.reservation == Some(pa) {
                cpu.mmu.store_virt_u32(va as u64, s2 as u32)?;
                cpu.write_x(f.rd, 0);
            } else {
                cpu.write_x(f.rd, 1);
            }
            cpu.reservation = None;
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        bits: 0x0800202f,
        name: "AMOSWAP.W",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1) as u64;
            let s2 = cpu.read_x(f.rs2) as u32;
            let tmp = i64::from(cpu.mmu.load_virt_u32(s1)? as i32);
            cpu.mmu.store_virt_u32(s1, s2)?;
            cpu.write_x(f.rd, tmp);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        bits: 0x0000202f,
        name: "AMOADD.W",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1) as u64;
            let s2 = cpu.read_x(f.rs2) as u32;
            let tmp = cpu.mmu.load_virt_u32(s1)?;
            cpu.mmu.store_virt_u32(s1, tmp.wrapping_add(s2))?;
            cpu.write_x(f.rd, i64::from(tmp as i32));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        bits: 0x2000202f,
        name: "AMOXOR.W",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1) as u64;
            let s2 = cpu.read_x(f.rs2) as u32;
            let tmp = cpu.mmu.load_virt_u32(s1)?;
            cpu.mmu.store_virt_u32(s1, s2 ^ tmp)?;
            cpu.write_x(f.rd, i64::from(tmp as i32));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        bits: 0x6000202f,
        name: "AMOAND.W",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1) as u64;
            let s2 = cpu.read_x(f.rs2);
            let tmp = i64::from(cpu.mmu.load_virt_u32(s1)? as i32);
            cpu.mmu.store_virt_u32(s1, (s2 & tmp) as u32)?;
            cpu.write_x(f.rd, tmp);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        bits: 0x4000202f,
        name: "AMOOR.W",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1) as u64;
            let s2 = cpu.read_x(f.rs2);
            let tmp = i64::from(cpu.mmu.load_virt_u32(s1)? as i32);
            cpu.mmu.store_virt_u32(s1, (s2 | tmp) as u32)?;
            cpu.write_x(f.rd, tmp);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        bits: 0x8000202f,
        name: "AMOMIN.W",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1) as u64;
            let s2 = cpu.read_x(f.rs2) as i32;
            let tmp = cpu.mmu.load_virt_u32(s1)? as i32;
            let min = if s2 < tmp { s2 } else { tmp };
            cpu.mmu.store_virt_u32(s1, min as u32)?;
            cpu.write_x(f.rd, i64::from(tmp));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        bits: 0xa000202f,
        name: "AMOMAX.W",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1) as u64;
            let s2 = cpu.read_x(f.rs2) as i32;
            let tmp = cpu.mmu.load_virt_u32(s1)? as i32;
            let max = if s2 >= tmp { s2 } else { tmp };
            cpu.mmu.store_virt_u32(s1, max as u32)?;
            cpu.write_x(f.rd, i64::from(tmp));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        bits: 0xc000202f,
        name: "AMOMINU.W",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1) as u64;
            let s2 = cpu.read_x(f.rs2) as u32;
            let tmp = cpu.mmu.load_virt_u32(s1)?;
            let min = if s2 <= tmp { s2 } else { tmp };
            cpu.mmu.store_virt_u32(s1, min)?;
            cpu.write_x(f.rd, i64::from(tmp as i32));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        bits: 0xe000202f,
        name: "AMOMAXU.W",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1) as u64;
            let s2 = cpu.read_x(f.rs2) as u32;
            let tmp = cpu.mmu.load_virt_u32(s1)?;
            let max = if s2 >= tmp { s2 } else { tmp };
            cpu.mmu.store_virt_u32(s1, max)?;
            cpu.write_x(f.rd, i64::from(tmp as i32));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    // RV64A
    Instruction {
        mask: 0xf9f0707f,
        bits: 0x1000302f,
        name: "LR.D",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let va = cpu.read_x(f.rs1);
            let data = cpu.mmu.load_virt_u64(va as u64)?;
            let pa = cpu
                .mmu
                .translate_address(va as u64, MemoryAccessType::Read, false)?;
            cpu.reservation = Some(pa);
            cpu.write_x(f.rd, data as i64);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        bits: 0x1800302f,
        name: "SC.D",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let va = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            let pa = cpu
                .mmu
                .translate_address(va as u64, MemoryAccessType::Read, false)?;
            if cpu.reservation == Some(pa) {
                cpu.mmu.store_virt_u64(va as u64, s2 as u64)?;
                cpu.write_x(f.rd, 0);
            } else {
                cpu.write_x(f.rd, 1);
            }
            cpu.reservation = None;
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        bits: 0x0800302f,
        name: "AMOSWAP.D",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1) as u64;
            let s2 = cpu.read_x(f.rs2) as u64;
            let tmp = cpu.mmu.load_virt_u64(s1)? as i64;
            cpu.mmu.store_virt_u64(s1, s2)?;
            cpu.reservation = None;
            cpu.write_x(f.rd, tmp);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        bits: 0x0000302f,
        name: "AMOADD.D",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1) as u64;
            let s2 = cpu.read_x(f.rs2) as u64;
            let tmp = cpu.mmu.load_virt_u64(s1)?;
            cpu.mmu.store_virt_u64(s1, tmp.wrapping_add(s2))?;
            cpu.reservation = None;
            cpu.write_x(f.rd, tmp as i64);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        bits: 0x2000302f,
        name: "AMOXOR.D",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1) as u64;
            let s2 = cpu.read_x(f.rs2) as u64;
            let tmp = cpu.mmu.load_virt_u64(s1)?;
            cpu.mmu.store_virt_u64(s1, tmp ^ s2)?;
            cpu.reservation = None;
            cpu.write_x(f.rd, tmp as i64);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        bits: 0x6000302f,
        name: "AMOAND.D",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1) as u64;
            let s2 = cpu.read_x(f.rs2) as u64;
            let tmp = cpu.mmu.load_virt_u64(s1)?;
            cpu.mmu.store_virt_u64(s1, tmp & s2)?;
            cpu.reservation = None;
            cpu.write_x(f.rd, tmp as i64);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        bits: 0x4000302f,
        name: "AMOOR.D",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1) as u64;
            let s2 = cpu.read_x(f.rs2) as u64;
            let tmp = cpu.mmu.load_virt_u64(s1)?;
            cpu.mmu.store_virt_u64(s1, tmp | s2)?;
            cpu.reservation = None;
            cpu.write_x(f.rd, tmp as i64);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        bits: 0x8000302f,
        name: "AMOMIN.D",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1) as u64;
            let s2 = cpu.read_x(f.rs2);
            let tmp = cpu.mmu.load_virt_u64(s1)? as i64;
            let min = if s2 < tmp { s2 } else { tmp };
            cpu.mmu.store_virt_u64(s1, min as u64)?;
            cpu.reservation = None;
            cpu.write_x(f.rd, tmp);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        bits: 0xa000302f,
        name: "AMOMAX.D",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1) as u64;
            let s2 = cpu.read_x(f.rs2);
            let tmp = cpu.mmu.load_virt_u64(s1)? as i64;
            let max = if s2 >= tmp { s2 } else { tmp };
            cpu.mmu.store_virt_u64(s1, max as u64)?;
            cpu.reservation = None;
            cpu.write_x(f.rd, tmp);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        bits: 0xc000302f,
        name: "AMOMINU.D",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1) as u64;
            let s2 = cpu.read_x(f.rs2) as u64;
            let tmp = cpu.mmu.load_virt_u64(s1)?;
            let min = if s2 <= tmp { s2 } else { tmp };
            cpu.mmu.store_virt_u64(s1, min)?;
            cpu.reservation = None;
            cpu.write_x(f.rd, tmp as i64);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        bits: 0xe000302f,
        name: "AMOMAXU.D",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1) as u64;
            let s2 = cpu.read_x(f.rs2) as u64;
            let tmp = cpu.mmu.load_virt_u64(s1)?;
            let max = if s2 >= tmp { s2 } else { tmp };
            cpu.mmu.store_virt_u64(s1, max)?;
            cpu.reservation = None;
            cpu.write_x(f.rd, tmp as i64);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    // RV32F
    Instruction {
        mask: 0x0000707f,
        bits: 0x00002007,
        name: "FLW",
        operation: |cpu, _address, word| {
            let f = parse_format_i_fx(word);
            cpu.check_float_access(0)?;
            let s1 = cpu.read_x(f.rs1);
            let v = cpu.memop(Read, s1, f.imm, 0, 4)?;
            cpu.write_f(f.rd, v | fp::NAN_BOX_F32);
            Ok(())
        },
        disassemble: dump_format_i_mem,
    },
    Instruction {
        mask: 0x0000707f,
        bits: 0x00002027,
        name: "FSW",
        operation: |cpu, _address, word| {
            cpu.check_float_access(0)?;
            let f = parse_format_s_xf(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_f(f.rs2);
            cpu.reservation = None;
            cpu.mmu.store_virt_u32_(s1.wrapping_add(f.imm), s2)
        },
        disassemble: dump_format_s,
    },
    Instruction {
        mask: 0x0600007f,
        bits: 0x00000043,
        name: "FMADD.S",
        operation: |cpu, _address, word| {
            let f = parse_format_r2_ffff(word);
            cpu.check_float_access(f.rm)?;
            // XXX Update fflags
            let s1 = cpu.read_f32(f.rs1);
            let s2 = cpu.read_f32(f.rs2);
            let value3 = cpu.read_f32(f.rs3);
            cpu.write_f32(f.rd, s1.mul_add(s2, value3));
            Ok(())
        },
        disassemble: dump_format_r2_ffff,
    },
    Instruction {
        mask: 0x0600007f,
        bits: 0x00000047,
        name: "FMSUB.S",
        operation: |cpu, _address, word| {
            let f = parse_format_r2_ffff(word);
            cpu.check_float_access(f.rm)?;
            cpu.write_f32(
                f.rd,
                cpu.read_f32(f.rs1)
                    .mul_add(cpu.read_f32(f.rs2), -cpu.read_f32(f.rs3)),
            );
            Ok(())
        },
        disassemble: dump_format_r2_ffff,
    },
    Instruction {
        mask: 0x0600007f,
        bits: 0x0000004b,
        name: "FNMSUB.S",
        operation: |cpu, _address, word| {
            let f = parse_format_r2_ffff(word);
            cpu.check_float_access(f.rm)?;
            cpu.write_f32(
                f.rd,
                -(cpu
                    .read_f32(f.rs1)
                    .mul_add(cpu.read_f32(f.rs2), -cpu.read_f32(f.rs3))),
            );
            Ok(())
        },
        disassemble: dump_format_r2_ffff,
    },
    Instruction {
        mask: 0x0600007f,
        bits: 0x0000004f,
        name: "FNMADD.S",
        operation: |cpu, _address, word| {
            let f = parse_format_r2_ffff(word);
            cpu.check_float_access(f.rm)?;
            cpu.write_f32(
                f.rd,
                -(cpu
                    .read_f32(f.rs1)
                    .mul_add(cpu.read_f32(f.rs2), cpu.read_f32(f.rs3))),
            );
            Ok(())
        },
        disassemble: dump_format_r2_ffff,
    },
    Instruction {
        mask: 0xfe00007f,
        bits: 0x00000053,
        name: "FADD.S",
        operation: |cpu, _address, word| {
            let f = parse_format_r_fff(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_f32(f.rd, cpu.read_f32(f.rs1) + cpu.read_f32(f.rs2));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00007f,
        bits: 0x08000053,
        name: "FSUB.S",
        operation: |cpu, _address, word| {
            let f = parse_format_r_fff(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_f32(f.rd, cpu.read_f32(f.rs1) - cpu.read_f32(f.rs2));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00007f,
        bits: 0x10000053,
        name: "FMUL.S",
        operation: |cpu, _address, word| {
            // @TODO: Update fcsr
            let f = parse_format_r_fff(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_f32(f.rd, cpu.read_f32(f.rs1) * cpu.read_f32(f.rs2));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00007f,
        bits: 0x18000053,
        name: "FDIV.S",
        operation: |cpu, _address, word| {
            let f = parse_format_r_fff(word);
            cpu.check_float_access(f.funct3)?;
            //let rm = cpu.get_rm(word);

            let s1 = cpu.read_f32(f.rs1);
            let s2 = cpu.read_f32(f.rs2);
            // Is this implementation correct?
            let r = if s2 == 0.0 {
                cpu.set_fcsr_dz();
                f32::INFINITY
            } else if s2 == -0.0 {
                cpu.set_fcsr_dz();
                f32::NEG_INFINITY
            } else {
                s1 / s2
            };

            cpu.write_f32(f.rd, r);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0007f,
        bits: 0x58000053,
        name: "FSQRT.S",
        operation: |cpu, _address, word| {
            let f = parse_format_r_ff(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_f32(f.rd, cpu.read_f32(f.rs1).sqrt());
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x20000053,
        name: "FSGNJ.S",
        operation: |cpu, _address, word| {
            let f = parse_format_r_fff(word);
            cpu.check_float_access(0)?;
            let rs1_bits = Sf32::unbox(cpu.read_f(f.rs1));
            let rs2_bits = Sf32::unbox(cpu.read_f(f.rs2));
            let sign_bit = rs2_bits & (0x80000000u64 as i64);
            cpu.write_f(f.rd, fp::NAN_BOX_F32 | sign_bit | (rs1_bits & 0x7fffffff));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x20001053,
        name: "FSGNJN.S",
        operation: |cpu, _address, word| {
            let f = parse_format_r_fff(word);
            cpu.check_float_access(0)?;
            let rs1_bits = Sf32::unbox(cpu.read_f(f.rs1));
            let rs2_bits = Sf32::unbox(cpu.read_f(f.rs2));
            let sign_bit = !rs2_bits & (0x80000000u64 as i64);
            cpu.write_f(f.rd, fp::NAN_BOX_F32 | sign_bit | (rs1_bits & 0x7fffffff));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x20002053,
        name: "FSGNJX.S",
        operation: |cpu, _address, word| {
            let f = parse_format_r_fff(word);
            cpu.check_float_access(0)?;
            let rs1_bits = Sf32::unbox(cpu.read_f(f.rs1));
            let rs2_bits = Sf32::unbox(cpu.read_f(f.rs2));
            let sign_bit = rs2_bits & (0x80000000u64 as i64);
            cpu.write_f(f.rd, fp::NAN_BOX_F32 | (sign_bit ^ rs1_bits));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x28000053,
        name: "FMIN.S",
        operation: |cpu, _address, word| {
            let f = parse_format_r_fff(word);
            cpu.check_float_access(0)?;
            let (f1, f2) = (cpu.read_f32(f.rs1), cpu.read_f32(f.rs2));
            let r = if f1 < f2 { f1 } else { f2 };
            cpu.write_f32(f.rd, r);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x28001053,
        name: "FMAX.S",
        operation: |cpu, _address, word| {
            let f = parse_format_r_fff(word);
            cpu.check_float_access(0)?;
            let (f1, f2) = (cpu.read_f32(f.rs1), cpu.read_f32(f.rs2));
            let r = if f1 > f2 { f1 } else { f2 };
            cpu.write_f32(f.rd, r);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0007f,
        bits: 0xc0000053,
        name: "FCVT.W.S",
        operation: |cpu, _address, word| {
            let f = parse_format_r_xf(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_x(f.rd, i64::from(cpu.read_f32(f.rs1) as i32));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0007f,
        bits: 0xc0100053,
        name: "FCVT.WU.S",
        operation: |cpu, _address, word| {
            let f = parse_format_r_xf(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_x(f.rd, i64::from(cpu.read_f32(f.rs1) as u32));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0707f,
        bits: 0xe0000053,
        name: "FMV.X.W",
        operation: |cpu, _address, word| {
            let f = parse_format_r_xf(word);
            cpu.check_float_access(0)?;
            cpu.write_x(f.rd, i64::from(cpu.read_f(f.rs1) as i32));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0xa0002053,
        name: "FEQ.S",
        operation: |cpu, _address, word| {
            let f = parse_format_r_xff(word);
            cpu.check_float_access(0)?;
            let (r, fflags) = Sf32::feq(cpu.read_f(f.rs1), cpu.read_f(f.rs2));
            cpu.write_x(f.rd, i64::from(r));
            cpu.add_to_fflags(fflags);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0xa0001053,
        name: "FLT.S",
        operation: |cpu, _address, word| {
            let f = parse_format_r_xff(word);
            cpu.check_float_access(0)?;
            let (r, fflags) = Sf32::flt(cpu.read_f(f.rs1), cpu.read_f(f.rs2));
            cpu.write_x(f.rd, i64::from(r));
            cpu.add_to_fflags(fflags);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0xa0000053,
        name: "FLE.S",
        operation: |cpu, _address, word| {
            let f = parse_format_r_xff(word);
            cpu.check_float_access(0)?;
            let (r, fflags) = Sf32::fle(cpu.read_f(f.rs1), cpu.read_f(f.rs2));
            cpu.write_x(f.rd, i64::from(r));
            cpu.add_to_fflags(fflags);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0707f,
        bits: 0xe0001053,
        name: "FCLASS.S",
        operation: |cpu, _address, word| {
            let f = parse_format_r_xf(word);
            cpu.check_float_access(0)?;
            cpu.write_x(f.rd, 1 << Sf32::fclass(cpu.read_f(f.rs1)) as usize);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0007f,
        bits: 0xd0000053,
        name: "FCVT.S.W",
        operation: |cpu, _address, word| {
            let f = parse_format_r_fx(word);
            cpu.check_float_access(f.funct3)?;
            let (r, fflags) = cvt_i32_sf32(cpu.read_x(f.rs1), cpu.get_rm(f.funct3));
            cpu.write_f(f.rd, r);
            cpu.add_to_fflags(fflags);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0007f,
        bits: 0xd0100053,
        name: "FCVT.S.WU",
        operation: |cpu, _address, word| {
            let f = parse_format_r_fx(word);
            cpu.check_float_access(f.funct3)?;
            let (r, fflags) = cvt_u32_sf32(cpu.read_x(f.rs1), cpu.get_rm(f.funct3));
            cpu.write_f(f.rd, r);
            cpu.add_to_fflags(fflags);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0707f,
        bits: 0xf0000053,
        name: "FMV.W.X",
        operation: |cpu, _address, word| {
            let f = parse_format_r_fx(word);
            cpu.check_float_access(f.funct3)?;
            let s1 = cpu.read_x(f.rs1);
            cpu.write_f(f.rd, fp::NAN_BOX_F32 | s1);
            Ok(())
        },
        disassemble: dump_format_r_f,
    },
    // RV64F
    Instruction {
        mask: 0xfff0007f,
        bits: 0xc0200053,
        name: "FCVT.L.S",
        operation: |cpu, _address, word| {
            let f = parse_format_r_xf(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_x(f.rd, cpu.read_f32(f.rs1) as i64);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0007f,
        bits: 0xc0300053,
        name: "FCVT.LU.S",
        operation: |cpu, _address, word| {
            let f = parse_format_r_xf(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_x(f.rd, cpu.read_f32(f.rs1) as u64 as i64);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0007f,
        bits: 0xd0200053,
        name: "FCVT.S.L",
        operation: |cpu, _address, word| {
            let f = parse_format_r_fx(word);
            cpu.check_float_access(f.funct3)?;
            let (r, fflags) = cvt_i64_sf32(cpu.read_x(f.rs1), cpu.get_rm(f.funct3));
            cpu.write_f(f.rd, r);
            cpu.add_to_fflags(fflags);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0007f,
        bits: 0xd0300053,
        name: "FCVT.S.LU",
        operation: |cpu, _address, word| {
            let f = parse_format_r_fx(word);
            cpu.check_float_access(f.funct3)?;
            let (r, fflags) = cvt_u64_sf32(cpu.read_x(f.rs1), cpu.get_rm(f.funct3));

            cpu.write_f(f.rd, r);
            cpu.add_to_fflags(fflags);

            Ok(())
        },
        disassemble: dump_format_r,
    },
    // RV32D
    Instruction {
        mask: 0x0000707f,
        bits: 0x00003007,
        name: "FLD",
        operation: |cpu, _address, word| {
            let f = parse_format_i_fx(word);
            cpu.check_float_access(0)?;
            let s1 = cpu.read_x(f.rs1);
            let v = cpu.memop(Read, s1, f.imm, 0, 8)?;
            cpu.write_f(f.rd, v);
            Ok(())
        },
        disassemble: dump_format_i,
    },
    Instruction {
        mask: 0x0000707f,
        bits: 0x00003027,
        name: "FSD",
        operation: |cpu, _address, word| {
            cpu.check_float_access(0)?;
            let f = parse_format_s_xf(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_f(f.rs2);
            cpu.mmu.store64(s1.wrapping_add(f.imm), s2)
        },
        disassemble: dump_format_s,
    },
    Instruction {
        mask: 0x0600007f,
        bits: 0x02000043,
        name: "FMADD.D",
        operation: |cpu, _address, word| {
            let f = parse_format_r2_ffff(word);
            cpu.check_float_access(f.rm)?;
            cpu.write_f64(
                f.rd,
                cpu.read_f64(f.rs1)
                    .mul_add(cpu.read_f64(f.rs2), cpu.read_f64(f.rs3)),
            );
            Ok(())
        },
        disassemble: dump_format_r2_ffff,
    },
    Instruction {
        mask: 0x0600007f,
        bits: 0x02000047,
        name: "FMSUB.D",
        operation: |cpu, _address, word| {
            let f = parse_format_r2_ffff(word);
            cpu.check_float_access(f.rm)?;
            cpu.write_f64(
                f.rd,
                cpu.read_f64(f.rs1)
                    .mul_add(cpu.read_f64(f.rs2), -cpu.read_f64(f.rs3)),
            );
            Ok(())
        },
        disassemble: dump_format_r2_ffff,
    },
    Instruction {
        mask: 0x0600007f,
        bits: 0x0200004b,
        name: "FNMSUB.D",
        operation: |cpu, _address, word| {
            let f = parse_format_r2_ffff(word);
            cpu.check_float_access(f.rm)?;
            cpu.write_f64(
                f.rd,
                -(cpu
                    .read_f64(f.rs1)
                    .mul_add(cpu.read_f64(f.rs2), -cpu.read_f64(f.rs3))),
            );
            Ok(())
        },
        disassemble: dump_format_r2_ffff,
    },
    Instruction {
        mask: 0x0600007f,
        bits: 0x0200004f,
        name: "FNMADD.D",
        operation: |cpu, _address, word| {
            let f = parse_format_r2_ffff(word);
            cpu.check_float_access(f.rm)?;
            cpu.write_f64(
                f.rd,
                -(cpu
                    .read_f64(f.rs1)
                    .mul_add(cpu.read_f64(f.rs2), cpu.read_f64(f.rs3))),
            );
            Ok(())
        },
        disassemble: dump_format_r2_ffff,
    },
    Instruction {
        mask: 0xfe00007f,
        bits: 0x02000053,
        name: "FADD.D",
        operation: |cpu, _address, word| {
            let f = parse_format_r_fff(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_f64(f.rd, cpu.read_f64(f.rs1) + cpu.read_f64(f.rs2));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00007f,
        bits: 0x0a000053,
        name: "FSUB.D",
        operation: |cpu, _address, word| {
            let f = parse_format_r_fff(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_f64(f.rd, cpu.read_f64(f.rs1) - cpu.read_f64(f.rs2));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00007f,
        bits: 0x12000053,
        name: "FMUL.D",
        operation: |cpu, _address, word| {
            // @TODO: Update fcsr
            let f = parse_format_r_fff(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_f64(f.rd, cpu.read_f64(f.rs1) * cpu.read_f64(f.rs2));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00007f,
        bits: 0x1a000053,
        name: "FDIV.D",
        operation: |cpu, _address, word| {
            let f = parse_format_r_fff(word);
            cpu.check_float_access(f.funct3)?;
            let s1 = cpu.read_f64(f.rs1);
            let s2 = cpu.read_f64(f.rs2);
            // Is this implementation correct?
            let r = if s2 == 0.0 {
                cpu.set_fcsr_dz();
                f64::INFINITY
            } else if s2 == -0.0 {
                cpu.set_fcsr_dz();
                f64::NEG_INFINITY
            } else {
                s1 / s2
            };
            cpu.write_f64(f.rd, r);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0007f,
        bits: 0x5a000053,
        name: "FSQRT.D",
        operation: |cpu, _address, word| {
            let f = parse_format_r_ff(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_f64(f.rd, cpu.read_f64(f.rs1).sqrt());
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x22000053,
        name: "FSGNJ.D",
        operation: |cpu, _address, word| {
            let f = parse_format_r_fff(word);
            cpu.check_float_access(0)?;
            let rs1_bits = cpu.read_f(f.rs1);
            let rs2_bits = cpu.read_f(f.rs2);
            let sign_bit = rs2_bits & (0x8000000000000000u64 as i64);
            cpu.write_f(f.rd, sign_bit | (rs1_bits & 0x7fffffffffffffff));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x22001053,
        name: "FSGNJN.D",
        operation: |cpu, _address, word| {
            let f = parse_format_r_fff(word);
            cpu.check_float_access(0)?;
            let rs1_bits = cpu.read_f(f.rs1);
            let rs2_bits = cpu.read_f(f.rs2);
            let sign_bit = !rs2_bits & (0x8000000000000000u64 as i64);
            cpu.write_f(f.rd, sign_bit | (rs1_bits & 0x7fffffffffffffff));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x22002053,
        name: "FSGNJX.D",
        operation: |cpu, _address, word| {
            let f = parse_format_r_fff(word);
            cpu.check_float_access(0)?;
            let rs1_bits = cpu.read_f(f.rs1);
            let rs2_bits = cpu.read_f(f.rs2);
            let sign_bit = rs2_bits & (0x8000000000000000u64 as i64);
            cpu.write_f(f.rd, sign_bit ^ rs1_bits);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x2A000053,
        name: "FMIN.D",
        operation: |cpu, _address, word| {
            let f = parse_format_r_fff(word);
            cpu.check_float_access(0)?;
            let (f1, f2) = (cpu.read_f64(f.rs1), cpu.read_f64(f.rs2));
            let r = if f1 < f2 { f1 } else { f2 };
            cpu.write_f64(f.rd, r);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x2A001053,
        name: "FMAX.D",
        operation: |cpu, _address, word| {
            let f = parse_format_r_fff(word);
            cpu.check_float_access(0)?;
            let (f1, f2) = (cpu.read_f64(f.rs1), cpu.read_f64(f.rs2));
            let r = if f1 > f2 { f1 } else { f2 };
            cpu.write_f64(f.rd, r);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0007f,
        bits: 0x40100053,
        name: "FCVT.S.D",
        operation: |cpu, _address, word| {
            let f = parse_format_r_fff(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_f32(f.rd, cpu.read_f64(f.rs1) as f32);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0007f,
        bits: 0x42000053,
        name: "FCVT.D.S",
        operation: |cpu, _address, word| {
            let f = parse_format_r_fff(word);
            cpu.check_float_access(f.funct3)?;
            let (v, fflags) = fp::fcvt_d_s(cpu.read_f(f.rs1));
            cpu.write_f(f.rd, v);
            cpu.add_to_fflags(fflags);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0xa2002053,
        name: "FEQ.D",
        operation: |cpu, _address, word| {
            let f = parse_format_r_xff(word);
            cpu.check_float_access(0)?;
            let (r, fflags) = Sf64::feq(cpu.read_f(f.rs1), cpu.read_f(f.rs2));
            cpu.write_x(f.rd, i64::from(r));
            cpu.add_to_fflags(fflags);

            Ok(())
        },
        disassemble: dump_empty,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0xa2001053,
        name: "FLT.D",
        operation: |cpu, _address, word| {
            let f = parse_format_r_xff(word);
            cpu.check_float_access(0)?;
            let (r, fflags) = Sf64::flt(cpu.read_f(f.rs1), cpu.read_f(f.rs2));
            cpu.write_x(f.rd, i64::from(r));
            cpu.add_to_fflags(fflags);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0xa2000053,
        name: "FLE.D",
        operation: |cpu, _address, word| {
            let f = parse_format_r_xff(word);
            cpu.check_float_access(0)?;
            let (r, fflags) = Sf64::fle(cpu.read_f(f.rs1), cpu.read_f(f.rs2));
            cpu.write_x(f.rd, i64::from(r));
            cpu.add_to_fflags(fflags);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0707f,
        bits: 0xe2001053,
        name: "FCLASS.D",
        operation: |cpu, _address, word| {
            cpu.check_float_access(0)?;
            let f = parse_format_r_xf(word);
            cpu.write_x(f.rd, 1 << Sf64::fclass(cpu.read_f(f.rs1)) as usize);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0007f,
        bits: 0xc2000053,
        name: "FCVT.W.D",
        operation: |cpu, _address, word| {
            let f = parse_format_r_xf(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_x(f.rd, i64::from(cpu.read_f64(f.rs1) as i32));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0007f,
        bits: 0xc2100053,
        name: "FCVT.WU.D",
        operation: |cpu, _address, word| {
            let f = parse_format_r_xf(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_x(f.rd, i64::from(cpu.read_f64(f.rs1) as u32));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0007f,
        bits: 0xd2000053,
        name: "FCVT.D.W",
        operation: |cpu, _address, word| {
            let f = parse_format_r_fx(word);
            cpu.check_float_access(f.funct3)?;
            let s1 = cpu.read_x(f.rs1);
            cpu.write_f64(f.rd, f64::from(s1 as i32));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0007f,
        bits: 0xd2100053,
        name: "FCVT.D.WU",
        operation: |cpu, _address, word| {
            let f = parse_format_r_fx(word);
            cpu.check_float_access(f.funct3)?;
            let s1 = cpu.read_x(f.rs1);
            cpu.write_f64(f.rd, f64::from(s1 as u32));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    // RV64D
    Instruction {
        mask: 0xfff0007f,
        bits: 0xc2200053,
        name: "FCVT.L.D",
        operation: |cpu, _address, word| {
            let f = parse_format_r_xf(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_x(f.rd, cpu.read_f64(f.rs1) as i64);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0007f,
        bits: 0xc2300053,
        name: "FCVT.LU.D",
        operation: |cpu, _address, word| {
            let f = parse_format_r_xf(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_x(f.rd, cpu.read_f64(f.rs1) as u64 as i64);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0707f,
        bits: 0xe2000053,
        name: "FMV.X.D",
        operation: |cpu, _address, word| {
            cpu.check_float_access(0)?;
            let f = parse_format_r_xf(word);
            cpu.write_x(f.rd, cpu.read_f(f.rs1));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0007f,
        bits: 0xd2200053,
        name: "FCVT.D.L",
        operation: |cpu, _address, word| {
            let f = parse_format_r_fx(word);
            cpu.check_float_access(f.funct3)?;
            let s1 = cpu.read_x(f.rs1);
            cpu.write_f64(f.rd, s1 as f64);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0007f,
        bits: 0xd2300053,
        name: "FCVT.D.LU",
        operation: |cpu, _address, word| {
            let f = parse_format_r_fx(word);
            cpu.check_float_access(f.funct3)?;
            let s1 = cpu.read_x(f.rs1);
            cpu.write_f64(f.rd, s1 as u64 as f64);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0707f,
        bits: 0xf2000053,
        name: "FMV.D.X",
        operation: |cpu, _address, word| {
            cpu.check_float_access(0)?;
            let f = parse_format_r_fx(word);
            let s1 = cpu.read_x(f.rs1);
            cpu.write_f(f.rd, s1);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    // Remaining (all system-level) that weren't listed in the instr-table
    Instruction {
        mask: 0xffffffff,
        bits: 0x7b200073,
        name: "DRET",
        operation: |_cpu, __address, _word| {
            todo!("Handling dret requires handling all of debug mode")
        },
        disassemble: dump_empty,
    },
    Instruction {
        mask: 0xffffffff,
        bits: 0x30200073,
        name: "MRET",
        operation: |cpu, _address, _word| {
            cpu.pc = cpu.read_csr(Csr::Mepc as u16)? as i64;
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
            Ok(())
        },
        disassemble: dump_empty,
    },
    Instruction {
        mask: 0xffffffff,
        bits: 0x10200073,
        name: "SRET",
        operation: |cpu, _address, word| {
            if cpu.mmu.prv == PrivMode::U
                || cpu.mmu.prv == PrivMode::S && cpu.mmu.mstatus & MSTATUS_TSR != 0
            {
                return Err(Exception {
                    trap: Trap::IllegalInstruction,
                    tval: word as i64,
                });
            }

            cpu.pc = cpu.read_csr(Csr::Sepc as u16)? as i64;
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
            Ok(())
        },
        disassemble: dump_empty,
    },
    Instruction {
        mask: 0xfe007fff,
        bits: 0x12000073,
        name: "SFENCE.VMA",
        operation: |cpu, _address, word| {
            if cpu.mmu.prv == PrivMode::U
                || cpu.mmu.prv == PrivMode::S && cpu.mmu.mstatus & MSTATUS_TVM != 0
            {
                return Err(Exception {
                    trap: Trap::IllegalInstruction,
                    tval: word as i64,
                });
            }

            cpu.mmu.clear_page_cache();
            cpu.reservation = None;
            Ok(())
        },
        disassemble: dump_empty,
    },
    Instruction {
        mask: 0xffffffff,
        bits: 0x10500073,
        name: "WFI",
        operation: |cpu, _address, word| {
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
                    tval: word as i64,
                });
            }
            cpu.wfi = true;
            Ok(())
        },
        disassemble: dump_empty,
    },
    // Zba -- AKA, my only favorite extension
    Instruction {
        mask: 0xfe00707f,
        bits: 0x0800003b,
        name: "ADD.UW",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            cpu.write_x(f.rd, s2.wrapping_add(s1 & 0xffffffff));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x20002033,
        name: "SH1ADD",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            cpu.write_x(f.rd, s2.wrapping_add(s1 << 1));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x2000203b,
        name: "SH1ADD.UW",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            cpu.write_x(f.rd, s2.wrapping_add((s1 & 0xffffffff) << 1));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x20004033,
        name: "SH2ADD",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            cpu.write_x(f.rd, s2.wrapping_add(s1 << 2));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x2000403b,
        name: "SH2ADD.UW",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            cpu.write_x(f.rd, s2.wrapping_add((s1 & 0xffffffff) << 2));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x20006033,
        name: "SH3ADD",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            cpu.write_x(f.rd, s2.wrapping_add(s1 << 3));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x2000603b,
        name: "SH3ADD.UW",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            cpu.write_x(f.rd, s2.wrapping_add((s1 & 0xffffffff) << 3));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x0800101b,
        name: "SLLI.UW",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1);
            let mask = 0x3f;
            let shamt = (word >> 20) & mask;
            cpu.write_x(f.rd, (s1 & 0xffffffff) << shamt);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    // Zicond extension
    Instruction {
        mask: 0xfe00707f,
        bits: 0x0e005033,
        name: "CZERO.EQZ",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            cpu.write_x(f.rd, if s2 == 0 { 0 } else { s1 });
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        bits: 0x0e007033,
        name: "CZERO.NEZ",
        operation: |cpu, _address, word| {
            let f = parse_format_r(word);
            let s1 = cpu.read_x(f.rs1);
            let s2 = cpu.read_x(f.rs2);
            cpu.write_x(f.rd, if s2 != 0 { 0 } else { s1 });
            Ok(())
        },
        disassemble: dump_format_r,
    },
    // Last one is a sentiel and must always be this illegal instruction
    Instruction {
        mask: 0,
        bits: 0,
        name: "INVALID",
        operation: |_cpu, _address, word| {
            Err(Exception {
                trap: Trap::IllegalInstruction,
                tval: word as i64,
            })
        },
        disassemble: dump_empty,
    },
];

#[cfg(test)]
mod test_cpu {
    use super::*;
    use crate::mmu::DRAM_BASE;
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
        cpu.update_pc(0xffffffffffffffffu64 as i64);
        assert_eq!(0xfffffffffffffffeu64 as i64, cpu.read_pc());
    }

    #[test]
    fn decode_sh2add() {
        let cpu = create_cpu();
        //    10894:       20e74633                sh2add  a2,a4,a4
        match decode(&cpu.decode_dag, 0x20e74633) {
            Ok(inst) => assert_eq!(inst.name, "SH2ADD"),
            _err => panic!("Failed to decode"),
        }
    }

    #[test]
    #[allow(clippy::match_wild_err_arm)]
    fn tick() {
        let mut cpu = create_cpu();
        cpu.update_pc(DRAM_BASE as i64);

        // Write non-compressed "addi x1, x1, 1" instruction
        match cpu.get_mut_mmu().store_virt_u32(DRAM_BASE, 0x00108093) {
            Ok(()) => {}
            Err(_e) => panic!("Failed to store"),
        }
        // Write compressed "addi x8, x0, 8" instruction
        match cpu.get_mut_mmu().store_virt_u32(DRAM_BASE + 4, 0x20) {
            Ok(()) => {}
            Err(_e) => panic!("Failed to store"),
        }

        cpu.run_soc(1);

        assert_eq!(DRAM_BASE as i64 + 4, cpu.read_pc());
        assert_eq!(1, cpu.read_register(x(1)));

        cpu.run_soc(1);

        assert_eq!(DRAM_BASE as i64 + 6, cpu.read_pc());
        assert_eq!(8, cpu.read_register(x(8)));
    }

    #[test]
    #[allow(clippy::match_wild_err_arm)]
    fn step_cpu() {
        let mut cpu = create_cpu();
        cpu.update_pc(DRAM_BASE as i64);
        // write non-compressed "addi a0, a0, 12" instruction
        match cpu.get_mut_mmu().store_virt_u32(DRAM_BASE, 0xc50513) {
            Ok(()) => {}
            Err(_e) => panic!("Failed to store"),
        }
        assert_eq!(DRAM_BASE as i64, cpu.read_pc());
        assert_eq!(0, cpu.read_register(x(10)));
        if let Err(exc) = cpu.step_cpu() {
            cpu.handle_exception(&exc);
        }
        assert_eq!(DRAM_BASE as i64 + 4, cpu.read_pc());
        // "addi a0, a0, a12" instruction writes 12 to a0 register.
        assert_eq!(12, cpu.read_register(x(10)));
    }

    #[test]
    #[allow(clippy::match_wild_err_arm)]
    fn decode_test() {
        let cpu = create_cpu();
        // 0x13 is addi instruction
        match decode(&cpu.decode_dag, 0x13) {
            Ok(inst) => assert_eq!(inst.name, "ADDI"),
            Err(_e) => panic!("Failed to decode"),
        }
        // .decode() returns error for invalid word data.
        assert!(
            decode(&cpu.decode_dag, 0x0).is_err(),
            "Unexpectedly succeeded in decoding"
        );
    }

    #[test]
    #[allow(clippy::match_wild_err_arm)]
    fn test_decompress() {
        let cpu = create_cpu();
        // .decompress() doesn't directly return an instruction but
        // it returns decompressed word. Then you need to call .decode().
        match decode(&cpu.decode_dag, decompress(0, 0x20).0) {
            Ok(inst) => assert_eq!(inst.name, "ADDI"),
            Err(_e) => panic!("Failed to decode"),
        }
    }

    #[test]
    #[allow(clippy::match_wild_err_arm)]
    fn wfi() {
        let wfi_instruction = 0x10500073;
        let mut cpu = create_cpu();
        // Just in case
        match decode(&cpu.decode_dag, wfi_instruction) {
            Ok(inst) => assert_eq!(inst.name, "WFI"),
            Err(_e) => panic!("Failed to decode"),
        }
        cpu.update_pc(DRAM_BASE as i64);
        // write WFI instruction
        match cpu.get_mut_mmu().store_virt_u32(DRAM_BASE, wfi_instruction) {
            Ok(()) => {}
            Err(_e) => panic!("Failed to store"),
        }
        cpu.run_soc(1);
        assert_eq!(DRAM_BASE as i64 + 4, cpu.read_pc());
        for _i in 0..10 {
            // Until interrupt happens, .tick() does nothing
            cpu.run_soc(1);
            assert_eq!(DRAM_BASE as i64 + 4, cpu.read_pc());
        }
        // Machine timer interrupt
        cpu.write_csr_raw(Csr::Mie, MIP_MTIP);
        cpu.mmu.mip |= MIP_MTIP;
        cpu.write_csr_raw(Csr::Mstatus, 0x8);
        cpu.write_csr_raw(Csr::Mtvec, 0x0);
        cpu.run_soc(1);
        // Interrupt happened and moved to handler
        assert_eq!(0, cpu.read_pc());
    }

    #[test]
    #[allow(clippy::match_wild_err_arm)]
    fn interrupt() {
        let handler_vector = 0x10000000;
        let mut cpu = create_cpu();
        // Write non-compressed "addi x0, x0, 1" instruction
        match cpu.get_mut_mmu().store_virt_u32(DRAM_BASE, 0x00100013) {
            Ok(()) => {}
            Err(_e) => panic!("Failed to store"),
        }
        cpu.update_pc(DRAM_BASE as i64);

        // Machine timer interrupt but mie in mstatus is not enabled yet
        cpu.write_csr_raw(Csr::Mie, MIP_MTIP);
        cpu.mmu.mip |= MIP_MTIP;
        cpu.write_csr_raw(Csr::Mtvec, handler_vector);

        cpu.run_soc(1);

        // Interrupt isn't caught because mie is disabled
        assert_eq!(DRAM_BASE as i64 + 4, cpu.read_pc());

        cpu.update_pc(DRAM_BASE as i64);
        // Enable mie in mstatus
        cpu.write_csr_raw(Csr::Mstatus, 0x8);

        cpu.run_soc(1);

        // Interrupt happened and moved to handler
        assert_eq!(handler_vector as i64, cpu.read_pc());

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
        let handler_vector = 0x10000000;
        let mut cpu = create_cpu();
        // Write ECALL instruction
        match cpu.get_mut_mmu().store_virt_u32(DRAM_BASE, 0x00000073) {
            Ok(()) => {}
            Err(_e) => panic!("Failed to store"),
        }
        cpu.write_csr_raw(Csr::Mtvec, handler_vector);
        cpu.update_pc(DRAM_BASE as i64);

        cpu.run_soc(1);

        // Interrupt happened and moved to handler
        assert_eq!(handler_vector as i64, cpu.read_pc());

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
        cpu.update_pc(DRAM_BASE as i64);

        // Write non-compressed "addi x0, x0, 1" instruction
        match cpu.get_mut_mmu().store_virt_u32(DRAM_BASE, 0x00100013) {
            Ok(()) => {}
            Err(_e) => panic!("Failed to store"),
        }
        // Write non-compressed "addi x1, x1, 1" instruction
        match cpu.get_mut_mmu().store_virt_u32(DRAM_BASE + 4, 0x00108093) {
            Ok(()) => {}
            Err(_e) => panic!("Failed to store"),
        }

        // Test x0
        assert_eq!(0, cpu.read_register(x(0)));
        cpu.run_soc(1); // Execute  "addi x0, x0, 1"
        // x0 is still zero because it's hardcoded zero
        assert_eq!(0, cpu.read_register(x(0)));

        // Test x1
        assert_eq!(0, cpu.read_register(x(1)));
        cpu.run_soc(1); // Execute  "addi x1, x1, 1"
        // x1 is not hardcoded zero
        assert_eq!(1, cpu.read_register(x(1)));
    }
}
