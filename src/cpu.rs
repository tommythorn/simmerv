#![allow(clippy::unreadable_literal)]
#![allow(clippy::cast_possible_wrap)]

use crate::csr;
use crate::fp;
use crate::fp::{
    RoundingMode, Sf, Sf32, Sf64, cvt_i32_sf32, cvt_i64_sf32, cvt_u32_sf32, cvt_u64_sf32,
};
use crate::mmu::MemoryAccessType::{Execute, Read, Write};
use crate::mmu::{AddressingMode, MemoryAccessType, Mmu};
use crate::rvc;
use crate::terminal::Terminal;
pub use csr::*;
use fnv::{self, FnvHashMap};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::fmt::Write as _;

pub const CONFIG_SW_MANAGED_A_AND_D: bool = false;

pub const PG_SHIFT: usize = 12; // 4K page size

/// Emulates a RISC-V CPU core
pub struct Cpu {
    // Alignment for the first two is deliberate
    x_: [i64; 32],
    f_: [i64; 32],
    x_seqno: [usize; 32],
    f_seqno: [usize; 32],
    frm_: RoundingMode,
    fflags_: u8,
    fs: u8,

    pub seqno: usize,
    pub cycle: u64,
    privilege_mode: PrivilegeMode,
    pc: i64,
    pub insn_addr: i64, // XXX make accessor functions instead of pub?
    pub insn: u32,      // This is the original original bytes, prior to decompression
    wfi: bool,
    csr: Box<[u64]>, // XXX this should be replaced with individual registers

    mmu: Mmu,
    reservation: Option<i64>,
    decode_cache: DecodeCache,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, FromPrimitive, PartialEq, Eq)]
pub enum PrivilegeMode {
    User,
    Supervisor,
    Reserved,
    Machine,
}

#[derive(Debug)]
pub struct Trap {
    pub trap_type: TrapType,
    pub value: i64, // Trap type specific value (tval)
}

#[derive(Clone, Copy, Debug, FromPrimitive)]
pub enum TrapType {
    InstructionAddressMisaligned = 0,
    InstructionAccessFault,
    IllegalInstruction,
    Breakpoint,
    LoadAddressMisaligned,
    LoadAccessFault,
    StoreAddressMisaligned,
    StoreAccessFault,
    EnvironmentCallFromUMode,
    EnvironmentCallFromSMode,
    // Reserved
    EnvironmentCallFromMMode = 11,
    InstructionPageFault,
    LoadPageFault,
    // Reserved
    StorePageFault = 15,

    UserSoftwareInterrupt = 100,
    SupervisorSoftwareInterrupt = 101,
    MachineSoftwareInterrupt = 103,

    UserTimerInterrupt = 104,
    SupervisorTimerInterrupt = 105,
    MachineTimerInterrupt = 107,

    UserExternalInterrupt = 108,
    SupervisorExternalInterrupt = 109,
    MachineExternalInterrupt = 111,
}

// bigger number is higher privilege level
const fn get_privilege_encoding(mode: PrivilegeMode) -> u8 {
    assert!(!matches!(mode, PrivilegeMode::Reserved));
    mode as u8
}

/// Returns `PrivilegeMode` from encoded privilege mode bits
/// # Panics
/// On unknown modes crash
#[must_use]
pub fn get_privilege_mode(encoding: u64) -> PrivilegeMode {
    assert_ne!(encoding, 2);
    let Some(m) = FromPrimitive::from_u64(encoding) else {
        unreachable!();
    };
    m
}

const fn get_trap_cause(trap: &Trap) -> u64 {
    let interrupt_bit = 0x8000_0000_0000_0000_u64;
    if (trap.trap_type as u64) < (TrapType::UserSoftwareInterrupt as u64) {
        trap.trap_type as u64
    } else {
        trap.trap_type as u64 - TrapType::UserSoftwareInterrupt as u64 + interrupt_bit
    }
}

impl Cpu {
    /// Creates a new `Cpu`.
    ///
    /// # Arguments
    /// * `Terminal`
    #[must_use]
    #[allow(clippy::precedence)]
    pub fn new(terminal: Box<dyn Terminal>) -> Self {
        let mut cpu = Self {
            x_: [0; 32],
            f_: [0; 32],
            x_seqno: [0; 32],
            f_seqno: [0; 32],
            frm_: RoundingMode::RoundNearestEven,
            fflags_: 0,
            fs: 1,

            seqno: 0,
            cycle: 0,
            privilege_mode: PrivilegeMode::Machine,
            wfi: false,
            pc: 0,
            insn_addr: 0,
            insn: 0,
            csr: vec![0; 4096].into_boxed_slice(), // XXX MUST GO AWAY SOON
            mmu: Mmu::new(terminal),
            reservation: None,
            decode_cache: DecodeCache::new(),
        };
        cpu.csr[Csr::Misa as usize] = 1 << 63; // RV64
        for c in "SUIMAFDC".bytes() {
            cpu.csr[Csr::Misa as usize] |= 1 << (c as usize - 65);
        }
        cpu.csr[Csr::Mstatus as usize] =
            2 << MSTATUS_UXL_SHIFT | 2 << MSTATUS_SXL_SHIFT | 3 << MSTATUS_MPP_SHIFT;
        cpu.write_x(10, 0); // boot hart
        cpu.write_x(11, 0x1020); // start of DTB (XXX could put that elsewhere);
        cpu
    }

    #[inline]
    const fn read_x(&self, r: usize) -> i64 {
        self.x_[r]
    }

    #[inline]
    fn write_x(&mut self, r: usize, v: i64) {
        if r != 0 {
            self.x_[r] = v;
            self.x_seqno[r] = self.seqno;
        }
    }

    /// Updates Program Counter content
    ///
    /// # Arguments
    /// * `value`
    pub const fn update_pc(&mut self, value: i64) {
        self.pc = value & !1;
    }

    /// Reads integer register content
    ///
    /// # Arguments
    /// * `reg` Register number. Must be 0-31
    #[must_use]
    pub fn read_register(&self, reg: u8) -> i64 {
        debug_assert!(reg <= 31, "reg must be 0-31. {reg}");
        self.read_x(reg as usize)
    }

    fn check_float_access(&self, rm: usize) -> Result<(), Trap> {
        if self.fs == 0 || rm == 5 || rm == 6 {
            Err(Trap {
                trap_type: TrapType::IllegalInstruction,
                value: i64::from(self.insn),
            })
        } else {
            Ok(())
        }
    }

    /// Reads Program counter content
    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub const fn read_pc(&self) -> i64 {
        self.pc
    }

    /// Runs program N cycles. Fetch, decode, and execution are completed in a cycle so far.
    #[allow(clippy::cast_sign_loss)]
    pub fn run_soc(&mut self, cpu_steps: usize) {
        for _ in 0..cpu_steps {
            self.run_cpu_tick();
            if self.wfi {
                break;
            }
        }
        self.mmu.service(self.cycle);
        self.handle_interrupt();
    }

    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
    fn run_cpu_tick(&mut self) {
        self.cycle = self.cycle.wrapping_add(1);
        if self.wfi {
            if self.mmu.mip & self.read_csr_raw(Csr::Mie) != 0 {
                self.wfi = false;
            }
            return;
        }

        self.seqno = self.seqno.wrapping_add(1);
        self.insn_addr = self.pc;
        let Some(word) = self.memop(Execute, self.insn_addr, 0, 0, 4) else {
            // Exception was triggered
            // XXX For full correctness we mustn't fail if we _can_ fetch 16-bit
            // _and_ they turn out to be a legal instruction.
            return;
        };
        self.insn = word as u32;

        let (insn, npc) = decompress(self.insn_addr, word as u32);
        self.pc = npc;
        let Ok(decoded) = self.decode(insn) else {
            self.handle_exception(&Trap {
                trap_type: TrapType::IllegalInstruction,
                value: word,
            });
            return;
        };

        if let Err(e) = (decoded.operation)(self.insn_addr as u64, insn, self) {
            self.handle_exception(&e);
        }
    }

    /// Decodes a word instruction data and returns a reference to
    /// [`Instruction`](struct.Instruction.html). Using [`DecodeCache`](struct.DecodeCache.html)
    /// so if cache hits this method returns the result very quickly.
    /// The result will be stored to cache.
    fn decode(&mut self, word: u32) -> Result<&Instruction, ()> {
        if let Some(index) = self.decode_cache.get(word) {
            return Ok(&INSTRUCTIONS[index]);
        }

        let index = self.decode_and_get_instruction_index(word)?;
        self.decode_cache.insert(word, index);
        Ok(&INSTRUCTIONS[index])
    }

    /// Decodes a word instruction data and returns a reference to
    /// [`Instruction`](struct.Instruction.html). Not Using [`DecodeCache`](struct.DecodeCache.html)
    /// so if you don't want to pollute the cache you should use this method
    /// instead of `decode`.
    fn decode_raw(&self, word: u32) -> Result<&Instruction, ()> {
        let index = self.decode_and_get_instruction_index(word)?;
        Ok(&INSTRUCTIONS[index])
    }

    /// Decodes a word instruction data and returns an index of
    /// [`INSTRUCTIONS`](constant.INSTRUCTIONS.html)
    ///
    /// # Arguments
    /// * `word` word instruction data decoded
    #[allow(clippy::unused_self)]
    fn decode_and_get_instruction_index(&self, word: u32) -> Result<usize, ()> {
        for (i, inst) in INSTRUCTIONS.iter().enumerate() {
            if word & inst.mask == inst.data {
                return Ok(i);
            }
        }
        Err(())
    }

    #[allow(clippy::cast_sign_loss)]
    fn handle_interrupt(&mut self) {
        use self::TrapType::{
            MachineExternalInterrupt, MachineSoftwareInterrupt, MachineTimerInterrupt,
            SupervisorExternalInterrupt, SupervisorSoftwareInterrupt, SupervisorTimerInterrupt,
        };
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
            let trap = Trap {
                trap_type,
                value: self.pc,
            };
            if minterrupt & intr != 0 && self.handle_trap(&trap, self.pc, true) {
                self.wfi = false;
                return;
            }
        }
    }

    fn handle_exception(&mut self, exception: &Trap) {
        self.handle_trap(exception, self.insn_addr, false);
    }

    #[allow(clippy::similar_names, clippy::too_many_lines)]
    #[allow(clippy::cast_sign_loss)]
    fn handle_trap(&mut self, trap: &Trap, insn_addr: i64, is_interrupt: bool) -> bool {
        let current_privilege_encoding = u64::from(get_privilege_encoding(self.privilege_mode));
        let cause = get_trap_cause(trap);

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

        let new_privilege_mode = if (mdeleg >> pos) & 1 == 0 {
            PrivilegeMode::Machine
        } else if (sdeleg >> pos) & 1 == 0 {
            PrivilegeMode::Supervisor
        } else {
            PrivilegeMode::User
        };
        let new_privilege_encoding = u64::from(get_privilege_encoding(new_privilege_mode));

        let current_status = match self.privilege_mode {
            PrivilegeMode::Machine => self.read_csr_raw(Csr::Mstatus),
            PrivilegeMode::Supervisor => self.read_csr_raw(Csr::Sstatus),
            PrivilegeMode::User => self.read_csr_raw(Csr::Ustatus),
            PrivilegeMode::Reserved => panic!(),
        };

        // Second, ignore the interrupt if it's disabled by some conditions

        if is_interrupt {
            let ie = match new_privilege_mode {
                PrivilegeMode::Machine => self.read_csr_raw(Csr::Mie),
                PrivilegeMode::Supervisor => self.read_csr_raw(Csr::Sie),
                PrivilegeMode::User => self.read_csr_raw(Csr::Uie),
                PrivilegeMode::Reserved => panic!(),
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

            if new_privilege_encoding < current_privilege_encoding
                || current_privilege_encoding == new_privilege_encoding
                    && 0 == match self.privilege_mode {
                        PrivilegeMode::Machine => current_mie,
                        PrivilegeMode::Supervisor => current_sie,
                        PrivilegeMode::User => current_uie,
                        PrivilegeMode::Reserved => panic!(),
                    }
            {
                return false;
            }

            // Interrupt can be maskable by xie csr register
            // where x is a new privilege mode.

            match trap.trap_type {
                TrapType::UserSoftwareInterrupt => {
                    if usie == 0 {
                        return false;
                    }
                }
                TrapType::SupervisorSoftwareInterrupt => {
                    if ssie == 0 {
                        return false;
                    }
                }
                TrapType::MachineSoftwareInterrupt => {
                    if msie == 0 {
                        return false;
                    }
                }
                TrapType::UserTimerInterrupt => {
                    if utie == 0 {
                        return false;
                    }
                }
                TrapType::SupervisorTimerInterrupt => {
                    if stie == 0 {
                        return false;
                    }
                }
                TrapType::MachineTimerInterrupt => {
                    if mtie == 0 {
                        return false;
                    }
                }
                TrapType::UserExternalInterrupt => {
                    if ueie == 0 {
                        return false;
                    }
                }
                TrapType::SupervisorExternalInterrupt => {
                    if seie == 0 {
                        return false;
                    }
                }
                TrapType::MachineExternalInterrupt => {
                    if meie == 0 {
                        return false;
                    }
                }
                _ => {}
            }
        }

        // So, this trap should be taken

        self.privilege_mode = new_privilege_mode;
        self.mmu.update_privilege_mode(self.privilege_mode);
        let csr_epc_address = match self.privilege_mode {
            PrivilegeMode::Machine => Csr::Mepc,
            PrivilegeMode::Supervisor => Csr::Sepc,
            PrivilegeMode::User => Csr::Uepc,
            PrivilegeMode::Reserved => panic!(),
        };
        let csr_cause_address = match self.privilege_mode {
            PrivilegeMode::Machine => Csr::Mcause,
            PrivilegeMode::Supervisor => Csr::Scause,
            PrivilegeMode::User => Csr::Ucause,
            PrivilegeMode::Reserved => panic!(),
        };
        let csr_tval_address = match self.privilege_mode {
            PrivilegeMode::Machine => Csr::Mtval,
            PrivilegeMode::Supervisor => Csr::Stval,
            PrivilegeMode::User => Csr::Utval,
            PrivilegeMode::Reserved => panic!(),
        };
        let csr_tvec_address = match self.privilege_mode {
            PrivilegeMode::Machine => Csr::Mtvec,
            PrivilegeMode::Supervisor => Csr::Stvec,
            PrivilegeMode::User => Csr::Utvec,
            PrivilegeMode::Reserved => panic!(),
        };

        self.write_csr_raw(csr_epc_address, insn_addr as u64);
        self.write_csr_raw(csr_cause_address, cause);
        self.write_csr_raw(csr_tval_address, trap.value as u64);
        self.pc = self.read_csr_raw(csr_tvec_address) as i64;

        // Add 4 * cause if tvec has vector type address
        if self.pc & 3 != 0 {
            self.pc = (self.pc & !3) + 4 * (cause as i64 & 0xffff);
        }

        match self.privilege_mode {
            PrivilegeMode::Machine => {
                let status = self.read_csr_raw(Csr::Mstatus);
                let mie = (status >> 3) & 1;
                // clear MIE[3], override MPIE[7] with MIE[3], override MPP[12:11] with current privilege encoding
                let new_status =
                    (status & !0x1888) | (mie << 7) | (current_privilege_encoding << 11);
                self.write_csr_raw(Csr::Mstatus, new_status);
            }
            PrivilegeMode::Supervisor => {
                let status = self.read_csr_raw(Csr::Sstatus);
                let sie = (status >> 1) & 1;
                // clear SIE[1], override SPIE[5] with SIE[1], override SPP[8] with current privilege encoding
                let new_status =
                    (status & !0x122) | (sie << 5) | ((current_privilege_encoding & 1) << 8);
                self.write_csr_raw(Csr::Sstatus, new_status);
            }
            PrivilegeMode::User => {
                panic!("Not implemented yet");
            }
            PrivilegeMode::Reserved => panic!(), // shouldn't happen
        }
        true
    }

    fn has_csr_access_privilege(&self, csrno: u16) -> Option<Csr> {
        let csr = FromPrimitive::from_u16(csrno)?;

        if !csr::legal(csr) {
            log::info!("** {:016x}: {csr:?} isn't implemented", self.insn_addr);
            return None;
        }

        let privilege = (csrno >> 8) & 3;
        if privilege as u8 > get_privilege_encoding(self.privilege_mode) {
            log::info!("** {:016x}: Lacking priviledge for {csr:?}", self.insn_addr);
            return None;
        }

        Some(csr)
    }

    // XXX This is still so far from complete; copy the logic from Dromajo and review
    // each CSR.  Do Not Blanket allow reads and writes from unsupported CSRs
    #[allow(clippy::cast_sign_loss)]
    fn read_csr(&self, csrno: u16) -> Result<u64, Trap> {
        use PrivilegeMode::Supervisor;

        let illegal = Err(Trap {
            trap_type: TrapType::IllegalInstruction,
            value: i64::from(self.insn),
        });

        let Some(csr) = self.has_csr_access_privilege(csrno) else {
            return illegal;
        };

        match csr {
            Csr::Fflags | Csr::Frm | Csr::Fcsr => {
                self.check_float_access(0)?;
            }
            // SATP access in S requires TVM = 0
            Csr::Satp => {
                if self.privilege_mode == Supervisor
                    && self.csr[Csr::Mstatus as usize] & MSTATUS_TVM != 0
                {
                    return illegal;
                }
            }

            _ => {}
        }
        Ok(self.read_csr_raw(csr))
    }

    #[allow(clippy::cast_sign_loss)]
    fn write_csr(&mut self, csrno: u16, mut value: u64) -> Result<(), Trap> {
        use PrivilegeMode::Supervisor;

        let illegal = Err(Trap {
            trap_type: TrapType::IllegalInstruction,
            value: i64::from(self.insn),
        });

        let Some(csr) = self.has_csr_access_privilege(csrno) else {
            return illegal;
        };

        match csr {
            Csr::Fflags | Csr::Frm | Csr::Fcsr => {
                self.check_float_access(0)?;
            }

            Csr::Cycle => {
                log::info!("** deny cycle writing from {:016x}", self.insn_addr);
                return illegal;
            }

            // SATP access in S requires TVM = 0
            Csr::Satp => {
                if self.privilege_mode == Supervisor
                    && self.csr[Csr::Mstatus as usize] & MSTATUS_TVM != 0
                {
                    return illegal;
                }
            }
            _ => {}
        }

        /*
        // Checking writability fails some tests so disabling so far
        let read_only = (address >> 10) & 3 == 3;
        if read_only {
            return Err(Exception::IllegalInstruction);
        }
        */
        if matches!(csr, Csr::Mstatus) {
            let mask = MSTATUS_MASK & !(MSTATUS_VS | MSTATUS_UXL_MASK | MSTATUS_SXL_MASK);
            value = value & mask | self.csr[Csr::Mstatus as usize] & !mask;
        }

        self.write_csr_raw(csr, value);
        if matches!(csr, Csr::Satp) {
            self.update_satp(value);
        }
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
                let mut mstatus = self.csr[Csr::Mstatus as usize];
                mstatus &= !MSTATUS_FS;
                mstatus |= u64::from(self.fs) << MSTATUS_FS_SHIFT;
                mstatus &= 0x8000_0003_000d_e162;
                if self.fs == 3 {
                    mstatus |= 1 << 63;
                }
                mstatus
            }
            Csr::Mstatus => {
                let mut mstatus = self.csr[Csr::Mstatus as usize];
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
            Csr::Cycle | Csr::Mcycle => self.cycle,
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
                self.csr[Csr::Mstatus as usize] &= !0x8000_0003_000d_e162;
                self.csr[Csr::Mstatus as usize] |= value & 0x8000_0003_000d_e162;
                self.fs = ((value >> MSTATUS_FS_SHIFT) & 3) as u8;
                self.mmu.update_mstatus(self.read_csr_raw(Csr::Mstatus));
            }
            Csr::Sie => {
                self.csr[Csr::Mie as usize] &= !0x222;
                self.csr[Csr::Mie as usize] |= value & 0x222;
            }
            Csr::Sip => {
                let mask = self.csr[Csr::Mideleg as usize];
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
                self.csr[Csr::Mstatus as usize] = value;
                self.fs = ((value >> MSTATUS_FS_SHIFT) & 3) as u8;
                self.mmu.update_mstatus(value);
            }
            Csr::Time => {
                // XXX This should trap actually
                self.mmu.get_mut_clint().write_mtime(value);
            }
            /*Csr::Cycle |*/ Csr::Mcycle => self.cycle = value,
            _ => {
                self.csr[csr as usize] = value;
            }
        }
    }

    fn _set_fcsr_nv(&mut self) {
        self.add_to_fflags(0x10);
    }

    fn set_fcsr_dz(&mut self) {
        self.add_to_fflags(8);
    }

    fn _set_fcsr_of(&mut self) {
        self.add_to_fflags(4);
    }

    fn _set_fcsr_uf(&mut self) {
        self.add_to_fflags(2);
    }

    fn _set_fcsr_nx(&mut self) {
        self.add_to_fflags(1);
    }

    fn update_satp(&mut self, satp: u64) {
        let satp_mode = (satp >> SATP_MODE_SHIFT) & SATP_MODE_MASK;
        let addressing_mode = match FromPrimitive::from_u64(satp_mode) {
            Some(SatpMode::Bare) => AddressingMode::None,
            Some(SatpMode::Sv39) => AddressingMode::SV39,
            Some(SatpMode::Sv48) => AddressingMode::SV48,
            Some(SatpMode::Sv57) => todo!("Unsupported SATP mode SV57"),
            Some(SatpMode::Sv64) => todo!("Unsupported SATP mode SV64"),
            _ => todo!("Illegal SATP mode {satp_mode:02x}"),
        };
        self.mmu.update_addressing_mode(addressing_mode);
        self.mmu
            .update_ppn((satp >> SATP_PPN_SHIFT) & SATP_PPN_MASK);
    }

    /// Disassembles an instruction pointed by Program Counter and
    /// and return the [possibly] writeback register
    #[allow(clippy::cast_sign_loss)]
    pub fn disassemble(&mut self, s: &mut String) -> usize {
        let Some(word32) = self.memop_disass(self.pc) else {
            let _ = write!(s, "<inaccessible>");
            return 0;
        };
        let word32 = (word32 & 0xffffffff) as u32;
        let (insn, _) = decompress(0, word32);
        let Ok(decoded) = self.decode_raw(insn) else {
            let _ = write!(s, "{:016x} {word32:08x} Illegal instruction", self.pc);
            return 0;
        };

        let _ = write!(s, "{:016x} {word32:08x} {} ", self.pc, decoded.name);
        (decoded.disassemble)(s, self, word32, self.pc as u64, true)
    }

    /// Returns mutable `Mmu`
    pub const fn get_mut_mmu(&mut self) -> &mut Mmu {
        &mut self.mmu
    }

    /// Returns mutable `Terminal`
    pub fn get_mut_terminal(&mut self) -> &mut Box<dyn Terminal> {
        self.mmu.get_mut_uart().get_mut_terminal()
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn read_f32(&self, r: usize) -> f32 {
        assert_ne!(self.fs, 0);
        f32::from_bits(Sf32::unbox(self.read_f(r)) as u32)
    }

    fn read_f(&self, r: usize) -> i64 {
        assert_ne!(self.fs, 0);
        self.f_[r]
    }

    fn write_f(&mut self, r: usize, v: i64) {
        assert_ne!(self.fs, 0);
        self.f_[r] = v;
        self.fs = 3;
    }

    fn write_f32(&mut self, r: usize, f: f32) {
        self.write_f(r, fp::NAN_BOX_F32 | i64::from(f.to_bits()));
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn read_f64(&self, r: usize) -> f64 {
        f64::from_bits(self.read_f(r) as u64)
    }

    fn write_f64(&mut self, r: usize, f: f64) {
        self.write_f(r, f.to_bits() as i64);
    }

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
    ) -> Option<i64> {
        self.memop_general(access, baseva, offset, v, size, false)
    }

    fn memop_disass(&mut self, baseva: i64) -> Option<i64> {
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
    ) -> Option<i64> {
        let va = baseva.wrapping_add(offset);

        if va & 0xfff > 0x1000 - size {
            // Slow path. All bytes aren't in the same page so not contigious
            // in memory
            return self.memop_slow(access, va, v, size, side_effect_free);
        }

        let pa = match self
            .mmu
            .translate_address(va as u64, access, side_effect_free)
        {
            Ok(pa) => pa as i64,
            Err(trap) if !side_effect_free => {
                self.handle_exception(&trap);
                return None;
            }
            _ => return None,
        };

        let Ok(slice) = self.mmu.memory.slice(pa, size as usize) else {
            return self.memop_slow(access, va, v, size, side_effect_free);
        };

        match access {
            Write => {
                slice.copy_from_slice(&i64::to_le_bytes(v)[0..size as usize]);
                None
            }
            Read | Execute => {
                // Unsigned, sign extension is the job of the consumer
                let mut buf = [0; 8];
                buf[0..size as usize].copy_from_slice(slice);
                Some(i64::from_le_bytes(buf))
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
    ) -> Option<i64> {
        let trap_type = match access {
            Read => TrapType::LoadAccessFault,
            Write => TrapType::StoreAccessFault,
            Execute => TrapType::InstructionAccessFault,
        };

        let mut r: u64 = 0;
        for i in 0..size {
            let pa = match self
                .mmu
                .translate_address((va + i) as u64, access, side_effect_free)
            {
                Ok(pa) => pa,
                Err(trap) => {
                    self.handle_exception(&trap);
                    return None;
                }
            };

            let mut b = 0;
            if let Ok(slice) = self.mmu.memory.slice(pa as i64, 1) {
                match access {
                    Write => slice[0] = v as u8,
                    Read | Execute => b = slice[0],
                }
            } else {
                if side_effect_free {
                    // XXX todo!("Improve logging of disassembly access errors.  We are trying to {access:?} {size} bytes @ {va:016x}");
                    return None;
                }

                match access {
                    Write => {
                        let Ok(()) = self.mmu.store_mmio_u8(pa as i64, v as u8) else {
                            self.handle_exception(&Trap {
                                trap_type,
                                value: va + 1,
                            });
                            return None;
                        };
                    }
                    Read | Execute => {
                        let Ok(w) = self.mmu.load_mmio_u8(pa) else {
                            self.handle_exception(&Trap {
                                trap_type,
                                value: va + 1,
                            });
                            return None;
                        };
                        b = w;
                    }
                }
            }
            r |= u64::from(b) << (i * 8);
            v >>= 8;
        }
        if matches!(access, Write) {
            None
        } else {
            Some(r as i64)
        }
    }
}

struct Instruction {
    mask: u32,
    data: u32, // @TODO: rename
    name: &'static str,
    operation: fn(address: u64, word: u32, cpu: &mut Cpu) -> Result<(), Trap>,
    disassemble:
        fn(s: &mut String, cpu: &mut Cpu, word: u32, address: u64, evaluate: bool) -> usize,
}

#[inline]
const fn decompress(addr: i64, insn: u32) -> (u32, i64) {
    // XXX Technically, wrapping the pc is illegal and should be
    // trapped
    if insn & 3 == 3 {
        (insn, addr.wrapping_add(4))
    } else {
        let insn = rvc::RVC64_EXPANDED[insn as usize & 0xffff];
        (insn, addr.wrapping_add(2))
    }
}

struct FormatB {
    rs1: usize,
    rs2: usize,
    imm: u64,
}

#[allow(clippy::cast_sign_loss)]
const fn parse_format_b(word: u32) -> FormatB {
    FormatB {
        rs1: ((word >> 15) & 0x1f) as usize, // [19:15]
        rs2: ((word >> 20) & 0x1f) as usize, // [24:20]
        imm: (
            match word & 0x8000_0000 { // imm[31:12] = [31]
                                0x8000_0000 => 0xffff_f000,
                                _ => 0
                        } |
                        ((word << 4) & 0x0000_0800) | // imm[11] = [7]
                        ((word >> 20) & 0x0000_07e0) | // imm[10:5] = [30:25]
                        ((word >> 7) & 0x0000_001e)
            // imm[4:1] = [11:8]
        ) as i32 as i64 as u64,
    }
}

fn dump_format_b(s: &mut String, cpu: &mut Cpu, word: u32, address: u64, evaluate: bool) -> usize {
    let f = parse_format_b(word);
    *s += get_register_name(f.rs1);
    if evaluate {
        let _ = write!(s, ":{:x}", cpu.read_x(f.rs1));
    }
    let _ = write!(s, ",{}", get_register_name(f.rs2));
    if evaluate {
        let _ = write!(s, ":{:x}", cpu.read_x(f.rs2));
    }
    let _ = write!(s, ",{:x}", address.wrapping_add(f.imm));
    0
}

struct FormatCSR {
    csr: u16,
    rs: usize,
    rd: usize,
}

const fn parse_format_csr(word: u32) -> FormatCSR {
    FormatCSR {
        csr: ((word >> 20) & 0xfff) as u16, // [31:20]
        rs: ((word >> 15) & 0x1f) as usize, // [19:15], also uimm
        rd: ((word >> 7) & 0x1f) as usize,  // [11:7]
    }
}

fn dump_format_csr(
    s: &mut String,
    cpu: &mut Cpu,
    word: u32,
    _address: u64,
    evaluate: bool,
) -> usize {
    let f = parse_format_csr(word);
    *s += get_register_name(f.rd);
    if evaluate {
        let _ = write!(s, ":{:x}", cpu.read_x(f.rd));
    }

    if evaluate {
        let _ = match FromPrimitive::from_u16(f.csr) {
            Some(csr) => {
                write!(s, ", {csr}:{:x}", cpu.read_csr_raw(csr))
            }
            None => {
                write!(s, ", {}:-", f.csr)
            }
        };
    } else {
        let _ = write!(s, ",{:x}", f.csr);
    }

    let _ = write!(s, ",{}", get_register_name(f.rs));
    if evaluate {
        let _ = write!(s, ":{:x}", cpu.read_x(f.rs));
    }
    f.rd
}

struct FormatI {
    rd: usize,
    rs1: usize,
    imm: i64,
}

const fn parse_format_i(word: u32) -> FormatI {
    FormatI {
        rd: ((word >> 7) & 0x1f) as usize,   // [11:7]
        rs1: ((word >> 15) & 0x1f) as usize, // [19:15]
        imm: (
            match word & 0x8000_0000 {
                // imm[31:11] = [31]
                0x8000_0000 => 0xffff_f800,
                _ => 0,
            } | ((word >> 20) & 0x0000_07ff)
            // imm[10:0] = [30:20]
        ) as i32 as i64,
    }
}

fn dump_format_i(s: &mut String, cpu: &mut Cpu, word: u32, _address: u64, evaluate: bool) -> usize {
    let f = parse_format_i(word);
    *s += get_register_name(f.rd);
    if evaluate {
        let _ = write!(s, ":{:x}", cpu.read_x(f.rd));
    }
    let _ = write!(s, ",{}", get_register_name(f.rs1));
    if evaluate {
        let _ = write!(s, ":{:x}", cpu.read_x(f.rs1));
    }
    let _ = write!(s, ",{:x}", f.imm);
    f.rd
}

fn dump_format_i_mem(
    s: &mut String,
    cpu: &mut Cpu,
    word: u32,
    _address: u64,
    evaluate: bool,
) -> usize {
    let f = parse_format_i(word);
    *s += get_register_name(f.rd);
    if evaluate {
        let _ = write!(s, ":{:x}", cpu.read_x(f.rd));
    }
    let _ = write!(s, ",{:x}({}", f.imm, get_register_name(f.rs1));
    if evaluate {
        let _ = write!(s, ":{:x}", cpu.read_x(f.rs1));
    }
    *s += ")";
    f.rd
}

struct FormatJ {
    rd: usize,
    imm: u64,
}

#[allow(clippy::cast_sign_loss)]
const fn parse_format_j(word: u32) -> FormatJ {
    FormatJ {
        rd: ((word >> 7) & 0x1f) as usize, // [11:7]
        imm: (
            match word & 0x8000_0000 { // imm[31:20] = [31]
                                0x8000_0000 => 0xfff0_0000,
                                _ => 0
                        } |
                        (word & 0x000f_f000) | // imm[19:12] = [19:12]
                        ((word & 0x0010_0000) >> 9) | // imm[11] = [20]
                        ((word & 0x7fe0_0000) >> 20)
            // imm[10:1] = [30:21]
        ) as i32 as i64 as u64,
    }
}

fn dump_format_j(s: &mut String, cpu: &mut Cpu, word: u32, address: u64, evaluate: bool) -> usize {
    let f = parse_format_j(word);
    *s += get_register_name(f.rd);
    if evaluate {
        let _ = write!(s, ":{:x}", cpu.read_x(f.rd));
    }
    let _ = write!(s, ",{:x}", address.wrapping_add(f.imm));
    f.rd
}

#[derive(Debug)]
struct FormatR {
    rd: usize,
    funct3: usize,
    rs1: usize,
    rs2: usize,
}

const fn parse_format_r(word: u32) -> FormatR {
    FormatR {
        rd: ((word >> 7) & 0x1f) as usize,   // [11:7]
        funct3: ((word >> 12) & 7) as usize, // [14:12]
        rs1: ((word >> 15) & 0x1f) as usize, // [19:15]
        rs2: ((word >> 20) & 0x1f) as usize, // [24:20]
    }
}

fn dump_format_r(s: &mut String, cpu: &mut Cpu, word: u32, _address: u64, evaluate: bool) -> usize {
    let f = parse_format_r(word);
    *s += get_register_name(f.rd);
    if evaluate {
        let _ = write!(s, ":{:x}", cpu.read_x(f.rd));
    }
    *s += get_register_name(f.rs1);
    if evaluate {
        let _ = write!(s, ":{:x}", cpu.read_x(f.rs1));
    }
    let _ = write!(s, ",{}", get_register_name(f.rs2));
    if evaluate {
        let _ = write!(s, ":{:x}", cpu.read_x(f.rs2));
    }
    f.rd
}

// has rs3
struct FormatR2 {
    rd: usize,
    rm: usize,
    rs1: usize,
    rs2: usize,
    rs3: usize,
}

const fn parse_format_r2(word: u32) -> FormatR2 {
    FormatR2 {
        rd: ((word >> 7) & 0x1f) as usize,   // [11:7]
        rm: ((word >> 12) & 7) as usize,     // [14:12]
        rs1: ((word >> 15) & 0x1f) as usize, // [19:15]
        rs2: ((word >> 20) & 0x1f) as usize, // [24:20]
        rs3: ((word >> 27) & 0x1f) as usize, // [31:27]
    }
}

fn dump_format_r2(
    s: &mut String,
    cpu: &mut Cpu,
    word: u32,
    _address: u64,
    evaluate: bool,
) -> usize {
    let f = parse_format_r2(word);
    *s += get_register_name(f.rd);
    if evaluate {
        let _ = write!(s, ":{:x}", cpu.read_f(f.rd));
    }
    let _ = write!(s, ",{}", get_register_name(f.rs1));
    if evaluate {
        let _ = write!(s, ":{:x}", cpu.read_f(f.rs1));
    }
    let _ = write!(s, ",{}", get_register_name(f.rs2));
    if evaluate {
        let _ = write!(s, ":{:x}", cpu.read_f(f.rs2));
    }
    let _ = write!(s, ",{}", get_register_name(f.rs3));
    if evaluate {
        let _ = write!(s, ":{:x}", cpu.read_f(f.rs3));
    }
    f.rd
}

struct FormatS {
    rs1: usize,
    rs2: usize,
    imm: i64,
}

const fn parse_format_s(word: u32) -> FormatS {
    FormatS {
        rs1: ((word >> 15) & 0x1f) as usize, // [19:15]
        rs2: ((word >> 20) & 0x1f) as usize, // [24:20]
        imm: (
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

fn dump_format_s(s: &mut String, cpu: &mut Cpu, word: u32, _address: u64, evaluate: bool) -> usize {
    let f = parse_format_s(word);
    *s += get_register_name(f.rs2);
    if evaluate {
        let _ = write!(s, ":{:x}", cpu.read_x(f.rs2));
    }
    let _ = write!(s, ",{:x}({}", f.imm, get_register_name(f.rs1));
    if evaluate {
        let _ = write!(s, ":{:x}", cpu.read_x(f.rs1));
    }
    *s += ")";
    0
}

struct FormatU {
    rd: usize,
    imm: u64,
}

const fn parse_format_u(word: u32) -> FormatU {
    FormatU {
        rd: ((word >> 7) & 0x1f) as usize, // [11:7]
        imm: (match word & 0x80000000 {
            0x80000000 => 0xffffffff00000000,
            _ => 0,
        } | ((word as u64) & 0xfffff000)),
    }
}

fn dump_format_u(s: &mut String, cpu: &mut Cpu, word: u32, _address: u64, evaluate: bool) -> usize {
    let f = parse_format_u(word);
    *s += get_register_name(f.rd);
    if evaluate {
        let _ = write!(s, ":{:x}", cpu.read_x(f.rd));
    }
    let _ = write!(s, ",{:x}", f.imm);

    f.rd
}

#[allow(clippy::ptr_arg)] // Clippy can't tell that we can't change the function type
const fn dump_empty(
    _s: &mut String,
    _cpu: &mut Cpu,
    _word: u32,
    _address: u64,
    _evaluate: bool,
) -> usize {
    0
}

const fn get_register_name(num: usize) -> &'static str {
    [
        "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4",
        "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
        "t5", "t6",
    ][num]
}

const INSTRUCTION_NUM: usize = 163;

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
        data: 0x00000037,
        name: "LUI",
        operation: |_address, word, cpu| {
            let f = parse_format_u(word);
            cpu.write_x(f.rd, f.imm as i64);
            Ok(())
        },
        disassemble: dump_format_u,
    },
    Instruction {
        mask: 0x0000007f,
        data: 0x00000017,
        name: "AUIPC",
        operation: |address, word, cpu| {
            let f = parse_format_u(word);
            cpu.write_x(f.rd, address.wrapping_add(f.imm) as i64);
            Ok(())
        },
        disassemble: dump_format_u,
    },
    Instruction {
        mask: 0x0000007f,
        data: 0x0000006f,
        name: "JAL",
        operation: |address, word, cpu| {
            let f = parse_format_j(word);
            cpu.write_x(f.rd, cpu.pc);
            cpu.pc = address.wrapping_add(f.imm) as i64;
            Ok(())
        },
        disassemble: dump_format_j,
    },
    Instruction {
        mask: 0x0000707f,
        data: 0x00000067,
        name: "JALR",
        operation: |_address, word, cpu| {
            let f = parse_format_i(word);
            let tmp = cpu.pc;
            cpu.pc = cpu.read_x(f.rs1).wrapping_add(f.imm as i64) & !1;
            cpu.write_x(f.rd, tmp);
            Ok(())
        },
        disassemble: |s, cpu, word, _address, evaluate| {
            let f = parse_format_i(word);
            *s += get_register_name(f.rd);
            if evaluate {
                let _ = write!(s, ":{:x}", cpu.read_x(f.rd));
            }
            let _ = write!(s, ",{:x}({}", f.imm, get_register_name(f.rs1));
            if evaluate {
                let _ = write!(s, ":{:x}", cpu.read_x(f.rs1));
            }
            *s += ")";
            f.rd
        },
    },
    Instruction {
        mask: 0x0000707f,
        data: 0x00000063,
        name: "BEQ",
        operation: |address, word, cpu| {
            let f = parse_format_b(word);
            if cpu.read_x(f.rs1) == cpu.read_x(f.rs2) {
                cpu.pc = address.wrapping_add(f.imm) as i64;
            }
            Ok(())
        },
        disassemble: dump_format_b,
    },
    Instruction {
        mask: 0x0000707f,
        data: 0x00001063,
        name: "BNE",
        operation: |address, word, cpu| {
            let f = parse_format_b(word);
            if cpu.read_x(f.rs1) != cpu.read_x(f.rs2) {
                cpu.pc = address.wrapping_add(f.imm) as i64;
            }
            Ok(())
        },
        disassemble: dump_format_b,
    },
    Instruction {
        mask: 0x0000707f,
        data: 0x00004063,
        name: "BLT",
        operation: |address, word, cpu| {
            let f = parse_format_b(word);
            if cpu.read_x(f.rs1) < cpu.read_x(f.rs2) {
                cpu.pc = address.wrapping_add(f.imm) as i64;
            }
            Ok(())
        },
        disassemble: dump_format_b,
    },
    Instruction {
        mask: 0x0000707f,
        data: 0x00005063,
        name: "BGE",
        operation: |address, word, cpu| {
            let f = parse_format_b(word);
            if cpu.read_x(f.rs1) >= cpu.read_x(f.rs2) {
                cpu.pc = address.wrapping_add(f.imm) as i64;
            }
            Ok(())
        },
        disassemble: dump_format_b,
    },
    Instruction {
        mask: 0x0000707f,
        data: 0x00006063,
        name: "BLTU",
        operation: |address, word, cpu| {
            let f = parse_format_b(word);
            if (cpu.read_x(f.rs1) as u64) < (cpu.read_x(f.rs2) as u64) {
                cpu.pc = address.wrapping_add(f.imm) as i64;
            }
            Ok(())
        },
        disassemble: dump_format_b,
    },
    Instruction {
        mask: 0x0000707f,
        data: 0x00007063,
        name: "BGEU",
        operation: |address, word, cpu| {
            let f = parse_format_b(word);
            if (cpu.read_x(f.rs1) as u64) >= (cpu.read_x(f.rs2) as u64) {
                cpu.pc = address.wrapping_add(f.imm) as i64;
            }
            Ok(())
        },
        disassemble: dump_format_b,
    },
    Instruction {
        mask: 0x0000707f,
        data: 0x00000003,
        name: "LB",
        operation: |_address, word, cpu| {
            let f = parse_format_i(word);
            if let Some(v) = cpu.memop(Read, cpu.read_x(f.rs1), f.imm, 0, 1) {
                let v = v as i8 as i64;
                cpu.write_x(f.rd, v);
            }
            Ok(())
        },
        disassemble: dump_format_i_mem,
    },
    Instruction {
        mask: 0x0000707f,
        data: 0x00001003,
        name: "LH",
        operation: |_address, word, cpu| {
            let f = parse_format_i(word);
            if let Some(v) = cpu.memop(Read, cpu.read_x(f.rs1), f.imm, 0, 2) {
                let v = v as i16 as i64;
                cpu.write_x(f.rd, v);
            }
            Ok(())
        },
        disassemble: dump_format_i_mem,
    },
    Instruction {
        mask: 0x0000707f,
        data: 0x00002003,
        name: "LW",
        operation: |_address, word, cpu| {
            let f = parse_format_i(word);
            if let Some(v) = cpu.memop(Read, cpu.read_x(f.rs1), f.imm, 0, 4) {
                if f.rd != 0 {
                    cpu.write_x(f.rd, v as i32 as i64);
                }
            }
            Ok(())
        },
        disassemble: dump_format_i_mem,
    },
    Instruction {
        mask: 0x0000707f,
        data: 0x00004003,
        name: "LBU",
        operation: |_address, word, cpu| {
            let f = parse_format_i(word);
            if let Some(v) = cpu.memop(Read, cpu.read_x(f.rs1), f.imm, 0, 1) {
                cpu.write_x(f.rd, v);
            }
            Ok(())
        },
        disassemble: dump_format_i_mem,
    },
    Instruction {
        mask: 0x0000707f,
        data: 0x00005003,
        name: "LHU",
        operation: |_address, word, cpu| {
            let f = parse_format_i(word);
            if let Some(v) = cpu.memop(Read, cpu.read_x(f.rs1), f.imm, 0, 2) {
                cpu.write_x(f.rd, v);
            }
            Ok(())
        },
        disassemble: dump_format_i_mem,
    },
    Instruction {
        mask: 0x0000707f,
        data: 0x00000023,
        name: "SB",
        operation: |_address, word, cpu| {
            let f = parse_format_s(word);
            cpu.memop(Write, cpu.read_x(f.rs1), f.imm, cpu.read_x(f.rs2), 1);
            Ok(())
        },
        disassemble: dump_format_s,
    },
    Instruction {
        mask: 0x0000707f,
        data: 0x00001023,
        name: "SH",
        operation: |_address, word, cpu| {
            let f = parse_format_s(word);
            cpu.memop(Write, cpu.read_x(f.rs1), f.imm, cpu.read_x(f.rs2), 2);
            Ok(())
        },
        disassemble: dump_format_s,
    },
    Instruction {
        mask: 0x0000707f,
        data: 0x00002023,
        name: "SW",
        operation: |_address, word, cpu| {
            let f = parse_format_s(word);
            cpu.memop(Write, cpu.read_x(f.rs1), f.imm, cpu.read_x(f.rs2), 4);
            Ok(())
        },
        disassemble: dump_format_s,
    },
    Instruction {
        mask: 0x0000707f,
        data: 0x00000013,
        name: "ADDI",
        operation: |_address, word, cpu| {
            let f = parse_format_i(word);
            cpu.write_x(f.rd, cpu.read_x(f.rs1).wrapping_add(f.imm));
            Ok(())
        },
        disassemble: dump_format_i,
    },
    Instruction {
        mask: 0x0000707f,
        data: 0x00002013,
        name: "SLTI",
        operation: |_address, word, cpu| {
            let f = parse_format_i(word);
            cpu.write_x(f.rd, i64::from(cpu.read_x(f.rs1) < f.imm));
            Ok(())
        },
        disassemble: dump_format_i,
    },
    Instruction {
        mask: 0x0000707f,
        data: 0x00003013,
        name: "SLTIU",
        operation: |_address, word, cpu| {
            let f = parse_format_i(word);
            cpu.write_x(f.rd, i64::from((cpu.read_x(f.rs1) as u64) < (f.imm as u64)));
            Ok(())
        },
        disassemble: dump_format_i,
    },
    Instruction {
        mask: 0x0000707f,
        data: 0x00004013,
        name: "XORI",
        operation: |_address, word, cpu| {
            let f = parse_format_i(word);
            cpu.write_x(f.rd, cpu.read_x(f.rs1) ^ f.imm);
            Ok(())
        },
        disassemble: dump_format_i,
    },
    Instruction {
        mask: 0x0000707f,
        data: 0x00006013,
        name: "ORI",
        operation: |_address, word, cpu| {
            let f = parse_format_i(word);
            cpu.write_x(f.rd, cpu.read_x(f.rs1) | f.imm);
            Ok(())
        },
        disassemble: dump_format_i,
    },
    Instruction {
        mask: 0x0000707f,
        data: 0x00007013,
        name: "ANDI",
        operation: |_address, word, cpu| {
            let f = parse_format_i(word);
            cpu.write_x(f.rd, cpu.read_x(f.rs1) & f.imm);
            Ok(())
        },
        disassemble: dump_format_i,
    },
    // RV32I SLLI subsumed by RV64I
    // RV32I SRLI subsumed by RV64I
    // RV32I SRAI subsumed by RV64I
    Instruction {
        mask: 0xfe00707f,
        data: 0x00000033,
        name: "ADD",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.write_x(f.rd, cpu.read_x(f.rs1).wrapping_add(cpu.read_x(f.rs2)));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0x40000033,
        name: "SUB",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.write_x(f.rd, cpu.read_x(f.rs1).wrapping_sub(cpu.read_x(f.rs2)));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0x00001033,
        name: "SLL",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.write_x(
                f.rd,
                cpu.read_x(f.rs1).wrapping_shl(cpu.read_x(f.rs2) as u32),
            );
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0x00002033,
        name: "SLT",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.write_x(f.rd, i64::from(cpu.read_x(f.rs1) < cpu.read_x(f.rs2)));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0x00003033,
        name: "SLTU",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.write_x(
                f.rd,
                i64::from((cpu.read_x(f.rs1) as u64) < (cpu.read_x(f.rs2) as u64)),
            );
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0x00004033,
        name: "XOR",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.write_x(f.rd, cpu.read_x(f.rs1) ^ cpu.read_x(f.rs2));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0x00005033,
        name: "SRL",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.write_x(
                f.rd,
                (cpu.read_x(f.rs1) as u64).wrapping_shr(cpu.read_x(f.rs2) as u32) as i64,
            );
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0x40005033,
        name: "SRA",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.write_x(
                f.rd,
                cpu.read_x(f.rs1).wrapping_shr(cpu.read_x(f.rs2) as u32),
            );
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0x00006033,
        name: "OR",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.write_x(f.rd, cpu.read_x(f.rs1) | cpu.read_x(f.rs2));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0x00007033,
        name: "AND",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.write_x(f.rd, cpu.read_x(f.rs1) & cpu.read_x(f.rs2));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf000707f,
        data: 0x0000000f,
        name: "FENCE",
        operation: |_cpu, _word, _address| {
            // Fence memory ops (we are currently TSO already)
            Ok(())
        },
        disassemble: dump_empty,
    },
    Instruction {
        mask: 0xf000707f,
        data: 0x8000000f,
        name: "FENCE.TSO",
        operation: |_cpu, _word, _address| {
            // Fence memory ops (we are currently TSO already)
            Ok(())
        },
        disassemble: dump_empty,
    },
    Instruction {
        mask: 0xffffffff,
        data: 0x0100000f,
        name: "PAUSE",
        operation: |_cpu, _word, _address| {
            // Nothing to do here, but it would be interesting to see
            // it used.
            todo!("pause");
            //Ok(())
        },
        disassemble: dump_empty,
    },
    Instruction {
        mask: 0xffffffff,
        data: 0x00000073,
        name: "ECALL",
        operation: |address, _word, cpu| {
            let exception_type = match cpu.privilege_mode {
                PrivilegeMode::User => TrapType::EnvironmentCallFromUMode,
                PrivilegeMode::Supervisor => TrapType::EnvironmentCallFromSMode,
                PrivilegeMode::Machine => TrapType::EnvironmentCallFromMMode,
                PrivilegeMode::Reserved => panic!("Unknown Privilege mode"),
            };
            Err(Trap {
                trap_type: exception_type,
                value: address as i64,
            })
        },
        disassemble: dump_empty,
    },
    Instruction {
        mask: 0xffffffff,
        data: 0x00100073,
        name: "EBREAK",
        operation: |_cpu, word, _address| {
            log::info!(
                "** Handling ebreak requires handling debug mode; reporting it as an illegal instruction **"
            );
            Err(Trap {
                trap_type: TrapType::IllegalInstruction,
                value: word as i64,
            })
        },
        disassemble: dump_empty,
    },
    // RV64I
    Instruction {
        mask: 0x0000707f,
        data: 0x00006003,
        name: "LWU",
        operation: |_address, word, cpu| {
            let f = parse_format_i(word);
            if let Some(v) = cpu.memop(Read, cpu.read_x(f.rs1), f.imm, 0, 4) {
                cpu.write_x(f.rd, v);
            }
            Ok(())
        },
        disassemble: dump_format_i_mem,
    },
    Instruction {
        mask: 0x0000707f,
        data: 0x00003003,
        name: "LD",
        operation: |_address, word, cpu| {
            let f = parse_format_i(word);
            if let Some(v) = cpu.memop(Read, cpu.read_x(f.rs1), f.imm, 0, 8) {
                cpu.write_x(f.rd, v);
            }
            Ok(())
        },
        disassemble: dump_format_i_mem,
    },
    Instruction {
        mask: 0x0000707f,
        data: 0x00003023,
        name: "SD",
        operation: |_address, word, cpu| {
            let f = parse_format_s(word);
            cpu.memop(Write, cpu.read_x(f.rs1), f.imm, cpu.read_x(f.rs2), 8);
            Ok(())
        },
        disassemble: dump_format_s,
    },
    Instruction {
        mask: 0xfc00707f, // RV64I version!
        data: 0x00001013,
        name: "SLLI",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            let mask = 0x3f;
            let shamt = (word >> 20) & mask;
            cpu.write_x(f.rd, cpu.read_x(f.rs1) << shamt);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfc00707f,
        data: 0x00005013,
        name: "SRLI",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            let mask = 0x3f;
            let shamt = (word >> 20) & mask;
            cpu.write_x(f.rd, ((cpu.read_x(f.rs1) as u64) >> shamt) as i64);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfc00707f,
        data: 0x40005013,
        name: "SRAI",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            let mask = 0x3f;
            let shamt = (word >> 20) & mask;
            cpu.write_x(f.rd, cpu.read_x(f.rs1) >> shamt);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0x0000707f,
        data: 0x0000001b,
        name: "ADDIW",
        operation: |_address, word, cpu| {
            let f = parse_format_i(word);
            cpu.write_x(
                f.rd,
                i64::from(cpu.read_x(f.rs1).wrapping_add(f.imm) as i32),
            );
            Ok(())
        },
        disassemble: dump_format_i,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0x0000101b,
        name: "SLLIW",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            let shamt = f.rs2 as u32;
            cpu.write_x(f.rd, i64::from((cpu.read_x(f.rs1) << shamt) as i32));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0x0000501b,
        name: "SRLIW",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            let mask = 0x3f;
            let shamt = (word >> 20) & mask;
            cpu.write_x(
                f.rd,
                i64::from(((cpu.read_x(f.rs1) as u32) >> shamt) as i32),
            );
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0x4000501b,
        name: "SRAIW",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            let shamt = (word >> 20) & 0x1f;
            cpu.write_x(f.rd, i64::from((cpu.read_x(f.rs1) as i32) >> shamt));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0x0000003b,
        name: "ADDW",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.write_x(
                f.rd,
                i64::from(cpu.read_x(f.rs1).wrapping_add(cpu.read_x(f.rs2)) as i32),
            );
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0x4000003b,
        name: "SUBW",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.write_x(
                f.rd,
                i64::from(cpu.read_x(f.rs1).wrapping_sub(cpu.read_x(f.rs2)) as i32),
            );
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0x0000103b,
        name: "SLLW",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.write_x(
                f.rd,
                i64::from((cpu.read_x(f.rs1) as u32).wrapping_shl(cpu.read_x(f.rs2) as u32) as i32),
            );
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0x0000503b,
        name: "SRLW",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.write_x(
                f.rd,
                i64::from((cpu.read_x(f.rs1) as u32).wrapping_shr(cpu.read_x(f.rs2) as u32) as i32),
            );
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0x4000503b,
        name: "SRAW",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.write_x(
                f.rd,
                i64::from((cpu.read_x(f.rs1) as i32).wrapping_shr(cpu.read_x(f.rs2) as u32)),
            );
            Ok(())
        },
        disassemble: dump_format_r,
    },
    // RV32/RV64 Zifencei
    Instruction {
        mask: 0xffffffff,
        data: 0x0000100f,
        name: "FENCE.I",
        operation: |_cpu, _word, _address| {
            // Flush any cached instrutions.  We have none so far.
            Ok(())
        },
        disassemble: dump_empty,
    },
    // RV32/RV64 Zicsr
    Instruction {
        mask: 0x0000707f,
        data: 0x00001073,
        name: "CSRRW",
        operation: |_address, word, cpu| {
            let f = parse_format_csr(word);

            let tmp = cpu.read_x(f.rs);
            if f.rd == 0 {
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
        data: 0x00002073,
        name: "CSRRS",
        operation: |_address, word, cpu| {
            let f = parse_format_csr(word);
            let data = cpu.read_csr(f.csr)? as i64;
            if f.rs != 0 {
                cpu.write_csr(f.csr, (data | cpu.read_x(f.rs)) as u64)?;
            }
            if f.rd != 0 {
                cpu.write_x(f.rd, data);
            }
            Ok(())
        },
        disassemble: dump_format_csr,
    },
    Instruction {
        mask: 0x0000707f,
        data: 0x00003073,
        name: "CSRRC",
        operation: |_address, word, cpu| {
            let f = parse_format_csr(word);
            let data = cpu.read_csr(f.csr)? as i64;
            if f.rs != 0 {
                cpu.write_csr(f.csr, (data & !cpu.read_x(f.rs)) as u64)?;
            }
            if f.rd != 0 {
                cpu.write_x(f.rd, data);
            }
            Ok(())
        },
        disassemble: dump_format_csr,
    },
    Instruction {
        mask: 0x0000707f,
        data: 0x00005073,
        name: "CSRRWI",
        operation: |_address, word, cpu| {
            let f = parse_format_csr(word);

            if f.rd == 0 {
                cpu.write_csr(f.csr, f.rs as u64)?;
            } else {
                let v = cpu.read_csr(f.csr)? as i64;
                cpu.write_csr(f.csr, f.rs as u64)?;
                cpu.write_x(f.rd, v);
            }

            Ok(())
        },
        disassemble: dump_format_csr,
    },
    Instruction {
        mask: 0x0000707f,
        data: 0x00006073,
        name: "CSRRSI",
        operation: |_address, word, cpu| {
            let f = parse_format_csr(word);
            let data = cpu.read_csr(f.csr)? as i64;
            if f.rs != 0 {
                cpu.write_csr(f.csr, (data | f.rs as i64) as u64)?;
            }
            if f.rd != 0 {
                cpu.write_x(f.rd, data);
            }
            Ok(())
        },
        disassemble: dump_format_csr,
    },
    Instruction {
        mask: 0x0000707f,
        data: 0x00007073,
        name: "CSRRCI",
        operation: |_address, word, cpu| {
            let f = parse_format_csr(word);
            let data = cpu.read_csr(f.csr)? as i64;
            if f.rs != 0 {
                cpu.write_csr(f.csr, (data & !(f.rs as i64)) as u64)?;
            }
            if f.rd != 0 {
                cpu.write_x(f.rd, data);
            }
            Ok(())
        },
        disassemble: dump_format_csr,
    },
    // RV32M
    Instruction {
        mask: 0xfe00707f,
        data: 0x02000033,
        name: "MUL",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.write_x(f.rd, cpu.read_x(f.rs1).wrapping_mul(cpu.read_x(f.rs2)));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0x02001033,
        name: "MULH",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.write_x(
                f.rd,
                ((i128::from(cpu.read_x(f.rs1)) * i128::from(cpu.read_x(f.rs2))) >> 64) as i64,
            );
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0x02002033,
        name: "MULHSU",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.write_x(
                f.rd,
                ((cpu.read_x(f.rs1) as u128).wrapping_mul(u128::from(cpu.read_x(f.rs2) as u64))
                    >> 64) as i64,
            );
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0x02003033,
        name: "MULHU",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.write_x(
                f.rd,
                (u128::from(cpu.read_x(f.rs1) as u64)
                    .wrapping_mul(u128::from(cpu.read_x(f.rs2) as u64))
                    >> 64) as i64,
            );
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0x02004033,
        name: "DIV",
        operation: |_address, word, cpu| {
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
        data: 0x02005033,
        name: "DIVU",
        operation: |_address, word, cpu| {
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
        data: 0x02006033,
        name: "REM",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            let dividend = cpu.read_x(f.rs1);
            let divisor = cpu.read_x(f.rs2);
            if divisor == 0 {
                cpu.write_x(f.rd, dividend);
            } else if dividend == i64::MIN && divisor == -1 {
                cpu.write_x(f.rd, 0);
            } else {
                cpu.write_x(f.rd, cpu.read_x(f.rs1).wrapping_rem(cpu.read_x(f.rs2)));
            }
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0x02007033,
        name: "REMU",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            let dividend = cpu.read_x(f.rs1) as u64;
            let divisor = cpu.read_x(f.rs2) as u64;
            cpu.write_x(
                f.rd,
                match divisor {
                    0 => dividend as i64,
                    _ => dividend.wrapping_rem(divisor) as i64,
                },
            );
            Ok(())
        },
        disassemble: dump_format_r,
    },
    // RV64M
    Instruction {
        mask: 0xfe00707f,
        data: 0x0200003b,
        name: "MULW",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.write_x(
                f.rd,
                i64::from((cpu.read_x(f.rs1) as i32).wrapping_mul(cpu.read_x(f.rs2) as i32)),
            );
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0x0200403b,
        name: "DIVW",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            let dividend = cpu.read_x(f.rs1) as i32;
            let divisor = cpu.read_x(f.rs2) as i32;
            if divisor == 0 {
                cpu.write_x(f.rd, -1);
            } else if dividend == i32::MIN && divisor == -1 {
                cpu.write_x(f.rd, i64::from(dividend as i32));
            } else {
                cpu.write_x(f.rd, i64::from(dividend.wrapping_div(divisor) as i32));
            }
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0x0200503b,
        name: "DIVUW",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            let dividend = cpu.read_x(f.rs1) as u32;
            let divisor = cpu.read_x(f.rs2) as u32;
            if divisor == 0 {
                cpu.write_x(f.rd, -1);
            } else {
                cpu.write_x(f.rd, i64::from(dividend.wrapping_div(divisor) as i32));
            }
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0x0200603b,
        name: "REMW",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            let dividend = cpu.read_x(f.rs1) as i32;
            let divisor = cpu.read_x(f.rs2) as i32;
            if divisor == 0 {
                cpu.write_x(f.rd, i64::from(dividend));
            } else if dividend == i32::MIN && divisor == -1 {
                cpu.write_x(f.rd, 0);
            } else {
                cpu.write_x(f.rd, i64::from(dividend.wrapping_rem(divisor)));
            }
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0x0200703b,
        name: "REMUW",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            let dividend = cpu.read_x(f.rs1) as u32;
            let divisor = cpu.read_x(f.rs2) as u32;
            cpu.write_x(
                f.rd,
                match divisor {
                    0 => i64::from(dividend as i32),
                    _ => i64::from(dividend.wrapping_rem(divisor) as i32),
                },
            );
            Ok(())
        },
        disassemble: dump_format_r,
    },
    // RV32A
    Instruction {
        mask: 0xf9f0707f,
        data: 0x1000202f,
        name: "LR.W",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            // @TODO: Implement properly
            match cpu.mmu.load_virt_u32(cpu.read_x(f.rs1) as u64) {
                Ok(data) => {
                    cpu.reservation = Some(cpu.read_x(f.rs1)); // Is virtual address ok?
                    cpu.write_x(f.rd, i64::from(data as i32));
                }
                Err(e) => return Err(e),
            };
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        data: 0x1800202f,
        name: "SC.W",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            // @TODO: Implement properly
            if cpu.reservation == Some(cpu.read_x(f.rs1)) {
                cpu.mmu
                    .store_virt_u32(cpu.read_x(f.rs1) as u64, cpu.read_x(f.rs2) as u32)?;
                cpu.reservation = None;
                cpu.write_x(f.rd, 0);
            } else {
                cpu.write_x(f.rd, 1);
            };
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        data: 0x0800202f,
        name: "AMOSWAP.W",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            let tmp = match cpu.mmu.load_virt_u32(cpu.read_x(f.rs1) as u64) {
                Ok(data) => i64::from(data as i32),
                Err(e) => return Err(e),
            };
            match cpu
                .mmu
                .store_virt_u32(cpu.read_x(f.rs1) as u64, cpu.read_x(f.rs2) as u32)
            {
                Ok(()) => {}
                Err(e) => return Err(e),
            }
            cpu.write_x(f.rd, tmp);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        data: 0x0000202f,
        name: "AMOADD.W",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            let tmp = match cpu.mmu.load_virt_u32(cpu.read_x(f.rs1) as u64) {
                Ok(data) => i64::from(data as i32),
                Err(e) => return Err(e),
            };
            match cpu.mmu.store_virt_u32(
                cpu.read_x(f.rs1) as u64,
                cpu.read_x(f.rs2).wrapping_add(tmp) as u32,
            ) {
                Ok(()) => {}
                Err(e) => return Err(e),
            }
            cpu.write_x(f.rd, tmp);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        data: 0x2000202f,
        name: "AMOXOR.W",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            let tmp = match cpu.mmu.load_virt_u32(cpu.read_x(f.rs1) as u64) {
                Ok(data) => data,
                Err(e) => return Err(e),
            };
            match cpu
                .mmu
                .store_virt_u32(cpu.read_x(f.rs1) as u64, cpu.read_x(f.rs2) as u32 ^ tmp)
            {
                Ok(()) => {}
                Err(e) => return Err(e),
            }
            cpu.write_x(f.rd, i64::from(tmp as i32));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        data: 0x6000202f,
        name: "AMOAND.W",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            let tmp = match cpu.mmu.load_virt_u32(cpu.read_x(f.rs1) as u64) {
                Ok(data) => i64::from(data as i32),
                Err(e) => return Err(e),
            };
            match cpu
                .mmu
                .store_virt_u32(cpu.read_x(f.rs1) as u64, (cpu.read_x(f.rs2) & tmp) as u32)
            {
                Ok(()) => {}
                Err(e) => return Err(e),
            }
            cpu.write_x(f.rd, tmp);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        data: 0x4000202f,
        name: "AMOOR.W",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            let tmp = match cpu.mmu.load_virt_u32(cpu.read_x(f.rs1) as u64) {
                Ok(data) => i64::from(data as i32),
                Err(e) => return Err(e),
            };
            match cpu
                .mmu
                .store_virt_u32(cpu.read_x(f.rs1) as u64, (cpu.read_x(f.rs2) | tmp) as u32)
            {
                Ok(()) => {}
                Err(e) => return Err(e),
            }
            cpu.write_x(f.rd, tmp);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        data: 0x8000202f,
        name: "AMOMIN.W",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            let tmp = match cpu.mmu.load_virt_u32(cpu.read_x(f.rs1) as u64) {
                Ok(data) => data as i32,
                Err(e) => return Err(e),
            };
            let min = if (cpu.read_x(f.rs2) as i32) < tmp {
                cpu.read_x(f.rs2) as i32
            } else {
                tmp
            };
            match cpu.mmu.store_virt_u32(cpu.read_x(f.rs1) as u64, min as u32) {
                Ok(()) => {}
                Err(e) => return Err(e),
            }
            cpu.write_x(f.rd, i64::from(tmp));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        data: 0xa000202f,
        name: "AMOMAX.W",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            let tmp = match cpu.mmu.load_virt_u32(cpu.read_x(f.rs1) as u64) {
                Ok(data) => data as i32,
                Err(e) => return Err(e),
            };
            let max = if cpu.read_x(f.rs2) as i32 >= tmp {
                cpu.read_x(f.rs2) as i32
            } else {
                tmp
            };
            match cpu.mmu.store_virt_u32(cpu.read_x(f.rs1) as u64, max as u32) {
                Ok(()) => {}
                Err(e) => return Err(e),
            }
            cpu.write_x(f.rd, i64::from(tmp));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        data: 0xc000202f,
        name: "AMOMINU.W",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            let tmp = match cpu.mmu.load_virt_u32(cpu.read_x(f.rs1) as u64) {
                Ok(data) => data,
                Err(e) => return Err(e),
            };
            let min = if cpu.read_x(f.rs2) as u32 <= tmp {
                cpu.read_x(f.rs2) as u32
            } else {
                tmp
            };
            match cpu.mmu.store_virt_u32(cpu.read_x(f.rs1) as u64, min) {
                Ok(()) => {}
                Err(e) => return Err(e),
            }
            if f.rd != 0 {
                cpu.write_x(f.rd, i64::from(tmp as i32));
            }
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        data: 0xe000202f,
        name: "AMOMAXU.W",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            let tmp = match cpu.mmu.load_virt_u32(cpu.read_x(f.rs1) as u64) {
                Ok(data) => data,
                Err(e) => return Err(e),
            };
            let max = if cpu.read_x(f.rs2) as u32 >= tmp {
                cpu.read_x(f.rs2) as u32
            } else {
                tmp
            };
            match cpu.mmu.store_virt_u32(cpu.read_x(f.rs1) as u64, max) {
                Ok(()) => {}
                Err(e) => return Err(e),
            }
            cpu.write_x(f.rd, i64::from(tmp as i32));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    // RV64A
    Instruction {
        mask: 0xf9f0707f,
        data: 0x1000302f,
        name: "LR.D",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            // @TODO: Implement properly
            match cpu.mmu.load_virt_u64(cpu.read_x(f.rs1) as u64) {
                Ok(data) => {
                    cpu.reservation = Some(cpu.read_x(f.rs1)); // Is virtual address ok?
                    cpu.write_x(f.rd, data as i64);
                }
                Err(e) => return Err(e),
            };
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        data: 0x1800302f,
        name: "SC.D",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            // @TODO: Implement properly
            if cpu.reservation == Some(cpu.read_x(f.rs1)) {
                cpu.mmu
                    .store_virt_u64(cpu.read_x(f.rs1) as u64, cpu.read_x(f.rs2) as u64)?;
                cpu.reservation = None;
                cpu.write_x(f.rd, 0);
            } else {
                cpu.write_x(f.rd, 1);
            }
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        data: 0x0800302f,
        name: "AMOSWAP.D",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            let tmp = match cpu.mmu.load_virt_u64(cpu.read_x(f.rs1) as u64) {
                Ok(data) => data as i64,
                Err(e) => return Err(e),
            };
            match cpu
                .mmu
                .store_virt_u64(cpu.read_x(f.rs1) as u64, cpu.read_x(f.rs2) as u64)
            {
                Ok(()) => {}
                Err(e) => return Err(e),
            }
            cpu.write_x(f.rd, tmp);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        data: 0x0000302f,
        name: "AMOADD.D",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            let tmp = match cpu.mmu.load_virt_u64(cpu.read_x(f.rs1) as u64) {
                Ok(data) => data as i64,
                Err(e) => return Err(e),
            };
            match cpu.mmu.store_virt_u64(
                cpu.read_x(f.rs1) as u64,
                cpu.read_x(f.rs2).wrapping_add(tmp) as u64,
            ) {
                Ok(()) => {}
                Err(e) => return Err(e),
            }
            cpu.write_x(f.rd, tmp);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        data: 0x2000302f,
        name: "AMOXOR.D",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            let tmp = match cpu.mmu.load_virt_u64(cpu.read_x(f.rs1) as u64) {
                Ok(data) => data,
                Err(e) => return Err(e),
            };
            match cpu
                .mmu
                .store_virt_u64(cpu.read_x(f.rs1) as u64, cpu.read_x(f.rs2) as u64 ^ tmp)
            {
                Ok(()) => {}
                Err(e) => return Err(e),
            }
            cpu.write_x(f.rd, tmp as i64);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        data: 0x6000302f,
        name: "AMOAND.D",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            let tmp = match cpu.mmu.load_virt_u64(cpu.read_x(f.rs1) as u64) {
                Ok(data) => data as i64,
                Err(e) => return Err(e),
            };
            match cpu
                .mmu
                .store_virt_u64(cpu.read_x(f.rs1) as u64, (cpu.read_x(f.rs2) & tmp) as u64)
            {
                Ok(()) => {}
                Err(e) => return Err(e),
            }
            cpu.write_x(f.rd, tmp);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        data: 0x4000302f,
        name: "AMOOR.D",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            let tmp = match cpu.mmu.load_virt_u64(cpu.read_x(f.rs1) as u64) {
                Ok(data) => data as i64,
                Err(e) => return Err(e),
            };
            match cpu
                .mmu
                .store_virt_u64(cpu.read_x(f.rs1) as u64, (cpu.read_x(f.rs2) | tmp) as u64)
            {
                Ok(()) => {}
                Err(e) => return Err(e),
            }
            cpu.write_x(f.rd, tmp);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        data: 0x8000302f,
        name: "AMOMIN.D",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            let tmp = match cpu.mmu.load_virt_u64(cpu.read_x(f.rs1) as u64) {
                Ok(data) => data as i64,
                Err(e) => return Err(e),
            };
            let min = if cpu.read_x(f.rs2) < tmp {
                cpu.read_x(f.rs2)
            } else {
                tmp
            };
            match cpu.mmu.store_virt_u64(cpu.read_x(f.rs1) as u64, min as u64) {
                Ok(()) => {}
                Err(e) => return Err(e),
            }
            cpu.write_x(f.rd, tmp);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        data: 0xa000302f,
        name: "AMOMAX.D",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            let tmp = match cpu.mmu.load_virt_u64(cpu.read_x(f.rs1) as u64) {
                Ok(data) => data as i64,
                Err(e) => return Err(e),
            };
            let max = if cpu.read_x(f.rs2) >= tmp {
                cpu.read_x(f.rs2)
            } else {
                tmp
            };
            match cpu.mmu.store_virt_u64(cpu.read_x(f.rs1) as u64, max as u64) {
                Ok(()) => {}
                Err(e) => return Err(e),
            }
            cpu.write_x(f.rd, tmp);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        data: 0xc000302f,
        name: "AMOMINU.D",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            let tmp = match cpu.mmu.load_virt_u64(cpu.read_x(f.rs1) as u64) {
                Ok(data) => data,
                Err(e) => return Err(e),
            };
            let min = if cpu.read_x(f.rs2) as u64 <= tmp {
                cpu.read_x(f.rs2) as u64
            } else {
                tmp
            };
            match cpu.mmu.store_virt_u64(cpu.read_x(f.rs1) as u64, min) {
                Ok(()) => {}
                Err(e) => return Err(e),
            }
            cpu.write_x(f.rd, tmp as i64);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xf800707f,
        data: 0xe000302f,
        name: "AMOMAXU.D",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            let tmp = match cpu.mmu.load_virt_u64(cpu.read_x(f.rs1) as u64) {
                Ok(data) => data,
                Err(e) => return Err(e),
            };
            let max = if cpu.read_x(f.rs2) as u64 >= tmp {
                cpu.read_x(f.rs2) as u64
            } else {
                tmp
            };
            match cpu.mmu.store_virt_u64(cpu.read_x(f.rs1) as u64, max) {
                Ok(()) => {}
                Err(e) => return Err(e),
            }
            cpu.write_x(f.rd, tmp as i64);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    // RV32F
    Instruction {
        mask: 0x0000707f,
        data: 0x00002007,
        name: "FLW",
        operation: |_address, word, cpu| {
            let f = parse_format_i(word);
            cpu.check_float_access(0)?;
            if let Some(v) = cpu.memop(Read, cpu.read_x(f.rs1), f.imm, 0, 4) {
                cpu.write_f(f.rd, v as i32 as i64 | fp::NAN_BOX_F32);
            }
            Ok(())
        },
        disassemble: dump_format_i_mem,
    },
    Instruction {
        mask: 0x0000707f,
        data: 0x00002027,
        name: "FSW",
        operation: |_address, word, cpu| {
            cpu.check_float_access(0)?;
            let f = parse_format_s(word);
            cpu.mmu
                .store_virt_u32_(cpu.read_x(f.rs1).wrapping_add(f.imm), cpu.read_f(f.rs2))
        },
        disassemble: dump_format_s,
    },
    Instruction {
        mask: 0x0600007f,
        data: 0x00000043,
        name: "FMADD.S",
        operation: |_address, word, cpu| {
            let f = parse_format_r2(word);
            cpu.check_float_access(f.rm)?;
            // XXX Update fflags
            cpu.write_f32(
                f.rd,
                cpu.read_f32(f.rs1)
                    .mul_add(cpu.read_f32(f.rs2), cpu.read_f32(f.rs3)),
            );
            Ok(())
        },
        disassemble: dump_format_r2,
    },
    Instruction {
        mask: 0x0600007f,
        data: 0x00000047,
        name: "FMSUB.S",
        operation: |_address, word, cpu| {
            let f = parse_format_r2(word);
            cpu.check_float_access(f.rm)?;
            cpu.write_f32(
                f.rd,
                cpu.read_f32(f.rs1)
                    .mul_add(cpu.read_f32(f.rs2), -cpu.read_f32(f.rs3)),
            );
            Ok(())
        },
        disassemble: dump_format_r2,
    },
    Instruction {
        mask: 0x0600007f,
        data: 0x0000004b,
        name: "FNMSUB.S",
        operation: |_address, word, cpu| {
            let f = parse_format_r2(word);
            cpu.check_float_access(f.rm)?;
            cpu.write_f32(
                f.rd,
                -(cpu
                    .read_f32(f.rs1)
                    .mul_add(cpu.read_f32(f.rs2), -cpu.read_f32(f.rs3))),
            );
            Ok(())
        },
        disassemble: dump_format_r2,
    },
    Instruction {
        mask: 0x0600007f,
        data: 0x0000004f,
        name: "FNMADD.S",
        operation: |_address, word, cpu| {
            let f = parse_format_r2(word);
            cpu.check_float_access(f.rm)?;
            cpu.write_f32(
                f.rd,
                -(cpu
                    .read_f32(f.rs1)
                    .mul_add(cpu.read_f32(f.rs2), cpu.read_f32(f.rs3))),
            );
            Ok(())
        },
        disassemble: dump_format_r2,
    },
    Instruction {
        mask: 0xfe00007f,
        data: 0x00000053,
        name: "FADD.S",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_f32(f.rd, cpu.read_f32(f.rs1) + cpu.read_f32(f.rs2));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00007f,
        data: 0x08000053,
        name: "FSUB.S",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_f32(f.rd, cpu.read_f32(f.rs1) - cpu.read_f32(f.rs2));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00007f,
        data: 0x10000053,
        name: "FMUL.S",
        operation: |_address, word, cpu| {
            // @TODO: Update fcsr
            let f = parse_format_r(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_f32(f.rd, cpu.read_f32(f.rs1) * cpu.read_f32(f.rs2));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00007f,
        data: 0x18000053,
        name: "FDIV.S",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.check_float_access(f.funct3)?;
            //let rm = cpu.get_rm(word);

            let dividend = cpu.read_f32(f.rs1);
            let divisor = cpu.read_f32(f.rs2);
            // Is this implementation correct?
            let r = if divisor == 0.0 {
                cpu.set_fcsr_dz();
                f32::INFINITY
            } else if divisor == -0.0 {
                cpu.set_fcsr_dz();
                f32::NEG_INFINITY
            } else {
                dividend / divisor
            };

            cpu.write_f32(f.rd, r);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0007f,
        data: 0x58000053,
        name: "FSQRT.S",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_f32(f.rd, cpu.read_f32(f.rs1).sqrt());
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0x20000053,
        name: "FSGNJ.S",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
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
        data: 0x20001053,
        name: "FSGNJN.S",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
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
        data: 0x20002053,
        name: "FSGNJX.S",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
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
        data: 0x28000053,
        name: "FMIN.S",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
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
        data: 0x28001053,
        name: "FMAX.S",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
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
        data: 0xc0000053,
        name: "FCVT.W.S",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_x(f.rd, i64::from(cpu.read_f32(f.rs1) as i32));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0007f,
        data: 0xc0100053,
        name: "FCVT.WU.S",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_x(f.rd, i64::from(cpu.read_f32(f.rs1) as u32));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0707f,
        data: 0xe0000053,
        name: "FMV.X.W",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.check_float_access(0)?;
            cpu.write_x(f.rd, i64::from(cpu.read_f(f.rs1) as i32));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0xa0002053,
        name: "FEQ.S",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.check_float_access(0)?;
            let (r, fflags) = Sf32::feq(cpu.read_f(f.rs1), cpu.read_f(f.rs2));
            if f.rd != 0 {
                cpu.write_x(f.rd, i64::from(r));
            }
            cpu.add_to_fflags(fflags);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0xa0001053,
        name: "FLT.S",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.check_float_access(0)?;
            let (r, fflags) = Sf32::flt(cpu.read_f(f.rs1), cpu.read_f(f.rs2));
            if f.rd != 0 {
                cpu.write_x(f.rd, i64::from(r));
            }
            cpu.add_to_fflags(fflags);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0xa0000053,
        name: "FLE.S",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.check_float_access(0)?;
            let (r, fflags) = Sf32::fle(cpu.read_f(f.rs1), cpu.read_f(f.rs2));
            if f.rd != 0 {
                cpu.write_x(f.rd, i64::from(r));
            }
            cpu.add_to_fflags(fflags);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0707f,
        data: 0xe0001053,
        name: "FCLASS.S",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.check_float_access(0)?;

            if f.rd != 0 {
                cpu.write_x(f.rd, 1 << Sf32::fclass(cpu.read_f(f.rs1)) as usize);
            }
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0007f,
        data: 0xd0000053,
        name: "FCVT.S.W",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
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
        data: 0xd0100053,
        name: "FCVT.S.WU",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
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
        data: 0xf0000053,
        name: "FMV.W.X",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_f(f.rd, fp::NAN_BOX_F32 | cpu.read_x(f.rs1));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    // RV64F
    Instruction {
        mask: 0xfff0007f,
        data: 0xc0200053,
        name: "FCVT.L.S",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.check_float_access(f.funct3)?;
            if f.rd != 0 {
                cpu.write_x(f.rd, cpu.read_f32(f.rs1) as i64);
            }
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0007f,
        data: 0xc0300053,
        name: "FCVT.LU.S",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.check_float_access(f.funct3)?;
            if f.rd != 0 {
                cpu.write_x(f.rd, cpu.read_f32(f.rs1) as u64 as i64);
            }
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0007f,
        data: 0xd0200053,
        name: "FCVT.S.L",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
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
        data: 0xd0300053,
        name: "FCVT.S.LU",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
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
        data: 0x00003007,
        name: "FLD",
        operation: |_address, word, cpu| {
            let f = parse_format_i(word);
            cpu.check_float_access(0)?;
            if let Some(v) = cpu.memop(Read, cpu.read_x(f.rs1), f.imm, 0, 8) {
                cpu.write_f(f.rd, v);
            }
            Ok(())
        },
        disassemble: dump_format_i,
    },
    Instruction {
        mask: 0x0000707f,
        data: 0x00003027,
        name: "FSD",
        operation: |_address, word, cpu| {
            cpu.check_float_access(0)?;
            let f = parse_format_s(word);
            cpu.mmu
                .store64(cpu.read_x(f.rs1).wrapping_add(f.imm), cpu.read_f(f.rs2))
        },
        disassemble: dump_format_s,
    },
    Instruction {
        mask: 0x0600007f,
        data: 0x02000043, // Example 7287f7c3 fmadd.d fa5,fa5,fs0,fa4
        name: "FMADD.D",
        operation: |_address, word, cpu| {
            let f = parse_format_r2(word);
            cpu.check_float_access(f.rm)?;
            // XXX Update fflf.rmags
            cpu.write_f64(
                f.rd,
                cpu.read_f64(f.rs1)
                    .mul_add(cpu.read_f64(f.rs2), cpu.read_f64(f.rs3)),
            );
            Ok(())
        },
        disassemble: dump_format_r2,
    },
    Instruction {
        mask: 0x0600007f,
        data: 0x02000047,
        name: "FMSUB.D",
        operation: |_address, word, cpu| {
            let f = parse_format_r2(word);
            cpu.check_float_access(f.rm)?;
            cpu.write_f64(
                f.rd,
                cpu.read_f64(f.rs1)
                    .mul_add(cpu.read_f64(f.rs2), -cpu.read_f64(f.rs3)),
            );
            Ok(())
        },
        disassemble: dump_format_r2,
    },
    Instruction {
        mask: 0x0600007f,
        data: 0x0200004b,
        name: "FNMSUB.D",
        operation: |_address, word, cpu| {
            let f = parse_format_r2(word);
            cpu.check_float_access(f.rm)?;
            cpu.write_f64(
                f.rd,
                -(cpu
                    .read_f64(f.rs1)
                    .mul_add(cpu.read_f64(f.rs2), -cpu.read_f64(f.rs3))),
            );
            Ok(())
        },
        disassemble: dump_format_r2,
    },
    Instruction {
        mask: 0x0600007f,
        data: 0x0200004f,
        name: "FNMADD.D",
        operation: |_address, word, cpu| {
            let f = parse_format_r2(word);
            cpu.check_float_access(f.rm)?;
            cpu.write_f64(
                f.rd,
                -(cpu
                    .read_f64(f.rs1)
                    .mul_add(cpu.read_f64(f.rs2), cpu.read_f64(f.rs3))),
            );
            Ok(())
        },
        disassemble: dump_format_r2,
    },
    Instruction {
        mask: 0xfe00007f,
        data: 0x02000053,
        name: "FADD.D",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_f64(f.rd, cpu.read_f64(f.rs1) + cpu.read_f64(f.rs2));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00007f,
        data: 0x0a000053,
        name: "FSUB.D",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_f64(f.rd, cpu.read_f64(f.rs1) - cpu.read_f64(f.rs2));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00007f,
        data: 0x12000053,
        name: "FMUL.D",
        operation: |_address, word, cpu| {
            // @TODO: Update fcsr
            let f = parse_format_r(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_f64(f.rd, cpu.read_f64(f.rs1) * cpu.read_f64(f.rs2));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00007f,
        data: 0x1a000053,
        name: "FDIV.D",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.check_float_access(f.funct3)?;
            let dividend = cpu.read_f64(f.rs1);
            let divisor = cpu.read_f64(f.rs2);
            // Is this implementation correct?
            let r = if divisor == 0.0 {
                cpu.set_fcsr_dz();
                f64::INFINITY
            } else if divisor == -0.0 {
                cpu.set_fcsr_dz();
                f64::NEG_INFINITY
            } else {
                dividend / divisor
            };
            cpu.write_f64(f.rd, r);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0007f,
        data: 0x5a000053,
        name: "FSQRT.D",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_f64(f.rd, cpu.read_f64(f.rs1).sqrt());
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0x22000053,
        name: "FSGNJ.D",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
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
        data: 0x22001053,
        name: "FSGNJN.D",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
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
        data: 0x22002053,
        name: "FSGNJX.D",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
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
        data: 0x2A000053,
        name: "FMIN.D",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
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
        data: 0x2A001053,
        name: "FMAX.D",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
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
        data: 0x40100053,
        name: "FCVT.S.D",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_f32(f.rd, cpu.read_f64(f.rs1) as f32);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0007f,
        data: 0x42000053,
        name: "FCVT.D.S",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
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
        data: 0xa2002053,
        name: "FEQ.D",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.check_float_access(0)?;
            let (r, fflags) = Sf64::feq(cpu.read_f(f.rs1), cpu.read_f(f.rs2));
            if f.rd != 0 {
                cpu.write_x(f.rd, i64::from(r));
            }
            cpu.add_to_fflags(fflags);

            Ok(())
        },
        disassemble: dump_empty,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0xa2001053,
        name: "FLT.D",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.check_float_access(0)?;
            let (r, fflags) = Sf64::flt(cpu.read_f(f.rs1), cpu.read_f(f.rs2));
            if f.rd != 0 {
                cpu.write_x(f.rd, i64::from(r));
            }
            cpu.add_to_fflags(fflags);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfe00707f,
        data: 0xa2000053,
        name: "FLE.D",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.check_float_access(0)?;
            let (r, fflags) = Sf64::fle(cpu.read_f(f.rs1), cpu.read_f(f.rs2));
            if f.rd != 0 {
                cpu.write_x(f.rd, i64::from(r));
            }
            cpu.add_to_fflags(fflags);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0707f,
        data: 0xe2001053,
        name: "FCLASS.D",
        operation: |_address, word, cpu| {
            cpu.check_float_access(0)?;
            let f = parse_format_r(word);

            if f.rd != 0 {
                cpu.write_x(f.rd, 1 << Sf64::fclass(cpu.read_f(f.rs1)) as usize);
            }
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0007f,
        data: 0xc2000053,
        name: "FCVT.W.D",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_x(f.rd, i64::from(cpu.read_f64(f.rs1) as i32));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0007f, // XXX Suspect
        data: 0xc2100053, // XXX Suspect
        name: "FCVT.WU.D",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_x(f.rd, i64::from(cpu.read_f64(f.rs1) as u32));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0007f,
        data: 0xd2000053,
        name: "FCVT.D.W",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_f64(f.rd, f64::from(cpu.read_x(f.rs1) as i32));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0007f,
        data: 0xd2100053,
        name: "FCVT.D.WU",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_f64(f.rd, f64::from(cpu.read_x(f.rs1) as u32));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    // RV64D
    Instruction {
        mask: 0xfff0007f, // XXX Suspect
        data: 0xc2200053, // XXX Suspect
        name: "FCVT.L.D",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.check_float_access(f.funct3)?;
            if f.rd != 0 {
                cpu.write_x(f.rd, cpu.read_f64(f.rs1) as i64);
            }
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0007f,
        data: 0xc2300053,
        name: "FCVT.LU.D",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.check_float_access(f.funct3)?;
            if f.rd != 0 {
                cpu.write_x(f.rd, cpu.read_f64(f.rs1) as u64 as i64);
            }
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0707f,
        data: 0xe2000053,
        name: "FMV.X.D",
        operation: |_address, word, cpu| {
            cpu.check_float_access(0)?;
            let f = parse_format_r(word);
            cpu.write_x(f.rd, cpu.read_f(f.rs1));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0007f,
        data: 0xd2200053,
        name: "FCVT.D.L",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_f64(f.rd, cpu.read_x(f.rs1) as f64);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0007f,
        data: 0xd2300053,
        name: "FCVT.D.LU",
        operation: |_address, word, cpu| {
            let f = parse_format_r(word);
            cpu.check_float_access(f.funct3)?;
            cpu.write_f64(f.rd, cpu.read_x(f.rs1) as u64 as f64);
            Ok(())
        },
        disassemble: dump_format_r,
    },
    Instruction {
        mask: 0xfff0707f,
        data: 0xf2000053,
        name: "FMV.D.X",
        operation: |_address, word, cpu| {
            cpu.check_float_access(0)?;
            let f = parse_format_r(word);
            cpu.write_f(f.rd, cpu.read_x(f.rs1));
            Ok(())
        },
        disassemble: dump_format_r,
    },
    // Remaining (all system-level) that weren't listed in the instr-table
    Instruction {
        mask: 0xffffffff,
        data: 0x7b200073,
        name: "DRET",
        operation: |_cpu, _word, _address| {
            todo!("Handling dret requires handling all of debug mode")
        },
        disassemble: dump_empty,
    },
    Instruction {
        mask: 0xffffffff,
        data: 0x30200073,
        name: "MRET",
        operation: |_address, _word, cpu| {
            cpu.pc = cpu.read_csr(Csr::Mepc as u16)? as i64;
            let status = cpu.read_csr_raw(Csr::Mstatus);
            let mpie = (status >> 7) & 1;
            let mpp = (status >> 11) & 0x3;
            let mprv = match get_privilege_mode(mpp) {
                PrivilegeMode::Machine => (status >> 17) & 1,
                _ => 0,
            };
            // Override MIE[3] with MPIE[7], set MPIE[7] to 1, set MPP[12:11] to 0
            // and override MPRV[17]
            let new_status = (status & !0x21888) | (mprv << 17) | (mpie << 3) | (1 << 7);
            cpu.write_csr_raw(Csr::Mstatus, new_status);
            cpu.privilege_mode = match mpp {
                0 => PrivilegeMode::User,
                1 => PrivilegeMode::Supervisor,
                3 => PrivilegeMode::Machine,
                _ => panic!(), // Shouldn't happen
            };
            cpu.mmu.update_privilege_mode(cpu.privilege_mode);
            Ok(())
        },
        disassemble: dump_empty,
    },
    Instruction {
        mask: 0xffffffff,
        data: 0x10200073,
        name: "SRET",
        operation: |_address, word, cpu| {
            // @TODO: Throw error if higher privilege return instruction is executed

            if cpu.privilege_mode == PrivilegeMode::User
                || cpu.privilege_mode == PrivilegeMode::Supervisor
                    && cpu.csr[Csr::Mstatus as usize] & MSTATUS_TSR != 0
            {
                cpu.handle_exception(&Trap {
                    trap_type: TrapType::IllegalInstruction,
                    value: word as i64,
                });
                return Ok(());
            }

            cpu.pc = cpu.read_csr(Csr::Sepc as u16)? as i64;
            let status = cpu.read_csr_raw(Csr::Sstatus);
            let spie = (status >> 5) & 1;
            let spp = (status >> 8) & 1;
            let mprv = match get_privilege_mode(spp) {
                PrivilegeMode::Machine => (status >> 17) & 1,
                _ => 0,
            };
            // Override SIE[1] with SPIE[5], set SPIE[5] to 1, set SPP[8] to 0,
            // and override MPRV[17]
            let new_status = (status & !0x20122) | (mprv << 17) | (spie << 1) | (1 << 5);
            cpu.write_csr_raw(Csr::Sstatus, new_status);
            cpu.privilege_mode = match spp {
                0 => PrivilegeMode::User,
                1 => PrivilegeMode::Supervisor,
                _ => panic!(), // Shouldn't happen
            };
            cpu.mmu.update_privilege_mode(cpu.privilege_mode);
            Ok(())
        },
        disassemble: dump_empty,
    },
    Instruction {
        mask: 0xfe007fff,
        data: 0x12000073,
        name: "SFENCE.VMA",
        operation: |_address, word, cpu| {
            if cpu.privilege_mode == PrivilegeMode::User
                || cpu.privilege_mode == PrivilegeMode::Supervisor
                    && cpu.csr[Csr::Mstatus as usize] & MSTATUS_TVM != 0
            {
                cpu.handle_exception(&Trap {
                    trap_type: TrapType::IllegalInstruction,
                    value: word as i64,
                });
            } else {
                /*
                    if f.rs1 == 0 {
                    // tlb_flush_all(s);
                } else {
                    // tlb_flush_vaddr(s, read_reg(rs1));
                }
                     */

                /* the current code TLB may have been flushed */
            }
            Ok(())
        },
        disassemble: dump_empty,
    },
    Instruction {
        mask: 0xffffffff,
        data: 0x10500073,
        name: "WFI",
        operation: |_address, word, cpu| {
            /*
             * "When TW=1, if WFI is executed in S- mode, and it does
             * not complete within an implementation-specific, bounded
             * time limit, the WFI instruction causes an illegal
             * instruction trap."
             */
            if matches!(cpu.privilege_mode, PrivilegeMode::User)
                || matches!(cpu.privilege_mode, PrivilegeMode::Supervisor)
                    && cpu.read_csr_raw(Csr::Mstatus) & MSTATUS_TW != 0
            {
                cpu.handle_exception(&Trap {
                    trap_type: TrapType::IllegalInstruction,
                    value: word as i64,
                });
            } else {
                cpu.wfi = true;
            }
            Ok(())
        },
        disassemble: dump_empty,
    },
];

/// The number of results [`DecodeCache`](struct.DecodeCache.html) holds.
/// You need to carefully choose the number. Too small number causes
/// bad cache hit ratio. Too large number causes memory consumption
/// and host hardware CPU cache memory miss.
const DECODE_CACHE_ENTRY_NUM: usize = 0x1000;

const INVALID_CACHE_ENTRY: usize = INSTRUCTION_NUM;
const NULL_ENTRY: usize = DECODE_CACHE_ENTRY_NUM;

/// `DecodeCache` provides a cache system for instruction decoding.
/// It holds the recent [`DECODE_CACHE_ENTRY_NUM`](constant.DECODE_CACHE_ENTRY_NUM.html)
/// instruction decode results. If it has a cache (called "hit") for passed
/// word data, it returns decoding result very quickly. Decoding is one of the
/// slowest parts in CPU. This cache system improves the CPU processing speed
/// by skipping decoding. Especially it should work well for loop. It is said
/// that some loops in a program consume the majority of time then this cache
/// system is expected to reduce the decoding time very well.
///
/// This cache system is based on LRU algorithm, and consists of a hash map and
/// a linked list. Linked list is for LRU, front means recently used and back
/// means least recently used. A content in hash map points to an entry in the
/// linked list. This is the key to achieve computing in O(1).
///
// @TODO: Write performance benchmark test to confirm this cache actually
//        improves the speed.
struct DecodeCache {
    /// Holds mappings from word instruction data to an index of `entries`
    /// pointing to the entry having the decoding result. Containing the word
    /// means cache hit.
    hash_map: FnvHashMap<u32, usize>,

    /// Holds the entries [`DecodeCacheEntry`](struct.DecodeCacheEntry.html)
    /// forming linked list.
    entries: Vec<DecodeCacheEntry>,

    /// An index of `entries` pointing to the head entry in the linked list
    front_index: usize,

    /// An index of `entries` pointing to the tail entry in the linked list
    back_index: usize,

    /// Cache hit count for debugging purpose
    hit_count: u64,

    /// Cache miss count for debugging purpose
    miss_count: u64,
}

impl DecodeCache {
    /// Creates a new `DecodeCache`.
    fn new() -> Self {
        // Initialize linked list
        let mut entries = Vec::new();
        for i in 0..DECODE_CACHE_ENTRY_NUM {
            let next_index = if i == DECODE_CACHE_ENTRY_NUM - 1 {
                NULL_ENTRY
            } else {
                i + 1
            };
            let prev_index = if i == 0 { NULL_ENTRY } else { i - 1 };
            entries.push(DecodeCacheEntry::new(next_index, prev_index));
        }

        Self {
            hash_map: FnvHashMap::default(),
            entries,
            front_index: 0,
            back_index: DECODE_CACHE_ENTRY_NUM - 1,
            hit_count: 0,
            miss_count: 0,
        }
    }

    /// Gets the cached decoding result. If hits this method moves the
    /// cache entry to front of the linked list and returns an index of
    /// [`INSTRUCTIONS`](constant.INSTRUCTIONS.html).
    /// Otherwise returns `None`. This operation should compute in O(1) time.
    ///
    /// # Arguments
    /// * `word` word instruction data
    #[allow(clippy::cast_precision_loss)]
    fn get(&mut self, word: u32) -> Option<usize> {
        let result = if let Some(index) = self.hash_map.get(&word) {
            self.hit_count += 1;
            // Move the entry to front of the list unless it is at front.
            if self.front_index != *index {
                let next_index = self.entries[*index].next_index;
                let prev_index = self.entries[*index].prev_index;

                // Remove the entry from the list
                if self.back_index == *index {
                    self.back_index = prev_index;
                } else {
                    self.entries[next_index].prev_index = prev_index;
                }
                self.entries[prev_index].next_index = next_index;

                // Push the entry to front
                self.entries[*index].prev_index = NULL_ENTRY;
                self.entries[*index].next_index = self.front_index;
                self.entries[self.front_index].prev_index = *index;
                self.front_index = *index;
            }
            Some(self.entries[*index].instruction_index)
        } else {
            self.miss_count += 1;
            None
        };
        log::trace!(
            "hit:{}, miss:{}, ratio:{}",
            self.hit_count,
            self.miss_count,
            (self.hit_count as f64) / (self.hit_count + self.miss_count) as f64
        );
        result
    }

    /// Inserts a new decode result to front of the linked list while removing
    /// the least recently used result from the list. This operation should
    /// compute in O(1) time.
    ///
    /// # Arguments
    /// * `word`
    /// * `instruction_index`
    fn insert(&mut self, word: u32, instruction_index: usize) {
        let index = self.back_index;

        // Remove the least recently used entry. The entry resource
        // is reused as new entry.
        if self.entries[index].instruction_index != INVALID_CACHE_ENTRY {
            self.hash_map.remove(&self.entries[index].word);
        }
        self.back_index = self.entries[index].prev_index;
        self.entries[self.back_index].next_index = NULL_ENTRY;

        // Push the new entry to front of the linked list
        self.hash_map.insert(word, index);
        self.entries[index].prev_index = NULL_ENTRY;
        self.entries[index].next_index = self.front_index;
        self.entries[index].word = word;
        self.entries[index].instruction_index = instruction_index;
        self.entries[self.front_index].prev_index = index;
        self.front_index = index;
    }
}

/// An entry of linked list managed by [`DecodeCache`](struct.DecodeCache.html).
/// An entry consists of a mapping from word instruction data to an index of
/// [`INSTRUCTIONS`](constant.INSTRUCTIONS.html) and next/previous entry index
/// in the linked list.
struct DecodeCacheEntry {
    /// Instruction word data
    word: u32,

    /// The result of decoding `word`. An index of [`INSTRUCTIONS`](constant.INSTRUCTIONS.html).
    instruction_index: usize,

    /// Next entry index in the linked list. [`NULL_ENTRY`](constant.NULL_ENTRY.html)
    /// represents no next entry, meaning the entry is at tail.
    next_index: usize,

    /// Previous entry index in the linked list. [`NULL_ENTRY`](constant.NULL_ENTRY.html)
    /// represents no previous entry, meaning the entry is at head.
    prev_index: usize,
}

impl DecodeCacheEntry {
    /// Creates a new entry. Initial `instruction_index` is
    /// `INVALID_CACHE_ENTRY` meaning the entry is invalid.
    ///
    /// # Arguments
    /// * `next_index`
    /// * `prev_index`
    const fn new(next_index: usize, prev_index: usize) -> Self {
        Self {
            word: 0,
            instruction_index: INVALID_CACHE_ENTRY,
            next_index,
            prev_index,
        }
    }
}

#[cfg(test)]
mod test_cpu {
    use super::*;
    use crate::mmu::DRAM_BASE;
    use crate::terminal::DummyTerminal;

    fn create_cpu() -> Cpu {
        Cpu::new(Box::new(DummyTerminal::new()))
    }

    #[test]
    fn initialize() {
        let _cpu = create_cpu();
    }

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
    #[allow(clippy::match_wild_err_arm)]
    fn tick() {
        let mut cpu = create_cpu();
        cpu.get_mut_mmu().init_memory(8);
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
        assert_eq!(1, cpu.read_register(1));

        cpu.run_soc(1);

        assert_eq!(DRAM_BASE as i64 + 6, cpu.read_pc());
        assert_eq!(8, cpu.read_register(8));
    }

    #[test]
    #[allow(clippy::match_wild_err_arm)]
    fn run_cpu_tick() {
        let mut cpu = create_cpu();
        cpu.get_mut_mmu().init_memory(4);
        cpu.update_pc(DRAM_BASE as i64);
        // write non-compressed "addi a0, a0, 12" instruction
        match cpu.get_mut_mmu().store_virt_u32(DRAM_BASE, 0xc50513) {
            Ok(()) => {}
            Err(_e) => panic!("Failed to store"),
        }
        assert_eq!(DRAM_BASE as i64, cpu.read_pc());
        assert_eq!(0, cpu.read_register(10));
        cpu.run_cpu_tick();
        /*
            should test for handing paniced
            {
            match
            Ok(()) => {}
            Err(_e) => panic!("run_cpu_tick() unexpectedly did panic"),
        }
        */
        // .run_cpu_tick() increments the program counter by 4 for
        // non-compressed instruction.
        assert_eq!(DRAM_BASE as i64 + 4, cpu.read_pc());
        // "addi a0, a0, a12" instruction writes 12 to a0 register.
        assert_eq!(12, cpu.read_register(10));
        // @TODO: Test compressed instruction operation
    }

    #[test]
    #[allow(clippy::match_wild_err_arm)]
    fn decode() {
        let mut cpu = create_cpu();
        // 0x13 is addi instruction
        match cpu.decode(0x13) {
            Ok(inst) => assert_eq!(inst.name, "ADDI"),
            Err(_e) => panic!("Failed to decode"),
        }
        // .decode() returns error for invalid word data.
        assert!(
            cpu.decode(0x0).is_err(),
            "Unexpectedly succeeded in decoding"
        );
        // @TODO: Should I test all instructions?
    }

    #[test]
    #[allow(clippy::match_wild_err_arm)]
    fn test_decompress() {
        let mut cpu = create_cpu();
        // .decompress() doesn't directly return an instruction but
        // it returns decompressed word. Then you need to call .decode().
        match cpu.decode(decompress(0, 0x20).0) {
            Ok(inst) => assert_eq!(inst.name, "ADDI"),
            Err(_e) => panic!("Failed to decode"),
        }
        // @TODO: Should I test all compressed instructions?
    }

    #[test]
    #[allow(clippy::match_wild_err_arm)]
    fn wfi() {
        let wfi_instruction = 0x10500073;
        let mut cpu = create_cpu();
        // Just in case
        match cpu.decode(wfi_instruction) {
            Ok(inst) => assert_eq!(inst.name, "WFI"),
            Err(_e) => panic!("Failed to decode"),
        }
        cpu.get_mut_mmu().init_memory(4);
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
            // @TODO: Check accurately that the state is unchanged
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
        cpu.get_mut_mmu().init_memory(4);
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
        cpu.get_mut_mmu().init_memory(4);
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
        cpu.get_mut_mmu().init_memory(8);
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
        assert_eq!(0, cpu.read_register(0));
        cpu.run_soc(1); // Execute  "addi x0, x0, 1"
        // x0 is still zero because it's hardcoded zero
        assert_eq!(0, cpu.read_register(0));

        // Test x1
        assert_eq!(0, cpu.read_register(1));
        cpu.run_soc(1); // Execute  "addi x1, x1, 1"
        // x1 is not hardcoded zero
        assert_eq!(1, cpu.read_register(1));
    }
}

#[cfg(test)]
mod test_decode_cache {
    use super::*;

    #[test]
    fn initialize() {
        let _cache = DecodeCache::new();
    }

    #[test]
    fn insert() {
        let mut cache = DecodeCache::new();
        cache.insert(0, 0);
    }

    #[test]
    fn get() {
        let mut cache = DecodeCache::new();
        cache.insert(1, 2);

        // Cache hit test
        match cache.get(1) {
            Some(index) => assert_eq!(2, index),
            None => panic!("Unexpected cache miss"),
        }

        // Cache miss test
        if let Some(_index) = cache.get(2) {
            panic!("Unexpected cache hit")
        }
    }

    #[test]
    #[allow(clippy::match_wild_err_arm, clippy::cast_possible_truncation)]
    fn lru() {
        let mut cache = DecodeCache::new();
        cache.insert(0, 1);

        match cache.get(0) {
            Some(index) => assert_eq!(1, index),
            None => panic!("Unexpected cache miss"),
        }

        for i in 1..=DECODE_CACHE_ENTRY_NUM {
            cache.insert(i as u32, i + 1);
        }

        // The oldest entry should have been removed because of the overflow
        if let Some(_index) = cache.get(0) {
            panic!("Unexpected cache hit")
        }

        // With this .get(), the entry with the word "1" moves to the tail of the list
        // and the entry with the word "2" becomes the oldest entry.
        if let Some(index) = cache.get(1) {
            assert_eq!(2, index);
        }

        // The oldest entry with the word "2" will be removed due to the overflow
        cache.insert(
            DECODE_CACHE_ENTRY_NUM as u32 + 1,
            DECODE_CACHE_ENTRY_NUM + 2,
        );

        if let Some(_index) = cache.get(2) {
            panic!("Unexpected cache hit")
        }
    }
}
