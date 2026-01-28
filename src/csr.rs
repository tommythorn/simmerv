use num_derive::FromPrimitive;
use std::fmt::Display;
use std::fmt::Formatter;

#[derive(FromPrimitive, Debug, Clone, Copy)]
pub enum Csr {
    Ustatus = 0x000,
    Fflags = 0x001,
    Frm = 0x002,
    Fcsr = 0x003,
    Uie = 0x004,
    Utvec = 0x005,
    Uscratch = 0x040,
    Uepc = 0x041,
    Ucause = 0x042,
    Utval = 0x043,
    Uip = 0x044,
    Sstatus = 0x100,
    Sedeleg = 0x102,
    Sideleg = 0x103,
    Scounteren = 0x106,
    Sie = 0x104,
    Stvec = 0x105,
    Sscratch = 0x140,
    Sepc = 0x141,
    Scause = 0x142,
    Stval = 0x143,
    Sip = 0x144,
    Satp = 0x180,

    Mstatus = 0x300,
    Misa = 0x301,
    Medeleg = 0x302,
    Mideleg = 0x303,
    Mie = 0x304,
    Mtvec = 0x305,
    Csr306 = 0x306,
    Menvcfg = 0x30a, // Unsupported Mostly Just Configure S Access To Timecmp
    Mscratch = 0x340,
    Mepc = 0x341,
    Mcause = 0x342,
    Mtval = 0x343,
    Mip = 0x344,
    Pmpcfg0 = 0x3a0,
    Pmpaddr0 = 0x3b0,
    Mcycle = 0xb00,
    Minstret = 0xb02,
    Cycle = 0xc00,
    Time = 0xc01,
    Instret = 0xc02,
    Mhartid = 0xf14,
    Mimpid = 0xf13,
    Marchid = 0xf12,
    Mvendorid = 0xf11,
    Mtopi = 0xfb0,   // Unsupported Highest Priority Pending And Enabled Interrupt
    Tselect = 0x7a0, // UNSUPPORTED Debug/Trace trigger register select
}

impl Display for Csr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // XXX First approximation, will improve later
        write!(f, "{self:?}")
    }
}

pub const MIP_MEIP: u64 = 0x800;
pub const MIP_MTIP: u64 = 0x080;
pub const MIP_MSIP: u64 = 0x008;
pub const MIP_SEIP: u64 = 0x200;
pub const MIP_STIP: u64 = 0x020;
pub const MIP_SSIP: u64 = 0x002;

// XXX Surely we can find a better way to handle the bitfields
pub const MSTATUS_SPIE_SHIFT: u64 = 5;
pub const MSTATUS_MPIE_SHIFT: u64 = 7;
pub const MSTATUS_SPP_SHIFT: u64 = 8;
pub const MSTATUS_VS_SHIFT: u64 = 9;
pub const MSTATUS_MPP_SHIFT: u64 = 11;
pub const MSTATUS_FS_SHIFT: u64 = 13;
pub const MSTATUS_UXL_SHIFT: u64 = 32;
pub const MSTATUS_SXL_SHIFT: u64 = 34;

pub const MSTATUS_UIE: u64 = 1 << 0;
pub const MSTATUS_SIE: u64 = 1 << 1;
pub const MSTATUS_HIE: u64 = 1 << 2;
pub const MSTATUS_MIE: u64 = 1 << 3;
pub const MSTATUS_UPIE: u64 = 1 << 4;
pub const MSTATUS_SPIE: u64 = 1 << MSTATUS_SPIE_SHIFT;
pub const MSTATUS_HPIE: u64 = 1 << 6;
pub const MSTATUS_MPIE: u64 = 1 << MSTATUS_MPIE_SHIFT;
pub const MSTATUS_SPP: u64 = 1 << MSTATUS_SPP_SHIFT;
pub const MSTATUS_VS: u64 = 3 << MSTATUS_VS_SHIFT;
pub const MSTATUS_MPP: u64 = 3 << MSTATUS_MPP_SHIFT;
pub const MSTATUS_FS: u64 = 3 << MSTATUS_FS_SHIFT;
pub const MSTATUS_XS: u64 = 3 << 15;
pub const MSTATUS_MPRV: u64 = 1 << 17;
pub const MSTATUS_SUM: u64 = 1 << 18;
pub const MSTATUS_MXR: u64 = 1 << 19;
pub const MSTATUS_TVM: u64 = 1 << 20;
pub const MSTATUS_TW: u64 = 1 << 21;
pub const MSTATUS_TSR: u64 = 1 << 22;
pub const MSTATUS_UXL_MASK: u64 = 3 << MSTATUS_UXL_SHIFT;
pub const MSTATUS_SXL_MASK: u64 = 3 << MSTATUS_SXL_SHIFT;

// MSTATUS_MASK are the only fields that are directly writable with an csr
// instruction
pub const MSTATUS_MASK: u64 = MSTATUS_SIE
    | MSTATUS_MIE
    | MSTATUS_SPIE
    | MSTATUS_MPIE
    | MSTATUS_SPP
    | MSTATUS_MPP
    | MSTATUS_VS  // XXX
    | MSTATUS_FS
    | MSTATUS_MPRV
    | MSTATUS_SUM
    | MSTATUS_MXR
    | MSTATUS_TVM
    | MSTATUS_TW
    | MSTATUS_TSR
    | MSTATUS_UXL_MASK  // XXX
    | MSTATUS_SXL_MASK; // XXX

pub const SATP_PPN_SHIFT: u64 = 0;
pub const SATP_ASID_SHIFT: u64 = 44;
pub const SATP_MODE_SHIFT: u64 = 60;
pub const SATP_PPN_MASK: u64 = (1 << SATP_ASID_SHIFT) - 1;
pub const SATP_ASID_MASK: u64 = (1 << (SATP_MODE_SHIFT - SATP_ASID_SHIFT)) - 1;
pub const SATP_MODE_MASK: u64 = (1 << (64 - SATP_MODE_SHIFT)) - 1;

#[derive(FromPrimitive, Debug, Clone, Copy)]
pub enum SatpMode {
    Bare = 0,
    Sv39 = 8,
    Sv48 = 9,
    Sv57 = 10,
    Sv64 = 11,
}

#[must_use]
pub const fn legal(csr: Csr) -> bool {
    matches!(
        csr,
        Csr::Cycle
            | Csr::Fcsr
            | Csr::Fflags
            | Csr::Frm
            | Csr::Instret
            | Csr::Marchid
            | Csr::Mcause
            | Csr::Mcycle
            | Csr::Minstret
            | Csr::Medeleg
            | Csr::Mepc
            | Csr::Mhartid
            | Csr::Mideleg
            | Csr::Mie
            | Csr::Mimpid
            | Csr::Mip
            | Csr::Misa
            | Csr::Mscratch
            | Csr::Mstatus
            | Csr::Mtval
            | Csr::Mtvec
            | Csr::Mvendorid
            | Csr::Satp
            | Csr::Scause
            | Csr::Sedeleg
            | Csr::Sepc
            | Csr::Sideleg
            | Csr::Scounteren
            | Csr::Sie
            | Csr::Sip
            | Csr::Sscratch
            | Csr::Sstatus
            | Csr::Stval
            | Csr::Stvec
            | Csr::Time
            | Csr::Ucause
            | Csr::Uepc
            | Csr::Uie
            | Csr::Uip
            | Csr::Uscratch
            | Csr::Ustatus
            | Csr::Utval
            | Csr::Utvec
            | Csr::Csr306
    )
}
