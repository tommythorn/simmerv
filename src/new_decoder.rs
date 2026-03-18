#![allow(
    clippy::cast_lossless,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::useless_format
)]

use crate::bounded::Bounded;
use crate::cpu::Uop;
use crate::generated_riscv_decoder::Op;
use crate::riscv_decoding::RiscvDecoder;

pub type Reg = Bounded<65>;
pub const ZEROREG: Reg = Reg::new(0);
pub const NODESTREG: Reg = Reg::new(64);

impl Reg {
    #[must_use]
    pub const fn is_x0_dest(self) -> bool { self.get() == 64 }
}

impl std::fmt::Display for Reg {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}",
            [
                "x0", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3",
                "a4", "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10",
                "s11", "t3", "t4", "t5", "t6", "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7",
                "f8", "f9", "f10", "f11", "f12", "f13", "f14", "f15", "f16", "f17", "f18", "f19",
                "f20", "f21", "f22", "f23", "f24", "f25", "f26", "f27", "f28", "f29", "f30", "f31",
                "",
            ][self.get() as usize]
        )
    }
}

fn decode_ci(_a: u64, insn: u32, op: Op) -> Uop {
    // CI-format compressed instructions (e.g. C.ADDI)
    let r = (insn >> 7) & 31; // [11:7]
    let raw_imm = (((insn >> 7) & 0x20) | ((insn >> 2) & 31)) as i32; // 6-bit imm
    let imm = i64::from((raw_imm << 26) >> 26) as u64; // sign-extend 6-bit to 64-bit

    Uop {
        op,
        rd: xd(r),
        rs1: x(r),
        imm,
        ..Uop::default()
    }
}

fn decode_cb(a: u64, insn: u32, op: Op) -> Uop {
    // CB-format compressed instructions, C.BEQZ and C.BNEZ
    let r = (insn >> 7) & 7;
    let offset = (u32::from((insn & 0x1000) != 0) * 0xffff_fe00)
        | ((insn >> 4) & 0x100)
        | ((insn >> 7) & 0x18)
        | ((insn << 1) & 0xc0)
        | ((insn >> 2) & 6)
        | ((insn << 3) & 0x20);

    let imm2 = ((offset >> 6) & 0x40) | ((offset >> 5) & 0x3f);
    let imm1 = (offset & 0x1e) | ((offset >> 11) & 1);
    let insn32 = (imm2 << 25) | ((r + 8) << 15) | (imm1 << 7) | 0x63;

    let iword = insn32 as i32;
    let imm = a.wrapping_add(
        (iword >> 31 << 12
            | ((iword << 4) & 0x800)
            | ((iword >> 20) & 0x7e0)
            | ((iword >> 7) & 0x1e)) as u64,
    );

    Uop {
        op,
        rs1: x(r + 8),
        rs2: x(0),
        imm,
        ..Uop::default()
    }
}

fn decode_ci_shift(_a: u64, insn: u32, op: Op) -> Uop {
    let rd_rs1 = ((insn >> 7) & 7) + 8;
    let imm = ((insn >> 2) & 31) | (((insn >> 12) & 1) << 5);
    Uop {
        op,
        rd: xd(rd_rs1),
        rs1: x(rd_rs1),
        imm: imm as u64,
        ..Uop::default()
    }
}

fn decode_ca(_a: u64, insn: u32, op: Op) -> Uop {
    let rs1 = (insn >> 7) & 7;
    let rs2 = (insn >> 2) & 7;
    Uop {
        op,
        rd: xd(rs1 + 8),
        rs1: x(rs1 + 8),
        rs2: x(rs2 + 8),
        ..Uop::default()
    }
}

const fn sign_extend(value: u32, bits: u32) -> i32 {
    let shift = 32 - bits;
    (value as i32) << shift >> shift
}

pub struct Decoder {}

impl RiscvDecoder for Decoder {
    type Context = Self;
    type Returns = Uop;

    fn c_unimp(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_exceptional(a, insn, Op::CUnimp)
    }
    fn c_addi4spn(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        // C.ADDI4SPN
        let rd = ((insn >> 2) & 7) + 8;
        // imm[5:4|9:6|2|3] from insn[12:11|10:7|6|5]
        let imm = (((insn >> 11) & 3) << 4)
            | (((insn >> 7) & 15) << 6)
            | (((insn >> 6) & 1) << 2)
            | (((insn >> 5) & 1) << 3);

        if imm == 0 {
            return decode_exceptional(a, insn, Op::CUnimp); // imm=0 is reserved/illegal
        }
        Uop {
            op: Op::CAddi4spn,
            rd: xd(rd),
            rs1: x(2), // base is sp
            imm: imm as u64,
            ..Uop::default()
        }
    }

    fn c_fld(_a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        let rd = ((insn >> 2) & 7) + 8;
        let rs1 = ((insn >> 7) & 7) + 8;
        let imm = (((insn >> 5) & 3) << 6) | (((insn >> 10) & 7) << 3);

        Uop {
            op: Op::CFld,
            rd: f(rd),
            rs1: x(rs1),
            imm: imm as u64,
            ..Uop::default()
        }
    }

    fn c_fldsp(_a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        let rd = (insn >> 7) & 31;
        let imm = (((insn >> 2) & 7) << 6) | (((insn >> 5) & 3) << 3) | (((insn >> 12) & 1) << 5);
        Uop {
            op: Op::CFldsp,
            rd: f(rd),
            rs1: x(2),
            imm: imm as u64,
            ..Uop::default()
        }
    }

    fn c_lw(_a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        let rd = xd(((insn >> 2) & 7) + 8);
        let rs1 = x(((insn >> 7) & 7) + 8);
        let imm = (((insn >> 5) & 1) << 6) | (((insn >> 6) & 1) << 2) | (((insn >> 10) & 7) << 3);
        Uop {
            op: Op::CLw,
            rd,
            rs1,
            imm: imm as u64,
            ..Uop::default()
        }
    }

    fn c_ld(_a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        let rd = xd(((insn >> 2) & 7) + 8);
        let rs1 = x(((insn >> 7) & 7) + 8);
        let imm = (((insn >> 5) & 3) << 6) | (((insn >> 10) & 7) << 3);
        Uop {
            op: Op::CLd,
            rd,
            rs1,
            imm: imm as u64,
            ..Uop::default()
        }
    }

    fn c_fsd(_a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        let rs2 = ((insn >> 2) & 7) + 8;
        let rs1 = ((insn >> 7) & 7) + 8;
        let imm = (((insn >> 5) & 3) << 6) | (((insn >> 10) & 7) << 3);
        Uop {
            op: Op::CFsd,
            rs1: x(rs1),
            rs2: f(rs2),
            imm: imm as u64,
            ..Uop::default()
        }
    }

    fn c_sw(_a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        let rs2 = ((insn >> 2) & 7) + 8;
        let rs1 = ((insn >> 7) & 7) + 8;
        let imm = (((insn >> 5) & 1) << 6) | (((insn >> 6) & 1) << 2) | (((insn >> 10) & 7) << 3);
        Uop {
            op: Op::CSw,
            rs1: x(rs1),
            rs2: x(rs2),
            imm: imm as u64,
            ..Uop::default()
        }
    }

    fn c_sd(_a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        let rs2 = ((insn >> 2) & 7) + 8;
        let rs1 = ((insn >> 7) & 7) + 8;
        let imm = (((insn >> 5) & 3) << 6) | (((insn >> 10) & 7) << 3);
        Uop {
            op: Op::CSd,
            rs1: x(rs1),
            rs2: x(rs2),
            imm: imm as u64,
            ..Uop::default()
        }
    }

    fn c_nop(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_ci(a, insn, Op::CNop) }
    fn c_addi(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_ci(a, insn, Op::CAddi) }
    fn c_addiw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        if insn & (31 << 7) == 0 {
            // C.ADDIW is valid only when rd ≠ 0
            return decode_exceptional(a, insn, Op::CUnimp);
        }
        decode_ci(a, insn, Op::CAddiw)
    }
    fn c_li(_a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        let rd = (insn >> 7) & 31;
        let imm = ((insn >> 2) & 31) | (((insn >> 12) & 1) << 5);
        let imm = sign_extend(imm, 6) as u64;
        Uop {
            op: Op::CLi,
            rd: xd(rd),
            imm,
            ..Uop::default()
        }
    }

    fn c_addi16sp(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        let imm = (((insn >> 2) & 1) << 5)
            | (((insn >> 3) & 3) << 7)
            | (((insn >> 5) & 1) << 6)
            | (((insn >> 6) & 1) << 4)
            | (((insn >> 12) & 1) << 9);
        let imm = sign_extend(imm, 10);
        if imm == 0 {
            return decode_exceptional(a, insn, Op::CUnimp);
        }
        Uop {
            op: Op::CAddi16sp,
            rd: xd(2), // sp is x2
            rs1: x(2),
            imm: imm as u64,
            ..Uop::default()
        }
    }

    fn c_lui(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        let rd = (insn >> 7) & 31;
        let imm = ((insn >> 2) & 31) | (((insn >> 12) & 1) << 5);
        let imm = sign_extend(imm, 6) << 12;
        if rd == 2 || imm == 0 {
            // Note, rd = x0 isn't a valid c.lui, but a hint
            return decode_exceptional(a, insn, Op::CUnimp);
        }
        Uop {
            op: Op::CLui,
            rd: xd(rd),
            imm: imm as u64,
            ..Uop::default()
        }
    }

    fn c_srli(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_ci_shift(a, insn, Op::CSrli)
    }
    fn c_srai(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_ci_shift(a, insn, Op::CSrai)
    }
    fn c_andi(_a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        let r = (insn >> 7) & 7;
        let imm = ((insn >> 7) & 0x20) | ((insn >> 2) & 31);
        Uop {
            op: Op::CAndi,
            rd: xd(r + 8),
            rs1: x(r + 8),
            imm: sign_extend(imm, 6) as u64,
            ..Uop::default()
        }
    }
    fn c_sub(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_ca(a, insn, Op::CSub) }
    fn c_xor(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_ca(a, insn, Op::CXor) }
    fn c_or(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_ca(a, insn, Op::COr) }
    fn c_and(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_ca(a, insn, Op::CAnd) }
    fn c_subw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_ca(a, insn, Op::CSubw) }
    fn c_addw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_ca(a, insn, Op::CAddw) }

    fn c_j(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        let imm = (((insn >> 2) & 1) << 5)
            | (((insn >> 3) & 7) << 1)
            | (((insn >> 6) & 1) << 7)
            | (((insn >> 7) & 1) << 6)
            | (((insn >> 8) & 1) << 10)
            | (((insn >> 9) & 3) << 8)
            | (((insn >> 11) & 1) << 4)
            | (((insn >> 12) & 1) << 11);
        let imm = sign_extend(imm, 12);
        Uop {
            op: Op::CJ,
            imm: a.wrapping_add(imm as u64),
            ..Uop::default()
        }
    }

    fn c_beqz(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_cb(a, insn, Op::CBeqz) }
    fn c_bnez(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_cb(a, insn, Op::CBnez) }
    fn c_slli(_a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        let rd = (insn >> 7) & 31;
        let imm = ((insn >> 2) & 31) | (((insn >> 12) & 1) << 5);
        // if rd == 0 {return decode_exceptional(a, insn, Op::CUnimp);}
        // XXX As far as I read the spec 0x0002 is an illegal instruction.  TBD!
        Uop {
            op: Op::CSlli,
            rd: xd(rd),
            rs1: x(rd),
            imm: imm as u64,
            ..Uop::default()
        }
    }

    fn c_lwsp(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        let rd = (insn >> 7) & 31;
        let imm = (((insn >> 2) & 3) << 6) | (((insn >> 4) & 7) << 2) | (((insn >> 12) & 1) << 5);
        if rd == 0 {
            // C.LWSP is valid only when rd ≠ 0
            return decode_exceptional(a, insn, Op::CUnimp);
        }

        Uop {
            op: Op::CLwsp,
            rd: xd(rd),
            rs1: x(2),
            imm: imm as u64,
            ..Uop::default()
        }
    }
    fn c_ldsp(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        let rd = (insn >> 7) & 31;

        let imm = (((insn >> 2) & 7) << 6) | (((insn >> 5) & 3) << 3) | (((insn >> 12) & 1) << 5);

        if rd == 0 {
            // C.LDSP is valid only when rd ≠ 0
            return decode_exceptional(a, insn, Op::CUnimp);
        }

        Uop {
            op: Op::CLdsp,
            rd: xd(rd),
            rs1: x(2),
            rs2: x(0),
            imm: imm as u64,
            ..Uop::default()
        }
    }

    fn c_jr(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        let rs1 = (insn >> 7) & 31;
        let rs2 = (insn >> 2) & 31;
        let funct1 = (insn >> 12) & 1;

        debug_assert_eq!(funct1, 0);
        debug_assert_eq!(rs2, 0);

        if rs1 == 0 {
            return decode_exceptional(a, insn, Op::CUnimp);
        }
        Uop {
            op: Op::CJr,
            rs1: x(rs1),
            ..Uop::default()
        }
    }

    fn c_jalr(_a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        let rs1 = (insn >> 7) & 31;
        let rs2 = (insn >> 2) & 31;
        let funct1 = (insn >> 12) & 1;

        debug_assert_eq!(funct1, 1);
        debug_assert_eq!(rs2, 0);
        debug_assert_ne!(rs1, 0);
        Uop {
            op: Op::CJalr,
            rd: xd(1),
            rs1: x(rs1),
            ..Uop::default()
        }
    }

    fn c_mv(_a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        let rd = (insn >> 7) & 31;
        let rs2 = (insn >> 2) & 31;
        Uop {
            op: Op::CMv,
            rd: xd(rd),
            rs1: x(0),
            rs2: x(rs2),
            ..Uop::default()
        }
    }

    fn c_ebreak(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_exceptional(a, insn, Op::CEbreak)
    }

    fn c_add(_a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        let rs1 = (insn >> 7) & 31;
        let rs2 = (insn >> 2) & 31;

        Uop {
            op: Op::CAdd,
            rd: xd(rs1),
            rs1: x(rs1),
            rs2: x(rs2),
            ..Uop::default()
        }
    }

    fn c_fsdsp(_a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        let rs2 = (insn >> 2) & 31;
        let imm = (((insn >> 7) & 7) << 6) | (((insn >> 10) & 7) << 3);
        Uop {
            op: Op::CFsdsp,
            rs1: x(2),
            rs2: f(rs2),
            imm: imm as u64,
            ..Uop::default()
        }
    }

    fn c_swsp(_a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        let rs2 = (insn >> 2) & 31;
        let imm = (((insn >> 7) & 3) << 6) | (((insn >> 9) & 0xF) << 2);
        Uop {
            op: Op::CSwsp,
            rs1: x(2),
            rs2: x(rs2),
            imm: imm as u64,
            ..Uop::default()
        }
    }

    fn c_sdsp(_a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        let rs2 = (insn >> 2) & 31;
        let imm = (((insn >> 7) & 7) << 6) | (((insn >> 10) & 7) << 3);
        Uop {
            op: Op::CSdsp,
            rs1: x(2),
            rs2: x(rs2),
            imm: imm as u64,
            ..Uop::default()
        }
    }

    fn lui(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_u(a, insn, Op::Lui) }
    fn auipc(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_auipc(a, insn, Op::Auipc) }
    fn jal(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_j(a, insn, Op::Jal) }
    fn jalr(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_i(a, insn, Op::Jalr) }
    fn beq(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_b(a, insn, Op::Beq) }
    fn bne(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_b(a, insn, Op::Bne) }
    fn blt(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_b(a, insn, Op::Blt) }
    fn bge(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_b(a, insn, Op::Bge) }
    fn bltu(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_b(a, insn, Op::Bltu) }
    fn bgeu(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_b(a, insn, Op::Bgeu) }
    fn lb(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_i(a, insn, Op::Lb) }
    fn lh(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_i(a, insn, Op::Lh) }
    fn lw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_i(a, insn, Op::Lw) }
    fn lbu(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_i(a, insn, Op::Lbu) }
    fn lhu(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_i(a, insn, Op::Lhu) }
    fn sb(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_s(a, insn, Op::Sb) }
    fn sh(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_s(a, insn, Op::Sh) }
    fn sw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_s(a, insn, Op::Sw) }
    fn addi(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_i(a, insn, Op::Addi) }
    fn slti(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_i(a, insn, Op::Slti) }
    fn sltiu(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_i(a, insn, Op::Sltiu) }
    fn xori(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_i(a, insn, Op::Xori) }
    fn ori(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_i(a, insn, Op::Ori) }
    fn andi(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_i(a, insn, Op::Andi) }
    fn add(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Add) }
    fn sub(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Sub) }
    fn sll(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Sll) }
    fn slt(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Slt) }
    fn sltu(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Sltu) }
    fn xor(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Xor) }
    fn srl(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Srl) }
    fn sra(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Sra) }
    fn or(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Or) }
    fn and(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::And) }
    fn fence(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_serialized(a, insn, Op::Fence)
    }
    fn fence_tso(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_serialized(a, insn, Op::FenceTso)
    }
    fn ecall(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_exceptional(a, insn, Op::Ecall)
    }
    fn ebreak(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_exceptional(a, insn, Op::Ebreak)
    }
    fn lwu(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_i(a, insn, Op::Lwu) }
    fn ld(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_i(a, insn, Op::Ld) }
    fn sd(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_s(a, insn, Op::Sd) }
    fn slli(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r_shift(a, insn, Op::Slli) }
    fn srli(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r_shift(a, insn, Op::Srli) }
    fn srai(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r_shift(a, insn, Op::Srai) }
    fn addiw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_i(a, insn, Op::Addiw) }
    fn slliw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_shift(a, insn, Op::Slliw)
    }
    fn srliw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_shift(a, insn, Op::Srliw)
    }
    fn sraiw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_shift(a, insn, Op::Sraiw)
    }
    fn addw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Addw) }
    fn subw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Subw) }
    fn sllw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Sllw) }
    fn srlw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Srlw) }
    fn sraw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Sraw) }
    fn fence_i(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_empty(a, insn, Op::FenceI)
    }
    fn csrrw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_csr(a, insn, Op::Csrrw) }
    fn csrrs(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_csr(a, insn, Op::Csrrs) }
    fn csrrc(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_csr(a, insn, Op::Csrrc) }
    fn csrrwi(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_csri(a, insn, Op::Csrrwi) }
    fn csrrsi(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_csri(a, insn, Op::Csrrsi) }
    fn csrrci(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_csri(a, insn, Op::Csrrci) }
    fn mul(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Mul) }
    fn mulh(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Mulh) }
    fn mulhsu(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Mulhsu) }
    fn mulhu(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Mulhu) }
    fn div(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Div) }
    fn divu(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Divu) }
    fn rem(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Rem) }
    fn remu(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Remu) }
    fn mulw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Mulw) }
    fn divw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Divw) }
    fn divuw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Divuw) }
    fn remw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Remw) }
    fn remuw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Remuw) }
    fn lr_w(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::LrW) }
    fn sc_w(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::ScW) }
    fn amoswap_w(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r(a, insn, Op::AmoswapW)
    }
    fn amoadd_w(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::AmoaddW) }
    fn amoxor_w(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::AmoxorW) }
    fn amoand_w(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::AmoandW) }
    fn amoor_w(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::AmoorW) }
    fn amomin_w(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::AmominW) }
    fn amomax_w(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::AmomaxW) }
    fn amominu_w(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r(a, insn, Op::AmominuW)
    }
    fn amomaxu_w(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r(a, insn, Op::AmomaxuW)
    }
    fn lr_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::LrD) }
    fn sc_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::ScD) }
    fn amoswap_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r(a, insn, Op::AmoswapD)
    }
    fn amoadd_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::AmoaddD) }
    fn amoxor_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::AmoxorD) }
    fn amoand_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::AmoandD) }
    fn amoor_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::AmoorD) }
    fn amomin_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::AmominD) }
    fn amomax_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::AmomaxD) }
    fn amominu_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r(a, insn, Op::AmominuD)
    }
    fn amomaxu_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r(a, insn, Op::AmomaxuD)
    }
    fn flw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_i_fx(a, insn, Op::Flw) }
    fn fsw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_s_xf(a, insn, Op::Fsw) }
    fn fmadd_s(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r2_ffff(a, insn, Op::FmaddS)
    }
    fn fmsub_s(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r2_ffff(a, insn, Op::FmsubS)
    }
    fn fnmsub_s(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r2_ffff(a, insn, Op::FnmsubS)
    }
    fn fnmadd_s(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r2_ffff(a, insn, Op::FnmaddS)
    }
    fn fadd_s(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r_fff(a, insn, Op::FaddS) }
    fn fsub_s(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r_fff(a, insn, Op::FsubS) }
    fn fmul_s(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r_fff(a, insn, Op::FmulS) }
    fn fdiv_s(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r_fff(a, insn, Op::FdivS) }
    fn fsqrt_s(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_fff(a, insn, Op::FsqrtS)
    }
    fn fsgnj_s(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_fff(a, insn, Op::FsgnjS)
    }
    fn fsgnjn_s(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_fff(a, insn, Op::FsgnjnS)
    }
    fn fsgnjx_s(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_fff(a, insn, Op::FsgnjxS)
    }
    fn fmin_s(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r_fff(a, insn, Op::FminS) }
    fn fmax_s(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r_fff(a, insn, Op::FmaxS) }
    fn fcvt_w_s(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_xf(a, insn, Op::FcvtWS)
    }
    fn fcvt_wu_s(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_xf(a, insn, Op::FcvtWuS)
    }
    fn fmv_x_w(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r_xf(a, insn, Op::FmvXW) }
    fn feq_s(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r_xff(a, insn, Op::FeqS) }
    fn flt_s(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r_xff(a, insn, Op::FltS) }
    fn fle_s(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r_xff(a, insn, Op::FleS) }
    fn fclass_s(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_xf(a, insn, Op::FclassS)
    }
    fn fcvt_s_w(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_fx(a, insn, Op::FcvtSW)
    }
    fn fcvt_s_wu(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_fx(a, insn, Op::FcvtSWu)
    }
    fn fmv_w_x(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r_fx(a, insn, Op::FmvWX) }
    fn fcvt_l_s(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_xf(a, insn, Op::FcvtLS)
    }
    fn fcvt_lu_s(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_xf(a, insn, Op::FcvtLuS)
    }
    fn fcvt_s_l(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_fx(a, insn, Op::FcvtSL)
    }
    fn fcvt_s_lu(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_fx(a, insn, Op::FcvtSLu)
    }
    fn fld(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_i_fx(a, insn, Op::Fld) }
    fn fsd(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_s_xf(a, insn, Op::Fsd) }
    fn fmadd_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r2_ffff(a, insn, Op::FmaddD)
    }
    fn fmsub_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r2_ffff(a, insn, Op::FmsubD)
    }
    fn fnmsub_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r2_ffff(a, insn, Op::FnmsubD)
    }
    fn fnmadd_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r2_ffff(a, insn, Op::FnmaddD)
    }
    fn fadd_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r_fff(a, insn, Op::FaddD) }
    fn fsub_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r_fff(a, insn, Op::FsubD) }
    fn fmul_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r_fff(a, insn, Op::FmulD) }
    fn fdiv_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r_fff(a, insn, Op::FdivD) }
    fn fsqrt_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_fff(a, insn, Op::FsqrtD)
    }
    fn fsgnj_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_fff(a, insn, Op::FsgnjD)
    }
    fn fsgnjn_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_fff(a, insn, Op::FsgnjnD)
    }
    fn fsgnjx_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_fff(a, insn, Op::FsgnjxD)
    }
    fn fmin_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r_fff(a, insn, Op::FminD) }
    fn fmax_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r_fff(a, insn, Op::FmaxD) }
    fn fcvt_s_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_fff(a, insn, Op::FcvtSD)
    }
    fn fcvt_d_s(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_fff(a, insn, Op::FcvtDS)
    }
    fn feq_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r_xff(a, insn, Op::FeqD) }
    fn flt_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r_xff(a, insn, Op::FltD) }
    fn fle_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r_xff(a, insn, Op::FleD) }
    fn fclass_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_xf(a, insn, Op::FclassD)
    }
    fn fcvt_w_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_xf(a, insn, Op::FcvtWD)
    }
    fn fcvt_wu_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_xf(a, insn, Op::FcvtWuD)
    }
    fn fcvt_d_w(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_fx(a, insn, Op::FcvtDW)
    }
    fn fcvt_d_wu(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_fx(a, insn, Op::FcvtDWu)
    }
    fn fcvt_l_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_xf(a, insn, Op::FcvtLD)
    }
    fn fcvt_lu_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_xf(a, insn, Op::FcvtLuD)
    }
    fn fmv_x_d(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r_xf(a, insn, Op::FmvXD) }
    fn fcvt_d_l(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_fx(a, insn, Op::FcvtDL)
    }
    fn fcvt_d_lu(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_fx(a, insn, Op::FcvtDLu)
    }
    fn fmv_d_x(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r_fx(a, insn, Op::FmvDX) }
    fn dret(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_exceptional(a, insn, Op::Dret)
    }
    fn mret(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_exceptional(a, insn, Op::Mret)
    }
    fn sret(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_exceptional(a, insn, Op::Sret)
    }
    fn sfence_vma(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_serialized(a, insn, Op::SfenceVma)
    }
    fn wfi(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_serialized(a, insn, Op::Wfi) }
    fn add_uw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::AddUw) }
    fn sh1add(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Sh1add) }
    fn sh1add_uw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r(a, insn, Op::Sh1addUw)
    }
    fn sh2add(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Sh2add) }
    fn sh2add_uw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r(a, insn, Op::Sh2addUw)
    }
    fn sh3add(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Sh3add) }
    fn sh3add_uw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r(a, insn, Op::Sh3addUw)
    }
    fn slli_uw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_shift(a, insn, Op::SlliUw)
    }
    fn czero_eqz(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r(a, insn, Op::CzeroEqz)
    }
    fn czero_nez(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r(a, insn, Op::CzeroNez)
    }
    fn andn(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Andn) }
    fn orn(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Orn) }
    fn xnor(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Xnor) }
    fn clz(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_i(a, insn, Op::Clz) }
    fn clzw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_i(a, insn, Op::Clzw) }
    fn ctz(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_i(a, insn, Op::Ctz) }
    fn ctzw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_i(a, insn, Op::Ctzw) }
    fn cpop(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_i(a, insn, Op::Cpop) }
    fn cpopw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_i(a, insn, Op::Cpopw) }
    fn max(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Max) }
    fn maxu(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Maxu) }
    fn min(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Min) }
    fn minu(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Minu) }
    fn orc_b(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_i(a, insn, Op::OrcB) }
    fn rev8(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_i(a, insn, Op::Rev8) }
    fn rol(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Rol) }
    fn rolw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Rolw) }
    fn ror(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Ror) }
    fn rori(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r_shift(a, insn, Op::Rori) }
    fn roriw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_r_shift(a, insn, Op::Roriw)
    }
    fn rorw(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Rorw) }
    fn sext_b(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_i(a, insn, Op::SextB) }
    fn sext_h(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_i(a, insn, Op::SextH) }
    fn zext_h(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::ZextH) }
    fn clmul(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Clmul) }
    fn clmulh(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Clmulh) }
    fn clmulr(a: u64, insn: u32, _c: &mut Self::Context) -> Uop { decode_r(a, insn, Op::Clmulr) }
    fn unimp(a: u64, insn: u32, _c: &mut Self::Context) -> Uop {
        decode_exceptional(a, insn, Op::Unimp)
    }
}

/// Generate a source integer `Reg`
/// # Panics
/// Trying to name a register > 31
#[must_use]
pub fn x(r: u32) -> Reg {
    debug_assert!(r < 32);
    Reg::new(r)
}

/// Generate a destination integer `Reg`
/// # Panics
/// Trying to name a register > 31
#[must_use]
pub fn xd(r: u32) -> Reg {
    debug_assert!(r < 32);
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
    debug_assert!(r < 32);
    Reg::new(r + 32)
}

fn decode_u(_addr: u64, word: u32, op: Op) -> Uop {
    Uop {
        op,
        rd: xd((word >> 7) & 31), // [11:7]
        imm: (word & 0xfffff000) as i32 as u64,
        ..Uop::default()
    }
}

fn decode_auipc(addr: u64, word: u32, op: Op) -> Uop {
    Uop {
        op,
        rd: xd((word >> 7) & 31), // [11:7]
        imm: addr.wrapping_add((word & 0xfffff000) as i32 as u64),
        ..Uop::default()
    }
}

fn decode_serialized(_addr: u64, _word: u32, op: Op) -> Uop {
    Uop {
        op,
        ..Uop::default()
    }
}

fn decode_exceptional(_addr: u64, _word: u32, op: Op) -> Uop {
    Uop {
        op,
        ..Uop::default()
    }
}

fn decode_j(addr: u64, word: u32, op: Op) -> Uop {
    let iword = word as i32;
    Uop {
        op,
        rd: xd((word >> 7) & 31), // [11:7]
        imm: addr.wrapping_add(
            (iword >> 31 << 20 | // imm[31:20] = [31]
             (iword & 0x000f_f000) | // imm[19:12] = [19:12]
             ((iword & 0x0010_0000) >> 9) | // imm[11] = [20]
             ((iword & 0x7fe0_0000) >> 20)) as u64,
        ), // imm[10:1] = [30:21]
        ..Uop::default()
    }
}

fn decode_empty(_addr: u64, _word: u32, op: Op) -> Uop {
    Uop {
        op,
        ..Uop::default()
    }
}

fn decode_b(addr: u64, word: u32, op: Op) -> Uop {
    let iword = word as i32;
    Uop {
        op,
        rs1: x((word >> 15) & 31), // [19:15]
        rs2: x((word >> 20) & 31), // [24:20]
        imm: addr.wrapping_add(
            (iword >> 31 << 12 | // imm[31:12] = [31]
            ((iword << 4) & 0x0000_0800) | // imm[11] = [7]
            ((iword >> 20) & 0x0000_07e0) | // imm[10:5] = [30:25]
            ((iword >> 7) & 0x0000_001e)) as u64,
        ), // imm[4:1] = [11:8]
        ..Uop::default()
    }
}

fn decode_csr(_addr: u64, word: u32, op: Op) -> Uop {
    Uop {
        op,
        rd: xd((word >> 7) & 31),             // [11:7]
        rs1: x((word >> 15) & 31),            // [19:15], also uimm
        imm: u64::from((word >> 20) & 0xfff), // [31:20]
        ..Uop::default()
    }
}

fn decode_csri(_addr: u64, word: u32, op: Op) -> Uop {
    // uimm is not a register read
    Uop {
        op,
        rd: xd((word >> 7) & 31),             // [11:7]
        rs1: x((word >> 15) & 31),            // [19:15], also uimm
        imm: u64::from((word >> 20) & 0xfff), // [31:20]
        ..Uop::default()
    }
}

fn decode_i(_addr: u64, word: u32, op: Op) -> Uop {
    Uop {
        op,
        rd: xd((word >> 7) & 31),          // [11:7]
        rs1: x((word >> 15) & 31),         // [19:15]
        imm: ((word as i32) >> 20) as u64, // [31:20]
        ..Uop::default()
    }
}

fn decode_i_fx(_addr: u64, word: u32, op: Op) -> Uop {
    Uop {
        op,
        rd: f((word >> 7) & 31),           // [11:7]
        rs1: x((word >> 15) & 31),         // [19:15]
        imm: ((word as i32) >> 20) as u64, // [31:20]
        ..Uop::default()
    }
}

fn decode_r(_addr: u64, word: u32, op: Op) -> Uop {
    Uop {
        op,
        rd: xd((word >> 7) & 31),  // [11:7]
        rs1: x((word >> 15) & 31), // [19:15]
        rs2: x((word >> 20) & 31), // [24:20]
        ..Uop::default()
    }
}

fn decode_r_xf(_addr: u64, word: u32, op: Op) -> Uop {
    Uop {
        op,
        rd: xd((word >> 7) & 31),  // [11:7]
        rs1: f((word >> 15) & 31), // [19:15]
        ..Uop::default()
    }
}

fn decode_r_xff(_addr: u64, word: u32, op: Op) -> Uop {
    Uop {
        op,
        rd: xd((word >> 7) & 31),  // [11:7]
        rs1: f((word >> 15) & 31), // [19:15]
        rs2: f((word >> 20) & 31), // [24:20]
        ..Uop::default()
    }
}

fn decode_r_fx(_addr: u64, word: u32, op: Op) -> Uop {
    #[allow(clippy::cast_possible_truncation)]
    Uop {
        op,
        rd: f((word >> 7) & 31),   // [11:7]
        rs1: x((word >> 15) & 31), // [19:15]
        rm: ((word >> 12) & 7) as u8,
        ..Uop::default()
    }
}

fn decode_r_fff(_addr: u64, word: u32, op: Op) -> Uop {
    #[allow(clippy::cast_possible_truncation)]
    Uop {
        op,
        rd: f((word >> 7) & 31),
        rs1: f((word >> 15) & 31),
        rs2: f((word >> 20) & 31),
        rm: ((word >> 12) & 7) as u8,
        ..Uop::default()
    }
}

fn decode_r_shift(_addr: u64, word: u32, op: Op) -> Uop {
    Uop {
        op,
        rd: xd((word >> 7) & 31),
        rs1: x((word >> 15) & 31),
        imm: u64::from((word >> 20) & 0x3f),
        ..Uop::default()
    }
}

fn decode_r2_ffff(_addr: u64, word: u32, op: Op) -> Uop {
    Uop {
        op,
        rd: f((word >> 7) & 31),
        rs1: f((word >> 15) & 31),
        rs2: f((word >> 20) & 31),
        rs3: f((word >> 27) & 31),
        rm: ((word >> 12) & 7) as u8,
        ..Uop::default()
    }
}

fn decode_s(_addr: u64, word: u32, op: Op) -> Uop {
    Uop {
        op,
        rs1: x((word >> 15) & 31),
        rs2: x((word >> 20) & 31),
        imm: sign_extend((word >> 20) & 0xfe0 | (word >> 7) & 31, 12) as u64,
        ..Uop::default()
    }
}

fn decode_s_xf(_addr: u64, word: u32, op: Op) -> Uop {
    Uop {
        op,
        rs1: x((word >> 15) & 31),
        rs2: f((word >> 20) & 31),
        imm: sign_extend((word >> 20) & 0xfe0 | (word >> 7) & 31, 12) as u64,
        ..Uop::default()
    }
}
