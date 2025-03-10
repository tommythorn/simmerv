//! RISC-V floating point
//!
//! This is largely based on RISCVEMU/TinyEMU/Dromajo,
//! Copyright (c) 2016 Fabrice Bellard
//! Copyright (C) 2017,2018,2019, Esperanto Technologies Inc.

#![allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
use num_derive::FromPrimitive;

pub const NAN_BOX_F32: i64 = 0xFFFF_FFFF_0000_0000u64 as i64;

#[derive(Copy, Clone, PartialEq, Eq, Debug, FromPrimitive)]
pub enum RoundingMode {
    RoundNearestEven, // Round to Nearest, ties to Even
    RoundTowardsZero,
    RoundDown,
    RoundUp,
    RoundNearestMagnitude,
    Reserved5,
    Reserved6,
    Dynamic, // Use rounding mode from fcsr
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, FromPrimitive)]
pub enum Fflag {
    Inexact,
    Underflow,
    Overflow,
    DivideZero,
    InvalidOp,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, FromPrimitive)]
pub enum Fclass {
    Ninf,
    Nnormal,
    Nsubnormal,
    Nzero,
    Pzero,
    Psubnormal,
    Pnormal,
    Pinf,
    Snan,
    Qnan,
}

pub trait Fp {
    const N: usize;
    const MANT_SIZE: usize;
    const EXP_SIZE: usize;

    const MASK: i64 = if Self::N == 64 { !0 } else { 0xFFFF_FFFF };
    const MASKSIGN: i64 = if Self::N == 64 {
        0x7FFF_FFFF_FFFF_FFFF
    } else {
        0x7FFF_FFFF
    };
    const EXP_MASK: i64 = (1 << Self::EXP_SIZE) - 1;
    const MANT_MASK: i64 = (1 << Self::MANT_SIZE) - 1;
    const QNAN_MASK: i64 = 1 << (Self::MANT_SIZE - 1);

    #[must_use]
    fn unbox(a: i64) -> i64;

    #[must_use]
    fn sign(a: i64) -> i64 {
        (a >> (Self::N - 1)) & 1
    }

    #[must_use]
    fn exp(a: i64) -> i64 {
        (a >> Self::MANT_SIZE) & Self::EXP_MASK
    }

    #[must_use]
    fn mant(a: i64) -> i64 {
        a & Self::MANT_MASK
    }

    #[must_use]
    fn fclass(a: i64) -> Fclass {
        if Self::exp(a) == Self::EXP_MASK {
            if Self::mant(a) != 0 {
                if Self::mant(a) & Self::QNAN_MASK != 0 {
                    Fclass::Qnan
                } else {
                    Fclass::Snan
                }
            } else if Self::sign(a) != 0 {
                Fclass::Ninf
            } else {
                Fclass::Pinf
            }
        } else if Self::exp(a) == 0 {
            if Self::mant(a) == 0 {
                if Self::sign(a) != 0 {
                    Fclass::Nzero
                } else {
                    Fclass::Pzero
                }
            } else if Self::sign(a) != 0 {
                Fclass::Nsubnormal
            } else {
                Fclass::Psubnormal
            }
        } else if Self::sign(a) != 0 {
            Fclass::Nnormal
        } else {
            Fclass::Pnormal
        }
    }

    #[must_use]
    fn isnan(a: i64) -> bool {
        Self::exp(a) == Self::EXP_MASK && Self::mant(a) != 0
    }

    #[must_use]
    fn issignan(a: i64) -> bool {
        let a_exp1 = (a >> (Self::MANT_SIZE - 1)) & ((1 << (Self::EXP_SIZE + 1)) - 1);
        a_exp1 == (2 * Self::EXP_MASK) && Self::mant(a) != 0
    }

    #[must_use]
    fn feq(a0: i64, b0: i64) -> (bool, u8) {
        let (a, b) = (Self::unbox(a0), Self::unbox(b0));
        if Self::isnan(a) || Self::isnan(b) {
            if Self::issignan(a) || Self::issignan(b) {
                (false, 1 << Fflag::InvalidOp as usize)
            } else {
                (false, 0)
            }
        } else if (a | b) & Self::MASKSIGN == 0 {
            (true, 0) /* zero case */
        } else {
            (a == b, 0)
        }
    }

    #[must_use]
    fn fle(a: i64, b: i64) -> (bool, u8) {
        let (a, b) = (Self::unbox(a), Self::unbox(b));
        if Self::isnan(a) || Self::isnan(b) {
            (false, 1 << Fflag::InvalidOp as usize)
        } else if Self::sign(a) != Self::sign(b) {
            (Self::sign(a) != 0 || (a | b) & Self::MASKSIGN == 0, 0)
        } else if Self::sign(a) != 0 {
            (a >= b, 0)
        } else {
            (a <= b, 0)
        }
    }

    #[must_use]
    fn flt(a: i64, b: i64) -> (bool, u8) {
        //print!("flt({a:016x},{b:016x}) -> ");
        let (a, b) = (Self::unbox(a), Self::unbox(b));
        //print!("({a:016x},{b:016x}) -> ");
        if Self::isnan(a) || Self::isnan(b) {
            //println!("NaN? {} NaN? {} -> v....", Self::isnan(a), Self::isnan(b));
            (false, 1 << Fflag::InvalidOp as usize)
        } else if Self::sign(a) != Self::sign(b) {
            (Self::sign(a) != 0 && (a | b) & Self::MASKSIGN != 0, 0)
        } else if Self::sign(a) != 0 {
            //println!("a > b {}", a > b);
            (a > b, 0)
        } else {
            //println!("a < b {}", a < b);
            (a < b, 0)
        }
    }
}

pub struct Fp32;
pub struct Fp64;

impl Fp for Fp32 {
    const N: usize = 32;
    const MANT_SIZE: usize = 23;
    const EXP_SIZE: usize = 8;

    fn unbox(r: i64) -> i64 {
        const F_QNAN32: i64 = 0x7fc0_0000;

        if (r & NAN_BOX_F32) == NAN_BOX_F32 {
            r
        } else {
            println!("** unboxing {r:016x} -> QNaN32");
            F_QNAN32
        }
    }
}

impl Fp for Fp64 {
    const N: usize = 64;
    const MANT_SIZE: usize = 52;
    const EXP_SIZE: usize = 11;

    fn unbox(r: i64) -> i64 {
        r
    }
}

// The Berkeley Float Test found some issues
#[cfg(test)]
mod test {
    use super::*;

    fn test(f: impl Fn(i64, i64) -> (bool, u8), f1: i64, f2: i64, wantr: bool, wantfflag: u8) {
        let (r, fflag) = f(f1, f2);
        assert_eq!(
            (wantr, wantfflag),
            (r, fflag),
            "{f1:08x}, {f2:08x} -> ({}, {fflag:0x}) / ({}, {wantfflag:0x})",
            r as usize,
            wantr as usize
        );
    }

    // Convert John's representation to RISC-V NaN-boxed floats
    fn fp32(sign: i64, exp: i64, mant: i64) -> i64 {
        NAN_BOX_F32 | sign << 31 | exp << 23 | mant
    }

    fn fp64(sign: i64, exp: i64, mant: i64) -> i64 {
        sign << 63 | exp << 52 | mant
    }

    /*    fn fp64(sign: i64, exp: i64, mant: i64) -> i64 {
        sign << 63 | exp << 52 | mant
    }*/

    #[test]
    fn test_feq64() {
        // Errors found in f64_eq:
        // -47E.10000000000FF  +7FF.4F3D114AF58E4  => 0 .....  expected 0 v....
        // +000.0000000000000  +000.0000100000000  => 1 .....  expected 0 .....
        // +000.0000000000000  +000.0000200000000  => 1 .....  expected 0 .....
        // +000.0000000000000  +000.0000400000000  => 1 .....  expected 0 .....
        // +000.0000000000000  +000.0000800000000  => 1 .....  expected 0 .....
        // +000.0000000000000  +000.0001000000000  => 1 .....  expected 0 .....
        // +000.0000000000000  +000.0002000000000  => 1 .....  expected 0 .....
        // +000.0000000000000  +000.0004000000000  => 1 .....  expected 0 .....
        // -400.7B8561C35DA43  +7FF.0000004002000  => 0 .....  expected 0 v....
        // +000.0000000000000  +000.0008000000000  => 1 .....  expected 0 .....
        // +000.0000000000000  +000.0010000000000  => 1 .....  expected 0 .....
        // +000.0000000000000  +000.0020000000000  => 1 .....  expected 0 .....
        // +000.0000000000000  +000.0040000000000  => 1 .....  expected 0 .....
        // +000.0000000000000  +000.0080000000000  => 1 .....  expected 0 .....
        // +000.0000000000000  +000.0100000000000  => 1 .....  expected 0 .....
        // +000.0000000000000  +000.0200000000000  => 1 .....  expected 0 .....
        // +000.0000000000000  +000.0400000000000  => 1 .....  expected 0 .....
        // +000.0000000000000  +000.0800000000000  => 1 .....  expected 0 .....
        // +000.0000000000000  +000.1000000000000  => 1 .....  expected 0 .....
        // +000.0000000000000  +000.2000000000000  => 1 .....  expected 0 .....
        // 102 tests performed; 20 errors found.
        test(Fp64::feq,
             fp64(1, 0x47E, 0x10000000000FF),
             fp64(0, 0x7FF, 0x4F3D114AF58E4),
             false, 0x10);
        test(Fp64::feq,
             fp64(0, 0x000, 0x0000000000000),
             fp64(0, 0x000, 0x0000100000000),
             false, 0x00);
    }

    #[test]
    fn test_fle32() {
        // Errors found in f32_le:
        // +7F.7E0000  -FF.7FFF7F  => 0 .....  expected 0 v....
        // -82.6E832F  +FF.7001FF  => 0 .....  expected 0 v....
        test(
            Fp32::fle,
            fp32(0, 0x7F, 0x7E0000),
            fp32(1, 0xFF, 0x7FFF7F),
            false,
            0x10,
        );
        test(
            Fp32::fle,
            fp32(1, 0x86, 0x6E832F),
            fp32(0, 0xFF, 0x7001FF),
            false,
            0x10,
        );
    }

    #[test]
    fn test_flt32() {
        // -00.000001  +7D.7FFFFF  => 0 v....  expected 1 .....
        // +7E.7FC000  +FF.008000 => 0 v....
        // +97.7BFFFF  -FD.000008 => 0 .....
        // +FF.080000  -7F.7FFF7F => 0 v....
        // +67.7FFE7F  +FD.003FC0 => 1 .....
        // -FF.7FFFFC  +FE.7FE000 => 0 v....
        test(
            Fp32::flt,
            fp32(1, 0x00, 0x000001),
            fp32(0, 0x7D, 0x7FFFFF),
            true,
            0,
        );
        test(
            Fp32::flt,
            fp32(0, 0x7E, 0x7FC000),
            fp32(0, 0xFF, 0x008000),
            false,
            0x10,
        );
        test(
            Fp32::flt,
            fp32(0, 0x97, 0x7BFFFF),
            fp32(1, 0xFD, 0x000008),
            false,
            0,
        );
        test(
            Fp32::flt,
            fp32(0, 0xFF, 0x080000),
            fp32(1, 0x7F, 0x7FFF7F),
            false,
            0x10,
        );
        test(
            Fp32::flt,
            fp32(0, 0x67, 0x7FFE7F),
            fp32(0, 0xFD, 0x003FC0),
            true,
            0,
        );
        test(
            Fp32::flt,
            fp32(1, 0xFF, 0x7FFFFC),
            fp32(0, 0xFE, 0x7FE000),
            false,
            0x10,
        );
    }
}
