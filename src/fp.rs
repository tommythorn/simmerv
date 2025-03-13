//! RISC-V floating point
//!
//! This is largely based on RISCVEMU/TinyEMU/Dromajo,
//! Copyright (c) 2016 Fabrice Bellard
//! Copyright (C) 2017,2018,2019, Esperanto Technologies Inc.

#![allow(clippy::cast_possible_wrap, clippy::cast_sign_loss, clippy::precedence)]
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

// XXX I think I can do better and make this more type safe:
// pub trait Sf {
//     fn unpack(a: Sf) -> (i64, i64, i64);
//     fn pack(s: i64, e: i64, m: i64) -> Sf;
//     fn fclass(self) -> Fclass { ... }
//     fn le(self, b: self) -> bool { ... }
//     ...
// }
// struct Sf32(i64)
// struct Sf64(i64)
// impl Sf for Sf32 ...

pub trait Sf {
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

    const QNAN: i64;

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
    fn pack(sign: i64, exp: i64, mant: i64) -> i64 {
        assert_eq!(sign & !1, 0);
        assert_eq!(exp & !Self::EXP_MASK, 0);
        assert_eq!(
            mant & !Self::MANT_MASK,
            0,
            "{mant:016x} & {:016x} == {:016x}",
            !Self::MANT_MASK,
            mant & !Self::MANT_MASK
        );
        sign << (Self::N - 1) | exp << Self::MANT_SIZE | mant
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
    fn is_nan(a: i64) -> bool {
        Self::exp(a) == Self::EXP_MASK && Self::mant(a) != 0
    }

    #[must_use]
    fn is_signan(a: i64) -> bool {
        let a_exp1 = (a >> (Self::MANT_SIZE - 1)) & ((1 << (Self::EXP_SIZE + 1)) - 1);
        a_exp1 == (2 * Self::EXP_MASK) && Self::mant(a) != 0
    }

    #[must_use]
    fn feq(a0: i64, b0: i64) -> (bool, u8) {
        let (a, b) = (Self::unbox(a0), Self::unbox(b0));
        if Self::is_nan(a) || Self::is_nan(b) {
            if Self::is_signan(a) || Self::is_signan(b) {
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
        if Self::is_nan(a) || Self::is_nan(b) {
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
        let (a, b) = (Self::unbox(a), Self::unbox(b));
        if Self::is_nan(a) || Self::is_nan(b) {
            (false, 1 << Fflag::InvalidOp as usize)
        } else if Self::sign(a) != Self::sign(b) {
            (Self::sign(a) != 0 && (a | b) & Self::MASKSIGN != 0, 0)
        } else if Self::sign(a) != 0 {
            (a > b, 0)
        } else {
            (a < b, 0)
        }
    }
}

pub struct Sf32;
pub struct Sf64;

impl Sf for Sf32 {
    const N: usize = 32;
    const MANT_SIZE: usize = 23;
    const EXP_SIZE: usize = 8;
    const QNAN: i64 = 0x7fc0_0000;

    fn unbox(r: i64) -> i64 {
        if (r & NAN_BOX_F32) == NAN_BOX_F32 {
            r
        } else {
            println!("** unboxing {r:016x} -> QNaN32");
            Self::QNAN
        }
    }
}

impl Sf for Sf64 {
    const N: usize = 64;
    const MANT_SIZE: usize = 52;
    const EXP_SIZE: usize = 11;
    const QNAN: i64 = 0x7ff8_0000_0000_0000; // XXX Check this

    fn unbox(r: i64) -> i64 {
        r
    }
}

#[must_use]
pub fn fcvt_d_s(a: i64) -> (i64, u8) {
    let a = Sf32::unbox(a);

    let a_mant = Sf32::mant(a);
    let a_exp = Sf32::exp(a);
    let a_sign = Sf32::sign(a);

    if Sf32::is_nan(a) {
        if Sf32::is_signan(a) {
            (Sf64::QNAN, 1 << Fflag::InvalidOp as usize)
        } else {
            (Sf64::QNAN, 0)
        }
    } else if a_exp == Sf32::EXP_MASK {
        /* infinity */
        (Sf64::pack(a_sign, Sf64::EXP_MASK, 0), 0)
    } else if a_exp == 0 {
        if a_mant == 0 {
            (Sf64::pack(a_sign, 0, 0), 0)
        } else {
            let (a_exp, a_mant) = normalize_subnormal_sf32(a_mant);
            /* convert the exponent value */
            let a_exp = a_exp - 0x7f + (Sf64::EXP_MASK / 2);
            /* shift the mantissa */
            let a_mant = a_mant << (Sf64::MANT_SIZE - Sf32::MANT_SIZE);
            /* We assume the target float is large enough to that no
            normalization is necessary */
            (Sf64::pack(a_sign, a_exp, a_mant), 0)
        }
    } else {
        /* convert the exponent value */
        let a_exp = a_exp - 0x7f + (Sf64::EXP_MASK / 2);
        /* shift the mantissa */
        let a_mant = a_mant << (Sf64::MANT_SIZE - Sf32::MANT_SIZE);
        /* We assume the target float is large enough to that no
        normalization is necessary */
        (Sf64::pack(a_sign, a_exp, a_mant), 0)
    }
}

#[allow(dead_code)]
fn normalize_subnormal_sf32(mant: i64) -> (i64, i64) {
    assert_eq!(mant & !Sf32::MANT_MASK, 0);
    let shift = Sf32::MANT_SIZE - (63 - mant.leading_zeros() as usize);
    log::info!(
        "Normalize 32 0x{mant:x} -> shift {shift} -> new mantissa {:x}",
        mant << shift
    );
    (1 - shift as i64, (mant << shift) & Sf32::MANT_MASK)
}

#[allow(dead_code)]
fn normalize_subnormal_sf64(mant: i64) -> (i64, i64) {
    let shift = Sf64::MANT_SIZE - (63 - mant.leading_zeros() as usize);
    log::info!(
        "Normalize 64 0x{mant:x} -> shift {shift} -> new mantissa {:x}",
        mant << shift
    );
    (1 - shift as i64, mant << shift)
}

// i64 -> f32
#[allow(clippy::cast_precision_loss, clippy::cast_sign_loss)]
#[must_use]
pub fn cvt_i64_sf32(a: i64, _rm: RoundingMode) -> (i64, u8) {
    // XXX The correct implementation, see
    // https://github.com/chipsalliance/dromajo/blob/8c0c1e3afd5cdea65d1b35872e395f988b0ec449/include/softfp_template_icvt.h#L130
    // is quite involved and thus slow.  Here we take a horrible
    // shortcut that ignores rounding modes and flags!

    let f = a as f32;
    (NAN_BOX_F32 | i64::from(f.to_bits()), 0)
}

// u64 -> f32
#[allow(clippy::cast_precision_loss, clippy::cast_sign_loss)]
#[must_use]
pub fn cvt_u64_sf32(a: i64, _rm: RoundingMode) -> (i64, u8) {
    // XXX The correct implementation, see
    // https://github.com/chipsalliance/dromajo/blob/8c0c1e3afd5cdea65d1b35872e395f988b0ec449/include/softfp_template_icvt.h#L130
    // is quite involved and thus slow.  Here we take a horrible
    // shortcut that ignores rounding modes and flags!

    let f = a as u64 as f32;
    (NAN_BOX_F32 | i64::from(f.to_bits()), 0)
}

// u32 -> f32
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)]
#[must_use]
pub fn cvt_u32_sf32(a: i64, _rm: RoundingMode) -> (i64, u8) {
    // XXX The correct implementation, see
    // https://github.com/chipsalliance/dromajo/blob/8c0c1e3afd5cdea65d1b35872e395f988b0ec449/include/softfp_template_icvt.h#L130
    // is quite involved and thus slow.  Here we take a horrible
    // shortcut that ignores rounding modes and flags!

    let f = a as u32 as f32;
    (NAN_BOX_F32 | i64::from(f.to_bits()), 0)
}

// i32 -> f32
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)]
#[must_use]
pub fn cvt_i32_sf32(a: i64, _rm: RoundingMode) -> (i64, u8) {
    // XXX The correct implementation, see
    // https://github.com/chipsalliance/dromajo/blob/8c0c1e3afd5cdea65d1b35872e395f988b0ec449/include/softfp_template_icvt.h#L130
    // is quite involved and thus slow.  Here we take a horrible
    // shortcut that ignores rounding modes and flags!

    let f = a as i32 as f32;
    (NAN_BOX_F32 | i64::from(f.to_bits()), 0)
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
            usize::from(r),
            usize::from(wantr)
        );
    }

    // Convert John's representation to RISC-V NaN-boxed floats
    const fn fp32(sign: i64, exp: i64, mant: i64) -> i64 {
        NAN_BOX_F32 | (sign << 31) | (exp << 23) | mant
    }

    const fn fp64(sign: i64, exp: i64, mant: i64) -> i64 {
        (sign << 63) | (exp << 52) | mant
    }

    /*    fn fp64(sign: i64, exp: i64, mant: i64) -> i64 {
        sign << 63 | exp << 52 | mant
    }*/

    #[test]
    fn test_feq64() {
        // Errors found in f64_eq:
        // -47E.10000000000FF  +7FF.4F3D114AF58E4  => 0 .....  expected 0 v....
        test(
            Sf64::feq,
            fp64(1, 0x47E, 0x10000000000FF),
            fp64(0, 0x7FF, 0x4F3D114AF58E4),
            false,
            0x10,
        );
        test(
            Sf64::feq,
            fp64(0, 0x000, 0x0000000000000),
            fp64(0, 0x000, 0x0000100000000),
            false,
            0x00,
        );
    }

    #[test]
    fn test_f64_lt() {
        // +46D.03FFFFFFFFFFB  +3CA.000000800000F  => 1 .....  expected 0 ....
        test(
            Sf64::flt,
            fp64(0, 0x46D, 0x03FFFFFFFFFFB),
            fp64(0, 0x3CA, 0x000000800000F),
            false,
            0x00,
        );
    }

    #[test]
    fn test_fle32() {
        // Errors found in f32_le:
        // +7F.7E0000  -FF.7FFF7F  => 0 .....  expected 0 v....
        // -82.6E832F  +FF.7001FF  => 0 .....  expected 0 v....
        test(
            Sf32::fle,
            fp32(0, 0x7F, 0x7E0000),
            fp32(1, 0xFF, 0x7FFF7F),
            false,
            0x10,
        );
        test(
            Sf32::fle,
            fp32(1, 0x86, 0x6E832F),
            fp32(0, 0xFF, 0x7001FF),
            false,
            0x10,
        );
    }

    #[test]
    fn test_f32_lt() {
        // Errors found in f32_lt:
        // -FF.000400  +FF.7BFFFF  => 0 .....  expected 0 v....
        test(
            Sf32::flt,
            fp32(1, 0xFF, 0x000400),
            fp32(0, 0xFF, 0x7BFFFF),
            false,
            0x10,
        );

        // -00.000001  +7D.7FFFFF  => 0 v....  expected 1 .....
        // +7E.7FC000  +FF.008000 => 0 v....
        // +97.7BFFFF  -FD.000008 => 0 .....
        // +FF.080000  -7F.7FFF7F => 0 v....
        // +67.7FFE7F  +FD.003FC0 => 1 .....
        // -FF.7FFFFC  +FE.7FE000 => 0 v....
        test(
            Sf32::flt,
            fp32(1, 0x00, 0x000001),
            fp32(0, 0x7D, 0x7FFFFF),
            true,
            0,
        );
        test(
            Sf32::flt,
            fp32(0, 0x7E, 0x7FC000),
            fp32(0, 0xFF, 0x008000),
            false,
            0x10,
        );
        test(
            Sf32::flt,
            fp32(0, 0x97, 0x7BFFFF),
            fp32(1, 0xFD, 0x000008),
            false,
            0,
        );
        test(
            Sf32::flt,
            fp32(0, 0xFF, 0x080000),
            fp32(1, 0x7F, 0x7FFF7F),
            false,
            0x10,
        );
        test(
            Sf32::flt,
            fp32(0, 0x67, 0x7FFE7F),
            fp32(0, 0xFD, 0x003FC0),
            true,
            0,
        );
        test(
            Sf32::flt,
            fp32(1, 0xFF, 0x7FFFFC),
            fp32(0, 0xFE, 0x7FE000),
            false,
            0x10,
        );
    }
}
