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
    fn feq(a: i64, b: i64) -> (bool, u8) {
        let (a, b) = (Self::unbox(a), Self::unbox(b));
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
        let (a, b) = (Self::unbox(a), Self::unbox(b));
        if Self::isnan(a) || Self::isnan(b) {
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
