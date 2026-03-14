#![allow(clippy::cast_possible_wrap, clippy::cast_sign_loss, clippy::precedence)]
//! RISC-V floating point
//!
//! This is largely based on RISCVEMU/TinyEMU/Dromajo,
//! Copyright (c) 2016 Fabrice Bellard
//! Copyright (C) 2017,2018,2019, Esperanto Technologies Inc.

use crate::native_fp;

use num_derive::FromPrimitive;

pub const NAN_BOX_F32: u64 = 0xFFFF_FFFF_0000_0000;

pub mod fflag {
    pub const INEXACT: u8 = 1;
    pub const UNDERFLOW: u8 = 2;
    pub const OVERFLOW: u8 = 4;
    pub const DIVIDEZERO: u8 = 8;
    pub const INVALIDOP: u8 = 16;
}

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

pub struct Sf32;
pub struct Sf64;

pub trait Sf {
    type F;
    const N: usize;
    const MANT_SIZE: usize;
    const EXP_SIZE: usize;
    const IMANT_SIZE: usize = Self::N - 2; /* internal mantissa size */
    const RND_SIZE: usize = Self::IMANT_SIZE - Self::MANT_SIZE;

    const MASK: u64 = if Self::N == 64 { !0 } else { 0xFFFF_FFFF };
    const MASKSIGN: u64 = if Self::N == 64 {
        0x7FFF_FFFF_FFFF_FFFF
    } else {
        0x7FFF_FFFF
    };
    const SIGN_MASK: u64 = 1 << (Self::N - 1);
    const EXP_MASK: u64 = (1 << Self::EXP_SIZE) - 1;
    const MANT_MASK: u64 = (1 << Self::MANT_SIZE) - 1;
    const QNAN_MASK: u64 = 1 << (Self::MANT_SIZE - 1);

    const QNAN: u64;

    fn from_float(a: Self::F) -> u64;
    fn to_float(a: u64) -> Self::F;

    #[must_use]
    fn unbox(a: u64) -> u64;

    #[must_use]
    fn nanbox(a: u64) -> u64;

    #[must_use]
    fn sign(a: u64) -> u64 { (a >> (Self::N - 1)) & 1 }

    #[must_use]
    fn exp(a: u64) -> u64 { (a >> Self::MANT_SIZE) & Self::EXP_MASK }

    #[must_use]
    fn mant(a: u64) -> u64 { a & Self::MANT_MASK }

    #[must_use]
    fn pack(sign: u64, exp: u64, mant: u64) -> u64 {
        assert_eq!(sign & !1, 0);
        assert_eq!(exp & !Self::EXP_MASK, 0);
        Self::nanbox(sign << (Self::N - 1) | exp << Self::MANT_SIZE | mant & Self::MANT_MASK)
    }

    #[must_use]
    fn fclass(a: u64) -> Fclass {
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
    fn is_zero(a: u64) -> bool { Self::exp(a) == 0 && Self::mant(a) == 0 }

    #[must_use]
    fn is_nan(a: u64) -> bool { Self::exp(a) == Self::EXP_MASK && Self::mant(a) != 0 }

    #[must_use]
    fn is_signan(a: u64) -> bool {
        let a_exp1 = (a >> (Self::MANT_SIZE - 1)) & ((1 << (Self::EXP_SIZE + 1)) - 1);
        a_exp1 == (2 * Self::EXP_MASK) && Self::mant(a) != 0
    }

    #[must_use]
    fn rshift_rnd(a: u64, d: i64) -> u64 {
        if d != 0 {
            if d >= Self::N as i64 {
                u64::from(a != 0)
            } else {
                let d = d as u64;
                let mask = (1 << d) - 1;
                ((a as i64) >> d) as u64 | u64::from((a & mask) != 0)
            }
        } else {
            a
        }
    }

    #[must_use]
    fn feq(a0: u64, b0: u64) -> (u64, u8) {
        let (a, b) = (Self::unbox(a0), Self::unbox(b0));
        if Self::is_nan(a) || Self::is_nan(b) {
            if Self::is_signan(a) || Self::is_signan(b) {
                (0, fflag::INVALIDOP)
            } else {
                (0, 0)
            }
        } else if (a | b) & Self::MASKSIGN == 0 {
            (1, 0) /* zero case */
        } else {
            (u64::from(a == b), 0)
        }
    }

    #[must_use]
    fn fle(a: u64, b: u64) -> (u64, u8) {
        let (a, b) = (Self::unbox(a), Self::unbox(b));
        if Self::is_nan(a) || Self::is_nan(b) {
            (0, fflag::INVALIDOP)
        } else if Self::sign(a) != Self::sign(b) {
            (
                u64::from(Self::sign(a) != 0 || (a | b) & Self::MASKSIGN == 0),
                0,
            )
        } else if Self::sign(a) != 0 {
            (u64::from((a as i64) >= (b as i64)), 0)
        } else {
            (u64::from((a as i64) <= (b as i64)), 0)
        }
    }

    #[must_use]
    fn flt(a: u64, b: u64) -> (u64, u8) {
        let (a, b) = (Self::unbox(a), Self::unbox(b));
        if Self::is_nan(a) || Self::is_nan(b) {
            (0, fflag::INVALIDOP)
        } else if Self::sign(a) != Self::sign(b) {
            (
                u64::from(Self::sign(a) != 0 && (a | b) & Self::MASKSIGN != 0),
                0,
            )
        } else if Self::sign(a) != 0 {
            (u64::from((a as i64) > (b as i64)), 0)
        } else {
            (u64::from((a as i64) < (b as i64)), 0)
        }
    }

    #[must_use]
    fn fsub(a: u64, b: u64, rm: RoundingMode) -> (u64, u8) {
        Self::fadd(a, b ^ Self::SIGN_MASK, rm)
    }

    #[must_use]
    /* Based heavily on Fabrice Bellard's RISCVEMU/TinyEMU */
    fn fadd(a: u64, b: u64, rm: RoundingMode) -> (u64, u8) {
        let (a, b) = (Self::unbox(a), Self::unbox(b));

        // swap so that abs(a) >= abs(b)
        let (a, b) = if a & Self::MASKSIGN < b & Self::MASKSIGN {
            (b, a)
        } else {
            (a, b)
        };

        let (mut a_sign, mut a_exp, mut a_mant) = (Self::sign(a), Self::exp(a), Self::mant(a) << 3);
        let (b_sign, mut b_exp, mut b_mant) = (Self::sign(b), Self::exp(b), Self::mant(b) << 3);

        if a_exp == Self::EXP_MASK {
            return if a_mant != 0 {
                // NaN result
                if (a_mant & (Self::QNAN_MASK << 3)) == 0 || Self::is_signan(b) {
                    (Self::QNAN, fflag::INVALIDOP)
                } else {
                    (Self::QNAN, 0)
                }
            } else if b_exp == Self::EXP_MASK && a_sign != b_sign {
                (Self::QNAN, fflag::INVALIDOP)
            } else {
                /* infinity */
                (a, 0)
            };
        }

        if a_exp == 0 {
            a_exp = 1;
        } else {
            a_mant |= 1 << (Self::MANT_SIZE + 3);
        }
        if b_exp == 0 {
            b_exp = 1;
        } else {
            b_mant |= 1 << (Self::MANT_SIZE + 3);
        }

        let (mut a_exp, b_exp) = (a_exp as i64, b_exp as i64);

        let b_mant = Self::rshift_rnd(b_mant, a_exp - b_exp);

        if a_sign == b_sign {
            /* same signs : add the absolute values */
            a_mant += b_mant;
        } else {
            /* different signs : subtract the absolute values */
            a_mant -= b_mant;

            if a_mant == 0 {
                /* zero result : the sign needs a specific handling */
                a_sign = u64::from(rm == RoundingMode::RoundDown);
            }
        }

        a_exp += Self::RND_SIZE as i64 - 3;

        Self::normalize(a_sign, a_exp, a_mant, rm)
    }

    #[must_use]
    fn normalize(a_sign: u64, a_exp: i64, mut a_mant: u64, rm: RoundingMode) -> (u64, u8) {
        // a_mant is considered to have at most F_SIZE - 1 bits
        let shift = a_mant.leading_zeros() as isize - (64 - 1 - Self::IMANT_SIZE) as isize;

        assert!(shift >= 0);
        let a_exp = a_exp - (shift as i64);
        a_mant <<= shift;
        Self::round_pack(a_sign, a_exp, a_mant, rm)
    }

    #[must_use]
    fn round_pack(a_sign: u64, mut a_exp: i64, mut a_mant: u64, rm: RoundingMode) -> (u64, u8) {
        use RoundingMode::RoundDown;
        use RoundingMode::RoundNearestEven;
        use RoundingMode::RoundNearestMagnitude;
        use RoundingMode::RoundTowardsZero;
        use RoundingMode::RoundUp;
        // a_mant is considered to have its MSB at N - 2 bits

        let addend = match rm {
            RoundNearestEven | RoundNearestMagnitude => 1 << (Self::RND_SIZE - 1),
            RoundTowardsZero => 0,
            RoundDown => {
                if a_sign != 0 {
                    (1 << Self::RND_SIZE) - 1
                } else {
                    0
                }
            }
            RoundUp => {
                if a_sign == 1 {
                    0
                } else {
                    (1 << Self::RND_SIZE) - 1
                }
            }
            _ => unreachable!("Rounding mode {rm:?} shouldn't be possible here"),
        };

        let mut fflags = 0;
        // potentially subnormal
        let rnd_bits;

        if a_exp <= 0 {
            // Note: we set the underflow flag if the rounded result is subnormal and
            // inexact
            let is_subnormal = a_exp < 0 || (a_mant + addend) < (1 << (Self::N - 1));
            let diff = 1 - a_exp;
            a_mant = Self::rshift_rnd(a_mant, diff);
            rnd_bits = a_mant & ((1 << Self::RND_SIZE) - 1);
            if is_subnormal && rnd_bits != 0 {
                fflags = fflag::UNDERFLOW;
            }
            a_exp = 1;
        } else {
            rnd_bits = a_mant & ((1 << Self::RND_SIZE) - 1);
        }

        if rnd_bits != 0 {
            fflags |= fflag::INEXACT;
        }

        a_mant = a_mant.wrapping_add(addend) >> Self::RND_SIZE;

        // half way: select even result
        if rm == RoundingMode::RoundNearestEven && rnd_bits == (1 << (Self::RND_SIZE - 1)) {
            a_mant &= !1;
        }

        // Note the rounding adds at least 1, so this is the maximum value
        a_exp += (a_mant >> (Self::MANT_SIZE + 1)) as i64;
        if a_mant <= Self::MANT_MASK {
            // denormalized or zero
            a_exp = 0;
        } else if a_exp >= Self::EXP_MASK as i64 {
            // overflow
            if addend == 0 {
                a_exp = (Self::EXP_MASK - 1) as i64;
                a_mant = Self::MANT_MASK;
            } else {
                // infinity
                a_exp = Self::EXP_MASK as i64;
                a_mant = 0;
            }
            fflags |= fflag::OVERFLOW | fflag::INEXACT;
        }

        (Self::pack(a_sign, a_exp as u64, a_mant), fflags)
    }

    #[must_use]
    fn normalize_subnormal(mant: u64) -> (i64, u64) {
        assert_eq!(mant & !Self::MANT_MASK, 0);
        let shift = Self::MANT_SIZE - (63 - mant.leading_zeros() as usize);
        log::info!(
            "Normalize {} 0x{mant:x} -> shift {shift} -> new mantissa {:x}",
            Self::N,
            mant << shift
        );
        (1 - shift as i64, (mant << shift) & Self::MANT_MASK)
    }

    fn map1(a: u64, f: impl Fn(Self::F) -> Self::F) -> (u64, u8) {
        let a = Self::to_float(a);
        let r = f(a);
        let fflags = native_fp::fflags_raised();
        (Self::from_float(r), fflags)
    }

    fn map2(a: u64, b: u64, f: impl Fn(Self::F, Self::F) -> Self::F) -> (u64, u8) {
        let (a, b) = (Self::to_float(a), Self::to_float(b));
        let r = f(a, b);
        let fflags = native_fp::fflags_raised();
        (Self::from_float(r), fflags)
    }

    fn map3(a: u64, b: u64, c: u64, f: impl Fn(Self::F, Self::F, Self::F) -> Self::F) -> (u64, u8) {
        let (a, b, c) = (Self::to_float(a), Self::to_float(b), Self::to_float(c));
        let r = f(a, b, c);
        let fflags = native_fp::fflags_raised();
        (Self::from_float(r), fflags)
    }

    #[must_use]
    fn min(a: u64, b: u64) -> (u64, u8)
    where
        <Self as Sf>::F: PartialOrd,
    {
        let fflags = if Self::is_signan(a) || Self::is_signan(b) {
            fflag::INVALIDOP
        } else {
            0
        };
        let r = if Self::is_zero(a) && Self::is_zero(b) {
            if a == b {
                a
            } else {
                // -0.0
                Self::SIGN_MASK
            }
        } else if Self::is_nan(a) {
            if Self::is_nan(b) { Self::QNAN } else { b }
        } else if Self::is_nan(b) {
            a
        } else {
            let a: Self::F = Self::to_float(a);
            let b: Self::F = Self::to_float(b);
            Self::from_float(if a < b { a } else { b })
        };

        (r, fflags)
    }

    #[must_use]
    fn max(a: u64, b: u64) -> (u64, u8)
    where
        <Self as Sf>::F: PartialOrd,
    {
        let fflags = if Self::is_signan(a) || Self::is_signan(b) {
            fflag::INVALIDOP
        } else {
            0
        };
        let r = if Self::is_zero(a) && Self::is_zero(b) {
            if a == b {
                a
            } else {
                // +0.0
                0
            }
        } else if Self::is_nan(a) {
            if Self::is_nan(b) { Self::QNAN } else { b }
        } else if Self::is_nan(b) {
            a
        } else {
            let a: Self::F = Self::to_float(a);
            let b: Self::F = Self::to_float(b);
            Self::from_float(if a < b { b } else { a })
        };

        (r, fflags)
    }
}

impl Sf for Sf32 {
    const N: usize = 32;
    const MANT_SIZE: usize = 23;
    const EXP_SIZE: usize = 8;
    const QNAN: u64 = 0x7fc0_0000;

    type F = f32;

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn from_float(f: Self::F) -> u64 { NAN_BOX_F32 | u64::from(f.to_bits()) }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn to_float(v: u64) -> Self::F { f32::from_bits(Self::unbox(v) as u32) }

    fn unbox(r: u64) -> u64 {
        if (r & NAN_BOX_F32) == NAN_BOX_F32 {
            r & !NAN_BOX_F32
        } else {
            Self::QNAN
        }
    }

    fn nanbox(r: u64) -> u64 { r | NAN_BOX_F32 }
}

impl Sf for Sf64 {
    type F = f64;

    const N: usize = 64;
    const MANT_SIZE: usize = 52;
    const EXP_SIZE: usize = 11;
    const QNAN: u64 = 0x7ff8_0000_0000_0000;

    fn unbox(r: u64) -> u64 { r }
    fn nanbox(r: u64) -> u64 { r }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn from_float(f: f64) -> u64 { f.to_bits() }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    fn to_float(v: u64) -> f64 { f64::from_bits(v) }
}

#[must_use]
pub fn fcvt_d_s(a: u64) -> (u64, u8) {
    let a = Sf32::unbox(a);

    let a_mant = Sf32::mant(a);
    let a_exp = Sf32::exp(a);
    let a_sign = Sf32::sign(a);

    if Sf32::is_nan(a) {
        if Sf32::is_signan(a) {
            (Sf64::QNAN, fflag::INVALIDOP)
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
            let (a_exp, a_mant) = Sf32::normalize_subnormal(a_mant);
            /* convert the exponent value */
            let a_exp = a_exp - 0x7f + (Sf64::EXP_MASK / 2) as i64;
            /* shift the mantissa */
            let a_mant = a_mant << (Sf64::MANT_SIZE - Sf32::MANT_SIZE);
            /* We assume the target float is large enough to that no
            normalization is necessary */
            (Sf64::pack(a_sign, a_exp as u64, a_mant), 0)
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

// i64 -> f32
#[allow(clippy::cast_precision_loss, clippy::cast_sign_loss)]
#[must_use]
pub fn cvt_i64_sf32(a: u64, _rm: RoundingMode) -> (u64, u8) {
    // XXX The correct implementation, see
    // https://github.com/chipsalliance/dromajo/blob/8c0c1e3afd5cdea65d1b35872e395f988b0ec449/include/softfp_template_icvt.h#L130
    // is quite involved and thus slow.  Here we take a horrible
    // shortcut that ignores rounding modes and flags!

    let f = a as i64 as f32;
    (NAN_BOX_F32 | u64::from(f.to_bits()), 0)
}

// u64 -> f32
#[allow(clippy::cast_precision_loss, clippy::cast_sign_loss)]
#[must_use]
pub fn cvt_u64_sf32(a: u64, _rm: RoundingMode) -> (u64, u8) {
    // XXX The correct implementation, see
    // https://github.com/chipsalliance/dromajo/blob/8c0c1e3afd5cdea65d1b35872e395f988b0ec449/include/softfp_template_icvt.h#L130
    // is quite involved and thus slow.  Here we take a horrible
    // shortcut that ignores rounding modes and flags!

    let f = a as f32;
    (NAN_BOX_F32 | u64::from(f.to_bits()), 0)
}

// u32 -> f32
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)]
#[must_use]
pub fn cvt_u32_sf32(a: u64, _rm: RoundingMode) -> (u64, u8) {
    // XXX The correct implementation, see
    // https://github.com/chipsalliance/dromajo/blob/8c0c1e3afd5cdea65d1b35872e395f988b0ec449/include/softfp_template_icvt.h#L130
    // is quite involved and thus slow.  Here we take a horrible
    // shortcut that ignores rounding modes and flags!

    let f = a as u32 as f32;
    (NAN_BOX_F32 | u64::from(f.to_bits()), 0)
}

// i32 -> f32
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)]
#[must_use]
pub fn cvt_i32_sf32(a: u64, _rm: RoundingMode) -> (u64, u8) {
    // XXX The correct implementation, see
    // https://github.com/chipsalliance/dromajo/blob/8c0c1e3afd5cdea65d1b35872e395f988b0ec449/include/softfp_template_icvt.h#L130
    // is quite involved and thus slow.  Here we take a horrible
    // shortcut that ignores rounding modes and flags!

    let f = a as i32 as f32;
    (NAN_BOX_F32 | u64::from(f.to_bits()), 0)
}

#[cfg(test)]
mod tests;
