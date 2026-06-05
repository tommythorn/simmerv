#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::precedence
)]
//! RISC-V floating point
//!
//! This is largely based on RISCVEMU/TinyEMU/Dromajo,
//! Copyright (c) 2016 Fabrice Bellard
//! Copyright (C) 2017,2018,2019, Esperanto Technologies Inc.

use crate::native_fp;

use num_derive::FromPrimitive;

pub const NAN_BOX_F32: u64 = 0xFFFF_FFFF_0000_0000;
pub const NAN_BOX_F16: u64 = 0xFFFF_FFFF_FFFF_0000;

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

pub struct Sf16;
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
        debug_assert_eq!(sign & !1, 0);
        debug_assert_eq!(exp & !Self::EXP_MASK, 0);
        Self::nanbox(sign << (Self::N - 1) | exp << Self::MANT_SIZE | mant & Self::MANT_MASK)
    }

    #[must_use]
    fn qnan() -> u64 { Self::nanbox(Self::QNAN) }

    #[must_use]
    fn fclass(a: u64) -> Fclass {
        let a = Self::unbox(a);
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
                let mask = (1u64 << d) - 1;
                (a >> d) | u64::from((a & mask) != 0)
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
                    (Self::qnan(), fflag::INVALIDOP)
                } else {
                    (Self::qnan(), 0)
                }
            } else if b_exp == Self::EXP_MASK && a_sign != b_sign {
                (Self::qnan(), fflag::INVALIDOP)
            } else {
                /* infinity */
                (Self::nanbox(a), 0)
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

        debug_assert!(shift >= 0);
        let a_exp = a_exp - (shift as i64);
        a_mant <<= shift;
        Self::round_pack(a_sign, a_exp, a_mant, rm)
    }

    #[must_use]
    fn normalize2(
        a_sign: u64,
        mut a_exp: i64,
        mut a_mant1: u64,
        mut a_mant0: u64,
        rm: RoundingMode,
    ) -> (u64, u8) {
        let l = if a_mant1 == 0 {
            Self::N + Self::clz(a_mant0)
        } else {
            Self::clz(a_mant1)
        };
        let shift = l as isize - (Self::N - 1 - Self::IMANT_SIZE) as isize;
        debug_assert!(shift >= 0);
        let shift = shift as usize;
        a_exp -= shift as i64;
        if shift == 0 {
            a_mant1 |= u64::from(a_mant0 != 0);
        } else if shift < Self::N {
            a_mant1 = (a_mant1 << shift) | (a_mant0 >> (Self::N - shift));
            a_mant0 <<= shift;
            a_mant1 |= u64::from(a_mant0 != 0);
        } else {
            a_mant1 = a_mant0 << (shift - Self::N);
        }
        Self::round_pack(a_sign, a_exp, a_mant1, rm)
    }

    #[must_use]
    fn clz(a: u64) -> usize { a.leading_zeros() as usize - (64 - Self::N) }

    #[must_use]
    fn mul_u(a: u64, b: u64) -> (u64, u64) {
        let mask = u128::from(Self::MASK);
        let r = u128::from(a & Self::MASK) * u128::from(b & Self::MASK);
        ((r >> Self::N) as u64, (r & mask) as u64)
    }

    #[must_use]
    fn add_n(a: u64, b: u64) -> (u64, u64) {
        let r = u128::from(a & Self::MASK) + u128::from(b & Self::MASK);
        ((r & u128::from(Self::MASK)) as u64, (r >> Self::N) as u64)
    }

    #[must_use]
    fn sub_n(a: u64, b: u64) -> (u64, u64) {
        let a = a & Self::MASK;
        let b = b & Self::MASK;
        (a.wrapping_sub(b) & Self::MASK, u64::from(a < b))
    }

    #[must_use]
    fn divrem_u(ah: u64, al: u64, b: u64) -> (u64, u64) {
        let a = (u128::from(ah & Self::MASK) << Self::N) | u128::from(al & Self::MASK);
        let b = u128::from(b & Self::MASK);
        ((a / b) as u64, (a % b) as u64)
    }

    #[must_use]
    fn sqrtrem_u(ah: u64, al: u64) -> (u64, bool) {
        let a = (u128::from(ah & Self::MASK) << Self::N) | u128::from(al & Self::MASK);
        if a == 0 {
            return (0, false);
        }

        let bit_len = 128 - a.leading_zeros() as usize;
        let mut u = 1u128 << bit_len.div_ceil(2);
        loop {
            let s = u;
            u = u128::midpoint(a / s, s);
            if u >= s {
                let inexact = a != s * s;
                return (s as u64, inexact);
            }
        }
    }

    #[must_use]
    fn fmul(a: u64, b: u64, rm: RoundingMode) -> (u64, u8) {
        let (a, b) = (Self::unbox(a), Self::unbox(b));
        let a_sign = Self::sign(a);
        let b_sign = Self::sign(b);
        let r_sign = a_sign ^ b_sign;
        let mut a_exp = Self::exp(a) as i64;
        let mut b_exp = Self::exp(b) as i64;
        let mut a_mant = Self::mant(a);
        let mut b_mant = Self::mant(b);

        if a_exp == Self::EXP_MASK as i64 || b_exp == Self::EXP_MASK as i64 {
            if Self::is_nan(a) || Self::is_nan(b) {
                let fflags = if Self::is_signan(a) || Self::is_signan(b) {
                    fflag::INVALIDOP
                } else {
                    0
                };
                return (Self::qnan(), fflags);
            }
            if (a_exp == Self::EXP_MASK as i64 && b_exp == 0 && b_mant == 0)
                || (b_exp == Self::EXP_MASK as i64 && a_exp == 0 && a_mant == 0)
            {
                return (Self::qnan(), fflag::INVALIDOP);
            }
            return (Self::pack(r_sign, Self::EXP_MASK, 0), 0);
        }
        if a_exp == 0 {
            if a_mant == 0 {
                return (Self::pack(r_sign, 0, 0), 0);
            }
            (a_exp, a_mant) = Self::normalize_subnormal_full(a_mant);
        } else {
            a_mant |= 1u64 << Self::MANT_SIZE;
        }
        if b_exp == 0 {
            if b_mant == 0 {
                return (Self::pack(r_sign, 0, 0), 0);
            }
            (b_exp, b_mant) = Self::normalize_subnormal_full(b_mant);
        } else {
            b_mant |= 1u64 << Self::MANT_SIZE;
        }

        let r_exp = a_exp + b_exp - (1 << (Self::EXP_SIZE - 1)) + 2;
        let (mut r_mant, r_mant_low) =
            Self::mul_u(a_mant << Self::RND_SIZE, b_mant << (Self::RND_SIZE + 1));
        r_mant |= u64::from(r_mant_low != 0);
        Self::normalize(r_sign, r_exp, r_mant, rm)
    }

    #[must_use]
    fn fdiv(a: u64, b: u64, rm: RoundingMode) -> (u64, u8) {
        let (a, b) = (Self::unbox(a), Self::unbox(b));
        let a_sign = Self::sign(a);
        let b_sign = Self::sign(b);
        let r_sign = a_sign ^ b_sign;
        let mut a_exp = Self::exp(a) as i64;
        let mut b_exp = Self::exp(b) as i64;
        let mut a_mant = Self::mant(a);
        let mut b_mant = Self::mant(b);

        if a_exp == Self::EXP_MASK as i64 {
            if a_mant != 0 || Self::is_nan(b) {
                let fflags = if Self::is_signan(a) || Self::is_signan(b) {
                    fflag::INVALIDOP
                } else {
                    0
                };
                return (Self::qnan(), fflags);
            }
            if b_exp == Self::EXP_MASK as i64 {
                return (Self::qnan(), fflag::INVALIDOP);
            }
            return (Self::pack(r_sign, Self::EXP_MASK, 0), 0);
        } else if b_exp == Self::EXP_MASK as i64 {
            if b_mant != 0 {
                let fflags = if Self::is_signan(a) || Self::is_signan(b) {
                    fflag::INVALIDOP
                } else {
                    0
                };
                return (Self::qnan(), fflags);
            }
            return (Self::pack(r_sign, 0, 0), 0);
        }

        if b_exp == 0 {
            if b_mant == 0 {
                if a_exp == 0 && a_mant == 0 {
                    return (Self::qnan(), fflag::INVALIDOP);
                }
                return (Self::pack(r_sign, Self::EXP_MASK, 0), fflag::DIVIDEZERO);
            }
            (b_exp, b_mant) = Self::normalize_subnormal_full(b_mant);
        } else {
            b_mant |= 1u64 << Self::MANT_SIZE;
        }
        if a_exp == 0 {
            if a_mant == 0 {
                return (Self::pack(r_sign, 0, 0), 0);
            }
            (a_exp, a_mant) = Self::normalize_subnormal_full(a_mant);
        } else {
            a_mant |= 1u64 << Self::MANT_SIZE;
        }

        let r_exp = a_exp - b_exp + (1 << (Self::EXP_SIZE - 1)) - 1;
        let (mut r_mant, r) = Self::divrem_u(a_mant, 0, b_mant << 2);
        if r != 0 {
            r_mant |= 1;
        }
        Self::normalize(r_sign, r_exp, r_mant, rm)
    }

    #[must_use]
    fn fsqrt(a: u64, rm: RoundingMode) -> (u64, u8) {
        let a = Self::unbox(a);
        let a_sign = Self::sign(a);
        let mut a_exp = Self::exp(a) as i64;
        let mut a_mant = Self::mant(a);

        if a_exp == Self::EXP_MASK as i64 {
            if a_mant != 0 {
                let fflags = if Self::is_signan(a) {
                    fflag::INVALIDOP
                } else {
                    0
                };
                return (Self::qnan(), fflags);
            }
            if a_sign != 0 {
                return (Self::qnan(), fflag::INVALIDOP);
            }
            return (Self::nanbox(a), 0);
        }
        if a_sign != 0 {
            if a_exp == 0 && a_mant == 0 {
                return (Self::nanbox(a), 0);
            }
            return (Self::qnan(), fflag::INVALIDOP);
        }
        if a_exp == 0 {
            if a_mant == 0 {
                return (Self::pack(0, 0, 0), 0);
            }
            (a_exp, a_mant) = Self::normalize_subnormal_full(a_mant);
        } else {
            a_mant |= 1u64 << Self::MANT_SIZE;
        }

        a_exp -= (Self::EXP_MASK / 2) as i64;
        if a_exp & 1 != 0 {
            a_exp -= 1;
            a_mant <<= 1;
        }
        a_exp = (a_exp >> 1) + (Self::EXP_MASK / 2) as i64;
        a_mant <<= Self::N - 4 - Self::MANT_SIZE;
        let (mut a_mant, inexact) = Self::sqrtrem_u(a_mant, 0);
        if inexact {
            a_mant |= 1;
        }
        Self::normalize(a_sign, a_exp, a_mant, rm)
    }

    #[must_use]
    #[allow(clippy::too_many_lines)]
    fn fma(a: u64, b: u64, c: u64, rm: RoundingMode) -> (u64, u8) {
        let (a, b, c) = (Self::unbox(a), Self::unbox(b), Self::unbox(c));
        let a_sign = Self::sign(a);
        let b_sign = Self::sign(b);
        let mut c_sign = Self::sign(c);
        let mut r_sign = a_sign ^ b_sign;
        let mut a_exp = Self::exp(a) as i64;
        let mut b_exp = Self::exp(b) as i64;
        let mut c_exp = Self::exp(c) as i64;
        let mut a_mant = Self::mant(a);
        let mut b_mant = Self::mant(b);
        let mut c_mant = Self::mant(c);

        if a_exp == Self::EXP_MASK as i64
            || b_exp == Self::EXP_MASK as i64
            || c_exp == Self::EXP_MASK as i64
        {
            if (a_exp == 0 && a_mant == 0 && b_exp == Self::EXP_MASK as i64 && b_mant == 0)
                || (b_exp == 0 && b_mant == 0 && a_exp == Self::EXP_MASK as i64 && a_mant == 0)
            {
                return (Self::qnan(), fflag::INVALIDOP);
            }

            if Self::is_nan(a) || Self::is_nan(b) || Self::is_nan(c) {
                let fflags = if Self::is_signan(a) || Self::is_signan(b) || Self::is_signan(c) {
                    fflag::INVALIDOP
                } else {
                    0
                };
                return (Self::qnan(), fflags);
            }
            if (a_exp == Self::EXP_MASK as i64 && b_exp == 0 && b_mant == 0)
                || (b_exp == Self::EXP_MASK as i64 && a_exp == 0 && a_mant == 0)
                || ((a_exp == Self::EXP_MASK as i64 || b_exp == Self::EXP_MASK as i64)
                    && c_exp == Self::EXP_MASK as i64
                    && r_sign != c_sign)
            {
                return (Self::qnan(), fflag::INVALIDOP);
            }
            if c_exp == Self::EXP_MASK as i64 {
                return (Self::pack(c_sign, Self::EXP_MASK, 0), 0);
            }
            return (Self::pack(r_sign, Self::EXP_MASK, 0), 0);
        }

        if a_exp == 0 {
            if a_mant == 0 {
                return Self::fma_mul_zero(r_sign, c_sign, c_exp, c_mant, rm, c);
            }
            (a_exp, a_mant) = Self::normalize_subnormal_full(a_mant);
        } else {
            a_mant |= 1u64 << Self::MANT_SIZE;
        }
        if b_exp == 0 {
            if b_mant == 0 {
                return Self::fma_mul_zero(r_sign, c_sign, c_exp, c_mant, rm, c);
            }
            (b_exp, b_mant) = Self::normalize_subnormal_full(b_mant);
        } else {
            b_mant |= 1u64 << Self::MANT_SIZE;
        }

        let mut r_exp = a_exp + b_exp - (1 << (Self::EXP_SIZE - 1)) + 3;
        let (mut r_mant1, mut r_mant0) =
            Self::mul_u(a_mant << Self::RND_SIZE, b_mant << Self::RND_SIZE);

        if r_mant1 < (1u64 << (Self::N - 3)) {
            r_mant1 = (r_mant1 << 1) | (r_mant0 >> (Self::N - 1));
            r_mant0 = (r_mant0 << 1) & Self::MASK;
            r_exp -= 1;
        }

        if c_exp == 0 {
            if c_mant == 0 {
                r_mant1 |= u64::from(r_mant0 != 0);
                return Self::normalize(r_sign, r_exp, r_mant1, rm);
            }
            (c_exp, c_mant) = Self::normalize_subnormal_full(c_mant);
        } else {
            c_mant |= 1u64 << Self::MANT_SIZE;
        }
        c_exp += 1;
        let mut c_mant1 = c_mant << (Self::RND_SIZE - 1);
        let mut c_mant0 = 0;

        if !(r_exp > c_exp || (r_exp == c_exp && r_mant1 >= c_mant1)) {
            core::mem::swap(&mut r_mant1, &mut c_mant1);
            core::mem::swap(&mut r_mant0, &mut c_mant0);
            core::mem::swap(&mut r_exp, &mut c_exp);
            core::mem::swap(&mut r_sign, &mut c_sign);
        }

        let shift = r_exp - c_exp;
        if shift >= (2 * Self::N) as i64 {
            c_mant0 = u64::from((c_mant0 | c_mant1) != 0);
            c_mant1 = 0;
        } else if shift >= (Self::N + 1) as i64 {
            c_mant0 = Self::rshift_rnd(c_mant1, shift - Self::N as i64);
            c_mant1 = 0;
        } else if shift == Self::N as i64 {
            c_mant0 = c_mant1 | u64::from(c_mant0 != 0);
            c_mant1 = 0;
        } else if shift != 0 {
            let shift = shift as usize;
            let mask = (1u64 << shift) - 1;
            c_mant0 = (c_mant1 << (Self::N - shift))
                | (c_mant0 >> shift)
                | u64::from((c_mant0 & mask) != 0);
            c_mant1 >>= shift;
        }

        if r_sign == c_sign {
            let (sum0, carry) = Self::add_n(r_mant0, c_mant0);
            r_mant0 = sum0;
            r_mant1 = r_mant1.wrapping_add(c_mant1).wrapping_add(carry);
            r_mant1 &= Self::MASK;
        } else {
            let (diff0, borrow0) = Self::sub_n(r_mant0, c_mant0);
            r_mant0 = diff0;
            r_mant1 = r_mant1.wrapping_sub(c_mant1).wrapping_sub(borrow0);
            r_mant1 &= Self::MASK;
            if (r_mant0 | r_mant1) == 0 {
                r_sign = u64::from(rm == RoundingMode::RoundDown);
            }
        }

        Self::normalize2(r_sign, r_exp, r_mant1, r_mant0, rm)
    }

    #[must_use]
    fn fma_mul_zero(
        mut r_sign: u64,
        c_sign: u64,
        c_exp: i64,
        c_mant: u64,
        rm: RoundingMode,
        c: u64,
    ) -> (u64, u8) {
        if c_exp == 0 && c_mant == 0 {
            if c_sign != r_sign {
                r_sign = u64::from(rm == RoundingMode::RoundDown);
            }
            (Self::pack(r_sign, 0, 0), 0)
        } else {
            (Self::nanbox(c), 0)
        }
    }

    #[must_use]
    fn rshift_rnd_u128(a: u128, d: i64) -> u128 {
        if d == 0 {
            a
        } else if d >= 128 {
            u128::from(a != 0)
        } else {
            let d = d as u32;
            let mask = (1u128 << d) - 1;
            (a >> d) | u128::from((a & mask) != 0)
        }
    }

    #[must_use]
    fn cvt_addend(a_sign: u64, rm: RoundingMode) -> u128 {
        match rm {
            RoundingMode::RoundNearestEven | RoundingMode::RoundNearestMagnitude => {
                1u128 << (Self::RND_SIZE - 1)
            }
            RoundingMode::RoundTowardsZero => 0,
            RoundingMode::RoundDown => {
                if a_sign != 0 {
                    (1u128 << Self::RND_SIZE) - 1
                } else {
                    0
                }
            }
            RoundingMode::RoundUp => {
                if a_sign == 0 {
                    (1u128 << Self::RND_SIZE) - 1
                } else {
                    0
                }
            }
            _ => unreachable!("Rounding mode {rm:?} shouldn't be possible here"),
        }
    }

    #[must_use]
    fn int_mask(bits: usize) -> u128 { if bits == 128 { !0 } else { (1u128 << bits) - 1 } }

    #[must_use]
    fn sign_extend(value: u128, bits: usize) -> u64 {
        let value = value & Self::int_mask(bits);
        if bits == 64 {
            value as u64
        } else {
            let sign = 1u128 << (bits - 1);
            if value & sign != 0 {
                (value | (!Self::int_mask(bits))) as u64
            } else {
                value as u64
            }
        }
    }

    #[must_use]
    fn finish_int(value: u128, bits: usize, is_unsigned: bool, is_negative: bool) -> u64 {
        let mask = Self::int_mask(bits);
        if is_unsigned {
            (value & mask) as u64
        } else if is_negative {
            Self::sign_extend((!value).wrapping_add(1) & mask, bits)
        } else {
            Self::sign_extend(value, bits)
        }
    }

    #[must_use]
    fn cvt_to_int(a: u64, rm: RoundingMode, bits: usize, is_unsigned: bool) -> (u64, u8) {
        let a = Self::unbox(a);
        let mut a_sign = Self::sign(a);
        let mut a_exp = Self::exp(a) as i64;
        let mut a_mant = Self::mant(a);

        if a_exp == Self::EXP_MASK as i64 && a_mant != 0 {
            a_sign = 0;
        }
        if a_exp == 0 {
            a_exp = 1;
        } else {
            a_mant |= 1u64 << Self::MANT_SIZE;
        }

        let mut a_mant = u128::from(a_mant) << Self::RND_SIZE;
        a_exp = a_exp - (Self::EXP_MASK / 2) as i64 - Self::MANT_SIZE as i64;

        let r_max = if is_unsigned {
            if a_sign != 0 { 0 } else { Self::int_mask(bits) }
        } else {
            (1u128 << (bits - 1)) - u128::from(a_sign ^ 1)
        };

        let overflow = |r_max| {
            (
                Self::finish_int(r_max, bits, is_unsigned, false),
                fflag::INVALIDOP,
            )
        };

        let r;
        let mut fflags = 0;
        if a_exp >= 0 {
            if a_exp <= bits as i64 - 1 - Self::MANT_SIZE as i64 {
                r = (a_mant >> Self::RND_SIZE) << a_exp;
                if r > r_max {
                    return overflow(r_max);
                }
            } else {
                return overflow(r_max);
            }
        } else {
            a_mant = Self::rshift_rnd_u128(a_mant, -a_exp);
            let addend = Self::cvt_addend(a_sign, rm);
            let rnd_bits = a_mant & ((1u128 << Self::RND_SIZE) - 1);
            a_mant = (a_mant + addend) >> Self::RND_SIZE;
            if rm == RoundingMode::RoundNearestEven && rnd_bits == (1u128 << (Self::RND_SIZE - 1)) {
                a_mant &= !1;
            }
            if a_mant > r_max {
                return overflow(r_max);
            }
            r = a_mant;
            if rnd_bits != 0 {
                fflags |= fflag::INEXACT;
            }
        }

        (Self::finish_int(r, bits, is_unsigned, a_sign != 0), fflags)
    }

    #[must_use]
    fn cvt_from_int(a: u64, rm: RoundingMode, bits: usize, is_unsigned: bool) -> (u64, u8) {
        let mask = Self::int_mask(bits);
        let value = u128::from(a) & mask;
        let sign_bit = 1u128 << (bits - 1);
        let (a_sign, mut r) = if !is_unsigned && value & sign_bit != 0 {
            (1, ((!value) + 1) & mask)
        } else {
            (0, value)
        };

        if r == 0 {
            return (Self::pack(0, 0, 0), 0);
        }

        let mut a_exp = (Self::EXP_MASK / 2) as i64 + Self::N as i64 - 2;
        let bit_len = bits - (r.leading_zeros() as usize - (128 - bits));
        let l = bit_len as i64 - (Self::N as i64 - 1);
        if l > 0 {
            let l = l as usize;
            let sticky = u128::from((r & ((1u128 << l) - 1)) != 0);
            r = (r >> l) | sticky;
            a_exp += l as i64;
        }
        Self::normalize(a_sign, a_exp, r as u64, rm)
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
        debug_assert_eq!(mant & !Self::MANT_MASK, 0);
        let shift = Self::MANT_SIZE - (63 - mant.leading_zeros() as usize);
        log::info!(
            "Normalize {} 0x{mant:x} -> shift {shift} -> new mantissa {:x}",
            Self::N,
            mant << shift
        );
        (1 - shift as i64, (mant << shift) & Self::MANT_MASK)
    }

    #[must_use]
    fn normalize_subnormal_full(mant: u64) -> (i64, u64) {
        debug_assert_eq!(mant & !Self::MANT_MASK, 0);
        let shift = Self::MANT_SIZE - (Self::N - 1 - Self::clz(mant));
        (1 - shift as i64, mant << shift)
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
        let (a, b) = (Self::unbox(a), Self::unbox(b));
        let fflags = if Self::is_signan(a) || Self::is_signan(b) {
            fflag::INVALIDOP
        } else {
            0
        };
        let r = if Self::is_nan(a) {
            if Self::is_nan(b) {
                Self::qnan()
            } else {
                Self::nanbox(b)
            }
        } else if Self::is_nan(b) {
            Self::nanbox(a)
        } else {
            let a_sign = Self::sign(a);
            let b_sign = Self::sign(b);
            if a_sign != b_sign {
                if a_sign != 0 {
                    Self::nanbox(a)
                } else {
                    Self::nanbox(b)
                }
            } else if (a < b) ^ (a_sign != 0) {
                Self::nanbox(a)
            } else {
                Self::nanbox(b)
            }
        };

        (r, fflags)
    }

    #[must_use]
    fn max(a: u64, b: u64) -> (u64, u8)
    where
        <Self as Sf>::F: PartialOrd,
    {
        let (a, b) = (Self::unbox(a), Self::unbox(b));
        let fflags = if Self::is_signan(a) || Self::is_signan(b) {
            fflag::INVALIDOP
        } else {
            0
        };
        let r = if Self::is_nan(a) {
            if Self::is_nan(b) {
                Self::qnan()
            } else {
                Self::nanbox(b)
            }
        } else if Self::is_nan(b) {
            Self::nanbox(a)
        } else {
            let a_sign = Self::sign(a);
            let b_sign = Self::sign(b);
            if a_sign != b_sign {
                if a_sign != 0 {
                    Self::nanbox(b)
                } else {
                    Self::nanbox(a)
                }
            } else if (a < b) ^ (a_sign != 0) {
                Self::nanbox(b)
            } else {
                Self::nanbox(a)
            }
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

impl Sf for Sf16 {
    type F = u16; // raw bits — no native f16 in stable Rust

    const N: usize = 16;
    const MANT_SIZE: usize = 10;
    const EXP_SIZE: usize = 5;
    const QNAN: u64 = 0x7E00;
    // Override defaults that assume N is 32 or 64
    const MASK: u64 = 0xFFFF;
    const MASKSIGN: u64 = 0x7FFF;

    fn from_float(x: u16) -> u64 { NAN_BOX_F16 | u64::from(x) }
    #[allow(clippy::cast_possible_truncation)]
    fn to_float(x: u64) -> u16 { Self::unbox(x) as u16 }

    fn unbox(r: u64) -> u64 {
        if (r & NAN_BOX_F16) == NAN_BOX_F16 {
            r & 0xFFFF
        } else {
            Self::QNAN
        }
    }

    fn nanbox(r: u64) -> u64 { r | NAN_BOX_F16 }
}

// f16 → f32 (widening, always exact)
#[must_use]
pub fn fcvt_s_h(a: u64) -> (u64, u8) {
    let a = Sf16::unbox(a);
    let sign = Sf16::sign(a);
    let exp16 = Sf16::exp(a);
    let mant16 = Sf16::mant(a);

    if exp16 == Sf16::EXP_MASK {
        if mant16 != 0 {
            let fflags = if Sf16::is_signan(a) {
                fflag::INVALIDOP
            } else {
                0
            };
            return (
                Sf32::pack(sign, Sf32::EXP_MASK, Sf32::QNAN_MASK | (mant16 << 13)),
                fflags,
            );
        }
        return (Sf32::pack(sign, Sf32::EXP_MASK, 0), 0);
    }
    if exp16 == 0 {
        if mant16 == 0 {
            return (Sf32::pack(sign, 0, 0), 0);
        }
        // subnormal f16 → normal f32
        let (exp_adj, norm_mant) = Sf16::normalize_subnormal(mant16);
        let exp32 = (exp_adj - 15 + 127) as u64;
        let mant32 = norm_mant << (Sf32::MANT_SIZE - Sf16::MANT_SIZE);
        return (Sf32::pack(sign, exp32, mant32), 0);
    }
    let exp32 = exp16 - 15 + 127;
    let mant32 = mant16 << (Sf32::MANT_SIZE - Sf16::MANT_SIZE);
    (Sf32::pack(sign, exp32, mant32), 0)
}

// f32 → f16 (narrowing, may lose precision)
#[must_use]
pub fn fcvt_h_s(a: u64, rm: RoundingMode) -> (u64, u8) {
    let a = Sf32::unbox(a);
    let sign = Sf32::sign(a);
    let exp32 = Sf32::exp(a);
    let mant32 = Sf32::mant(a);

    if Sf32::is_nan(a) {
        let fflags = if Sf32::is_signan(a) {
            fflag::INVALIDOP
        } else {
            0
        };
        return (Sf16::nanbox(Sf16::QNAN), fflags);
    }
    if exp32 == Sf32::EXP_MASK {
        return (Sf16::pack(sign, Sf16::EXP_MASK, 0), 0);
    }
    if exp32 == 0 && mant32 == 0 {
        return (Sf16::pack(sign, 0, 0), 0);
    }

    let (a_exp, a_mant_full) = if exp32 == 0 {
        let (adj_exp, norm_mant) = Sf32::normalize_subnormal(mant32);
        (adj_exp - 127 + 15, (1u64 << Sf32::MANT_SIZE) | norm_mant)
    } else {
        (exp32 as i64 - 127 + 15, (1u64 << Sf32::MANT_SIZE) | mant32)
    };

    // Shift 24-bit f32 mantissa (MSB at bit 23) right to 15-bit Sf16 form (MSB at
    // bit 14). shift = 23 - 14 = 9; lower 9 bits collapse into sticky LSB.
    let shift = Sf32::MANT_SIZE - Sf16::IMANT_SIZE;
    let mask = (1u64 << shift) - 1;
    let a_mant = (a_mant_full >> shift) | u64::from((a_mant_full & mask) != 0);
    Sf16::normalize(sign, a_exp, a_mant, rm)
}

// f16 → f64 (widening, always exact)
#[must_use]
pub fn fcvt_d_h(a: u64) -> (u64, u8) {
    let a = Sf16::unbox(a);
    let sign = Sf16::sign(a);
    let exp16 = Sf16::exp(a);
    let mant16 = Sf16::mant(a);

    if exp16 == Sf16::EXP_MASK {
        if mant16 != 0 {
            let fflags = if Sf16::is_signan(a) {
                fflag::INVALIDOP
            } else {
                0
            };
            return (
                Sf64::pack(sign, Sf64::EXP_MASK, Sf64::QNAN_MASK | (mant16 << 42)),
                fflags,
            );
        }
        return (Sf64::pack(sign, Sf64::EXP_MASK, 0), 0);
    }
    if exp16 == 0 {
        if mant16 == 0 {
            return (Sf64::pack(sign, 0, 0), 0);
        }
        let (exp_adj, norm_mant) = Sf16::normalize_subnormal(mant16);
        let exp64 = (exp_adj - 15 + 1023) as u64;
        let mant64 = norm_mant << (Sf64::MANT_SIZE - Sf16::MANT_SIZE);
        return (Sf64::pack(sign, exp64, mant64), 0);
    }
    let exp64 = exp16 - 15 + 1023;
    let mant64 = mant16 << (Sf64::MANT_SIZE - Sf16::MANT_SIZE);
    (Sf64::pack(sign, exp64, mant64), 0)
}

// f64 → f16 (narrowing, may lose precision)
#[must_use]
pub fn fcvt_h_d(a: u64, rm: RoundingMode) -> (u64, u8) {
    let a = Sf64::unbox(a);
    let sign = Sf64::sign(a);
    let exp64 = Sf64::exp(a);
    let mant64 = Sf64::mant(a);

    if Sf64::is_nan(a) {
        let fflags = if Sf64::is_signan(a) {
            fflag::INVALIDOP
        } else {
            0
        };
        return (Sf16::nanbox(Sf16::QNAN), fflags);
    }
    if exp64 == Sf64::EXP_MASK {
        return (Sf16::pack(sign, Sf16::EXP_MASK, 0), 0);
    }
    if exp64 == 0 && mant64 == 0 {
        return (Sf16::pack(sign, 0, 0), 0);
    }

    let (a_exp, a_mant_full) = if exp64 == 0 {
        let (adj_exp, norm_mant) = Sf64::normalize_subnormal(mant64);
        (adj_exp - 1023 + 15, (1u64 << Sf64::MANT_SIZE) | norm_mant)
    } else {
        (exp64 as i64 - 1023 + 15, (1u64 << Sf64::MANT_SIZE) | mant64)
    };

    // Shift 53-bit f64 mantissa (MSB at bit 52) right to 15-bit Sf16 form (MSB at
    // bit 14). shift = 52 - 14 = 38; lower 38 bits collapse into sticky LSB.
    let shift = Sf64::MANT_SIZE - Sf16::IMANT_SIZE;
    let mask = (1u64 << shift) - 1;
    let a_mant = (a_mant_full >> shift) | u64::from((a_mant_full & mask) != 0);
    Sf16::normalize(sign, a_exp, a_mant, rm)
}

#[must_use]
pub fn fcvt_d_s(a: u64) -> (u64, u8) {
    let a = Sf32::unbox(a);

    let a_mant = Sf32::mant(a);
    let a_exp = Sf32::exp(a);
    let a_sign = Sf32::sign(a);

    if Sf32::is_nan(a) {
        if Sf32::is_signan(a) {
            (Sf64::qnan(), fflag::INVALIDOP)
        } else {
            (Sf64::qnan(), 0)
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

#[must_use]
pub fn fcvt_s_d(a: u64, rm: RoundingMode) -> (u64, u8) {
    let a = Sf64::unbox(a);
    let a_sign = Sf64::sign(a);
    let mut a_exp = Sf64::exp(a) as i64;
    let mut a_mant = Sf64::mant(a);

    if a_exp == Sf64::EXP_MASK as i64 {
        if a_mant != 0 {
            let fflags = if Sf64::is_signan(a) {
                fflag::INVALIDOP
            } else {
                0
            };
            return (Sf32::qnan(), fflags);
        }
        return (Sf32::pack(a_sign, Sf32::EXP_MASK, 0), 0);
    }
    if a_exp == 0 {
        if a_mant == 0 {
            return (Sf32::pack(a_sign, 0, 0), 0);
        }
        (a_exp, a_mant) = Sf64::normalize_subnormal_full(a_mant);
    } else {
        a_mant |= 1u64 << Sf64::MANT_SIZE;
    }

    a_exp = a_exp - (Sf64::EXP_MASK / 2) as i64 + (Sf32::EXP_MASK / 2) as i64;
    a_mant = Sf64::rshift_rnd(a_mant, (Sf64::MANT_SIZE - Sf32::IMANT_SIZE) as i64);
    Sf32::normalize(a_sign, a_exp, a_mant, rm)
}

// i64 -> f32
#[must_use]
pub fn cvt_i64_sf32(a: u64, rm: RoundingMode) -> (u64, u8) { Sf32::cvt_from_int(a, rm, 64, false) }

// u64 -> f32
#[must_use]
pub fn cvt_u64_sf32(a: u64, rm: RoundingMode) -> (u64, u8) { Sf32::cvt_from_int(a, rm, 64, true) }

// u32 -> f32
#[must_use]
pub fn cvt_u32_sf32(a: u64, rm: RoundingMode) -> (u64, u8) { Sf32::cvt_from_int(a, rm, 32, true) }

// i32 -> f32
#[must_use]
pub fn cvt_i32_sf32(a: u64, rm: RoundingMode) -> (u64, u8) { Sf32::cvt_from_int(a, rm, 32, false) }

#[must_use]
pub fn cvt_sf32_i32(a: u64, rm: RoundingMode) -> (u64, u8) { Sf32::cvt_to_int(a, rm, 32, false) }

#[must_use]
pub fn cvt_sf32_u32(a: u64, rm: RoundingMode) -> (u64, u8) { Sf32::cvt_to_int(a, rm, 32, true) }

#[must_use]
pub fn cvt_sf32_i64(a: u64, rm: RoundingMode) -> (u64, u8) { Sf32::cvt_to_int(a, rm, 64, false) }

#[must_use]
pub fn cvt_sf32_u64(a: u64, rm: RoundingMode) -> (u64, u8) { Sf32::cvt_to_int(a, rm, 64, true) }

#[must_use]
pub fn cvt_i32_sf64(a: u64, rm: RoundingMode) -> (u64, u8) { Sf64::cvt_from_int(a, rm, 32, false) }

#[must_use]
pub fn cvt_u32_sf64(a: u64, rm: RoundingMode) -> (u64, u8) { Sf64::cvt_from_int(a, rm, 32, true) }

#[must_use]
pub fn cvt_i64_sf64(a: u64, rm: RoundingMode) -> (u64, u8) { Sf64::cvt_from_int(a, rm, 64, false) }

#[must_use]
pub fn cvt_u64_sf64(a: u64, rm: RoundingMode) -> (u64, u8) { Sf64::cvt_from_int(a, rm, 64, true) }

#[must_use]
pub fn cvt_sf64_i32(a: u64, rm: RoundingMode) -> (u64, u8) { Sf64::cvt_to_int(a, rm, 32, false) }

#[must_use]
pub fn cvt_sf64_u32(a: u64, rm: RoundingMode) -> (u64, u8) { Sf64::cvt_to_int(a, rm, 32, true) }

#[must_use]
pub fn cvt_sf64_i64(a: u64, rm: RoundingMode) -> (u64, u8) { Sf64::cvt_to_int(a, rm, 64, false) }

#[must_use]
pub fn cvt_sf64_u64(a: u64, rm: RoundingMode) -> (u64, u8) { Sf64::cvt_to_int(a, rm, 64, true) }

#[cfg(test)]
mod tests;
