//! RISC-V floating point

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

pub const MANT_SIZE32: usize = 23;
pub const EXP_SIZE32: usize = 8;
pub const EXP_MASK32: u32 = (1 << EXP_SIZE32) - 1;
pub const MANT_MASK32: u32 = (1 << MANT_SIZE32) - 1;
//pub const SIGN_MASK32: u32 = 1 << (32 - 1);
//pub const IMANT_SIZE32: usize = 32 - 2; /* internal mantissa size */
//pub const RND_SIZE32: usize = IMANT_SIZE32 - MANT_SIZE32;
pub const QNAN_MASK32: u32 = 1 << (MANT_SIZE32 - 1);
//pub const F_QNAN32 : u32 = ???; /* quiet NaN */
pub const MANT_SIZE64: usize = 52;
pub const EXP_SIZE64: usize = 11;
pub const EXP_MASK64: u64 = (1 << EXP_SIZE64) - 1;
pub const MANT_MASK64: u64 = (1 << MANT_SIZE64) - 1;
//pub const SIGN_MASK64: u64 = 1 << (64 - 1);
//pub const IMANT_SIZE64: usize = 64 - 2; /* internal mantissa size */
//pub const RND_SIZE64: usize = IMANT_SIZE64 - MANT_SIZE64;
pub const QNAN_MASK64: u64 = 1 << (MANT_SIZE64 - 1);
//pub const F_QNA64: u64 = ????;/* quiet NaN */
pub const fn fclass_f32(a: u32) -> Fclass {
    let a_sign = a >> (32 - 1);
    let a_exp = (a >> MANT_SIZE32) & EXP_MASK32;
    let a_mant = a & MANT_MASK32;
    if a_exp == EXP_MASK32 {
        if a_mant != 0 {
            if a_mant & QNAN_MASK32 != 0 {
                Fclass::Qnan
            } else {
                Fclass::Snan
            }
        } else if a_sign != 0 {
            Fclass::Ninf
        } else {
            Fclass::Pinf
        }
    } else if a_exp == 0 {
        if a_mant == 0 {
            if a_sign != 0 {
                Fclass::Nzero
            } else {
                Fclass::Pzero
            }
        } else if a_sign != 0 {
            Fclass::Nsubnormal
        } else {
            Fclass::Psubnormal
        }
    } else if a_sign != 0 {
        Fclass::Nnormal
    } else {
        Fclass::Pnormal
    }
}

#[allow(clippy::cast_sign_loss)]
pub const fn fclass_f64(a: i64) -> Fclass {
    let a = a as u64;
    let a_sign = a >> (64 - 1);
    let a_exp = (a >> MANT_SIZE64) & EXP_MASK64;
    let a_mant = a & MANT_MASK64;
    if a_exp == EXP_MASK64 {
        if a_mant != 0 {
            if a_mant & QNAN_MASK64 != 0 {
                Fclass::Qnan
            } else {
                Fclass::Snan
            }
        } else if a_sign != 0 {
            Fclass::Ninf
        } else {
            Fclass::Pinf
        }
    } else if a_exp == 0 {
        if a_mant == 0 {
            if a_sign != 0 {
                Fclass::Nzero
            } else {
                Fclass::Pzero
            }
        } else if a_sign != 0 {
            Fclass::Nsubnormal
        } else {
            Fclass::Psubnormal
        }
    } else if a_sign != 0 {
        Fclass::Nnormal
    } else {
        Fclass::Pnormal
    }
}
