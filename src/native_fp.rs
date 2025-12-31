/// Small simple module to capture the native floating point exception flags
/// from operations The returned flags are in the RISC-V order, translated from
/// the native one.
use std::os::raw::c_int;

#[cfg(not(target_arch = "wasm32"))]
#[link(name = "m")]
#[cfg(not(target_arch = "wasm32"))]
unsafe extern "C" {
    fn feclearexcept(excepts: c_int) -> c_int;
    fn fetestexcept(excepts: c_int) -> c_int;
}

// *Bit position*, not the value
// fenv         x86 [1]  macOS/Arm64 [2]  RISC-V [3]
// DIVBYZERO     2       1                3
// INEXCEPT      5       4                0
// INVALID       0       0                4
// OVERFLOW      3       2                2
// UNDERFLOW     4       3                1
//
// [1] /usr/include/x86_64-linux-gnu/bits/fenv.h
// [2] /Library/Developer/CommandLineTools/SDKs/MacOSX26.2.sdk/usr/include/fenv.
// h:136 [3] https://docs.riscv.org/reference/isa/unpriv/f-st-ext.html

#[cfg(target_arch = "x86_64")]
const FE_DIVBYZERO: c_int = 0x04;
#[cfg(target_arch = "x86_64")]
const FE_INEXACT: c_int = 0x20;
#[cfg(target_arch = "x86_64")]
const FE_INVALID: c_int = 0x01;
#[cfg(target_arch = "x86_64")]
const FE_OVERFLOW: c_int = 0x08;
#[cfg(target_arch = "x86_64")]
const FE_UNDERFLOW: c_int = 0x10;

#[cfg(target_arch = "aarch64")]
const FE_DIVBYZERO: c_int = 0x02;
#[cfg(target_arch = "aarch64")]
const FE_INEXACT: c_int = 0x10;
#[cfg(target_arch = "aarch64")]
const FE_INVALID: c_int = 0x01;
#[cfg(target_arch = "aarch64")]
const FE_OVERFLOW: c_int = 0x04;
#[cfg(target_arch = "aarch64")]
const FE_UNDERFLOW: c_int = 0x08;

#[cfg(target_arch = "wasm32")]
const FE_DIVBYZERO: c_int = 0x02;
#[cfg(target_arch = "wasm32")]
const FE_INEXACT: c_int = 0x10;
#[cfg(target_arch = "wasm32")]
const FE_INVALID: c_int = 0x01;
#[cfg(target_arch = "wasm32")]
const FE_OVERFLOW: c_int = 0x04;
#[cfg(target_arch = "wasm32")]
const FE_UNDERFLOW: c_int = 0x08;

#[cfg(not(target_arch = "wasm32"))]
const FE_ALL_EXCEPT: c_int = FE_INVALID | FE_DIVBYZERO | FE_OVERFLOW | FE_UNDERFLOW | FE_INEXACT;

pub fn fflags_clear() {
    #[cfg(not(target_arch = "wasm32"))]
    unsafe {
        feclearexcept(FE_ALL_EXCEPT)
    };
}
#[must_use]
pub fn fflags_raised() -> u8 {
    #[cfg(target_arch = "wasm32")]
    let raised = 0;
    #[cfg(not(target_arch = "wasm32"))]
    let raised = unsafe { fetestexcept(FE_ALL_EXCEPT) };

    let mut fflags = 0;
    if raised & FE_INVALID != 0 {
        fflags |= 16;
    }
    if raised & FE_DIVBYZERO != 0 {
        fflags |= 8;
    }
    if raised & FE_OVERFLOW != 0 {
        fflags |= 4;
    }
    if raised & FE_UNDERFLOW != 0 {
        fflags |= 2;
    }
    if raised & FE_INEXACT != 0 {
        fflags |= 1;
    }
    fflags
}
