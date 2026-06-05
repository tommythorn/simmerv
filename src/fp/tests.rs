use super::*;

fn test(
    f: impl Fn(u64, u64, RoundingMode) -> (u64, u8),
    f1: u64,
    f2: u64,
    rm: RoundingMode,
    wantr: u64,
    wantfflag: u8,
) {
    let (r, fflag) = f(f1, f2, rm);
    assert_eq!(
        (wantr, /* wantfflag */ 0), // XXX We'll get to the flags
        (r, /* fflag */ 0),
        "{f1:08x}, {f2:08x}, {} -> ({r:08x}, {fflag}) / ({wantr:08x}, {wantfflag})",
        rm as usize
    );
}

fn test_bool(f: impl Fn(u64, u64) -> (u64, u8), f1: u64, f2: u64, wantr: bool, wantfflag: u8) {
    let (r, fflag) = f(f1, f2);
    assert_eq!(
        (wantr as u64, wantfflag),
        (r, fflag),
        "{f1:08x}, {f2:08x} -> ({r}, {fflag:0x}) / ({wantr}, {wantfflag:0x})",
    );
}

fn test_wf(got: (u64, u8), want: (u64, u8)) {
    assert_eq!(
        want, got,
        "got ({:016x}, {:02x}) want ({:016x}, {:02x})",
        got.0, got.1, want.0, want.1
    );
}

// Convert John's representation to RISC-V NaN-boxed floats
const fn fp32(sign: u64, exp: u64, mant: u64) -> u64 {
    NAN_BOX_F32 | (sign << 31) | (exp << 23) | mant
}

const fn fp64(sign: u64, exp: u64, mant: u64) -> u64 { (sign << 63) | (exp << 52) | mant }

/*    fn fp64(sign: u64, exp: u64, mant: u64) -> u64 {
sign << 63 | exp << 52 | mant
    }*/

#[test]
fn test_feq64() {
    // Errors found in f64_eq:
    // -47E.10000000000FF  +7FF.4F3D114AF58E4  => 0 .....  expected 0 v....
    test_bool(
        Sf64::feq,
        fp64(1, 0x47E, 0x10000000000FF),
        fp64(0, 0x7FF, 0x4F3D114AF58E4),
        false,
        0x10,
    );
    test_bool(
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
    test_bool(
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
    test_bool(
        Sf32::fle,
        fp32(0, 0x7F, 0x7E0000),
        fp32(1, 0xFF, 0x7FFF7F),
        false,
        0x10,
    );
    test_bool(
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
    test_bool(
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
    test_bool(
        Sf32::flt,
        fp32(1, 0x00, 0x000001),
        fp32(0, 0x7D, 0x7FFFFF),
        true,
        0,
    );
    test_bool(
        Sf32::flt,
        fp32(0, 0x7E, 0x7FC000),
        fp32(0, 0xFF, 0x008000),
        false,
        0x10,
    );
    test_bool(
        Sf32::flt,
        fp32(0, 0x97, 0x7BFFFF),
        fp32(1, 0xFD, 0x000008),
        false,
        0,
    );
    test_bool(
        Sf32::flt,
        fp32(0, 0xFF, 0x080000),
        fp32(1, 0x7F, 0x7FFF7F),
        false,
        0x10,
    );
    test_bool(
        Sf32::flt,
        fp32(0, 0x67, 0x7FFE7F),
        fp32(0, 0xFD, 0x003FC0),
        true,
        0,
    );
    test_bool(
        Sf32::flt,
        fp32(1, 0xFF, 0x7FFFFC),
        fp32(0, 0xFE, 0x7FE000),
        false,
        0x10,
    );
}

#[test]
fn test_f32_add() {
    let pairs = [(0.0, 0.0), (1.0, 1.0), (1.0, 2.0)];
    for (a, b) in pairs {
        test(
            Sf32::fadd,
            Sf32::from_float(a),
            Sf32::from_float(b),
            RoundingMode::RoundNearestEven,
            Sf32::from_float(a + b),
            0,
        );
    }
}

#[test]
fn test_fadd() {
    test(
        Sf64::fadd,
        0x2b50000200000020,
        0xbca0000000000000,
        RoundingMode::RoundNearestEven,
        0xbca0000000000000,
        1,
    );
}

#[test]
fn test_translated_mul_div_sqrt_fma32() {
    test_wf(
        Sf32::fmul(
            Sf32::from_float(2.0),
            Sf32::from_float(3.0),
            RoundingMode::RoundNearestEven,
        ),
        (Sf32::from_float(6.0), 0),
    );
    test_wf(
        Sf32::fdiv(
            Sf32::from_float(1.0),
            Sf32::from_float(0.0),
            RoundingMode::RoundNearestEven,
        ),
        (fp32(0, 0xff, 0), fflag::DIVIDEZERO),
    );
    test_wf(
        Sf32::fsqrt(Sf32::from_float(-1.0), RoundingMode::RoundNearestEven),
        (NAN_BOX_F32 | Sf32::QNAN, fflag::INVALIDOP),
    );
    test_wf(
        Sf32::fma(
            Sf32::from_float(2.0),
            Sf32::from_float(3.0),
            Sf32::from_float(4.0),
            RoundingMode::RoundNearestEven,
        ),
        (Sf32::from_float(10.0), 0),
    );
}

#[test]
fn test_translated_conversions() {
    test_wf(
        cvt_i64_sf32(16_777_217, RoundingMode::RoundNearestEven),
        (Sf32::from_float(16_777_216.0), fflag::INEXACT),
    );
    test_wf(
        cvt_i64_sf32(16_777_217, RoundingMode::RoundNearestMagnitude),
        (Sf32::from_float(16_777_218.0), fflag::INEXACT),
    );
    test_wf(
        cvt_sf32_i32(NAN_BOX_F32 | Sf32::QNAN, RoundingMode::RoundNearestEven),
        (0x7fff_ffff, fflag::INVALIDOP),
    );
    test_wf(
        cvt_sf32_u32(fp32(0, 0x80, 0x20003f), RoundingMode::RoundTowardsZero),
        (2, fflag::INEXACT),
    );
    test_wf(
        cvt_sf32_u64(fp32(0, 0x7e, 0x000001), RoundingMode::RoundTowardsZero),
        (0, fflag::INEXACT),
    );
    test_wf(
        cvt_sf32_i32(fp32(1, 0x7e, 0x6e138c), RoundingMode::RoundTowardsZero),
        (0, fflag::INEXACT),
    );
    test_wf(
        fcvt_s_d(f64::MAX.to_bits(), RoundingMode::RoundNearestEven),
        (fp32(0, 0xff, 0), fflag::OVERFLOW | fflag::INEXACT),
    );
}

#[test]
fn test_min_max_nanbox_zero32() {
    test_wf(
        Sf32::min(Sf32::from_float(0.0), Sf32::from_float(-0.0)),
        (Sf32::from_float(-0.0), 0),
    );
    test_wf(
        Sf32::max(Sf32::from_float(0.0), Sf32::from_float(-0.0)),
        (Sf32::from_float(0.0), 0),
    );
}

#[test]
fn test_fclass_unboxed32_is_qnan() {
    assert_eq!(Sf32::fclass(0), Fclass::Qnan);
}
