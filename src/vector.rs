//! The RISC-V "V" vector extension, version 1.0.
//!
//! # Shape of the implementation
//!
//! V has roughly 400 instructions packed into a dense `funct6` × `funct3`
//! space, all sharing a handful of operand layouts.  Rather than give each one
//! an `Op` variant (which would bloat the generated dispatch table by an order
//! of magnitude for no benefit), the decoder classifies a vector instruction
//! into one of eighteen encoding groups, stashes the raw instruction word in
//! `Uop::imm`, and this module does the `funct6` dispatch.  The scalar operands
//! (`rs1`/`rd`) are still named in the `Uop` so the generic register plumbing
//! in `Cpu::step_block` keeps working; everything else is pulled out of the
//! word.
//!
//! # Parameters
//!
//! `VLEN` = 128 and `ELEN` = 64, that is `Zvl128b` + `Zve64d` — the minimum an
//! RVA23U64 hart may implement, and the same geometry QEMU's `rv64,v=true`
//! default uses, which makes differential testing straightforward.
//!
//! # Choices the specification leaves open
//!
//! * **Tail and mask agnostic policy** (`vta`/`vma`): agnostic elements are
//!   left *undisturbed*.  The specification allows an implementation to write
//!   either all-ones or the old value for agnostic elements; leaving them alone
//!   is the cheaper and more reproducible of the two.
//! * **`vstart`**: maintained exactly — a trapping element-wise memory access
//!   records the element index, and every instruction that completes resets it.
//! * **Reserved-encoding checks**: `vill`, register-group alignment, EMUL range
//!   and the `vd`-may-not-be-`v0`-when-masked rule are enforced.  The finer
//!   source/destination overlap constraints (which no conforming assembler
//!   emits) are not; those encodings execute rather than trap.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::many_single_char_names
)]

use crate::cpu::Cpu;
use crate::cpu::Exception;
use crate::cpu::ExecOut;
use crate::fp::RoundingMode;
use crate::fp::Sf;
use crate::fp::Sf16;
use crate::fp::Sf32;
use crate::fp::Sf64;
use crate::fp::fflag;
use crate::generated_riscv_decoder::Op;
use crate::riscv::Trap;

/// Default vector register length in bits (`Zvl128b`), and the value the
/// QEMU differential test in `tests/vector/` is calibrated against.
pub const VLEN: usize = 128;
/// Default vector register length in bytes; the value read from `vlenb`.
pub const VLENB: usize = VLEN / 8;
/// Widest `VLEN` the register file is sized for.
///
/// `VLEN` is runtime state (`VectorUnit::vlenb`) so one binary can be either
/// width -- Tenstorrent's arch tests only ship a VLEN=256 build -- but the
/// register file stays a fixed array sized for the maximum, so nothing
/// allocates and no hot path gains an indirection.
pub const MAX_VLEN: usize = 256;
pub const MAX_VLENB: usize = MAX_VLEN / 8;
/// Widest supported element, in bits (`Zve64d` and up).
pub const ELEN: usize = 64;

const VREGS: usize = 32;
pub const MAX_VRF_BYTES: usize = VREGS * MAX_VLENB;

// vtype fields
const VTYPE_VILL: u64 = 1 << 63;
const VTYPE_VMA: u64 = 1 << 7;
const VTYPE_VTA: u64 = 1 << 6;
const VTYPE_VSEW: u64 = 7 << 3;
const VTYPE_VLMUL: u64 = 7;

/// The architectural vector state: the register file plus `vtype`, `vl`,
/// `vstart` and the fixed-point CSRs.  `mstatus.VS` lives next to `Cpu::fs`.
#[derive(Clone)]
pub struct VectorUnit {
    /// The 32 vector registers, flat and little-endian, so that an `LMUL > 1`
    /// register group is simply a longer run of bytes.
    pub vrf: [u8; MAX_VRF_BYTES],
    /// Bytes per vector register: `VLEN / 8`.  A power of two in
    /// `[VLENB, MAX_VLENB]`, so the register-file masking stays a single AND.
    pub vlenb: usize,
    pub vtype: u64,
    pub vl: u64,
    pub vstart: u64,
    /// Fixed-point rounding mode (`vxrm`), 2 bits.
    pub vxrm: u8,
    /// Fixed-point saturation flag (`vxsat`).
    pub vxsat: bool,
}

impl Default for VectorUnit {
    fn default() -> Self { Self::new() }
}

impl VectorUnit {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            vrf: [0; MAX_VRF_BYTES],
            vlenb: VLENB,
            // Reset leaves vtype invalid: software must execute a vset before
            // any other vector instruction.
            vtype: VTYPE_VILL,
            vl: 0,
            vstart: 0,
            vxrm: 0,
            vxsat: false,
        }
    }

    #[must_use]
    pub const fn vill(&self) -> bool { self.vtype & VTYPE_VILL != 0 }
    #[must_use]
    pub const fn vta(&self) -> bool { self.vtype & VTYPE_VTA != 0 }
    #[must_use]
    pub const fn vma(&self) -> bool { self.vtype & VTYPE_VMA != 0 }
    /// Element width in *bytes* (SEW/8).
    #[must_use]
    pub const fn sew(&self) -> usize { 1 << ((self.vtype & VTYPE_VSEW) >> 3) }
    #[must_use]
    pub const fn vlmul(&self) -> u64 { self.vtype & VTYPE_VLMUL }

    /// `vcsr` packs `vxrm` and `vxsat` into one CSR.
    #[must_use]
    pub const fn vcsr(&self) -> u64 { (self.vxrm as u64) << 1 | self.vxsat as u64 }
    pub const fn set_vcsr(&mut self, v: u64) {
        self.vxsat = v & 1 != 0;
        self.vxrm = ((v >> 1) & 3) as u8;
    }

    /// Size of the live part of the register file, in bytes.  Offsets are
    /// masked against this, so a reserved encoding naming a group that runs
    /// off the end wraps instead of reading another width's bytes.
    #[inline]
    #[must_use]
    pub const fn vrf_bytes(&self) -> usize { VREGS * self.vlenb }

    /// Read element `idx` of the register group based at `vreg`, as `ebytes`
    /// little-endian bytes zero-extended to 64 bits.
    ///
    /// The offset is masked into the register file, so a reserved encoding
    /// naming a group that runs off the end wraps instead of panicking.
    #[inline]
    #[must_use]
    pub fn eget(&self, vreg: usize, idx: usize, ebytes: usize) -> u64 {
        let o = (vreg * self.vlenb + idx * ebytes) & (self.vrf_bytes() - 1);
        let v = &self.vrf;
        match ebytes {
            1 => u64::from(v[o]),
            2 => u64::from(u16::from_le_bytes([v[o], v[o + 1]])),
            4 => u64::from(u32::from_le_bytes([v[o], v[o + 1], v[o + 2], v[o + 3]])),
            _ => u64::from_le_bytes([
                v[o],
                v[o + 1],
                v[o + 2],
                v[o + 3],
                v[o + 4],
                v[o + 5],
                v[o + 6],
                v[o + 7],
            ]),
        }
    }

    /// Write element `idx` of the register group based at `vreg`.
    #[inline]
    pub fn eset(&mut self, vreg: usize, idx: usize, ebytes: usize, val: u64) {
        let o = (vreg * self.vlenb + idx * ebytes) & (self.vrf_bytes() - 1);
        let v = &mut self.vrf;
        match ebytes {
            1 => v[o] = val as u8,
            2 => v[o..o + 2].copy_from_slice(&(val as u16).to_le_bytes()),
            4 => v[o..o + 4].copy_from_slice(&(val as u32).to_le_bytes()),
            _ => v[o..o + 8].copy_from_slice(&val.to_le_bytes()),
        }
    }

    /// Bit `idx` of mask register `vreg` (masks are always bit-per-element,
    /// packed from bit 0 of the register regardless of SEW).
    #[inline]
    #[must_use]
    pub const fn mget(&self, vreg: usize, idx: usize) -> bool {
        self.vrf[(vreg * self.vlenb + (idx >> 3)) & (self.vrf_bytes() - 1)] >> (idx & 7) & 1 != 0
    }

    #[inline]
    pub const fn mset(&mut self, vreg: usize, idx: usize, bit: bool) {
        let o = (vreg * self.vlenb + (idx >> 3)) & (self.vrf_bytes() - 1);
        let m = 1u8 << (idx & 7);
        if bit {
            self.vrf[o] |= m;
        } else {
            self.vrf[o] &= !m;
        }
    }

    /// Raw byte access, used by the whole-register moves and loads/stores.
    #[inline]
    #[must_use]
    pub const fn byte(&self, vreg: usize, off: usize) -> u8 {
        self.vrf[(vreg * self.vlenb + off) & (self.vrf_bytes() - 1)]
    }
    #[inline]
    pub const fn set_byte(&mut self, vreg: usize, off: usize, b: u8) {
        self.vrf[(vreg * self.vlenb + off) & (self.vrf_bytes() - 1)] = b;
    }
}

// ── small numeric helpers ────────────────────────────────────────────────────

/// Sign-extend the low `ebytes` bytes of `v` to a full `i64`.
#[inline]
const fn sext(v: u64, ebytes: usize) -> i64 {
    let sh = 64 - ebytes * 8;
    ((v << sh) as i64) >> sh
}

/// Truncate `v` to `ebytes` bytes (zero-extended into a `u64`).
#[inline]
const fn trunc(v: u64, ebytes: usize) -> u64 {
    if ebytes >= 8 {
        v
    } else {
        v & ((1u64 << (ebytes * 8)) - 1)
    }
}

const fn illegal() -> Exception {
    Exception {
        trap: Trap::IllegalInstruction,
        tval: 0,
    }
}

/// Number of elements a register group of `emul_num/emul_den` registers holds.
const fn vlmax_for(vlenb: usize, ebytes: usize, lmul_field: u64) -> usize {
    let per_reg = vlenb / ebytes;
    match lmul_field {
        0 => per_reg,
        1 => per_reg * 2,
        2 => per_reg * 4,
        3 => per_reg * 8,
        5 => per_reg / 8,
        6 => per_reg / 4,
        7 => per_reg / 2,
        _ => 0,
    }
}

/// Registers occupied by a group with the given LMUL encoding (fractional LMUL
/// still occupies one register).
const fn regs_for(lmul_field: u64) -> usize {
    match lmul_field {
        1 => 2,
        2 => 4,
        3 => 8,
        _ => 1,
    }
}

// ── instruction context ──────────────────────────────────────────────────────

/// The fields every vector arithmetic instruction shares, decoded once.
struct Ctx {
    vd: usize,
    vs1: usize,
    vs2: usize,
    /// The `vm` bit: true means *unmasked*.
    vm: bool,
    funct6: u32,
    /// Element size in bytes (SEW/8).
    sew: usize,
    lmul: u64,
    vl: usize,
    vstart: usize,
    vlmax: usize,
    /// The scalar operand of a `.vx`/`.vf` form, or the sign-extended
    /// immediate of a `.vi` form, truncated to SEW.  Meaningless for `.vv`.
    scalar: u64,
    /// As `scalar`, but with the `.vi` immediate *zero*-extended.  The shift
    /// and clip instructions are specified to take an unsigned immediate, and
    /// the difference is visible once SEW reaches 64: sign-extending 29 gives
    /// a shift amount of 61 rather than 29.
    scalar_u: u64,
    /// Raw scalar register value, before truncation (needed by the slides and
    /// the gather index, which are not element-width quantities).
    raw_scalar: u64,
    /// True for the `.vv`/`.vm` forms, where the second operand is a vector.
    vv: bool,
}

impl Ctx {
    #[inline]
    const fn active(&self, v: &VectorUnit, i: usize) -> bool { self.vm || v.mget(0, i) }
}

// ── entry point ──────────────────────────────────────────────────────────────

/// Execute one vector instruction.
///
/// `s1`/`s2` are the (already read) scalar source registers; the return value
/// is written back to `Uop::rd`, which is only meaningful for `vset*`,
/// `vmv.x.s`, `vcpop.m`, `vfirst.m` and `vfmv.f.s`.
pub fn execute(cpu: &mut Cpu, op: Op, insn: u32, s1: u64, s2: u64) -> ExecOut {
    // mstatus.VS = Off makes every vector instruction and vector CSR access
    // illegal, exactly like mstatus.FS does for F/D.
    if cpu.vs == 0 {
        return ExecOut::err(Trap::IllegalInstruction, 0);
    }

    let r = match op {
        Op::Vsetvli | Op::Vsetivli | Op::Vsetvl => Ok(vset(cpu, op, insn, s1, s2)),
        Op::Vload8 => vmem(cpu, insn, 1, false, s1, s2),
        Op::Vload16 => vmem(cpu, insn, 2, false, s1, s2),
        Op::Vload32 => vmem(cpu, insn, 4, false, s1, s2),
        Op::Vload64 => vmem(cpu, insn, 8, false, s1, s2),
        Op::Vstore8 => vmem(cpu, insn, 1, true, s1, s2),
        Op::Vstore16 => vmem(cpu, insn, 2, true, s1, s2),
        Op::Vstore32 => vmem(cpu, insn, 4, true, s1, s2),
        Op::Vstore64 => vmem(cpu, insn, 8, true, s1, s2),
        _ => varith(cpu, op, insn, s1),
    };

    match r {
        Ok(val) => {
            // Any vector instruction that completes leaves vstart at zero and
            // the vector state dirty.
            cpu.v.vstart = 0;
            cpu.vs = 3;
            ExecOut::ok(val)
        }
        Err(e) => ExecOut::err(e.trap, e.tval),
    }
}

// ── vsetvli / vsetivli / vsetvl ──────────────────────────────────────────────

/// Compute the `vtype` written by a `vset*`, replacing it with just `vill` if
/// the requested configuration is unsupported.
const fn legalize_vtype(vlenb: usize, vtype: u64) -> u64 {
    let lmul = vtype & VTYPE_VLMUL;
    let sew_field = (vtype & VTYPE_VSEW) >> 3;
    let reserved = vtype & !(VTYPE_VMA | VTYPE_VTA | VTYPE_VSEW | VTYPE_VLMUL);

    // vlmul=100 is reserved, SEW must be within ELEN, and the SEW/LMUL ratio
    // has to leave at least one element in the group.
    if reserved != 0
        || lmul == 4
        || (8usize << sew_field) > ELEN
        || vlmax_for(vlenb, 1 << sew_field, lmul) == 0
    {
        VTYPE_VILL
    } else {
        vtype
    }
}

fn vset(cpu: &mut Cpu, op: Op, insn: u32, s1: u64, s2: u64) -> u64 {
    let rd = (insn >> 7) & 31;
    let rs1 = (insn >> 15) & 31;

    let (avl, keep_vl) = match op {
        // vsetivli: AVL is a zero-extended 5-bit immediate in the rs1 field.
        Op::Vsetivli => (u64::from(rs1), false),
        // rs1 != x0: AVL = x[rs1].  rs1 == x0 and rd != x0: AVL = VLMAX ("set
        // to the maximum").  Both x0: keep the current vl.
        _ if rs1 != 0 => (s1, false),
        _ if rd != 0 => (u64::MAX, false),
        _ => (0, true),
    };

    let vtype = match op {
        Op::Vsetvl => s2,
        Op::Vsetivli => u64::from((insn >> 20) & 0x3ff),
        _ => u64::from((insn >> 20) & 0x7ff),
    };

    let vtype = legalize_vtype(cpu.v.vlenb, vtype);
    if vtype & VTYPE_VILL != 0 {
        cpu.v.vtype = VTYPE_VILL;
        cpu.v.vl = 0;
        return 0;
    }

    let vlmax = vlmax_for(
        cpu.v.vlenb,
        1 << ((vtype & VTYPE_VSEW) >> 3),
        vtype & VTYPE_VLMUL,
    ) as u64;
    let vl = if keep_vl {
        // rd == x0 && rs1 == x0 updates vtype but keeps vl.  (Changing VLMAX
        // with this form is a reserved use, so no clamping is called for.)
        cpu.v.vl
    } else {
        avl.min(vlmax)
    };

    cpu.v.vtype = vtype;
    cpu.v.vl = vl;
    vl
}

// ── loads and stores ─────────────────────────────────────────────────────────

/// Addressing mode of a vector load/store, from the `mop` field.
#[derive(PartialEq, Eq, Clone, Copy)]
enum Mop {
    Unit,
    Strided,
    Indexed,
}

/// Vector loads and stores: unit-stride, strided, indexed (ordered and
/// unordered — both are performed in element order here), the mask, whole
/// register and fault-only-first variants, each with an optional segment count.
fn vmem(
    cpu: &mut Cpu,
    insn: u32,
    width: usize,
    is_store: bool,
    base: u64,
    stride: u64,
) -> Result<u64, Exception> {
    let vd = ((insn >> 7) & 31) as usize;
    let lumop = (insn >> 20) & 31;
    let vm = (insn >> 25) & 1 != 0;
    let mop = (insn >> 26) & 3;
    let mew = (insn >> 28) & 1;
    let nf = ((insn >> 29) & 7) as usize + 1;

    // mew=1 encodes EEW > 64, which this hart does not implement.
    if mew != 0 {
        return Err(illegal());
    }

    let mop = match mop {
        0 => Mop::Unit,
        2 => Mop::Strided,
        _ => Mop::Indexed,
    };

    // Whole-register load/store: vl and vtype are ignored, nf registers are
    // moved verbatim.  (mop=unit, lumop=01000.)
    if mop == Mop::Unit && lumop == 0b01000 {
        if !matches!(nf, 1 | 2 | 4 | 8) || vd + nf > VREGS {
            return Err(illegal());
        }
        return whole_reg(cpu, vd, nf, base, is_store);
    }

    // vlm.v / vsm.v move ceil(vl/8) bytes of mask, EEW=8, EMUL=1.
    let mask_op = mop == Mop::Unit && lumop == 0b01011;
    if mask_op && (nf != 1 || width != 1) {
        return Err(illegal());
    }

    if cpu.v.vill() {
        return Err(illegal());
    }
    let sew = cpu.v.sew();
    let lmul = cpu.v.vlmul();

    // Fault-only-first: only the first element may fault; a fault at element
    // i > 0 truncates vl instead of trapping.
    let fof = mop == Mop::Unit && lumop == 0b10000;
    if fof && (is_store || nf > 8) {
        return Err(illegal());
    }
    if mop == Mop::Unit && !matches!(lumop, 0 | 0b01011 | 0b10000) {
        return Err(illegal());
    }

    // Data EEW: the width field for unit-stride and strided accesses, but SEW
    // for the indexed forms (where width gives the *index* width instead).
    let (deew, ieew) = if mop == Mop::Indexed {
        (sew, width)
    } else {
        (width, 0)
    };

    // EMUL = (EEW / SEW) * LMUL, expressed in the same 3-bit encoding.  A mask
    // access always moves exactly one register, whatever vtype says.
    let dregs = if mask_op {
        1
    } else {
        regs_for(scale_lmul(lmul, deew, sew).ok_or_else(illegal)?)
    };
    if vd + dregs * nf > VREGS {
        return Err(illegal());
    }
    // A masked access may not write v0 (the mask itself); stores read only.
    if !vm && !is_store && vd == 0 && !mask_op {
        return Err(illegal());
    }

    let iregs = if mop == Mop::Indexed {
        let iemul = scale_lmul(lmul, ieew, sew).ok_or_else(illegal)?;
        regs_for(iemul)
    } else {
        0
    };
    let vs2 = ((insn >> 20) & 31) as usize;
    if mop == Mop::Indexed && vs2 + iregs > VREGS {
        return Err(illegal());
    }

    // Elements to transfer, and the per-register element count of the
    // destination group (used to step from field to field of a segment).
    let evl = if mask_op {
        (cpu.v.vl as usize).div_ceil(8)
    } else {
        cpu.v.vl as usize
    };
    let ebytes = if mask_op { 1 } else { deew };
    let vstart = cpu.v.vstart as usize;

    for i in vstart..evl {
        if !vm && !mask_op && !cpu.v.mget(0, i) {
            continue;
        }
        // Offset of element i's first field from the base address.
        let eoff = match mop {
            Mop::Unit => (i * nf * ebytes) as u64,
            Mop::Strided => (i as u64).wrapping_mul(stride),
            Mop::Indexed => cpu.v.eget(vs2, i, ieew),
        };
        for j in 0..nf {
            let addr = base.wrapping_add(eoff).wrapping_add((j * ebytes) as u64);
            let vreg = vd + j * dregs;
            if is_store {
                let val = elem_of_group(&cpu.v, vreg, i, ebytes);
                if let Err(e) = cpu.memop_write_vector(addr, val, ebytes as u64) {
                    cpu.v.vstart = i as u64;
                    return Err(e);
                }
            } else {
                match cpu.memop_read_vector(addr, ebytes as u64) {
                    Ok(val) => set_elem_of_group(&mut cpu.v, vreg, i, ebytes, val),
                    Err(e) => {
                        if fof && i > 0 {
                            // Trim the vector to the elements that did fault-free.
                            cpu.v.vl = i as u64;
                            return Ok(0);
                        }
                        cpu.v.vstart = i as u64;
                        return Err(e);
                    }
                }
            }
        }
    }
    Ok(0)
}

/// Element access that walks into the following registers of a group.  (For
/// segment accesses each field is a separate group, so the index is relative to
/// the group base.)
#[inline]
fn elem_of_group(v: &VectorUnit, vreg: usize, idx: usize, ebytes: usize) -> u64 {
    v.eget(vreg, idx, ebytes)
}

#[inline]
fn set_elem_of_group(v: &mut VectorUnit, vreg: usize, idx: usize, ebytes: usize, val: u64) {
    v.eset(vreg, idx, ebytes, val);
}

/// `vl<nf>re<eew>.v` / `vs<nf>r.v`: copy `nf` whole registers to or from
/// memory, ignoring `vl`, `vtype` and the mask.
fn whole_reg(
    cpu: &mut Cpu,
    vd: usize,
    nf: usize,
    base: u64,
    is_store: bool,
) -> Result<u64, Exception> {
    let vlenb = cpu.v.vlenb;
    let total = nf * vlenb;
    let start = cpu.v.vstart as usize;
    for byte in start..total {
        let addr = base.wrapping_add(byte as u64);
        let reg = vd + byte / vlenb;
        let off = byte % vlenb;
        if is_store {
            let b = cpu.v.byte(reg, off);
            if let Err(e) = cpu.memop_write(addr, 0, u64::from(b), 1) {
                cpu.v.vstart = byte as u64;
                return Err(e);
            }
        } else {
            match cpu.memop_read(addr, 0, 1) {
                Ok(b) => cpu.v.set_byte(reg, off, b as u8),
                Err(e) => {
                    cpu.v.vstart = byte as u64;
                    return Err(e);
                }
            }
        }
    }
    Ok(0)
}

// ── arithmetic: shared plumbing ──────────────────────────────────────────────

/// The `b` operand of element `i`: the corresponding `vs1` element for a `.vv`
/// form, or the broadcast scalar/immediate otherwise.
#[inline]
fn bop(v: &VectorUnit, c: &Ctx, i: usize) -> u64 {
    if c.vv {
        v.eget(c.vs1, i, c.sew)
    } else {
        c.scalar
    }
}

/// As [`bop`], for the instructions whose immediate form is unsigned.
#[inline]
fn bop_u(v: &VectorUnit, c: &Ctx, i: usize) -> u64 {
    if c.vv {
        v.eget(c.vs1, i, c.sew)
    } else {
        c.scalar_u
    }
}

/// Element-wise loop for the unsigned-immediate operations (the shifts).
fn ew_u(cpu: &mut Cpu, c: &Ctx, mut f: impl FnMut(u64, u64) -> u64) {
    for i in c.vstart..c.vl {
        if !c.active(&cpu.v, i) {
            continue;
        }
        let a = cpu.v.eget(c.vs2, i, c.sew);
        let b = bop_u(&cpu.v, c, i);
        let r = f(a, b);
        cpu.v.eset(c.vd, i, c.sew, r);
    }
}

/// Element-wise loop over the active body, `vd[i] = f(vs2[i], b[i])`.
fn ew(cpu: &mut Cpu, c: &Ctx, mut f: impl FnMut(u64, u64) -> u64) {
    for i in c.vstart..c.vl {
        if !c.active(&cpu.v, i) {
            continue;
        }
        let a = cpu.v.eget(c.vs2, i, c.sew);
        let b = bop(&cpu.v, c, i);
        let r = f(a, b);
        cpu.v.eset(c.vd, i, c.sew, r);
    }
}

/// Element-wise loop writing a *mask* bit per element (comparisons, carries).
fn ew_mask(cpu: &mut Cpu, c: &Ctx, masked: bool, mut f: impl FnMut(u64, u64, bool) -> bool) {
    for i in c.vstart..c.vl {
        if masked && !c.active(&cpu.v, i) {
            continue;
        }
        let a = cpu.v.eget(c.vs2, i, c.sew);
        let b = bop(&cpu.v, c, i);
        // The carry/borrow input of vmadc/vmsbc, unused by comparisons.
        let carry = !c.vm && cpu.v.mget(0, i);
        let r = f(a, b, carry);
        cpu.v.mset(c.vd, i, r);
    }
}

/// The fixed-point rounding increment for `v >> d` under rounding mode `vxrm`
/// (`roundoff_unsigned` in the specification).
#[inline]
fn round_incr(v: u64, d: u32, vxrm: u8) -> u64 {
    if d == 0 {
        return 0;
    }
    let round_bit = (v >> (d - 1)) & 1;
    let sticky = u64::from(v & ((1u64 << (d - 1)) - 1) != 0);
    let lsb = (v >> d) & 1;
    match vxrm {
        0 => round_bit,                                  // rnu: round to nearest, ties up
        1 => round_bit & (sticky | lsb),                 // rne: ties to even
        2 => 0,                                          // rdn: truncate
        _ => u64::from(lsb == 0) & (round_bit | sticky), // rod: round to odd
    }
}

/// 128-bit sibling of [`round_incr`], for `vsmul`.
#[inline]
fn round_incr128(v: u128, d: u32, vxrm: u8) -> u128 {
    if d == 0 {
        return 0;
    }
    let round_bit = (v >> (d - 1)) & 1;
    let sticky = u128::from(v & ((1u128 << (d - 1)) - 1) != 0);
    let lsb = (v >> d) & 1;
    match vxrm {
        0 => round_bit,
        1 => round_bit & (sticky | lsb),
        2 => 0,
        _ => u128::from(lsb == 0) & (round_bit | sticky),
    }
}

/// Saturate a signed value into `ebytes` bytes, reporting whether it clipped.
#[inline]
const fn sat_signed(v: i128, ebytes: usize) -> (u64, bool) {
    let bits = ebytes * 8;
    let max = (1i128 << (bits - 1)) - 1;
    let min = -(1i128 << (bits - 1));
    if v > max {
        (trunc(max as u64, ebytes), true)
    } else if v < min {
        (trunc(min as u64, ebytes), true)
    } else {
        (trunc(v as u64, ebytes), false)
    }
}

/// Saturate an unsigned value into `ebytes` bytes.
#[inline]
const fn sat_unsigned(v: u128, ebytes: usize) -> (u64, bool) {
    let bits = ebytes * 8;
    let max = (1u128 << bits) - 1;
    if v > max {
        (trunc(max as u64, ebytes), true)
    } else {
        (trunc(v as u64, ebytes), false)
    }
}

/// Common entry for the arithmetic groups: build the context, run the
/// per-group reserved-encoding checks, then dispatch on `funct6`.
fn varith(cpu: &mut Cpu, op: Op, insn: u32, s1: u64) -> Result<u64, Exception> {
    if cpu.v.vill() {
        return Err(illegal());
    }

    let vm = (insn >> 25) & 1 != 0;
    let vd = ((insn >> 7) & 31) as usize;
    let vs1 = ((insn >> 15) & 31) as usize;
    let vs2 = ((insn >> 20) & 31) as usize;
    let funct6 = insn >> 26;
    let sew = cpu.v.sew();
    let lmul = cpu.v.vlmul();

    let vv = matches!(op, Op::VopIvv | Op::VopMvv | Op::VopFvv);
    let imm5 = ((insn >> 15) & 31) as u64;
    let simm5 = (((imm5 << 59) as i64) >> 59) as u64;

    let raw_scalar = match op {
        Op::VopIvi => simm5,
        Op::VopIvv | Op::VopMvv | Op::VopFvv => 0,
        _ => s1,
    };

    let c = Ctx {
        vd,
        vs1,
        vs2,
        vm,
        funct6,
        sew,
        lmul,
        vl: cpu.v.vl as usize,
        vstart: cpu.v.vstart as usize,
        vlmax: vlmax_for(cpu.v.vlenb, sew, lmul),
        scalar: trunc(raw_scalar, sew),
        scalar_u: trunc(if op == Op::VopIvi { imm5 } else { s1 }, sew),
        raw_scalar: if op == Op::VopIvi { imm5 } else { s1 },
        vv,
    };

    // Nothing to do when the starting element is past the end; vstart is still
    // cleared by the caller.
    if c.vstart >= c.vl && !matches!(op, Op::VopMvv | Op::VopFvv) {
        return Ok(0);
    }

    match op {
        Op::VopIvv | Op::VopIvx | Op::VopIvi => op_integer(cpu, &c, op),
        Op::VopMvv | Op::VopMvx => op_mvx(cpu, &c, op),
        Op::VopFvv | Op::VopFvf => op_float(cpu, &c, op),
        _ => Err(illegal()),
    }
}

// ── OPIVV / OPIVX / OPIVI ────────────────────────────────────────────────────

fn op_integer(cpu: &mut Cpu, c: &Ctx, op: Op) -> Result<u64, Exception> {
    let sew = c.sew;
    let bits = (sew * 8) as u32;
    let vv = c.vv;
    let vi = op == Op::VopIvi;
    let vxrm = cpu.v.vxrm;
    // A masked instruction with a non-mask destination may not write v0, which
    // is the mask it is reading (specification section 5.3).
    let require_vm = |_: &Cpu| {
        if !c.vm && c.vd == 0 {
            Err(illegal())
        } else {
            Ok(())
        }
    };
    let mut sat = false;

    match c.funct6 {
        // Zvbb vandn: vd = vs2 & ~vs1.  No immediate form.
        0b000001 if !vi => {
            require_vm(cpu)?;
            ew(cpu, c, |a, b| a & !b);
        }
        // Zvbb vror/vrol.  The rotate amount is taken modulo the element width.
        // vror.vi carries a *six*-bit immediate whose top bit is funct6[0], so
        // the two funct6 values are one instruction in the .vi form and two
        // different ones otherwise.
        0b010100 | 0b010101 => {
            require_vm(cpu)?;
            let rotate_left = !vi && c.funct6 == 0b010101;
            let imm_high = u64::from(vi && c.funct6 == 0b010101) << 5;
            ew(cpu, c, |a, b| {
                let n = (b | imm_high) % u64::from(bits);
                if n == 0 {
                    a
                } else if rotate_left {
                    (a << n) | (a >> (u64::from(bits) - n))
                } else {
                    (a >> n) | (a << (u64::from(bits) - n))
                }
            });
        }
        // Zvbb vwsll: zero-extend each element, then shift left into a
        // double-width destination.
        0b110101 => {
            require_vm(cpu)?;
            let wide = sew * 2;
            if wide > ELEN / 8 || scale_lmul(cpu.v.vlmul(), wide, sew).is_none() {
                return Err(illegal());
            }
            for i in c.vstart..c.vl {
                if !c.active(&cpu.v, i) {
                    continue;
                }
                let a = cpu.v.eget(c.vs2, i, sew);
                // The shift amount is masked to log2 of the *widened* width.
                let n = bop(&cpu.v, c, i) & (((wide * 8) - 1) as u64);
                cpu.v.eset(c.vd, i, wide, a << n);
            }
        }
        0b000000 => {
            require_vm(cpu)?;
            ew(cpu, c, u64::wrapping_add);
        }
        0b000010 => {
            // vsub has no immediate form
            if vi {
                return Err(illegal());
            }
            require_vm(cpu)?;
            ew(cpu, c, u64::wrapping_sub);
        }
        0b000011 => {
            // vrsub is .vx/.vi only
            if vv {
                return Err(illegal());
            }
            require_vm(cpu)?;
            ew(cpu, c, |a, b| b.wrapping_sub(a));
        }
        0b000100..=0b000111 if !vi => {
            require_vm(cpu)?;
            match c.funct6 {
                0b000100 => ew(cpu, c, u64::min), // vminu
                0b000101 => ew(cpu, c, |a, b| sext(a, sew).min(sext(b, sew)) as u64), // vmin
                0b000110 => ew(cpu, c, u64::max), // vmaxu
                _ => ew(cpu, c, |a, b| sext(a, sew).max(sext(b, sew)) as u64), // vmax
            }
        }
        0b001001 => {
            require_vm(cpu)?;
            ew(cpu, c, |a, b| a & b);
        }
        0b001010 => {
            require_vm(cpu)?;
            ew(cpu, c, |a, b| a | b);
        }
        0b001011 => {
            require_vm(cpu)?;
            ew(cpu, c, |a, b| a ^ b);
        }
        // vrgather.vv / .vx / .vi — index within the source register group
        0b001100 => {
            require_vm(cpu)?;
            let fixed = c.raw_scalar;
            for i in c.vstart..c.vl {
                if !c.active(&cpu.v, i) {
                    continue;
                }
                let idx = if vv { cpu.v.eget(c.vs1, i, sew) } else { fixed };
                let val = if idx >= c.vlmax as u64 {
                    0
                } else {
                    cpu.v.eget(c.vs2, idx as usize, sew)
                };
                cpu.v.eset(c.vd, i, sew, val);
            }
        }
        // vrgatherei16.vv (16-bit indices) / vslideup.vx / vslideup.vi
        0b001110 => {
            require_vm(cpu)?;
            if vv {
                for i in c.vstart..c.vl {
                    if !c.active(&cpu.v, i) {
                        continue;
                    }
                    let idx = cpu.v.eget(c.vs1, i, 2);
                    let val = if idx >= c.vlmax as u64 {
                        0
                    } else {
                        cpu.v.eget(c.vs2, idx as usize, sew)
                    };
                    cpu.v.eset(c.vd, i, sew, val);
                }
            } else {
                let off = c.raw_scalar;
                let start = c.vstart.max(off.min(c.vl as u64) as usize);
                for i in start..c.vl {
                    if !c.active(&cpu.v, i) {
                        continue;
                    }
                    let val = cpu.v.eget(c.vs2, i - off as usize, sew);
                    cpu.v.eset(c.vd, i, sew, val);
                }
            }
        }
        // vslidedown.vx / .vi
        0b001111 if !vv => {
            require_vm(cpu)?;
            let off = c.raw_scalar;
            for i in c.vstart..c.vl {
                if !c.active(&cpu.v, i) {
                    continue;
                }
                let src = (i as u64).saturating_add(off);
                let val = if src >= c.vlmax as u64 {
                    0
                } else {
                    cpu.v.eget(c.vs2, src as usize, sew)
                };
                cpu.v.eset(c.vd, i, sew, val);
            }
        }
        // vadc: vd[i] = vs2[i] + b + v0[i].  Always "masked" in encoding
        // (vm=0) but every body element is written.
        0b010000 if !c.vm => {
            for i in c.vstart..c.vl {
                let a = cpu.v.eget(c.vs2, i, sew);
                let b = bop(&cpu.v, c, i);
                let carry = u64::from(cpu.v.mget(0, i));
                cpu.v
                    .eset(c.vd, i, sew, a.wrapping_add(b).wrapping_add(carry));
            }
        }
        // vmadc: carry out
        0b010001 => ew_mask(cpu, c, false, |a, b, carry| {
            let s = u128::from(a) + u128::from(b) + u128::from(carry);
            s >> bits != 0
        }),
        // vsbc: vd[i] = vs2[i] - b - v0[i]
        0b010010 if !c.vm && !vi => {
            for i in c.vstart..c.vl {
                let a = cpu.v.eget(c.vs2, i, sew);
                let b = bop(&cpu.v, c, i);
                let borrow = u64::from(cpu.v.mget(0, i));
                cpu.v
                    .eset(c.vd, i, sew, a.wrapping_sub(b).wrapping_sub(borrow));
            }
        }
        // vmsbc: borrow out
        0b010011 if !vi => ew_mask(cpu, c, false, |a, b, borrow| {
            u128::from(a) < u128::from(b) + u128::from(borrow)
        }),
        // vmerge.v?m (vm=0) and vmv.v.? (vm=1)
        0b010111 => {
            if c.vm {
                ew(cpu, c, |_a, b| b);
            } else {
                for i in c.vstart..c.vl {
                    let take = cpu.v.mget(0, i);
                    let val = if take {
                        bop(&cpu.v, c, i)
                    } else {
                        cpu.v.eget(c.vs2, i, sew)
                    };
                    cpu.v.eset(c.vd, i, sew, val);
                }
            }
        }
        // Integer comparisons — all write a mask register.
        0b011000 => ew_mask(cpu, c, true, |a, b, _| a == b), // vmseq
        0b011001 => ew_mask(cpu, c, true, |a, b, _| a != b), // vmsne
        0b011010 if !vi => ew_mask(cpu, c, true, |a, b, _| a < b), // vmsltu
        0b011011 if !vi => {
            ew_mask(cpu, c, true, |a, b, _| sext(a, sew) < sext(b, sew)); // vmslt
        }
        0b011100 => ew_mask(cpu, c, true, |a, b, _| a <= b), // vmsleu
        0b011101 => ew_mask(cpu, c, true, |a, b, _| sext(a, sew) <= sext(b, sew)), // vmsle
        0b011110 if !vv => ew_mask(cpu, c, true, |a, b, _| a > b), // vmsgtu
        0b011111 if !vv => ew_mask(cpu, c, true, |a, b, _| sext(a, sew) > sext(b, sew)), // vmsgt
        // Saturating add/subtract
        0b100000 => {
            require_vm(cpu)?;
            ew(cpu, c, |a, b| {
                let (r, s) = sat_unsigned(u128::from(a) + u128::from(b), sew);
                sat |= s;
                r
            });
        }
        0b100001 => {
            require_vm(cpu)?;
            ew(cpu, c, |a, b| {
                let (r, s) = sat_signed(i128::from(sext(a, sew)) + i128::from(sext(b, sew)), sew);
                sat |= s;
                r
            });
        }
        0b100010 if !vi => {
            require_vm(cpu)?;
            ew(cpu, c, |a, b| {
                if a < b {
                    sat = true;
                    0
                } else {
                    a - b
                }
            });
        }
        0b100011 if !vi => {
            require_vm(cpu)?;
            ew(cpu, c, |a, b| {
                let (r, s) = sat_signed(i128::from(sext(a, sew)) - i128::from(sext(b, sew)), sew);
                sat |= s;
                r
            });
        }
        0b100101 => {
            require_vm(cpu)?;
            ew_u(cpu, c, |a, b| a << (b & u64::from(bits - 1)));
        }
        // vsmul (vv/vx) — signed saturating fractional multiply; the .vi
        // encoding is vmv<nr>r.v instead.
        0b100111 if !vi => {
            require_vm(cpu)?;
            ew(cpu, c, |a, b| {
                let prod = i128::from(sext(a, sew)) * i128::from(sext(b, sew));
                let inc = round_incr128(prod as u128, bits - 1, vxrm) as i128;
                let (r, s) = sat_signed((prod >> (bits - 1)) + inc, sew);
                sat |= s;
                r
            });
        }
        // vmv<nr>r.v — copy whole registers, ignoring vl/vtype/mask.
        0b100111 => {
            let nr = (c.raw_scalar + 1) as usize;
            if !matches!(nr, 1 | 2 | 4 | 8) || c.vd + nr > VREGS || c.vs2 + nr > VREGS {
                return Err(illegal());
            }
            for r in 0..nr {
                for o in 0..cpu.v.vlenb {
                    let b = cpu.v.byte(c.vs2 + r, o);
                    cpu.v.set_byte(c.vd + r, o, b);
                }
            }
        }
        0b101000 => {
            require_vm(cpu)?;
            ew_u(cpu, c, |a, b| a >> (b & u64::from(bits - 1)));
        }
        0b101001 => {
            require_vm(cpu)?;
            ew_u(cpu, c, |a, b| {
                (sext(a, sew) >> (b & u64::from(bits - 1))) as u64
            });
        }
        // vssrl / vssra — shift right with fixed-point rounding
        0b101010 => {
            require_vm(cpu)?;
            ew_u(cpu, c, |a, b| {
                let d = (b & u64::from(bits - 1)) as u32;
                (a >> d) + round_incr(a, d, vxrm)
            });
        }
        0b101011 => {
            require_vm(cpu)?;
            ew_u(cpu, c, |a, b| {
                let d = (b & u64::from(bits - 1)) as u32;
                let s = sext(a, sew);
                ((s >> d) + round_incr(a, d, vxrm) as i64) as u64
            });
        }
        // Narrowing shifts and clips: vs2 is a 2*SEW group.
        0b101100..=0b101111 => {
            require_vm(cpu)?;
            narrowing(cpu, c, vxrm, &mut sat)?;
        }
        // Widening integer reductions (vv only)
        0b110000 | 0b110001 if vv => {
            reduce_widening(cpu, c, c.funct6 == 0b110001)?;
        }
        _ => return Err(illegal()),
    }

    cpu.v.vxsat |= sat;
    Ok(0)
}

/// `vnsrl` / `vnsra` / `vnclipu` / `vnclip`: read `vs2` at 2·SEW, write `vd` at
/// SEW.
fn narrowing(cpu: &mut Cpu, c: &Ctx, vxrm: u8, sat: &mut bool) -> Result<(), Exception> {
    let sew = c.sew;
    let wide = sew * 2;
    if wide > ELEN / 8 {
        return Err(illegal());
    }
    // The source group is twice as long; make sure it exists.
    scale_lmul(c.lmul, wide, sew).ok_or_else(illegal)?;
    let wbits = (wide * 8) as u32;

    for i in c.vstart..c.vl {
        if !c.active(&cpu.v, i) {
            continue;
        }
        let a = cpu.v.eget(c.vs2, i, wide);
        let b = bop_u(&cpu.v, c, i);
        let d = (b & u64::from(wbits - 1)) as u32;
        let r = match c.funct6 {
            0b101100 => trunc(a >> d, sew),                      // vnsrl
            0b101101 => trunc((sext(a, wide) >> d) as u64, sew), // vnsra
            0b101110 => {
                // vnclipu: rounding shift then unsigned saturate
                let v = (a >> d) + round_incr(a, d, vxrm);
                let (r, s) = sat_unsigned(u128::from(v), sew);
                *sat |= s;
                r
            }
            _ => {
                // vnclip: rounding arithmetic shift then signed saturate
                let v = (sext(a, wide) >> d) + round_incr(a, d, vxrm) as i64;
                let (r, s) = sat_signed(i128::from(v), sew);
                *sat |= s;
                r
            }
        };
        cpu.v.eset(c.vd, i, sew, r);
    }
    Ok(())
}

/// `vwredsumu.vs` / `vwredsum.vs`: a 2·SEW accumulator seeded from `vs1[0]`.
fn reduce_widening(cpu: &mut Cpu, c: &Ctx, signed: bool) -> Result<(), Exception> {
    if c.vstart != 0 {
        return Err(illegal());
    }
    let sew = c.sew;
    let wide = sew * 2;
    if wide > ELEN / 8 || c.vl == 0 {
        return if wide > ELEN / 8 {
            Err(illegal())
        } else {
            Ok(())
        };
    }
    let mut acc = cpu.v.eget(c.vs1, 0, wide);
    for i in 0..c.vl {
        if !c.active(&cpu.v, i) {
            continue;
        }
        let e = cpu.v.eget(c.vs2, i, sew);
        let e = if signed { sext(e, sew) as u64 } else { e };
        acc = acc.wrapping_add(e);
    }
    cpu.v.eset(c.vd, 0, wide, acc);
    Ok(())
}

// ── OPMVV / OPMVX ────────────────────────────────────────────────────────────

fn op_mvx(cpu: &mut Cpu, c: &Ctx, op: Op) -> Result<u64, Exception> {
    let sew = c.sew;
    let bits = (sew * 8) as u32;
    let vv = op == Op::VopMvv;
    let vxrm = cpu.v.vxrm;
    let wide = sew * 2;

    // Widening forms need a destination group of 2*LMUL registers.
    let check_wide = |cpu: &Cpu| -> Result<(), Exception> {
        if wide > ELEN / 8 || scale_lmul(cpu.v.vlmul(), wide, sew).is_none() {
            Err(illegal())
        } else {
            Ok(())
        }
    };

    match c.funct6 {
        // Single-width integer reductions (vv only, `.vs` form)
        0b000000..=0b000111 if vv => {
            if c.vstart != 0 {
                return Err(illegal());
            }
            if c.vl == 0 {
                return Ok(0);
            }
            let mut acc = cpu.v.eget(c.vs1, 0, sew);
            for i in 0..c.vl {
                if !c.active(&cpu.v, i) {
                    continue;
                }
                let e = cpu.v.eget(c.vs2, i, sew);
                acc = match c.funct6 {
                    0b000000 => acc.wrapping_add(e),
                    0b000001 => acc & e,
                    0b000010 => acc | e,
                    0b000011 => acc ^ e,
                    0b000100 => acc.min(e),
                    0b000101 => sext(acc, sew).min(sext(e, sew)) as u64,
                    0b000110 => acc.max(e),
                    _ => sext(acc, sew).max(sext(e, sew)) as u64,
                };
            }
            cpu.v.eset(c.vd, 0, sew, acc);
        }
        // Averaging add/subtract: (a op b) >> 1 with fixed-point rounding.
        0b001000 => ew(cpu, c, |a, b| {
            let s = u128::from(a) + u128::from(b);
            trunc(((s >> 1) + round_incr128(s, 1, vxrm)) as u64, sew)
        }),
        0b001001 => ew(cpu, c, |a, b| {
            let s = i128::from(sext(a, sew)) + i128::from(sext(b, sew));
            trunc(
                ((s >> 1) + round_incr128(s as u128, 1, vxrm) as i128) as u64,
                sew,
            )
        }),
        0b001010 => ew(cpu, c, |a, b| {
            let s = i128::from(a) - i128::from(b);
            trunc(
                ((s >> 1) + round_incr128(s as u128, 1, vxrm) as i128) as u64,
                sew,
            )
        }),
        0b001011 => ew(cpu, c, |a, b| {
            let s = i128::from(sext(a, sew)) - i128::from(sext(b, sew));
            trunc(
                ((s >> 1) + round_incr128(s as u128, 1, vxrm) as i128) as u64,
                sew,
            )
        }),
        // vslide1up.vx / vslide1down.vx
        0b001110 if !vv => {
            for i in c.vstart..c.vl {
                if !c.active(&cpu.v, i) {
                    continue;
                }
                let val = if i == 0 {
                    c.scalar
                } else {
                    cpu.v.eget(c.vs2, i - 1, sew)
                };
                cpu.v.eset(c.vd, i, sew, val);
            }
        }
        0b001111 if !vv => {
            for i in c.vstart..c.vl {
                if !c.active(&cpu.v, i) {
                    continue;
                }
                let val = if i + 1 == c.vl {
                    c.scalar
                } else {
                    cpu.v.eget(c.vs2, i + 1, sew)
                };
                cpu.v.eset(c.vd, i, sew, val);
            }
        }
        // VWXUNARY0 (vv): scalar reads out of the vector unit
        0b010000 if vv => {
            return match c.vs1 {
                // vmv.x.s — reads element 0 regardless of vl
                0b00000 => Ok(sext(cpu.v.eget(c.vs2, 0, sew), sew) as u64),
                // vcpop.m — number of active set mask bits
                0b10000 => {
                    let mut n = 0u64;
                    for i in c.vstart..c.vl {
                        if c.active(&cpu.v, i) && cpu.v.mget(c.vs2, i) {
                            n += 1;
                        }
                    }
                    Ok(n)
                }
                // vfirst.m — index of the first active set bit, else -1
                0b10001 => {
                    for i in c.vstart..c.vl {
                        if c.active(&cpu.v, i) && cpu.v.mget(c.vs2, i) {
                            return Ok(i as u64);
                        }
                    }
                    Ok(u64::MAX)
                }
                _ => Err(illegal()),
            };
        }
        // VRXUNARY0 (vx): vmv.s.x
        0b010000 => {
            if c.vs2 != 0 {
                return Err(illegal());
            }
            if c.vl > 0 && c.vstart < c.vl {
                cpu.v.eset(c.vd, 0, sew, c.scalar);
            }
        }
        // VXUNARY0 (vv): Zvbb's bit-manipulation unaries share this group with
        // vzext/vsext, selected by the vs1 field rather than by funct6.  All of
        // them are same-width, element-wise and read only vs2.
        0b010010 if vv && matches!(c.vs1, 0b01000..=0b01010 | 0b01100..=0b01110) => {
            let vs1 = c.vs1;
            for i in c.vstart..c.vl {
                if !c.active(&cpu.v, i) {
                    continue;
                }
                let e = cpu.v.eget(c.vs2, i, sew);
                let r = match vs1 {
                    // vbrev8: reverse the bits within each byte
                    0b01000 => {
                        let mut v = 0u64;
                        for byte in 0..sew {
                            let b = ((e >> (byte * 8)) & 0xff) as u8;
                            v |= u64::from(b.reverse_bits()) << (byte * 8);
                        }
                        v
                    }
                    // vrev8: reverse the byte order within the element
                    0b01001 => {
                        let mut v = 0u64;
                        for byte in 0..sew {
                            let b = (e >> (byte * 8)) & 0xff;
                            v |= b << ((sew - 1 - byte) * 8);
                        }
                        v
                    }
                    // vbrev: reverse every bit of the element
                    0b01010 => e.reverse_bits() >> (64 - bits),
                    // vclz / vctz: counts saturate at the element width
                    0b01100 => u64::from(e.leading_zeros()) - u64::from(64 - bits),
                    0b01101 => {
                        if e == 0 {
                            u64::from(bits)
                        } else {
                            u64::from(e.trailing_zeros())
                        }
                    }
                    // vcpop
                    _ => u64::from(e.count_ones()),
                };
                cpu.v.eset(c.vd, i, sew, r);
            }
        }
        // VXUNARY0 (vv): vzext / vsext by a factor of 2, 4 or 8
        0b010010 if vv => {
            let (frac, signed) = match c.vs1 {
                0b00010 => (8usize, false),
                0b00011 => (8, true),
                0b00100 => (4, false),
                0b00101 => (4, true),
                0b00110 => (2, false),
                0b00111 => (2, true),
                _ => return Err(illegal()),
            };
            if !sew.is_multiple_of(frac) {
                return Err(illegal());
            }
            let seb = sew / frac;
            scale_lmul(c.lmul, seb, sew).ok_or_else(illegal)?;
            for i in c.vstart..c.vl {
                if !c.active(&cpu.v, i) {
                    continue;
                }
                let e = cpu.v.eget(c.vs2, i, seb);
                let e = if signed { sext(e, seb) as u64 } else { e };
                cpu.v.eset(c.vd, i, sew, e);
            }
        }
        // VMUNARY0 (vv): mask scans, viota and vid
        0b010100 if vv => {
            match c.vs1 {
                // vmsbf.m / vmsof.m / vmsif.m.  Only *active* elements take
                // part in the scan: the specification's masked example has the
                // search for the first set bit skip over inactive elements
                // entirely, not merely suppress their writeback.
                0b00001..=0b00011 => {
                    if c.vstart != 0 {
                        return Err(illegal());
                    }
                    let mut seen = false;
                    for i in 0..c.vl {
                        if !c.active(&cpu.v, i) {
                            continue;
                        }
                        let bit = cpu.v.mget(c.vs2, i);
                        let out = match c.vs1 {
                            0b00001 => !seen && !bit, // set-before-first
                            0b00010 => !seen && bit,  // set-only-first
                            _ => !seen,               // set-including-first
                        };
                        cpu.v.mset(c.vd, i, out);
                        seen |= bit;
                    }
                }
                // viota.m — prefix sum of the active mask bits
                0b10000 => {
                    if c.vstart != 0 {
                        return Err(illegal());
                    }
                    let mut n = 0u64;
                    for i in 0..c.vl {
                        let active = c.active(&cpu.v, i);
                        if active {
                            cpu.v.eset(c.vd, i, sew, n);
                        }
                        if active && cpu.v.mget(c.vs2, i) {
                            n += 1;
                        }
                    }
                }
                // vid.v — element index
                0b10001 => {
                    for i in c.vstart..c.vl {
                        if c.active(&cpu.v, i) {
                            cpu.v.eset(c.vd, i, sew, i as u64);
                        }
                    }
                }
                _ => return Err(illegal()),
            }
        }
        // vcompress.vm — pack the elements selected by vs1 down to vd[0..]
        0b010111 if vv => {
            if c.vstart != 0 || !c.vm {
                return Err(illegal());
            }
            let mut n = 0usize;
            for i in 0..c.vl {
                if cpu.v.mget(c.vs1, i) {
                    let e = cpu.v.eget(c.vs2, i, sew);
                    cpu.v.eset(c.vd, n, sew, e);
                    n += 1;
                }
            }
        }
        // Mask-register logical operations
        0b011000..=0b011111 if vv => {
            for i in c.vstart..c.vl {
                let a = cpu.v.mget(c.vs2, i);
                let b = cpu.v.mget(c.vs1, i);
                let r = match c.funct6 {
                    0b011000 => a && !b, // vmandn
                    0b011001 => a & b,   // vmand
                    0b011010 => a | b,   // vmor
                    0b011011 => a ^ b,   // vmxor
                    0b011100 => a || !b, // vmorn
                    0b011101 => !(a & b),
                    0b011110 => !(a | b),
                    _ => !(a ^ b),
                };
                cpu.v.mset(c.vd, i, r);
            }
        }
        // Integer divide, remainder and multiply
        // Division by zero yields all ones rather than trapping.
        0b100000 => ew(cpu, c, |a, b| {
            a.checked_div(b).unwrap_or_else(|| trunc(!0, sew))
        }),
        0b100001 => ew(cpu, c, |a, b| {
            let (x, y) = (sext(a, sew), sext(b, sew));
            if y == 0 { !0 } else { x.wrapping_div(y) as u64 }
        }),
        0b100010 => ew(cpu, c, |a, b| if b == 0 { a } else { a % b }),
        0b100011 => ew(cpu, c, |a, b| {
            let (x, y) = (sext(a, sew), sext(b, sew));
            if y == 0 { a } else { x.wrapping_rem(y) as u64 }
        }),
        0b100100 => ew(cpu, c, |a, b| {
            ((u128::from(a) * u128::from(b)) >> bits) as u64
        }),
        0b100101 => ew(cpu, c, u64::wrapping_mul),
        0b100110 => ew(cpu, c, |a, b| {
            ((i128::from(sext(a, sew)) * i128::from(b)) >> bits) as u64
        }),
        0b100111 => ew(cpu, c, |a, b| {
            ((i128::from(sext(a, sew)) * i128::from(sext(b, sew))) >> bits) as u64
        }),
        // Integer multiply-add, all SEW-wide, reading the destination
        0b101001 | 0b101011 | 0b101101 | 0b101111 => {
            let f6 = c.funct6;
            for i in c.vstart..c.vl {
                if !c.active(&cpu.v, i) {
                    continue;
                }
                let a = cpu.v.eget(c.vs2, i, sew);
                let b = bop(&cpu.v, c, i);
                let d = cpu.v.eget(c.vd, i, sew);
                let r = match f6 {
                    0b101001 => b.wrapping_mul(d).wrapping_add(a), // vmadd
                    0b101011 => a.wrapping_sub(b.wrapping_mul(d)), // vnmsub
                    0b101101 => d.wrapping_add(b.wrapping_mul(a)), // vmacc
                    _ => d.wrapping_sub(b.wrapping_mul(a)),        // vnmsac
                };
                cpu.v.eset(c.vd, i, sew, r);
            }
        }
        // Widening add/subtract; the `.w` forms take a 2*SEW first operand.
        0b110000..=0b110111 => {
            check_wide(cpu)?;
            let f6 = c.funct6;
            let wide_a = f6 & 0b100 != 0;
            let signed = f6 & 1 != 0;
            let sub = f6 & 0b10 != 0;
            for i in c.vstart..c.vl {
                if !c.active(&cpu.v, i) {
                    continue;
                }
                let a = if wide_a {
                    cpu.v.eget(c.vs2, i, wide)
                } else {
                    let e = cpu.v.eget(c.vs2, i, sew);
                    if signed { sext(e, sew) as u64 } else { e }
                };
                let b = bop(&cpu.v, c, i);
                let b = if signed { sext(b, sew) as u64 } else { b };
                let r = if sub {
                    a.wrapping_sub(b)
                } else {
                    a.wrapping_add(b)
                };
                cpu.v.eset(c.vd, i, wide, r);
            }
        }
        // Widening multiply and multiply-add
        0b111000 | 0b111010 | 0b111011 | 0b111100..=0b111111 => {
            check_wide(cpu)?;
            if c.funct6 == 0b111110 && vv {
                return Err(illegal()); // vwmaccus is .vx only
            }
            let f6 = c.funct6;
            for i in c.vstart..c.vl {
                if !c.active(&cpu.v, i) {
                    continue;
                }
                let a = cpu.v.eget(c.vs2, i, sew);
                let b = bop(&cpu.v, c, i);
                let (x, y): (i128, i128) = match f6 {
                    // vwmulu and vwmaccu: unsigned times unsigned
                    0b111000 | 0b111100 => (i128::from(a), i128::from(b)),
                    // vwmulsu and vwmaccus: vs2 signed, vs1/rs1 unsigned
                    0b111010 | 0b111110 => (i128::from(sext(a, sew)), i128::from(b)),
                    // vwmaccsu: vs2 unsigned, vs1 signed
                    0b111111 => (i128::from(a), i128::from(sext(b, sew))),
                    // vwmul and vwmacc: signed times signed
                    _ => (i128::from(sext(a, sew)), i128::from(sext(b, sew))),
                };
                let prod = x * y;
                let r = if f6 >= 0b111100 {
                    (i128::from(sext(cpu.v.eget(c.vd, i, wide), wide)) + prod) as u64
                } else {
                    prod as u64
                };
                cpu.v.eset(c.vd, i, wide, r);
            }
        }
        _ => return Err(illegal()),
    }

    Ok(0)
}

// ── OPFVV / OPFVF ────────────────────────────────────────────────────────────

fn op_float(cpu: &mut Cpu, c: &Ctx, op: Op) -> Result<u64, Exception> {
    // Vector floating point updates fflags, so it needs FP state enabled and a
    // usable static rounding mode, exactly like the scalar F/D instructions.
    if cpu.fs == 0 {
        return Err(illegal());
    }
    let rm = cpu.read_frm();
    if matches!(
        rm,
        RoundingMode::Reserved5 | RoundingMode::Reserved6 | RoundingMode::Dynamic
    ) {
        return Err(illegal());
    }
    match c.sew {
        2 => op_float_t::<Sf16, Sf32>(cpu, c, op, rm),
        4 => op_float_t::<Sf32, Sf64>(cpu, c, op, rm),
        // SEW=64 has no wider type; the widening opcodes reject themselves.
        8 => op_float_t::<Sf64, Sf64>(cpu, c, op, rm),
        _ => Err(illegal()),
    }
}

/// Widen one element from `T` to `W`.  Only f16→f32 and f32→f64 exist.
fn fwiden<T: Sf, W: Sf>(a: u64) -> (u64, u8) {
    match (T::N, W::N) {
        (16, 32) => crate::fp::fcvt_s_h(T::nanbox(a)),
        (32, 64) => crate::fp::fcvt_d_s(T::nanbox(a)),
        _ => (0, 0),
    }
}

/// Narrow one element from `W` to `T`.
fn fnarrow<T: Sf, W: Sf>(a: u64, rm: RoundingMode) -> (u64, u8) {
    match (T::N, W::N) {
        (16, 32) => crate::fp::fcvt_h_s(W::nanbox(a), rm),
        (32, 64) => crate::fp::fcvt_s_d(W::nanbox(a), rm),
        _ => (0, 0),
    }
}

#[allow(clippy::cognitive_complexity)]
fn op_float_t<T: Sf, W: Sf>(
    cpu: &mut Cpu,
    c: &Ctx,
    op: Op,
    rm: RoundingMode,
) -> Result<u64, Exception>
where
    T::F: PartialOrd,
    W::F: PartialOrd,
{
    let eb = T::N / 8;
    let wb = W::N / 8;
    let vv = op == Op::VopFvv;
    let widening_ok = W::N == 2 * T::N && scale_lmul(c.lmul, wb, eb).is_some();
    // The .vf operand comes from an f register, so it is NaN-unboxed to SEW.
    let fscalar = T::unbox(c.raw_scalar);
    let mut ff = 0u8;

    // vd[i] = f(vs2[i], vs1[i] or the scalar), all at SEW.
    macro_rules! fbin {
        (|$a:ident, $b:ident| $body:expr) => {{
            for i in c.vstart..c.vl {
                if !c.active(&cpu.v, i) {
                    continue;
                }
                let $a = T::nanbox(cpu.v.eget(c.vs2, i, eb));
                let $b = if vv {
                    T::nanbox(cpu.v.eget(c.vs1, i, eb))
                } else {
                    T::nanbox(fscalar)
                };
                let (r, f): (u64, u8) = $body;
                ff |= f;
                cpu.v.eset(c.vd, i, eb, trunc(r, eb));
            }
        }};
    }

    // Comparisons, which write a mask register.
    macro_rules! fcmp {
        (|$a:ident, $b:ident| $body:expr) => {{
            for i in c.vstart..c.vl {
                if !c.active(&cpu.v, i) {
                    continue;
                }
                let $a = T::nanbox(cpu.v.eget(c.vs2, i, eb));
                let $b = if vv {
                    T::nanbox(cpu.v.eget(c.vs1, i, eb))
                } else {
                    T::nanbox(fscalar)
                };
                let (r, f): (u64, u8) = $body;
                ff |= f;
                cpu.v.mset(c.vd, i, r != 0);
            }
        }};
    }

    let neg = |x: u64| x ^ T::SIGN_MASK;

    match c.funct6 {
        0b000000 => fbin!(|a, b| T::fadd(a, b, rm)),
        0b000010 => fbin!(|a, b| T::fsub(a, b, rm)),
        0b000100 => fbin!(|a, b| T::min(a, b)),
        0b000110 => fbin!(|a, b| T::max(a, b)),
        0b001000 => fbin!(|a, b| (a & !T::SIGN_MASK | b & T::SIGN_MASK, 0)),
        0b001001 => fbin!(|a, b| (a & !T::SIGN_MASK | !b & T::SIGN_MASK, 0)),
        0b001010 => fbin!(|a, b| (a ^ (b & T::SIGN_MASK), 0)),
        0b100000 => fbin!(|a, b| T::fdiv(a, b, rm)),
        0b100001 if !vv => fbin!(|a, b| T::fdiv(b, a, rm)), // vfrdiv.vf
        0b100100 => fbin!(|a, b| T::fmul(a, b, rm)),
        0b100111 if !vv => fbin!(|a, b| T::fsub(b, a, rm)), // vfrsub.vf
        // Single-width floating-point reductions
        0b000001 | 0b000011 | 0b000101 | 0b000111 if vv => {
            if c.vstart != 0 {
                return Err(illegal());
            }
            if c.vl == 0 {
                return Ok(0);
            }
            let mut acc = T::nanbox(cpu.v.eget(c.vs1, 0, eb));
            for i in 0..c.vl {
                if !c.active(&cpu.v, i) {
                    continue;
                }
                let e = T::nanbox(cpu.v.eget(c.vs2, i, eb));
                let (r, f) = match c.funct6 {
                    0b000001 | 0b000011 => T::fadd(acc, e, rm),
                    0b000101 => T::min(acc, e),
                    _ => T::max(acc, e),
                };
                ff |= f;
                acc = r;
            }
            cpu.v.eset(c.vd, 0, eb, trunc(acc, eb));
        }
        // Widening floating-point reductions
        0b110001 | 0b110011 if vv => {
            if !widening_ok {
                return Err(illegal());
            }
            if c.vstart != 0 {
                return Err(illegal());
            }
            if c.vl == 0 {
                return Ok(0);
            }
            let mut acc = W::nanbox(cpu.v.eget(c.vs1, 0, wb));
            for i in 0..c.vl {
                if !c.active(&cpu.v, i) {
                    continue;
                }
                let (e, f) = fwiden::<T, W>(cpu.v.eget(c.vs2, i, eb));
                ff |= f;
                let (r, f) = W::fadd(acc, e, rm);
                ff |= f;
                acc = r;
            }
            cpu.v.eset(c.vd, 0, wb, trunc(acc, wb));
        }
        // vfslide1up.vf / vfslide1down.vf
        0b001110 | 0b001111 if !vv => {
            let up = c.funct6 == 0b001110;
            for i in c.vstart..c.vl {
                if !c.active(&cpu.v, i) {
                    continue;
                }
                let val = if up {
                    if i == 0 {
                        fscalar
                    } else {
                        cpu.v.eget(c.vs2, i - 1, eb)
                    }
                } else if i + 1 == c.vl {
                    fscalar
                } else {
                    cpu.v.eget(c.vs2, i + 1, eb)
                };
                cpu.v.eset(c.vd, i, eb, trunc(val, eb));
            }
        }
        // vfmv.f.s (vv) and vfmv.s.f (vf)
        0b010000 => {
            if vv {
                if c.vs1 != 0 {
                    return Err(illegal());
                }
                cpu.mark_fp_dirty();
                return Ok(T::nanbox(cpu.v.eget(c.vs2, 0, eb)));
            }
            if c.vs2 != 0 {
                return Err(illegal());
            }
            if c.vl > 0 && c.vstart < c.vl {
                cpu.v.eset(c.vd, 0, eb, trunc(fscalar, eb));
            }
        }
        // VFUNARY0 — integer/float and width conversions
        0b010010 if vv => {
            fp_convert::<T, W>(cpu, c, rm, widening_ok, &mut ff)?;
        }
        // VFUNARY1 — square root, reciprocal estimates and classification
        0b010011 if vv => match c.vs1 {
            0b00000 => {
                for i in c.vstart..c.vl {
                    if !c.active(&cpu.v, i) {
                        continue;
                    }
                    let a = T::nanbox(cpu.v.eget(c.vs2, i, eb));
                    let (r, f) = T::fsqrt(a, rm);
                    ff |= f;
                    cpu.v.eset(c.vd, i, eb, trunc(r, eb));
                }
            }
            0b00100 | 0b00101 => {
                let rec = c.vs1 == 0b00101;
                for i in c.vstart..c.vl {
                    if !c.active(&cpu.v, i) {
                        continue;
                    }
                    let a = T::nanbox(cpu.v.eget(c.vs2, i, eb));
                    let (r, f) = if rec {
                        frec7::<T>(a, rm)
                    } else {
                        frsqrt7::<T>(a)
                    };
                    ff |= f;
                    cpu.v.eset(c.vd, i, eb, trunc(r, eb));
                }
            }
            0b10000 => {
                for i in c.vstart..c.vl {
                    if !c.active(&cpu.v, i) {
                        continue;
                    }
                    let a = T::nanbox(cpu.v.eget(c.vs2, i, eb));
                    cpu.v.eset(c.vd, i, eb, 1 << T::fclass(a) as usize);
                }
            }
            _ => return Err(illegal()),
        },
        // vfmerge.vfm (vm=0) / vfmv.v.f (vm=1), .vf only
        0b010111 if !vv => {
            if c.vm {
                for i in c.vstart..c.vl {
                    cpu.v.eset(c.vd, i, eb, trunc(fscalar, eb));
                }
            } else {
                for i in c.vstart..c.vl {
                    let val = if cpu.v.mget(0, i) {
                        fscalar
                    } else {
                        cpu.v.eget(c.vs2, i, eb)
                    };
                    cpu.v.eset(c.vd, i, eb, trunc(val, eb));
                }
            }
        }
        // Floating-point comparisons
        0b011000 => fcmp!(|a, b| T::feq(a, b)),
        0b011001 => fcmp!(|a, b| T::fle(a, b)),
        0b011011 => fcmp!(|a, b| T::flt(a, b)),
        0b011100 => fcmp!(|a, b| {
            let (r, f) = T::feq(a, b);
            (u64::from(r == 0), f)
        }),
        0b011101 if !vv => fcmp!(|a, b| T::flt(b, a)), // vmfgt.vf
        0b011111 if !vv => fcmp!(|a, b| T::fle(b, a)), // vmfge.vf
        // Fused multiply-add family, all SEW-wide and reading vd
        0b101000..=0b101111 => {
            let f6 = c.funct6;
            for i in c.vstart..c.vl {
                if !c.active(&cpu.v, i) {
                    continue;
                }
                let a = T::nanbox(cpu.v.eget(c.vs2, i, eb));
                let b = if vv {
                    T::nanbox(cpu.v.eget(c.vs1, i, eb))
                } else {
                    T::nanbox(fscalar)
                };
                let d = T::nanbox(cpu.v.eget(c.vd, i, eb));
                let (x, y, z) = match f6 {
                    0b101000 => (b, d, a),           // vfmadd:  +(b*d) + a
                    0b101001 => (neg(b), d, neg(a)), // vfnmadd: -(b*d) - a
                    0b101010 => (b, d, neg(a)),      // vfmsub:  +(b*d) - a
                    0b101011 => (neg(b), d, a),      // vfnmsub: -(b*d) + a
                    0b101100 => (b, a, d),           // vfmacc:  +(b*a) + d
                    0b101101 => (neg(b), a, neg(d)), // vfnmacc: -(b*a) - d
                    0b101110 => (b, a, neg(d)),      // vfmsac:  +(b*a) - d
                    _ => (neg(b), a, d),             // vfnmsac: -(b*a) + d
                };
                let (r, f) = T::fma(x, y, z, rm);
                ff |= f;
                cpu.v.eset(c.vd, i, eb, trunc(r, eb));
            }
        }
        // Widening add/subtract; the `.w` forms take a 2*SEW first operand.
        0b110000 | 0b110010 | 0b110100 | 0b110110 => {
            if !widening_ok {
                return Err(illegal());
            }
            let f6 = c.funct6;
            let wide_a = f6 & 0b100 != 0;
            let sub = f6 & 0b10 != 0;
            for i in c.vstart..c.vl {
                if !c.active(&cpu.v, i) {
                    continue;
                }
                let a = if wide_a {
                    W::nanbox(cpu.v.eget(c.vs2, i, wb))
                } else {
                    let (w, f) = fwiden::<T, W>(cpu.v.eget(c.vs2, i, eb));
                    ff |= f;
                    w
                };
                let raw_b = if vv {
                    cpu.v.eget(c.vs1, i, eb)
                } else {
                    fscalar
                };
                let (b, f) = fwiden::<T, W>(raw_b);
                ff |= f;
                let (r, f) = if sub {
                    W::fsub(a, b, rm)
                } else {
                    W::fadd(a, b, rm)
                };
                ff |= f;
                cpu.v.eset(c.vd, i, wb, trunc(r, wb));
            }
        }
        // Widening multiply and widening fused multiply-add
        0b111000 | 0b111100..=0b111111 => {
            if !widening_ok {
                return Err(illegal());
            }
            let f6 = c.funct6;
            for i in c.vstart..c.vl {
                if !c.active(&cpu.v, i) {
                    continue;
                }
                let (a, f) = fwiden::<T, W>(cpu.v.eget(c.vs2, i, eb));
                ff |= f;
                let raw_b = if vv {
                    cpu.v.eget(c.vs1, i, eb)
                } else {
                    fscalar
                };
                let (b, f) = fwiden::<T, W>(raw_b);
                ff |= f;
                let (r, f) = if f6 == 0b111000 {
                    W::fmul(a, b, rm)
                } else {
                    let d = W::nanbox(cpu.v.eget(c.vd, i, wb));
                    let nb = b ^ W::SIGN_MASK;
                    let nd = d ^ W::SIGN_MASK;
                    match f6 {
                        0b111100 => W::fma(a, b, d, rm),   // vfwmacc
                        0b111101 => W::fma(a, nb, nd, rm), // vfwnmacc
                        0b111110 => W::fma(a, b, nd, rm),  // vfwmsac
                        _ => W::fma(a, nb, d, rm),         // vfwnmsac
                    }
                };
                ff |= f;
                cpu.v.eset(c.vd, i, wb, trunc(r, wb));
            }
        }
        _ => return Err(illegal()),
    }

    if ff != 0 {
        cpu.add_to_fflags(ff);
    }
    Ok(0)
}

/// VFUNARY0: the integer↔float and float↔float conversions.
fn fp_convert<T: Sf, W: Sf>(
    cpu: &mut Cpu,
    c: &Ctx,
    rm: RoundingMode,
    widening_ok: bool,
    ff: &mut u8,
) -> Result<(), Exception>
where
    T::F: PartialOrd,
    W::F: PartialOrd,
{
    let eb = T::N / 8;
    let wb = W::N / 8;
    // Everything above 0b01000 changes width.
    let widening = (0b01000..0b10000).contains(&c.vs1);
    let narrowing = c.vs1 >= 0b10000;
    if (widening || narrowing) && !widening_ok {
        return Err(illegal());
    }

    for i in c.vstart..c.vl {
        if !c.active(&cpu.v, i) {
            continue;
        }
        let (dst_bytes, val, f) = match c.vs1 {
            // Same-width conversions
            0b00000 => (
                eb,
                T::cvt_to_int(T::nanbox(cpu.v.eget(c.vs2, i, eb)), rm, T::N, true),
                0,
            ),
            0b00001 => (
                eb,
                T::cvt_to_int(T::nanbox(cpu.v.eget(c.vs2, i, eb)), rm, T::N, false),
                0,
            ),
            0b00010 => (
                eb,
                T::cvt_from_int(cpu.v.eget(c.vs2, i, eb), rm, T::N, true),
                0,
            ),
            0b00011 => (
                eb,
                T::cvt_from_int(cpu.v.eget(c.vs2, i, eb), rm, T::N, false),
                0,
            ),
            0b00110 => (
                eb,
                T::cvt_to_int(
                    T::nanbox(cpu.v.eget(c.vs2, i, eb)),
                    RoundingMode::RoundTowardsZero,
                    T::N,
                    true,
                ),
                0,
            ),
            0b00111 => (
                eb,
                T::cvt_to_int(
                    T::nanbox(cpu.v.eget(c.vs2, i, eb)),
                    RoundingMode::RoundTowardsZero,
                    T::N,
                    false,
                ),
                0,
            ),
            // Widening: SEW source, 2*SEW destination
            0b01000 => (
                wb,
                T::cvt_to_int(T::nanbox(cpu.v.eget(c.vs2, i, eb)), rm, W::N, true),
                0,
            ),
            0b01001 => (
                wb,
                T::cvt_to_int(T::nanbox(cpu.v.eget(c.vs2, i, eb)), rm, W::N, false),
                0,
            ),
            0b01010 => (
                wb,
                W::cvt_from_int(cpu.v.eget(c.vs2, i, eb), rm, T::N, true),
                0,
            ),
            0b01011 => (
                wb,
                W::cvt_from_int(cpu.v.eget(c.vs2, i, eb), rm, T::N, false),
                0,
            ),
            0b01100 => (wb, fwiden::<T, W>(cpu.v.eget(c.vs2, i, eb)), 0),
            0b01110 => (
                wb,
                T::cvt_to_int(
                    T::nanbox(cpu.v.eget(c.vs2, i, eb)),
                    RoundingMode::RoundTowardsZero,
                    W::N,
                    true,
                ),
                0,
            ),
            0b01111 => (
                wb,
                T::cvt_to_int(
                    T::nanbox(cpu.v.eget(c.vs2, i, eb)),
                    RoundingMode::RoundTowardsZero,
                    W::N,
                    false,
                ),
                0,
            ),
            // Narrowing: 2*SEW source, SEW destination
            0b10000 => (
                eb,
                W::cvt_to_int(W::nanbox(cpu.v.eget(c.vs2, i, wb)), rm, T::N, true),
                0,
            ),
            0b10001 => (
                eb,
                W::cvt_to_int(W::nanbox(cpu.v.eget(c.vs2, i, wb)), rm, T::N, false),
                0,
            ),
            0b10010 => (
                eb,
                T::cvt_from_int(cpu.v.eget(c.vs2, i, wb), rm, W::N, true),
                0,
            ),
            0b10011 => (
                eb,
                T::cvt_from_int(cpu.v.eget(c.vs2, i, wb), rm, W::N, false),
                0,
            ),
            0b10100 => (eb, fnarrow::<T, W>(cpu.v.eget(c.vs2, i, wb), rm), 0),
            // vfncvt.rod.f.f.w — round to odd, built from truncation plus a
            // sticky bit, which is exactly what round-to-odd means.
            0b10101 => {
                let (r, f) =
                    fnarrow::<T, W>(cpu.v.eget(c.vs2, i, wb), RoundingMode::RoundTowardsZero);
                let r = if f & fflag::INEXACT != 0 { r | 1 } else { r };
                (eb, (r, f), 0)
            }
            0b10110 => (
                eb,
                W::cvt_to_int(
                    W::nanbox(cpu.v.eget(c.vs2, i, wb)),
                    RoundingMode::RoundTowardsZero,
                    T::N,
                    true,
                ),
                0,
            ),
            0b10111 => (
                eb,
                W::cvt_to_int(
                    W::nanbox(cpu.v.eget(c.vs2, i, wb)),
                    RoundingMode::RoundTowardsZero,
                    T::N,
                    false,
                ),
                0,
            ),
            _ => return Err(illegal()),
        };
        let _ = f;
        *ff |= val.1;
        cpu.v.eset(c.vd, i, dst_bytes, trunc(val.0, dst_bytes));
    }
    Ok(())
}

// The two 7-bit lookup tables from the specification's appendix, used by
// vfrsqrt7.v and vfrec7.v.
const RSQRT7_TABLE: [u8; 128] = [
    52, 51, 50, 48, 47, 46, 44, 43, 42, 41, 40, 39, 38, 36, 35, 34, 33, 32, 31, 30, 30, 29, 28, 27,
    26, 25, 24, 23, 23, 22, 21, 20, 19, 19, 18, 17, 16, 16, 15, 14, 14, 13, 12, 12, 11, 10, 10, 9,
    9, 8, 7, 7, 6, 6, 5, 4, 4, 3, 3, 2, 2, 1, 1, 0, 127, 125, 123, 121, 119, 118, 116, 114, 113,
    111, 109, 108, 106, 105, 103, 102, 100, 99, 97, 96, 95, 93, 92, 91, 90, 88, 87, 86, 85, 84, 83,
    82, 80, 79, 78, 77, 76, 75, 74, 73, 72, 71, 70, 70, 69, 68, 67, 66, 65, 64, 63, 63, 62, 61, 60,
    59, 59, 58, 57, 56, 56, 55, 54, 53,
];

const REC7_TABLE: [u8; 128] = [
    127, 125, 123, 121, 119, 117, 116, 114, 112, 110, 109, 107, 105, 104, 102, 100, 99, 97, 96, 94,
    93, 91, 90, 88, 87, 85, 84, 83, 81, 80, 79, 77, 76, 75, 74, 72, 71, 70, 69, 68, 66, 65, 64, 63,
    62, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 47, 46, 45, 44, 43, 42, 41, 40, 40,
    39, 38, 37, 36, 35, 35, 34, 33, 32, 31, 31, 30, 29, 28, 28, 27, 26, 25, 25, 24, 23, 23, 22, 21,
    21, 20, 19, 19, 18, 17, 17, 16, 15, 15, 14, 14, 13, 12, 12, 11, 11, 10, 9, 9, 8, 8, 7, 7, 6, 5,
    5, 4, 4, 3, 3, 2, 2, 1, 1, 0,
];

/// `vfrsqrt7.v`: a 7-bit-accurate reciprocal square root estimate.
fn frsqrt7<T: Sf>(a: u64) -> (u64, u8) {
    let a = T::unbox(a);
    let sign = T::sign(a);
    let exp = T::exp(a);
    let mant = T::mant(a);

    if T::is_nan(a) {
        return (
            T::qnan(),
            if T::is_signan(a) { fflag::INVALIDOP } else { 0 },
        );
    }
    if sign != 0 && !(exp == 0 && mant == 0) {
        // Negative (but not -0) has no real square root.
        return (T::qnan(), fflag::INVALIDOP);
    }
    if exp == 0 && mant == 0 {
        // ±0 -> ±inf
        return (T::pack(sign, T::EXP_MASK, 0), fflag::DIVIDEZERO);
    }
    if exp == T::EXP_MASK {
        return (T::pack(0, 0, 0), 0); // +inf -> +0
    }

    // Normalise a subnormal input so the significand's MSB is set.
    let (mut e, mut m) = (exp as i64, mant);
    if exp == 0 {
        let sh = T::MANT_SIZE as u32 - (64 - m.leading_zeros()) + 1;
        e = 1 - i64::from(sh);
        m = (m << sh) & T::MANT_MASK;
    }

    let idx = (((e as u64) & 1) << 6) | (m >> (T::MANT_SIZE - 6));
    let out_mant = u64::from(RSQRT7_TABLE[idx as usize]) << (T::MANT_SIZE - 7);
    let bias = T::EXP_MASK / 2;
    let out_exp = ((3 * bias as i64 - 1 - e) / 2) as u64;
    (T::pack(0, out_exp & T::EXP_MASK, out_mant), 0)
}

/// `vfrec7.v`: a 7-bit-accurate reciprocal estimate.
fn frec7<T: Sf>(a: u64, rm: RoundingMode) -> (u64, u8) {
    let a = T::unbox(a);
    let sign = T::sign(a);
    let exp = T::exp(a);
    let mant = T::mant(a);

    if T::is_nan(a) {
        return (
            T::qnan(),
            if T::is_signan(a) { fflag::INVALIDOP } else { 0 },
        );
    }
    if exp == T::EXP_MASK {
        return (T::pack(sign, 0, 0), 0); // ±inf -> ±0
    }
    if exp == 0 && mant == 0 {
        return (T::pack(sign, T::EXP_MASK, 0), fflag::DIVIDEZERO); // ±0 -> ±inf
    }

    // Inputs smaller than 2^(-bias-1) have reciprocals that overflow.
    if exp == 0 && mant >> (T::MANT_SIZE - 2) == 0 {
        let inf = T::pack(sign, T::EXP_MASK, 0);
        let greatest = T::pack(sign, T::EXP_MASK - 1, T::MANT_MASK);
        let to_inf = match rm {
            RoundingMode::RoundNearestEven | RoundingMode::RoundNearestMagnitude => true,
            RoundingMode::RoundUp => sign == 0,
            RoundingMode::RoundDown => sign != 0,
            _ => false,
        };
        return (
            if to_inf { inf } else { greatest },
            fflag::OVERFLOW | fflag::INEXACT,
        );
    }

    let (mut e, mut m) = (exp as i64, mant);
    if exp == 0 {
        let sh = if mant >> (T::MANT_SIZE - 1) != 0 {
            1
        } else {
            2
        };
        e = 1 - sh;
        m = (m << sh) & T::MANT_MASK;
    }

    let idx = m >> (T::MANT_SIZE - 7);
    let mut out_mant = u64::from(REC7_TABLE[idx as usize]) << (T::MANT_SIZE - 7);
    let bias = (T::EXP_MASK / 2) as i64;
    let mut out_exp = 2 * bias - 1 - e;

    // A result at or below the subnormal boundary needs the hidden bit made
    // explicit and the significand shifted down.
    if out_exp <= 0 {
        out_mant = (out_mant >> 1) | (1 << (T::MANT_SIZE - 1));
        if out_exp == -1 {
            out_mant >>= 1;
        }
        out_exp = 0;
    }

    (T::pack(sign, out_exp as u64 & T::EXP_MASK, out_mant), 0)
}

/// Scale an LMUL encoding by `eew / sew`, returning `None` when the result
/// falls outside the architectural 1/8 .. 8 range.
///
/// The 3-bit LMUL encoding is a signed log2 (`0..3` => `2^n`, `5..7` =>
/// `2^(n-8)`), so scaling by a power-of-two ratio is just an addition.
fn scale_lmul(lmul: u64, eew: usize, sew: usize) -> Option<u64> {
    let l = if lmul >= 5 {
        lmul as i64 - 8
    } else {
        lmul as i64
    };
    let scaled = l + i64::from(eew.trailing_zeros()) - i64::from(sew.trailing_zeros());
    if !(-3..=3).contains(&scaled) {
        None
    } else if scaled < 0 {
        Some((scaled + 8) as u64)
    } else {
        Some(scaled as u64)
    }
}
