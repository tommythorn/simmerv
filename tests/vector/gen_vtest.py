#!/usr/bin/env python3
"""Generate a bare-metal RVV 1.0 differential test.

The emitted assembly runs a long list of vector instructions, dumping the whole
vector register file, a scratch memory area and the vector CSRs after each one.
The same binary runs on simmerv and on QEMU's virt machine (identical memory
map: NS16550A at 0x10000000, syscon at 0x100000, RAM at 0x80000000), so the two
transcripts can simply be diffed.

Usage: gen_vtest.py > vtest.S
"""

import sys

# ── the tests ────────────────────────────────────────────────────────────────
#
# Each entry is (sew, lmul, avl, vxrm, prep, insn).  `prep` runs after the
# vsetvli and before the instruction under test; it is used to build safe index
# vectors and to set up scalar operands.
#
# Register conventions inside a test:
#   a0  = scratch (4 KiB, writable, pre-filled with pseudo-random bytes)
#   a1  = a second scratch pointer, 64 bytes in
#   a2  = a small scalar operand
#   ft0 = a floating-point scalar operand
# v0 holds pseudo-random bits, so it is a mixed mask; v1..v31 likewise.

TESTS = []


def t(insn, sew=32, lmul="m1", avl=7, vxrm=0, prep=()):
    TESTS.append((sew, lmul, avl, vxrm, list(prep), insn))


def widths(insn_fmt, **kw):
    """Emit one test per SEW."""
    for sew in (8, 16, 32, 64):
        t(insn_fmt, sew=sew, **kw)


# ── configuration ────────────────────────────────────────────────────────────
for sew in (8, 16, 32, 64):
    for lmul in ("mf8", "mf4", "mf2", "m1", "m2", "m4", "m8"):
        t(f"vsetvli t1, t0, e{sew}, {lmul}, ta, ma", sew=sew, avl=13)
        t(f"vsetvli t1, t0, e{sew}, {lmul}, tu, mu", sew=sew, avl=1)
t("vsetivli t1, 5, e32, m2, ta, ma")
t("vsetivli t1, 31, e8, m1, tu, ma")
t("li t2, 0xd1\n\tvsetvl t1, t0, t2")
t("li t2, 0\n\tvsetvl t1, t0, t2")
# rs1=x0, rd!=x0 asks for VLMAX; both x0 keeps vl.
t("vsetvli t1, x0, e16, m2, ta, ma")
t("vsetvli x0, x0, e16, m2, ta, ma")
# An unsupported SEW/LMUL ratio must set vill.
t("vsetvli t1, t0, e64, mf8, ta, ma")

# ── OPIVV / OPIVX / OPIVI ────────────────────────────────────────────────────
for op in ("vadd", "vsub", "vand", "vor", "vxor", "vminu", "vmin", "vmaxu", "vmax",
           "vsaddu", "vsadd", "vssubu", "vssub", "vsll", "vsrl", "vsra", "vsmul",
           "vssrl", "vssra", "vmseq", "vmsne", "vmsltu", "vmslt", "vmsleu", "vmsle"):
    widths(f"{op}.vv v1, v2, v3")
    widths(f"{op}.vx v1, v2, a2")
# The .vi immediate is sign-extended for most operations but zero-extended
# for the shifts, whose assembler syntax only accepts 0..31.
for op in ("vadd", "vand", "vor", "vxor", "vsaddu", "vsadd", "vmseq", "vmsne",
           "vmsleu", "vmsle", "vmsgtu", "vmsgt", "vrsub"):
    widths(f"{op}.vi v1, v2, 5")
    widths(f"{op}.vi v1, v2, -3")
for op in ("vsll", "vsrl", "vsra", "vssrl", "vssra"):
    widths(f"{op}.vi v1, v2, 3")
    widths(f"{op}.vi v1, v2, 29")
widths("vrsub.vx v1, v2, a2")
widths("vmsgtu.vx v1, v2, a2")
widths("vmsgt.vx v1, v2, a2")
# fixed-point rounding modes
for rm in range(4):
    t("vssrl.vi v1, v2, 3", vxrm=rm)
    t("vssra.vi v1, v2, 3", vxrm=rm)
    t("vsmul.vv v1, v2, v3", vxrm=rm)
    t("vnclip.wi v1, v2, 3", vxrm=rm)
    t("vnclipu.wi v1, v2, 3", vxrm=rm)
    t("vaadd.vv v1, v2, v3", vxrm=rm)
    t("vaaddu.vv v1, v2, v3", vxrm=rm)
    t("vasub.vv v1, v2, v3", vxrm=rm)
    t("vasubu.vv v1, v2, v3", vxrm=rm)
# masked forms
for op in ("vadd.vv v1, v2, v3", "vsub.vx v1, v2, a2", "vand.vi v1, v2, 7",
           "vmseq.vv v1, v2, v3", "vmul.vv v1, v2, v3", "vmacc.vv v1, v2, v3"):
    widths(f"{op}, v0.t")
# carry / borrow
for op in ("vadc.vvm v1, v2, v3, v0", "vadc.vxm v1, v2, a2, v0",
           "vadc.vim v1, v2, 5, v0", "vsbc.vvm v1, v2, v3, v0",
           "vsbc.vxm v1, v2, a2, v0"):
    widths(op)
for op in ("vmadc.vvm v1, v2, v3, v0", "vmadc.vv v1, v2, v3",
           "vmadc.vim v1, v2, 5, v0", "vmsbc.vvm v1, v2, v3, v0",
           "vmsbc.vv v1, v2, v3", "vmsbc.vxm v1, v2, a2, v0"):
    widths(op)
# merge and move
for op in ("vmerge.vvm v1, v2, v3, v0", "vmerge.vxm v1, v2, a2, v0",
           "vmerge.vim v1, v2, -5, v0", "vmv.v.v v1, v3", "vmv.v.x v1, a2",
           "vmv.v.i v1, -7"):
    widths(op)
# narrowing shifts and clips
# vs1 must not overlap the double-width vs2 group (which is {v2,v3} here).
for op in ("vnsrl.wv", "vnsra.wv", "vnclipu.wv", "vnclip.wv"):
    for sew in (8, 16, 32):
        t(f"{op} v1, v2, v4", sew=sew)
for op in ("vnsrl.wi", "vnsra.wi", "vnclipu.wi", "vnclip.wi"):
    for sew in (8, 16, 32):
        t(f"{op} v1, v2, 6", sew=sew)
for op in ("vnsrl.wx", "vnsra.wx", "vnclipu.wx", "vnclip.wx"):
    for sew in (8, 16, 32):
        t(f"{op} v1, v2, a2", sew=sew)
# gather, slides and compress
widths("vrgather.vv v1, v2, v3")
widths("vrgather.vx v1, v2, a2")
widths("vrgather.vi v1, v2, 3")
for sew in (8, 16, 32, 64):
    t("vrgatherei16.vv v1, v4, v8", sew=sew)
widths("vslideup.vx v1, v2, a2")
widths("vslideup.vi v1, v2, 2")
widths("vslidedown.vx v1, v2, a2")
widths("vslidedown.vi v1, v2, 2")
widths("vslide1up.vx v1, v2, a2")
widths("vslide1down.vx v1, v2, a2")
widths("vcompress.vm v1, v2, v3")
# whole-register move
for nr in (1, 2, 4, 8):
    t(f"vmv{nr}r.v v8, v16")
# widening reductions
for sew in (8, 16, 32):
    t(f"vwredsum.vs v1, v2, v3", sew=sew)
    t(f"vwredsumu.vs v1, v2, v3", sew=sew)

# ── OPMVV / OPMVX ────────────────────────────────────────────────────────────
for op in ("vredsum", "vredand", "vredor", "vredxor", "vredminu", "vredmin",
           "vredmaxu", "vredmax"):
    widths(f"{op}.vs v1, v2, v3")
for op in ("vdivu", "vdiv", "vremu", "vrem", "vmulhu", "vmul", "vmulhsu", "vmulh"):
    widths(f"{op}.vv v1, v2, v3")
    widths(f"{op}.vx v1, v2, a2")
for op in ("vmadd", "vnmsub", "vmacc", "vnmsac"):
    widths(f"{op}.vv v1, v2, v3")
    widths(f"{op}.vx v1, a2, v3")
for op in ("vaaddu", "vaadd", "vasubu", "vasub"):
    widths(f"{op}.vv v1, v2, v3")
    widths(f"{op}.vx v1, v2, a2")
widths("vslide1up.vx v1, v2, a2")
widths("vslide1down.vx v1, v2, a2")
t("vmv.x.s t1, v2")
for sew in (8, 16, 32, 64):
    t("vmv.x.s t1, v2", sew=sew)
    t("vmv.s.x v1, a2", sew=sew)
    t("vcpop.m t1, v2", sew=sew)
    t("vfirst.m t1, v2", sew=sew)
    t("vcpop.m t1, v2, v0.t", sew=sew)
    t("vfirst.m t1, v2, v0.t", sew=sew)
for f in (2, 4, 8):
    for sew in (8, 16, 32, 64):
        if sew // f >= 8:
            t(f"vzext.vf{f} v1, v2", sew=sew)
            t(f"vsext.vf{f} v1, v2", sew=sew)
for op in ("vmsbf.m", "vmsof.m", "vmsif.m"):
    widths(f"{op} v1, v2")
    widths(f"{op} v1, v2, v0.t")
widths("viota.m v1, v2")
widths("vid.v v1")
widths("vid.v v1, v0.t")
for op in ("vmand", "vmnand", "vmandn", "vmxor", "vmor", "vmnor", "vmorn", "vmxnor"):
    t(f"{op}.mm v1, v2, v3")
# widening integer
for op in ("vwaddu", "vwadd", "vwsubu", "vwsub"):
    for sew in (8, 16, 32):
        t(f"{op}.vv v4, v2, v3", sew=sew)
        t(f"{op}.vx v4, v2, a2", sew=sew)
        t(f"{op}.wv v4, v6, v3", sew=sew)
        t(f"{op}.wx v4, v6, a2", sew=sew)
for op in ("vwmulu", "vwmulsu", "vwmul"):
    for sew in (8, 16, 32):
        t(f"{op}.vv v4, v2, v3", sew=sew)
        t(f"{op}.vx v4, v2, a2", sew=sew)
for op in ("vwmaccu", "vwmacc", "vwmaccsu"):
    for sew in (8, 16, 32):
        t(f"{op}.vv v4, v2, v3", sew=sew)
        t(f"{op}.vx v4, a2, v3", sew=sew)
for sew in (8, 16, 32):
    t(f"vwmaccus.vx v4, a2, v3", sew=sew)

# ── OPFVV / OPFVF ────────────────────────────────────────────────────────────
FSEW = (16, 32, 64)
for op in ("vfadd", "vfsub", "vfmul", "vfdiv", "vfmin", "vfmax",
           "vfsgnj", "vfsgnjn", "vfsgnjx"):
    for sew in FSEW:
        t(f"{op}.vv v1, v2, v3", sew=sew)
        t(f"{op}.vf v1, v2, ft0", sew=sew)
for sew in FSEW:
    t(f"vfrdiv.vf v1, v2, ft0", sew=sew)
    t(f"vfrsub.vf v1, v2, ft0", sew=sew)
for op in ("vfmadd", "vfnmadd", "vfmsub", "vfnmsub",
           "vfmacc", "vfnmacc", "vfmsac", "vfnmsac"):
    for sew in FSEW:
        t(f"{op}.vv v1, v2, v3", sew=sew)
        t(f"{op}.vf v1, ft0, v3", sew=sew)
for op in ("vmfeq", "vmfle", "vmflt", "vmfne"):
    for sew in FSEW:
        t(f"{op}.vv v1, v2, v3", sew=sew)
        t(f"{op}.vf v1, v2, ft0", sew=sew)
for op in ("vmfgt", "vmfge"):
    for sew in FSEW:
        t(f"{op}.vf v1, v2, ft0", sew=sew)
for sew in FSEW:
    t(f"vfsqrt.v v1, v2", sew=sew)
    t(f"vfrsqrt7.v v1, v2", sew=sew)
    t(f"vfrec7.v v1, v2", sew=sew)
    t(f"vfclass.v v1, v2", sew=sew)
    t(f"vfmv.f.s ft1, v2", sew=sew)
    t(f"vfmv.s.f v1, ft0", sew=sew)
    t(f"vfmv.v.f v1, ft0", sew=sew)
    t(f"vfmerge.vfm v1, v2, ft0, v0", sew=sew)
    t(f"vfredusum.vs v1, v2, v3", sew=sew)
    t(f"vfredosum.vs v1, v2, v3", sew=sew)
    t(f"vfredmin.vs v1, v2, v3", sew=sew)
    t(f"vfredmax.vs v1, v2, v3", sew=sew)
    t(f"vfslide1up.vf v1, v2, ft0", sew=sew)
    t(f"vfslide1down.vf v1, v2, ft0", sew=sew)
# conversions
for sew in FSEW:
    for op in ("vfcvt.xu.f.v", "vfcvt.x.f.v", "vfcvt.f.xu.v", "vfcvt.f.x.v",
               "vfcvt.rtz.xu.f.v", "vfcvt.rtz.x.f.v"):
        t(f"{op} v1, v2", sew=sew)
for sew in (16, 32):
    for op in ("vfwcvt.xu.f.v", "vfwcvt.x.f.v", "vfwcvt.f.xu.v", "vfwcvt.f.x.v",
               "vfwcvt.f.f.v", "vfwcvt.rtz.xu.f.v", "vfwcvt.rtz.x.f.v"):
        t(f"{op} v4, v2", sew=sew)
    for op in ("vfncvt.xu.f.w", "vfncvt.x.f.w", "vfncvt.f.xu.w", "vfncvt.f.x.w",
               "vfncvt.f.f.w", "vfncvt.rod.f.f.w", "vfncvt.rtz.xu.f.w",
               "vfncvt.rtz.x.f.w"):
        t(f"{op} v1, v4", sew=sew)
# widening float
for sew in (16, 32):
    for op in ("vfwadd", "vfwsub"):
        t(f"{op}.vv v4, v2, v3", sew=sew)
        t(f"{op}.vf v4, v2, ft0", sew=sew)
        t(f"{op}.wv v4, v6, v3", sew=sew)
        t(f"{op}.wf v4, v6, ft0", sew=sew)
    t(f"vfwmul.vv v4, v2, v3", sew=sew)
    t(f"vfwmul.vf v4, v2, ft0", sew=sew)
    for op in ("vfwmacc", "vfwnmacc", "vfwmsac", "vfwnmsac"):
        t(f"{op}.vv v4, v2, v3", sew=sew)
        t(f"{op}.vf v4, ft0, v3", sew=sew)
    t(f"vfwredusum.vs v4, v2, v3", sew=sew)
    t(f"vfwredosum.vs v4, v2, v3", sew=sew)
# the four rounding modes, on operations that round
for frm in range(5):
    for sew in (32, 64):
        t(f"vfadd.vv v1, v2, v3", sew=sew, prep=[f"csrwi frm, {frm}"])
        t(f"vfdiv.vv v1, v2, v3", sew=sew, prep=[f"csrwi frm, {frm}"])
        t(f"vfcvt.x.f.v v1, v2", sew=sew, prep=[f"csrwi frm, {frm}"])
    t(f"vfncvt.f.f.w v1, v4", sew=32, prep=[f"csrwi frm, {frm}"])

# ── loads and stores ─────────────────────────────────────────────────────────
# EMUL of the index group = (index EEW / SEW) * LMUL; for the SEW=32, LMUL=1
# tests below that is a quarter, a half, one and two respectively.
IDX_EMUL = {8: "mf4", 16: "mf2", 32: "m1", 64: "m2"}


def idx_prep(ieew, sew=32, lmul="m1"):
    """Build a small in-range index vector in v24, at the index element width."""
    return [
        f"vsetvli x0, t0, e{ieew}, {IDX_EMUL[ieew]}, ta, ma",
        "vid.v v24",
        "vsll.vi v24, v24, 2",
        "vand.vi v24, v24, 15",
        f"vsetvli t1, t0, e{sew}, {lmul}, ta, ma",
    ]


IDX = idx_prep(32)
for eew in (8, 16, 32, 64):
    t(f"vle{eew}.v v1, (a0)", sew=eew)
    t(f"vle{eew}.v v1, (a0), v0.t", sew=eew)
    t(f"vse{eew}.v v2, (a0)", sew=eew)
    t(f"vse{eew}.v v2, (a0), v0.t", sew=eew)
    t(f"vlse{eew}.v v1, (a0), a2", sew=eew, prep=["li a2, 12"])
    t(f"vsse{eew}.v v2, (a0), a2", sew=eew, prep=["li a2, 12"])
    t(f"vle{eew}ff.v v1, (a0)", sew=eew)
for ieew in (8, 16, 32, 64):
    t(f"vluxei{ieew}.v v1, (a0), v24", prep=idx_prep(ieew))
    t(f"vloxei{ieew}.v v1, (a0), v24", prep=idx_prep(ieew))
    t(f"vsuxei{ieew}.v v2, (a0), v24", prep=idx_prep(ieew))
    t(f"vsoxei{ieew}.v v2, (a0), v24", prep=idx_prep(ieew))
t("vlm.v v1, (a0)")
t("vsm.v v2, (a0)")
for nr in (1, 2, 4, 8):
    for eew in (8, 16, 32, 64):
        t(f"vl{nr}re{eew}.v v8, (a0)")
    t(f"vs{nr}r.v v8, (a0)")
# segments
for nf in range(2, 9):
    for eew in (8, 32):
        t(f"vlseg{nf}e{eew}.v v8, (a0)", sew=eew, avl=3)
        t(f"vsseg{nf}e{eew}.v v8, (a0)", sew=eew, avl=3)
    t(f"vlsseg{nf}e32.v v8, (a0), a2", sew=32, avl=3, prep=["li a2, 40"])
    t(f"vssseg{nf}e32.v v8, (a0), a2", sew=32, avl=3, prep=["li a2, 40"])
    t(f"vluxseg{nf}ei32.v v8, (a0), v24", sew=32, avl=3, prep=IDX)
    t(f"vsuxseg{nf}ei32.v v8, (a0), v24", sew=32, avl=3, prep=IDX)
# non-unit LMUL arithmetic
for lmul in ("mf2", "m2", "m4"):
    for sew in (8, 32):
        t(f"vadd.vv v4, v8, v12", sew=sew, lmul=lmul, avl=20)
        t(f"vmul.vx v4, v8, a2", sew=sew, lmul=lmul, avl=20)
        t(f"vle{sew}.v v4, (a0)", sew=sew, lmul=lmul, avl=20)
        t(f"vse{sew}.v v4, (a0)", sew=sew, lmul=lmul, avl=20)
        t(f"vrgather.vv v4, v8, v12", sew=sew, lmul=lmul, avl=20)
        t(f"vslidedown.vi v4, v8, 3", sew=sew, lmul=lmul, avl=20)
# vl = 0 and vl = vlmax
t("vadd.vv v1, v2, v3", avl=0)
t("vadd.vv v1, v2, v3", avl=64)
t("vredsum.vs v1, v2, v3", avl=0)

# ── emit ─────────────────────────────────────────────────────────────────────

PROLOGUE = r"""
# Generated by gen_vtest.py -- do not edit.
	.option	nopic
	.section .text.init,"ax",@progbits
	.globl	_start
_start:
	# Enable the FP and vector units (QEMU starts with both Off).
	li	t0, (3 << 13) | (3 << 9)
	csrs	mstatus, t0
	csrwi	fcsr, 0
	la	sp, stack_top
	# A trap must not be fatal: an instruction one simulator rejects and the
	# other accepts is exactly the divergence we are looking for, and without
	# a handler mtvec is 0 and the guest spins forever instead of telling us.
	la	t0, trap_handler
	csrw	mtvec, t0
	call	init_data
"""

EPILOGUE = r"""
finish:
	li	t0, 0x100000
	li	t1, 0x5555
	sw	t1, 0(t0)
1:	j	1b

# ── runtime ──────────────────────────────────────────────────────────────────

# Report the trap and resume at the next instruction.  Every instruction under
# test is 32 bits, so mepc+4 is the right resume point.  The handler reports
# mcause, so the two simulators must agree on *whether* they trap and on why,
# not merely on the architectural state afterwards.
	.balign 4
trap_handler:
	csrw	mscratch, ra
	addi	sp, sp, -48
	sd	a0, 0(sp)
	sd	s2, 8(sp)
	sd	t0, 16(sp)
	sd	t1, 24(sp)
	csrr	t0, mepc
	addi	t0, t0, 4
	csrw	mepc, t0
	li	a0, 'T'
	call	putchar
	csrr	a0, mcause
	call	puthex16
	ld	a0, 0(sp)
	ld	s2, 8(sp)
	ld	t0, 16(sp)
	ld	t1, 24(sp)
	addi	sp, sp, 48
	csrr	ra, mscratch
	mret

# Fill vdata with a deterministic xorshift stream.
init_data:
	la	a0, vdata
	li	a1, 2048
	li	t0, 0x12345678
1:	slliw	t1, t0, 13
	xor	t0, t0, t1
	sext.w	t0, t0
	srliw	t1, t0, 17
	xor	t0, t0, t1
	sext.w	t0, t0
	slliw	t1, t0, 5
	xor	t0, t0, t1
	sext.w	t0, t0
	sw	t0, 0(a0)
	addi	a0, a0, 4
	addi	a1, a1, -4
	bnez	a1, 1b
	ret

# Restore v0..v31 and the scratch area, and clear the sticky flags.
setup:
	addi	sp, sp, -16
	sd	ra, 0(sp)
	la	t0, vdata
	vl8re8.v v0, (t0)
	addi	t0, t0, 128
	vl8re8.v v8, (t0)
	addi	t0, t0, 128
	vl8re8.v v16, (t0)
	addi	t0, t0, 128
	vl8re8.v v24, (t0)
	la	t0, vdata
	la	t1, scratch
	li	t2, 4096
1:	ld	t3, 0(t0)
	sd	t3, 0(t1)
	addi	t0, t0, 8
	addi	t1, t1, 8
	addi	t2, t2, -8
	bnez	t2, 1b
	csrwi	fflags, 0
	csrwi	vxsat, 0
	csrwi	vstart, 0
	csrwi	frm, 0
	# scalar operands, stable across tests
	li	a2, 0x35
	la	t0, vdata
	fld	ft0, 32(t0)
	la	a0, scratch
	addi	a1, a0, 64
	ld	ra, 0(sp)
	addi	sp, sp, 16
	ret

# Dump the architectural vector state as one line of hex.
dump:
	addi	sp, sp, -16
	sd	ra, 0(sp)
	la	t0, vbuf
	vs8r.v	v0, (t0)
	addi	t0, t0, 128
	vs8r.v	v8, (t0)
	addi	t0, t0, 128
	vs8r.v	v16, (t0)
	addi	t0, t0, 128
	vs8r.v	v24, (t0)
	la	a0, vbuf
	li	a1, 512
	call	puthexbuf
	la	a0, scratch
	li	a1, 256
	call	puthexbuf
	li	a0, ' '
	call	putchar
	csrr	a0, vl
	call	puthex16
	csrr	a0, vtype
	call	puthex16
	csrr	a0, fflags
	call	puthex16
	csrr	a0, vxsat
	call	puthex16
	csrr	a0, vstart
	call	puthex16
	li	a0, 10
	call	putchar
	ld	ra, 0(sp)
	addi	sp, sp, 16
	ret

# a0 = buffer, a1 = length
puthexbuf:
	addi	sp, sp, -32
	sd	ra, 0(sp)
	sd	s0, 8(sp)
	sd	s1, 16(sp)
	mv	s0, a0
	mv	s1, a1
1:	beqz	s1, 2f
	lbu	a0, 0(s0)
	call	puthex8
	addi	s0, s0, 1
	addi	s1, s1, -1
	j	1b
2:	ld	ra, 0(sp)
	ld	s0, 8(sp)
	ld	s1, 16(sp)
	addi	sp, sp, 32
	ret

puthex8:
	addi	sp, sp, -16
	sd	ra, 0(sp)
	sd	s2, 8(sp)
	mv	s2, a0
	srli	a0, s2, 4
	andi	a0, a0, 15
	call	putnibble
	andi	a0, s2, 15
	call	putnibble
	ld	ra, 0(sp)
	ld	s2, 8(sp)
	addi	sp, sp, 16
	ret

# 16 hex digits of a0
puthex16:
	addi	sp, sp, -16
	sd	ra, 0(sp)
	sd	s2, 8(sp)
	mv	s2, a0
	li	t0, 60
1:	srl	a0, s2, t0
	andi	a0, a0, 15
	addi	sp, sp, -16
	sd	t0, 0(sp)
	call	putnibble
	ld	t0, 0(sp)
	addi	sp, sp, 16
	addi	t0, t0, -4
	bgez	t0, 1b
	li	a0, ' '
	call	putchar
	ld	ra, 0(sp)
	ld	s2, 8(sp)
	addi	sp, sp, 16
	ret

putnibble:
	li	t1, 10
	blt	a0, t1, 1f
	addi	a0, a0, 'a' - 10
	j	putchar
1:	addi	a0, a0, '0'
	j	putchar

putchar:
	li	t1, 0x10000000
	sb	a0, 0(t1)
	ret

	.section .data
	.balign 64
vdata:	.space	4096
	.balign 64
scratch:
	.space	8192
	.balign 64
vbuf:	.space	512
	.balign 64
	.space	4096
stack_top:
"""


def main():
    out = [PROLOGUE]
    for n, (sew, lmul, avl, vxrm, prep, insn) in enumerate(TESTS):
        out.append(f"\t# --- test {n}: {insn.splitlines()[-1].strip()}")
        out.append("\tcall\tsetup")
        out.append(f"\tcsrwi\tvxrm, {vxrm}")
        out.append(f"\tli\tt0, {avl}")
        if not insn.startswith("vset"):
            out.append(f"\tvsetvli\tt1, t0, e{sew}, {lmul}, ta, ma")
        for p in prep:
            out.append(f"\t{p}")
        out.append(f"\t{insn}")
        out.append("\tcall\tdump")
    out.append(EPILOGUE)
    sys.stdout.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
