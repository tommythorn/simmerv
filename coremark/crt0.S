/*
 * Minimal crt0 for RISC-V Linux (no libc).
 * Linux zeros BSS and sets up the stack for us.
 */

        .section .text
        .globl  _start
        .type   _start, @function
_start:
        /* Set up global pointer for gp-relative addressing */
        .option push
        .option norelax
        la      gp, __global_pointer$
        .option pop

        /* Call main(void) — MAIN_HAS_NOARGC=1 */
        call    main

        /* exit(main_return_value) — a0 already holds return value */
        li      a7, 93          /* __NR_exit */
        ecall

        .size   _start, . - _start

/*
 * memset — needed by compiler-generated code.
 */
        .globl  memset
        .type   memset, @function
memset:
        /* a0 = dst, a1 = byte, a2 = count; returns a0 */
        mv      t0, a0
1:      beqz    a2, 2f
        sb      a1, 0(t0)
        addi    t0, t0, 1
        addi    a2, a2, -1
        j       1b
2:      ret
        .size   memset, . - memset

/*
 * memcpy — needed by compiler-generated code.
 */
        .globl  memcpy
        .type   memcpy, @function
memcpy:
        /* a0 = dst, a1 = src, a2 = count; returns a0 */
        mv      t0, a0
1:      beqz    a2, 2f
        lb      t1, 0(a1)
        sb      t1, 0(t0)
        addi    a1, a1, 1
        addi    t0, t0, 1
        addi    a2, a2, -1
        j       1b
2:      ret
        .size   memcpy, . - memcpy

/*
 * memcmp — may be needed by compiler-generated code.
 */
        .globl  memcmp
        .type   memcmp, @function
memcmp:
        /* a0 = s1, a1 = s2, a2 = count; returns <0, 0, >0 */
1:      beqz    a2, 2f
        lbu     t0, 0(a0)
        lbu     t1, 0(a1)
        sub     t2, t0, t1
        bnez    t2, 3f
        addi    a0, a0, 1
        addi    a1, a1, 1
        addi    a2, a2, -1
        j       1b
2:      li      a0, 0
        ret
3:      mv      a0, t2
        ret
        .size   memcmp, . - memcmp
