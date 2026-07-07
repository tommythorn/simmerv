#ifndef SIMMERV_COSIM_H
#define SIMMERV_COSIM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Keep in sync with simmerv::cpu::RetireCapture (#[repr(C)]).
typedef struct {
    uint64_t pc;          // PC of the retiring instruction
    uint64_t next_pc;     // PC after retire (trap vector if trapped)
    uint32_t insn;        // 16 or 32-bit insn word, zero-extended (0 if no insn retired)
    uint32_t _pad;
    uint8_t  rd_kind;     // 0=none, 1=int, 2=fp
    uint8_t  rd_idx;      // 0..31 within rd_kind's bank
    uint8_t  prv;         // privilege BEFORE retirement (0=U, 1=S, 3=M)
    uint8_t  trapped;     // 1 if trap taken
    uint32_t fflags;      // fcsr[4:0] after retire
    uint64_t rd_val;      // writeback value (FP: raw bits, NaN-boxed if single)
    uint64_t trap_cause;  // trap cause (MSB set = interrupt)
    uint64_t trap_tval;   // trap value
    uint64_t mtime;       // mtime observed at retirement
    uint64_t seqno;       // retirement sequence number
    uint64_t mepc;        // DEBUG: mepc after retire
} SimmervRetire;

typedef struct SimmervCtx SimmervCtx;

// Lifecycle
SimmervCtx* simmerv_create(size_t memory_bytes);
void        simmerv_destroy(SimmervCtx*);

// Initialization — call once before the first step.
int32_t     simmerv_write_memory(SimmervCtx*, uint64_t phys_addr,
                                 const uint8_t* data, size_t len);
void        simmerv_set_pc(SimmervCtx*, uint64_t pc);
void        simmerv_zero_registers(SimmervCtx*);
// 0..31 = integer register, 32..63 = fp register; idx==0 is ignored.
uint64_t simmerv_read_register(SimmervCtx *ctx, uint32_t idx);
void        simmerv_write_register(SimmervCtx*, uint32_t idx, uint64_t val);

// Per-retirement: drive mtime then step.
void        simmerv_set_mtime(SimmervCtx*, uint64_t value);
void        simmerv_set_mtimecmp(SimmervCtx*, uint64_t value);
void        simmerv_set_seip(SimmervCtx*, bool asserted);
// Full interrupt DUT-follow: call every retirement with `cause` = the DUT's
// interrupt mcause/scause (MSB set) when it took an interrupt this retire, else 0.
// simmerv takes exactly that interrupt and never decides interrupts on its own.
// Replaces the per-type stip/seip/mtip armed gates.
void        simmerv_set_forced_interrupt(SimmervCtx*, uint64_t cause);
void        simmerv_set_plic_ip(SimmervCtx*, uint32_t irq, bool asserted);
// Arm a one-shot CSR-read override: the next read of `csrno` returns
// `value`. Consumed on first matching read, and unconditionally cleared
// at the end of simmerv_step_retire so a stale arming can't bleed into
// later retires. Use for CSRs whose value is implementation/hardware-
// dependent (counters, externally-driven mip bits) so the DUT's read
// authoritatively wins.
void        simmerv_arm_csr_read(SimmervCtx*, uint16_t csrno, uint64_t value);
// Arm the DUT's loaded value for the next retire; simmerv uses it only if its
// own load resolves to MMIO (device-register reads are model-specific). Also
// auto-cleared at the end of simmerv_step_retire.
void        simmerv_arm_load_value(SimmervCtx*, uint64_t value);
int32_t     simmerv_step_retire(SimmervCtx*, SimmervRetire* out);

#ifdef __cplusplus
}
#endif

#endif // SIMMERV_COSIM_H
