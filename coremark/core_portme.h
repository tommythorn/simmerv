#ifndef CORE_PORTME_H
#define CORE_PORTME_H

/* No libc — bare-metal port for RISC-V Linux via raw syscalls. */

#define HAS_FLOAT   0
#define HAS_TIME_H  0
#define USE_CLOCK   0
#define HAS_STDIO   0
#define HAS_PRINTF  0

#ifndef COMPILER_VERSION
#ifdef __GNUC__
#define COMPILER_VERSION "GCC"__VERSION__
#else
#define COMPILER_VERSION "unknown"
#endif
#endif
#ifndef COMPILER_FLAGS
#define COMPILER_FLAGS FLAGS_STR
#endif
#ifndef MEM_LOCATION
#define MEM_LOCATION "STACK"
#endif

typedef signed short        ee_s16;
typedef unsigned short      ee_u16;
typedef signed int          ee_s32;
typedef double              ee_f32;
typedef unsigned char       ee_u8;
typedef unsigned int        ee_u32;
typedef unsigned long       ee_ptr_int;  /* 64-bit for RV64 */
typedef unsigned long       ee_size_t;

#define align_mem(x) (void *)(4 + (((ee_ptr_int)(x) - 1) & ~3))
#define NULL ((void *)0)

/* Timing: rdcycle counts emulated instructions in simmerv.
   We report ticks directly; set EE_TICKS_PER_SEC = 1 so that
   "secs" = cycles.  The useful metric is the raw cycle count
   (or external wall-clock time). */
typedef unsigned long CORE_TICKS;
#define CORETIMETYPE               unsigned long
#define CLOCKS_PER_SEC             1
#define NSECS_PER_SEC              CLOCKS_PER_SEC
#define EE_TICKS_PER_SEC           1
#define TIMER_RES_DIVIDER          1
#define SAMPLE_TIME_IMPLEMENTATION 1

#define SEED_METHOD   SEED_VOLATILE
#define MEM_METHOD    MEM_STACK
#define MULTITHREAD   1
#define USE_PTHREAD   0
#define USE_FORK      0
#define USE_SOCKET    0
#define MAIN_HAS_NOARGC   1
#define MAIN_HAS_NORETURN 0

extern ee_u32 default_num_contexts;

typedef struct CORE_PORTABLE_S {
    ee_u8 portable_id;
} core_portable;

void portable_init(core_portable *p, int *argc, char *argv[]);
void portable_fini(core_portable *p);

int ee_printf(const char *fmt, ...);

#if !defined(PROFILE_RUN) && !defined(PERFORMANCE_RUN) \
    && !defined(VALIDATION_RUN)
#if (TOTAL_DATA_SIZE == 1200)
#define PROFILE_RUN 1
#elif (TOTAL_DATA_SIZE == 2000)
#define PERFORMANCE_RUN 1
#else
#define VALIDATION_RUN 1
#endif
#endif

#endif /* CORE_PORTME_H */
