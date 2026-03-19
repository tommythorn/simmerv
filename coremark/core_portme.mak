# CoreMark port for simmerv RISC-V emulator
# Cross-compiled with riscv64-elf-gcc, no libc, raw Linux syscalls.

CC = riscv64-elf-gcc
AS = riscv64-elf-gcc
LD = riscv64-elf-gcc
OBJCOPY = riscv64-elf-objcopy

PORT_CFLAGS = -O2 -march=rv64gc_zba_zbb_zbs -mabi=lp64d \
              -nostdlib -nostartfiles -ffreestanding \
              -DPERFORMANCE_RUN=1
FLAGS_STR = "$(PORT_CFLAGS) $(XCFLAGS) $(XLFLAGS) $(LFLAGS_END)"
CFLAGS = $(PORT_CFLAGS) -I$(PORT_DIR) -I. -DFLAGS_STR=\"$(FLAGS_STR)\"

LFLAGS_END = -lgcc
OUTFLAG = -o

PORT_SRCS = $(PORT_DIR)/core_portme.c $(PORT_DIR)/ee_printf.c $(PORT_DIR)/crt0.S
PORT_OBJS = $(PORT_DIR)/crt0.o

LOAD = echo Loading done
RUN =

OEXT = .o
EXE = .elf

.PHONY : port_prebuild port_postbuild port_prerun port_postrun port_preload port_postload
port_pre% port_post% :

OPATH = ./
MKDIR = mkdir -p
