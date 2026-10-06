#!/bin/sh
#
# Build mandelbrot, a Mandelbrot zoom on the --graphics framebuffer, to copy
# into a guest and run there.
#
# Needs: riscv64-linux-gnu-gcc.

set -e
cd "$(dirname "$0")"

# Freestanding: see ../demo/build.sh for why.  The -march is the widest that
# smolrv64 (RVA22 + extensions, no V) and simmerv without --rva23 both run.
# No linker relaxation: with no crt0 to set gp, gp-relative .bss accesses
# would fault.
riscv64-linux-gnu-gcc -O2 -march=rv64gc_zba_zbb_zbs_zicond -mabi=lp64d \
	-nostdlib -static -no-pie -ffreestanding -fno-builtin \
	-mno-relax -Wl,--no-relax \
	-o mandelbrot mandelbrot.c

echo "mandelbrot  $(stat -c%s mandelbrot) bytes"
