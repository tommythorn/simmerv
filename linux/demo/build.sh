#!/bin/sh
#
# Rebuild the demo's boot glue: the initramfs.
#
# The root filesystem is NOT built here; see ../../mkdemo-image.sh, which turns
# a Debian disk image into rootfs.sqfs.
#
# This used to build a device tree too: a copy of src/device/dts.dts with
# linux,initrd-start/-end sed'd in at a hardcoded address, which the emulator's
# default tree does not carry. That file is gone. Both the sim CLI (-i) and the
# wasm demo (setup_initrd) now place the ramdisk themselves and insert those
# properties into the tree they are using, so the address is derived rather
# than frozen and nothing here has to agree with anything.
#
# Needs: riscv64-linux-gnu-gcc, cpio.

set -e
cd "$(dirname "$0")"

# rv64gc only, freestanding: a libc-linked init would drag in glibc's RVV
# memcpy/memset variants, which SIGILL on an emulator built without V.
riscv64-linux-gnu-gcc -Os -march=rv64gc -mabi=lp64d \
	-nostdlib -static -no-pie -ffreestanding -fno-builtin \
	-o init init.c

rm -rf root
mkdir root
cp init root/init
(cd root && find . | cpio -o -H newc --quiet) > initramfs.cpio
rm -rf root init

echo "initramfs.cpio  $(stat -c%s initramfs.cpio) bytes"
