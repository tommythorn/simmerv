#!/bin/sh
#
# Rebuild the demo's boot glue: the initramfs and the device tree that tells
# the kernel where it lives. Both are tiny and change rarely, so they are
# checked in -- but they are generated, and this is how.
#
# The root filesystem itself is NOT built here; see ../../mkdemo-image.sh,
# which turns a Debian disk image into rootfs.sqfs.
#
# Needs: riscv64-linux-gnu-gcc, dtc, cpio.

set -e
cd "$(dirname "$0")"

# Where the initramfs is placed in guest RAM. Must sit inside the memory the
# emulator is configured with -- the wasm demo uses 512 MB (0x80000000 ..
# 0xa0000000) and the device tree is written near the very top, so this leaves
# room for both. index.html passes the same address to load_blob_at().
INITRD_ADDR=0x9e000000

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

SIZE=$(stat -c%s initramfs.cpio)
END=$(printf '0x%x' $(( ( (INITRD_ADDR + SIZE + 0xfff) / 0x1000 ) * 0x1000 )))

# The machine description comes from src/device/dts.dts (the same layout the
# emulator compiles in); this only adds the initrd window and drops the root=
# argument, since our init chooses the root itself.
cpp -P -nostdinc -x assembler-with-cpp ../../src/device/dts.dts |
sed -e 's|root=/dev/vda1 rw ||' \
    -e "s|\(bootargs = \"[^\"]*\";\)|\1\n\t\tlinux,initrd-start = <0x0 $INITRD_ADDR>;\n\t\tlinux,initrd-end   = <0x0 $END>;|" |
dtc -I dts -O dtb -o demo.dtb - 2>/dev/null

echo "initramfs.cpio  $SIZE bytes at $INITRD_ADDR..$END"
echo "demo.dtb        $(stat -c%s demo.dtb) bytes"
