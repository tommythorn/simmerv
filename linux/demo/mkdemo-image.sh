#!/bin/sh
#
# Build the browser demo's root filesystem from a Debian disk image
# (https://people.debian.org/~gio/dqib/, or that image after you have installed
# more into it under QEMU).
#
# Produces a compressed, read-only squashfs. The demo boots it with a tmpfs
# overlay, so the guest is fully writable at run time -- changes just do not
# persist. To change the base, edit the source image and re-run this.
#
# Everything here is rootless: debugfs reads the ext4 without a loop mount, and
# the fakeroot wrapper is what makes ownership survive -- without it debugfs
# cannot chown and every file lands owned by the invoking user.
#
# Usage: mkdemo-image.sh <image.qcow2|image.img> [out.sqfs]

set -e

SRC=${1:?usage: mkdemo-image.sh <image.qcow2|image.img> [out.sqfs]}
OUT=${2:-debian-demo.sqfs}
# Deliberately NOT mktemp -d: /tmp is frequently a tmpfs a few GB in size, and
# this needs room for a raw copy of the disk plus the unpacked tree. Silently
# running out of space produces truncated files and an image that boots to a
# shell but cannot exec systemd (ENOEXEC on a zero-byte binary). Ask for it
# next to the output instead, which is normally real disk.
WORK=$(cd "$(dirname "$OUT")" && pwd)/.mkdemo.$$
mkdir -p "$WORK"
trap 'rm -rf "$WORK"' EXIT

# 64K blocks: ~15% larger than 1M, but a block is the unit squashfs must
# decompress to serve any read -- and the unit an HTTP range request would
# fetch if the disk is ever served remotely. Worth the bytes.
BLOCK=64K

case "$SRC" in
*.qcow2)
	echo "==> converting qcow2 to raw"
	qemu-img convert -f qcow2 -O raw "$SRC" "$WORK/disk.img"
	DISK=$WORK/disk.img
	;;
*)
	DISK=$SRC
	;;
esac

echo "==> locating the root partition"
OFF=$(sfdisk -J "$DISK" |
	sed -n 's/.*"start": *\([0-9]*\).*/\1/p' | head -1)
[ -n "$OFF" ] || { echo "no partition table in $DISK" >&2; exit 1; }
OFF=$((OFF * 512))
echo "    root partition at byte $OFF"
dd if="$DISK" of="$WORK/root.ext4" bs=1M iflag=skip_bytes skip="$OFF" \
	conv=sparse status=none
# The raw whole-disk copy is dead weight from here on.
if [ "$DISK" = "$WORK/disk.img" ]; then rm -f "$WORK/disk.img"; fi

echo "==> extracting and packing (fakeroot: preserves ownership)"
cat > "$WORK/inner.sh" <<'INNER'
set -e
WORK=$1
BLOCK=$2
mkdir -p "$WORK/tree"
# Do not discard debugfs's stderr: rdump reports per-file failures there and
# still exits 0, so a silent ENOSPC looks like success.
debugfs -R "rdump / $WORK/tree" "$WORK/root.ext4" 2>"$WORK/rdump.err"
# Ignore debugfs's version banner and the chown failures inherent to running
# unprivileged; anything else is real.
grep -vE '^debugfs [0-9]|while changing ownership' "$WORK/rdump.err" | grep . >&2 && {
	echo "extraction reported errors (out of space?)" >&2; exit 1; }
:
cd "$WORK/tree"

# Modules and vmlinux belong to Debian's kernel; simmerv supplies its own, so
# they can never load. That is the single biggest win (~137 MB + ~83 MB).
rm -rf usr/lib/modules boot/initrd.img-* boot/vmlinux-*
# Translations, docs and package lists the demo has no use for.
# man pages are deliberately kept -- a shell you cannot look things up in is a
# worse demo, and they cost only a few MB compressed.
rm -rf usr/share/locale usr/share/doc usr/share/info \
       usr/lib/udev/hwdb.bin var/cache/apt var/lib/apt/lists

# Things a headless demo cannot use, but which apt drags in anyway.
# Mesa's software renderer and the LLVM it needs to JIT shaders: 150+ MB of
# OpenGL on a machine with no display.
rm -f usr/lib/riscv64-linux-gnu/libLLVM.so.* \
      usr/lib/riscv64-linux-gnu/libgallium-*.so
# LTO is a link-time pass nobody runs interactively (~100 MB).
rm -f usr/libexec/gcc/*/*/lto1 usr/bin/*-lto-dump-*
# Sanitizer runtimes: static archives only used with -fsanitize=.
for a in asan tsan ubsan lsan hwasan; do
	rm -f usr/lib/gcc/*/*/lib$a.a
done
# C++ compiler proper: C still builds, g++ does not (~54 MB).
rm -f usr/libexec/gcc/*/*/cc1plus
# Static archives of the C/C++ runtimes -- dynamic linking is unaffected
# (~72 MB). libgcc.a is deliberately kept: linking needs it.
rm -f usr/lib/riscv64-linux-gnu/libc.a
rm -f usr/lib/gcc/*/*/libstdc++.a usr/lib/gcc/*/*/libstdc++exp.a \
      usr/lib/gcc/*/*/libsupc++.a
# Emacs ships both .el sources and compiled .elc; the sources are ~45 MB and
# only needed to jump to the definition of a built-in. Drop a source only when
# its .elc is present, so nothing becomes unloadable.
if [ -d usr/share/emacs ]; then
	find usr/share/emacs -name '*.el.gz' | while read -r f; do
		if [ -e "${f%.el.gz}.elc" ]; then rm -f "$f"; fi
	done
	find usr/share/emacs -name '*.el' | while read -r f; do
		if [ -e "${f}c" ]; then rm -f "$f"; fi
	done
fi
# systemd spends far longer on startup than the kernel does, most of it on
# things this image has no use for: an ext4 metadata scrub on a squashfs root,
# and ifupdown waiting out a DHCP timeout on a NIC that is often not attached.
# Masking is only a symlink to /dev/null, so it can be done here rather than
# inside a booted guest -- and because the root is an overlay, anyone who does
# want these back can "systemctl unmask" them at run time.
mkdir -p etc/systemd/system
for u in e2scrub_reap.service e2scrub_all.timer \
         apt-daily.service apt-daily.timer \
         apt-daily-upgrade.service apt-daily-upgrade.timer \
         man-db.timer dpkg-db-backup.timer \
         systemd-networkd-wait-online.service \
         networking.service ifupdown-pre.service \
         ssh.service ssh.socket \
         dracut-shutdown.service; do
	ln -sf /dev/null "etc/systemd/system/$u"
done
# Nothing graphical is installed; stopping at multi-user skips a whole target.
ln -sf /usr/lib/systemd/system/multi-user.target etc/systemd/system/default.target

# Logs from whatever session built the image.
rm -rf var/log/journal/* var/log/*.log var/log/apt

# Cheap canary: these must exist and be non-empty or the image will not boot.
for f in usr/lib/systemd/systemd usr/bin/bash usr/sbin/init; do
	[ -s "$WORK/tree/$f" ] || [ -L "$WORK/tree/$f" ] || {
		echo "missing or empty after extraction: $f" >&2; exit 1; }
done

cd "$WORK"
mksquashfs tree "$WORK/out.sqfs" -comp zstd -Xcompression-level 19 \
	-b $BLOCK -no-progress -quiet
INNER
fakeroot sh "$WORK/inner.sh" "$WORK" "$BLOCK"

mv "$WORK/out.sqfs" "$OUT"
echo "==> $OUT  $(du -h "$OUT" | cut -f1)"
