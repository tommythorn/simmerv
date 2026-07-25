#!/bin/bash
# Differential test of simmerv's V implementation against QEMU.
#
# Builds a bare-metal RVV test image, runs it on both simulators (which share
# the virt memory map) and diffs the transcripts.  The first differing line
# names the test that disagreed.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
out=${OUT:-$here/out}
mkdir -p "$out"

CC=${CC:-riscv64-linux-gnu-gcc}
QEMU=${QEMU:-qemu-system-riscv64}

echo "== generating =="
python3 "$here/gen_vtest.py" > "$out/vtest.S"

echo "== assembling =="
# The linker script puts _start at exactly 0x80000000 with no ELF headers in
# the loaded image, which is what both QEMU's -kernel and simmerv expect.
$CC -march=rv64gcv_zvfh -mabi=lp64d -nostdlib -nostartfiles -static \
    -Wl,-T,"$here/link.ld" -Wl,--no-warn-rwx-segments \
    -o "$out/vtest.elf" "$out/vtest.S" 2>&1 | grep -v 'build-id' || true

echo "== qemu =="
# Never -nographic here: it takes over the controlling terminal.
timeout 900 "$QEMU" -M virt -cpu rv64,v=true,vlen=128,elen=64,zvfh=true \
    -bios none -kernel "$out/vtest.elf" -display none -monitor none \
    -serial "file:$out/qemu.txt" < /dev/null 2>"$out/qemu.err" || true
grep -c '' "$out/qemu.txt" | sed 's/^/qemu lines: /'

echo "== simmerv =="
(cd "$root" && cargo build --release -q)
timeout 900 "$root/target/release/simmerv_cli" -V -n "$out/vtest.elf" \
    > "$out/simmerv.txt" 2>"$out/simmerv.err" < /dev/null || true
grep -c '' "$out/simmerv.txt" | sed 's/^/simmerv lines: /'

echo "== comparing =="
# Label each line with the test it belongs to so a diff points at a mnemonic.
grep -n '# --- test' "$out/vtest.S" | sed 's/.*# --- //' > "$out/labels.txt"

if diff -q <(tr -d '\r' < "$out/qemu.txt") <(tr -d '\r' < "$out/simmerv.txt") >/dev/null; then
    echo "PASS: $(grep -c '' "$out/qemu.txt") transcript lines identical"
    exit 0
fi

echo "FAIL: transcripts differ"
paste -d'|' <(sed -n '1,100000p' "$out/labels.txt") /dev/null > /dev/null 2>&1 || true
n=0
while IFS= read -r line; do
    n=$((n + 1))
    q=$(sed -n "${n}p" "$out/qemu.txt" | tr -d '\r')
    s=$(sed -n "${n}p" "$out/simmerv.txt" | tr -d '\r')
    if [ "$q" != "$s" ]; then
        label=$(sed -n "${n}p" "$out/labels.txt")
        echo "first difference at line $n  ($label)"
        echo "  qemu:    $q"
        echo "  simmerv: $s"
        break
    fi
done < "$out/qemu.txt"

# Summarise every differing test so one run shows the whole picture.
echo
echo "all differing tests:"
diff <(nl -ba "$out/qemu.txt") <(nl -ba "$out/simmerv.txt") \
    | grep -oE '^< *[0-9]+' | awk '{print $2}' \
    | while read -r ln; do sed -n "${ln}p" "$out/labels.txt"; done \
    | sort | uniq -c | sort -rn | head -60
exit 1
