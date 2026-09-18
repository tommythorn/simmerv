#!/bin/bash
# Run the Rust-compile benchmark: build the benchmark disk if needed, boot
# Ubuntu straight into the workload, and report the rate.
#
#   ./run-bench.sh              # the full build, a couple of hours
#   ./run-bench.sh --smoke      # a trivial crate instead, a few minutes
#
# Needs no network in the guest and no root on the host, so it runs the same
# way on macOS, Linux and CI.  See "How to benchmark" in README.md.
set -u -o pipefail

cd "$(dirname "$0")" || exit 1

mode=full
disk=bench-disk.img
image=
mem=8192
source=head
rebuild=0
timeout=

usage() {
    sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
    cat <<'EOF'

Options:
  --smoke           compile a trivial crate instead of the full dependency graph
  --image PATH      Ubuntu disk image (default: the newest ubuntu-*-riscv64.img here)
  --disk PATH       benchmark disk (default: bench-disk.img, built if absent)
  --mem MB          guest memory in MiB (default: 8192)
  --source head|worktree
                    benchmark the committed HEAD (default) or the working tree
  --rebuild         rebuild the benchmark disk even if it exists
  --timeout SEC     give up after SEC without output (default: 21600, or 3600 with --smoke)
  -h, --help        this
EOF
}

die() { echo "run-bench: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --smoke)    mode=smoke ;;
        --image)    image="${2:-}"; shift ;;
        --disk)     disk="${2:-}"; shift ;;
        --mem)      mem="${2:-}"; shift ;;
        --source)   source="${2:-}"; shift ;;
        --rebuild)  rebuild=1 ;;
        --timeout)  timeout="${2:-}"; shift ;;
        -h|--help)  usage; exit 0 ;;
        *)          echo "run-bench: unknown option $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

[ -n "$timeout" ] || { [ "$mode" = smoke ] && timeout=3600 || timeout=21600; }

# The guest image.  Not downloaded automatically: it is gigabytes, and which
# release to benchmark on is a decision worth making explicitly.
if [ -z "$image" ]; then
    image=$(ls -t ubuntu-*-preinstalled-server-riscv64.img 2>/dev/null | head -1)
fi
[ -n "$image" ] && [ -f "$image" ] || die "no Ubuntu image found.  Fetch one with:
    wget https://cdimage.ubuntu.com/releases/26.04/release/ubuntu-26.04-preinstalled-server-riscv64.img.xz
    unxz ubuntu-26.04-preinstalled-server-riscv64.img.xz
  ...or point at an existing one with --image PATH."

[ -f linux/fw_payload.elf ] || die "linux/fw_payload.elf is missing"

echo "==> building the emulator"
cargo build --release -q || die "cargo build failed"
sim=target/release/simmerv-cli
[ -x "$sim" ] || die "$sim was not built"

if [ "$rebuild" = 1 ] || [ ! -f "$disk" ]; then
    echo "==> building the benchmark disk ($disk)"
    ./tools/mk-bench-disk.py --out "$disk" --source "$source" || die "could not build $disk"
else
    echo "==> reusing $disk (--rebuild to rebuild it)"
fi

log=$(mktemp -t run-bench)
echo "==> running the $mode benchmark on $image"
echo "    log: $log"

# --rva23 is required: Ubuntu's riscv64 port is RVA23-baseline and its /bin/sh
# takes an illegal instruction trap without it.
#
# --max-insns is set far above what the run needs.  It is not expected to fire;
# it is what makes the emulator print the instruction count and rate on exit,
# and it caps a run that wedges instead of letting it sit forever.
#
# init=/bin/sh skips systemd and cloud-init entirely -- both host-clock
# dependent, and neither of them part of what is being measured.
./tools/drive.py --timeout "$timeout" --log "$log" -- \
    "$sim" -m "$mem" --rva23 --max-insns 2000G \
    --append "root=/dev/vda1 rw console=ttyS0 init=/bin/sh bench.mode=$mode" \
    linux/fw_payload.elf -f "$image" -f "$disk" <<'EOF'
expect [#$] $
send mount -t proc proc /proc; mkdir -p /mnt/bench; mount -t ext4 -o ro /dev/vdb /mnt/bench && echo DISK-OK
expect DISK-OK
send exec /mnt/bench/bench-init.sh
expect BENCH-END rc=
EOF

# Guest-side lines only: drive.py echoes its own script, so a bare grep for
# BENCH-END would match the expect line and report success for a run that hung.
guest() { grep -a "$1" "$log" | grep -av '\[drive\]'; }

# tr -d '\r': the guest console ends lines with CRLF, so the exit status arrives
# as "0\r" and compares unequal to "0" -- a passing run reported as a failure.
rc=$(guest 'BENCH-END rc=' | tail -1 | sed 's/.*rc=//' | tr -d '\r[:space:]')
echo
echo "=============================== result ==============================="
guest 'BENCH-ELAPSED' | tail -1
grep -a 'insns .* MIPS' "$log" | tail -1
echo "pins: $(guest 'rustc 1' | tail -1)"
echo "======================================================================"

if [ -z "$rc" ]; then
    die "the workload never reported a result; see $log"
elif [ "$rc" != 0 ]; then
    echo "run-bench: the guest build FAILED (rc=$rc); first error:" >&2
    guest 'error\[\|^error' | head -3 | sed 's/\x1b\[[0-9;]*m//g' >&2
    exit 1
fi
echo "run-bench: ok"
