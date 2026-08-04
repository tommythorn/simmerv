#!/bin/bash
# Run Tenstorrent's RISC-V architectural tests against simmerv.
#
#   tests/tenstorrent/run.sh                     # the whole bare-metal suite
#   tests/tenstorrent/run.sh machine/paging_bare # one privilege/paging group
#   tests/tenstorrent/run.sh machine/paging_bare/rv_i   # one extension
#
# The suite is not vendored: it is ~28k files. The first run clones it next to
# this script (gitignored).
#
# What is and is not expected to pass:
#   * A, C, D, F, I, M, Zba, Zbb, Zbc, Zbs pass everywhere -- every privilege
#     mode crossed with every paging mode.
#   * rv_v needs VLEN=256, which the suite is generated for and simmerv only
#     reaches with --vlen 256.  Note these tests are misfiled: the ones under
#     machine/paging_bare declare PRIV_MODE_SUPER and PAGING_MODE_SV48 in
#     their own headers, so they need the wider satp mode too.
#   * rv_zfh tests full Zfh arithmetic.  simmerv implements Zfhmin, which is
#     what RVA23 mandates, so these fail by design.
#   * rv_zfbfmin needs bf16, which simmerv does not implement.
set -u

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
suite=${SUITE:-$here/riscv_arch_tests}
sim=${SIM:-$root/target/release/simmerv_cli}
jobs=${JOBS:-$(( $(nproc) - 2 ))}
timeout_s=${TIMEOUT:-60}
out=${OUT:-$here/out}
cc=${CC:-riscv64-linux-gnu-gcc}

# Everything the tests can reach.  A single -march keeps one build command for
# every extension directory; simmerv decides what it actually implements.
march=${MARCH:-rv64imafdcv_zba_zbb_zbc_zbs_zfh_zvfh}

if [ ! -d "$suite" ]; then
    echo "== cloning tenstorrent/riscv_arch_tests =="
    git clone --depth 1 https://github.com/tenstorrent/riscv_arch_tests.git "$suite" || exit 1
fi

[ -x "$sim" ] || (cd "$root" && cargo build --release -q) || exit 1

one() {
    local s=$1 out=$2 sim=$3 tmo=$4 cc=$5 march=$6 root=$7; shift 7
    local base elf log res
    # Name outputs after the path: rv_v repeats test names under each vlmul_*
    # subdirectory, and flattening them lets parallel jobs clobber each other.
    base=$(echo "${s#"$root"/}" | sed 's|\.S$||; s|/|_|g')
    elf=$out/$base.elf; log=$out/$base.log
    # -Wl,-n (nmagic): otherwise the linker backs the first LOAD segment up a
    # page to hold the ELF headers, so a test whose .text sits exactly at
    # 0x80000000 gets a segment at 0x7ffff000 -- below RAM on this machine,
    # and on any real one with RAM starting there.
    if ! $cc -march="$march" -mabi=lp64d -nostdlib -no-pie -static -Wl,-n \
            -T "${s%.S}.ld" -o "$elf" "$s" > "$out/$base.build" 2>&1; then
        echo "BUILDFAIL $base"; return
    fi
    timeout "$tmo" "$sim" -n "$@" "$elf" > "$log" 2>&1
    [ $? -eq 124 ] && { echo "TIMEOUT $base"; return; }
    res=$(grep -m1 -oE "Test Passed|Test Failed with [0-9]+" "$log")
    case "$res" in
        "Test Passed")  echo "PASS $base" ;;
        "Test Failed"*) echo "FAIL $base" ;;
        *)              echo "NORESULT $base" ;;
    esac
}
export -f one

run_dir() {
    local dir=$1 tag args
    tag=$(echo "${dir#"$suite"/riscv_tests/bare_metal/}" | tr / _)
    # Match the machine to what the tests in this directory were generated for.
    args="--rva23"
    case "$dir" in
        *sv48*) args="$args --satp-mode sv48" ;;
        *sv57*) args="$args --satp-mode sv57" ;;
    esac
    # rv_v is generated for VLEN=256, and (despite its location) for Sv48.
    case "$dir" in
        */rv_v|*/rv_v/*) args="--rva23 --vlen 256 --satp-mode sv57" ;;
    esac

    mkdir -p "$out/$tag"
    # shellcheck disable=SC2086
    find "$dir" -name '*.S' | sort |
        xargs -P "$jobs" -I{} bash -c 'one "$@"' _ {} "$out/$tag" "$sim" \
            "$timeout_s" "$cc" "$march" "$dir" $args > "$out/$tag/results.txt"

    local total pass
    total=$(grep -c '' "$out/$tag/results.txt")
    pass=$(grep -c '^PASS' "$out/$tag/results.txt")
    printf "%-46s %5d / %-5d %s\n" "${dir#"$suite"/riscv_tests/bare_metal/}" \
        "$pass" "$total" \
        "$(grep -vE '^PASS' "$out/$tag/results.txt" | awk '{print $1}' | sort | uniq -c | tr '\n' ' ')"
    [ "$pass" -eq "$total" ]
}

mkdir -p "$out"
base=$suite/riscv_tests/bare_metal
target=${1:-}
rc=0
if [ -n "$target" ] && [ -d "$base/$target" ] && find "$base/$target" -maxdepth 1 -name '*.S' | grep -q .; then
    run_dir "$base/$target" || rc=1
else
    for d in $(find "$base/${target:-}" -type d | sort); do
        find "$d" -maxdepth 1 -name '*.S' | grep -q . || continue
        run_dir "$d" || rc=1
    done
fi
exit $rc
