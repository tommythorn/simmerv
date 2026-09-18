#!/usr/bin/env python3
"""Build a self-contained "benchmark disk" for Simmerv.

The disk carries a riscv64 Rust toolchain, a gcc link driver, and a vendored
copy of a crate to compile, so the guest can run a real rustc workload with no
network at all -- which is what makes the benchmark reproducible and runnable
under CI, where neither --vmnet (root, macOS) nor --tap (root, Linux) is
available.

Attach it as the second disk and mount it read-only:

    simmerv-cli -m 8192 --rva23 linux/fw_payload.elf \\
        -f ubuntu-26.04-preinstalled-server-riscv64.img -f bench-disk.img
    # in the guest:
    mount -o ro /dev/vdb /mnt && /mnt/bench.sh

Everything is pinned: the Rust version, the Ubuntu suite the .debs come from,
and the source revision being compiled. Change a pin and you have a different
benchmark, so record it with the result.
"""

import argparse, gzip, hashlib, os, shutil, subprocess, sys, tarfile, urllib.request
from pathlib import Path

RUST_VERSION = "1.98.1"
RUST_TARGET = "riscv64gc-unknown-linux-gnu"
RUST_COMPONENTS = ("rustc", "cargo", "rust-std")

UBUNTU_MIRROR = "http://ports.ubuntu.com/ubuntu-ports"
UBUNTU_SUITE = "resolute"
UBUNTU_ARCH = "riscv64"
# Resolved transitively against the archive index. gcc is here only as a *link
# driver*: rustc shells out to `cc` to link, and the preinstalled server image
# ships binutils and crt1.o but no compiler.
DEB_ROOTS = ("gcc",)
# Shipped by the Ubuntu image already; pulling them again would just bloat the
# disk and risk shadowing the running system's own libraries.
DEB_SKIP = {"libc6", "libc-bin", "binutils", "binutils-common",
            "binutils-riscv64-linux-gnu", "libgcc-s1", "libstdc++6", "zlib1g"}

MIB = 1024 * 1024


def log(msg): print(f"[mk-bench-disk] {msg}", flush=True)


def fetch(url, dest, sha256=None):
    if dest.exists() and (sha256 is None or sha_of(dest) == sha256):
        log(f"cached  {dest.name}")
        return dest
    log(f"fetch   {url}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    with urllib.request.urlopen(url, timeout=120) as r, open(tmp, "wb") as f:
        shutil.copyfileobj(r, f, 1 << 20)
    if sha256 and sha_of(tmp) != sha256:
        sys.exit(f"sha256 mismatch for {url}")
    tmp.rename(dest)
    return dest


def sha_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def rust_manifest(cache):
    url = f"https://static.rust-lang.org/dist/channel-rust-{RUST_VERSION}.toml"
    return fetch(url, cache / f"channel-{RUST_VERSION}.toml").read_text()


def rust_urls(manifest):
    """(xz_url, xz_hash) per component, read from the pinned channel manifest."""
    out = {}
    for comp in RUST_COMPONENTS:
        want, url, digest, inside = f"[pkg.{comp}.target.{RUST_TARGET}]", None, None, False
        for line in manifest.splitlines():
            if line.strip() == want:
                inside = True
                continue
            if inside:
                if line.startswith("["):
                    break
                if line.startswith("xz_url"):
                    url = line.split("=", 1)[1].strip().strip('"')
                elif line.startswith("xz_hash"):
                    digest = line.split("=", 1)[1].strip().strip('"')
        if not url:
            sys.exit(f"no {comp} for {RUST_TARGET} in the {RUST_VERSION} manifest")
        out[comp] = (url, digest)
    return out


def install_rust(cache, prefix):
    """Extract the dist tarballs, honouring each component's install manifest.

    A rust dist tarball is <name>/<component>/{bin,lib,...} plus a manifest
    listing the files to install; merging the component directories into one
    prefix is exactly what install.sh would do, without needing to run it.
    """
    urls = rust_urls(rust_manifest(cache))
    for comp, (url, digest) in urls.items():
        tarball = fetch(url, cache / Path(url).name, digest)
        log(f"unpack  {tarball.name}")
        with tarfile.open(tarball) as tf:
            top = tf.getnames()[0].split("/")[0]
            # The component directory is *not* always the package name:
            # rust-std's is "rust-std-<target>". Read the tarball's own
            # `components` manifest rather than guessing, because guessing wrong
            # matches no members and extracts nothing at all -- silently.
            listing = tf.extractfile(f"{top}/components")
            if listing is None:
                sys.exit(f"{tarball.name} has no components manifest")
            comp_dirs = listing.read().decode().split()
            extracted = 0
            for comp_dir in comp_dirs:
                members, strip = [], f"{top}/{comp_dir}/"
                for m in tf.getmembers():
                    if m.name.startswith(strip):
                        m.name = m.name[len(strip):]
                        if m.name:
                            members.append(m)
                tf.extractall(prefix, members=members, filter="tar")
                extracted += len(members)
            if not extracted:
                sys.exit(f"{tarball.name}: components {comp_dirs} matched no files")

    # A missing std is the failure this function is most likely to produce and
    # the least likely to be noticed until a build fails inside the guest.
    std = prefix / "lib/rustlib" / RUST_TARGET / "lib"
    if not std.is_dir() or not any(std.glob("libstd-*.rlib")):
        sys.exit(f"no std for {RUST_TARGET} under {std}")
    log(f"rust    {RUST_VERSION} ok (std at {std.relative_to(prefix)})")
    return urls


def deb_index(cache):
    gz = fetch(f"{UBUNTU_MIRROR}/dists/{UBUNTU_SUITE}/main/binary-{UBUNTU_ARCH}/Packages.gz",
               cache / f"Packages-{UBUNTU_SUITE}.gz")
    text = gzip.decompress(gz.read_bytes()).decode("utf-8", "replace")
    pkgs, provides = {}, {}
    for stanza in text.split("\n\n"):
        if not stanza.strip():
            continue
        fields = {}
        key = None
        for line in stanza.splitlines():
            if line[:1] in (" ", "\t") and key:
                fields[key] += " " + line.strip()
            elif ":" in line:
                key, _, val = line.partition(":")
                fields[key] = val.strip()
        name = fields.get("Package")
        if name and name not in pkgs:
            pkgs[name] = fields
            for prov in fields.get("Provides", "").split(","):
                prov = prov.split("(")[0].strip()
                if prov:
                    provides.setdefault(prov, name)
    return pkgs, provides


def deb_closure(pkgs, provides, roots):
    """Transitive Depends closure. Alternatives ("a | b") take the first that
    resolves; Recommends/Suggests are ignored -- this is a link driver, not a
    desktop."""
    seen, order, queue = set(), [], list(roots)
    while queue:
        name = queue.pop(0)
        name = name if name in pkgs else provides.get(name, name)
        if name in seen or name in DEB_SKIP or name not in pkgs:
            continue
        seen.add(name)
        order.append(name)
        for dep in pkgs[name].get("Depends", "").split(","):
            dep = dep.strip()
            if not dep:
                continue
            for alt in dep.split("|"):
                cand = alt.split("(")[0].strip()
                cand = cand if cand in pkgs else provides.get(cand, cand)
                if cand in pkgs:
                    queue.append(cand)
                    break
    return order


def install_debs(cache, sysroot):
    pkgs, provides = deb_index(cache)
    names = deb_closure(pkgs, provides, DEB_ROOTS)
    log(f"deb closure: {len(names)} packages")
    for name in names:
        f = pkgs[name]
        deb = fetch(f"{UBUNTU_MIRROR}/{f['Filename']}", cache / Path(f["Filename"]).name,
                    f.get("SHA256"))
        subprocess.run(["dpkg-deb", "-x", str(deb), str(sysroot)], check=True)

    # `cc` is a dpkg *alternatives* symlink, so it lives in no .deb -- but it is
    # the linker rustc invokes by default. Create it ourselves.
    cc = sysroot / "usr/bin/cc"
    if not cc.exists():
        cc.symlink_to("gcc")
    return names


def vendor_source(repo, staging, source):
    """Copy the crate to compile plus a vendored registry, so cargo never needs
    the network inside the guest.

    `source` is "head" for a committed revision -- the reproducible default, and
    the only one worth quoting a result from -- or "worktree" to benchmark
    uncommitted changes. Worktree mode copies the *tracked* files only, with
    their current contents: `git ls-files` rather than anything that walks the
    directory, because the repo routinely holds tens of GB of untracked disk
    images that must not end up on a 2 GiB benchmark disk.
    """
    src = staging / "src"
    src.mkdir(parents=True, exist_ok=True)
    crate = src / "simmerv"
    rev = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                         capture_output=True, text=True, check=True).stdout.strip()

    if source == "worktree":
        dirty = subprocess.run(["git", "-C", str(repo), "status", "--porcelain", "-uno"],
                               capture_output=True, text=True, check=True).stdout.strip()
        rev = f"{rev[:12]}-worktree" if dirty else f"{rev[:12]}-clean"
        log(f"vendor  {repo.name} @ {rev} (working tree, tracked files)")
        listing = subprocess.run(["git", "-C", str(repo), "ls-files", "-z"],
                                 capture_output=True, check=True).stdout
        for rel in listing.split(b"\0"):
            if not rel:
                continue
            rel = rel.decode()
            source_file = repo / rel
            if not source_file.is_file():   # deleted but still tracked
                continue
            dest = crate / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_file, dest)
    else:
        log(f"vendor  {repo.name} @ {rev[:12]}")
        subprocess.run(["git", "-C", str(repo), "archive", "--format=tar", "HEAD"],
                       check=True, stdout=open(src / "repo.tar", "wb"))
        with tarfile.open(src / "repo.tar") as tf:
            tf.extractall(crate, filter="tar")
        (src / "repo.tar").unlink()
    subprocess.run(["cargo", "vendor", "--versioned-dirs", str(crate / "vendor")],
                   cwd=crate, check=True, stdout=subprocess.DEVNULL)
    cargo_dir = crate / ".cargo"
    cargo_dir.mkdir(exist_ok=True)
    (cargo_dir / "config.toml").write_text(
        '[source.crates-io]\nreplace-with = "vendored-sources"\n\n'
        '[source.vendored-sources]\ndirectory = "vendor"\n')
    return rev


def write_runner(staging, rust_version, rev):
    """Emit the PID 1 entry point and the workload it runs.

    Split in two because they are used two ways: `bench-init.sh` is what
    `--append init=...` boots into (no systemd, no login, nothing in the
    measurement but the compile), while `bench.sh` is the same workload run by
    hand from an ordinary shell.
    """
    (staging / "bench-init.sh").write_text(f"""#!/bin/sh
# PID 1 for an unattended benchmark run. Boot with:
#   --append "root=/dev/vda1 rw console=ttyS0 init=/mnt/bench/bench-init.sh"
# ...except this disk is not mounted yet at that point, so the kernel needs the
# script to live on the *root* filesystem. Copy it there, or use the
# bench.mode=... cmdline knob below with the disk mounted by hand.
#
# As PID 1 there is no init system: mount what the workload needs, run it, and
# power down. Returning from PID 1 panics the kernel, so every path ends in a
# poweroff.
set -u
DISK=/mnt/bench

export PATH="$DISK/sysroot/usr/bin:$PATH"
export LD_LIBRARY_PATH="$DISK/sysroot/usr/lib/{UBUNTU_ARCH}-linux-gnu:${{LD_LIBRARY_PATH:-}}"

mount -t proc proc /proc 2>/dev/null
mount -t sysfs sysfs /sys 2>/dev/null
mount -t devtmpfs devtmpfs /dev 2>/dev/null

# Ubuntu's /sbin/poweroff is a systemd symlink and does nothing with no systemd
# running, and sysrq turned out not to fire the syscon poweroff either. So make
# the syscall directly, with the compiler this disk already carries: a five-line
# helper is more dependable than hoping a distro tool works without its init.
POWEROFF=/tmp/poweroff
build_poweroff() {{
    cat > /tmp/poweroff.c <<'CEOF'
#include <unistd.h>
#include <sys/reboot.h>
int main(void) {{ sync(); reboot(RB_POWER_OFF); return 1; }}
CEOF
    "$DISK/sysroot/usr/bin/gcc" -O0 -o "$POWEROFF" /tmp/poweroff.c 2>/tmp/poweroff.log
}}

poweroff_now() {{
    sync
    [ -x "$POWEROFF" ] || build_poweroff
    if [ -x "$POWEROFF" ]; then
        "$POWEROFF"
    fi
    # Fallbacks, in case the helper could not be built: sysrq, then a plain
    # exit. Returning from PID 1 panics the kernel, which at least ends the run
    # visibly rather than hanging forever.
    echo 1 > /proc/sys/kernel/sysrq 2>/dev/null
    echo o > /proc/sysrq-trigger 2>/dev/null
    sleep 10
    exit 0
}}

# Idempotent: this script is also run by hand from an `init=/bin/sh` shell,
# where the disk had to be mounted already to reach it.
mkdir -p "$DISK"
if ! grep -q " $DISK " /proc/mounts 2>/dev/null; then
    if ! mount -t ext4 -o ro /dev/vdb "$DISK"; then
        echo "BENCH-FAIL: cannot mount the benchmark disk at /dev/vdb"
        poweroff_now
    fi
fi

MODE=full
for arg in $(cat /proc/cmdline); do
    case "$arg" in bench.mode=*) MODE="${{arg#bench.mode=}}" ;; esac
done

echo "BENCH-BEGIN mode=$MODE"
BENCH_MODE="$MODE" "$DISK/bench.sh"
echo "BENCH-END rc=$?"
poweroff_now
""")
    (staging / "bench-init.sh").chmod(0o755)

    (staging / "bench.sh").write_text(f"""#!/bin/sh
# Simmerv benchmark workload: compile a fixed Rust crate with a pinned
# toolchain. Needs no network.
#
#   rust {rust_version} / simmerv {rev} / ubuntu {UBUNTU_SUITE}
#
# BENCH_MODE=smoke compiles a trivial crate instead -- enough to prove the
# toolchain runs at all, which is minutes rather than a long build.
set -eu
DISK="$(cd "$(dirname "$0")" && pwd)"
WORK="${{WORK:-/tmp/bench}}"
MODE="${{BENCH_MODE:-full}}"

# Build in a tmpfs: otherwise this measures virtio and the host filesystem as
# much as it measures emulation, which ruins the cross-platform comparison.
mkdir -p "$WORK"
grep -q " $WORK " /proc/mounts || mount -t tmpfs -o size=4G tmpfs "$WORK"

export PATH="$DISK/rust/bin:$DISK/sysroot/usr/bin:$PATH"
export LD_LIBRARY_PATH="$DISK/sysroot/usr/lib/{UBUNTU_ARCH}-linux-gnu:${{LD_LIBRARY_PATH:-}}"
export CARGO_HOME="$WORK/cargo-home"
export RUSTUP_TOOLCHAIN=
# codegen-units=1 and -j1 remove the two biggest sources of run-to-run
# variation; incremental is off so every run does the same work.
export CARGO_BUILD_JOBS=1
export CARGO_INCREMENTAL=0
export RUSTFLAGS="-C codegen-units=1 -C linker=$DISK/sysroot/usr/bin/gcc"

rustc --version
cc --version | head -1

elapsed() {{ cut -d' ' -f1 /proc/uptime; }}

if [ "$MODE" = smoke ]; then
    mkdir -p "$WORK/smoke"
    printf 'pub fn f(x: u64) -> u64 {{ x + 1 }}\n' > "$WORK/smoke/lib.rs"
    echo "=== smoke start ==="
    T0=$(elapsed)
    rustc --crate-type=lib -O -o "$WORK/smoke/libsmoke.rlib" "$WORK/smoke/lib.rs"
    printf 'fn main() {{ println!("linked ok"); }}\n' > "$WORK/smoke/main.rs"
    rustc -O -o "$WORK/smoke/main" "$WORK/smoke/main.rs"
    "$WORK/smoke/main"
    T1=$(elapsed)
else
    cp -a "$DISK/src/simmerv" "$WORK/simmerv"
    cd "$WORK/simmerv"
    echo "=== build start ==="
    T0=$(elapsed)
    cargo build --release --offline -p simmerv --lib
    T1=$(elapsed)
fi

echo "=== done ==="
echo "$T1 $T0" | awk '{{print "BENCH-ELAPSED", $1-$2, "s (guest uptime clock)"}}'
""")
    (staging / "bench.sh").chmod(0o755)


def build_image(staging, out, slack_mb):
    used = sum(f.stat().st_size for f in staging.rglob("*") if f.is_file())
    size_mb = used // MIB + slack_mb
    log(f"image   {size_mb} MiB ({used // MIB} MiB of content)")
    if out.exists():
        out.unlink()
    mke2fs = shutil.which("mke2fs") or "/opt/homebrew/opt/e2fsprogs/sbin/mke2fs"
    subprocess.run([mke2fs, "-q", "-t", "ext4", "-d", str(staging),
                    "-L", "simmerv-bench", "-O", "^has_journal",
                    str(out), f"{size_mb}m"], check=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-o", "--out", default="bench-disk.img")
    ap.add_argument("--cache", default=".bench-cache", help="download cache")
    ap.add_argument("--slack-mb", type=int, default=256)
    ap.add_argument("--keep-staging", action="store_true")
    ap.add_argument("--source", choices=("head", "worktree"), default="head",
                    help="build the committed HEAD (default, reproducible) or "
                         "the current working tree (for testing uncommitted changes)")
    a = ap.parse_args()

    repo = Path(__file__).resolve().parent.parent
    cache = (repo / a.cache).resolve()
    staging = cache / "staging"
    if staging.exists():
        shutil.rmtree(staging)
    (staging / "rust").mkdir(parents=True)
    (staging / "sysroot").mkdir(parents=True)

    install_rust(cache, staging / "rust")
    install_debs(cache, staging / "sysroot")
    rev = vendor_source(repo, staging, a.source)
    write_runner(staging, RUST_VERSION, rev)
    build_image(staging, (repo / a.out).resolve(), a.slack_mb)
    if not a.keep_staging:
        shutil.rmtree(staging)
    log(f"done -> {a.out}")


if __name__ == "__main__":
    main()
