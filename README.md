[![Rust](https://github.com/tommythorn/simmerv/actions/workflows/rust.yml/badge.svg)](https://github.com/tommythorn/simmerv/actions/workflows/rust.yml)

# Simmerv

Simmerv is a high-performance full RVA23 and RVA22 [RISC-V](https://riscv.org/) SoC emulator written in Rust
and compilable to WebAssembly.

## Online Demo

You can run Linux on the emulator in your browser: [online demo is
here](https://tommythorn.github.io/simmerv/)

## Booting Ubuntu on Simmerv (sped up 50 X)

![Installing and running Ubuntu](screenshots/simmerv.gif)

## Quick start: boot Ubuntu in three steps

```sh
wget https://cdimage.ubuntu.com/releases/26.04/release/ubuntu-26.04-preinstalled-server-riscv64.img.xz
unxz ubuntu-26.04-preinstalled-server-riscv64.img.xz
cargo r -rq -- -m 8192 --rva23 linux/fw_payload.elf -f ubuntu-26.04-preinstalled-server-riscv64.img
```

## Features

- Emulates RISC-V `RV64GC_Zba_Zbb_Zbc_Zbs_Zicond_Zfhmin_Svinval_Svade_Svpbmt_Sstc_Zicbom_Zicbop_Zicboz_Zihpm` (RVA22) processor and peripheral devices
  (CLINT, PLIC, NS16550A UART, virtio block device, and VirtIO ethernet)
- Optional RVA23 mode, enabled with `--rva23`: the `V` vector extension
  (RVV 1.0, `ELEN`=64, `VLEN`=128 or 256 via `--vlen`) plus Zcb, Zimop,
  Zcmop, Zfa, Zawrs, Zacas, Zabha, Zvbb, Zvkt and Zihintntl.  Boots the RVA23
  port of Ubuntu 26.04.
- Targets native and WASM
- Snapshots
- Speedometer

## Instructions/Features support status

### RVA22 profile (complete)

- [x] RV64IMAC
- [x] RV64FD
- [x] RV64Zifencei
- [x] RV64Zicsr
- [x] Zba, Zbb, Zbc, Zbs ("B" extension)
- [x] Zicond
- [x] Zfhmin (half-precision float conversions)
- [x] Zihpm (hardware performance counters)
- [x] Zicbom, Zicbop, Zicboz (cache block operations)
- [x] Svinval (fine-grained TLB invalidation)
- [x] Svade (hardware A/D fault-on-access)
- [x] Sstc (stimecmp/menvcfg timer compare)
- [x] Sv39, Sv48, Sv57 (the wider two are opt-in: see `--satp-mode`)
- [x] Svpbmt (page-based memory types; PTEs accepted, no caches to model)
- [x] Privileged Spec 1.12 (mcounteren/scounteren, senvcfg, PMP stub with 0 entries)
- [x] Svnapot
- [-] PMP enforcement (0 entries implemented; all accesses permitted)

The emulator supports all instructions listed above.

- Passes all riscof (RISC-V Architectural Tests) for RV64IMC
- Boots Buildroot, Debian Trixie, Ubuntu
- Linux OpenSBI and legacy BBL boot support

### RVA23 profile (in progress)

- [x] **V** — the vector extension, RVV 1.0.  All of `Zve64d` plus the full
      `V` instruction set: configuration, unit-stride / strided / indexed /
      segment / whole-register / fault-only-first loads and stores, the
      integer, fixed-point, mask, permutation and floating-point operations,
      and the `vstart` / `vl` / `vtype` / `vxrm` / `vxsat` / `vcsr` / `vlenb`
      CSRs with `mstatus.VS`.  `VLEN` defaults to 128 (`Zvl128b`, the profile
      minimum); `--vlen 256` selects `Zvl256b` instead.
- [x] Zvfh, Zvfhmin — vector half-precision (the full arithmetic set, which is
      a superset of the `Zvfhmin` the profile requires)
- [x] Zvkt, Zkt — constant-time execution; trivially satisfied by a functional
      model with no data-dependent timing
- [x] Zicond, Zfhmin, Zicbom/z/p, Svinval, Svnapot, Svpbmt, Sstc, Svade
      (inherited from RVA22)
- [x] Zcb — the newer compressed encodings.  Each one abbreviates an
      instruction the emulator already had, so all twelve decode straight to
      that uop rather than to a parallel execution path.
- [x] Zimop, Zcmop — may-be-operations.  `mop.r.n` / `mop.rr.n` write zero to
      `rd`; `c.mop.n` changes no architectural state at all.
- [x] Zfa — `fli` (both constant tables), `fminm`/`fmaxm`, the quiet compares
      `fleq`/`fltq`, `fround`/`froundnx` and `fcvtmod.w.d`.  The
      half-precision members are omitted: they need full `Zfh`, which RVA23
      does not mandate and this emulator does not implement.
- [x] Zvbb — vector basic bit manipulation (`vandn`, `vbrev`, `vbrev8`,
      `vrev8`, `vclz`, `vctz`, `vcpop`, `vrol`, `vror`, `vwsll`), and with it
      `Zvkb`, which is a strict subset
- [x] Zawrs — wait-on-reservation-set.  Both forms may terminate the wait
      immediately and for any reason, so both retire as no-ops.
- [x] Zacas — `amocas.b/h/w/d/q`, including the quadword form over even/odd
      register pairs
- [x] Zabha — byte and halfword forms of every AMO
- [x] Zihintntl — non-temporal locality hints.  The four hints are
      `ADD x0, x0, x2..x5` (and the `C.ADD x0, x2..x5` compressed forms), so
      any conforming hart already retires them as no-ops; a functional model
      has no cache hierarchy to hint at, which is the same reason `Zkt` and
      `Zvkt` are satisfied for free.  Verified to leave `x0` and the source
      registers untouched.
- [x] Sv48, Sv57 in `satp`.  Opt-in with `--satp-mode sv48` / `sv57`, because
      Linux keeps the widest mode `satp` accepts: defaulting to Sv57 would move
      every existing guest onto a deeper page table.  Exercised by the
      Tenstorrent suite's `paging_sv48` and `paging_sv57` groups.
- [ ] Supm / Ssnpm / Smnpm — pointer masking.  **Deferred.**  Nothing depends
      on it: masking is opt-in per process (`prctl(PR_SET_TAGGED_ADDR_CTRL)`),
      so software that does not find it simply does not tag pointers, and the
      one real beneficiary -- HWASAN, which is why Android leans on Arm's
      equivalent TBI -- does not exist for RISC-V yet.  Nor would an emulator
      gain what the feature is *for*: the point is that hardware ignores the
      tag bits for free, and here that is just "do not fault on these
      addresses".  Revisit if LLVM gains RISC-V HWASAN, or a distro ships
      HWASAN-instrumented RISC-V packages.
- [x] Sscofpmf — count-overflow interrupts.  A counter wrapping past all-ones
      sets `OF` on the 0->1 edge and raises `LCOFIP`; the interrupt is
      delivered as `CounterOverflowInterrupt` and `scountovf` reflects it.
      Advertised in both device trees.
- [x] Ssstateen / Smstateen — the state-enable CSRs.  `mstateen0`'s `SE0` and
      `ENVCFG` bits gate `sstateen0` and `senvcfg` below M-mode; every other
      bit, and `mstateen1..3` / `sstateen0..3` entire, reads zero, because the
      state those bits guard (AIA, IMSIC, `Zcmt`'s `jvt`, `Zfinx`'s `fcsr`,
      custom) does not exist here.  `mstateen0` resets permissive rather than
      to the architectural zero: the only state it gates is `senvcfg`, so
      denying by default protects nothing while breaking any firmware that
      predates Smstateen and never opens the gate.
- [ ] H — the hypervisor extension, required by RVA23S64.  **Deferred.**  Not
      needed to *run* Linux, only to host it: a guest that finds no H simply
      offers no KVM.  It is also the largest item by a distance -- two-stage
      translation, the VS-mode CSR bank, the hypervisor load/stores -- and it
      lands on the MMU fast path.  Tenstorrent's suite ships an `h_ext` test
      tree that is skipped for now, so the tests are waiting whenever it is
      picked up.

So RVA23 is **complete but for `Supm` and `H`**, both deferred above for the
same reason: nothing depends on either, and neither blocks anything simmerv is
for.

Coverage is not self-reported: the user-mode set is exercised by Tenstorrent's
architectural tests (see `tests/tenstorrent/run.sh`) and the vector
implementation is diffed against QEMU instruction by instruction at both
`VLEN` widths (`tests/vector/run.sh`).

The device trees advertise what is implemented, so a guest can discover it.
That includes the default (non-`--rva23`) machine, which used to name only
`imafdc` plus a handful of CSR extensions despite always having had the
bitmanip set, `Zicond`, `Zfhmin` and the cache-block operations.

`V`, Zcb, Zimop, Zcmop, Zfa, Zvbb, Zawrs, Zacas and Zabha are off by default and
enabled together by `--rva23`, so that a run without the flag still models a hart
that traps every one of those encodings.  (The entries inherited from RVA22 are
always on.)  RVA23 mandates `V`, so one switch covers the lot: it gates
instruction decoding, the `misa` `V` bit and the vector CSRs, and swaps in a
device tree whose cpu node advertises the profile.

```sh
$ cargo r -r -- --rva23 -n my-vector-program.elf
```

To boot the RVA23 port of Ubuntu, the guest kernel must also have been built
with `CONFIG_RISCV_ISA_V=y` — without it the kernel drops `v` from the ISA it
parses out of the device tree, and an RVA23 userland dies on the first vector
instruction in `ld.so`, because the profile lets glibc emit vector code with no
scalar fallback.  `riscv: base ISA extensions` in the boot log is the thing to
check: it should read `acdfimv`.

```sh
$ cargo r -r -- --rva23 -f ubuntu-26.04-preinstalled-server-riscv64.img \
      fw_payload.bin,0x80000000
```

`tests/vector/run.sh` builds a bare-metal exerciser — 1994 instruction cases
across every SEW, LMUL, rounding mode and addressing form, covering the RVA23
additions as well as base RVV — and diffs simmerv's transcript against QEMU's
`virt` machine, which shares simmerv's memory map.  All 1994 transcript lines
currently match exactly, with three traps on both sides: `vwsll` at `SEW`=64,
where the widened element exceeds `ELEN` and the encoding must be illegal.

One deliberate difference: simmerv enforces `vill`, register-group alignment,
EMUL range and the "masked instruction may not write v0" rule, but not the
finer source/destination overlap constraints (a narrowing `vs1` inside the
double-width `vs2` group, a segment-load destination overlapping the index
group).  QEMU raises an illegal instruction for those; simmerv executes them.
No conforming assembler emits them.

## How to run Linux with VirtIO Block Device (/dev/vda)

*VERY IMPORTANT: images are stored with git LFS*. Install LFS (don't
forget `git lfs install` also) and recheckout if needed.  Otherwise
the images will be small files with LFS pointers.

```sh
$ cargo r -r -- linux/fw_payload.bin,0x80000000 -f linux/rootfs.img
```

or
```sh
$ cargo r -r -- -c linux/opensbi/fw_jump.elf,0x80000000 linux/vmlinux,0x80200000 -f linux/rootfs.img
```

## How to run Linux with an initramfs

`-i`/`--initfs` takes a cpio archive, loads it into RAM *below* the device
tree, and inserts the `linux,initrd-start` / `linux,initrd-end` properties into
the tree's `/chosen` node so the kernel finds it.  Nothing else has to be
arranged: no address to work out, and no hand-maintained device tree.

```sh
$ cargo r -r -- -m 2048 -i linux/gb6.cpio linux/fw_payload.bin,0x80000000
```

The tree is placed at the top of RAM and the ramdisk goes flush underneath it,
page-aligned:

```
initrd linux/gb6.cpio: [0xe608b000, 0xffffe600) = 435631616 byte(s), device tree at 0xfffff000
```

The end sits a little below the tree (2560 bytes here) because the start is
rounded down to a page boundary; `end - start` is always exactly the file's
length.

The properties are inserted, never overwritten. If the tree you pass to `-d`
already defines them, it is stating where its ramdisk lives, and `-i` refuses
rather than silently contradicting it:

```sh
$ cargo r -r -- -m 2048 -i linux/gb6.cpio -d linux/with-initrd.dtb linux/fw_payload.bin,0x80000000
Error: /chosen already defines linux,initrd-start (8 byte(s) at 0xb8); this
device tree pins its own ramdisk address, so placing one would contradict it.
Remove the property to let the emulator choose an address, or keep this tree
and supply no ramdisk of your own
```

Append `,0xADDR` to pin the ramdisk's address instead of deriving it
(`-i linux/gb6.cpio,0xa0000000`). The address must still leave room for the
tree, and the properties are still written.

### Seeing what the guest sees

`--dumpdtb` writes the *effective* device tree — after the memory-size patch
and after any `-i` properties have been inserted — to stdout and exits without
running. That is byte-for-byte what the kernel would have been handed, which
makes it the quickest way to check a layout:

```sh
$ cargo r -r -- --dumpdtb -m 2048 -i linux/gb6.cpio | dtc -I dtb -O dts | sed -n '/chosen/,/};/p'
	chosen {
		bootargs = "console=ttyS0 earlycon=sbi root=/dev/vda1 rw ignore_loglevel random.trust_bootloader=on";
		stdout-path = "/uart@10000000";
		rng-seed = <...>;
		linux,initrd-start = <0x00 0xe608b000>;
		linux,initrd-end = <0x00 0xffffe600>;
	};
```

Note the stdout: redirect the blob to a file, and keep in mind that the
emulator's own diagnostics go to stderr for exactly this reason.

### Why this exists

`linux/with-initrd.dtb`, the wasm demo's `linux/demo/demo.dtb` and the
`linux/tiny128.dtb` placeholder were each hand-maintained trees that freeze a
ramdisk address in them — `demo/build.sh` had to compute
`INITRD_ADDR=0x9e000000`, sed the two properties into a copy of `dts.dts`, and
`index.html` had to repeat the same address so the host side loaded the file to
the right place. Three files, two languages and one number that had to agree
everywhere.

`-i` removes that on the `sim` path, and the wasm demo drops it too: it now
calls the same machinery through `setup_initrd` on the emulator's default tree,
so `demo.dtb` is deleted, `build.sh` builds nothing but the initramfs, and no
address appears anywhere. The remaining trees still work — `tiny128.dtb` is a
placeholder that pins its own ramdisk, and `with-initrd.dtb` is what `-i`
refuses by name — but neither is how you should boot a ramdisk.

`linux/demo/build.sh` also used to strip `root=/dev/vda1 rw` from the tree's
`bootargs`, since the demo's init chooses its own root. That is unnecessary: the
kernel runs the initramfs's `/init` when there is one, and `root=` is never
consulted. Booting the demo geometry with the stock tree and `-i` reaches a
login prompt, which is the check that this holds.

## How to set up networking (VirtIO-net)

Simmerv emulates a VirtIO-net device (MAC `52:54:00:12:34:56`) on the second
virtio-mmio window. The built-in device tree already declares it, so a guest
kernel with `CONFIG_VIRTIO_NET` probes it automatically — but the device stays
inert (packets are dropped) until you attach a host backend. There is no
built-in emulator NAT/DHCP other than what the backend provides.

### Linux: TAP interface (`-T`)

On Linux, Simmerv connects the guest's NIC to a **TAP** device — a raw
layer-2 link with no DHCP or NAT of its own, so you configure the host side
and give the guest a static address (or bridge `tap0` into a real network if
you prefer).

1. Create a persistent TAP owned by your user (so Simmerv needs no root):

```sh
$ sudo ip tuntap add dev tap0 mode tap user $USER
$ sudo ip link set tap0 up
$ sudo ip addr add 172.16.0.1/24 dev tap0
```

2. *For guest internet access*, enable forwarding + NAT on the host. The
   MASQUERADE rule must name your **internet-facing** interface — auto-detect
   it from the default route rather than assuming `eth0`:

```sh
$ UPLINK=$(ip route show default | awk '{print $5; exit}')   # e.g. enp9s0, wlan0
$ echo "NAT via uplink: $UPLINK"                              # sanity-check it
$ sudo sysctl -w net.ipv4.ip_forward=1
$ sudo iptables -t nat -A POSTROUTING -s 172.16.0.0/24 -o "$UPLINK" -j MASQUERADE
$ sudo iptables -A FORWARD -i tap0 -j ACCEPT
$ sudo iptables -A FORWARD -o tap0 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

   If the guest reaches the host (`172.16.0.1`) but nothing beyond it, this
   rule is almost always the culprit — check it with
   `sudo iptables -t nat -L POSTROUTING -n -v` (wrong `out` interface, or a
   `pkts` count stuck at 0 while the guest generates traffic).

3. Run Simmerv attached to the TAP (`-T <ifname>`):

```sh
$ cargo r -r -- -T tap0 linux/fw_payload.bin,0x80000000 -f linux/rootfs.img
```

4. Configure the interface inside the guest (the name may be `eth0`,
   `enp0s…`, etc. — check `ip link`):

```sh
# in the guest
$ ip addr add 172.16.0.2/24 dev eth0
$ ip link set eth0 up
$ ip route add default via 172.16.0.1        # only needed for step 2
$ echo 'nameserver 1.1.1.1' > /etc/resolv.conf
```

Host (`172.16.0.1`) and guest (`172.16.0.2`) can now ping each other; with
step 2 the guest also reaches the internet. Remove the TAP afterwards with
`sudo ip tuntap del dev tap0 mode tap`.

### macOS: vmnet shared/NAT (`--vmnet`)

On macOS, Simmerv uses Apple's `vmnet.framework` in **shared mode**, which
supplies DHCP *and* NAT automatically — the guest just needs to request an
address. `vmnet` shared mode requires elevated privileges, so run under
`sudo`. Build first so `sudo` doesn't rebuild the tree as root:

```sh
$ cargo build -r
$ sudo ./target/release/simmerv-cli --vmnet linux/fw_payload.bin,0x80000000 -f linux/rootfs.img
```

The guest receives an address on vmnet's subnet (typically `192.168.x.x`) with
NAT to the host's network. If your guest image doesn't bring the link up
automatically, run a DHCP client inside it:

```sh
# in the guest
$ udhcpc -i eth0        # busybox; or: dhclient eth0
```

(`-T`/`--tap` is Linux-only and `--vmnet` is macOS-only; each errors out on the
other platform.)

## How to benchmark

The benchmark workload is a Rust compile: `rustc` is LLVM plus a large frontend
on top, so it has the instruction footprint that a boot or a small kernel like
coremark does not. `tools/mk-bench-disk.py` builds a disk carrying a pinned
riscv64 Rust toolchain, a gcc link driver, this repo's source and a vendored
registry, so the guest compiles entirely offline -- no networking, and so no
root, on any platform:

```sh
$ ./tools/mk-bench-disk.py                 # ~2 GiB, downloads cached in .bench-cache
$ ./tools/drive.py --timeout 21600 -- \
    ./target/release/simmerv-cli -m 8192 --rva23 --max-insns 2000G \
    --append "root=/dev/vda1 rw console=ttyS0 init=/bin/sh bench.mode=full" \
    linux/fw_payload.elf \
    -f ubuntu-26.04-preinstalled-server-riscv64.img -f bench-disk.img <<'EOF'
expect [#$] $
send mount -t proc proc /proc; mkdir -p /mnt/bench; mount -t ext4 -o ro /dev/vdb /mnt/bench && echo DISK-OK
expect DISK-OK
send exec /mnt/bench/bench-init.sh
expect BENCH-END rc=
EOF
```

The guest compiles `simmerv`'s lib and its dependencies and then powers itself
off, so the run is unattended. The emulator reports on exit:

```
insns 1005524461313 in 8094.782 s = 124.2 MIPS
```

`bench.mode=smoke` on the kernel command line substitutes a trivial crate,
which takes seconds instead of a couple of hours and is enough to check the
toolchain works. `--source worktree` builds uncommitted changes instead of
`HEAD`, tagging the reported revision so the result cannot be mistaken for a
committed one.

Everything the disk carries is pinned -- the Rust version, the Ubuntu suite the
`.deb`s come from, and the source revision -- because changing any of them
makes it a different benchmark. Record them with the result; the generated
`bench.sh` states all three.

### Comparing platforms: `--max-insns`

`--max-insns N` stops after `N` instructions (a `k`/`M`/`G` suffix is accepted)
and reports the rate. A fixed instruction budget is the same amount of work on
every host, which a fixed wall-clock window is not, so it is the flag to use
when comparing machines or builds:

```sh
$ cargo r -rq -- -n --max-insns 200M -m 2048 linux/fw_payload.elf -f linux/rootfs.img
insns 200000124 in 0.799 s = 250.4 MIPS
```

It fixes the instruction *count*, not the instruction *stream*: a Linux boot
still takes a slightly different path from run to run, because its timer
interrupts follow the host clock. So this makes rates comparable across hosts;
it does not by itself make a boot a valid A/B for an emulator change.

### Running a guest unattended: `--append`

`--append` replaces the device tree's `/chosen/bootargs`, which is what lets a
run skip userspace entirely:

```sh
$ cargo r -rq -- --append "root=/dev/vda1 rw console=ttyS0 init=/bin/sh" \
    -m 8192 --rva23 linux/fw_payload.elf -f ubuntu-26.04-preinstalled-server-riscv64.img
```

Booting Ubuntu 26.04 this way reaches a root shell in about 0.4 s of guest
time. It also keeps systemd and cloud-init, whose ordering follows the host
clock, out of whatever is being measured. Note that Ubuntu 26.04's riscv64 port
is RVA23-baseline: without `--rva23` its `/bin/sh` takes an illegal-instruction
trap and the kernel panics immediately.

It is applied after `-d`, so it overrides a supplied tree, and before
`--dumpdtb`, so the dump shows the command line that would really be used.

## How to run riscv-tests

```sh
$ ./run-riscv-tests.sh
```

## How to import and use WebAssembly RISC-V emulator in a web browser

See [wasm/web](https://github.com/tommythorn/simmerv/tree/master/wasm/web)

## How to install and use WebAssembly RISC-V emulator npm package

See [wasm/npm](https://github.com/tommythorn/simmerv/tree/master/wasm/npm)

## Links

### Linux RISC-V port

[Running 64-bit RISC-V Linux on QEMU](https://risc-v-getting-started-guide.readthedocs.io/en/latest/linux-qemu.html)

### Specifications

- [RISC-V ISA](https://riscv.org/specifications/)
- [Virtio Device](https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html)
- [UART](http://www.ti.com/lit/ug/sprugp1/sprugp1.pdf)
- [CLINT, PLIC (SiFive E31 Manual)](https://sifive.cdn.prismic.io/sifive%2Fc89f6e5a-cf9e-44c3-a3db-04420702dcc1_sifive+e31+manual+v19.08.pdf)
- [SiFive Interrupt Cookbook](https://sifive.cdn.prismic.io/sifive/0d163928-2128-42be-a75a-464df65e04e0_sifive-interrupt-cookbook.pdf)
