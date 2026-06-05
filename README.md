[![Rust](https://github.com/tommythorn/simmerv/actions/workflows/rust.yml/badge.svg)](https://github.com/tommythorn/simmerv/actions/workflows/rust.yml)

# Simmerv

Simmerv is a [RISC-V](https://riscv.org/) SoC emulator written in Rust
and compilable to WebAssembly.  It began as a fork of [Takahiro's
riscv-rust emulator](https://github.com/takahirox/riscv-rust), but has
by now been extensively rewritten, making it far more complete and
much faster.  Ultimately, we expect it to become substantially faster,
but this work is delayed until we are able to run standard benchmarks
and off-the-shelf Linux distributions.

## Online Demo

You can run Linux on the emulator in your browser: [online demo is
here](https://tommythorn.github.io/simmerv/wasm/web/index.html)

## Screenshots (somewhat out of date)

![animation](./screenshots/animation.gif)
![debugger](./screenshots/debugger.gif)

## Features

- Emulates RISC-V `RV64GC_Zba_Zbb_Zbc_Zbs_Zicond_Zfhmin_Svinval_Svade_Sstc_Zicbom_Zicbop_Zicboz_Zihpm` (RVA22) processor and peripheral devices
  (CLINT, PLIC, NS16550A UART, virtio block device, and VirtIO ethernet)
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
- [x] Sv39, Sv48, Sv57
- [x] Privileged Spec 1.12 (mcounteren/scounteren, senvcfg, PMP stub with 0 entries)
- [ ] Svnapot
- [-] PMP enforcement (0 entries implemented; all accesses permitted)

The emulator supports all instructions listed above.

- Passes all riscof (RISC-V Architectural Tests) for RV64IMC
- Boots Buildroot, Debian Trixie, Ubuntu
- Linux OpenSBI and legacy BBL boot support

## How to run Linux with VirtIO Block Device (/dev/vda)

*VERY IMPORTANT: images are stored with git LFS*. Install LFS (don't
forget `git lfs install` also) and recheckout if needed.  Otherwise
the images will be small files with LFS pointers.

```sh
$ cargo r -r -- linux/fw_payload.elf -f linux/rootfs.img
```

or
```sh
$ cargo r -r -- -c linux/opensbi/fw_jump.elf,0x80000000 linux/vmlinux,0x80200000 -f linux/rootfs.img
```

## How to run Linux with initramfs (/dev/ram)

Allocate 2 GiB, use a device tree with initramfs at 0xa0000000 and
load the initrd2+gdb.cpio binary at that address.

```sh
$ (cd linux;cargo r -r -- -m 2048 -d with-initrd.dtb fw_payload.elf initrd2+gdb.cpio,0xa0000000)
```

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
