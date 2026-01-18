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

- Emulates RISC-V `RV64GC_Zba_Zicond` processor and peripheral devices
  (PLIC, CLINT, virtio block device and a UART)
- Targets native and WASM

## Instructions/Features support status

- [x] RV64IMAC
- [x] RV64FD (*PARTIALLY*: flags/rounding modes not complete for all insns)
- [x] RV64Zifencei
- [x] RV64Zicsr
- [ ] Svnapot
- [x] Zba (part of "B", RVA22)
- [ ] Zbb (part of "B", RVA22)
- [ ] Zbs (part of "B", RVA22)
- [x] Zicond
- [x] CSR (nearly complete)
- [x] Sv39, Sv48, Sv57
- [x] Privileged instructions
- [-] PMP (this is intensionally not implemented as it will negatively affect performance)

The emulator supports all instructions listed above but some (like
many FP instructions) are not 100% to the spec.

- Boots Buildroot and Debian Trixie
- Linux OpenSBI and legacy BBL boot support

### Current Issues Being Worked

- Newer Linux kernel have issues with VirtIO block devices (initramfs works)
- U-boot loads but hangs before hand-off; might be an issue with ELF loading

### High Priority Work Post Issues

- Snapshot and resume

- Disk support without an in-memory copy (can WASM support this?)

- Improve the disassembler to recognize pseudo ops like li, mv, ret,
  etc. (This requires a structural change).

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

```sh
$ cargo r --example sim -r -- -d linux/with-initrd.dtb linux/fw_payload.elf linux/initrd.xz,0xa0000000
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
