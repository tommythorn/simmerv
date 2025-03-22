# Simmerv

Simmerv is a virtual [RISC-V](https://riscv.org/) processor
and peripheral devices emulator project written in Rust and
compilable to WebAssembly.

This is a substantially enhanced fork of [Takahiro's riscv-rust
original emulator](https://github.com/takahirox/riscv-rust).  This
fork is already far more complete and is working towards near 100%
correctness.  Ultimately, we also expect it to become substantially
faster, but this work is delayed until this is sufficiently correct to
run benchmarks and off-the-shelf Linux distributions.

## Online Demo

You can run Linux on the emulator in your browser. [Online demo is
here](https://tommythorn.github.io/simmerv/wasm/web/index.html)

## Screenshots

![animation](./screenshots/animation.gif)
![debugger](./screenshots/debugger.gif)

## Features

- Emulate RISC-V RV64GC_Zba_Zicond processor and peripheral devices (virtio block
  device and a UART)
- Also runnable in browser with WebAssembly
- Runnable locally
- Debugger

## Instructions/Features support status

- [x] RV64IMAC
- [x] RV64FD (*PARTIALLY* flags/rounding modes very lacking)
- [x] RV64Zifencei
- [x] RV64Zicsr
- [ ] RV64B (Zicond and Zba done)
- [ ] Svnapot
- [x] CSR (mostly done)
- [x] Sv39
- [x] Sv48 (untested, but should work)
- [x] Privileged instructions
- [ ] PMP (this is intensionally not implemented as it will negatively affect performance)

The emulator supports all instructions listed above but some 

- Boots Buildroot and Debian Trixie
- Linux OpenSBI and legacy BBL boot support

### Current Known Issues

- gdb, rustc, and Geekbench segfaults
- Ubuntu boot crashes and hangs
- Debian boot sees non-fatal crashes
- U-boot loads but hangs before hand-off


## How to run Linux

```sh
$ cargo b -r --all
$ target/release/simmerv_cli ../resources/linux/opensbi/fw_payload.elf -f ../resources/linux/rootfs.img
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
