//! `--graphics`: carving a `simple-framebuffer` out of the top of RAM and
//! advertising it in the device tree.
//!
//! As in `initrd.rs`, the trees are the shipped ones, whose zero slack means
//! the node and the `/memreserve/` entry force a rebuild in which every header
//! offset has to move consistently.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use simmerv::Emulator;
use simmerv::fdt;
use simmerv::uop_cache::CacheMode;

const DTB: &[u8] = include_bytes!("../src/device/dtb.dtb");
const DTB_V: &[u8] = include_bytes!("../src/device/dtb-v.dtb");
const INITRD: &[u8] = include_bytes!("../linux/demo/initramfs.cpio");

fn header(dtb: &[u8]) -> [u32; 10] {
    let mut out = [0u32; 10];
    for (i, word) in out.iter_mut().enumerate() {
        *word = u32::from_be_bytes(dtb[i * 4..i * 4 + 4].try_into().unwrap());
    }
    out
}

fn emulator(ram_megs: usize) -> Emulator {
    Emulator::new(
        Box::new(simmerv::buffered_serial_backend::BufferedSerialBackend::new()),
        ram_megs * 1024 * 1024,
        1024,
        CacheMode::Skew,
    )
}

/// Every property of root-level `node`, as `(name, value)`, found by walking.
fn node_props(dtb: &[u8], node: &str) -> Option<Vec<(String, Vec<u8>)>> {
    let h = header(dtb);
    let (off_struct, off_strings) = (h[2] as usize, h[3] as usize);
    let struct_end = off_struct + h[9] as usize;
    let (mut pos, mut depth, mut inside, mut props) = (off_struct, 0u32, false, None);
    while pos + 4 <= struct_end {
        let token = u32::from_be_bytes(dtb[pos..pos + 4].try_into().unwrap());
        pos += 4;
        match token {
            1 => {
                let end = dtb[pos..].iter().position(|&b| b == 0).unwrap() + pos;
                depth += 1;
                if depth == 2 && &dtb[pos..end] == node.as_bytes() {
                    inside = true;
                    props = Some(Vec::new());
                }
                pos = (end + 1 + 3) & !3;
            }
            2 => {
                if depth == 2 {
                    inside = false;
                }
                depth -= 1;
            }
            3 => {
                let len = u32::from_be_bytes(dtb[pos..pos + 4].try_into().unwrap()) as usize;
                let nameoff =
                    u32::from_be_bytes(dtb[pos + 4..pos + 8].try_into().unwrap()) as usize;
                let value = dtb[pos + 8..pos + 8 + len].to_vec();
                pos += 8 + ((len + 3) & !3);
                let at = off_strings + nameoff;
                let end = dtb[at..].iter().position(|&b| b == 0).unwrap() + at;
                if inside && depth == 2 {
                    let name = String::from_utf8(dtb[at..end].to_vec()).unwrap();
                    props.as_mut().unwrap().push((name, value));
                }
            }
            9 => break,
            _ => {}
        }
    }
    props
}

fn prop<'a>(props: &'a [(String, Vec<u8>)], name: &str) -> &'a [u8] {
    &props.iter().find(|(n, _)| n == name).unwrap().1
}

#[test]
fn embed_adds_a_coherent_node_and_reservation() {
    let fb = fdt::Framebuffer {
        base: 0xfff0_0000,
        size: 0x10_0000,
        width: 800,
        height: 600,
    };
    for dtb in [DTB, DTB_V] {
        let out = fdt::embed_framebuffer(dtb, &fb).unwrap();
        let h = header(&out);
        assert_eq!(h[1] as usize, out.len());
        assert_eq!(h[1], h[3] + h[8], "strings block does not end the blob");
        assert_eq!(h[3], h[2] + h[9], "structure block does not abut strings");
        assert_eq!(fdt::mem_reserve_ranges(&out), [
            (0x8000_0000, 0x8020_0000),
            (0xfff0_0000, 0x1_0000_0000)
        ]);

        let props = node_props(&out, "framebuffer@fff00000").unwrap();
        assert_eq!(prop(&props, "compatible"), b"simple-framebuffer\0");
        assert_eq!(prop(&props, "format"), b"r5g6b5\0");
        assert_eq!(prop(&props, "width"), 800u32.to_be_bytes());
        assert_eq!(prop(&props, "height"), 600u32.to_be_bytes());
        assert_eq!(prop(&props, "stride"), 1600u32.to_be_bytes());
        assert_eq!(
            prop(&props, "reg"),
            [0, 0xfff0_0000u32, 0, 0x10_0000]
                .map(u32::to_be_bytes)
                .concat()
        );
        // Existing names still resolve after the strings block moved.
        let uart = node_props(&out, "uart@10000000").unwrap();
        assert_eq!(prop(&uart, "compatible"), b"ns16550a\0");
    }
}

#[test]
fn the_region_is_a_power_of_two_aligned_to_itself_at_the_top_of_ram() {
    // 1024x768x2 = 1.5 MiB, so 2 MiB.
    let mut emu = emulator(2048);
    let fb = emu.setup_framebuffer(1024, 768).unwrap();
    assert_eq!((fb.base, fb.size), (0xffe0_0000, 0x20_0000));
    assert_eq!(fb.base % fb.size, 0);
    assert_eq!(fb.visible_len(), 1024 * 768 * 2);

    // RAM whose top is not aligned to the size: the region rounds down.
    let mut emu = emulator(2047);
    let fb = emu.setup_framebuffer(1024, 768).unwrap();
    assert_eq!(fb.base % fb.size, 0);
    assert!(fb.base + fb.size <= 0x8000_0000 + 2047 * 1024 * 1024);
}

#[test]
fn the_tree_and_initrd_go_below_the_framebuffer() {
    let mut emu = emulator(512);
    let fb = emu.setup_framebuffer(800, 600).unwrap();
    let initrd = emu.setup_initrd(INITRD).unwrap();
    assert!(initrd.end <= initrd.dtb_base);
    assert!(initrd.dtb_base + emu.effective_dtb().len() as u64 <= fb.base);
    assert!(node_props(emu.effective_dtb(), &format!("framebuffer@{:x}", fb.base)).is_some());

    // The framebuffer starts black, not with the tree that used to be there.
    let pixels = emu
        .cpu
        .get_mut_mmu()
        .dma_slice(fb.base, usize::try_from(fb.size).unwrap())
        .unwrap();
    assert!(pixels.iter().all(|&b| b == 0));
}

#[test]
fn the_framebuffer_survives_an_rva23_tree_swap() {
    let mut emu = emulator(512);
    let fb = emu.setup_framebuffer(640, 480).unwrap();
    emu.set_rva23_enabled(true);
    assert!(node_props(emu.effective_dtb(), &format!("framebuffer@{:x}", fb.base)).is_some());
}

#[test]
fn bad_sizes_are_refused() {
    let mut emu = emulator(64);
    assert!(emu.setup_framebuffer(0, 600).is_err());
    // 4096x8192x2 = 64 MiB, all of RAM.
    assert!(emu.setup_framebuffer(4096, 8192).is_err());
    assert!(emu.framebuffer().is_none());

    let mut emu = emulator(512);
    emu.setup_initrd(INITRD).unwrap();
    assert!(emu.setup_framebuffer(800, 600).is_err());
}

#[test]
fn the_keyboard_is_a_virtio_node_on_the_plic() {
    let mut emu = emulator(512);
    emu.setup_framebuffer(800, 600).unwrap();
    emu.setup_keyboard().unwrap();
    let props = node_props(emu.effective_dtb(), "virtio_mmio@10004000").unwrap();
    assert_eq!(prop(&props, "compatible"), b"virtio,mmio\0");
    assert_eq!(prop(&props, "interrupts"), 4u32.to_be_bytes());
    // The PLIC's phandle in dts.dts.
    assert_eq!(prop(&props, "interrupt-parent"), 3u32.to_be_bytes());
    assert_eq!(
        prop(&props, "reg"),
        [0, 0x1000_4000u32, 0, 0x1000]
            .map(u32::to_be_bytes)
            .concat()
    );
    // The device answers as virtio-input (ID 18).
    assert_eq!(emu.cpu.get_mut_mmu().load_mmio(0x1000_4008, 4), Ok(18));
    assert!(emu.setup_keyboard().is_err());
}

#[test]
fn a_snapshot_with_a_keyboard_restores() {
    let mut emu = emulator(64);
    emu.setup_framebuffer(320, 200).unwrap();
    emu.setup_keyboard().unwrap();
    let snap = emu.snapshot_bytes().unwrap();
    let mut fresh = emulator(64);
    fresh.load_snapshot(&snap).unwrap();
    assert_eq!(fresh.cpu.get_mut_mmu().load_mmio(0x1000_4008, 4), Ok(18));
}

#[test]
fn hid_usages_map_to_linux_keycodes() {
    use simmerv::device::virtio_input::hid_to_linux;
    // A, 1, Enter, Space, Up, Left Ctrl, Right GUI; 0 and 0xff have none.
    let pairs = [
        (4, 30),
        (0x1e, 2),
        (0x28, 28),
        (0x2c, 57),
        (0x52, 103),
        (0xe0, 29),
        (0xe7, 126),
    ];
    for (usage, code) in pairs {
        assert_eq!(hid_to_linux(usage), Some(code), "usage {usage:#x}");
    }
    assert_eq!(hid_to_linux(0), None);
    assert_eq!(hid_to_linux(0xff), None);
}
