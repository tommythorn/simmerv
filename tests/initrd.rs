//! The `-i/--initfs` mechanism: inserting the ramdisk properties into a device
//! tree, and the layouts the emulator derives from them.
//!
//! The trees are real ones from the repo, because the whole point is the
//! geometry of an actual blob -- the shipped trees have *zero* slack after the
//! strings block (`totalsize == off_dt_strings + size_dt_strings`), so an
//! inserted property has to rebuild the blob and every offset has to move
//! consistently. A synthetic tree would not exercise that.

// Every fallible call here is asserted on, so a failure has to abort the test
// with the offending value in the panic message -- which is what `unwrap` does
// and what propagating the error would lose.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use simmerv::Emulator;
use simmerv::fdt;
use simmerv::uop_cache::CacheMode;

const DTB: &[u8] = include_bytes!("../src/device/dtb.dtb");
const DTB_V: &[u8] = include_bytes!("../src/device/dtb-v.dtb");
/// Carries its own `linux,initrd-start`/`-end`, so it must be refused.
const TINY128: &[u8] = include_bytes!("../linux/tiny128.dtb");
/// Small enough to place in any of the RAM sizes used here.
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

fn read_tree(emu: &mut Emulator, addr: u64, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = emu.cpu.get_mut_mmu().load_phys_u8(addr + i as u64);
    }
    out
}

/// The growth is exactly what the header arithmetic predicts: two properties at
/// 12 bytes of header plus two 4-byte cells each, and two names at their length
/// plus a NUL.
#[test]
fn growth_is_two_properties_and_two_names() {
    let slot = fdt::analyze_initrd_slot(DTB).unwrap();
    assert_eq!(slot.addr_cells(), 2);
    assert_eq!(slot.growth(), 2 * 20 + 19 + 17);
    assert_eq!(slot.growth(), 76);
}

/// The blob has no room for an in-place write, so this is the invariant that
/// makes the rebuild necessary -- and the one the rebuild must preserve.
#[test]
fn shipped_trees_have_no_slack() {
    for blob in [DTB, DTB_V, TINY128] {
        let [_, total, _, off_strings, _, _, _, _, size_strings, _] = header(blob);
        assert_eq!(
            total,
            off_strings + size_strings,
            "expected no slack after the strings block"
        );
    }
}

/// Every offset in the rebuilt header, checked against the values the geometry
/// predicts. A mis-shifted strings block still parses, so `dtc` alone is not
/// enough -- these are the numbers that catch it.
#[test]
fn embed_moves_each_offset_exactly_once() {
    let slot = fdt::analyze_initrd_slot(DTB).unwrap();
    let out = slot.embed(DTB, 0xe608_b000, 0xffff_e600).unwrap();

    let before = header(DTB);
    let after = header(&out);
    // magic, off_dt_struct, off_mem_rsvmap, version, last_comp_version,
    // boot_cpuid_phys.
    assert_eq!(
        [after[0], after[2], after[4], after[5], after[6], after[7]],
        [before[0], before[2], before[4], before[5], before[6], before[7]],
        "fields that describe nothing about the edit must not move"
    );
    assert_eq!(after[1], 2950, "totalsize");
    assert_eq!(after[3], 2440, "off_dt_strings = 2400 + 40");
    assert_eq!(after[8], 510, "size_dt_strings = 474 + 36");
    assert_eq!(after[9], 2368, "size_dt_struct = 2328 + 40");
    assert_eq!(out.len(), 2950);
    // Preserved, and the reason every existing `nameoff` still resolves: the
    // strings block simply moved.
    assert_eq!(after[1], after[3] + after[8]);
}

/// The values must be readable back through the same walker the edit was built
/// from, which proves they landed as properties of `/chosen` rather than of the
/// root -- a mistake that parses cleanly and silently does nothing.
#[test]
fn embedded_properties_round_trip() {
    let slot = fdt::analyze_initrd_slot(DTB).unwrap();
    let out = slot.embed(DTB, 0xe608_b000, 0xffff_e600).unwrap();

    // Re-analysing must now refuse the tree, and the refusal is what tells us
    // the two properties are present, inside `/chosen`, with the right width.
    let err = fdt::analyze_initrd_slot(&out).unwrap_err().to_string();
    assert!(err.contains("linux,initrd-start"), "got: {err}");
}

/// A tree that states its own ramdisk address is stating a fact, not a default.
#[test]
fn a_tree_that_pins_its_own_initrd_is_refused() {
    let err = fdt::analyze_initrd_slot(TINY128).unwrap_err().to_string();
    assert!(err.contains("already defines"), "got: {err}");

    let emu = emulator(512);
    assert!(
        !emu.effective_dtb().is_empty(),
        "the default tree should be placed at construction"
    );
}

/// `dts.dts` reserves the firmware's window; a ramdisk placed there would
/// corrupt `OpenSBI`, so the reserved ranges have to be visible.
#[test]
fn memreserve_ranges_are_readable() {
    let ranges = fdt::mem_reserve_ranges(DTB);
    assert!(
        ranges.iter().any(|&(start, _)| start == 0x8000_0000),
        "expected the firmware reservation at 0x80000000, got {ranges:?}"
    );
}

/// The ramdisk goes flush below the tree, its end is the file's length past its
/// start, and the tree is told about exactly that range.
#[test]
fn initrd_lands_below_the_tree_and_is_advertised() {
    let mut emu = emulator(512);
    let placement = emu.setup_initrd(INITRD).unwrap();

    assert_eq!(placement.dtb_base, 0x9fff_f000, "top of 512 MiB, one page in");
    assert_eq!(placement.end - placement.start, INITRD.len() as u64);
    assert!(placement.end <= placement.dtb_base);
    assert_eq!(placement.start % 4096, 0, "start is page aligned");
    assert_eq!(placement.dtb_base - placement.end, 1536, "alignment slack");

    // The tree in RAM is the effective one, and it is the one the guest reads.
    let tree_len = emu.effective_dtb().len();
    let from_ram = read_tree(&mut emu, placement.dtb_base, tree_len);
    assert_eq!(from_ram, emu.effective_dtb());
    assert_eq!(from_ram.len(), DTB.len() + 76);
    assert_eq!(emu.cpu.dtb_base, placement.dtb_base);

    // And the ramdisk really is there.
    let loaded = read_tree(&mut emu, placement.start, INITRD.len());
    assert_eq!(loaded, INITRD);
}

/// The tree must not move when it gains an initrd: 2874 + 76 = 2950 still pads
/// to one page, so a pinned layout keeps working. If this ever fails, every
/// `-d FILE,0xADDR` in the wild has silently shifted by a page.
#[test]
fn the_tree_base_is_stable_across_placing_an_initrd() {
    let mut emu = emulator(2048);
    let before = emu.cpu.dtb_base;
    let placement = emu.setup_initrd(INITRD).unwrap();
    assert_eq!(placement.dtb_base, before);
}

/// An image already loaded is not ours to overwrite, and the check has to come
/// from the emulator: a file's length does not bound an ELF's footprint.
#[test]
fn an_initrd_may_not_land_on_a_loaded_image() {
    let mut emu = emulator(512);
    emu.load_image(
        "blob",
        &vec![0u8; 4096],
        Some(0x8000_0000),
        &mut std::collections::BTreeMap::new(),
    )
    .unwrap();
    assert_eq!(emu.image_extent(), Some((0x8000_0000, 0x8000_1000)));

    // A ramdisk placed by default lands flush under the tree, at
    // [0x9fffd000, 0x9fffea00), so an image there is exactly the collision:
    // close enough to the top of RAM that no size of ramdisk could dodge it.
    emu.load_image(
        "kernel",
        &vec![0u8; 4096],
        Some(0x9fff_e000),
        &mut std::collections::BTreeMap::new(),
    )
    .unwrap();
    assert_eq!(
        emu.image_extent(),
        Some((0x8000_0000, 0x9fff_f000)),
        "the extent spans both loads"
    );

    let err = emu.setup_initrd(INITRD).unwrap_err().to_string();
    assert!(
        err.contains("overwrite an image already loaded"),
        "got: {err}"
    );
}

/// Nothing that does not fit may be written, and the message has to say by how
/// much: `write_memory_at` would have truncated this silently.
#[test]
fn an_initrd_too_large_for_ram_is_refused() {
    let mut emu = emulator(64);
    let err = emu.setup_initrd(&vec![0u8; 128 * 1024 * 1024])
        .unwrap_err()
        .to_string();
    assert!(err.contains("does not fit in RAM"), "got: {err}");
    assert!(err.contains("Increase -m"), "got: {err}");
}

/// An empty ramdisk is a user mistake, not an image.
#[test]
fn an_empty_initrd_is_refused() {
    let mut emu = emulator(512);
    let err = emu.setup_initrd(&[]).unwrap_err().to_string();
    assert!(err.contains("empty"), "got: {err}");
}

/// `--rva23` replaces the tree after construction, so a ramdisk placed
/// afterwards must be advertised in the tree that actually ends up in RAM.
#[test]
fn the_initrd_survives_an_rva23_tree_swap() {
    let mut emu = emulator(512);
    emu.set_rva23_enabled(true);
    let placement = emu.setup_initrd(INITRD).unwrap();

    let effective = emu.effective_dtb().to_vec();
    assert_eq!(
        effective.len(),
        DTB_V.len() + 76,
        "the RVA23 tree is the one that grew"
    );
    let from_ram = read_tree(&mut emu, placement.dtb_base, effective.len());
    assert_eq!(from_ram, effective);
    let err = fdt::analyze_initrd_slot(&effective).unwrap_err().to_string();
    assert!(err.contains("already defines"), "got: {err}");
}

/// A pinned ramdisk address is used as given, and still advertised.
#[test]
fn a_pinned_initrd_address_is_honoured() {
    let mut emu = emulator(512);
    let placement = emu.setup_initrd_at(INITRD, 0x9000_0000).unwrap();
    assert_eq!(placement.start, 0x9000_0000);
    assert_eq!(placement.end, 0x9000_0000 + INITRD.len() as u64);
    assert_eq!(read_tree(&mut emu, placement.start, INITRD.len()), INITRD);

    // Pinned too high, and there is no room left for the tree above it.
    let err = emu.setup_initrd_at(INITRD, 0x9fff_f800).unwrap_err().to_string();
    assert!(err.contains("overlaps the device tree"), "got: {err}");
}