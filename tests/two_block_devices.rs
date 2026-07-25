//! Integration test: the machine exposes two independent `virtio-blk` MMIO
//! windows, `/dev/vda` at `VIRTIO_BASE` and `/dev/vdb` at `VIRTIO2_BASE`, each
//! backed by its own disk image.

use simmerv::Emulator;
use simmerv::mmu::Mmu;
use simmerv::serial_backend::DummySerialBackend;
use simmerv::uop_cache::CacheMode;

const VIRTIO_MAGIC: u64 = 0x7472_6976; // "virt"
const VIRTIO_BLOCK_DEVICE_ID: u64 = 2;

fn fresh_emulator() -> Emulator {
    Emulator::new(
        Box::new(DummySerialBackend::new()),
        8 * 1024 * 1024,
        1024,
        CacheMode::Skew,
    )
}

/// Both `virtio-blk` windows answer the magic-value and device-id registers, so
/// the guest's virtio-mmio probe finds a block device at each address.
#[test]
fn both_virtio_blk_windows_are_mapped() {
    let mut emu = fresh_emulator();
    let mmu = emu.cpu.get_mut_mmu();

    for base in [Mmu::VIRTIO_BASE, Mmu::VIRTIO2_BASE] {
        assert_eq!(
            mmu.load_mmio(base, 4),
            Ok(VIRTIO_MAGIC),
            "virtio magic missing at {base:#x}"
        );
        assert_eq!(
            mmu.load_mmio(base + 0x008, 4),
            Ok(VIRTIO_BLOCK_DEVICE_ID),
            "device id at {base:#x} is not virtio-blk",
        );
    }
}

/// The two disks are distinct devices: filling only disk 1 leaves disk 0 empty,
/// proving `-f`/`setup_filesystem_at` routes to independent backing stores.
/// Capacity (in 512-byte sectors) lives at config-space offset 0x100.
#[test]
fn second_disk_capacity_is_independent() {
    let mut emu = fresh_emulator();
    // 4 sectors of content on disk 1 only.
    emu.setup_filesystem_at(1, vec![0xA5u8; 4 * 512]);
    let mmu = emu.cpu.get_mut_mmu();

    assert_eq!(
        mmu.load_mmio(Mmu::VIRTIO_BASE + 0x100, 4),
        Ok(0),
        "disk 0 should still be empty"
    );
    assert_eq!(
        mmu.load_mmio(Mmu::VIRTIO2_BASE + 0x100, 4),
        Ok(4),
        "disk 1 should report 4 sectors"
    );
}
