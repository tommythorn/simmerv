//! `Mmu::read_memory_at` returns what `write_memory_at` stored, stops at the
//! end of the region and reads nothing outside RAM.

use simmerv::Emulator;
use simmerv::serial_backend::DummySerialBackend;
use simmerv::uop_cache::CacheMode;

const RAM_BASE: u64 = 0x8000_0000;
const RAM_SIZE: usize = 1024 * 1024;

#[test]
fn read_memory_at_returns_what_was_written() {
    let mut emu = Emulator::new(
        Box::new(DummySerialBackend::new()),
        RAM_SIZE,
        1024,
        CacheMode::Skew,
    );
    let data: Vec<u8> = (0u8..16).collect();
    emu.cpu.mmu.write_memory_at(RAM_BASE + 0x100, &data);
    let mut out = [0u8; 16];
    assert_eq!(emu.cpu.mmu.read_memory_at(RAM_BASE + 0x100, &mut out), 16);
    assert_eq!(&out[..], &data[..]);
    // the region's last 4 bytes, then nothing past it
    let mut out = [0u8; 8];
    assert_eq!(
        emu.cpu
            .mmu
            .read_memory_at(RAM_BASE + RAM_SIZE as u64 - 4, &mut out),
        4
    );
    assert_eq!(emu.cpu.mmu.read_memory_at(0x1000, &mut out), 0);
}
