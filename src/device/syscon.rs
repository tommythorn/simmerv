use super::Context;
use super::MemoryMapped;
use super::MemoryMappedInfo;
use super::MmioError;
use super::Pack;
use super::Unpack;
use super::write_u32;
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

/// Syscon power/reset controller.  Recognises two writes at offset 0:
///   0x5555 → assert the poweroff flag (emulator exits)
///   0x7777 → assert the reset flag (emulator resets CPU and continues)
///
/// The register is accumulated byte-by-byte because the CPU write path
/// (`memop_slow`) issues individual `store_mmio_u8` calls for MMIO addresses.
pub struct Syscon {
    reg: u32,
    poweroff: Arc<AtomicBool>,
    reset: Arc<AtomicBool>,
}

impl Syscon {
    pub const fn new(poweroff: Arc<AtomicBool>, reset: Arc<AtomicBool>) -> Self {
        Self {
            reg: 0,
            poweroff,
            reset,
        }
    }
}

impl MemoryMapped for Syscon {
    fn write(
        &mut self,
        _ctx: &mut Context,
        _base: u64,
        offset: usize,
        size: usize,
        data: &[u8],
    ) -> Result<(), MmioError> {
        write_u32(offset, size, &mut self.reg, data)?;
        match self.reg {
            0x5555 => self.poweroff.store(true, Ordering::Relaxed),
            0x7777 => self.reset.store(true, Ordering::Relaxed),
            _ => {}
        }
        Ok(())
    }

    fn service(&mut self, _ctx: &mut Context, _memory: &mut [(Range<u64>, Vec<u8>)]) {}

    fn save_state(&self, w: &mut Pack) { w.u32(self.reg); }

    fn restore_state(&mut self, r: &mut Unpack) -> Result<(), ()> {
        self.reg = r.u32()?;
        Ok(())
    }

    fn info(&self) -> MemoryMappedInfo {
        MemoryMappedInfo {
            name: "Syscon".to_string(),
        }
    }
}
