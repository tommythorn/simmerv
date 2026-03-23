#![allow(clippy::unreadable_literal)]

use super::Context;
use super::MemoryMapped;
use super::MemoryMappedInfo;
use super::Pack;
use super::Unpack;
use super::read_u32;
use super::read_u64;
use super::write_u32;
use super::write_u64;
use crate::cpu::MIP_MSIP;
use crate::cpu::MIP_MTIP;
use std::ops::Range;

#[cfg(not(target_arch = "wasm32"))]
use std::time::Instant;
#[cfg(target_arch = "wasm32")]
use wasm_timer::SystemTime as Instant;

/// Emulates CLINT known as Timer. Refer to the [specification](https://sifive.cdn.prismic.io/sifive%2Fc89f6e5a-cf9e-44c3-a3db-04420702dcc1_sifive+e31+manual+v19.08.pdf)
/// for the detail.
pub struct Clint {
    pub mtimecmp: u64,
    pub mtime_delta: u64,
    t0: Instant,
}

impl Default for Clint {
    fn default() -> Self { Self::new() }
}

impl Clint {
    /// Creates a new `Clint`
    #[must_use]
    pub fn new() -> Self {
        Self {
            mtimecmp: 0,
            mtime_delta: 0,
            t0: Instant::now(),
        }
    }

    /// `Clint` can raise interrupt. If it does it rises a certain bit
    /// depending on interrupt type of CPU `mip` register.
    ///
    /// # Arguments
    #[allow(clippy::cast_possible_truncation)]
    #[cfg(target_arch = "wasm32")]
    fn now_micros(&self) -> u64 { self.t0.elapsed().map_or(0, |t| t.as_micros() as u64) }

    #[allow(clippy::cast_possible_truncation)]
    #[cfg(not(target_arch = "wasm32"))]
    fn now_micros(&self) -> u64 { self.t0.elapsed().as_micros() as u64 }

    /// `Clint` can raise interrupt. If it does it rises a certain bit
    /// depending on interrupt type of CPU `mip` register.
    ///
    /// # Arguments
    /// * `mip` CPU `mip` register. It can be updated if interrupt occurs.
    pub fn service(&mut self, mip: &mut u64) {
        if self.mtimecmp > 0 && self.read_mtime() >= self.mtimecmp {
            *mip |= MIP_MTIP;
        }
    }

    /// Reads `mtime` register content
    #[must_use]
    pub fn read_mtime(&self) -> u64 { self.now_micros().wrapping_add(self.mtime_delta) }

    /// Writes to `mtime` register content
    pub fn write_mtime(&mut self, mtime: u64) {
        self.mtime_delta = mtime.wrapping_sub(self.now_micros());
    }
}

impl MemoryMapped for Clint {
    /// Register layout by offset:
    ///   0x00000..=0x00003: MSIP (u32)
    ///   0x04000..=0x04007: MTIMECMP (u64)
    ///   0x0bff8..=0x0bfff: MTIME (u64)
    fn read(&mut self, ctx: &mut Context, _base: u64, offset: usize, size: usize, data: &mut [u8]) {
        match offset {
            0x00000..=0x00003 => read_u32(offset, size, u32::from(ctx.mip & MIP_MSIP != 0), data),
            0x04000..=0x04007 => read_u64(offset, size, self.mtimecmp, data),
            0x0bff8..=0x0bfff => read_u64(offset, size, self.read_mtime(), data),
            _ => data[..size].fill(0),
        }
    }

    fn write(&mut self, ctx: &mut Context, _base: u64, offset: usize, size: usize, data: &[u8]) {
        match offset {
            0x00000..=0x00003 => {
                let mut msip = 0u32;
                write_u32(offset, size, &mut msip, data);
                if msip & 1 != 0 {
                    ctx.mip |= MIP_MSIP;
                } else {
                    ctx.mip &= !MIP_MSIP;
                }
            }
            0x04000..=0x04007 => {
                write_u64(offset, size, &mut self.mtimecmp, data);
                ctx.mip &= !MIP_MTIP;
                if self.mtimecmp > 0 && self.read_mtime() >= self.mtimecmp {
                    ctx.mip |= MIP_MTIP;
                }
            }
            0x0bff8..=0x0bfff => {
                let mut new_mtime = self.read_mtime();
                write_u64(offset, size, &mut new_mtime, data);
                self.write_mtime(new_mtime);
            }
            _ => {}
        }
    }

    fn service(&mut self, ctx: &mut Context, _memory: &mut [(Range<u64>, Vec<u8>)]) {
        self.service(&mut ctx.mip);
        ctx.next_service_in = Some(1);
    }

    fn save_state(&self, w: &mut Pack) {
        w.u64(self.mtimecmp);
        w.u64(self.mtime_delta);
    }

    fn restore_state(&mut self, r: &mut Unpack) -> Result<(), ()> {
        self.mtimecmp = r.u64()?;
        self.mtime_delta = r.u64()?;
        Ok(())
    }

    fn info(&self) -> MemoryMappedInfo {
        MemoryMappedInfo {
            name: "SiFive CLINT".to_string(),
        }
    }
}

#[test]
fn sanity_mtime() {
    let mut clint = Clint::new();
    let mut dummy = 0;

    assert!(clint.read_mtime() < 1000);

    clint.write_mtime(2000);
    assert_eq!(clint.read_mtime(), 2000);
    clint.service(&mut dummy);
    assert!(clint.read_mtime() < 3000);

    clint.write_mtime(0);
    assert_eq!(clint.read_mtime(), 0);
    clint.service(&mut dummy);
    assert!(clint.read_mtime() < 1000);
}
