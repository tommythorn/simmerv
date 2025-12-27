#![allow(clippy::unreadable_literal)]

use crate::cpu::MIP_MSIP;
use crate::cpu::MIP_MTIP;
use wasm_timer::SystemTime;

/// Emulates CLINT known as Timer. Refer to the [specification](https://sifive.cdn.prismic.io/sifive%2Fc89f6e5a-cf9e-44c3-a3db-04420702dcc1_sifive+e31+manual+v19.08.pdf)
/// for the detail.
pub struct Clint {
    msip: u32,
    mtimecmp: u64,
    mtime_system: u64,
    mtime_delta: u64,
    t0: SystemTime,
}

impl Default for Clint {
    fn default() -> Self { Self::new() }
}

impl Clint {
    /// Creates a new `Clint`
    #[must_use]
    pub fn new() -> Self {
        Self {
            msip: 0,
            mtimecmp: 0,
            mtime_system: 0,
            mtime_delta: 0,
            t0: SystemTime::now(),
        }
    }

    /// `Clint` can raise interrupt. If it does it rises a certain bit
    /// depending on interrupt type of CPU `mip` register.
    ///
    /// # Arguments
    /// * `mip` CPU `mip` register. It can be updated if interrupt occurs.
    #[allow(clippy::cast_possible_truncation)]
    #[allow(clippy::option_if_let_else)]
    pub fn service(&mut self, cycle: u64, mip: &mut u64) {
        self.mtime_system = self
            .t0
            .elapsed()
            .map_or(cycle / 16, |t| t.as_micros() as u64);

        if (self.msip & 1) != 0 {
            *mip |= MIP_MSIP;
        }

        let mtime = self.mtime_system.wrapping_add(self.mtime_delta);
        if self.mtimecmp > 0 && mtime >= self.mtimecmp {
            *mip |= MIP_MTIP;
        }
    }

    /// Loads register content.
    ///
    /// # Arguments
    /// * `address`
    #[allow(clippy::cast_possible_truncation)]
    #[must_use]
    pub const fn load(&self, address: u64) -> u8 {
        //println!("CLINT Load AD:{:X}", address);
        let mtime = self.mtime_system.wrapping_add(self.mtime_delta);
        match address {
            // MSIP register 4 bytes
            0x02000000 => (self.msip & 0xff) as u8,
            0x02000001 => ((self.msip >> 8) & 0xff) as u8,
            0x02000002 => ((self.msip >> 16) & 0xff) as u8,
            0x02000003 => ((self.msip >> 24) & 0xff) as u8,
            // MTIMECMP Registers 8 bytes
            0x02004000 => self.mtimecmp as u8,
            0x02004001 => (self.mtimecmp >> 8) as u8,
            0x02004002 => (self.mtimecmp >> 16) as u8,
            0x02004003 => (self.mtimecmp >> 24) as u8,
            0x02004004 => (self.mtimecmp >> 32) as u8,
            0x02004005 => (self.mtimecmp >> 40) as u8,
            0x02004006 => (self.mtimecmp >> 48) as u8,
            0x02004007 => (self.mtimecmp >> 56) as u8,
            0x0200bff8 => mtime as u8,
            0x0200bff9 => (mtime >> 8) as u8,
            0x0200bffa => (mtime >> 16) as u8,
            0x0200bffb => (mtime >> 24) as u8,
            0x0200bffc => (mtime >> 32) as u8,
            0x0200bffd => (mtime >> 40) as u8,
            0x0200bffe => (mtime >> 48) as u8,
            0x0200bfff => (mtime >> 56) as u8,
            _ => 0,
        }
    }

    /// Stores register content.
    ///
    /// # Arguments
    /// * `address`
    /// * `value`
    #[allow(clippy::cast_lossless)]
    pub const fn store(&mut self, address: u64, value: u8, mip: &mut u64) {
        //println!("CLINT Store AD:{:X} VAL:{:X}", address, value);
        let mut mtime: u64 = self.mtime_system.wrapping_add(self.mtime_delta);
        match address {
            // MSIP register 4 bytes. Upper 31 bits are hardwired to zero.
            0x02000000 => {
                self.msip = (self.msip & !0x1) | ((value & 1) as u32);
            }
            // XXX Clean up this atrocity
            // MTIMECMP Registers 8 bytes
            0x02004000 => {
                self.mtimecmp = (self.mtimecmp & !0xff) | (value as u64);
                *mip &= !MIP_MTIP;
            }
            0x02004001 => {
                self.mtimecmp = (self.mtimecmp & !(0xff << 8)) | ((value as u64) << 8);
                *mip &= !MIP_MTIP;
            }
            0x02004002 => {
                self.mtimecmp = (self.mtimecmp & !(0xff << 16)) | ((value as u64) << 16);
                *mip &= !MIP_MTIP;
            }
            0x02004003 => {
                self.mtimecmp = (self.mtimecmp & !(0xff << 24)) | ((value as u64) << 24);
                *mip &= !MIP_MTIP;
            }
            0x02004004 => {
                self.mtimecmp = (self.mtimecmp & !(0xff << 32)) | ((value as u64) << 32);
                *mip &= !MIP_MTIP;
            }
            0x02004005 => {
                self.mtimecmp = (self.mtimecmp & !(0xff << 40)) | ((value as u64) << 40);
                *mip &= !MIP_MTIP;
            }
            0x02004006 => {
                self.mtimecmp = (self.mtimecmp & !(0xff << 48)) | ((value as u64) << 48);
                *mip &= !MIP_MTIP;
            }
            0x02004007 => {
                self.mtimecmp = (self.mtimecmp & !(0xff << 56)) | ((value as u64) << 56);
                *mip &= !MIP_MTIP;
            }
            // MTIME registers 8 bytes
            0x0200bff8 => {
                mtime = (mtime & !0xff) | (value as u64);
            }
            0x0200bff9 => {
                mtime = (mtime & !(0xff << 8)) | ((value as u64) << 8);
            }
            0x0200bffa => {
                mtime = (mtime & !(0xff << 16)) | ((value as u64) << 16);
            }
            0x0200bffb => {
                mtime = (mtime & !(0xff << 24)) | ((value as u64) << 24);
            }
            0x0200bffc => {
                mtime = (mtime & !(0xff << 32)) | ((value as u64) << 32);
            }
            0x0200bffd => {
                mtime = (mtime & !(0xff << 40)) | ((value as u64) << 40);
            }
            0x0200bffe => {
                mtime = (mtime & !(0xff << 48)) | ((value as u64) << 48);
            }
            0x0200bfff => {
                mtime = (mtime & !(0xff << 56)) | ((value as u64) << 56);
            }
            _ => {}
        }

        self.mtime_delta = mtime.wrapping_sub(self.mtime_system);

        if (self.msip & 1) != 0 {
            *mip |= MIP_MSIP;
        }

        if self.mtimecmp > 0 && mtime >= self.mtimecmp {
            *mip |= MIP_MTIP;
        }
    }

    /// Reads `mtime` register content
    #[must_use]
    #[allow(dead_code)]
    pub const fn read_mtime(&self) -> u64 { self.mtime_system.wrapping_add(self.mtime_delta) }

    /// Writes to `mtime` register content
    #[allow(dead_code)]
    pub const fn write_mtime(&mut self, mtime: u64) {
        self.mtime_delta = mtime.wrapping_sub(self.mtime_system);
    }
}

#[test]
fn sanity_mtime() {
    let mut clint = Clint::new();
    let mut dummy = 0;

    assert!(clint.read_mtime() < 1000);

    clint.write_mtime(2000);
    assert_eq!(clint.read_mtime(), 2000);
    clint.service(0, &mut dummy);
    assert!(clint.read_mtime() < 3000);

    clint.write_mtime(0);
    assert_eq!(clint.read_mtime(), 0);
    clint.service(0, &mut dummy);
    assert!(clint.read_mtime() < 1000);
}
