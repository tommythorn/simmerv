#![allow(unused_variables, dead_code, clippy::cast_possible_truncation)]

use crate::network_backend::NetworkBackend;
use crate::serial_backend::SerialBackend;
use std::fmt;
use std::ops::Range;

pub mod clint;
pub mod plic;
pub mod syscon;
pub mod uart;
#[cfg(not(target_arch = "wasm32"))]
pub mod url_disk;
pub mod virtio_block_disk;
pub mod virtio_net;

// ---------------------------------------------------------------------------
// Serialization helpers: Pack (write) and Unpack (read)
// ---------------------------------------------------------------------------

/// Append helper: wraps a `&mut Vec<u8>` and exposes typed LE-write methods.
pub struct Pack<'a>(&'a mut Vec<u8>);

impl<'a> Pack<'a> {
    pub const fn new(v: &'a mut Vec<u8>) -> Self { Self(v) }
    pub fn u8(&mut self, v: u8) { self.0.push(v); }
    pub fn u16(&mut self, v: u16) { self.0.extend_from_slice(&v.to_le_bytes()); }
    pub fn u32(&mut self, v: u32) { self.0.extend_from_slice(&v.to_le_bytes()); }
    pub fn u64(&mut self, v: u64) { self.0.extend_from_slice(&v.to_le_bytes()); }
    pub fn bool(&mut self, v: bool) { self.0.push(u8::from(v)); }
    /// Append raw bytes with no length prefix.
    pub fn raw(&mut self, v: &[u8]) { self.0.extend_from_slice(v); }
    /// Prepend a `u64` length, then append the bytes.
    pub fn bytes(&mut self, v: &[u8]) {
        self.u64(v.len() as u64);
        self.0.extend_from_slice(v);
    }
}

/// Cursor helper: wraps a `&[u8]` and advances through it as typed LE values.
/// Every method returns `Err(())` on underrun.
pub struct Unpack<'a>(&'a [u8]);

#[allow(clippy::result_unit_err, clippy::missing_errors_doc)]
impl<'a> Unpack<'a> {
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self { Self(data) }
    pub fn u8(&mut self) -> Result<u8, ()> {
        let (&b, rest) = self.0.split_first().ok_or(())?;
        self.0 = rest;
        Ok(b)
    }
    pub fn u16(&mut self) -> Result<u16, ()> {
        let (b, rest) = self.0.split_first_chunk::<2>().ok_or(())?;
        self.0 = rest;
        Ok(u16::from_le_bytes(*b))
    }
    pub fn u32(&mut self) -> Result<u32, ()> {
        let (b, rest) = self.0.split_first_chunk::<4>().ok_or(())?;
        self.0 = rest;
        Ok(u32::from_le_bytes(*b))
    }
    pub fn u64(&mut self) -> Result<u64, ()> {
        let (b, rest) = self.0.split_first_chunk::<8>().ok_or(())?;
        self.0 = rest;
        Ok(u64::from_le_bytes(*b))
    }
    pub fn bool(&mut self) -> Result<bool, ()> { Ok(self.u8()? != 0) }
    /// Consume `n` bytes and return a slice into the original data.
    pub const fn raw(&mut self, n: usize) -> Result<&'a [u8], ()> {
        if self.0.len() < n {
            return Err(());
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
    /// Read a `u64` length prefix, then that many bytes.
    pub fn bytes(&mut self) -> Result<Vec<u8>, ()> {
        let n = self.u64()? as usize;
        Ok(self.raw(n)?.to_vec())
    }
    /// Remaining bytes not yet consumed.
    #[must_use]
    pub const fn remaining(&self) -> &'a [u8] { self.0 }
}

// ---------------------------------------------------------------------------
// MemoryMapped trait
// ---------------------------------------------------------------------------

/// A memory-mapped device (pluggable, for the generic device list).
pub trait MemoryMapped {
    /// Return a mutable reference to this device's serial backend, if it has
    /// one.
    fn backend(&mut self) -> Option<&mut dyn SerialBackend> { None }

    /// Extract and return the device's serial backend, leaving it unconnected.
    fn take_backend(&mut self) -> Option<Box<dyn SerialBackend>> { None }

    /// Extract and return the device's network backend, leaving it unconnected.
    fn take_net_backend(&mut self) -> Option<Box<dyn NetworkBackend>> { None }

    /// Serialize device-specific state into `w`.
    fn save_state(&self, w: &mut Pack);

    /// Restore device-specific state from `r`.
    ///
    /// # Errors
    /// Returns `Err(())` if the data is malformed or too short.
    #[allow(clippy::result_unit_err)]
    fn restore_state(&mut self, r: &mut Unpack) -> Result<(), ()>;

    /// Append a self-describing record to `data`:
    ///   [32 B] name, UTF-8, zero-padded / truncated
    ///   [ 8 B] base address, u64 LE
    ///   [ 8 B] end address, u64 LE  (exclusive — the range is `base..end`)
    ///   [ 8 B] state-chunk size, u64 LE
    ///   [ N B] state (produced by `save_state`)
    fn save(&self, base: u64, end: u64, data: &mut Vec<u8>) {
        let info = self.info();
        let mut name_buf = [0; 32];
        let src = info.name.as_bytes();
        name_buf[..src.len().min(32)].copy_from_slice(&src[..src.len().min(32)]);
        data.extend_from_slice(&name_buf);
        data.extend_from_slice(&base.to_le_bytes());
        data.extend_from_slice(&end.to_le_bytes());

        let size_slot = data.len();
        data.extend_from_slice(&0u64.to_le_bytes()); // placeholder
        let state_start = data.len();
        self.save_state(&mut Pack::new(data));
        let state_size = (data.len() - state_start) as u64;
        data[size_slot..size_slot + 8].copy_from_slice(&state_size.to_le_bytes());
    }

    /// Restore from a record produced by `save`.
    ///
    /// # Errors
    /// Returns `Err(())` if the record is malformed or the name doesn't match.
    #[allow(clippy::result_unit_err, clippy::cast_possible_truncation)]
    fn restore(&mut self, data: &[u8]) -> Result<(), ()> {
        let mut r = Unpack::new(data);
        let name_bytes = r.raw(32)?;
        let mut expected = [0; 32];
        let src = self.info().name;
        let src = src.as_bytes();
        expected[..src.len().min(32)].copy_from_slice(&src[..src.len().min(32)]);
        if name_bytes != expected {
            return Err(());
        }
        let _base = r.u64()?;
        let _end = r.u64()?;
        let state_size = r.u64()? as usize;
        self.restore_state(&mut Unpack::new(r.raw(state_size)?))
    }

    /// Read `size` bytes starting at `base + offset` into `data`.
    ///
    /// # Errors
    /// Returns `Err` when the requested MMIO access is not valid for the
    /// target device register.
    fn read(
        &mut self,
        _ctx: &mut Context,
        _base: u64,
        _offset: usize,
        size: usize,
        data: &mut [u8],
    ) -> Result<(), MmioError> {
        data[..size].fill(0);
        Ok(())
    }

    /// Write `size` bytes from `data` to `base + offset`.
    ///
    /// # Errors
    /// Returns `Err` when the requested MMIO access is not valid for the
    /// target device register.
    fn write(
        &mut self,
        _ctx: &mut Context,
        _base: u64,
        _offset: usize,
        _size: usize,
        _data: &[u8],
    ) -> Result<(), MmioError> {
        Ok(())
    }

    /// Advance the device by one tick.  Sets `ctx.asserted_irq` if the device
    /// asserts an interrupt.
    fn service(&mut self, ctx: &mut Context, memory: &mut [(Range<u64>, Vec<u8>)]);

    fn info(&self) -> MemoryMappedInfo;
}

pub struct MemoryMappedInfo {
    pub name: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MmioError {
    CrossesRegister {
        offset: usize,
        size: usize,
        register_width: usize,
    },
    BufferTooSmall {
        size: usize,
        len: usize,
    },
    OutOfRange {
        offset: usize,
        size: usize,
        device_len: usize,
    },
}

impl fmt::Display for MmioError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CrossesRegister {
                offset,
                size,
                register_width,
            } => write!(
                f,
                "access at register byte offset {:#x} with size {} crosses {}-byte register",
                offset & (register_width - 1),
                size,
                register_width
            ),
            Self::BufferTooSmall { size, len } => {
                write!(f, "MMIO buffer is too small: need {size} bytes, got {len}")
            }
            Self::OutOfRange {
                offset,
                size,
                device_len,
            } => write!(
                f,
                "access at offset {offset:#x} with size {size} exceeds device register space \
                 length {device_len:#x}"
            ),
        }
    }
}

/// Passed to every device on `read` / `write` / `service`.
pub struct Context {
    /// Machine interrupt-pending bits.  Devices that drive mip directly
    /// (CLINT, PLIC) read the incoming value and write back their update.
    pub mip: u64,
    /// Set by pluggable devices when they assert an interrupt; contains the
    /// IRQ number to assert, or `None` if no interrupt.
    pub asserted_irq: Option<u32>,
    pub next_service_in: Option<usize>,
    pub cycle: u64,
}

// ---------------------------------------------------------------------------
// MMIO register helpers — sub-word-aligned reads and writes.
// ---------------------------------------------------------------------------

const fn check_register_access(
    offset: usize,
    size: usize,
    register_width: usize,
    buffer_len: usize,
) -> Result<usize, MmioError> {
    if size > buffer_len {
        return Err(MmioError::BufferTooSmall {
            size,
            len: buffer_len,
        });
    }
    let byte_off = offset & (register_width - 1);
    if byte_off + size > register_width {
        return Err(MmioError::CrossesRegister {
            offset,
            size,
            register_width,
        });
    }
    Ok(byte_off)
}

/// Read `size` bytes of `value` starting at byte `offset & (align-1)` into
/// `data`.
///
/// # Errors
/// Returns `Err` if the access crosses the end of the 32-bit register or the
/// destination buffer is too small.
pub fn read_u32(offset: usize, size: usize, value: u32, data: &mut [u8]) -> Result<(), MmioError> {
    let byte_off = check_register_access(offset, size, 4, data.len())?;
    data[..size].copy_from_slice(&value.to_le_bytes()[byte_off..byte_off + size]);
    Ok(())
}

/// # Errors
/// Returns `Err` if the access crosses the end of the 32-bit register or the
/// source buffer is too small.
pub fn write_u32(
    offset: usize,
    size: usize,
    value: &mut u32,
    data: &[u8],
) -> Result<(), MmioError> {
    let byte_off = check_register_access(offset, size, 4, data.len())?;
    let mut bytes = value.to_le_bytes();
    bytes[byte_off..byte_off + size].copy_from_slice(&data[..size]);
    *value = u32::from_le_bytes(bytes);
    Ok(())
}

/// # Errors
/// Returns `Err` if the access crosses the end of the 64-bit register or the
/// destination buffer is too small.
pub fn read_u64(offset: usize, size: usize, value: u64, data: &mut [u8]) -> Result<(), MmioError> {
    let byte_off = check_register_access(offset, size, 8, data.len())?;
    data[..size].copy_from_slice(&value.to_le_bytes()[byte_off..byte_off + size]);
    Ok(())
}

/// # Errors
/// Returns `Err` if the access crosses the end of the 64-bit register or the
/// source buffer is too small.
pub fn write_u64(
    offset: usize,
    size: usize,
    value: &mut u64,
    data: &[u8],
) -> Result<(), MmioError> {
    let byte_off = check_register_access(offset, size, 8, data.len())?;
    let mut bytes = value.to_le_bytes();
    bytes[byte_off..byte_off + size].copy_from_slice(&data[..size]);
    *value = u64::from_le_bytes(bytes);
    Ok(())
}

// ---------------------------------------------------------------------------
// DMA helpers — used by devices (e.g. VirtIO) that need direct RAM access.
// ---------------------------------------------------------------------------

/// Returns a mutable sub-slice of the RAM covering `[pa, pa+len)`,
/// or `None` if no such region exists.
pub fn dma_slice(memory: &mut [(Range<u64>, Vec<u8>)], pa: u64, len: usize) -> Option<&mut [u8]> {
    for (range, mem) in memory.iter_mut() {
        if range.contains(&pa) {
            let offset = (pa - range.start) as usize;
            if offset + len <= mem.len() {
                return Some(&mut mem[offset..offset + len]);
            }
        }
    }
    None
}

pub fn dma_read_u8(memory: &mut [(Range<u64>, Vec<u8>)], pa: u64) -> u8 {
    dma_slice(memory, pa, 1).map_or(0, |s| s[0])
}

pub fn dma_read_u16(memory: &mut [(Range<u64>, Vec<u8>)], pa: u64) -> u16 {
    dma_slice(memory, pa, 2).map_or(0, |s| u16::from_le_bytes([s[0], s[1]]))
}

pub fn dma_read_u32(memory: &mut [(Range<u64>, Vec<u8>)], pa: u64) -> u32 {
    dma_slice(memory, pa, 4).map_or(0, |s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

pub fn dma_read_u64(memory: &mut [(Range<u64>, Vec<u8>)], pa: u64) -> u64 {
    dma_slice(memory, pa, 8).map_or(0, |s| {
        u64::from_le_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]])
    })
}

pub fn dma_write_u8(memory: &mut [(Range<u64>, Vec<u8>)], pa: u64, value: u8) -> bool {
    dma_slice(memory, pa, 1).is_some_and(|s| {
        s[0] = value;
        true
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serial_backend::DummySerialBackend;

    fn mk_ctx() -> Context {
        Context {
            mip: 0,
            asserted_irq: None,
            next_service_in: None,
            cycle: 0,
        }
    }

    #[test]
    fn read_u32_reports_cross_register_access() {
        let mut data = [0; 4];

        let err = read_u32(2, 4, 0x1234_5678, &mut data).unwrap_err();

        assert_eq!(err, MmioError::CrossesRegister {
            offset: 2,
            size: 4,
            register_width: 4
        });
    }

    #[test]
    fn write_u64_reports_short_source_buffer() {
        let mut value = 0;

        let err = write_u64(0, 8, &mut value, &[1, 2, 3, 4]).unwrap_err();

        assert_eq!(err, MmioError::BufferTooSmall { size: 8, len: 4 });
    }

    /// Save `device` at `base`, restore a fresh instance, save again, assert
    /// equal.
    fn round_trip<D: MemoryMapped>(base: u64, end: u64, device: &mut D, fresh: impl Fn() -> D) {
        let mut buf1 = Vec::new();
        device.save(base, end, &mut buf1);

        let mut d2 = fresh();
        d2.restore(&buf1).expect("restore() failed");

        let mut buf2 = Vec::new();
        d2.save(base, end, &mut buf2);
        assert_eq!(buf1, buf2, "save→restore→save produced different bytes");
    }

    #[test]
    fn uart_round_trip() {
        let base = 0x1000_0000;
        let end = base + 8;
        let mut uart = uart::Uart::new(Box::new(DummySerialBackend::new()), 10);
        // Enable THRE interrupt (rising edge sets thre_ip internally)
        uart.write(&mut mk_ctx(), base, 1, 1, &[0x02]).unwrap();
        // Set LCR to a non-default value (8N1)
        uart.write(&mut mk_ctx(), base, 3, 1, &[0x03]).unwrap();
        round_trip(base, end, &mut uart, || {
            uart::Uart::new(Box::new(DummySerialBackend::new()), 10)
        });
    }

    #[test]
    fn clint_round_trip() {
        let base = 0x0200_0000;
        let mut clint = clint::Clint::new();
        // Set MSIP = 1
        clint.write(&mut mk_ctx(), base, 0, 1, &[0x01]).unwrap();
        // Set MTIMECMP = 0x12345678
        clint
            .write(
                &mut mk_ctx(),
                base,
                0x4000,
                4,
                &0x1234_5678u32.to_le_bytes(),
            )
            .unwrap();

        round_trip(base, base + 8, &mut clint, clint::Clint::new);
    }

    #[test]
    fn plic_round_trip() {
        let base = 0x0c00_0000u64;
        let mut plic = plic::Plic::new();
        // Set priority 7 for UART IRQ (source 10)
        plic.write(&mut mk_ctx(), base, 10 * 4, 4, &7u32.to_le_bytes())
            .unwrap();
        // Enable UART IRQ in supervisor context (offset 0x2081, bit 2 = IRQ 10)
        plic.write(&mut mk_ctx(), base, 0x2081, 1, &[1 << 2])
            .unwrap();
        round_trip(base, base + 0x400_0000, &mut plic, plic::Plic::new);
    }

    #[test]
    fn virtio_round_trip() {
        let base = 0x1000_1000u64;
        let end = 0x1000_2000u64;
        let mut disk = virtio_block_disk::VirtioBlockDisk::new_with_contents(vec![0xABu8; 1024], 1);
        // Simulate driver setup: STATUS = ACKNOWLEDGE|DRIVER|FEATURES_OK|DRIVER_OK
        disk.store(0x070, 0x0f);
        disk.store(0x080, 0x00); // QueueDescLow  = 0x8000_1000
        disk.store(0x081, 0x10);
        disk.store(0x082, 0x00);
        disk.store(0x083, 0x80);
        disk.store(0x090, 0x00); // QueueDriverLow = 0x8000_2000
        disk.store(0x091, 0x20);
        disk.store(0x092, 0x00);
        disk.store(0x093, 0x80);
        disk.store(0x0a0, 0x00); // QueueDeviceLow = 0x8000_3000
        disk.store(0x0a1, 0x30);
        disk.store(0x0a2, 0x00);
        disk.store(0x0a3, 0x80);
        disk.store(0x044, 1); // QueueReady = 1
        round_trip(base, end, &mut disk, || {
            virtio_block_disk::VirtioBlockDisk::new(1)
        });
    }
}
