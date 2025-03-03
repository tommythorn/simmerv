#![allow(
    clippy::cast_possible_wrap,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::unwrap_used,
    clippy::cast_sign_loss,
    clippy::result_unit_err,
    clippy::cast_possible_truncation
)]

/// DRAM base address. Offset from this base address
/// is the address in main memory.
/// XXX Clean this up
pub const DRAM_BASE: u64 = 0x80000000;
pub const MEMORY_BASE: i64 = DRAM_BASE as i64;
pub struct Memory(pub Vec<u8>);
impl Memory {
    pub const fn new() -> Self {
        Self(vec![])
    }

    pub fn init(&mut self, capacity: usize) {
        self.0.resize(capacity, 0);
    }

    #[allow(clippy::cast_possible_truncation)]
    pub fn read_u8(&mut self, p_address: u64) -> u8 {
        debug_assert!(
            p_address >= DRAM_BASE,
            "Memory address must equals to or bigger than DRAM_BASE. {p_address:X}"
        );
        let address = p_address - DRAM_BASE;
        self.0[address as usize]
    }

    #[allow(clippy::cast_possible_truncation)]
    /// # Panic
    /// No, it can't panic
    pub fn read_u16(&mut self, p_address: u64) -> u16 {
        debug_assert!(
            p_address >= DRAM_BASE && p_address.wrapping_add(1) >= DRAM_BASE,
            "Memory address must equals to or bigger than DRAM_BASE. {p_address:X}"
        );
        let address = p_address - DRAM_BASE;
        let address = address as usize;
        u16::from_le_bytes(self.0[address..address + 2].try_into().unwrap())
    }

    #[allow(clippy::cast_possible_truncation)]
    pub fn read_u32(&mut self, p_address: u64) -> u32 {
        debug_assert!(
            p_address >= DRAM_BASE && p_address.wrapping_add(3) >= DRAM_BASE,
            "Memory address must equals to or bigger than DRAM_BASE. {p_address:X}"
        );
        let address = p_address - DRAM_BASE;
        let address = address as usize;
        let mut buf = [0; 4];
        buf.copy_from_slice(&self.0[address..address + 4]);
        u32::from_le_bytes(buf)
    }

    #[allow(clippy::cast_possible_truncation)]
    pub fn read_u64(&mut self, p_address: u64) -> u64 {
        debug_assert!(
            p_address >= DRAM_BASE && p_address.wrapping_add(7) >= DRAM_BASE,
            "Memory address must equals to or bigger than DRAM_BASE. {p_address:X}"
        );
        let address = p_address - DRAM_BASE;
        let address = address as usize;
        let mut buf = [0; 8];
        buf.copy_from_slice(&self.0[address..address + 8]);
        u64::from_le_bytes(buf)
    }

    /// # Errors
    /// If any part of the access is outside memory, an unit error is returned
    #[allow(clippy::cast_possible_truncation)]
    pub fn write_u8(&mut self, pa: u64, b: u8) -> Result<(), ()> {
        let offset = pa.wrapping_sub(DRAM_BASE) as usize;
        if self.0.len() <= offset {
            return Err(());
        }
        self.0[offset] = b;
        Ok(())
    }

    /// # Errors
    /// If any part of the access is outside memory, an unit error is returned
    #[allow(clippy::cast_possible_truncation)]
    pub fn write_u16(&mut self, pa: u64, value: u16) -> Result<(), ()> {
        let offset = pa.wrapping_sub(DRAM_BASE) as usize;
        if self.0.len() < offset + 2 {
            // XXX would still fail DRAM_BASE-1 but the more exhausing checking is expensive
            return Err(());
        }
        self.0[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    /// # Errors
    /// If any part of the access is outside memory, an unit error is returned
    #[allow(clippy::cast_possible_truncation)]
    pub fn write_u32(&mut self, pa: u64, value: u32) -> Result<(), ()> {
        let offset = pa.wrapping_sub(DRAM_BASE) as usize;
        if self.0.len() < offset + 4 {
            // XXX would still fail DRAM_BASE-3..DRAM_BASE-1 but the more exhausing checking is expensive
            return Err(());
        }
        self.0[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    /// # Errors
    /// If any part of the access is outside memory, an unit error is returned
    #[allow(clippy::cast_possible_truncation)]
    pub fn write_u64(&mut self, pa: u64, value: u64) -> Result<(), ()> {
        let offset = pa.wrapping_sub(DRAM_BASE) as usize;
        if self.0.len() < offset + 8 {
            // XXX would still fail DRAM_BASE-3..DRAM_BASE-1 but the more exhausing checking is expensive
            return Err(());
        }
        self.0[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }

    // A new family of accessor functions that
    // - operates on physical addresses (i64)
    // - uses only i64 values
    // - traps out-of-range access
    // - allows misaligned access
    // AAAND this is repeating the same old mistakes.
    // What we should have instead:

    /// `slice` gives access to a writable slice of memory.
    /// # Errors
    /// If any part of the access is outside memory, an unit error is returned
    pub fn slice(&mut self, pa: i64, size: usize) -> Result<&mut [u8], ()> {
        let pa = pa.wrapping_sub(DRAM_BASE as i64) as usize;
        if pa <= self.0.len() && pa + size <= self.0.len() {
            Ok(&mut self.0[pa..pa + size])
        } else {
            Err(())
        }
    }
}

impl Default for Memory {
    fn default() -> Self {
        Self::new()
    }
}
