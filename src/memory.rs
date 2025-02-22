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
pub const MEMORY_SIZE: usize = 512 * 1024 * 1024;
pub const MEMORY_BASE: i64 = DRAM_BASE as i64;
pub const MEMORY_END: i64 = MEMORY_BASE + MEMORY_SIZE as i64;
pub struct Memory(Vec<u8>);
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

    #[allow(clippy::cast_possible_truncation)]
    pub fn write_u8(&mut self, p_address: u64, value: u8) {
        debug_assert!(
            p_address >= DRAM_BASE,
            "Memory address must equals to or bigger than DRAM_BASE. {p_address:X}"
        );
        let address = p_address - DRAM_BASE;
        self.0[address as usize] = value;
    }

    #[allow(clippy::cast_possible_truncation)]
    pub fn write_u16(&mut self, p_address: u64, value: u16) {
        debug_assert!(
            p_address >= DRAM_BASE && p_address.wrapping_add(1) >= DRAM_BASE,
            "Memory address must equals to or bigger than DRAM_BASE. {p_address:X}"
        );
        let address = p_address - DRAM_BASE;
        let address = address as usize;
        self.0[address..address + 2].copy_from_slice(&value.to_le_bytes());
    }

    #[allow(clippy::cast_possible_truncation)]
    pub fn write_u32(&mut self, p_address: u64, value: u32) {
        debug_assert!(
            p_address >= DRAM_BASE && p_address.wrapping_add(3) >= DRAM_BASE,
            "Memory address must equals to or bigger than DRAM_BASE. {p_address:X}"
        );
        let address = p_address - DRAM_BASE;
        let address = address as usize;
        self.0[address..address + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[allow(clippy::cast_possible_truncation)]
    pub fn write_u64(&mut self, p_address: u64, value: u64) {
        debug_assert!(
            p_address >= DRAM_BASE && p_address.wrapping_add(7) >= DRAM_BASE,
            "Memory address must equals to or bigger than DRAM_BASE. {p_address:X}"
        );
        let address = p_address - DRAM_BASE;
        let address: usize = address as usize;
        self.0[address..address + 8].copy_from_slice(&value.to_le_bytes());
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
    /// a unit error is returned if any part of the `[pa..pa+size]` range
    /// is outside memory.
    pub fn slice(&mut self, pa: i64, size: usize) -> Result<&mut [u8], ()> {
        let pa = pa.wrapping_sub(MEMORY_BASE) as usize;
        if pa <= MEMORY_SIZE && pa + size < MEMORY_SIZE + 1 {
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
