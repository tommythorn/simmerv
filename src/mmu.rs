#![allow(clippy::unreadable_literal)]

use crate::cpu::{
    PrivilegeMode, Trap, TrapType, CONFIG_SW_MANAGED_A_AND_D, MSTATUS_MPP_SHIFT, MSTATUS_MPRV,
    MSTATUS_MXR, MSTATUS_SUM, PG_SHIFT,
};
use crate::device::clint::Clint;
use crate::device::plic::Plic;
use crate::device::uart::Uart;
use crate::device::virtio_block_disk::VirtioBlockDisk;
use crate::terminal::Terminal;
use fnv::FnvHashMap;
use num_traits::FromPrimitive;

/// DRAM base address. Offset from this base address
/// is the address in main memory.
pub const DRAM_BASE: u64 = 0x80000000;

const DTB_SIZE: usize = 0xfe0;

/// Emulates Memory Management Unit. It holds the Main memory and peripheral
/// devices, maps address to them, and accesses them depending on address.
///
/// It also manages virtual-physical address translation and memoty protection.
/// It may also be said Bus.
/// @TODO: Memory protection is not implemented yet. We should support.
pub struct Mmu {
    ppn: u64,
    addressing_mode: AddressingMode,
    privilege_mode: PrivilegeMode,
    memory: Memory,
    dtb: Vec<u8>,
    disk: VirtioBlockDisk,
    plic: Plic,
    clint: Clint,
    uart: Uart,

    /// Address translation can be affected `mstatus` (MPRV, MPP in machine mode)
    /// then `Mmu` has copy of it.
    mstatus: u64,

    /// Address translation page cache. Experimental feature.
    /// The cache is cleared when translation mapping can be changed;
    /// xlen, ppn, `privilege_mode`, or `addressing_mode` is updated.
    /// Precisely it isn't good enough because page table entries
    /// can be updated anytime with store instructions, of course
    /// very depending on how pages are mapped tho.
    /// But observing all page table entries is high cost so
    /// ignoring so far. Then this cache optimization can cause a bug
    /// due to unexpected (meaning not in page fault handler)
    /// page table entry update. So this is experimental feature and
    /// disabled by default. If you want to enable, use `enable_page_cache()`.
    page_cache_enabled: bool,
    fetch_page_cache: FnvHashMap<u64, u64>,
    load_page_cache: FnvHashMap<u64, u64>,
    store_page_cache: FnvHashMap<u64, u64>,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum AddressingMode {
    None,
    SV39,
    SV48, // @TODO: Implement
}

#[derive(Copy, Clone, PartialEq, Debug)]
enum MemoryAccessType {
    Execute,
    Read,
    Write,
}

pub const PTE_V_MASK: u64 = 1 << 0;
pub const PTE_U_MASK: u64 = 1 << 4;
pub const PTE_A_MASK: u64 = 1 << 6;
pub const PTE_D_MASK: u64 = 1 << 7;

impl Mmu {
    /// Creates a new `Mmu`.
    ///
    /// # Arguments
    /// * `xlen`
    /// * `terminal`
    #[must_use]
    pub fn new(terminal: Box<dyn Terminal>) -> Self {
        let mut dtb = vec![0; DTB_SIZE];

        // Load default device tree binary content
        let content = include_bytes!("./device/dtb.dtb");
        dtb[..content.len()].copy_from_slice(&content[..]);

        Self {
            ppn: 0,
            addressing_mode: AddressingMode::None,
            privilege_mode: PrivilegeMode::Machine,
            memory: Memory::new(),
            dtb,
            disk: VirtioBlockDisk::new(),
            plic: Plic::new(),
            clint: Clint::new(),
            uart: Uart::new(terminal),
            mstatus: 0,
            page_cache_enabled: false,
            fetch_page_cache: FnvHashMap::default(),
            load_page_cache: FnvHashMap::default(),
            store_page_cache: FnvHashMap::default(),
        }
    }

    /// Initializes Main memory. This method is expected to be called only once.
    ///
    /// # Arguments
    /// * `capacity`
    pub fn init_memory(&mut self, capacity: usize) {
        self.memory.init(capacity);
    }

    /// Initializes Virtio block disk. This method is expected to be called only once.
    ///
    /// # Arguments
    /// * `data` Filesystem binary content
    pub fn init_disk(&mut self, data: Vec<u8>) {
        self.disk.init(data);
    }

    /// Overrides default Device tree configuration.
    ///
    /// # Arguments
    /// * `data` DTB binary content
    pub fn init_dtb(&mut self, data: &[u8]) {
        self.dtb[..data.len()].copy_from_slice(data);
        for i in data.len()..self.dtb.len() {
            self.dtb[i] = 0;
        }
    }

    /// Enables or disables page cache optimization.
    ///
    /// # Arguments
    /// * `enabled`
    pub fn enable_page_cache(&mut self, enabled: bool) {
        self.page_cache_enabled = enabled;
        self.clear_page_cache();
    }

    /// Clears page cache entries
    fn clear_page_cache(&mut self) {
        self.fetch_page_cache.clear();
        self.load_page_cache.clear();
        self.store_page_cache.clear();
    }

    /// Runs one cycle of MMU and peripheral devices.
    pub fn service(&mut self, mip: &mut u64) {
        self.clint.service(mip);
        self.disk.service(&mut self.memory);
        self.uart.service();
        self.plic.service(
            self.disk.is_interrupting(),
            self.uart.is_interrupting(),
            mip,
        );
    }

    /// Updates addressing mode
    ///
    /// # Arguments
    /// * `new_addressing_mode`
    pub fn update_addressing_mode(&mut self, new_addressing_mode: AddressingMode) {
        self.addressing_mode = new_addressing_mode;
        self.clear_page_cache();
    }

    /// Updates privilege mode
    ///
    /// # Arguments
    /// * `mode`
    pub fn update_privilege_mode(&mut self, mode: PrivilegeMode) {
        self.privilege_mode = mode;
        self.clear_page_cache();
    }

    /// Updates mstatus copy. `CPU` needs to call this method whenever
    /// `mstatus` is updated.
    ///
    /// # Arguments
    /// * `mstatus`
    pub const fn update_mstatus(&mut self, mstatus: u64) {
        self.mstatus = mstatus;
    }

    /// Updates PPN used for address translation
    ///
    /// # Arguments
    /// * `ppn`
    pub fn update_ppn(&mut self, ppn: u64) {
        self.ppn = ppn;
        self.clear_page_cache();
    }

    /// Fetches an instruction byte. This method takes virtual address
    /// and translates into physical address inside.
    ///
    /// # Arguments
    /// * `v_address` Virtual address
    fn fetch_u8(&mut self, v_address: u64) -> Result<u8, Trap> {
        let p_address = self.translate_address(v_address, MemoryAccessType::Execute)?;
        Ok(self.load_raw(p_address))
    }

    /// Fetches instruction four bytes. This method takes virtual address
    /// and translates into physical address inside.
    ///
    /// # Arguments
    /// * `v_address` Virtual address
    /// # Errors
    /// Exceptions are returned as errors
    pub fn fetch_word(&mut self, v_address: u64) -> Result<u32, Trap> {
        let width = 4;
        if v_address & 0xfff <= 0x1000 - width {
            // Fast path. All bytes fetched are in the same page so
            // translating an address only once.
            let p_address = self.translate_address(v_address, MemoryAccessType::Execute)?;
            Ok(self.load_word_raw(p_address)) // XXX Can't fail?
        } else {
            let mut data = 0_u32;
            for i in 0..width {
                let byte = self.fetch_u8(v_address.wrapping_add(i))?;
                data |= u32::from(byte) << (i * 8);
            }
            Ok(data)
        }
    }

    /// Loads an byte. This method takes virtual address and translates
    /// into physical address inside.
    ///
    /// # Arguments
    /// * `v_address` Virtual address
    /// # Errors
    /// Exceptions are returned as errors
    pub fn load(&mut self, v_address: u64) -> Result<u8, Trap> {
        let p_address = self.translate_address(v_address, MemoryAccessType::Read)?;
        Ok(self.load_raw(p_address))
    }

    /// Loads multiple bytes. This method takes virtual address and translates
    /// into physical address inside.
    ///
    /// # Arguments
    /// * `v_address` Virtual address
    /// * `width` Must be 1, 2, 4, or 8
    fn load_bytes(&mut self, v_address: u64, width: u64) -> Result<u64, Trap> {
        debug_assert!(
            width == 1 || width == 2 || width == 4 || width == 8,
            "Width must be 1, 2, 4, or 8. {width:X}"
        );
        if v_address & 0xfff <= 0x1000 - width {
            // Fast path. All bytes fetched are in the same page so
            // translating an address only once.
            let p_address = self.translate_address(v_address, MemoryAccessType::Read)?;
            Ok(match width {
                1 => u64::from(self.load_raw(p_address)),
                2 => u64::from(self.load_halfword_raw(p_address)),
                4 => u64::from(self.load_word_raw(p_address)),
                8 => self.load_doubleword_raw(p_address),
                _ => panic!("Width must be 1, 2, 4, or 8. {width:X}"),
            })
        } else {
            let mut data = 0_u64;
            for i in 0..width {
                let byte = self.load(v_address.wrapping_add(i))?;
                data |= u64::from(byte) << (i * 8);
            }
            Ok(data)
        }
    }

    /// Loads two bytes. This method takes virtual address and translates
    /// into physical address inside.
    ///
    /// # Arguments
    /// * `v_address` Virtual address
    /// # Errors
    /// Exceptions are returned as errors
    #[allow(clippy::cast_possible_truncation)]
    pub fn load_halfword(&mut self, v_address: u64) -> Result<u16, Trap> {
        match self.load_bytes(v_address, 2) {
            Ok(data) => Ok(data as u16),
            Err(e) => Err(e),
        }
    }

    /// Loads four bytes. This method takes virtual address and translates
    /// into physical address inside.
    ///
    /// # Arguments
    /// * `v_address` Virtual address
    /// # Errors
    /// Exceptions are returned as errors
    #[allow(clippy::cast_possible_truncation)]
    pub fn load_word(&mut self, v_address: u64) -> Result<u32, Trap> {
        match self.load_bytes(v_address, 4) {
            Ok(data) => Ok(data as u32),
            Err(e) => Err(e),
        }
    }

    /// Loads eight bytes. This method takes virtual address and translates
    /// into physical address inside.
    ///
    /// # Arguments
    /// * `v_address` Virtual address
    /// # Errors
    /// Exceptions are returned as errors
    pub fn load_doubleword(&mut self, v_address: u64) -> Result<u64, Trap> {
        match self.load_bytes(v_address, 8) {
            Ok(data) => Ok(data),
            Err(e) => Err(e),
        }
    }

    /// Loads eight bytes as i64. This method takes virtual address and translates
    /// into physical address inside.
    ///
    /// # Arguments
    /// * `v_address` Virtual address
    /// # Errors
    /// Exceptions are returned as errors
    #[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
    pub fn load64(&mut self, v_address: i64) -> Result<i64, Trap> {
        // XXX All addresses should be i64
        Ok(self.load_bytes(v_address as u64, 8)? as i64)
    }

    /// Store an byte. This method takes virtual address and translates
    /// into physical address inside.
    ///
    /// # Arguments
    /// * `v_address` Virtual address
    /// * `value`
    /// # Errors
    /// Exceptions are returned as errors
    pub fn store(&mut self, v_address: u64, value: u8) -> Result<(), Trap> {
        let p_address = self.translate_address(v_address, MemoryAccessType::Write)?;
        self.store_raw(p_address, value);
        Ok(())
    }

    /// Stores multiple bytes. This method takes a virtual address and translates
    /// it into physical address inside.
    ///
    /// # Arguments
    /// * `v_address` Virtual address
    /// * `value` data written
    /// * `width` Must be 1, 2, 4, or 8
    /// # Errors
    /// Exceptions are returned as errors
    #[allow(clippy::cast_possible_truncation)]
    fn store_bytes(&mut self, v_address: u64, value: u64, width: u64) -> Result<(), Trap> {
        debug_assert!(
            width == 1 || width == 2 || width == 4 || width == 8,
            "Width must be 1, 2, 4, or 8. {width:X}"
        );
        if v_address & 0xfff <= 0x1000 - width {
            // Fast path. All bytes fetched are in the same page so
            // translating an address only once.
            let p_address = self.translate_address(v_address, MemoryAccessType::Write)?;
            match width {
                1 => self.store_raw(p_address, value as u8),
                2 => self.store_halfword_raw(p_address, value as u16),
                4 => self.store_word_raw(p_address, value as u32),
                8 => self.store_doubleword_raw(p_address, value),
                _ => panic!("Width must be 1, 2, 4, or 8. {width:X}"),
            }
        } else {
            for i in 0..width {
                self.store(v_address.wrapping_add(i), ((value >> (i * 8)) & 0xff) as u8)?;
            }
        }
        Ok(())
    }

    /// Stores two bytes. This method takes virtual address and translates
    /// into physical address inside.
    ///
    /// # Arguments
    /// * `v_address` Virtual address
    /// * `value` data written
    /// # Errors
    /// Exceptions are returned as errors
    pub fn store_halfword(&mut self, v_address: u64, value: u16) -> Result<(), Trap> {
        self.store_bytes(v_address, u64::from(value), 2)
    }

    /// Stores four bytes. This method takes virtual address and translates
    /// into physical address inside.
    ///
    /// # Arguments
    /// * `v_address` Virtual address
    /// * `value` data written
    /// # Errors
    /// Exceptions are returned as errors
    pub fn store_word(&mut self, v_address: u64, value: u32) -> Result<(), Trap> {
        self.store_bytes(v_address, u64::from(value), 4)
    }

    /// Stores eight bytes. This method takes virtual address and translates
    /// into physical address inside.
    ///
    /// # Arguments
    /// * `v_address` Virtual address
    /// * `value` data written
    /// # Errors
    /// Exceptions are returned as errors
    pub fn store_doubleword(&mut self, v_address: u64, value: u64) -> Result<(), Trap> {
        self.store_bytes(v_address, value, 8)
    }

    /// # Errors
    /// Exceptions are returned as errors
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn store64(&mut self, v_address: i64, value: i64) -> Result<(), Trap> {
        self.store_bytes(v_address as u64, value as u64, 8)
    }

    /// # Errors
    /// Exceptions are returned as errors
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn store32(&mut self, v_address: i64, value: i64) -> Result<(), Trap> {
        self.store_bytes(v_address as u64, value as u64, 4)
    }

    /// Loads a byte from main memory or peripheral devices depending on
    /// physical address.
    ///
    /// # Arguments
    /// * `p_address` Physical address
    #[allow(clippy::cast_possible_truncation)]
    fn load_raw(&mut self, p_address: u64) -> u8 {
        // @TODO: Mapping should be configurable with dtb
        if p_address >= DRAM_BASE {
            self.memory.read_u8(p_address)
        } else {
            match p_address {
                // I don't know why but dtb data seems to be stored from 0x1020 on Linux.
                // It might be from self.x[0xb] initialization?
                // And DTB size is arbitray.
                0x00001020..=0x00001fff => self.dtb[p_address as usize - 0x1020],
                0x02000000..=0x0200ffff => self.clint.load(p_address),
                0x0C000000..=0x0fffffff => self.plic.load(p_address),
                0x10000000..=0x100000ff => self.uart.load(p_address),
                0x10001000..=0x10001FFF => self.disk.load(p_address),
                _ => panic!("Unknown memory mapping {p_address:X}."),
            }
        }
    }

    /// Loads two bytes from main memory or peripheral devices depending on
    /// physical address.
    ///
    /// # Arguments
    /// * `p_address` Physical address
    fn load_halfword_raw(&mut self, p_address: u64) -> u16 {
        if p_address >= DRAM_BASE && p_address.wrapping_add(1) > p_address {
            // Fast path. Directly load main memory at a time.
            self.memory.read_u16(p_address)
        } else {
            let mut data = 0_u16;
            for i in 0..2 {
                data |= u16::from(self.load_raw(p_address.wrapping_add(i))) << (i * 8);
            }
            data
        }
    }

    /// Loads four bytes from main memory or peripheral devices depending on
    /// physical address.
    ///
    /// # Arguments
    /// * `p_address` Physical address
    pub fn load_word_raw(&mut self, p_address: u64) -> u32 {
        if p_address >= DRAM_BASE && p_address.wrapping_add(3) > p_address {
            self.memory.read_u32(p_address)
        } else {
            let mut data = 0_u32;
            for i in 0..4 {
                data |= u32::from(self.load_raw(p_address.wrapping_add(i))) << (i * 8);
            }
            data
        }
    }

    /// Loads eight bytes from main memory or peripheral devices depending on
    /// physical address.
    ///
    /// # Arguments
    /// * `p_address` Physical address
    fn load_doubleword_raw(&mut self, p_address: u64) -> u64 {
        if p_address >= DRAM_BASE && p_address.wrapping_add(7) > p_address {
            self.memory.read_u64(p_address)
        } else {
            let mut data = 0_u64;
            for i in 0..8 {
                data |= u64::from(self.load_raw(p_address.wrapping_add(i))) << (i * 8);
            }
            data
        }
    }

    /// Stores a byte to main memory or peripheral devices depending on
    /// physical address.
    ///
    /// # Arguments
    /// * `p_address` Physical address
    /// * `value` data written
    /// # Panics
    /// Will panic on access to unsupported MMIO ranges (XXX this should just ignore them)
    pub fn store_raw(&mut self, p_address: u64, value: u8) {
        // @TODO: Mapping should be configurable with dtb
        if p_address >= DRAM_BASE {
            self.memory.write_u8(p_address, value);
        } else {
            match p_address {
                0x02000000..=0x0200ffff => self.clint.store(p_address, value),
                0x0c000000..=0x0fffffff => self.plic.store(p_address, value),
                0x10000000..=0x100000ff => self.uart.store(p_address, value),
                0x10001000..=0x10001FFF => self.disk.store(p_address, value),
                _ => panic!("Unknown memory mapping {p_address:X}."),
            }
        }
    }

    /// Stores two bytes to main memory or peripheral devices depending on
    /// physical address.
    ///
    /// # Arguments
    /// * `p_address` Physical address
    /// * `value` data written
    fn store_halfword_raw(&mut self, p_address: u64, value: u16) {
        if p_address >= DRAM_BASE && p_address.wrapping_add(1) > p_address {
            self.memory.write_u16(p_address, value);
        } else {
            for i in 0..2 {
                self.store_raw(p_address.wrapping_add(i), ((value >> (i * 8)) & 0xff) as u8);
            }
        }
    }

    /// Stores four bytes to main memory or peripheral devices depending on
    /// physical address.
    ///
    /// # Arguments
    /// * `p_address` Physical address
    /// * `value` data written
    fn store_word_raw(&mut self, p_address: u64, value: u32) {
        if p_address >= DRAM_BASE && p_address.wrapping_add(3) > p_address {
            self.memory.write_u32(p_address, value);
        } else {
            for i in 0..4 {
                self.store_raw(p_address.wrapping_add(i), ((value >> (i * 8)) & 0xff) as u8);
            }
        }
    }

    /// Stores eight bytes to main memory or peripheral devices depending on
    /// physical address.
    ///
    /// # Arguments
    /// * `p_address` Physical address
    /// * `value` data written
    fn store_doubleword_raw(&mut self, p_address: u64, value: u64) {
        if p_address >= DRAM_BASE && p_address.wrapping_add(7) > p_address {
            self.memory.write_u64(p_address, value);
        } else {
            for i in 0..8 {
                self.store_raw(p_address.wrapping_add(i), ((value >> (i * 8)) & 0xff) as u8);
            }
        }
    }

    fn translate_address(
        &mut self,
        address: u64,
        access_type: MemoryAccessType,
    ) -> Result<u64, Trap> {
        let v_page = address & !0xfff;

        let cache = if self.page_cache_enabled {
            match access_type {
                MemoryAccessType::Execute => self.fetch_page_cache.get(&v_page),
                MemoryAccessType::Read => self.load_page_cache.get(&v_page),
                MemoryAccessType::Write => self.store_page_cache.get(&v_page),
            }
        } else {
            None
        };

        if let Some(p_page) = cache {
            return Ok(p_page | (address & 0xfff));
        }

        let p_address = self.translate_address_slow(address, access_type)?;

        if self.page_cache_enabled {
            let p_page = p_address & !0xfff;
            let _ = match access_type {
                MemoryAccessType::Execute => self.fetch_page_cache.insert(v_page, p_page),
                MemoryAccessType::Read => self.load_page_cache.insert(v_page, p_page),
                MemoryAccessType::Write => self.store_page_cache.insert(v_page, p_page),
            };
        }

        Ok(p_address)
    }

    #[allow(clippy::cast_possible_wrap)]
    fn translate_address_slow(
        &mut self,
        address: u64,
        access_type: MemoryAccessType,
    ) -> Result<u64, Trap> {
        let effective_priv = if self.mstatus & MSTATUS_MPRV != 0
            && access_type != MemoryAccessType::Execute
        {
            // Use previous privilege
            let Some(prv) = FromPrimitive::from_u64((self.mstatus >> MSTATUS_MPP_SHIFT) & 3) else {
                unreachable!();
            };
            prv
        } else {
            self.privilege_mode
        };

        if matches!(effective_priv, PrivilegeMode::Machine)
            || matches!(self.addressing_mode, AddressingMode::None)
        {
            return Ok(address);
        }

        // Sv39 (Sv48 in future)
        let levels = match self.addressing_mode {
            AddressingMode::SV39 => 3,
            AddressingMode::SV48 => 4,
            AddressingMode::None => unreachable!(),
        };

        let access_shift = match access_type {
            MemoryAccessType::Read => 0,
            MemoryAccessType::Write => 1,
            MemoryAccessType::Execute => 2,
        };

        let pte_size_log2 = 3;
        let vaddr_shift = 64 - (PG_SHIFT + levels * 9);
        // Check for canonical addresses
        if ((address as i64) << vaddr_shift) >> vaddr_shift != address as i64 {
            // XXX Some debugging logging here might be useful
            return page_fault(address as i64, access_type);
        }
        let pte_addr_bits = 44;
        let mut pte_addr = (self.ppn & ((1 << pte_addr_bits) - 1)) << PG_SHIFT;
        let pte_bits = 12 - pte_size_log2;
        let pte_mask = (1 << pte_bits) - 1;

        for i in 0..levels {
            let vaddr_shift = PG_SHIFT + pte_bits * (levels - 1 - i);
            let pte_idx = (address >> vaddr_shift) & pte_mask;
            pte_addr += pte_idx << pte_size_log2;
            // XXX Not only do we need to raise an exception if this
            // fails, but failing here doesn't cause a page fault but
            // just a fault (eg CAUSE_FAULT_LOAD/STORE instead of all
            // the others which are
            // CAUSE_LOAD/STORE/FETCH_PAGE_FAULT).
            let pte = self.load_doubleword_raw(pte_addr);
            // return access_fault(address, access_type);

            if pte & PTE_V_MASK == 0 {
                // XXX Debug log would be useful
                //info!("** {:?} mode access to {address:08x} denied: invalid PTE", self.privilege_mode);
                break;
            }

            // XXX too many hardcoded values
            let paddr = (pte >> 10) << PG_SHIFT;
            let mut xwr = (pte >> 1) & 7;
            if xwr == 0 {
                pte_addr = paddr;
                continue;
            }

            // *** Found a leaf node ***

            if xwr == 2 || xwr == 6 {
                // XXX Debug log would be useful
                //info!("** {:?} mode access to {address:08x} denied: invalid xwr {xwr}", self.privilege_mode);
                break;
            }

            // priviledge check
            if effective_priv == PrivilegeMode::Supervisor {
                if pte & PTE_U_MASK != 0 && self.mstatus & MSTATUS_SUM == 0 {
                    // XXX Debug log would be useful
                    //info!("** {:?} mode access to {address:08x} denied: U & !SUM", self.privilege_mode);
                    break;
                }
            } else if pte & PTE_U_MASK == 0 {
                // XXX Debug log would be useful
                //info!("** {:?} mode access to {address:08x} denied: !U", self.privilege_mode);
                return page_fault(address as i64, access_type);
            }

            /* protection check */
            /* MXR allows read access to execute-only pages */
            if self.mstatus & MSTATUS_MXR != 0 {
                xwr |= xwr >> 2;
            }

            if (xwr >> access_shift) & 1 == 0 {
                //info!("** {:?} mode access to {address:08x} denied: want {access_shift}, got {xwr}", self.privilege_mode);
                break;
            }

            /* 6. Check for misaligned superpages */
            let ppn = pte >> 10;
            let j = levels - 1 - i;
            if ((1 << j) - 1) & ppn != 0 {
                //info!("** {:?} mode access to {address:08x} denied: misaligned superpage {i} / {ppn}", self.privilege_mode);
                break;
            }

            /*
              RISC-V Priv. Spec 1.11 (draft) Section 4.3.1 offers two
              ways to handle the A and D TLB flags.  Spike uses the
              software managed approach whereas Dromajo used to manage
              them (causing far fewer exceptions).
            */
            if CONFIG_SW_MANAGED_A_AND_D {
                if pte & PTE_A_MASK == 0 {
                    //info!("** {:?} mode access to {address:08x} denied: missing A", self.privilege_mode);
                    break; // Must have A on access
                }
                if access_type == MemoryAccessType::Write && pte & PTE_D_MASK == 0 {
                    //info!("** {:?} mode access to {address:08x} denied: missing D", self.privilege_mode);
                    break; // Must have D on write
                }
            } else {
                let mut new_pte = pte | PTE_A_MASK;
                if access_type == MemoryAccessType::Write {
                    new_pte |= PTE_D_MASK;
                }
                if pte != new_pte {
                    // XXX must return access fault on failure here
                    self.store_doubleword_raw(pte_addr, new_pte);
                    // return access_fault(address, access_type);
                }
            }

            let vaddr_mask = (1 << vaddr_shift) - 1;
            return Ok(paddr & !vaddr_mask | address & vaddr_mask);
        }

        page_fault(address as i64, access_type)
    }

    /// Returns immutable reference to `Clint`.
    #[must_use]
    pub const fn get_clint(&self) -> &Clint {
        &self.clint
    }

    /// Returns mutable reference to `Clint`.
    pub const fn get_mut_clint(&mut self) -> &mut Clint {
        &mut self.clint
    }

    /// Returns mutable reference to `Uart`.
    pub const fn get_mut_uart(&mut self) -> &mut Uart {
        &mut self.uart
    }
}

#[allow(dead_code)]
#[allow(clippy::cast_sign_loss)]
const fn access_fault<T>(address: i64, access_type: MemoryAccessType) -> Result<T, Trap> {
    Err::<T, Trap>(Trap {
        trap_type: match access_type {
            MemoryAccessType::Read => TrapType::LoadAccessFault,
            MemoryAccessType::Write => TrapType::StoreAccessFault,
            MemoryAccessType::Execute => TrapType::InstructionAccessFault,
        },
        value: address,
    })
}

#[allow(clippy::cast_sign_loss, clippy::cast_possible_wrap)] // XXX Try to remove this later when the u64 -> i64 conversion is done
const fn page_fault<T>(address: i64, access_type: MemoryAccessType) -> Result<T, Trap> {
    Err::<T, Trap>(Trap {
        trap_type: match access_type {
            MemoryAccessType::Read => TrapType::LoadPageFault,
            MemoryAccessType::Write => TrapType::StorePageFault,
            MemoryAccessType::Execute => TrapType::InstructionPageFault,
        },
        value: address,
    })
}

/// [`Memory`](../memory/struct.Memory.html). Converts physical address to the one in memory
/// using [`DRAM_BASE`](constant.DRAM_BASE.html) and accesses [`Memory`](../memory/struct.Memory.html).
// XXX Out of range access must fault, not crash.
pub struct Memory {
    data: Vec<u8>,
}

impl Memory {
    const fn new() -> Self {
        Self { data: vec![] }
    }

    fn init(&mut self, capacity: usize) {
        self.data.resize(capacity, 0);
    }

    #[allow(clippy::cast_possible_truncation)]
    pub fn read_u8(&mut self, p_address: u64) -> u8 {
        debug_assert!(
            p_address >= DRAM_BASE,
            "Memory address must equals to or bigger than DRAM_BASE. {p_address:X}"
        );
        let address = p_address - DRAM_BASE;
        self.data[address as usize]
    }

    #[allow(clippy::cast_possible_truncation)]
    pub fn read_u16(&mut self, p_address: u64) -> u16 {
        debug_assert!(
            p_address >= DRAM_BASE && p_address.wrapping_add(1) >= DRAM_BASE,
            "Memory address must equals to or bigger than DRAM_BASE. {p_address:X}"
        );
        let address = p_address - DRAM_BASE;
        let address = address as usize;
        let mut buf = [0; 2];
        buf.copy_from_slice(&self.data[address..address + 2]);
        u16::from_le_bytes(buf)
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
        buf.copy_from_slice(&self.data[address..address + 4]);
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
        buf.copy_from_slice(&self.data[address..address + 8]);
        u64::from_le_bytes(buf)
    }

    #[allow(clippy::cast_possible_truncation)]
    pub fn write_u8(&mut self, p_address: u64, value: u8) {
        debug_assert!(
            p_address >= DRAM_BASE,
            "Memory address must equals to or bigger than DRAM_BASE. {p_address:X}"
        );
        let address = p_address - DRAM_BASE;
        self.data[address as usize] = value;
    }

    #[allow(clippy::cast_possible_truncation)]
    pub fn write_u16(&mut self, p_address: u64, value: u16) {
        debug_assert!(
            p_address >= DRAM_BASE && p_address.wrapping_add(1) >= DRAM_BASE,
            "Memory address must equals to or bigger than DRAM_BASE. {p_address:X}"
        );
        let address = p_address - DRAM_BASE;
        let address = address as usize;
        self.data[address..address + 2].copy_from_slice(&value.to_le_bytes());
    }

    #[allow(clippy::cast_possible_truncation)]
    pub fn write_u32(&mut self, p_address: u64, value: u32) {
        debug_assert!(
            p_address >= DRAM_BASE && p_address.wrapping_add(3) >= DRAM_BASE,
            "Memory address must equals to or bigger than DRAM_BASE. {p_address:X}"
        );
        let address = p_address - DRAM_BASE;
        let address = address as usize;
        self.data[address..address + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[allow(clippy::cast_possible_truncation)]
    pub fn write_u64(&mut self, p_address: u64, value: u64) {
        debug_assert!(
            p_address >= DRAM_BASE && p_address.wrapping_add(7) >= DRAM_BASE,
            "Memory address must equals to or bigger than DRAM_BASE. {p_address:X}"
        );
        let address = p_address - DRAM_BASE;
        let address: usize = address as usize;
        self.data[address..address + 8].copy_from_slice(&value.to_le_bytes());
    }
}
