#![allow(clippy::unreadable_literal)]

use crate::device::Context;
use crate::device::MemoryMapped;
use crate::device::MemoryMappedInfo;
use crate::device::Pack;
use crate::device::Unpack;
use crate::device::dma_read_u16;
use crate::device::dma_read_u32;
use crate::device::dma_read_u64;
use crate::device::dma_slice;
use crate::device::dma_write_u8;
use std::ops::Range;

// Based on Virtual I/O Device (VIRTIO) Version 1.1
// https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html

// 0x2000 is an arbitary number.
const MAX_QUEUE_SIZE: u64 = 0x2000;

const VIRTQ_DESC_F_NEXT: u16 = 1;

// 0: buffer is write-only = read from disk operation
// 1: buffer is read-only = write to disk operation
const VIRTQ_DESC_F_WRITE: u16 = 2;

const SECTOR_SIZE: usize = 512;

// Feature bits for virtio block device
const VIRTIO_BLK_F_BLK_SIZE: u64 = 6; // Block size of disk is available
const VIRTIO_BLK_F_FLUSH: u64 = 9; // Cache flush command support
const VIRTIO_BLK_F_TOPOLOGY: u64 = 10; // Device exports information on optimal I/O alignment
const VIRTIO_BLK_F_CONFIG_WCE: u64 = 11; // Device can toggle its cache between writeback and writethrough modes
const VIRTIO_BLK_F_DISCARD: u64 = 13; // Device can support discard command
const VIRTIO_BLK_F_WRITE_ZEROES: u64 = 14; // Device can support write zeroes command

// Default block size in bytes
const DEFAULT_BLOCK_SIZE: u32 = 512;

/// Emulates Virtio Block device. Refer to the [specification](https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html)
/// for the detail. It follows legacy API.
pub struct VirtioBlockDisk {
    pub used_ring_index: u16,
    pub device_features: u64,     // read only
    pub device_features_sel: u32, // write only
    pub driver_features: u64,     // write only
    _driver_features_sel: u32,    // write only
    pub guest_page_size: u32,     // write only
    pub queue_select: u32,        // write only
    pub queue_size: u32,          // write only
    pub queue_align: u32,         // write only
    pub queue_pfn: u32,           // read and write
    pub queue_notify: u32,        // write only
    pub interrupt_status: u32,    // read only
    pub status: u32,              // read and write
    /// Number of pending disk requests (replaces `notify_cycles` Vec).
    pub pending_requests: u32,
    pub contents: Vec<u8>,
    pub block_size: u32, // Block size in bytes
    pub writeback: bool, // Cache mode (true = writeback, false = writethrough)
    /// IRQ number asserted on the PLIC when interrupting.
    pub irq: u32,
}

impl Default for VirtioBlockDisk {
    fn default() -> Self { Self::new(Vec::new(), 1) }
}

impl VirtioBlockDisk {
    /// Creates a new `VirtioBlockDisk`.
    #[allow(clippy::cast_possible_truncation)]
    #[must_use]
    pub const fn new(contents: Vec<u8>, irq: u32) -> Self {
        Self {
            used_ring_index: 0,
            device_features: (1 << VIRTIO_BLK_F_BLK_SIZE)
                | (1 << VIRTIO_BLK_F_FLUSH)
                | (1 << VIRTIO_BLK_F_TOPOLOGY)
                | (1 << VIRTIO_BLK_F_CONFIG_WCE)
                | (1 << VIRTIO_BLK_F_DISCARD)
                | (1 << VIRTIO_BLK_F_WRITE_ZEROES),
            device_features_sel: 0,
            driver_features: 0,
            _driver_features_sel: 0,
            guest_page_size: 0,
            queue_select: 0,
            queue_size: 0,
            queue_align: 0x1000, // xv6 seems to expect this default value
            queue_pfn: 0,
            queue_notify: 0,
            status: 0,
            interrupt_status: 0,
            pending_requests: 0,
            contents,
            block_size: DEFAULT_BLOCK_SIZE,
            writeback: false,
            irq,
        }
    }

    /// Indicates whether `VirtioBlockDisk` raises an interrupt signal
    pub const fn is_interrupting(&mut self) -> bool { self.interrupt_status & 1 == 1 }

    /// Initializes filesystem content. The method is expected to be called
    /// only up to once.
    ///
    /// # Arguments
    /// * `contents` filesystem content binary
    #[allow(clippy::cast_lossless)]
    pub fn init(&mut self, contents: Vec<u8>) {
        if !contents.len().is_multiple_of(SECTOR_SIZE) {
            log::warn!(
                "Contents isn't a multiple of {SECTOR_SIZE}; {}B in last block",
                contents.len() % SECTOR_SIZE
            );
        }
        self.contents = contents;
    }

    /// Runs one service tick. If `pending_requests > 0`, handles disk access.
    /// Returns `Some(irq)` if interrupting, `None` otherwise.
    pub fn service_disk(&mut self, memory: &mut [(Range<u64>, Vec<u8>)]) -> Option<u32> {
        if self.pending_requests > 0 {
            // bit 0 in interrupt_status register indicates
            // the interrupt was asserted because the device has used a buffer
            // in at least one of the active virtual queues.
            self.interrupt_status |= 1;
            self.handle_disk_access(memory);
            self.pending_requests -= 1;
        }
        if self.is_interrupting() {
            Some(self.irq)
        } else {
            None
        }
    }

    /// Loads register content
    ///
    /// # Arguments
    /// * `offset` offset from the `VirtIO` device base address
    #[allow(clippy::match_same_arms, clippy::cast_possible_truncation)]
    pub fn load(&mut self, offset: u64) -> u8 {
        match offset {
            // Magic number: 0x74726976
            0x000 => 0x76,
            0x001 => 0x69,
            0x002 => 0x72,
            0x003 => 0x74,
            // Device version: 1 (Legacy device)
            0x004 => 1,
            // Virtio Subsystem Device id: 2 (Block device)
            0x008 => 2,
            // Virtio Subsystem Vendor id: 0x554d4551
            0x00c => 0x51,
            0x00d => 0x45,
            0x00e => 0x4d,
            0x00f => 0x55,
            // Flags representing features the device supports
            0x010 => ((self.device_features >> (self.device_features_sel * 32)) & 0xff) as u8,
            0x011 => {
                (((self.device_features >> (self.device_features_sel * 32)) >> 8) & 0xff) as u8
            }
            0x012 => {
                (((self.device_features >> (self.device_features_sel * 32)) >> 16) & 0xff) as u8
            }
            0x013 => {
                (((self.device_features >> (self.device_features_sel * 32)) >> 24) & 0xff) as u8
            }
            // Maximum virtual queue size
            0x034 => MAX_QUEUE_SIZE as u8,
            0x035 => (MAX_QUEUE_SIZE >> 8) as u8,
            0x036 => (MAX_QUEUE_SIZE >> 16) as u8,
            0x037 => (MAX_QUEUE_SIZE >> 24) as u8,
            // Guest physical page number of the virtual queue
            0x040 => self.queue_pfn as u8,
            0x041 => (self.queue_pfn >> 8) as u8,
            0x042 => (self.queue_pfn >> 16) as u8,
            0x043 => (self.queue_pfn >> 24) as u8,
            // Interrupt status
            0x060 => self.interrupt_status as u8,
            0x061 => (self.interrupt_status >> 8) as u8,
            0x062 => (self.interrupt_status >> 16) as u8,
            0x063 => (self.interrupt_status >> 24) as u8,
            // Device status
            0x070 => self.status as u8,
            0x071 => (self.status >> 8) as u8,
            0x072 => (self.status >> 16) as u8,
            0x073 => (self.status >> 24) as u8,
            // Configurations
            0x100..=0x107 => {
                let n_secs: u64 = self.contents.len() as u64 / u64::from(self.block_size);
                let n_secs_as_u8: [u8; 8] = n_secs.to_le_bytes();
                n_secs_as_u8[offset as usize & 7]
            }
            // Block size configuration
            0x108..=0x10B => {
                let block_size_as_u8: [u8; 4] = self.block_size.to_le_bytes();
                block_size_as_u8[offset as usize & 3]
            }
            // Topology configuration
            0x10C..=0x113 => {
                // Optimal I/O alignment in sectors
                let alignment: u64 = 1; // Default to 1 sector alignment
                let alignment_as_u8: [u8; 8] = alignment.to_le_bytes();
                alignment_as_u8[offset as usize & 7]
            }
            // Writeback configuration
            0x114 => u8::from(self.writeback),
            _ => 0,
        }
    }

    /// Stores register content
    ///
    /// # Arguments
    /// * `offset` offset from the `VirtIO` device base address
    /// * `value`
    /// # Panics
    /// Will panic if multi queue are attempted enabled (XXX should probably
    /// just ignore)
    #[allow(clippy::cast_lossless, clippy::too_many_lines)]
    pub fn store(&mut self, offset: u64, value: u8) {
        match offset {
            0x014 => {
                self.device_features_sel = (self.device_features_sel & !0xff) | (value as u32);
            }
            0x015 => {
                self.device_features_sel =
                    (self.device_features_sel & !(0xff << 8)) | ((value as u32) << 8);
            }
            0x016 => {
                self.device_features_sel =
                    (self.device_features_sel & !(0xff << 16)) | ((value as u32) << 16);
            }
            0x017 => {
                self.device_features_sel =
                    (self.device_features_sel & !(0xff << 24)) | ((value as u32) << 24);
            }
            0x020 => {
                self.driver_features = (self.driver_features & !0xff) | (value as u64);
            }
            0x021 => {
                self.driver_features =
                    (self.driver_features & !(0xff << 8)) | ((value as u64) << 8);
            }
            0x022 => {
                self.driver_features =
                    (self.driver_features & !(0xff << 16)) | ((value as u64) << 16);
            }
            0x023 => {
                self.driver_features =
                    (self.driver_features & !(0xff << 24)) | ((value as u64) << 24);
            }
            0x024 => {
                self.driver_features =
                    (self.driver_features & !(0xff << 32)) | ((value as u64) << 32);
            }
            0x025 => {
                self.driver_features =
                    (self.driver_features & !(0xff << 40)) | ((value as u64) << 40);
            }
            0x026 => {
                self.driver_features =
                    (self.driver_features & !(0xff << 48)) | ((value as u64) << 48);
            }
            0x027 => {
                self.driver_features =
                    (self.driver_features & !(0xff << 56)) | ((value as u64) << 56);
            }
            0x028 => {
                self.guest_page_size = (self.guest_page_size & !0xff) | (value as u32);
            }
            0x029 => {
                self.guest_page_size =
                    (self.guest_page_size & !(0xff << 8)) | ((value as u32) << 8);
            }
            0x02a => {
                self.guest_page_size =
                    (self.guest_page_size & !(0xff << 16)) | ((value as u32) << 16);
            }
            0x02b => {
                self.guest_page_size =
                    (self.guest_page_size & !(0xff << 24)) | ((value as u32) << 24);
            }
            0x030 => {
                self.queue_select = (self.queue_select & !0xff) | (value as u32);
            }
            0x031 => {
                self.queue_select = (self.queue_select & !(0xff << 8)) | ((value as u32) << 8);
            }
            0x032 => {
                self.queue_select = (self.queue_select & !(0xff << 16)) | ((value as u32) << 16);
            }
            0x033 => {
                self.queue_select = (self.queue_select & !(0xff << 24)) | ((value as u32) << 24);
                assert!(
                    self.queue_select == 0,
                    "Virtio: No multi queue support yet."
                );
            }
            0x038 => {
                self.queue_size = (self.queue_size & !0xff) | (value as u32);
            }
            0x039 => {
                self.queue_size = (self.queue_size & !(0xff << 8)) | ((value as u32) << 8);
            }
            0x03a => {
                self.queue_size = (self.queue_size & !(0xff << 16)) | ((value as u32) << 16);
            }
            0x03b => {
                self.queue_size = (self.queue_size & !(0xff << 24)) | ((value as u32) << 24);
            }
            0x03c => {
                self.queue_align = (self.queue_align & !0xff) | (value as u32);
            }
            0x03d => {
                self.queue_align = (self.queue_align & !(0xff << 8)) | ((value as u32) << 8);
            }
            0x03e => {
                self.queue_align = (self.queue_align & !(0xff << 16)) | ((value as u32) << 16);
            }
            0x03f => {
                self.queue_align = (self.queue_align & !(0xff << 24)) | ((value as u32) << 24);
            }
            0x040 => {
                self.queue_pfn = (self.queue_pfn & !0xff) | (value as u32);
            }
            0x041 => {
                self.queue_pfn = (self.queue_pfn & !(0xff << 8)) | ((value as u32) << 8);
            }
            0x042 => {
                self.queue_pfn = (self.queue_pfn & !(0xff << 16)) | ((value as u32) << 16);
            }
            0x043 => {
                self.queue_pfn = (self.queue_pfn & !(0xff << 24)) | ((value as u32) << 24);
            }
            // @TODO: Queue request support
            0x050 => {
                self.queue_notify = (self.queue_notify & !0xff) | (value as u32);
            }
            0x051 => {
                self.queue_notify = (self.queue_notify & !(0xff << 8)) | ((value as u32) << 8);
            }
            0x052 => {
                self.queue_notify = (self.queue_notify & !(0xff << 16)) | ((value as u32) << 16);
            }
            0x053 => {
                self.queue_notify = (self.queue_notify & !(0xff << 24)) | ((value as u32) << 24);
                self.pending_requests += 1;
            }
            0x064 => self.interrupt_status &= !(value as u32), // interrupt ack
            0x070 => {
                self.status = (self.status & !0xff) | (value as u32);
            }
            0x071 => {
                self.status = (self.status & !(0xff << 8)) | ((value as u32) << 8);
            }
            0x072 => {
                self.status = (self.status & !(0xff << 16)) | ((value as u32) << 16);
            }
            0x073 => {
                self.status = (self.status & !(0xff << 24)) | ((value as u32) << 24);
            }
            0x114 if self.driver_features & (1 << VIRTIO_BLK_F_CONFIG_WCE) != 0 => {
                self.writeback = value != 0;
            }
            _ => {}
        }
    }

    /// Fast path of transferring the data from disk to memory.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::expect_used,
        clippy::cast_possible_wrap
    )]
    fn transfer_from_disk(
        &self,
        memory: &mut [(Range<u64>, Vec<u8>)],
        pa: u64,
        disk_address: usize,
        length: usize,
    ) {
        dma_slice(memory, pa, length)
            .expect("transfer_from_disk() reaches outside memory")
            .copy_from_slice(&self.contents[disk_address..disk_address + length]);
    }

    /// Fast path of transferring the data from memory to disk.
    #[allow(
        clippy::cast_possible_truncation,
        clippy::expect_used,
        clippy::cast_possible_wrap
    )]
    fn transfer_to_disk(
        &mut self,
        memory: &mut [(Range<u64>, Vec<u8>)],
        pa: u64,
        disk_address: usize,
        length: usize,
    ) {
        self.contents[disk_address..disk_address + length].copy_from_slice(
            dma_slice(memory, pa, length).expect("transfer_to_disk() reaches outside memory"),
        );
    }

    const fn get_page_address(&self) -> u64 { self.queue_pfn as u64 * self.guest_page_size as u64 }

    const fn get_base_desc_address(&self) -> u64 { self.get_page_address() }

    fn get_base_avail_address(&self) -> u64 {
        self.get_base_desc_address() + u64::from(self.queue_size) * 16
    }

    fn get_base_used_address(&self) -> u64 {
        let align = u64::from(self.queue_align);
        let queue_size = u64::from(self.queue_size);
        (self.get_base_avail_address() + 4 + queue_size * 2).div_ceil(align) * align
    }

    // @TODO: Follow the virtio block specification more propertly.
    #[allow(clippy::cast_possible_truncation)]
    fn handle_disk_access(&mut self, memory: &mut [(Range<u64>, Vec<u8>)]) {
        let base_desc_address = self.get_base_desc_address();
        let base_avail_address = self.get_base_avail_address();
        let base_used_address = self.get_base_used_address();
        let queue_size = u64::from(self.queue_size);

        let _avail_flag = u64::from(dma_read_u16(memory, base_avail_address));
        let _avail_index = u64::from(dma_read_u16(memory, base_avail_address.wrapping_add(2)));
        let desc_index_address = base_avail_address
            .wrapping_add(4)
            .wrapping_add((u64::from(self.used_ring_index) % queue_size) * 2);
        let desc_head_index = u64::from(dma_read_u16(memory, desc_index_address)) % queue_size;

        let mut _blk_type = 0;
        let mut _blk_reserved = 0;
        let mut blk_sector = 0;
        let mut desc_num = 0;
        let mut desc_next = desc_head_index;
        loop {
            let desc_element_address = base_desc_address + 16 * desc_next;
            let desc_addr = dma_read_u64(memory, desc_element_address);
            let desc_len = dma_read_u32(memory, desc_element_address.wrapping_add(8));
            let desc_flags = dma_read_u16(memory, desc_element_address.wrapping_add(12));
            desc_next =
                u64::from(dma_read_u16(memory, desc_element_address.wrapping_add(14))) % queue_size;

            match desc_num {
                0 => {
                    _blk_type = dma_read_u32(memory, desc_addr);
                    _blk_reserved = dma_read_u32(memory, desc_addr.wrapping_add(4));
                    blk_sector = dma_read_u64(memory, desc_addr.wrapping_add(8)) as usize;
                }
                1 => {
                    // Second descriptor: Read/Write disk
                    if desc_flags & VIRTQ_DESC_F_WRITE == 0 {
                        // write to disk
                        self.transfer_to_disk(
                            memory,
                            desc_addr,
                            blk_sector * SECTOR_SIZE,
                            desc_len as usize,
                        );
                    } else {
                        // read from disk
                        self.transfer_from_disk(
                            memory,
                            desc_addr,
                            blk_sector * SECTOR_SIZE,
                            desc_len as usize,
                        );
                    }
                }
                2 => {
                    // Third descriptor: Result status
                    assert!(
                        desc_flags & VIRTQ_DESC_F_WRITE != 0,
                        "Third descriptor should be write."
                    );
                    assert!(desc_len == 1, "Third descriptor length should be one.");
                    if !dma_write_u8(memory, desc_addr, 0) {
                        println!(
                            "VirtioBlockDisk tries to write outside memory, trying to continue"
                        );
                    }
                }
                _ => {}
            }

            desc_num += 1;

            if desc_flags & VIRTQ_DESC_F_NEXT == 0 {
                break;
            }
        }

        assert!(desc_num == 3, "Descript chain length should be three.");

        let used_elem_addr = base_used_address
            .wrapping_add(4)
            .wrapping_add((u64::from(self.used_ring_index) % queue_size) * 8);
        if let Some(s) = dma_slice(memory, used_elem_addr, 4) {
            s.copy_from_slice(&(desc_head_index as u32).to_le_bytes());
        } else {
            println!("VirtioBlockDisk tries to write outside memory, trying to continue");
        }

        self.used_ring_index = self.used_ring_index.wrapping_add(1);
        let used_idx_addr = base_used_address.wrapping_add(2);
        if let Some(s) = dma_slice(memory, used_idx_addr, 2) {
            s.copy_from_slice(&self.used_ring_index.to_le_bytes());
        } else {
            println!("VirtioBlockDisk tries to write outside memory, trying to continue");
        }
    }
}

impl MemoryMapped for VirtioBlockDisk {
    fn read(
        &mut self,
        _ctx: &mut Context,
        _base: u64,
        offset: usize,
        size: usize,
        data: &mut [u8],
    ) {
        for (i, slot) in data[..size].iter_mut().enumerate() {
            *slot = self.load((offset + i) as u64);
        }
    }

    fn write(&mut self, _ctx: &mut Context, _base: u64, offset: usize, size: usize, data: &[u8]) {
        for (i, &byte) in data[..size].iter().enumerate() {
            self.store((offset + i) as u64, byte);
        }
    }

    fn service(&mut self, ctx: &mut Context, memory: &mut [(Range<u64>, Vec<u8>)]) {
        if let Some(irq) = self.service_disk(memory) {
            ctx.asserted_irq = Some(irq);
        }
        ctx.next_service_in = Some(1);
    }

    fn save_state(&self, w: &mut Pack) {
        w.u16(self.used_ring_index);
        w.u64(self.device_features);
        w.u32(self.device_features_sel);
        w.u64(self.driver_features);
        w.u32(self.queue_select);
        w.u32(self.queue_size);
        w.u32(self.queue_align);
        w.u32(self.queue_pfn);
        w.u32(self.guest_page_size);
        w.u32(self.queue_notify);
        w.u32(self.interrupt_status);
        w.u32(self.status);
        w.u32(self.block_size);
        w.bool(self.writeback);
        w.bytes(&self.contents);
        w.u32(self.pending_requests);
        w.u32(self.irq);
    }

    fn restore_state(&mut self, r: &mut Unpack) -> Result<(), ()> {
        self.used_ring_index = r.u16()?;
        self.device_features = r.u64()?;
        self.device_features_sel = r.u32()?;
        self.driver_features = r.u64()?;
        self.queue_select = r.u32()?;
        self.queue_size = r.u32()?;
        self.queue_align = r.u32()?;
        self.queue_pfn = r.u32()?;
        self.guest_page_size = r.u32()?;
        self.queue_notify = r.u32()?;
        self.interrupt_status = r.u32()?;
        self.status = r.u32()?;
        self.block_size = r.u32()?;
        self.writeback = r.bool()?;
        self.contents = r.bytes()?;
        self.pending_requests = r.u32()?;
        self.irq = r.u32()?;
        Ok(())
    }

    fn info(&self) -> MemoryMappedInfo {
        MemoryMappedInfo {
            name: "VirtIO Block".to_string(),
        }
    }
}
