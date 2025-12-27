#![allow(clippy::unreadable_literal)]

use crate::mmu::Memory;

// Based on Virtual I/O Device (VIRTIO) Version 1.1
// https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html

// 0x2000 is an arbitary number.
const MAX_QUEUE_SIZE: u64 = 0x2000;

// To simulate disk access time.
// @TODO: Set more proper number. 500 core cycles may be too short.
const DISK_ACCESS_DELAY: u64 = 500;

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
    used_ring_index: u16,
    cycle: u64,
    device_features: u64,      // read only
    device_features_sel: u32,  // write only
    driver_features: u64,      // write only
    _driver_features_sel: u32, // write only
    guest_page_size: u32,      // write only
    queue_select: u32,         // write only
    queue_size: u32,           // write only
    queue_align: u32,          // write only
    queue_pfn: u32,            // read and write
    queue_notify: u32,         // write only
    interrupt_status: u32,     // read only
    status: u32,               // read and write
    notify_cycles: Vec<u64>,
    contents: Vec<u8>,
    block_size: u32, // Block size in bytes
    writeback: bool, // Cache mode (true = writeback, false = writethrough)
}

impl Default for VirtioBlockDisk {
    fn default() -> Self { Self::new() }
}

impl VirtioBlockDisk {
    /// Creates a new `VirtioBlockDisk`.
    #[allow(clippy::cast_possible_truncation)]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            used_ring_index: 0,
            cycle: 0,
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
            notify_cycles: Vec::new(),
            contents: Vec::new(),
            block_size: DEFAULT_BLOCK_SIZE,
            writeback: false,
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

    /// Runs one cycle. Data transfer between main memory and block device
    /// can happen depending on condition.
    ///
    /// # Arguments
    /// * `memory`
    pub fn service(&mut self, memory: &mut Memory, cycle: u64) {
        self.cycle = cycle;
        if !self.notify_cycles.is_empty() && self.cycle >= self.notify_cycles[0] + DISK_ACCESS_DELAY
        {
            // bit 0 in interrupt_status register indicates
            // the interrupt was asserted because the device has used a buffer
            // in at least one of the active virtual queues.
            self.interrupt_status |= 1;
            self.handle_disk_access(memory);
            self.notify_cycles.remove(0);
        }
    }

    /// Loads register content
    ///
    /// # Arguments
    /// * `address`
    #[allow(clippy::match_same_arms, clippy::cast_possible_truncation)]
    pub fn load(&mut self, address: u64) -> u8 {
        match address {
            // Magic number: 0x74726976
            0x10001000 => 0x76,
            0x10001001 => 0x69,
            0x10001002 => 0x72,
            0x10001003 => 0x74,
            // Device version: 1 (Legacy device)
            0x10001004 => 1,
            // Virtio Subsystem Device id: 2 (Block device)
            0x10001008 => 2,
            // Virtio Subsystem Vendor id: 0x554d4551
            0x1000100c => 0x51,
            0x1000100d => 0x45,
            0x1000100e => 0x4d,
            0x1000100f => 0x55,
            // Flags representing features the device supports
            0x10001010 => ((self.device_features >> (self.device_features_sel * 32)) & 0xff) as u8,
            0x10001011 => {
                (((self.device_features >> (self.device_features_sel * 32)) >> 8) & 0xff) as u8
            }
            0x10001012 => {
                (((self.device_features >> (self.device_features_sel * 32)) >> 16) & 0xff) as u8
            }
            0x10001013 => {
                (((self.device_features >> (self.device_features_sel * 32)) >> 24) & 0xff) as u8
            }
            // Maximum virtual queue size
            0x10001034 => MAX_QUEUE_SIZE as u8,
            0x10001035 => (MAX_QUEUE_SIZE >> 8) as u8,
            0x10001036 => (MAX_QUEUE_SIZE >> 16) as u8,
            0x10001037 => (MAX_QUEUE_SIZE >> 24) as u8,
            // Guest physical page number of the virtual queue
            0x10001040 => self.queue_pfn as u8,
            0x10001041 => (self.queue_pfn >> 8) as u8,
            0x10001042 => (self.queue_pfn >> 16) as u8,
            0x10001043 => (self.queue_pfn >> 24) as u8,
            // Interrupt status
            0x10001060 => self.interrupt_status as u8,
            0x10001061 => (self.interrupt_status >> 8) as u8,
            0x10001062 => (self.interrupt_status >> 16) as u8,
            0x10001063 => (self.interrupt_status >> 24) as u8,
            // Device status
            0x10001070 => self.status as u8,
            0x10001071 => (self.status >> 8) as u8,
            0x10001072 => (self.status >> 16) as u8,
            0x10001073 => (self.status >> 24) as u8,
            // Configurations
            0x10001100..=0x10001107 => {
                let n_secs: u64 = self.contents.len() as u64 / u64::from(self.block_size);
                let n_secs_as_u8: [u8; 8] = n_secs.to_le_bytes();
                n_secs_as_u8[address as usize & 7]
            }
            // Block size configuration
            0x10001108..=0x1000110B => {
                let block_size_as_u8: [u8; 4] = self.block_size.to_le_bytes();
                block_size_as_u8[address as usize & 3]
            }
            // Topology configuration
            0x1000110C..=0x10001113 => {
                // Optimal I/O alignment in sectors
                let alignment: u64 = 1; // Default to 1 sector alignment
                let alignment_as_u8: [u8; 8] = alignment.to_le_bytes();
                alignment_as_u8[address as usize & 7]
            }
            // Writeback configuration
            0x10001114 => u8::from(self.writeback),
            _ => 0,
        }
    }

    /// Stores register content
    ///
    /// # Arguments
    /// * `address`
    /// * `value`
    /// # Panics
    /// Will panic if multi queue are attempted enabled (XXX should probably
    /// just ignore)
    #[allow(clippy::cast_lossless, clippy::too_many_lines)]
    pub fn store(&mut self, address: u64, value: u8) {
        match address {
            0x10001014 => {
                self.device_features_sel = (self.device_features_sel & !0xff) | (value as u32);
            }
            0x10001015 => {
                self.device_features_sel =
                    (self.device_features_sel & !(0xff << 8)) | ((value as u32) << 8);
            }
            0x10001016 => {
                self.device_features_sel =
                    (self.device_features_sel & !(0xff << 16)) | ((value as u32) << 16);
            }
            0x10001017 => {
                self.device_features_sel =
                    (self.device_features_sel & !(0xff << 24)) | ((value as u32) << 24);
            }
            0x10001020 => {
                self.driver_features = (self.driver_features & !0xff) | (value as u64);
            }
            0x10001021 => {
                self.driver_features =
                    (self.driver_features & !(0xff << 8)) | ((value as u64) << 8);
            }
            0x10001022 => {
                self.driver_features =
                    (self.driver_features & !(0xff << 16)) | ((value as u64) << 16);
            }
            0x10001023 => {
                self.driver_features =
                    (self.driver_features & !(0xff << 24)) | ((value as u64) << 24);
            }
            0x10001024 => {
                self.driver_features =
                    (self.driver_features & !(0xff << 32)) | ((value as u64) << 32);
            }
            0x10001025 => {
                self.driver_features =
                    (self.driver_features & !(0xff << 40)) | ((value as u64) << 40);
            }
            0x10001026 => {
                self.driver_features =
                    (self.driver_features & !(0xff << 48)) | ((value as u64) << 48);
            }
            0x10001027 => {
                self.driver_features =
                    (self.driver_features & !(0xff << 56)) | ((value as u64) << 56);
            }
            0x10001028 => {
                self.guest_page_size = (self.guest_page_size & !0xff) | (value as u32);
            }
            0x10001029 => {
                self.guest_page_size =
                    (self.guest_page_size & !(0xff << 8)) | ((value as u32) << 8);
            }
            0x1000102a => {
                self.guest_page_size =
                    (self.guest_page_size & !(0xff << 16)) | ((value as u32) << 16);
            }
            0x1000102b => {
                self.guest_page_size =
                    (self.guest_page_size & !(0xff << 24)) | ((value as u32) << 24);
            }
            0x10001030 => {
                self.queue_select = (self.queue_select & !0xff) | (value as u32);
            }
            0x10001031 => {
                self.queue_select = (self.queue_select & !(0xff << 8)) | ((value as u32) << 8);
            }
            0x10001032 => {
                self.queue_select = (self.queue_select & !(0xff << 16)) | ((value as u32) << 16);
            }
            0x10001033 => {
                self.queue_select = (self.queue_select & !(0xff << 24)) | ((value as u32) << 24);
                assert!(
                    self.queue_select == 0,
                    "Virtio: No multi queue support yet."
                );
            }
            0x10001038 => {
                self.queue_size = (self.queue_size & !0xff) | (value as u32);
            }
            0x10001039 => {
                self.queue_size = (self.queue_size & !(0xff << 8)) | ((value as u32) << 8);
            }
            0x1000103a => {
                self.queue_size = (self.queue_size & !(0xff << 16)) | ((value as u32) << 16);
            }
            0x1000103b => {
                self.queue_size = (self.queue_size & !(0xff << 24)) | ((value as u32) << 24);
            }
            0x1000103c => {
                self.queue_align = (self.queue_align & !0xff) | (value as u32);
            }
            0x1000103d => {
                self.queue_align = (self.queue_align & !(0xff << 8)) | ((value as u32) << 8);
            }
            0x1000103e => {
                self.queue_align = (self.queue_align & !(0xff << 16)) | ((value as u32) << 16);
            }
            0x1000103f => {
                self.queue_align = (self.queue_align & !(0xff << 24)) | ((value as u32) << 24);
            }
            0x10001040 => {
                self.queue_pfn = (self.queue_pfn & !0xff) | (value as u32);
            }
            0x10001041 => {
                self.queue_pfn = (self.queue_pfn & !(0xff << 8)) | ((value as u32) << 8);
            }
            0x10001042 => {
                self.queue_pfn = (self.queue_pfn & !(0xff << 16)) | ((value as u32) << 16);
            }
            0x10001043 => {
                self.queue_pfn = (self.queue_pfn & !(0xff << 24)) | ((value as u32) << 24);
            }
            // @TODO: Queue request support
            0x10001050 => {
                self.queue_notify = (self.queue_notify & !0xff) | (value as u32);
            }
            0x10001051 => {
                self.queue_notify = (self.queue_notify & !(0xff << 8)) | ((value as u32) << 8);
            }
            0x10001052 => {
                self.queue_notify = (self.queue_notify & !(0xff << 16)) | ((value as u32) << 16);
            }
            0x10001053 => {
                self.queue_notify = (self.queue_notify & !(0xff << 24)) | ((value as u32) << 24);
                self.notify_cycles.push(self.cycle);
            }
            0x10001064 => {
                // interrupt ack
                if value & 1 == 1 {
                    self.interrupt_status &= !1;
                } else {
                    panic!("Unknown ack {value:X}");
                }
            }
            0x10001070 => {
                self.status = (self.status & !0xff) | (value as u32);
            }
            0x10001071 => {
                self.status = (self.status & !(0xff << 8)) | ((value as u32) << 8);
            }
            0x10001072 => {
                self.status = (self.status & !(0xff << 16)) | ((value as u32) << 16);
            }
            0x10001073 => {
                self.status = (self.status & !(0xff << 24)) | ((value as u32) << 24);
            }
            0x10001114 => {
                if (self.driver_features & (1 << VIRTIO_BLK_F_CONFIG_WCE)) != 0 {
                    self.writeback = value != 0;
                }
            }
            _ => {}
        }
    }

    /// Fast path of transferring the data from disk to memory.
    ///
    /// # Arguments
    /// * `memory`
    /// * `mem_addresss` Physical address. Must be eight-byte aligned.
    /// * `disk_address` Must be eight-byte aligned.
    /// * `length` Must be eight-byte aligned.
    /// # Panics
    /// This will panic if the `disk_address` isn't reasonable
    #[allow(
        clippy::cast_possible_truncation,
        clippy::expect_used,
        clippy::cast_possible_wrap
    )]
    fn transfer_from_disk(&self, memory: &mut Memory, pa: u64, disk_address: usize, length: usize) {
        memory
            .slice(pa as i64, length)
            .expect("transfer_from_disk() reaches outside memory")
            .copy_from_slice(&self.contents[disk_address..disk_address + length]);
    }

    /// Fast path of transferring the data from memory to disk.
    ///
    /// # Arguments
    /// * `memory`
    /// * `mem_addresss` Physical address. Must be eight-byte aligned.
    /// * `disk_address` Must be eight-byte aligned.
    /// * `length` Must be eight-byte aligned.
    /// #
    #[allow(
        clippy::cast_possible_truncation,
        clippy::expect_used,
        clippy::cast_possible_wrap
    )]
    fn transfer_to_disk(
        &mut self,
        memory: &mut Memory,
        pa: u64,
        disk_address: usize,
        length: usize,
    ) {
        self.contents[disk_address..disk_address + length].copy_from_slice(
            memory
                .slice(pa as i64, length)
                .expect("transfer_to_disk() reaches outside memory"),
        );
    }

    const fn get_page_address(&self) -> u64 { self.queue_pfn as u64 * self.guest_page_size as u64 }

    // Virtqueue layout: Starting at page address
    //
    // struct virtq {
    //   struct virtq_desc desc[queue_size]; // queue_size * 16bytes
    //   struct virtq_avail avail;           // 2 * 2bytes + queue_size * 2bytes
    //   uint8 pad[padding];                 // until queue_align
    //   struct virtq_used used;             // 2 * 2bytes + queue_size * 8bytes
    // }
    //
    // struct virtq_desc {
    //   uint64 addr;
    //   uint32 len;
    //   uint16 flags;
    //   uint16 next;
    // }
    //
    // struct virtq_avail {
    //   uint16 flags;
    //   uint16 idx;
    //   uint16 ring[queue_size];
    // }
    //
    // struct virtq_used {
    //   uint16 flags;
    //   uint16 idx;
    //   struct virtq_used_elem ring[queue_size];
    // }
    //
    // struct virtq_used_elem {
    //   uint32 id;
    //   uint32 len;
    // }

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
    fn handle_disk_access(&mut self, memory: &mut Memory) {
        let base_desc_address = self.get_base_desc_address();
        let base_avail_address = self.get_base_avail_address();
        let base_used_address = self.get_base_used_address();
        let queue_size = u64::from(self.queue_size);

        let _avail_flag = u64::from(memory.read_u16(base_avail_address));
        let _avail_index = u64::from(memory.read_u16(base_avail_address.wrapping_add(2)));
        let desc_index_address = base_avail_address
            .wrapping_add(4)
            .wrapping_add((u64::from(self.used_ring_index) % queue_size) * 2);
        let desc_head_index = u64::from(memory.read_u16(desc_index_address)) % queue_size;

        let mut _blk_type = 0;
        let mut _blk_reserved = 0;
        let mut blk_sector = 0;
        let mut desc_num = 0;
        let mut desc_next = desc_head_index;
        loop {
            let desc_element_address = base_desc_address + 16 * desc_next;
            let desc_addr = memory.read_u64(desc_element_address);
            let desc_len = memory.read_u32(desc_element_address.wrapping_add(8));
            let desc_flags = memory.read_u16(desc_element_address.wrapping_add(12));
            desc_next =
                u64::from(memory.read_u16(desc_element_address.wrapping_add(14))) % queue_size;

            match desc_num {
                0 => {
                    _blk_type = memory.read_u32(desc_addr);
                    _blk_reserved = memory.read_u32(desc_addr.wrapping_add(4));
                    blk_sector = memory.read_u64(desc_addr.wrapping_add(8)) as usize;
                }
                1 => {
                    // Second descriptor: Read/Write disk
                    if (desc_flags & VIRTQ_DESC_F_WRITE) == 0 {
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
                        (desc_flags & VIRTQ_DESC_F_WRITE) != 0,
                        "Third descriptor should be write."
                    );
                    assert!(desc_len == 1, "Third descriptor length should be one.");
                    memory.write_u8(desc_addr, 0).unwrap_or_else(|()| {
                        println!(
                            "VirtioBlockDisk tries to write outside memory, trying to continue"
                        );
                    }); // 0 means succeeded
                }
                _ => {}
            }

            desc_num += 1;

            if (desc_flags & VIRTQ_DESC_F_NEXT) == 0 {
                break;
            }
        }

        assert!(desc_num == 3, "Descript chain length should be three.");

        memory
            .write_u32(
                base_used_address
                    .wrapping_add(4)
                    .wrapping_add((u64::from(self.used_ring_index) % queue_size) * 8),
                desc_head_index as u32,
            )
            .unwrap_or_else(|()| {
                println!("VirtioBlockDisk tries to write outside memory, trying to continue");
            });

        self.used_ring_index = self.used_ring_index.wrapping_add(1);
        memory
            .write_u16(base_used_address.wrapping_add(2), self.used_ring_index)
            .unwrap_or_else(|()| {
                println!("VirtioBlockDisk tries to write outside memory, trying to continue");
            });
    }
}
