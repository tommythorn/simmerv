#![allow(clippy::unreadable_literal)]

use crate::device::Context;
use crate::device::MemoryMapped;
use crate::device::MemoryMappedInfo;
use crate::device::MmioError;
use crate::device::Pack;
use crate::device::Unpack;
use crate::device::dma_read_u16;
use crate::device::dma_read_u32;
use crate::device::dma_read_u64;
use crate::device::dma_slice;
use crate::device::dma_write_u8;
use std::ops::Range;

// ── Backing storage abstraction ──────────────────────────────────────────────

enum DiskStorage {
    Memory(Vec<u8>),
    /// Direct file I/O — reads and writes go straight to the backing file.
    /// The `File` variant is unavailable on WASM where there is no filesystem.
    #[cfg(not(target_arch = "wasm32"))]
    File(std::fs::File),
    /// Base image served from a URL, with local copy-on-write for writes.
    #[cfg(not(target_arch = "wasm32"))]
    Url(crate::device::url_disk::UrlStorage),
}

#[allow(clippy::use_self)]
impl DiskStorage {
    fn sector_count(&self) -> u64 {
        match self {
            DiskStorage::Memory(v) => v.len() as u64 / SECTOR_SIZE as u64,
            #[cfg(not(target_arch = "wasm32"))]
            DiskStorage::File(f) => f.metadata().map_or(0, |m| m.len()) / SECTOR_SIZE as u64,
            #[cfg(not(target_arch = "wasm32"))]
            DiskStorage::Url(u) => u.sector_count(),
        }
    }

    #[allow(clippy::expect_used)]
    fn read_at(&self, offset: u64, buf: &mut [u8]) {
        match self {
            DiskStorage::Memory(v) => {
                let o = offset as usize;
                buf.copy_from_slice(&v[o..o + buf.len()]);
            }
            #[cfg(not(target_arch = "wasm32"))]
            DiskStorage::File(f) => {
                use std::os::unix::fs::FileExt;
                f.read_exact_at(buf, offset).expect("disk read failed");
            }
            #[cfg(not(target_arch = "wasm32"))]
            DiskStorage::Url(u) => u.read_at(offset, buf),
        }
    }

    #[allow(clippy::expect_used)]
    fn write_at(&mut self, offset: u64, data: &[u8]) {
        match self {
            DiskStorage::Memory(v) => {
                let o = offset as usize;
                v[o..o + data.len()].copy_from_slice(data);
            }
            #[cfg(not(target_arch = "wasm32"))]
            DiskStorage::File(f) => {
                use std::os::unix::fs::FileExt;
                f.write_all_at(data, offset).expect("disk write failed");
            }
            #[cfg(not(target_arch = "wasm32"))]
            DiskStorage::Url(u) => u.write_at(offset, data),
        }
    }
}

// Based on Virtual I/O Device (VIRTIO) Version 1.2
// https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html
// Section 4.2: Virtio Over MMIO (modern, Version=2)
// Section 5.2: Block Device

const MAX_QUEUE_SIZE: u32 = 0x100;

const VIRTQ_DESC_F_NEXT: u16 = 1;

// VIRTQ_DESC_F_WRITE: buffer is write-only *from the device's perspective*
// (i.e., the device writes into it — this is a READ from disk operation)
const VIRTQ_DESC_F_WRITE: u16 = 2;

const SECTOR_SIZE: usize = 512;

// VirtIO block device feature bits (section 5.2.3)
const VIRTIO_BLK_F_BLK_SIZE: u32 = 6;
const VIRTIO_BLK_F_TOPOLOGY: u32 = 10;
const VIRTIO_BLK_F_CONFIG_WCE: u32 = 11;

// Common VirtIO feature bits (section 6)
const VIRTIO_F_VERSION_1: u32 = 32;

const DEVICE_FEATURES: u64 = (1_u64 << VIRTIO_F_VERSION_1)
    | (1_u64 << VIRTIO_BLK_F_BLK_SIZE)
    | (1_u64 << VIRTIO_BLK_F_TOPOLOGY)
    | (1_u64 << VIRTIO_BLK_F_CONFIG_WCE);

const DEFAULT_BLOCK_SIZE: u32 = 512;

/// Emulates a `VirtIO` 1.2 (modern) block device over MMIO.
///
/// Register layout follows section 4.2.2 of the `VirtIO` specification.
/// The three virtqueue address registers (desc, driver, device) replace the
/// legacy page-frame-number scheme.
pub struct VirtioBlockDisk {
    pub used_ring_index: u16,

    // Feature negotiation
    pub device_features: u64,
    pub device_features_sel: u32,
    pub driver_features: u64,
    pub driver_features_sel: u32,

    // Queue setup
    pub queue_select: u32,
    pub queue_size: u32,
    pub queue_ready: bool,
    pub queue_desc_addr: u64,   // physical address of descriptor table
    pub queue_driver_addr: u64, // physical address of available ring (driver area)
    pub queue_device_addr: u64, // physical address of used ring (device area)

    pub queue_notify: u32,
    pub interrupt_status: u32,
    pub status: u32,
    /// Number of pending disk requests.
    pub pending_requests: u32,
    storage: DiskStorage,
    pub block_size: u32,
    pub writeback: bool,
    /// IRQ number asserted on the PLIC when interrupting.
    pub irq: u32,
}

impl Default for VirtioBlockDisk {
    fn default() -> Self { Self::new(1) }
}

impl VirtioBlockDisk {
    /// Creates a new disk with empty in-memory storage.
    #[must_use]
    pub const fn new(irq: u32) -> Self {
        Self {
            used_ring_index: 0,
            device_features: DEVICE_FEATURES,
            device_features_sel: 0,
            driver_features: 0,
            driver_features_sel: 0,
            queue_select: 0,
            queue_size: 0,
            queue_ready: false,
            queue_desc_addr: 0,
            queue_driver_addr: 0,
            queue_device_addr: 0,
            queue_notify: 0,
            interrupt_status: 0,
            status: 0,
            pending_requests: 0,
            storage: DiskStorage::Memory(Vec::new()),
            block_size: DEFAULT_BLOCK_SIZE,
            writeback: false,
            irq,
        }
    }

    /// Creates a new disk backed by the given in-memory image.
    #[must_use]
    pub fn new_with_contents(contents: Vec<u8>, irq: u32) -> Self {
        let mut d = Self::new(irq);
        d.storage = DiskStorage::Memory(contents);
        d
    }

    /// Creates a new disk backed by the given file.
    ///
    /// Reads and writes go directly to the file; the image is never copied
    /// into the emulator's heap.
    #[cfg(not(target_arch = "wasm32"))]
    #[must_use]
    pub fn new_with_file(file: std::fs::File, irq: u32) -> Self {
        let mut d = Self::new(irq);
        d.storage = DiskStorage::File(file);
        d
    }

    /// Creates a disk whose base image is served from `url`, with writes kept
    /// in a local copy-on-write overlay (never sent back to the server).
    ///
    /// # Errors
    /// Returns an error if the URL is unusable (bad scheme, compressed image,
    /// no range support, or an unreachable server) — see [`UrlStorage::open`].
    ///
    /// [`UrlStorage::open`]: crate::device::url_disk::UrlStorage::open
    #[cfg(not(target_arch = "wasm32"))]
    pub fn new_with_url(url: &str, irq: u32) -> anyhow::Result<Self> {
        let mut d = Self::new(irq);
        d.storage = DiskStorage::Url(crate::device::url_disk::UrlStorage::open(url)?);
        Ok(d)
    }

    /// Replaces the in-memory image. Expected to be called at most once.
    pub fn init(&mut self, contents: Vec<u8>) {
        if !contents.len().is_multiple_of(SECTOR_SIZE) {
            log::warn!(
                "Contents isn't a multiple of {SECTOR_SIZE}; {}B in last block",
                contents.len() % SECTOR_SIZE
            );
        }
        self.storage = DiskStorage::Memory(contents);
    }

    /// Returns `true` when the device has an asserted interrupt pending.
    #[must_use]
    pub const fn is_interrupting(&self) -> bool { self.interrupt_status & 1 == 1 }

    /// Resets the device to its power-on state (triggered by writing Status=0).
    /// Disk contents and block size are preserved.
    const fn reset(&mut self) {
        self.device_features_sel = 0;
        self.driver_features = 0;
        self.driver_features_sel = 0;
        self.queue_select = 0;
        self.queue_size = 0;
        self.queue_ready = false;
        self.queue_desc_addr = 0;
        self.queue_driver_addr = 0;
        self.queue_device_addr = 0;
        self.queue_notify = 0;
        self.interrupt_status = 0;
        self.used_ring_index = 0;
        self.pending_requests = 0;
    }

    /// Services all pending disk requests and returns `Some(irq)` if the
    /// device should assert an interrupt, `None` otherwise.
    ///
    /// The driver may batch multiple requests into the available ring before
    /// issuing a single `QueueNotify` (this became common in kernel 6.x).
    /// We therefore drain the entire ring up to `avail->idx` on each service
    /// call rather than processing one request per notification.
    pub fn service_disk(&mut self, memory: &mut [(Range<u64>, Vec<u8>)]) -> Option<u32> {
        if self.pending_requests > 0 {
            // avail->idx lives at queue_driver_addr + 2 (u16, wrapping counter).
            let avail_idx = dma_read_u16(memory, self.queue_driver_addr.wrapping_add(2));
            while self.used_ring_index != avail_idx {
                self.handle_disk_access(memory);
            }
            self.interrupt_status |= 1;
            self.pending_requests = 0;
        }
        if self.is_interrupting() {
            Some(self.irq)
        } else {
            None
        }
    }

    /// Reads a MMIO register byte (offset from `VIRTIO_BASE`).
    ///
    /// Register layout per `VirtIO` 1.2 §4.2.2 (modern, Version=2).
    #[must_use]
    #[allow(
        clippy::match_same_arms,
        clippy::cast_possible_truncation,
        clippy::cast_lossless
    )]
    pub fn load(&self, offset: u64) -> u8 {
        match offset {
            // Magic value: "virt" = 0x74726976
            0x000 => 0x76,
            0x001 => 0x69,
            0x002 => 0x72,
            0x003 => 0x74,
            // Version: 2 (modern)
            0x004 => 2,
            0x005..=0x007 => 0,
            // Device ID: 2 (block device)
            0x008 => 2,
            0x009..=0x00b => 0,
            // Vendor ID: 0x554d4551 ("QEMU")
            0x00c => 0x51,
            0x00d => 0x45,
            0x00e => 0x4d,
            0x00f => 0x55,
            // 0x010: DeviceFeatures (R) — 32-bit page selected by DeviceFeaturesSel
            0x010..=0x013 => {
                let shift = u64::from(self.device_features_sel) * 32 + (offset - 0x010) * 8;
                (self.device_features >> shift) as u8
            }
            // 0x014: DeviceFeaturesSel (W only; reads reserved → 0)
            0x014..=0x017 => 0,
            // 0x034: QueueNumMax
            0x034..=0x037 => (MAX_QUEUE_SIZE >> ((offset - 0x034) * 8)) as u8,
            // 0x044: QueueReady
            0x044 => u8::from(self.queue_ready),
            0x045..=0x047 => 0,
            // 0x060: InterruptStatus
            0x060..=0x063 => (self.interrupt_status >> ((offset - 0x060) * 8)) as u8,
            // 0x070: Status
            0x070..=0x073 => (self.status >> ((offset - 0x070) * 8)) as u8,
            // 0x080: QueueDescLow/High (readable so driver can verify)
            0x080..=0x087 => (self.queue_desc_addr >> ((offset - 0x080) * 8)) as u8,
            // 0x090: QueueDriverLow/High
            0x090..=0x097 => (self.queue_driver_addr >> ((offset - 0x090) * 8)) as u8,
            // 0x0a0: QueueDeviceLow/High
            0x0a0..=0x0a7 => (self.queue_device_addr >> ((offset - 0x0a0) * 8)) as u8,
            // 0x0fc: ConfigGeneration (we never change config during operation)
            0x0fc..=0x0ff => 0,

            // ── Config space (§5.2.4) ──────────────────────────────────────
            // offset  size  field              feature
            // 0x000      8  capacity (sectors) always
            // 0x008      4  size_max           SIZE_MAX (not advertised)
            // 0x00c      4  seg_max            SEG_MAX  (not advertised)
            // 0x010      4  geometry           GEOMETRY (not advertised)
            // 0x014      4  blk_size           BLK_SIZE
            // 0x018      1  physical_block_exp TOPOLOGY
            // 0x019      1  alignment_offset   TOPOLOGY
            // 0x01a      2  min_io_size        TOPOLOGY
            // 0x01c      4  opt_io_size        TOPOLOGY
            // 0x020      1  writeback          CONFIG_WCE
            0x100..=0x107 => {
                let n_secs = self.storage.sector_count();
                (n_secs >> ((offset - 0x100) * 8)) as u8
            }
            0x108..=0x10b => 0, // size_max  (not advertised)
            0x10c..=0x10f => 0, // seg_max   (not advertised)
            0x110..=0x113 => 0, // geometry  (not advertised)
            0x114..=0x117 => (self.block_size >> ((offset - 0x114) * 8)) as u8,
            0x118..=0x11f => 0, // topology fields: default zeros (1-sector alignment)
            0x120 => u8::from(self.writeback),
            _ => 0,
        }
    }

    /// Writes a MMIO register byte (offset from `VIRTIO_BASE`).
    #[allow(clippy::cast_lossless, clippy::too_many_lines)]
    pub const fn store(&mut self, offset: u64, value: u8) {
        match offset {
            // 0x014: DeviceFeaturesSel (W)
            0x014..=0x017 => {
                let shift = (offset - 0x014) * 8;
                self.device_features_sel =
                    (self.device_features_sel & !(0xff << shift)) | ((value as u32) << shift);
            }
            // 0x020: DriverFeatures (W) — 32-bit page selected by DriverFeaturesSel
            0x020..=0x023 => {
                let shift = self.driver_features_sel as u64 * 32 + (offset - 0x020) * 8;
                self.driver_features =
                    (self.driver_features & !(0xff_u64 << shift)) | ((value as u64) << shift);
            }
            // 0x024: DriverFeaturesSel (W)
            0x024..=0x027 => {
                let shift = (offset - 0x024) * 8;
                self.driver_features_sel =
                    (self.driver_features_sel & !(0xff << shift)) | ((value as u32) << shift);
            }
            // 0x030: QueueSel (W) — only queue 0 supported
            0x030..=0x033 => {
                let shift = (offset - 0x030) * 8;
                self.queue_select =
                    (self.queue_select & !(0xff << shift)) | ((value as u32) << shift);
            }
            // 0x038: QueueNum (W)
            0x038..=0x03b => {
                let shift = (offset - 0x038) * 8;
                self.queue_size = (self.queue_size & !(0xff << shift)) | ((value as u32) << shift);
            }
            // 0x044: QueueReady (W) — driver sets 1 when queue is configured
            0x044 => self.queue_ready = value != 0,
            // 0x050: QueueNotify (W) — writing triggers a request
            0x050..=0x052 => {
                let shift = (offset - 0x050) * 8;
                self.queue_notify =
                    (self.queue_notify & !(0xff << shift)) | ((value as u32) << shift);
            }
            0x053 => {
                self.queue_notify = (self.queue_notify & !(0xff << 24)) | ((value as u32) << 24);
                if self.queue_ready {
                    self.pending_requests += 1;
                }
            }
            // 0x064: InterruptACK (W) — driver clears asserted interrupt bits
            0x064 => self.interrupt_status &= !(value as u32),
            // 0x070: Status (R/W) — writing 0 resets the device
            0x070..=0x073 => {
                let shift = (offset - 0x070) * 8;
                self.status = (self.status & !(0xff << shift)) | ((value as u32) << shift);
                if self.status == 0 {
                    self.reset();
                }
            }
            // 0x080: QueueDescLow/High (W)
            0x080..=0x087 => {
                let shift = (offset - 0x080) * 8;
                self.queue_desc_addr =
                    (self.queue_desc_addr & !(0xff_u64 << shift)) | ((value as u64) << shift);
            }
            // 0x090: QueueDriverLow/High (W)
            0x090..=0x097 => {
                let shift = (offset - 0x090) * 8;
                self.queue_driver_addr =
                    (self.queue_driver_addr & !(0xff_u64 << shift)) | ((value as u64) << shift);
            }
            // 0x0a0: QueueDeviceLow/High (W)
            0x0a0..=0x0a7 => {
                let shift = (offset - 0x0a0) * 8;
                self.queue_device_addr =
                    (self.queue_device_addr & !(0xff_u64 << shift)) | ((value as u64) << shift);
            }
            // 0x120: writeback (W) — CONFIG_WCE feature
            0x120 if self.driver_features & (1_u64 << VIRTIO_BLK_F_CONFIG_WCE) != 0 => {
                self.writeback = value != 0;
            }
            _ => {}
        }
    }

    // ── Disk transfer helpers ──────────────────────────────────────────────

    #[allow(clippy::expect_used)]
    fn transfer_from_disk(
        &self,
        memory: &mut [(Range<u64>, Vec<u8>)],
        pa: u64,
        disk_address: usize,
        length: usize,
    ) {
        let buf = dma_slice(memory, pa, length).expect("transfer_from_disk: address outside RAM");
        self.storage.read_at(disk_address as u64, buf);
    }

    #[allow(clippy::expect_used)]
    fn transfer_to_disk(
        &mut self,
        memory: &mut [(Range<u64>, Vec<u8>)],
        pa: u64,
        disk_address: usize,
        length: usize,
    ) {
        let data = dma_slice(memory, pa, length).expect("transfer_to_disk: address outside RAM");
        // SAFETY: we need to read from `data` (RAM slice) and write to storage.
        // We can't hold a RAM borrow and a storage borrow simultaneously when
        // storage is Memory(Vec) backed by the same allocation, but in practice
        // disk sectors and guest RAM are always different regions.
        let data: Vec<u8> = data.to_vec();
        self.storage.write_at(disk_address as u64, &data);
    }

    // ── Virtqueue processing ───────────────────────────────────────────────
    //
    // Virtqueue layout (§2.7, same for legacy and modern):
    //
    //   Descriptor table  @ queue_desc_addr   — queue_size × 16 B entries
    //   Available ring    @ queue_driver_addr — driver → device notifications
    //   Used ring         @ queue_device_addr — device → driver completions
    //
    // struct virtq_desc   { addr:u64, len:u32, flags:u16, next:u16 }
    // struct virtq_avail  { flags:u16, idx:u16, ring[queue_size]:u16, … }
    // struct virtq_used   { flags:u16, idx:u16, ring[queue_size]:virtq_used_elem, …
    // } struct virtq_used_elem { id:u32, len:u32 }
    //
    // Block request descriptor chain (§5.2.6):
    //   desc[0]  header  { type:u32, reserved:u32, sector:u64 }  RO
    //   desc[1]  data    buffer                                   RO or WO
    //   desc[2]  status  { status:u8 }                           WO
    #[allow(clippy::cast_possible_truncation)]
    fn handle_disk_access(&mut self, memory: &mut [(Range<u64>, Vec<u8>)]) {
        let base_desc_addr = self.queue_desc_addr;
        let base_avail_addr = self.queue_driver_addr;
        let base_used_addr = self.queue_device_addr;
        let queue_size = u64::from(self.queue_size);

        // Read the next available ring entry.
        let avail_ring_idx = u64::from(self.used_ring_index) % queue_size;
        let desc_index_addr = base_avail_addr
            .wrapping_add(4)
            .wrapping_add(avail_ring_idx * 2);
        let desc_head_index = u64::from(dma_read_u16(memory, desc_index_addr)) % queue_size;

        // Walk the descriptor chain (expected length: 3).
        let mut blk_sector: usize = 0;
        let mut desc_num = 0u32;
        let mut desc_next = desc_head_index;

        loop {
            let desc_elem_addr = base_desc_addr.wrapping_add(16 * desc_next);
            let desc_addr = dma_read_u64(memory, desc_elem_addr);
            let desc_len = dma_read_u32(memory, desc_elem_addr.wrapping_add(8));
            let desc_flags = dma_read_u16(memory, desc_elem_addr.wrapping_add(12));
            desc_next =
                u64::from(dma_read_u16(memory, desc_elem_addr.wrapping_add(14))) % queue_size;

            match desc_num {
                0 => {
                    // Request header: type(u32) + reserved(u32) + sector(u64)
                    let _blk_type = dma_read_u32(memory, desc_addr);
                    blk_sector = dma_read_u64(memory, desc_addr.wrapping_add(8)) as usize;
                }
                1 => {
                    // Data buffer: WRITE flag means device writes here (read from disk).
                    if desc_flags & VIRTQ_DESC_F_WRITE != 0 {
                        self.transfer_from_disk(
                            memory,
                            desc_addr,
                            blk_sector * SECTOR_SIZE,
                            desc_len as usize,
                        );
                    } else {
                        self.transfer_to_disk(
                            memory,
                            desc_addr,
                            blk_sector * SECTOR_SIZE,
                            desc_len as usize,
                        );
                    }
                }
                2 => {
                    // Status byte: 0 = VIRTIO_BLK_S_OK
                    assert!(
                        desc_flags & VIRTQ_DESC_F_WRITE != 0,
                        "VirtIO: status descriptor must be device-writable"
                    );
                    assert!(desc_len == 1, "VirtIO: status descriptor length must be 1");
                    if !dma_write_u8(memory, desc_addr, 0) {
                        log::warn!("VirtIO: status write outside RAM — continuing");
                    }
                }
                _ => {}
            }

            desc_num += 1;
            if desc_flags & VIRTQ_DESC_F_NEXT == 0 {
                break;
            }
        }

        assert!(
            desc_num == 3,
            "VirtIO: expected 3-descriptor chain, got {desc_num}"
        );

        // Update the used ring.
        let used_elem_addr = base_used_addr
            .wrapping_add(4)
            .wrapping_add((u64::from(self.used_ring_index) % queue_size) * 8);
        if let Some(s) = dma_slice(memory, used_elem_addr, 4) {
            s.copy_from_slice(&(desc_head_index as u32).to_le_bytes());
        } else {
            log::warn!("VirtIO: used-ring write outside RAM — continuing");
        }

        self.used_ring_index = self.used_ring_index.wrapping_add(1);

        let used_idx_addr = base_used_addr.wrapping_add(2);
        if let Some(s) = dma_slice(memory, used_idx_addr, 2) {
            s.copy_from_slice(&self.used_ring_index.to_le_bytes());
        } else {
            log::warn!("VirtIO: used-idx write outside RAM — continuing");
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
    ) -> Result<(), MmioError> {
        for (i, slot) in data[..size].iter_mut().enumerate() {
            *slot = self.load((offset + i) as u64);
        }
        Ok(())
    }

    fn write(
        &mut self,
        _ctx: &mut Context,
        _base: u64,
        offset: usize,
        size: usize,
        data: &[u8],
    ) -> Result<(), MmioError> {
        for (i, &byte) in data[..size].iter().enumerate() {
            self.store((offset + i) as u64, byte);
        }
        Ok(())
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
        w.u32(self.driver_features_sel);
        w.u32(self.queue_select);
        w.u32(self.queue_size);
        w.bool(self.queue_ready);
        w.u64(self.queue_desc_addr);
        w.u64(self.queue_driver_addr);
        w.u64(self.queue_device_addr);
        w.u32(self.queue_notify);
        w.u32(self.interrupt_status);
        w.u32(self.status);
        w.u32(self.block_size);
        w.bool(self.writeback);
        // File- and URL-backed storage write a zero-length sentinel: the base
        // image lives outside the snapshot (in the file, or at the URL), so it
        // is not embedded here. A URL disk's copy-on-write overlay is likewise
        // not captured — restoring yields an empty in-memory disk, matching the
        // file-backed behavior.
        match &self.storage {
            DiskStorage::Memory(v) => w.bytes(v),
            #[cfg(not(target_arch = "wasm32"))]
            DiskStorage::File(_) | DiskStorage::Url(_) => w.u64(0),
        }
        w.u32(self.pending_requests);
        w.u32(self.irq);
    }

    fn restore_state(&mut self, r: &mut Unpack) -> Result<(), ()> {
        self.used_ring_index = r.u16()?;
        self.device_features = r.u64()?;
        self.device_features_sel = r.u32()?;
        self.driver_features = r.u64()?;
        self.driver_features_sel = r.u32()?;
        self.queue_select = r.u32()?;
        self.queue_size = r.u32()?;
        self.queue_ready = r.bool()?;
        self.queue_desc_addr = r.u64()?;
        self.queue_driver_addr = r.u64()?;
        self.queue_device_addr = r.u64()?;
        self.queue_notify = r.u32()?;
        self.interrupt_status = r.u32()?;
        self.status = r.u32()?;
        self.block_size = r.u32()?;
        self.writeback = r.bool()?;
        let n = r.u64()? as usize;
        if n > 0 {
            self.storage = DiskStorage::Memory(r.raw(n)?.to_vec());
        }
        // else: zero sentinel — leave existing storage (file-backed or empty) in place.
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
