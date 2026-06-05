#![allow(clippy::unreadable_literal)]

use crate::device::Context;
use crate::device::MemoryMapped;
use crate::device::MemoryMappedInfo;
use crate::device::MmioError;
use crate::device::Pack;
use crate::device::Unpack;
use crate::device::dma_read_u16;
use crate::device::dma_read_u64;
use crate::device::dma_slice;
use crate::device::read_u32;
use crate::device::read_u64;
use crate::device::write_u32;
use crate::device::write_u64;
use crate::network_backend::DummyNetworkBackend;
use crate::network_backend::NetworkBackend;
use log::debug;
use std::ops::Range;

// VirtIO 1.2 §5.1 — Network Device (Device ID = 1)
// Two virtqueues: receiveq (0) and transmitq (1)

const RXQ: usize = 0;
const TXQ: usize = 1;
const MAX_QUEUE_SIZE: u32 = 0x100;

const VIRTIO_NET_F_MAC: u32 = 5;
const VIRTIO_NET_F_STATUS: u32 = 16;
const VIRTIO_F_VERSION_1: u32 = 32;

const DEVICE_FEATURES: u64 =
    (1_u64 << VIRTIO_F_VERSION_1) | (1_u64 << VIRTIO_NET_F_MAC) | (1_u64 << VIRTIO_NET_F_STATUS);

/// Size of `virtio_net_hdr_v1` (used when `VIRTIO_F_VERSION_1` is negotiated).
/// Adds `num_buffers` (2 bytes) over the base 10-byte header.
const NET_HDR_LEN: usize = 12;

/// `VIRTIO_NET_S_LINK_UP`
const LINK_UP: u16 = 1;

const DEFAULT_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

fn log_packet(dir: &str, pkt: &[u8]) {
    if !log::log_enabled!(log::Level::Debug) || pkt.len() < 14 {
        return;
    }
    let ethertype = u16::from_be_bytes([pkt[12], pkt[13]]);
    match ethertype {
        0x0800 if pkt.len() >= 34 => {
            let proto = pkt[23];
            let src_ip = &pkt[26..30];
            let dst_ip = &pkt[30..34];
            let proto_str = match proto {
                1 => "ICMP",
                6 => "TCP",
                17 => "UDP",
                _ => "?",
            };
            if proto == 17 && pkt.len() >= 42 {
                let src_port = u16::from_be_bytes([pkt[34], pkt[35]]);
                let dst_port = u16::from_be_bytes([pkt[36], pkt[37]]);
                debug!(
                    "virtio-net: {dir} {} bytes IPv4/{proto_str} {}.{}.{}.{}:{src_port} → \
                     {}.{}.{}.{}:{dst_port}",
                    pkt.len(),
                    src_ip[0],
                    src_ip[1],
                    src_ip[2],
                    src_ip[3],
                    dst_ip[0],
                    dst_ip[1],
                    dst_ip[2],
                    dst_ip[3],
                );
            } else {
                debug!(
                    "virtio-net: {dir} {} bytes IPv4/{proto_str} {}.{}.{}.{} → {}.{}.{}.{}",
                    pkt.len(),
                    src_ip[0],
                    src_ip[1],
                    src_ip[2],
                    src_ip[3],
                    dst_ip[0],
                    dst_ip[1],
                    dst_ip[2],
                    dst_ip[3],
                );
            }
        }
        0x0806 => debug!("virtio-net: {dir} {} bytes ARP", pkt.len()),
        0x86dd => debug!("virtio-net: {dir} {} bytes IPv6", pkt.len()),
        _ => debug!(
            "virtio-net: {dir} {} bytes ethertype={ethertype:#06x}",
            pkt.len()
        ),
    }
}

/// Emulates a `VirtIO` 1.2 (modern) network device over MMIO.
pub struct VirtioNet {
    device_features: u64,
    device_features_sel: u32,
    driver_features: u64,
    driver_features_sel: u32,

    queue_select: u32,
    queue_size: [u32; 2],
    queue_ready: [bool; 2],
    queue_desc_addr: [u64; 2],
    queue_driver_addr: [u64; 2],
    queue_device_addr: [u64; 2],
    used_ring_index: [u16; 2],

    /// Partial accumulation of the 4-byte `QueueNotify` register.
    queue_notify: u32,
    interrupt_status: u32,
    status: u32,
    /// Number of pending TX notifications.
    pending_tx: u32,

    mac: [u8; 6],
    irq: u32,

    backend: Box<dyn NetworkBackend>,
}

impl VirtioNet {
    #[must_use]
    pub fn new(backend: Box<dyn NetworkBackend>, irq: u32) -> Self {
        Self {
            device_features: DEVICE_FEATURES,
            device_features_sel: 0,
            driver_features: 0,
            driver_features_sel: 0,
            queue_select: 0,
            queue_size: [0; 2],
            queue_ready: [false; 2],
            queue_desc_addr: [0; 2],
            queue_driver_addr: [0; 2],
            queue_device_addr: [0; 2],
            used_ring_index: [0; 2],
            queue_notify: 0,
            interrupt_status: 0,
            status: 0,
            pending_tx: 0,
            mac: DEFAULT_MAC,
            irq,
            backend,
        }
    }

    const fn reset(&mut self) {
        self.device_features_sel = 0;
        self.driver_features = 0;
        self.driver_features_sel = 0;
        self.queue_select = 0;
        self.queue_size = [0; 2];
        self.queue_ready = [false; 2];
        self.queue_desc_addr = [0; 2];
        self.queue_driver_addr = [0; 2];
        self.queue_device_addr = [0; 2];
        self.used_ring_index = [0; 2];
        self.queue_notify = 0;
        self.interrupt_status = 0;
        self.pending_tx = 0;
    }

    /// Currently selected queue index, clamped to `[0, 1]`.
    const fn q(&self) -> usize { (self.queue_select & 1) as usize }

    /// Drain the TX queue, sending each frame via the backend.
    ///
    /// Returns `true` if at least one frame was sent (so we should interrupt).
    #[allow(clippy::cast_possible_truncation)]
    fn service_tx(&mut self, memory: &mut [(Range<u64>, Vec<u8>)]) -> bool {
        if !self.queue_ready[TXQ] || self.pending_tx == 0 {
            return false;
        }

        let avail_idx = dma_read_u16(memory, self.queue_driver_addr[TXQ].wrapping_add(2));
        let queue_size = u64::from(self.queue_size[TXQ].max(1));
        let mut did_work = false;

        while self.used_ring_index[TXQ] != avail_idx {
            let avail_ring_idx = u64::from(self.used_ring_index[TXQ]) % queue_size;
            let desc_index_addr = self.queue_driver_addr[TXQ]
                .wrapping_add(4)
                .wrapping_add(avail_ring_idx * 2);
            let desc_head = u64::from(dma_read_u16(memory, desc_index_addr)) % queue_size;

            // Collect the packet: skip the first NET_HDR_LEN bytes (virtio_net_hdr).
            let mut packet: Vec<u8> = Vec::new();
            let mut skipped: usize = 0;
            let mut desc_next = desc_head;
            loop {
                let desc_elem = self.queue_desc_addr[TXQ].wrapping_add(16 * desc_next);
                let buf_addr = dma_read_u64(memory, desc_elem);
                let buf_len = crate::device::dma_read_u32(memory, desc_elem.wrapping_add(8));
                let flags = dma_read_u16(memory, desc_elem.wrapping_add(12));
                desc_next =
                    u64::from(dma_read_u16(memory, desc_elem.wrapping_add(14))) % queue_size;

                let buf_len = buf_len as usize;
                if skipped < NET_HDR_LEN {
                    let hdr_remaining = NET_HDR_LEN - skipped;
                    if buf_len <= hdr_remaining {
                        skipped += buf_len;
                    } else {
                        // Part of this buffer is payload
                        let payload_offset = hdr_remaining;
                        skipped = NET_HDR_LEN;
                        if let Some(s) = dma_slice(
                            memory,
                            buf_addr + payload_offset as u64,
                            buf_len - payload_offset,
                        ) {
                            packet.extend_from_slice(s);
                        }
                    }
                } else if let Some(s) = dma_slice(memory, buf_addr, buf_len) {
                    packet.extend_from_slice(s);
                }

                if flags & VIRTQ_DESC_F_NEXT == 0 {
                    break;
                }
            }

            if !packet.is_empty() {
                log_packet("TX", &packet);
                self.backend.send(&packet);
            }

            // Update used ring
            let used_elem = self.queue_device_addr[TXQ]
                .wrapping_add(4)
                .wrapping_add((u64::from(self.used_ring_index[TXQ]) % queue_size) * 8);
            if let Some(s) = dma_slice(memory, used_elem, 4) {
                s.copy_from_slice(&(desc_head as u32).to_le_bytes());
            }
            self.used_ring_index[TXQ] = self.used_ring_index[TXQ].wrapping_add(1);
            let used_idx_addr = self.queue_device_addr[TXQ].wrapping_add(2);
            if let Some(s) = dma_slice(memory, used_idx_addr, 2) {
                s.copy_from_slice(&self.used_ring_index[TXQ].to_le_bytes());
            }
            did_work = true;
        }

        self.pending_tx = 0;
        did_work
    }

    /// Poll the backend for incoming frames and push them into the RX queue.
    ///
    /// Returns `true` if at least one frame was delivered.
    #[allow(clippy::cast_possible_truncation)]
    fn service_rx(&mut self, memory: &mut [(Range<u64>, Vec<u8>)]) -> bool {
        if !self.queue_ready[RXQ] {
            return false;
        }

        let mut did_work = false;
        while let Some(packet) = self.backend.recv() {
            log_packet("RX", &packet);
            let avail_idx = dma_read_u16(memory, self.queue_driver_addr[RXQ].wrapping_add(2));
            if self.used_ring_index[RXQ] == avail_idx {
                // No RX buffers available — drop packet
                break;
            }

            let queue_size = u64::from(self.queue_size[RXQ].max(1));
            let avail_ring_idx = u64::from(self.used_ring_index[RXQ]) % queue_size;
            let desc_index_addr = self.queue_driver_addr[RXQ]
                .wrapping_add(4)
                .wrapping_add(avail_ring_idx * 2);
            let desc_head = u64::from(dma_read_u16(memory, desc_index_addr)) % queue_size;

            let desc_elem = self.queue_desc_addr[RXQ].wrapping_add(16 * desc_head);
            let buf_addr = dma_read_u64(memory, desc_elem);
            let buf_cap = crate::device::dma_read_u32(memory, desc_elem.wrapping_add(8)) as usize;

            let total = NET_HDR_LEN + packet.len();
            if buf_cap < total {
                // Buffer too small — drop packet and try the next one
                continue;
            }
            // Zero the net header
            if let Some(s) = dma_slice(memory, buf_addr, NET_HDR_LEN) {
                s.fill(0);
            }
            // Copy frame
            if let Some(s) = dma_slice(memory, buf_addr + NET_HDR_LEN as u64, packet.len()) {
                s.copy_from_slice(&packet);
            }

            // Update used ring with bytes written
            let used_elem = self.queue_device_addr[RXQ]
                .wrapping_add(4)
                .wrapping_add((u64::from(self.used_ring_index[RXQ]) % queue_size) * 8);
            if let Some(s) = dma_slice(memory, used_elem, 4) {
                s.copy_from_slice(&(desc_head as u32).to_le_bytes());
            }
            if let Some(s) = dma_slice(memory, used_elem.wrapping_add(4), 4) {
                s.copy_from_slice(&(total as u32).to_le_bytes());
            }
            self.used_ring_index[RXQ] = self.used_ring_index[RXQ].wrapping_add(1);
            let used_idx_addr = self.queue_device_addr[RXQ].wrapping_add(2);
            if let Some(s) = dma_slice(memory, used_idx_addr, 2) {
                s.copy_from_slice(&self.used_ring_index[RXQ].to_le_bytes());
            }
            did_work = true;
        }

        did_work
    }
}

impl MemoryMapped for VirtioNet {
    #[allow(clippy::cast_possible_truncation)]
    fn read(
        &mut self,
        _ctx: &mut Context,
        _base: u64,
        offset: usize,
        size: usize,
        data: &mut [u8],
    ) -> Result<(), MmioError> {
        if offset == 0 {
            debug!("virtio-net: probed by kernel (magic read)");
        }
        let q = self.q();
        // Config space §5.1.4: MAC (6B) + status (2B) + max_virtqueue_pairs (2B) + mtu
        // (2B)
        let link_status: u8 = if self.backend.is_connected() {
            LINK_UP as u8
        } else {
            0
        };
        let cfg: [u8; 12] = [
            self.mac[0],
            self.mac[1],
            self.mac[2],
            self.mac[3],
            self.mac[4],
            self.mac[5],
            link_status,
            0, // status high byte (LE)
            1,
            0, // max_virtqueue_pairs = 1, LE
            0xdc,
            0x05, // mtu = 1500 = 0x05dc, LE
        ];
        match offset {
            0x000..=0x003 => read_u32(offset, size, 0x7472_6976, data), // magic "virt"
            0x004..=0x007 => read_u32(offset, size, 2, data),           // version
            0x008..=0x00b => read_u32(offset, size, 1, data),           // device ID (net)
            0x00c..=0x00f => read_u32(offset, size, 0x554d_4551, data), // vendor "QEMU"
            0x010..=0x013 => {
                let word =
                    (self.device_features >> (u64::from(self.device_features_sel) * 32)) as u32;
                read_u32(offset, size, word, data)
            }
            0x034..=0x037 => read_u32(offset, size, MAX_QUEUE_SIZE, data),
            0x044..=0x047 => read_u32(offset, size, u32::from(self.queue_ready[q]), data),
            0x060..=0x063 => read_u32(offset, size, self.interrupt_status, data),
            0x070..=0x073 => read_u32(offset, size, self.status, data),
            0x080..=0x087 => read_u64(offset, size, self.queue_desc_addr[q], data),
            0x090..=0x097 => read_u64(offset, size, self.queue_driver_addr[q], data),
            0x0a0..=0x0a7 => read_u64(offset, size, self.queue_device_addr[q], data),
            0x0fc..=0x0ff => read_u32(offset, size, 0, data),
            0x100..=0x10b => {
                let i = offset - 0x100;
                for (j, slot) in data[..size].iter_mut().enumerate() {
                    *slot = cfg.get(i + j).copied().unwrap_or(0);
                }
                Ok(())
            }
            _ => {
                data[..size].fill(0);
                Ok(())
            }
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    fn write(
        &mut self,
        _ctx: &mut Context,
        _base: u64,
        offset: usize,
        size: usize,
        data: &[u8],
    ) -> Result<(), MmioError> {
        let q = self.q();
        match offset {
            0x014..=0x017 => write_u32(offset, size, &mut self.device_features_sel, data)?,
            0x020..=0x023 => {
                // DriverFeatures word selected by DriverFeaturesSel (0 = low 32 bits, 1 = high)
                let sel = self.driver_features_sel;
                let mut word = (self.driver_features >> (u64::from(sel) * 32)) as u32;
                write_u32(offset, size, &mut word, data)?;
                if sel == 0 {
                    self.driver_features =
                        (self.driver_features & 0xffff_ffff_0000_0000) | u64::from(word);
                } else {
                    self.driver_features =
                        (self.driver_features & 0x0000_0000_ffff_ffff) | (u64::from(word) << 32);
                }
            }
            0x024..=0x027 => write_u32(offset, size, &mut self.driver_features_sel, data)?,
            0x030..=0x033 => write_u32(offset, size, &mut self.queue_select, data)?,
            0x038..=0x03b => {
                write_u32(offset, size, &mut self.queue_size[q], data)?;
                debug!("virtio-net: queue[{q}] size={}", self.queue_size[q]);
            }
            0x044 => {
                self.queue_ready[q] = data[0] != 0;
                debug!("virtio-net: queue[{q}] ready={}", self.queue_ready[q]);
            }
            // 0x045..=0x047: upper bytes of QueueReady — handled by wildcard
            0x050..=0x053 => {
                write_u32(offset, size, &mut self.queue_notify, data)?;
                let notified_q = self.queue_notify as usize & 1;
                debug!("virtio-net: QueueNotify q={notified_q}");
                if notified_q == TXQ && self.queue_ready[TXQ] {
                    self.pending_tx += 1;
                }
            }
            0x064..=0x067 => {
                let mut v = 0u32;
                write_u32(offset, size, &mut v, data)?;
                self.interrupt_status &= !v;
            }
            0x070..=0x073 => {
                write_u32(offset, size, &mut self.status, data)?;
                debug!(
                    "virtio-net: Status={:#04x} ({}{}{}{}{})",
                    self.status,
                    if self.status & 0x80 != 0 {
                        "FAILED "
                    } else {
                        ""
                    },
                    if self.status & 0x04 != 0 {
                        "DRIVER_OK "
                    } else {
                        ""
                    },
                    if self.status & 0x08 != 0 {
                        "FEATURES_OK "
                    } else {
                        ""
                    },
                    if self.status & 0x02 != 0 {
                        "DRIVER "
                    } else {
                        ""
                    },
                    if self.status & 0x01 != 0 {
                        "ACKNOWLEDGE"
                    } else {
                        ""
                    },
                );
                if self.status == 0 {
                    debug!("virtio-net: reset");
                    self.reset();
                }
            }
            0x080..=0x087 => write_u64(offset, size, &mut self.queue_desc_addr[q], data)?,
            0x090..=0x097 => write_u64(offset, size, &mut self.queue_driver_addr[q], data)?,
            0x0a0..=0x0a7 => write_u64(offset, size, &mut self.queue_device_addr[q], data)?,
            _ => {}
        }
        Ok(())
    }

    fn service(&mut self, ctx: &mut Context, memory: &mut [(Range<u64>, Vec<u8>)]) {
        let tx = self.service_tx(memory);
        let rx = self.service_rx(memory);
        if tx || rx {
            self.interrupt_status |= 1;
        }
        // IRQ is level-triggered: hold it high while interrupt_status is set,
        // not just on the cycle when new work was done.  The PLIC IP bit gets
        // cleared when the driver claims the interrupt; without re-asserting
        // here, subsequent TX/RX completions would never be seen by the CPU.
        if self.interrupt_status != 0 {
            ctx.asserted_irq = Some(self.irq);
        }
        ctx.next_service_in = Some(1);
    }

    fn take_net_backend(&mut self) -> Option<Box<dyn NetworkBackend>> {
        Some(std::mem::replace(
            &mut self.backend,
            Box::new(DummyNetworkBackend),
        ))
    }

    fn save_state(&self, w: &mut Pack) {
        w.u64(self.device_features);
        w.u32(self.device_features_sel);
        w.u64(self.driver_features);
        w.u32(self.driver_features_sel);
        w.u32(self.queue_select);
        for i in 0..2 {
            w.u32(self.queue_size[i]);
            w.bool(self.queue_ready[i]);
            w.u64(self.queue_desc_addr[i]);
            w.u64(self.queue_driver_addr[i]);
            w.u64(self.queue_device_addr[i]);
            w.u16(self.used_ring_index[i]);
        }
        w.u32(self.queue_notify);
        w.u32(self.interrupt_status);
        w.u32(self.status);
        w.u32(self.pending_tx);
        w.raw(&self.mac);
        w.u32(self.irq);
    }

    fn restore_state(&mut self, r: &mut Unpack) -> Result<(), ()> {
        self.device_features = r.u64()?;
        self.device_features_sel = r.u32()?;
        self.driver_features = r.u64()?;
        self.driver_features_sel = r.u32()?;
        self.queue_select = r.u32()?;
        for i in 0..2 {
            self.queue_size[i] = r.u32()?;
            self.queue_ready[i] = r.bool()?;
            self.queue_desc_addr[i] = r.u64()?;
            self.queue_driver_addr[i] = r.u64()?;
            self.queue_device_addr[i] = r.u64()?;
            self.used_ring_index[i] = r.u16()?;
        }
        self.queue_notify = r.u32()?;
        self.interrupt_status = r.u32()?;
        self.status = r.u32()?;
        self.pending_tx = r.u32()?;
        let mac = r.raw(6)?;
        self.mac.copy_from_slice(mac);
        self.irq = r.u32()?;
        Ok(())
    }

    fn info(&self) -> MemoryMappedInfo {
        MemoryMappedInfo {
            name: "VirtIO Net".to_string(),
        }
    }
}
