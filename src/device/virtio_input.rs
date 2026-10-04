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
use crate::device::read_u32;
use crate::device::read_u64;
use crate::device::write_u32;
use crate::device::write_u64;
use std::collections::VecDeque;
use std::ops::Range;
use std::sync::Arc;
use std::sync::Mutex;

// VirtIO 1.2 §5.8 — Input Device (Device ID = 18)
// Two virtqueues: eventq (0), device to driver, and statusq (1), driver to
// device (LED state, which a keyboard with no LEDs just acknowledges).

const EVENTQ: usize = 0;
const STATUSQ: usize = 1;
const MAX_QUEUE_SIZE: u32 = 0x40;
const VIRTIO_F_VERSION_1: u32 = 32;

// `virtio_input_config.select`
const CFG_ID_NAME: u8 = 0x01;
const CFG_ID_DEVIDS: u8 = 0x03;
const CFG_EV_BITS: u8 = 0x11;

// Linux input event types and codes (include/uapi/linux/input-event-codes.h).
pub const EV_SYN: u16 = 0x00;
pub const EV_KEY: u16 = 0x01;
const EV_REP: u16 = 0x14;
const SYN_REPORT: u16 = 0;
const BUS_VIRTUAL: u16 = 0x06;

const NAME: &str = "simmerv keyboard";

/// One `virtio_input_event`, as the guest's evdev sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputEvent {
    pub kind: u16,
    pub code: u16,
    pub value: u32,
}

/// The host's end of the keyboard: events pushed here reach the guest on the
/// device's next service.  Cloning shares the queue.
#[derive(Clone, Default)]
pub struct Keyboard(Arc<Mutex<VecDeque<InputEvent>>>);

impl Keyboard {
    /// Press (`down`) or release Linux key `code`, followed by the
    /// `SYN_REPORT` that makes evdev deliver it.  Autorepeat is the guest's
    /// business: the device advertises `EV_REP`, so only transitions are sent.
    pub fn key(&self, code: u16, down: bool) {
        if let Ok(mut q) = self.0.lock() {
            q.push_back(InputEvent {
                kind: EV_KEY,
                code,
                value: u32::from(down),
            });
            q.push_back(InputEvent {
                kind: EV_SYN,
                code: SYN_REPORT,
                value: 0,
            });
        }
    }

    fn front(&self) -> Option<InputEvent> { self.0.lock().ok()?.front().copied() }

    fn pop(&self) { drop(self.0.lock().map(|mut q| q.pop_front())); }
}

/// Linux keycode for USB HID keyboard usage `usage`, which SDL calls a
/// scancode.
///
/// The table is `hid_keyboard[]` from Linux's
/// `drivers/hid/hid-input.c`, through Keypad `.` and the non-US backslash,
/// plus the eight modifiers.
#[must_use]
pub fn hid_to_linux(usage: u32) -> Option<u16> {
    #[rustfmt::skip]
    const MAIN: [u8; 0x66] = [
          0,  0,  0,  0, 30, 48, 46, 32, 18, 33, 34, 35, 23, 36, 37, 38,
         50, 49, 24, 25, 16, 19, 31, 20, 22, 47, 17, 45, 21, 44,  2,  3,
          4,  5,  6,  7,  8,  9, 10, 11, 28,  1, 14, 15, 57, 12, 13, 26,
         27, 43, 43, 39, 40, 41, 51, 52, 53, 58, 59, 60, 61, 62, 63, 64,
         65, 66, 67, 68, 87, 88, 99, 70,119,110,102,104,111,107,109,106,
        105,108,103, 69, 98, 55, 74, 78, 96, 79, 80, 81, 75, 76, 77, 71,
         72, 73, 82, 83, 86,127,
    ];
    const MODIFIERS: [u8; 8] = [29, 42, 56, 125, 97, 54, 100, 126];
    let code = match usage {
        0..0x66 => MAIN[usage as usize],
        0xe0..0xe8 => MODIFIERS[usage as usize - 0xe0],
        _ => 0,
    };
    (code != 0).then_some(u16::from(code))
}

/// Emulates a `VirtIO` 1.2 (modern) keyboard over MMIO.
pub struct VirtioInput {
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

    interrupt_status: u32,
    status: u32,
    /// `virtio_input_config.select` / `.subsel`, as last written.
    cfg_select: u8,
    cfg_subsel: u8,
    irq: u32,

    keyboard: Keyboard,
}

impl VirtioInput {
    #[must_use]
    pub const fn new(keyboard: Keyboard, irq: u32) -> Self {
        Self {
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
            interrupt_status: 0,
            status: 0,
            cfg_select: 0,
            cfg_subsel: 0,
            irq,
            keyboard,
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
        self.interrupt_status = 0;
        self.cfg_select = 0;
        self.cfg_subsel = 0;
    }

    const fn q(&self) -> usize { (self.queue_select & 1) as usize }

    /// The `virtio_input_config` union for the current selection: its `size`
    /// byte is the length of what this returns.
    fn cfg_payload(&self) -> Vec<u8> {
        match (self.cfg_select, u16::from(self.cfg_subsel)) {
            (CFG_ID_NAME, _) => NAME.as_bytes().to_vec(),
            (CFG_ID_DEVIDS, _) => [BUS_VIRTUAL, 0x0627, 0x0001, 0x0001]
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect(),
            (CFG_EV_BITS, EV_KEY) => {
                // Every key the HID table can produce.
                let mut bits = vec![0u8; 16];
                for code in (0..0x100).filter_map(hid_to_linux) {
                    bits[usize::from(code / 8)] |= 1 << (code % 8);
                }
                bits
            }
            // Non-empty is all that matters: it turns on the guest's autorepeat.
            (CFG_EV_BITS, EV_REP) => vec![1],
            _ => Vec::new(),
        }
    }

    /// The next descriptor chain the driver has made available on `q`, or
    /// `None` if the ring is empty.
    fn next_avail(&self, memory: &mut [(Range<u64>, Vec<u8>)], q: usize) -> Option<u64> {
        let avail_idx = dma_read_u16(memory, self.queue_driver_addr[q].wrapping_add(2));
        if self.used_ring_index[q] == avail_idx {
            return None;
        }
        let queue_size = u64::from(self.queue_size[q].max(1));
        let slot = u64::from(self.used_ring_index[q]) % queue_size;
        let head = dma_read_u16(
            memory,
            self.queue_driver_addr[q]
                .wrapping_add(4)
                .wrapping_add(slot * 2),
        );
        Some(u64::from(head) % queue_size)
    }

    /// Return chain `head` on `q` with `len` bytes written.
    #[allow(clippy::cast_possible_truncation)]
    fn push_used(&mut self, memory: &mut [(Range<u64>, Vec<u8>)], q: usize, head: u64, len: u32) {
        let queue_size = u64::from(self.queue_size[q].max(1));
        let elem = self.queue_device_addr[q]
            .wrapping_add(4)
            .wrapping_add((u64::from(self.used_ring_index[q]) % queue_size) * 8);
        if let Some(s) = dma_slice(memory, elem, 8) {
            s[..4].copy_from_slice(&(head as u32).to_le_bytes());
            s[4..].copy_from_slice(&len.to_le_bytes());
        }
        self.used_ring_index[q] = self.used_ring_index[q].wrapping_add(1);
        if let Some(s) = dma_slice(memory, self.queue_device_addr[q].wrapping_add(2), 2) {
            s.copy_from_slice(&self.used_ring_index[q].to_le_bytes());
        }
    }

    /// Move pending key events into the driver's buffers.  An event waits
    /// in the queue, rather than being dropped, while the driver has no
    /// buffer for it.
    fn service_events(&mut self, memory: &mut [(Range<u64>, Vec<u8>)]) -> bool {
        if !self.queue_ready[EVENTQ] {
            return false;
        }
        let mut did_work = false;
        while let Some(event) = self.keyboard.front() {
            let Some(head) = self.next_avail(memory, EVENTQ) else {
                break;
            };
            let desc = self.queue_desc_addr[EVENTQ].wrapping_add(16 * head);
            let buf = dma_read_u64(memory, desc);
            let cap = dma_read_u32(memory, desc.wrapping_add(8));
            let written = match dma_slice(memory, buf, 8) {
                Some(s) if cap >= 8 => {
                    s[0..2].copy_from_slice(&event.kind.to_le_bytes());
                    s[2..4].copy_from_slice(&event.code.to_le_bytes());
                    s[4..8].copy_from_slice(&event.value.to_le_bytes());
                    8
                }
                _ => 0,
            };
            self.push_used(memory, EVENTQ, head, written);
            self.keyboard.pop();
            did_work = true;
        }
        did_work
    }

    /// Acknowledge LED updates; there are no LEDs to light.
    fn service_status(&mut self, memory: &mut [(Range<u64>, Vec<u8>)]) -> bool {
        if !self.queue_ready[STATUSQ] {
            return false;
        }
        let mut did_work = false;
        while let Some(head) = self.next_avail(memory, STATUSQ) {
            self.push_used(memory, STATUSQ, head, 0);
            did_work = true;
        }
        did_work
    }
}

impl MemoryMapped for VirtioInput {
    #[allow(clippy::cast_possible_truncation)]
    fn read(
        &mut self,
        _ctx: &mut Context,
        _base: u64,
        offset: usize,
        size: usize,
        data: &mut [u8],
    ) -> Result<(), MmioError> {
        let q = self.q();
        match offset {
            0x000..=0x003 => read_u32(offset, size, 0x7472_6976, data), // magic "virt"
            0x004..=0x007 => read_u32(offset, size, 2, data),           // version
            0x008..=0x00b => read_u32(offset, size, 18, data),          // device ID (input)
            0x00c..=0x00f => read_u32(offset, size, 0x554d_4551, data), // vendor "QEMU"
            0x010..=0x013 => {
                let word = if self.device_features_sel == 1 {
                    1 << (VIRTIO_F_VERSION_1 - 32)
                } else {
                    0
                };
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
            // virtio_input_config: select, subsel, size, 5 reserved, union.
            0x100..=0x187 => {
                let payload = self.cfg_payload();
                let mut cfg = [0u8; 0x88];
                cfg[0] = self.cfg_select;
                cfg[1] = self.cfg_subsel;
                cfg[2] = payload.len() as u8;
                cfg[8..8 + payload.len()].copy_from_slice(&payload);
                for (j, slot) in data[..size].iter_mut().enumerate() {
                    *slot = cfg.get(offset - 0x100 + j).copied().unwrap_or(0);
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
                let sel = self.driver_features_sel;
                let mut word = (self.driver_features >> (u64::from(sel & 1) * 32)) as u32;
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
            0x038..=0x03b => write_u32(offset, size, &mut self.queue_size[q], data)?,
            0x044 => self.queue_ready[q] = data[0] != 0,
            0x064..=0x067 => {
                let mut v = 0u32;
                write_u32(offset, size, &mut v, data)?;
                self.interrupt_status &= !v;
            }
            0x070..=0x073 => {
                write_u32(offset, size, &mut self.status, data)?;
                if self.status == 0 {
                    self.reset();
                }
            }
            0x080..=0x087 => write_u64(offset, size, &mut self.queue_desc_addr[q], data)?,
            0x090..=0x097 => write_u64(offset, size, &mut self.queue_driver_addr[q], data)?,
            0x0a0..=0x0a7 => write_u64(offset, size, &mut self.queue_device_addr[q], data)?,
            0x100 => self.cfg_select = data[0],
            0x101 => self.cfg_subsel = data[0],
            _ => {}
        }
        Ok(())
    }

    fn service(&mut self, ctx: &mut Context, memory: &mut [(Range<u64>, Vec<u8>)]) {
        let events = self.service_events(memory);
        let status = self.service_status(memory);
        if events || status {
            self.interrupt_status |= 1;
        }
        // Level-triggered, as in `VirtioNet::service`.
        if self.interrupt_status != 0 {
            ctx.asserted_irq = Some(self.irq);
        }
        // Typing is slow: polling every thousand cycles is microseconds of
        // latency and keeps the queue's lock out of the hot path.
        ctx.next_service_in = Some(1000);
    }

    fn save_state(&self, w: &mut Pack) {
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
        w.u32(self.interrupt_status);
        w.u32(self.status);
        w.u8(self.cfg_select);
        w.u8(self.cfg_subsel);
        w.u32(self.irq);
    }

    fn restore_state(&mut self, r: &mut Unpack) -> Result<(), ()> {
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
        self.interrupt_status = r.u32()?;
        self.status = r.u32()?;
        self.cfg_select = r.u8()?;
        self.cfg_subsel = r.u8()?;
        self.irq = r.u32()?;
        Ok(())
    }

    fn info(&self) -> MemoryMappedInfo {
        MemoryMappedInfo {
            name: "VirtIO Input".to_string(),
        }
    }
}
