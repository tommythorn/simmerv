#![allow(clippy::unreadable_literal)]

use crate::device::Context;
use crate::device::MemoryMapped;
use crate::device::MemoryMappedInfo;
use crate::device::Pack;
use crate::device::Unpack;
use crate::serial_backend::SerialBackend;
use std::collections::VecDeque;
use std::ops::Range;

const FIFO_CAPACITY: usize = 16;

// Register offsets within the backing array
const RBR_THR: usize = 0; // Receiver Buffer (read) / Transmitter Holding (write)
const IER: usize = 1; // Interrupt Enable
const IIR: usize = 2; // Interrupt Identification (read-only)
const LCR: usize = 3; // Line Control  (DLAB = bit 7)
const LSR: usize = 5; // Line Status
// offset 4 = MCR (modem control, unused), 6 = MSR (modem status, unused)
const SCR: usize = 7; // Scratch

const IER_RXINT_BIT: u8 = 0x01;
const IER_THREINT_BIT: u8 = 0x02;

const IIR_THR_EMPTY: u8 = 0x02;
const IIR_RD_AVAILABLE: u8 = 0x04;
const IIR_NO_INTERRUPT: u8 = 0x07;

const LSR_DATA_AVAILABLE: u8 = 0x01;
const LSR_THR_EMPTY: u8 = 0x20;
const LSR_TEMT: u8 = 0x40; // Transmitter Empty (shift register also empty)

/// NS16550A-compatible UART.
pub struct Uart {
    pub regs: [u8; 8],
    pub rx_fifo: VecDeque<u8>,
    pub ier_prev: u8,
    pub thre_ip: bool,
    pub interrupting: bool,
    pub backend: Option<Box<dyn SerialBackend>>,
    pub irq: u32,
}

impl Uart {
    #[must_use]
    pub fn new(backend: Box<dyn SerialBackend>, irq: u32) -> Self {
        let mut regs = [0; 8];
        regs[LSR] = LSR_THR_EMPTY | LSR_TEMT;
        Self {
            regs,
            rx_fifo: VecDeque::new(),
            ier_prev: 0,
            thre_ip: false,
            interrupting: false,
            backend: Some(backend),
            irq,
        }
    }

    #[allow(clippy::missing_const_for_fn)]
    fn dlab(&self) -> bool { self.regs[LCR] >> 7 != 0 }

    #[allow(clippy::missing_const_for_fn)]
    fn update_iir(&mut self) {
        let rx_ip = self.regs[IER] & IER_RXINT_BIT != 0 && !self.rx_fifo.is_empty();
        let thre_ip = self.regs[IER] & IER_THREINT_BIT != 0;
        self.regs[IIR] = if rx_ip {
            IIR_RD_AVAILABLE
        } else if thre_ip {
            IIR_THR_EMPTY
        } else {
            IIR_NO_INTERRUPT
        };
    }
}

impl MemoryMapped for Uart {
    fn backend(&mut self) -> Option<&mut dyn SerialBackend> {
        self.backend
            .as_deref_mut()
            .map(|b| b as &mut dyn SerialBackend)
    }

    fn take_backend(&mut self) -> Option<Box<dyn SerialBackend>> { self.backend.take() }

    fn save_state(&self, w: &mut Pack) {
        w.raw(&self.regs);
        w.u8(self.rx_fifo.len() as u8);
        for &b in &self.rx_fifo {
            w.u8(b);
        }
        w.u8(self.ier_prev);
        w.bool(self.thre_ip);
        w.bool(self.interrupting);
        w.u32(self.irq);
    }

    fn restore_state(&mut self, r: &mut Unpack) -> Result<(), ()> {
        self.regs.copy_from_slice(r.raw(8)?);
        let fifo_len = r.u8()? as usize;
        self.rx_fifo.clear();
        for _ in 0..fifo_len {
            self.rx_fifo.push_back(r.u8()?);
        }
        self.ier_prev = r.u8()?;
        self.thre_ip = r.bool()?;
        self.interrupting = r.bool()?;
        self.irq = r.u32()?;
        Ok(())
    }

    fn read(&mut self, ctx: &mut Context, _base: u64, offset: usize, size: usize, data: &mut [u8]) {
        data[..size].copy_from_slice(&self.regs[offset..offset + size]);
        // RBR (offset 0) is a destructive read when DLAB=0
        for i in offset..offset + size {
            if i == 0 && !self.dlab() {
                self.rx_fifo.pop_front();
                self.regs[RBR_THR] = self.rx_fifo.front().copied().unwrap_or(0);
                if self.rx_fifo.is_empty() {
                    self.regs[LSR] &= !LSR_DATA_AVAILABLE;
                }
                self.update_iir();
            }
        }
        ctx.asserted_irq = self.interrupting.then_some(self.irq);
    }

    fn write(&mut self, ctx: &mut Context, _base: u64, offset: usize, size: usize, data: &[u8]) {
        self.regs[offset..offset + size].copy_from_slice(&data[..size]);
        let dlab = self.dlab();
        for i in offset..offset + size {
            match (i, dlab) {
                (0, false) => {
                    // THR write: transmit then restore RBR view
                    if let Some(b) = &mut self.backend {
                        b.put_byte(self.regs[RBR_THR]);
                    }
                    self.regs[RBR_THR] = self.rx_fifo.front().copied().unwrap_or(0);
                    // We transmit instantly so both THRE and TEMT stay set
                    self.regs[LSR] |= LSR_THR_EMPTY | LSR_TEMT;
                }
                (1, false) => {
                    // IER write: rising edge of THREINT_BIT fires THRE interrupt
                    let new_ier = self.regs[IER];
                    if self.ier_prev & IER_THREINT_BIT == 0 && new_ier & IER_THREINT_BIT != 0 {
                        self.thre_ip = true;
                    }
                    self.ier_prev = new_ier;
                    self.update_iir();
                }
                _ => {}
            }
        }
        ctx.asserted_irq = self.interrupting.then_some(self.irq);
    }

    fn service(&mut self, ctx: &mut Context, _memory: &mut [(Range<u64>, Vec<u8>)]) {
        let mut rx_ip = false;
        // Drain all available input into the FIFO. We always call get_input()
        // at least once so break-key detection (Ctrl-C/Ctrl-X) fires even
        // when the FIFO is full — the backend handles those via side-effects.
        loop {
            let value = self.backend.as_mut().map_or(0, |b| b.get_input());
            if value == 0 {
                break;
            }
            if self.rx_fifo.len() < FIFO_CAPACITY {
                self.rx_fifo.push_back(value);
                self.regs[RBR_THR] = self.rx_fifo.front().copied().unwrap_or(0);
                self.regs[LSR] |= LSR_DATA_AVAILABLE;
                self.update_iir();
                if self.regs[IER] & IER_RXINT_BIT != 0 {
                    rx_ip = true;
                }
            }
        }
        if self.thre_ip || rx_ip {
            self.interrupting = true;
            self.thre_ip = false;
        } else {
            self.interrupting = false;
        }
        ctx.asserted_irq = self.interrupting.then_some(self.irq);
        ctx.next_service_in = Some(4096);
    }

    fn info(&self) -> MemoryMappedInfo {
        MemoryMappedInfo {
            name: "NS16550A".into(),
        }
    }
}
