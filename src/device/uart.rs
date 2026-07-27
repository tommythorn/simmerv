#![allow(clippy::unreadable_literal)]

use crate::device::Context;
use crate::device::MemoryMapped;
use crate::device::MemoryMappedInfo;
use crate::device::MmioError;
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
// smolrv64 DUT convention: bit 0=1 (no interrupt pending), code=000; not 0x07.
const IIR_NO_INTERRUPT: u8 = 0x01;

const LSR_DATA_AVAILABLE: u8 = 0x01;
const LSR_THR_EMPTY: u8 = 0x20;
const LSR_TEMT: u8 = 0x40; // Transmitter Empty (shift register also empty)

/// NS16550A-compatible UART.
pub struct Uart {
    pub regs: [u8; 8],
    // DLL (offset 0) and DLM (offset 1) alias RBR and IER through the DLAB
    // bit in LCR, but they are *separate* latches in real 16550 hardware.
    // Store them in their own fields so writing the baud divisor (DLAB=1)
    // doesn't overwrite the RBR/IER view that reads (DLAB=0) depend on.
    pub dll: u8,
    pub dlm: u8,
    pub rx_fifo: VecDeque<u8>,
    pub ier_prev: u8,
    pub thre_ip: bool,
    pub fcr_fifo: bool,
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
            dll: 0,
            dlm: 0,
            rx_fifo: VecDeque::new(),
            ier_prev: 0,
            thre_ip: false,
            fcr_fifo: false,
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
        let code = if rx_ip {
            IIR_RD_AVAILABLE
        } else if thre_ip {
            IIR_THR_EMPTY
        } else {
            IIR_NO_INTERRUPT
        };
        // smolrv64 DUT mirrors FCR bit 0 into IIR[7:6].
        let fifo_bits = if self.fcr_fifo { 0xC0 } else { 0x00 };
        self.regs[IIR] = fifo_bits | code;
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
        w.u8(self.dll);
        w.u8(self.dlm);
        w.u8(self.rx_fifo.len() as u8);
        for &b in &self.rx_fifo {
            w.u8(b);
        }
        w.u8(self.ier_prev);
        w.bool(self.thre_ip);
        w.bool(self.fcr_fifo);
        w.bool(self.interrupting);
        w.u32(self.irq);
    }

    fn restore_state(&mut self, r: &mut Unpack) -> Result<(), ()> {
        self.regs.copy_from_slice(r.raw(8)?);
        self.dll = r.u8()?;
        self.dlm = r.u8()?;
        let fifo_len = r.u8()? as usize;
        self.rx_fifo.clear();
        for _ in 0..fifo_len {
            self.rx_fifo.push_back(r.u8()?);
        }
        self.ier_prev = r.u8()?;
        self.thre_ip = r.bool()?;
        self.fcr_fifo = r.bool()?;
        self.interrupting = r.bool()?;
        self.irq = r.u32()?;
        Ok(())
    }

    fn read(
        &mut self,
        ctx: &mut Context,
        _base: u64,
        offset: usize,
        size: usize,
        data: &mut [u8],
    ) -> Result<(), MmioError> {
        if size > data.len() {
            return Err(MmioError::BufferTooSmall {
                size,
                len: data.len(),
            });
        }
        if offset
            .checked_add(size)
            .is_none_or(|end| end > self.regs.len())
        {
            return Err(MmioError::OutOfRange {
                offset,
                size,
                device_len: self.regs.len(),
            });
        }
        let dlab = self.dlab();
        for i in offset..offset + size {
            // smolrv64 DUT: returns 0 for DLL/DLM reads (divisor ignored) and
            // a constant 0xB0 for MSR (CTS+DSR+CD asserted).
            data[i - offset] = match (i, dlab) {
                (0 | 1, true) => 0,
                (6, _) => 0xB0,
                _ => self.regs[i],
            };
            // RBR (offset 0, DLAB=0) is a destructive read
            if i == 0 && !dlab {
                self.rx_fifo.pop_front();
                self.regs[RBR_THR] = self.rx_fifo.front().copied().unwrap_or(0);
                if self.rx_fifo.is_empty() {
                    self.regs[LSR] &= !LSR_DATA_AVAILABLE;
                }
                self.update_iir();
            }
        }
        ctx.asserted_irq = self.interrupting.then_some(self.irq);
        Ok(())
    }

    fn write(
        &mut self,
        ctx: &mut Context,
        _base: u64,
        offset: usize,
        size: usize,
        data: &[u8],
    ) -> Result<(), MmioError> {
        if size > data.len() {
            return Err(MmioError::BufferTooSmall {
                size,
                len: data.len(),
            });
        }
        if offset
            .checked_add(size)
            .is_none_or(|end| end > self.regs.len())
        {
            return Err(MmioError::OutOfRange {
                offset,
                size,
                device_len: self.regs.len(),
            });
        }
        let dlab = self.dlab();
        for i in offset..offset + size {
            let byte = data[i - offset];
            match (i, dlab) {
                (0, true) => self.dll = byte,
                (1, true) => self.dlm = byte,
                (0, false) => {
                    // THR write: transmit. Keep regs[RBR_THR] synced to FIFO front.
                    if let Some(b) = &mut self.backend {
                        b.put_byte(byte);
                    }
                    self.regs[RBR_THR] = self.rx_fifo.front().copied().unwrap_or(0);
                    // Instant transmit → THRE/TEMT stay set
                    self.regs[LSR] |= LSR_THR_EMPTY | LSR_TEMT;
                }
                (1, false) => {
                    // IER write: DUT masks to bits [3:0].  Rising edge of
                    // THREINT_BIT still fires THRE interrupt.
                    let byte = byte & 0x0F;
                    self.regs[IER] = byte;
                    if self.ier_prev & IER_THREINT_BIT == 0 && byte & IER_THREINT_BIT != 0 {
                        self.thre_ip = true;
                    }
                    self.ier_prev = byte;
                    self.update_iir();
                }
                (2, _) => {
                    // FCR write (DUT): bit 0 sets fcr_fifo (surfaces in
                    // IIR[7:6]); bit 1 resets RX FIFO.  IIR is read-only.
                    self.fcr_fifo = byte & 0x01 != 0;
                    if byte & 0x02 != 0 {
                        self.rx_fifo.clear();
                        self.regs[LSR] &= !LSR_DATA_AVAILABLE;
                    }
                    self.update_iir();
                }
                _ => self.regs[i] = byte,
            }
        }
        ctx.asserted_irq = self.interrupting.then_some(self.irq);
        Ok(())
    }

    fn service(&mut self, ctx: &mut Context, _memory: &mut [(Range<u64>, Vec<u8>)]) {
        let mut rx_ip = false;
        // Always let the backend drain host input and process host-side control
        // keys (the Ctrl-C menu) first — even when our FIFO is full — so the
        // menu stays responsive while the guest is not reading.
        if let Some(b) = self.backend.as_mut() {
            b.poll_input();
        }
        // Move buffered input into the FIFO only while there is room. When the
        // FIFO fills we stop pulling so the excess stays buffered in the backend
        // (delivered on later ticks as the guest drains the FIFO) rather than
        // being read out and dropped — otherwise a paste longer than the FIFO
        // would lose everything past the first FIFO_CAPACITY bytes.
        while self.rx_fifo.len() < FIFO_CAPACITY {
            let value = self.backend.as_mut().map_or(0, |b| b.get_input());
            if value == 0 {
                break;
            }
            self.rx_fifo.push_back(value);
            self.regs[RBR_THR] = self.rx_fifo.front().copied().unwrap_or(0);
            self.regs[LSR] |= LSR_DATA_AVAILABLE;
            self.update_iir();
            if self.regs[IER] & IER_RXINT_BIT != 0 {
                rx_ip = true;
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
