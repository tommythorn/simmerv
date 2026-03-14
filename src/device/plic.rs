#![allow(clippy::unreadable_literal)]

use super::Context;
use super::MemoryMapped;
use super::MemoryMappedInfo;
use super::Pack;
use super::Unpack;
use super::read_u32;
use super::read_u64;
use super::write_u32;
use super::write_u64;
use crate::cpu::MIP_MEIP;
use crate::cpu::MIP_SEIP;
use std::ops::Range;

// Based on SiFive Interrupt Cookbook
// https://sifive.cdn.prismic.io/sifive/0d163928-2128-42be-a75a-464df65e04e0_sifive-interrupt-cookbook.pdf

/// Emulates PLIC known as Interrupt Controller.
/// Refer to the [specification](https://sifive.cdn.prismic.io/sifive%2Fc89f6e5a-cf9e-44c3-a3db-04420702dcc1_sifive+e31+manual+v19.08.pdf)
/// for the detail.
pub struct Plic {
    pub irq: u32,
    pub enabled: u64,
    pub threshold: u32,
    pub ips: [u8; 1024],
    pub priorities: [u32; 1024],
}

impl Default for Plic {
    fn default() -> Self { Self::new() }
}

impl Plic {
    /// Creates a new `Plic`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            irq: 0,
            enabled: 0,
            threshold: 0,
            priorities: [0; 1024],
            ips: [0; 1024],
        }
    }

    /// Tick: set IPs for the given asserted IRQs and run `update_irq` if
    /// needed.
    pub fn tick(&mut self, asserted_irqs: &[u32], mip: &mut u64) {
        for &irq in asserted_irqs {
            if irq > 0 && irq < 64 {
                self.set_ip(irq);
            }
        }
        self.update_irq(mip);
    }

    fn update_irq(&mut self, mip: &mut u64) {
        let mut best_irq = 0;
        let mut best_priority = 0;

        for irq in 1..64 {
            let ip = (self.ips[irq >> 3] >> (irq & 7)) & 1 == 1;
            let enabled = (self.enabled >> irq) & 1 == 1;
            let priority = self.priorities[irq];
            if ip && enabled && priority > self.threshold && priority > best_priority {
                best_irq = irq;
                best_priority = priority;
            }
        }

        self.irq = best_irq as u32;
        if self.irq != 0 {
            *mip |= MIP_MEIP | MIP_SEIP;
        } else {
            *mip &= !MIP_MEIP & !MIP_SEIP;
        }
    }

    const fn set_ip(&mut self, irq: u32) {
        let index = (irq >> 3) as usize;
        self.ips[index] |= 1 << (irq & 7);
    }

    const fn clear_ip(&mut self, irq: u32) {
        let index = (irq >> 3) as usize;
        self.ips[index] &= !(1 << (irq & 7));
    }
}

impl MemoryMapped for Plic {
    /// Register layout by offset:
    ///   0x000000..=0x000fff: priorities[offset>>2] (u32 each)
    ///   0x001000..=0x00107f: ips[offset-0x1000] (u8 array)
    ///   0x002080..=0x002087: enabled (u64 LE)
    ///   0x201000..=0x201003: threshold (u32 LE)
    ///   0x201004..=0x201007: irq/claim (u32 LE)
    fn read(
        &mut self,
        _ctx: &mut Context,
        _base: u64,
        offset: usize,
        size: usize,
        data: &mut [u8],
    ) {
        match offset {
            0x000000..=0x000fff => read_u32(offset, size, self.priorities[offset / 4], data),
            0x001000..=0x00107f => {
                let idx = offset - 0x1000;
                let src = self.ips.get(idx..).unwrap_or(&[]);
                let copy_len = src.len().min(size);
                data[..copy_len].copy_from_slice(&src[..copy_len]);
                data[copy_len..size].fill(0);
            }
            0x002080..=0x002087 => read_u64(offset, size, self.enabled, data),
            0x201000..=0x201003 => read_u32(offset, size, self.threshold, data),
            0x201004..=0x201007 => read_u32(offset, size, self.irq, data),
            _ => data[..size].fill(0),
        }
    }

    fn write(&mut self, ctx: &mut Context, _base: u64, offset: usize, size: usize, data: &[u8]) {
        match offset {
            0x000000..=0x000fff => write_u32(offset, size, &mut self.priorities[offset / 4], data),
            0x002080..=0x002087 => write_u64(offset, size, &mut self.enabled, data),
            0x201000..=0x201003 => write_u32(offset, size, &mut self.threshold, data),
            0x201004..=0x201007 => {
                let mut claimed_irq = 0;
                write_u32(offset, size, &mut claimed_irq, data);
                if 0 < claimed_irq && claimed_irq < 64 {
                    self.clear_ip(claimed_irq);
                }
            }
            _ => {}
        }
        self.update_irq(&mut ctx.mip);
    }

    fn service(&mut self, _ctx: &mut Context, _memory: &mut [(Range<u64>, Vec<u8>)]) {}

    fn process_irqs(&mut self, irqs: &[u32], mip: &mut u64) { self.tick(irqs, mip); }

    fn save_state(&self, w: &mut Pack) {
        w.u32(self.irq);
        w.u64(self.enabled);
        w.u32(self.threshold);
        w.raw(&self.ips);
        for p in &self.priorities {
            w.u32(*p);
        }
    }

    fn restore_state(&mut self, r: &mut Unpack) -> Result<(), ()> {
        self.irq = r.u32()?;
        self.enabled = r.u64()?;
        self.threshold = r.u32()?;
        self.ips.copy_from_slice(r.raw(1024)?);
        for p in &mut self.priorities {
            *p = r.u32()?;
        }
        Ok(())
    }

    fn info(&self) -> MemoryMappedInfo {
        MemoryMappedInfo {
            name: "SiFive PLIC".to_string(),
        }
    }
}
