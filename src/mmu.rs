#![allow(clippy::unreadable_literal, clippy::cast_possible_wrap)]

use crate::cpu;
use crate::csr;
use crate::device::Context;
use crate::device::MemoryMapped;
use crate::device::Pack;
use crate::device::Unpack;
use crate::device::clint::Clint;
use crate::device::plic::Plic;
use crate::device::uart::Uart;
use crate::riscv;
use crate::serial_backend::SerialBackend;
use crate::tlb::DTlb;
use crate::tlb::Tlb;
use crate::tlb::check_perm;
use crate::tlb::pack_perm;
use cpu::CONFIG_SW_MANAGED_A_AND_D;
use cpu::Exception;
use cpu::MSTATUS_MPP_SHIFT;
use cpu::MSTATUS_MPRV;
use cpu::MSTATUS_MXR;
use cpu::MSTATUS_SUM;
use cpu::PG_SHIFT;
use csr::SATP_ASID_MASK;
use csr::SATP_ASID_SHIFT;
use csr::SATP_MODE_MASK;
use csr::SATP_MODE_SHIFT;
use csr::SATP_PPN_MASK;
use csr::SATP_PPN_SHIFT;
use csr::SatpMode;
use log::trace;
use log::warn;
use riscv::MemoryAccessType;
use riscv::PrivMode;
use riscv::Trap;
use riscv::priv_mode_from;
use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::ops::Range;

/// UART IRQ number on the PLIC.
const UART_IRQ: u32 = 10;

/// Emulates Memory Management Unit. It holds the Main memory and peripheral
/// devices, maps address to them, and accesses them depending on address.
///
/// It also manages virtual-physical address translation and memory protection.
/// It could also be called Bus.
pub struct Mmu {
    // CPU state that lives here
    pub prv: PrivMode,
    pub mstatus: u64,
    pub mip: u64,
    pub satp: u64,

    /// Plain RAM regions — fast path for load/store.
    pub memory: Vec<(Range<u64>, Vec<u8>)>,

    /// CLINT — always present, serviced every cycle outside the device queue.
    clint: (Range<u64>, Clint),

    /// PLIC — always present, receives asserted IRQs after each service round.
    plic: (Range<u64>, Plic),

    /// All memory-mapped I/O devices (`VirtIO`, UART, …).
    devices: Vec<(Range<u64>, Box<dyn MemoryMapped>)>,

    /// Min-heap event queue: `(next_cycle, device_index)` pairs.
    service_queue: BinaryHeap<Reverse<(u64, usize)>>,
    /// Current cycle, updated at the start of `service()`.
    cycle: u64,

    /// Split TLBs for instruction fetch and data access.
    /// iTLB: 512 entries (stores physical page numbers).
    /// dTLB: 1024 entries (stores RAM region index + page byte offset).
    pub itlb: Tlb<512>,
    pub dtlb: DTlb<1024>,

    /// Cosim mode: when true, PLIC service no longer drives MIP.SEIP/MEIP.
    /// The bits are instead forced externally via `write_seip` to mirror the
    /// DUT's independent PLIC/UART state.
    pub cosim_ext_irq_driven: bool,

    /// TLB flush counters (shared — both TLBs are always flushed together).
    pub flush_full: u64,
    pub flush_asid: u64,
    pub flush_vpage: u64,
    pub flush_vpage_asid: u64,
}

/// Result of a data address translation.
///
/// When `mem_idx != DataAddr::NO_RAM` the access targets RAM and can be
/// served directly from `Mmu::memory[mem_idx].1[page_byte_offset | (va &
/// 0xfff)]` without any further scanning.  Otherwise the physical address `pa`
/// must be used with the normal MMIO load/store path.
pub struct DataAddr {
    /// Physical address.  Always valid (used for MMIO and by callers that
    /// only need `pa`).
    pub pa: u64,
    /// Index into `Mmu::memory`, or `NO_RAM` when the page is MMIO or the
    /// access is in physical (M-mode) mode.
    pub mem_idx: u8,
    /// Byte offset of the start of the virtual page within
    /// `Mmu::memory[mem_idx].1`.  Only valid when `mem_idx != NO_RAM`.
    pub page_byte_offset: u64,
}

impl DataAddr {
    /// Sentinel `mem_idx` meaning "not a cached RAM entry".
    pub const NO_RAM: u8 = u8::MAX;
}

pub const PTE_V_MASK: u64 = 1 << 0;
pub const PTE_U_MASK: u64 = 1 << 4;
pub const PTE_A_MASK: u64 = 1 << 6;
pub const PTE_D_MASK: u64 = 1 << 7;

#[derive(Clone, Copy, Default)]
pub struct TlbDisplayStats {
    pub itlb_misses: u64,
    pub dtlb_misses: u64,
    pub flush_full: u64,
    pub flush_asid: u64,
    pub flush_vpage: u64,
    pub flush_vpage_asid: u64,
}

impl Default for Mmu {
    fn default() -> Self { Self::new() }
}

impl Mmu {
    pub const CLINT_BASE: u64 = 0x0200_0000;
    pub const CLINT_END: u64 = 0x0201_0000;
    pub const PLIC_BASE: u64 = 0x0c00_0000;
    pub const PLIC_END: u64 = 0x1000_0000;
    pub const VIRTIO_BASE: u64 = 0x1000_1000;
    pub const VIRTIO_END: u64 = 0x1000_2000;
    pub const VIRTIO_IRQ: u32 = 1;
    pub const NET_BASE: u64 = 0x1000_2000;
    pub const NET_END: u64 = 0x1000_3000;
    pub const NET_IRQ: u32 = 2;
    pub const SYSCON_BASE: u64 = 0x0010_0000;
    pub const SYSCON_END: u64 = 0x0010_1000;

    /// Creates a new `Mmu` with CLINT and PLIC; no RAM or `VirtIO`.
    /// Call `add_memory` and `add_device` (for `VirtIO`), and `attach_uart`
    /// before use.
    #[must_use]
    pub fn new() -> Self {
        Self {
            prv: PrivMode::M,
            mstatus: 0,
            mip: 0,
            satp: 0,
            memory: Vec::new(),
            clint: (Self::CLINT_BASE..Self::CLINT_END, Clint::new()),
            plic: (Self::PLIC_BASE..Self::PLIC_END, Plic::new()),
            devices: Vec::new(),
            service_queue: BinaryHeap::new(),
            cycle: 0,
            itlb: Tlb::<512>::new(),
            dtlb: DTlb::<1024>::new(),
            cosim_ext_irq_driven: false,
            flush_full: 0,
            flush_asid: 0,
            flush_vpage: 0,
            flush_vpage_asid: 0,
        }
    }

    /// Appends a zeroed RAM region covering `base..base+size`.
    pub fn add_memory(&mut self, base: u64, size: usize) {
        self.memory
            .push((base..base + size as u64, vec![0u8; size]));
    }

    /// Writes `data` into the memory region containing `addr`.
    /// Silently truncates if `data` extends past the region end.
    #[allow(clippy::cast_possible_truncation)]
    pub fn write_memory_at(&mut self, addr: u64, data: &[u8]) {
        for (range, mem) in &mut self.memory {
            if addr >= range.start && addr < range.end {
                let offset = (addr - range.start) as usize;
                let len = data.len().min(mem.len() - offset);
                mem[offset..offset + len].copy_from_slice(&data[..len]);
                return;
            }
        }
    }

    /// Attaches a pluggable memory-mapped device at the given address range and
    /// registers it in the service queue.
    pub fn add_device(&mut self, range: Range<u64>, device: Box<dyn MemoryMapped>) {
        let idx = self.devices.len();
        self.devices.push((range, device));
        self.service_queue.push(Reverse((0, idx)));
    }

    /// Attaches a UART backed by `backend` at the standard address with the
    /// standard IRQ.
    pub fn attach_uart(&mut self, backend: Box<dyn SerialBackend>) {
        self.add_device(
            0x1000_0000..0x1000_0008,
            Box::new(Uart::new(backend, UART_IRQ)),
        );
    }

    /// Swap the device registered at `range` for `device`.
    /// The service-queue entries (indexed by position) remain valid.
    pub fn replace_device(&mut self, range: Range<u64>, device: Box<dyn MemoryMapped>) {
        if let Some((_, dev)) = self.devices.iter_mut().find(|(r, _)| *r == range) {
            *dev = device;
        }
    }

    /// Flush both I-TLB and D-TLB.
    pub const fn flush_tlb(&mut self) {
        self.flush_full += 1;
        self.itlb.flush_all();
        self.dtlb.flush_all();
    }

    /// Flush TLB entries matching the given ASID (skip global).
    pub fn flush_tlb_asid(&mut self, asid: u16) {
        self.flush_asid += 1;
        self.itlb.flush_asid(asid);
        self.dtlb.flush_asid(asid);
    }

    /// Flush TLB entries matching the given virtual page (all ASIDs).
    pub const fn flush_tlb_vpage(&mut self, vpage: u32) {
        self.flush_vpage += 1;
        self.itlb.flush_vpage(vpage);
        self.dtlb.flush_vpage(vpage);
    }

    /// Flush TLB entries matching both vpage and ASID.
    pub const fn flush_tlb_vpage_asid(&mut self, vpage: u32, asid: u16) {
        self.flush_vpage_asid += 1;
        self.itlb.flush_vpage_asid(vpage, asid);
        self.dtlb.flush_vpage_asid(vpage, asid);
    }

    /// Snapshot all TLB statistics for display.
    #[must_use]
    pub const fn tlb_stats(&self) -> TlbDisplayStats {
        TlbDisplayStats {
            itlb_misses: self.itlb.misses,
            dtlb_misses: self.dtlb.misses,
            flush_full: self.flush_full,
            flush_asid: self.flush_asid,
            flush_vpage: self.flush_vpage,
            flush_vpage_asid: self.flush_vpage_asid,
        }
    }

    /// Read the mtime CSR via CLINT.
    #[must_use]
    pub fn read_mtime_csr(&self) -> u64 { self.clint.1.read_mtime() }

    /// Write the mtime CSR via CLINT.
    pub fn write_mtime_csr(&mut self, mtime: u64) { self.clint.1.write_mtime(mtime); }

    /// Overwrite CLINT's mtimecmp (cosim). Mirrors the MMIO path: clear
    /// MIP.MTIP and re-raise it iff mtime>=mtimecmp, so cosim gating can
    /// both suppress and force timer interrupts.
    pub fn write_mtimecmp(&mut self, v: u64) {
        use crate::csr::MIP_MTIP;
        self.clint.1.mtimecmp = v;
        self.mip &= !MIP_MTIP;
        if v > 0 && self.clint.1.read_mtime() >= v {
            self.mip |= MIP_MTIP;
        }
    }

    /// Overwrite MIP.SEIP (cosim). Mirrors PLIC→SEIP wiring: set or clear
    /// the bit so cosim can force simmerv's supervisor-external-interrupt
    /// state to match the DUT's independent PLIC/UART state.
    /// Cosim: force a specific IRQ bit into the PLIC's pending (ips) mask,
    /// so PLIC claim reads return the same IRQ as the DUT.
    pub const fn write_plic_ip(&mut self, irq: u32, asserted: bool) {
        self.plic.1.cosim_force_ip(irq, asserted);
    }

    pub const fn write_seip(&mut self, asserted: bool) {
        use crate::csr::MIP_SEIP;
        self.cosim_ext_irq_driven = true;
        if asserted {
            self.mip |= MIP_SEIP;
        } else {
            self.mip &= !MIP_SEIP;
        }
    }

    /// Put CLINT's mtime in frozen mode (cosim): `read_mtime` no longer
    /// advances with wall clock, only with explicit `write_mtime_csr`
    /// calls.
    pub const fn freeze_clint(&mut self, mtime: u64) {
        self.clint.1.frozen = true;
        self.clint.1.mtime_delta = mtime;
    }

    /// Runs one cycle of MMU and peripheral devices.
    ///
    /// # Panics
    /// Panics if the service queue is internally inconsistent (should not
    /// happen in normal operation).
    pub fn service(&mut self, cycle: u64) {
        self.cycle = cycle;
        self.clint.1.service(&mut self.mip);
        let mut all_irqs = [0u32; 16];
        let mut n_irqs: usize = 0;

        loop {
            match self.service_queue.peek() {
                Some(&Reverse((due, _))) if due > cycle => break,
                None => break,
                _ => {}
            }
            let Some(Reverse((_, idx))) = self.service_queue.pop() else {
                break;
            };
            let mut ctx = Context {
                mip: self.mip,
                asserted_irq: None,
                next_service_in: None,
                cycle,
            };
            // Split borrow: self.devices[idx].1 and self.memory are separate fields
            self.devices[idx].1.service(&mut ctx, &mut self.memory);
            self.mip = ctx.mip;
            if let Some(irq) = ctx.asserted_irq
                && n_irqs < all_irqs.len()
            {
                all_irqs[n_irqs] = irq;
                n_irqs += 1;
            }
            if let Some(n) = ctx.next_service_in {
                self.service_queue.push(Reverse((cycle + n as u64, idx)));
            }
        }

        if self.cosim_ext_irq_driven {
            // In cosim: discard simmerv-side PLIC's opinion of MEIP/SEIP; the
            // DUT drives those bits via `write_seip`. Feed a scratch mip to
            // keep PLIC state machine (dirty/best_irq) updated anyway.
            let mut scratch = 0u64;
            self.plic.1.process_irqs(&all_irqs[..n_irqs], &mut scratch);
        } else {
            self.plic.1.process_irqs(&all_irqs[..n_irqs], &mut self.mip);
        }
    }

    /// Updates privilege mode. With permission bits stored in TLB entries
    /// and checked at lookup time, no flush is needed on priv changes.
    pub const fn update_priv_mode(&mut self, mode: PrivMode) { self.prv = mode; }

    /// Loads an byte. This method takes virtual address and translates
    /// into physical address inside.
    ///
    /// # Errors
    /// Returns an `Exception` if the address translation fails.
    pub fn load_virt_u8(&mut self, va: u64) -> Result<u8, Exception> {
        let pa = self.translate_address(va, MemoryAccessType::Read, false)?;
        Ok(self.load_phys_u8(pa))
    }

    /// Loads multiple bytes. This method takes virtual address and translates
    /// into physical address inside.
    fn load_virt_bytes(&mut self, va: u64, width: u64) -> Result<u64, Exception> {
        debug_assert!(
            width == 1 || width == 2 || width == 4 || width == 8,
            "Width must be 1, 2, 4, or 8. {width:X}"
        );
        if va & 0xfff <= 0x1000 - width {
            let pa = self.translate_address(va, MemoryAccessType::Read, false)?;
            Ok(match width {
                1 => u64::from(self.load_phys_u8(pa)),
                2 => u64::from(self.load_phys_u16(pa)),
                4 => u64::from(self.load_phys_u32(pa)),
                8 => self.load_phys_u64(pa),
                _ => panic!("Width must be 1, 2, 4, or 8. {width:X}"),
            })
        } else if self.page_cross_access_traps() {
            Err(Exception {
                trap: Trap::LoadAddressMisaligned,
                tval: va,
            })
        } else {
            let mut data = 0_u64;
            for i in 0..width {
                let byte = self.load_virt_u8(va.wrapping_add(i))?;
                data |= u64::from(byte) << (i * 8);
            }
            Ok(data)
        }
    }

    /// Loads four bytes. This method takes virtual address and translates
    /// into physical address inside.
    ///
    /// # Errors
    /// Returns an `Exception` if the address translation fails.
    #[allow(clippy::cast_possible_truncation)]
    pub fn load_virt_u32(&mut self, va: u64) -> Result<u32, Exception> {
        match self.load_virt_bytes(va, 4) {
            Ok(data) => Ok(data as u32),
            Err(e) => Err(e),
        }
    }

    /// Loads eight bytes. This method takes virtual address and translates
    /// into physical address inside.
    ///
    /// # Errors
    /// Returns an `Exception` if the address translation fails.
    pub fn load_virt_u64(&mut self, va: u64) -> Result<u64, Exception> {
        match self.load_virt_bytes(va, 8) {
            Ok(data) => Ok(data),
            Err(e) => Err(e),
        }
    }

    /// Loads eight bytes as u64. This method takes virtual address and
    /// translates into physical address inside.
    ///
    /// # Errors
    /// Returns an `Exception` if the address translation fails.
    #[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
    pub fn load_virt_u64_(&mut self, va: u64) -> Result<u64, Exception> {
        self.load_virt_bytes(va, 8)
    }

    /// Store an byte. This method takes virtual address and translates
    /// into physical address inside.
    ///
    /// # Errors
    /// Returns an `Exception` if the address translation or store fails.
    pub fn store_virt_u8(&mut self, va: u64, value: u8) -> Result<(), Exception> {
        let pa = self.translate_address(va, MemoryAccessType::Write, false)?;
        self.store_phys_u8(pa, value).map_err(|()| Exception {
            trap: Trap::StoreAccessFault,
            tval: va,
        })
    }

    /// Stores multiple bytes. This method takes a virtual address and
    /// translates it into physical address inside.
    ///
    /// # Errors
    /// Returns an `Exception` if the address translation or store fails.
    ///
    /// # Panics
    /// Panics if `width` is not 1, 2, 4, or 8.
    #[allow(clippy::cast_possible_truncation)]
    pub fn store_virt_bytes(&mut self, va: u64, value: u64, width: u64) -> Result<(), Exception> {
        debug_assert!(
            width == 1 || width == 2 || width == 4 || width == 8,
            "Width must be 1, 2, 4, or 8. {width:X}"
        );
        if va & 0xfff <= 0x1000 - width {
            let pa = self.translate_address(va, MemoryAccessType::Write, false)?;
            let r = match width {
                1 => self.store_phys_u8(pa, value as u8),
                2 => self.store_phys_u16(pa, value as u16),
                4 => self.store_phys_u32(pa, value as u32),
                8 => self.store_phys_u64(pa, value),
                _ => panic!("Width must be 1, 2, 4, or 8. {width:X}"),
            };
            r.map_err(|()| Exception {
                trap: Trap::StoreAccessFault,
                tval: va,
            })
        } else if self.page_cross_access_traps() {
            Err(Exception {
                trap: Trap::StoreAddressMisaligned,
                tval: va,
            })
        } else {
            for i in 0..width {
                self.store_virt_u8(va.wrapping_add(i), ((value >> (i * 8)) & 0xff) as u8)?;
            }
            Ok(())
        }
    }

    /// Stores two bytes. This method takes virtual address and translates
    /// into physical address inside.
    ///
    /// # Errors
    /// Returns an `Exception` if the address translation or store fails.
    pub fn store_virt_u16(&mut self, va: u64, value: u16) -> Result<(), Exception> {
        self.store_virt_bytes(va, u64::from(value), 2)
    }

    /// Stores four bytes. This method takes virtual address and translates
    /// into physical address inside.
    ///
    /// # Errors
    /// Returns an `Exception` if the address translation or store fails.
    pub fn store_virt_u32(&mut self, va: u64, value: u32) -> Result<(), Exception> {
        self.store_virt_bytes(va, u64::from(value), 4)
    }

    /// Stores eight bytes. This method takes virtual address and translates
    /// into physical address inside.
    ///
    /// # Errors
    /// Returns an `Exception` if the address translation or store fails.
    pub fn store_virt_u64(&mut self, va: u64, value: u64) -> Result<(), Exception> {
        self.store_virt_bytes(va, value, 8)
    }

    /// # Errors
    /// If this fails then the error will have the exception that should be
    /// raised
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn store64(&mut self, va: u64, value: u64) -> Result<(), Exception> {
        self.store_virt_bytes(va, value, 8)
    }

    /// Loads a byte from any mapped device (RAM or MMIO).
    #[allow(clippy::cast_possible_truncation, clippy::unwrap_used)]
    pub fn load_phys_u8(&mut self, pa: u64) -> u8 { self.load_mmio_u8(pa).unwrap_or(0) }

    /// # Errors
    /// Returns `Err(())` if no device covers `pa`.
    #[allow(clippy::result_unit_err, clippy::cast_possible_truncation)]
    pub fn load_mmio_u8(&mut self, pa: u64) -> Result<u8, ()> { Ok(self.load_mmio(pa, 1)? as u8) }

    /// Load `size` bytes (1, 2, 4, or 8) from any mapped device as a LE
    /// integer.
    ///
    /// Checks RAM first (fast path), then MMIO devices.
    ///
    /// # Errors
    /// Returns `Err(())` if no device covers `pa`.
    #[allow(
        clippy::result_unit_err,
        clippy::cast_possible_truncation,
        clippy::too_many_lines
    )]
    pub fn load_mmio(&mut self, pa: u64, size: u64) -> Result<u64, ()> {
        // RAM fast path
        for (range, mem) in &self.memory {
            if range.contains(&pa) {
                let end = pa + size;
                if end > range.end {
                    // Cross-boundary: byte by byte
                    let mut val = 0u64;
                    for i in 0..size {
                        let b = self.load_mmio(pa + i, 1)?;
                        val |= b << (i * 8);
                    }
                    return Ok(val);
                }
                let offset = (pa - range.start) as usize;
                let mut buf = [0u8; 8];
                buf[..size as usize].copy_from_slice(&mem[offset..offset + size as usize]);
                return Ok(u64::from_le_bytes(buf));
            }
        }
        // CLINT (named field, not in devices vec)
        if self.clint.0.contains(&pa) {
            let end = pa + size;
            if end > self.clint.0.end {
                let mut val = 0u64;
                for j in 0..size {
                    let b = u64::from(self.load_mmio_u8(pa + j)?);
                    val |= b << (j * 8);
                }
                return Ok(val);
            }
            let base = self.clint.0.start;
            let offset = (pa - base) as usize;
            let mut buf = [0u8; 8];
            let mut ctx = Context {
                mip: self.mip,
                asserted_irq: None,
                next_service_in: None,
                cycle: self.cycle,
            };
            self.clint.1.read(
                &mut ctx,
                base,
                offset,
                size as usize,
                &mut buf[..size as usize],
            );
            self.mip = ctx.mip;
            return Ok(u64::from_le_bytes(buf));
        }
        // PLIC (named field, not in devices vec)
        if self.plic.0.contains(&pa) {
            let end = pa + size;
            if end > self.plic.0.end {
                let mut val = 0u64;
                for j in 0..size {
                    let b = u64::from(self.load_mmio_u8(pa + j)?);
                    val |= b << (j * 8);
                }
                return Ok(val);
            }
            let base = self.plic.0.start;
            let offset = (pa - base) as usize;
            let mut buf = [0u8; 8];
            let mut ctx = Context {
                mip: self.mip,
                asserted_irq: None,
                next_service_in: None,
                cycle: self.cycle,
            };
            self.plic.1.read(
                &mut ctx,
                base,
                offset,
                size as usize,
                &mut buf[..size as usize],
            );
            self.mip = ctx.mip;
            return Ok(u64::from_le_bytes(buf));
        }
        // MMIO devices
        for i in 0..self.devices.len() {
            if self.devices[i].0.contains(&pa) {
                let end = pa + size;
                if end > self.devices[i].0.end {
                    // Cross-boundary: byte by byte
                    let mut val = 0u64;
                    for j in 0..size {
                        let b = u64::from(self.load_mmio_u8(pa + j)?);
                        val |= b << (j * 8);
                    }
                    return Ok(val);
                }
                let base = self.devices[i].0.start;
                let offset = (pa - base) as usize;
                let mut buf = [0u8; 8];
                let mut ctx = Context {
                    mip: self.mip,
                    asserted_irq: None,
                    next_service_in: None,
                    cycle: self.cycle,
                };
                self.devices[i].1.read(
                    &mut ctx,
                    base,
                    offset,
                    size as usize,
                    &mut buf[..size as usize],
                );
                self.mip = ctx.mip;
                if let Some(n) = ctx.next_service_in {
                    self.service_queue.push(Reverse((self.cycle + n as u64, i)));
                }
                return Ok(u64::from_le_bytes(buf));
            }
        }
        Err(())
    }

    #[allow(clippy::cast_possible_truncation)]
    fn load_phys_u16(&mut self, pa: u64) -> u16 { self.load_mmio(pa, 2).unwrap_or(0) as u16 }

    #[allow(clippy::cast_possible_truncation)]
    pub fn load_phys_u32(&mut self, pa: u64) -> u32 { self.load_mmio(pa, 4).unwrap_or(0) as u32 }

    pub fn load_phys_u64(&mut self, pa: u64) -> u64 { self.load_mmio(pa, 8).unwrap_or(0) }

    /// Stores a byte to main memory or peripheral devices depending on
    /// physical address.
    ///
    /// # Errors
    /// Returns `Err(())` if no device covers `pa`.
    #[allow(clippy::result_unit_err)]
    pub fn store_mmio_u8(&mut self, pa: u64, value: u8) -> Result<(), ()> {
        self.store_mmio(pa, u64::from(value), 1)
    }

    /// Store `size` bytes (1, 2, 4, or 8) to any mapped device.
    ///
    /// Checks RAM first (fast path), then MMIO devices.
    ///
    /// # Errors
    /// Returns `Err(())` if no device covers `pa`.
    #[allow(clippy::result_unit_err, clippy::cast_possible_truncation)]
    pub fn store_mmio(&mut self, pa: u64, value: u64, size: u64) -> Result<(), ()> {
        // RAM fast path
        for (range, mem) in &mut self.memory {
            if range.contains(&pa) {
                let end = pa + size;
                if end > range.end {
                    // Cross-boundary fallback
                    let _ = mem; // release borrow — re-borrow per iteration
                    for j in 0..size {
                        self.store_mmio_u8(pa + j, ((value >> (j * 8)) & 0xff) as u8)?;
                    }
                    return Ok(());
                }
                let offset = (pa - range.start) as usize;
                let buf = value.to_le_bytes();
                mem[offset..offset + size as usize].copy_from_slice(&buf[..size as usize]);
                return Ok(());
            }
        }
        // CLINT (named field, not in devices vec)
        if self.clint.0.contains(&pa) {
            let end = pa + size;
            if end > self.clint.0.end {
                for j in 0..size {
                    self.store_mmio_u8(pa + j, ((value >> (j * 8)) & 0xff) as u8)?;
                }
                return Ok(());
            }
            let base = self.clint.0.start;
            let offset = (pa - base) as usize;
            let buf = value.to_le_bytes();
            let mut ctx = Context {
                mip: self.mip,
                asserted_irq: None,
                next_service_in: None,
                cycle: self.cycle,
            };
            self.clint
                .1
                .write(&mut ctx, base, offset, size as usize, &buf[..size as usize]);
            self.mip = ctx.mip;
            return Ok(());
        }
        // PLIC (named field, not in devices vec)
        if self.plic.0.contains(&pa) {
            let end = pa + size;
            if end > self.plic.0.end {
                for j in 0..size {
                    self.store_mmio_u8(pa + j, ((value >> (j * 8)) & 0xff) as u8)?;
                }
                return Ok(());
            }
            let base = self.plic.0.start;
            let offset = (pa - base) as usize;
            let buf = value.to_le_bytes();
            let mut ctx = Context {
                mip: self.mip,
                asserted_irq: None,
                next_service_in: None,
                cycle: self.cycle,
            };
            self.plic
                .1
                .write(&mut ctx, base, offset, size as usize, &buf[..size as usize]);
            self.mip = ctx.mip;
            return Ok(());
        }
        // MMIO devices
        for i in 0..self.devices.len() {
            if self.devices[i].0.contains(&pa) {
                let end = pa + size;
                if end > self.devices[i].0.end {
                    // Cross-boundary fallback
                    for j in 0..size {
                        self.store_mmio_u8(pa + j, ((value >> (j * 8)) & 0xff) as u8)?;
                    }
                    return Ok(());
                }
                let base = self.devices[i].0.start;
                let offset = (pa - base) as usize;
                let buf = value.to_le_bytes();
                let mut ctx = Context {
                    mip: self.mip,
                    asserted_irq: None,
                    next_service_in: None,
                    cycle: self.cycle,
                };
                self.devices[i].1.write(
                    &mut ctx,
                    base,
                    offset,
                    size as usize,
                    &buf[..size as usize],
                );
                self.mip = ctx.mip;
                if let Some(n) = ctx.next_service_in {
                    self.service_queue.push(Reverse((self.cycle + n as u64, i)));
                }
                return Ok(());
            }
        }
        Err(())
    }

    #[allow(clippy::result_unit_err, clippy::missing_errors_doc)]
    pub fn store_phys_u8(&mut self, pa: u64, value: u8) -> Result<(), ()> {
        self.store_mmio_u8(pa, value)
    }

    #[allow(clippy::result_unit_err, clippy::missing_errors_doc)]
    pub fn store_phys_u16(&mut self, pa: u64, value: u16) -> Result<(), ()> {
        self.store_mmio(pa, u64::from(value), 2)
    }

    #[allow(clippy::result_unit_err, clippy::missing_errors_doc)]
    pub fn store_phys_u32(&mut self, pa: u64, value: u32) -> Result<(), ()> {
        self.store_mmio(pa, u64::from(value), 4)
    }

    #[allow(clippy::result_unit_err, clippy::missing_errors_doc)]
    pub fn store_phys_u64(&mut self, pa: u64, value: u64) -> Result<(), ()> {
        self.store_mmio(pa, value, 8)
    }

    /// Extract the current ASID from the SATP register.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    const fn current_asid(&self) -> u16 { ((self.satp >> SATP_ASID_SHIFT) & SATP_ASID_MASK) as u16 }

    /// Find which RAM region contains `pa` and return `(mem_idx,
    /// page_byte_offset)`. `page_byte_offset` is `(pa & !0xfff) -
    /// region.start`, i.e. the byte offset of the start of the containing
    /// page within the region's backing `Vec<u8>`.
    #[allow(clippy::cast_possible_truncation)]
    fn find_ram_for_pa(&self, pa: u64) -> Option<(u8, u64)> {
        for (i, (range, _)) in self.memory.iter().enumerate() {
            if range.contains(&pa) {
                let page_byte_offset = (pa - range.start) & !0xfff;
                return Some((i as u8, page_byte_offset));
            }
        }
        None
    }

    /// # Errors
    /// If this fails then the error will have the exception that should be
    /// raised
    #[allow(clippy::cast_possible_truncation, clippy::missing_panics_doc)]
    pub fn translate_address(
        &mut self,
        address: u64,
        access_type: MemoryAccessType,
        side_effect_free: bool,
    ) -> Result<u64, Exception> {
        if access_type == MemoryAccessType::Execute {
            self.translate_code_address(address)
        } else {
            Ok(self
                .translate_data_address(address, access_type, side_effect_free)?
                .pa)
        }
    }

    /// Translate a fetch (Execute) address. No MPRV, uses iTLB.
    ///
    /// # Errors
    /// Returns an `Exception` if the address translation fails.
    #[allow(
        clippy::inline_always,
        clippy::cast_possible_truncation,
        clippy::missing_panics_doc
    )]
    #[inline(always)]
    pub fn translate_code_address(&mut self, address: u64) -> Result<u64, Exception> {
        if self.prv == PrivMode::M
            || (self.satp >> SATP_MODE_SHIFT) & SATP_MODE_MASK == SatpMode::Bare as u64
        {
            return Ok(address);
        }

        let vpage = (address >> PG_SHIFT) as u32;
        let asid = self.current_asid();

        if let Some((ppage, perm)) = self.itlb.lookup(vpage, asid) {
            let prv_is_user = self.prv == PrivMode::U;
            let sum = self.mstatus & MSTATUS_SUM != 0;
            let mxr = self.mstatus & MSTATUS_MXR != 0;
            if check_perm(perm, 2, prv_is_user, sum, mxr) {
                let tlb_pa = (u64::from(ppage) << PG_SHIFT) | (address & 0xfff);
                if cfg!(feature = "paranoid-tlb") {
                    let slow =
                        self.translate_address_slow(address, MemoryAccessType::Execute, true);
                    match slow {
                        Ok((expected_pa, _)) => assert_eq!(
                            tlb_pa, expected_pa,
                            "iTLB hit pa {tlb_pa:#x} != walk pa {expected_pa:#x} \
                             for va {address:#x} asid {asid}"
                        ),
                        Err(e) => panic!(
                            "iTLB hit pa {tlb_pa:#x} but walk faulted {:?} \
                             for va {address:#x} asid {asid} perm {perm:#06x}",
                            e.trap
                        ),
                    }
                }
                return Ok(tlb_pa);
            }
        }

        self.itlb.misses += 1;
        let (pa, pte) = self.translate_address_slow(address, MemoryAccessType::Execute, false)?;
        if pte != 0 {
            let ppage = (pa >> PG_SHIFT) as u32;
            let xwr = ((pte >> 1) & 7) as u8;
            let user = pte & PTE_U_MASK != 0;
            let global = pte & (1 << 5) != 0;
            let perm = pack_perm(xwr, user, global, asid);
            self.itlb.insert(vpage, ppage, perm, asid);
        }
        Ok(pa)
    }

    /// smolrv64 performs a single dTLB translation per data access, so a
    /// load/store whose byte range crosses a 4 KiB page boundary cannot be
    /// serviced in hardware and traps as address-misaligned (M-mode firmware
    /// then emulates it byte-by-byte). This only applies with Sv39 paging
    /// active and effective privilege below M — mirrors smolrv64.v's
    /// `csr_satp[63:60]==8 && eff_prv!=M && mem_addr[11:0]+bytes>4096` check.
    #[must_use]
    pub fn page_cross_access_traps(&self) -> bool {
        let effective_prv = if self.mstatus & MSTATUS_MPRV != 0 {
            priv_mode_from((self.mstatus >> MSTATUS_MPP_SHIFT) & 3)
        } else {
            self.prv
        };
        effective_prv != PrivMode::M
            && (self.satp >> SATP_MODE_SHIFT) & SATP_MODE_MASK == SatpMode::Sv39 as u64
    }

    /// Translate a load or store address. Handles MPRV, uses dTLB.
    ///
    /// On a dTLB hit to a RAM page, `mem_idx` and `page_byte_offset` in the
    /// returned [`DataAddr`] are valid — callers can access
    /// `memory[mem_idx].1[page_byte_offset | (va & 0xfff)]` directly.
    /// MMIO and physical-mode accesses return `mem_idx == DataAddr::NO_RAM`.
    ///
    /// # Errors
    /// Returns an `Exception` if the address translation fails.
    #[allow(
        clippy::inline_always,
        clippy::cast_possible_truncation,
        clippy::missing_panics_doc
    )]
    #[inline(always)]
    pub fn translate_data_address(
        &mut self,
        address: u64,
        access_type: MemoryAccessType,
        side_effect_free: bool,
    ) -> Result<DataAddr, Exception> {
        let effective_prv = if self.mstatus & MSTATUS_MPRV != 0 {
            priv_mode_from((self.mstatus >> MSTATUS_MPP_SHIFT) & 3)
        } else {
            self.prv
        };

        if effective_prv == PrivMode::M
            || (self.satp >> SATP_MODE_SHIFT) & SATP_MODE_MASK == SatpMode::Bare as u64
        {
            return Ok(DataAddr {
                pa: address,
                mem_idx: DataAddr::NO_RAM,
                page_byte_offset: 0,
            });
        }

        let vpage = (address >> PG_SHIFT) as u32;
        let asid = self.current_asid();
        let access_shift = u32::from(access_type == MemoryAccessType::Write);

        if let Some((mem_idx, page_byte_offset, perm)) = self.dtlb.lookup(vpage, asid) {
            let prv_is_user = effective_prv == PrivMode::U;
            let sum = self.mstatus & MSTATUS_SUM != 0;
            let mxr = self.mstatus & MSTATUS_MXR != 0;
            if check_perm(perm, access_shift, prv_is_user, sum, mxr) {
                // Reconstruct pa for the paranoid check and for callers that only need pa.
                let pa =
                    self.memory[mem_idx as usize].0.start + page_byte_offset + (address & 0xfff);
                if cfg!(feature = "paranoid-tlb") {
                    let slow = self.translate_address_slow(address, access_type, true);
                    match slow {
                        Ok((expected_pa, _)) => assert_eq!(
                            pa, expected_pa,
                            "dTLB hit pa {pa:#x} != walk pa {expected_pa:#x} \
                             for va {address:#x} access {access_type:?} \
                             prv {effective_prv:?} asid {asid}"
                        ),
                        Err(e) => panic!(
                            "dTLB hit pa {pa:#x} but walk faulted {:?} \
                             for va {address:#x} access {access_type:?} \
                             prv {effective_prv:?} asid {asid} perm {perm:#06x}",
                            e.trap
                        ),
                    }
                }
                return Ok(DataAddr {
                    pa,
                    mem_idx,
                    page_byte_offset,
                });
            }
        }

        self.dtlb.misses += 1;
        let (pa, pte) = self.translate_address_slow(address, access_type, side_effect_free)?;
        if !side_effect_free && pte != 0 {
            let mut xwr = ((pte >> 1) & 7) as u8;
            // When using SW-managed A/D, mask out W if D is not set so
            // that future writes still fault through the slow path.
            if CONFIG_SW_MANAGED_A_AND_D && pte & PTE_D_MASK == 0 {
                xwr &= !2; // clear W
            }
            let user = pte & PTE_U_MASK != 0;
            let global = pte & (1 << 5) != 0;
            let perm = pack_perm(xwr, user, global, asid);
            // Only RAM pages go into the dTLB; MMIO pages use the slow path every time.
            if let Some((mem_idx, page_byte_offset)) = self.find_ram_for_pa(pa) {
                self.dtlb
                    .insert(vpage, mem_idx, page_byte_offset, perm, asid);
                return Ok(DataAddr {
                    pa,
                    mem_idx,
                    page_byte_offset,
                });
            }
        }
        Ok(DataAddr {
            pa,
            mem_idx: DataAddr::NO_RAM,
            page_byte_offset: 0,
        })
    }

    #[allow(
        clippy::cast_possible_wrap,
        clippy::too_many_lines,
        clippy::expect_used,
        clippy::cognitive_complexity
    )]
    /// Slow-path page table walk.  Returns `(physical_address, leaf_pte)`.
    /// The leaf PTE is needed by the caller to populate TLB permission bits.
    fn translate_address_slow(
        &mut self,
        va: u64,
        access: MemoryAccessType,
        side_effect_free: bool,
    ) -> Result<(u64, u64), Exception> {
        let prv = self.prv;
        let effective_prv =
            if self.mstatus & MSTATUS_MPRV != 0 && access != MemoryAccessType::Execute {
                // Use previous privilege
                priv_mode_from((self.mstatus >> MSTATUS_MPP_SHIFT) & 3)
            } else {
                prv
            };

        let satp_mode = ((self.satp >> SATP_MODE_SHIFT) & SATP_MODE_MASK) as usize;
        if effective_prv == PrivMode::M || satp_mode == SatpMode::Bare as usize {
            return Ok((va, 0));
        }

        // Sv39, Sv48, Sv57
        let levels = 3 + satp_mode - SatpMode::Sv39 as usize;
        let access_shift = match access {
            MemoryAccessType::Read => 0,
            MemoryAccessType::Write => 1,
            MemoryAccessType::Execute => 2,
        };

        let pte_size_log2 = 3;
        let vaddr_shift = 64 - (PG_SHIFT + levels * 9);
        // Check for canonical addresses
        if ((va as i64) << vaddr_shift) >> vaddr_shift != va as i64 {
            return page_fault(va, access);
        }
        let pte_addr_bits = 44;
        let page_table_root = (self.satp >> SATP_PPN_SHIFT) & SATP_PPN_MASK;
        let mut pte_addr = (page_table_root & ((1 << pte_addr_bits) - 1)) << PG_SHIFT;
        let pte_bits = 12 - pte_size_log2;
        let pte_mask = (1 << pte_bits) - 1;

        for i in 0..levels {
            let vaddr_shift = PG_SHIFT + pte_bits * (levels - 1 - i);
            let pte_idx = (va >> vaddr_shift) & pte_mask;
            pte_addr += pte_idx << pte_size_log2;
            let pte = self.load_phys_u64(pte_addr);

            if pte & PTE_V_MASK == 0 {
                trace!("** {prv:?} mode access to {va:08x} denied: invalid PTE");
                break;
            }

            let paddr = (pte >> 10) << PG_SHIFT;
            let mut xwr = (pte >> 1) & 7;
            if xwr == 0 {
                pte_addr = paddr;
                continue;
            }

            // *** Found a leaf node ***

            if xwr == 2 || xwr == 6 {
                trace!("** {prv:?} mode access to {va:08x} denied: invalid xwr {xwr}");
                break;
            }

            // priviledge check
            if effective_prv == PrivMode::S {
                if pte & PTE_U_MASK != 0 && self.mstatus & MSTATUS_SUM == 0 {
                    warn!("** {prv:?} mode access to {va:08x} denied: U & !SUM");
                    break;
                }
            } else if pte & PTE_U_MASK == 0 {
                warn!("** {prv:?} mode access to {va:08x} denied: !U");
                return page_fault(va, access);
            }

            /* protection check */
            /* MXR allows read access to execute-only pages */
            if self.mstatus & MSTATUS_MXR != 0 {
                xwr |= xwr >> 2;
            }

            if xwr >> access_shift & 1 == 0 {
                let want = 1 << access_shift;
                trace!("** {prv:?} mode access to {va:08x} denied: want {want}, got {xwr}");
                break;
            }

            /* 6. Check for misaligned superpages */
            let ppn = pte >> 10;
            let j = levels - 1 - i;
            if ((1 << j) - 1) & ppn != 0 {
                warn!("** access to {va:08x} denied: misaligned superpage {i} / {ppn}");
                break;
            }

            if CONFIG_SW_MANAGED_A_AND_D {
                if pte & PTE_A_MASK == 0 {
                    trace!("** {prv:?} mode access to {va:08x} denied: missing A");
                    break;
                }
                if access == MemoryAccessType::Write && pte & PTE_D_MASK == 0 {
                    trace!("** {prv:?} mode access to {va:08x} denied: missing D");
                    break;
                }
            } else {
                let mut new_pte = pte | PTE_A_MASK;
                if access == MemoryAccessType::Write {
                    new_pte |= PTE_D_MASK;
                }
                if pte != new_pte
                    && !side_effect_free
                    && self.store_phys_u64(pte_addr, new_pte).is_err()
                {
                    return access_fault(va, access);
                }
            }

            let vaddr_mask = (1 << vaddr_shift) - 1;
            return Ok((paddr & !vaddr_mask | va & vaddr_mask, pte));
        }

        page_fault(va, access)
    }

    // --- Snapshot ---

    /// Serialises MMU state (SIMMERVC3 format).
    #[allow(clippy::cast_possible_truncation)]
    pub fn write_state(&self, out: &mut Vec<u8>) {
        {
            let mut w = Pack::new(out);
            w.u8(u64::from(self.prv) as u8);
            w.u64(self.mstatus);
            w.u64(self.mip);
            w.u64(self.satp);
            // Memory regions
            w.u64(self.memory.len() as u64);
        }
        for (range, mem) in &self.memory {
            let mut w = Pack::new(out);
            w.u64(range.start);
            w.u64(range.end);
            w.bytes(mem);
        }
        // Save CLINT and PLIC separately (not counted in device_count)
        self.clint.1.save(self.clint.0.start, self.clint.0.end, out);
        self.plic.1.save(self.plic.0.start, self.plic.0.end, out);
        {
            let mut w = Pack::new(out);
            w.u64(self.devices.len() as u64);
        }
        // Save remaining devices (DTB, VirtIO, UART, …)
        for (range, device) in &self.devices {
            device.save(range.start, range.end, out);
        }
        // Service queue
        {
            let mut w = Pack::new(out);
            w.u64(self.service_queue.len() as u64);
            w.u64(self.cycle);
        }
        for &Reverse((sched_cycle, idx)) in &self.service_queue {
            let mut w = Pack::new(out);
            w.u64(sched_cycle);
            w.u64(idx as u64);
        }
    }

    /// Restores MMU state from a blob produced by `write_state`.
    ///
    /// `make_device(name, range)` is called for each device in the snapshot;
    /// it must return a freshly-created device of the right type.
    ///
    /// # Errors
    /// Returns `Err(())` on truncation, unknown device name, or corrupt data.
    #[allow(clippy::result_unit_err, clippy::cast_possible_truncation)]
    pub fn read_state(
        &mut self,
        data: &[u8],
        mut make_device: impl FnMut(&str, Range<u64>) -> Option<Box<dyn MemoryMapped>>,
    ) -> Result<(), ()> {
        let mut r = Unpack::new(data);

        self.prv = riscv::PrivMode::try_from(u64::from(r.u8()?))?;
        self.mstatus = r.u64()?;
        self.mip = r.u64()?;
        self.satp = r.u64()?;

        // Restore memory regions
        self.memory.clear();
        let mem_count = r.u64()? as usize;
        for _ in 0..mem_count {
            let base = r.u64()?;
            let end = r.u64()?;
            let bytes = r.bytes()?;
            self.memory.push((base..end, bytes));
        }

        // Restore CLINT (leading record, not counted in device_count)
        {
            let name_raw = r.raw(32)?;
            let _base = r.u64()?;
            let _end = r.u64()?;
            let state_size = r.u64()? as usize;
            let state = r.raw(state_size)?;
            let name_len = name_raw.iter().position(|&b| b == 0).unwrap_or(32);
            let name = std::str::from_utf8(&name_raw[..name_len]).map_err(|_| ())?;
            if name != "SiFive CLINT" {
                return Err(());
            }
            self.clint.1.restore_state(&mut Unpack::new(state))?;
        }

        // Restore PLIC (second leading record, not counted in device_count)
        {
            let name_raw = r.raw(32)?;
            let _base = r.u64()?;
            let _end = r.u64()?;
            let state_size = r.u64()? as usize;
            let state = r.raw(state_size)?;
            let name_len = name_raw.iter().position(|&b| b == 0).unwrap_or(32);
            let name = std::str::from_utf8(&name_raw[..name_len]).map_err(|_| ())?;
            if name != "SiFive PLIC" {
                return Err(());
            }
            self.plic.1.restore_state(&mut Unpack::new(state))?;
        }

        // Restore remaining devices
        self.devices.clear();
        self.service_queue.clear();
        let device_count = r.u64()? as usize;
        for _ in 0..device_count {
            let name_raw = r.raw(32)?;
            let base = r.u64()?;
            let end = r.u64()?;
            let state_size = r.u64()? as usize;
            let state = r.raw(state_size)?;

            let name_len = name_raw.iter().position(|&b| b == 0).unwrap_or(32);
            let name = std::str::from_utf8(&name_raw[..name_len]).map_err(|_| ())?;

            let mut dev = make_device(name, base..end).ok_or(())?;
            dev.restore_state(&mut Unpack::new(state))?;
            self.devices.push((base..end, dev));
        }

        // Restore service queue
        let queue_len = r.u64()? as usize;
        let cycle = r.u64()?;
        self.cycle = cycle;
        for _ in 0..queue_len {
            let sched_cycle = r.u64()?;
            let idx = r.u64()? as usize;
            self.service_queue.push(Reverse((sched_cycle, idx)));
        }

        self.flush_tlb();
        Ok(())
    }

    /// Extracts the network backend from whichever device owns it.
    pub fn take_net_backend(&mut self) -> Option<Box<dyn crate::network_backend::NetworkBackend>> {
        self.devices
            .iter_mut()
            .find_map(|(_, dev)| dev.take_net_backend())
    }

    /// Extracts the serial backend from whichever device owns it.
    pub fn take_uart_backend(&mut self) -> Option<Box<dyn SerialBackend>> {
        self.devices
            .iter_mut()
            .find_map(|(_, dev)| dev.take_backend())
    }

    /// Returns mutable reference to the serial backend, if any device has one.
    pub fn get_mut_serial_backend(&mut self) -> Option<&mut dyn SerialBackend> {
        self.devices.iter_mut().find_map(|(_, d)| d.backend())
    }

    /// Returns mutable reference to the backend (alias for
    /// `get_mut_serial_backend`).
    pub fn get_mut_backend(&mut self) -> Option<&mut dyn SerialBackend> {
        self.get_mut_serial_backend()
    }

    /// Returns a mutable slice into the backing RAM covering `[pa, pa+size)`.
    ///
    /// # Errors
    /// Returns `Err(())` if no RAM region covers the range.
    #[allow(clippy::result_unit_err)]
    pub fn dma_slice(&mut self, pa: u64, size: usize) -> Result<&mut [u8], ()> {
        crate::device::dma_slice(&mut self.memory, pa, size).ok_or(())
    }
}

const fn page_fault<T>(address: u64, access_type: MemoryAccessType) -> Result<T, Exception> {
    Err::<T, Exception>(Exception {
        trap: match access_type {
            MemoryAccessType::Read => Trap::LoadPageFault,
            MemoryAccessType::Write => Trap::StorePageFault,
            MemoryAccessType::Execute => Trap::InstructionPageFault,
        },
        tval: address,
    })
}

const fn access_fault<T>(address: u64, access_type: MemoryAccessType) -> Result<T, Exception> {
    Err::<T, Exception>(Exception {
        trap: match access_type {
            MemoryAccessType::Read => Trap::LoadAccessFault,
            MemoryAccessType::Write => Trap::StoreAccessFault,
            MemoryAccessType::Execute => Trap::InstructionAccessFault,
        },
        tval: address,
    })
}
