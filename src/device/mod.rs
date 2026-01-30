#![allow(unused_variables, dead_code, clippy::cast_possible_truncation)]

use std::ops::Range;

pub mod clint;
pub mod plic;
pub mod uart;
pub mod virtio_block_disk;

// Memory Mapped Devices, the next generation
// Note, inspired by PCI, devices knows a lot about themselves
// XXX Open questions:
// - devices with interrupts, how do they change IRQ?
// - do they know they IRQ number(s)?
// - how do they schedule new service requests?
pub trait MemoryMapped {
    fn save(&self); // XXX TBD serialization (Serde?)
    fn restore(&mut self);
    fn read(&mut self, context: &mut Context, offset: u64, size: u64, data: &mut [u8]); // XXX What should be the error behavior?
    fn write(&mut self, context: &mut Context, offset: u64, size: u64, data: &[u8]); // XXX What should be the error behavior?
    fn service(&mut self, context: &mut Context);
    fn extent(&self) -> Range<u64>;
    fn info(&self) -> MemoryMappedInfo;
}

pub struct MemoryMappedInfo {
    pub name: String,
    pub irqs: Vec<usize>,
    pub cachable: bool,
}

pub struct Context {
    irq: Option<bool>, // XXX TBD, should this be just bool?
    schedule_update: Option<usize>,
}

const UART_SERVICE_INTERVAL: usize = 10000; // Effectively how often we look for input

// Wrap the existing UART just as an example
impl MemoryMapped for uart::Uart {
    fn save(&self) {
        todo!("serialize the Uart structure");
    }
    fn restore(&mut self) {
        todo!("deserialize the Uart structure");
    }

    fn read(&mut self, context: &mut Context, offset: u64, size: u64, data: &mut [u8]) {
        for i in 0..size {
            data[i as usize] = self.load(offset + i + 0x10000000);
        }
        context.irq = Some(self.is_interrupting());
    }

    fn write(&mut self, context: &mut Context, offset: u64, size: u64, data: &[u8]) {
        for i in 0..size {
            self.store(offset + i + 0x10000000, data[i as usize]);
        }
        context.irq = Some(self.is_interrupting());
    }

    fn service(&mut self, context: &mut Context) {
        self.service();
        context.irq = Some(self.is_interrupting());
        context.schedule_update = Some(UART_SERVICE_INTERVAL);
    }

    fn extent(&self) -> Range<u64> { 0x10000000..0x10000008 }

    fn info(&self) -> MemoryMappedInfo {
        MemoryMappedInfo {
            name: "uart".into(),
            irqs: vec![],
            cachable: false,
        }
    }
}

type DeviceMap<'a> = Vec<(u64, u64, &'a mut dyn MemoryMapped)>;

fn read(devices: &mut DeviceMap, context: &mut Context, addr: u64, size: u64, data: &mut [u8]) {
    let end = addr + size;
    for (i, (dev_base, dev_end, d)) in devices.iter_mut().enumerate() {
        if *dev_base < end && addr < *dev_end {
            if addr < *dev_base || *dev_end < end {
                todo!(
                    "handle the weird cases access \
                       [{addr:#x}; {end:#x}) to dev {i}:[{dev_base:#x}; {dev_end:#x})"
                );
            }
            d.read(context, addr - *dev_base, size, data);
            return;
        }
    }

    for d in data.iter_mut() {
        *d = 0xff;
    }
    log::warn!(
        "Read from unknown device in [{addr:#x}, {:#x}]",
        addr + size
    );
}
