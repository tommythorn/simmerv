//! Block storage fetched on demand by the host, with a copy-on-write overlay.
//!
//! This is the browser counterpart of [`url_disk`](crate::device::url_disk).
//! The shape is the same — a block cache over a read-only base image plus an
//! overlay for writes — but the fetching is inverted: `url_disk` blocks on a
//! synchronous HTTP request, which no browser permits on the main thread.
//! Here the emulator never waits. A read whose blocks are absent records them
//! as *wanted* and reports itself not-resident, which makes
//! `VirtioBlockDisk::try_handle_disk_access` leave the request in the
//! virtqueue. JavaScript drains the wanted list, issues `Range` requests, and
//! hands blocks back through `provide`; the retry then completes normally.
//!
//! The guest just sees a slow disk, which is what a virtqueue is for.
//!
//! Only the touched blocks are ever transferred: booting Debian to a login
//! prompt reads about 12% of a 208 MB image.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::rc::Rc;

use super::virtio_block_disk::SECTOR_SIZE;

/// Shared between the block device and whoever feeds it blocks.
///
/// `Rc`/`RefCell` rather than `Arc`/`Mutex`: the intended host is a browser,
/// which is single-threaded, and nothing here needs to cross threads.
pub type StreamedHandle = Rc<RefCell<StreamedStorage>>;

pub struct StreamedStorage {
    /// Size of the base image in bytes, told to us up front (the guest needs a
    /// capacity at probe time, long before any block has arrived).
    len: u64,
    /// Fetch granularity. Wants to match the squashfs block size: too small
    /// and each miss costs a round trip, too large and every miss drags in
    /// slack.
    block_size: u64,
    /// Base-image blocks that have arrived, keyed by block index.
    blocks: BTreeMap<u64, Vec<u8>>,
    /// Blocks a read has asked for that have not arrived yet.
    wanted: BTreeSet<u64>,
    /// Written sectors. Writes never go back to the server.
    overlay: BTreeMap<u64, [u8; SECTOR_SIZE]>,
}

impl StreamedStorage {
    #[must_use]
    pub fn new(len: u64, block_size: u64) -> StreamedHandle {
        Rc::new(RefCell::new(Self {
            len,
            block_size: block_size.max(SECTOR_SIZE as u64),
            blocks: BTreeMap::new(),
            wanted: BTreeSet::new(),
            overlay: BTreeMap::new(),
        }))
    }

    #[must_use]
    pub const fn sector_count(&self) -> u64 { self.len / SECTOR_SIZE as u64 }

    #[must_use]
    pub const fn block_size(&self) -> u64 { self.block_size }

    /// Block indices spanned by `[offset, offset + len)`, clamped to the image.
    fn block_range(&self, offset: u64, len: usize) -> std::ops::RangeInclusive<u64> {
        let last = offset
            .saturating_add(len as u64)
            .saturating_sub(1)
            .min(self.len.saturating_sub(1));
        (offset / self.block_size)..=(last / self.block_size)
    }

    /// Whether a read can be served now. Blocks that are missing are recorded
    /// as wanted, so asking is also what triggers the fetch.
    ///
    /// Sectors already in the overlay are satisfied from there and need no
    /// base block — a guest that overwrites a region never pulls it.
    pub fn is_resident(&mut self, offset: u64, len: usize) -> bool {
        if offset >= self.len {
            return true; // reads past the end are answered with zeros
        }
        let mut ready = true;
        for block in self.block_range(offset, len) {
            if self.blocks.contains_key(&block) {
                continue;
            }
            // A block wholly covered by the overlay is never needed.
            let start = block * self.block_size;
            let end = (start + self.block_size).min(self.len);
            let covered = (start / SECTOR_SIZE as u64..end.div_ceil(SECTOR_SIZE as u64))
                .all(|s| self.overlay.contains_key(&s));
            if covered {
                continue;
            }
            self.wanted.insert(block);
            ready = false;
        }
        ready
    }

    /// Blocks the device is waiting for, removed from the list as they are
    /// handed out so the same block is not fetched twice concurrently.
    pub fn take_wanted(&mut self) -> Vec<u64> {
        std::mem::take(&mut self.wanted).into_iter().collect()
    }

    /// Supplies a fetched block. Ignores blocks that already arrived.
    pub fn provide(&mut self, block: u64, bytes: Vec<u8>) {
        self.wanted.remove(&block);
        self.blocks.entry(block).or_insert(bytes);
    }

    /// Reads from the base image, zero-filling anything not present. Callers
    /// are expected to have checked [`Self::is_resident`] first; a miss here
    /// would silently read zeros, so it is worth a log.
    fn base_read(&self, offset: u64, buf: &mut [u8]) {
        let mut done = 0usize;
        while done < buf.len() {
            let cur = offset + done as u64;
            if cur >= self.len {
                buf[done..].fill(0);
                return;
            }
            let block = cur / self.block_size;
            let within = (cur % self.block_size) as usize;
            let n = (self.block_size as usize - within).min(buf.len() - done);
            if let Some(b) = self.blocks.get(&block) {
                let avail = b.len().saturating_sub(within);
                let take = n.min(avail);
                buf[done..done + take].copy_from_slice(&b[within..within + take]);
                buf[done + take..done + n].fill(0);
            } else {
                log::warn!("streamed disk: read of block {block} before it arrived");
                buf[done..done + n].fill(0);
            }
            done += n;
        }
    }

    /// Reads `buf.len()` bytes at `offset`, preferring written sectors.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) {
        let mut done = 0usize;
        while done < buf.len() {
            let cur = offset + done as u64;
            let sector = cur / SECTOR_SIZE as u64;
            let within = (cur % SECTOR_SIZE as u64) as usize;
            let n = (SECTOR_SIZE - within).min(buf.len() - done);
            if let Some(sec) = self.overlay.get(&sector) {
                buf[done..done + n].copy_from_slice(&sec[within..within + n]);
            } else {
                self.base_read(cur, &mut buf[done..done + n]);
            }
            done += n;
        }
    }

    /// Writes into the overlay only. A partial write of a sector that is not
    /// yet in the overlay needs the base sector first; if it has not arrived
    /// the surrounding bytes read as zero, so the caller checks residency for
    /// writes too.
    pub fn write_at(&mut self, offset: u64, data: &[u8]) {
        let mut done = 0usize;
        while done < data.len() {
            let cur = offset + done as u64;
            let sector = cur / SECTOR_SIZE as u64;
            let within = (cur % SECTOR_SIZE as u64) as usize;
            let n = (SECTOR_SIZE - within).min(data.len() - done);
            if !self.overlay.contains_key(&sector) {
                let mut sec = [0u8; SECTOR_SIZE];
                if within != 0 || n != SECTOR_SIZE {
                    self.base_read(sector * SECTOR_SIZE as u64, &mut sec);
                }
                self.overlay.insert(sector, sec);
            }
            if let Some(sec) = self.overlay.get_mut(&sector) {
                sec[within..within + n].copy_from_slice(&data[done..done + n]);
            }
            done += n;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BS: u64 = 65536;

    fn store(len: u64) -> StreamedHandle { StreamedStorage::new(len, BS) }

    /// Block `n` filled with a recognisable pattern.
    fn block(n: u64) -> Vec<u8> { vec![(n as u8).wrapping_add(1); BS as usize] }

    #[test]
    fn absent_blocks_are_reported_wanted_and_not_resident() {
        let s = store(4 * BS);
        // A read spanning two blocks should want both.
        assert!(!s.borrow_mut().is_resident(BS - 512, 1024));
        let mut wanted = s.borrow_mut().take_wanted();
        wanted.sort_unstable();
        assert_eq!(wanted, vec![0, 1]);
        // Draining clears the list, so a block in flight is not asked for twice.
        assert!(s.borrow_mut().take_wanted().is_empty());
    }

    #[test]
    fn a_provided_block_becomes_resident_and_readable() {
        let s = store(4 * BS);
        assert!(!s.borrow_mut().is_resident(0, 512));
        s.borrow_mut().provide(0, block(0));
        assert!(s.borrow_mut().is_resident(0, 512));

        let mut buf = [0u8; 512];
        s.borrow().read_at(0, &mut buf);
        assert_eq!(buf, [1u8; 512]);
    }

    #[test]
    fn reads_past_the_end_are_resident_and_zero() {
        let s = store(2 * BS);
        assert!(s.borrow_mut().is_resident(4 * BS, 512));
        let mut buf = [0xFFu8; 512];
        s.borrow().read_at(4 * BS, &mut buf);
        assert_eq!(buf, [0u8; 512]);
    }

    #[test]
    fn writes_go_to_the_overlay_and_are_read_back() {
        let s = store(4 * BS);
        s.borrow_mut().provide(0, block(0));
        s.borrow_mut().write_at(0, &[0xAA; 512]);

        let mut buf = [0u8; 1024];
        s.borrow().read_at(0, &mut buf);
        assert_eq!(
            &buf[..512],
            &[0xAA; 512],
            "overlay wins over the base image"
        );
        assert_eq!(
            &buf[512..],
            &[1u8; 512],
            "the rest still comes from the base"
        );
    }

    /// A region the guest has entirely overwritten never needs fetching --
    /// otherwise a freshly formatted disk would pull the whole image.
    #[test]
    fn fully_overwritten_blocks_are_never_fetched() {
        let s = store(2 * BS);
        s.borrow_mut().provide(0, block(0));
        for sector in 0..(BS as usize / SECTOR_SIZE) {
            s.borrow_mut()
                .write_at(sector as u64 * SECTOR_SIZE as u64, &[0xCD; SECTOR_SIZE]);
        }
        // Drop the base block; the overlay alone must satisfy the read.
        let mut inner = s.borrow_mut();
        inner.blocks.clear();
        assert!(inner.is_resident(0, BS as usize));
        assert!(inner.take_wanted().is_empty());
        drop(inner);

        let mut buf = [0u8; 512];
        s.borrow().read_at(0, &mut buf);
        assert_eq!(buf, [0xCD; 512]);
    }

    #[test]
    fn capacity_is_known_before_any_block_arrives() {
        let s = store(100 * SECTOR_SIZE as u64);
        assert_eq!(s.borrow().sector_count(), 100);
    }
}
