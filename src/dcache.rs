#![allow(clippy::cast_possible_truncation)]

//! Directly Mapped virtually index and virtually and physically
//! mapped with lazy invalidation
//!
//! # A Quick Primer on Caches
//!
//! A cache stores a subset of physical memory (the "backing memory")
//! in a smaller, faster memory.  The challenge is doing this with as
//! little overhead as possible and, of course, be transparent, that
//! is, getting the same result as we had accessed the memory
//! directly.
//!
//! To reduce the overhead of we divide the memory into blocks (called
//! "lines") and track the mapping at that level.  Common line sizes
//! are (32, 64, and 128 are common size, with 64 being the most
//! popular choice by a large margin.
//!
//! Associativity determines where in the cache a line may be mapped.
//! Fully associative cache can map them anywhere whereas N-way
//! associative caches divides the cache into N sets and restricts all
//! lines to a particular location in any of the N sets.  Directly
//! mapped caches are the special case where N=1.  As associativity
//! determines how many places we should search for a line, the
//! smaller it is, the cheaper the implementation.
//!
//! The handling of writes offers several choices:
//!
//! - A "write-through" cache keeps the backing memory consistent by immediately
//!   writing back any updates, whereas
//!
//! - a "write-back" cache delays the backing memory write until a later time.
//!
//! - A "write-back" cache usually implement "dirty" bits to avoid having to
//!   write back clean lines.
//!
//! - For "write-back" caches, when a write arrives for data not in the cache, a
//!   "write-allocate" policy would fetch the line into the cache before writing
//!   in, as opposed to just writing the backing memory directly.  (Instructions
//!   can provide temporal hints to direct the policy on a per-write basis).
//!
//! ## Virtual Memory
//!
//! Virtual memory presents a fictive "virtual" view of memory that is
//! mapped to physical (supports process isolation and more).  Memory
//! is mapped at the "page" level (commonly 4096 bytes, but other
//! larger powers-of-two are also used), to reduce the overheads.
//! Each page mapping may have different write, read, and execute
//! privileges.
//!
//! When the two or more virtual pages are mapped to the same physical
//! page, they are said to "alias".
//!
//! ## Virtual Memory Caches
//!
//! For virtual memory we would conceptually first translate the
//! virtual address to physical and then address the cache with a
//! physical address, but there are opportunites to improve on this.
//! The parts of the address that correspond to the offset within the
//! page are not translated and thus can be use to index [part of] the
//! cache.  A very common caching scheme is to divide the cache into
//! as many sets as needed such that each set is a page.  The leads to
//! a Virtually Indexed, Physically Tagged (VIPT) cache where cache
//! access is done in parallel with virtual-to-physical translation,
//! followed by picking the cache way that had a match, if any.
//!
//! # A VIVPT cache with lazy invalidation
//!
//! The virtual-to-physical translation is expensive so we are using a
//! hybrid of VIVT and VIPT: we mostly use the virtual tags, except
//! for when we have to write back dirty lines and when we have to
//! check for aliases. (Technically having multiple _clean_ aliased
//! lines resident in the cache isn't a problem, but to keep the cache
//! consistent we can't have any aliases of a dirty line).
//!
//! ## Mapping Updates and Lazy Invalidation
//!
//! A particular complication occurs when the virtual mapping is
//! updated which means some of the lines virtual tags might be
//! invalid.  Rather than flushing the entire cache and forcing an
//! expensive reload we mark every line as needing a re-validation
//! which forces accesses to check the virtual tags is still valid and
//! flush the line if it isn't.

pub const PAGESIZE: usize = 4096;
pub const LINESIZE: usize = 64;
pub const CACHESIZE: usize = 65536;
pub const LINES: usize = CACHESIZE / LINESIZE;
pub const INVALID_PPN: usize = !0;

pub trait Context {
    fn read_line(&self, phys_line_addr: usize, line: &mut [u8; LINESIZE]);
    fn write_line(&mut self, phys_line_addr: usize, line: &[u8; LINESIZE]);
    fn virt2phys_pageno(&self, vpn: usize) -> usize; // XXX Permissing, exceptions, etc.
}

pub struct DataCache {
    data: Box<[[u8; LINESIZE]; LINES]>,
    /// dirty is true if that line is valid and needs to be written back
    dirty: [bool; LINES],
    virt_tag_valid: [bool; LINES], // This should be densely packed

    /// The virtual tag is simply the address part not covered by the
    /// cache address.  For Sv39 and a 64 KiB cache we need just 39-16
    /// = 21-bits
    virt_tag: [usize; LINES],

    /// The physical tag is the physical page number (PPN). 32-bit is
    /// sufficient for a 44-bit physical address space (16 TiB).
    phys_tag: [usize; LINES],
}

#[allow(clippy::unwrap_used)]
impl Default for DataCache {
    fn default() -> Self {
        Self {
            data: vec![[0; LINESIZE]; LINES]
                .into_boxed_slice()
                .try_into()
                .unwrap(),
            dirty: [false; LINES],
            virt_tag_valid: [false; LINES],
            virt_tag: [0; LINES],
            phys_tag: [INVALID_PPN; LINES],
        }
    }
}

impl DataCache {
    pub fn revalidate_virt(&mut self) {
        for valid in &mut self.virt_tag_valid {
            *valid = false;
        }
    }

    fn access(&mut self, ctx: &mut impl Context, line_addr: usize) {
        let (line_virt_tag, line_index) = (line_addr / LINES, line_addr % LINES);
        if self.virt_tag_valid[line_index] && self.virt_tag[line_index] == line_virt_tag {
            return;
        }

        // We have to look up the physical page number (PPN) that the
        // virtual page number (VPN) maps to.  There are PAGESIZE /
        // LINESIZE lines in each page, so we divide by that to get
        // the VPN.
        let ppn = ctx.virt2phys_pageno(line_addr / (PAGESIZE / LINESIZE));
        if self.phys_tag[line_index] == ppn {
            // phys_tag hit, validate
            self.virt_tag_valid[line_index] = true;
            self.virt_tag[line_index] = line_virt_tag;
            return;
        }

        // Cache miss, write back dirty lines and refill
        self.write_back_and_fill(ctx, line_addr, ppn);
    }

    /// # Panics
    /// on line-crossing accesses
    pub fn read<const SIZE: usize>(
        &mut self,
        ctx: &mut impl Context,
        addr: usize,
        data: &mut [u8; SIZE],
    ) {
        let (line_addr, line_offset) = (addr / LINESIZE, addr % LINESIZE);
        let line_index = line_addr % LINES;

        assert_eq!(
            line_addr,
            (addr + SIZE - 1) / LINESIZE,
            "{SIZE}-byte read access @ {addr:#x} crosses two cache lines"
        );

        self.access(ctx, line_addr);
        data.copy_from_slice(&self.data[line_index][line_offset..line_offset + SIZE]);
    }

    /// # Panics
    /// on line-crossing accesses
    pub fn write<const SIZE: usize>(
        &mut self,
        ctx: &mut impl Context,
        addr: usize,
        data: &[u8; SIZE],
    ) {
        let (line_addr, line_offset) = (addr / LINESIZE, addr % LINESIZE);
        let line_index = line_addr % LINES;

        assert_eq!(
            line_addr,
            (addr + SIZE - 1) / LINESIZE,
            "{SIZE}-byte write access @ {addr:#x} crosses two cache lines"
        );

        self.access(ctx, line_addr); // XXX Optimization: needn't fill when SIZE == LINESIZE
        self.data[line_index][line_offset..line_offset + SIZE].copy_from_slice(data);
        self.dirty[line_index] = true;
    }

    fn write_back_and_fill(&mut self, ctx: &mut impl Context, line_addr: usize, ppn: usize) {
        let (line_virt_tag, line_index) = (line_addr / LINES, line_addr % LINES);

        // Write back the dirty line being evicted (if any)
        if self.dirty[line_index] {
            let old_ppn = self.phys_tag[line_index];
            let line_in_page = line_index % (PAGESIZE / LINESIZE);
            ctx.write_line(
                old_ppn * (PAGESIZE / LINESIZE) + line_in_page,
                &self.data[line_index],
            );
            self.dirty[line_index] = false;
        }

        // Evict all aliases of the new line

        // XXX There is an interesting opportunity here; if we find an
        // alias then we can simply copy it to the new location and
        // evict it from the old location.  We don't even need to
        // write back dirty lines.
        for set in 0..LINES / (PAGESIZE / LINESIZE) {
            let alias_index = (line_index + set * (PAGESIZE / LINESIZE)) % LINES;
            if alias_index != line_index && self.phys_tag[alias_index] == ppn {
                if self.dirty[alias_index] {
                    let line_in_page = alias_index % (PAGESIZE / LINESIZE);
                    ctx.write_line(
                        self.phys_tag[alias_index] * (PAGESIZE / LINESIZE) + line_in_page,
                        &self.data[alias_index],
                    );
                }
                self.virt_tag_valid[alias_index] = false;
                self.phys_tag[alias_index] = INVALID_PPN;
                self.dirty[alias_index] = false; // Only valid lines can be dirty
            }
        }

        // Fill line
        let line_in_page = line_index % (PAGESIZE / LINESIZE);
        ctx.read_line(
            ppn * (PAGESIZE / LINESIZE) + line_in_page,
            &mut self.data[line_index],
        );
        self.phys_tag[line_index] = ppn;
        self.virt_tag[line_index] = line_virt_tag;
        self.virt_tag_valid[line_index] = true;
    }
}

// ============================================================================
// Comprehensive test suite
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // ============================================================================
    // Mock Memory Context for Testing
    // ============================================================================

    #[derive(Debug)]
    struct MockContext {
        /// Physical memory: maps physical line address to data
        physical_memory: HashMap<usize, [u8; LINESIZE]>,

        /// Virtual to physical page mapping
        page_table: HashMap<usize, usize>,

        /// Statistics
        read_count: usize,
        write_count: usize,
    }

    impl MockContext {
        fn new() -> Self {
            Self {
                physical_memory: HashMap::new(),
                page_table: HashMap::new(),
                read_count: 0,
                write_count: 0,
            }
        }

        /// Map a virtual page number to a physical page number
        fn map_page(&mut self, vpn: usize, ppn: usize) { self.page_table.insert(vpn, ppn); }

        /// Initialize physical memory with a pattern
        fn init_physical_line(&mut self, phys_line_addr: usize, pattern: u8) {
            let mut line = [pattern; LINESIZE];
            // Add address info to make each line unique
            let addr_bytes = phys_line_addr.to_le_bytes();
            line[0..8].copy_from_slice(
                &addr_bytes
                    .iter()
                    .cycle()
                    .take(8)
                    .copied()
                    .collect::<Vec<_>>(),
            );
            self.physical_memory.insert(phys_line_addr, line);
        }

        /// Get physical memory for verification
        fn get_physical_line(&self, phys_line_addr: usize) -> Option<[u8; LINESIZE]> {
            self.physical_memory.get(&phys_line_addr).copied()
        }

        /// Reset statistics
        fn reset_stats(&mut self) {
            self.read_count = 0;
            self.write_count = 0;
        }
    }

    impl Context for MockContext {
        fn read_line(&self, phys_line_addr: usize, line: &mut [u8; LINESIZE]) {
            if let Some(data) = self.physical_memory.get(&phys_line_addr) {
                line.copy_from_slice(data);
            } else {
                // Return zeros for uninitialized memory
                *line = [0; LINESIZE];
            }
            // Can't mutate self in read_line due to &self, so we can't track
            // stats here In real tests, we'll use interior
            // mutability if needed
        }

        fn write_line(&mut self, phys_line_addr: usize, line: &[u8; LINESIZE]) {
            self.physical_memory.insert(phys_line_addr, *line);
            self.write_count += 1;
        }

        fn virt2phys_pageno(&self, vpn: usize) -> usize {
            *self
                .page_table
                .get(&vpn)
                .unwrap_or_else(|| panic!("No mapping for VPN {vpn:#x}"))
        }
    }

    #[test]
    fn test_basic_read_write() {
        let mut cache = DataCache::default();
        let mut ctx = MockContext::new();

        // Map virtual page 0 to physical page 0
        ctx.map_page(0, 0);

        // Initialize physical memory
        for i in 0..64 {
            ctx.init_physical_line(i, i as u8);
        }

        // Write a value
        let write_data = [0x42u8; 8];
        cache.write(&mut ctx, 0x100, &write_data);

        // Read it back
        let mut read_data = [0u8; 8];
        cache.read(&mut ctx, 0x100, &mut read_data);

        assert_eq!(read_data, write_data, "Read should return written data");
    }

    #[test]
    fn test_cache_hit_no_physical_lookup() {
        let mut cache = DataCache::default();
        let mut ctx = MockContext::new();

        ctx.map_page(0, 0);
        ctx.init_physical_line(0, 0xAA);

        // First access - cache miss
        let mut data1 = [0u8; 8];
        cache.read(&mut ctx, 0, &mut data1);

        // Modify page table to point to different physical page
        // If cache uses virtual tag correctly, it won't notice
        ctx.map_page(0, 999);

        // Second access - should hit in cache using virtual tag
        let mut data2 = [0u8; 8];
        cache.read(&mut ctx, 0, &mut data2);

        // Data should be the same (from cache, not from physical page 999)
        assert_eq!(data1, data2, "Cache hit should not consult page table");
    }

    #[test]
    fn test_writeback_on_eviction() {
        let mut cache = DataCache::default();
        let mut ctx = MockContext::new();

        // Map two virtual pages to different physical pages
        ctx.map_page(0, 0);
        ctx.map_page(16, 1); // VPN for address LINES * LINESIZE = 65536 / 4096 = 16

        // Initialize physical memory
        for i in 0..(PAGESIZE / LINESIZE) {
            ctx.init_physical_line(i, 0x00);
            ctx.init_physical_line((PAGESIZE / LINESIZE) + i, 0x00);
        }

        // Write to first page
        let write_data = [0x42u8; 8];
        cache.write(&mut ctx, 0, &write_data);

        ctx.reset_stats();

        // Access a line that maps to the same cache index but different page
        // LINES * LINESIZE is in a different virtual page
        let mut read_data = [0u8; 8];
        let evicting_addr = LINES * LINESIZE;
        cache.read(&mut ctx, evicting_addr, &mut read_data);

        // Verify writeback occurred
        assert!(ctx.write_count > 0, "Dirty line should be written back");

        // Verify the written data is in physical memory
        let phys_line = ctx
            .get_physical_line(0)
            .expect("Physical line should exist");
        assert_eq!(
            phys_line[0..8],
            write_data,
            "Written data should be in physical memory"
        );
    }

    #[test]
    fn test_aliasing_two_virtual_pages_same_physical() {
        let mut cache = DataCache::default();
        let mut ctx = MockContext::new();

        // Map two different virtual addresses to the SAME physical page
        // Use VPN 0 and VPN 16 which both access cache line 0
        let vpn1 = 0;
        let vpn2 = 16; // Address LINES * LINESIZE = 65536, VPN = 16
        let ppn = 42;

        ctx.map_page(vpn1, ppn);
        ctx.map_page(vpn2, ppn);

        // Initialize all lines in the physical page
        for i in 0..(PAGESIZE / LINESIZE) {
            ctx.init_physical_line(ppn * (PAGESIZE / LINESIZE) + i, 0x00);
        }

        // Write through first alias
        let write_data = [0x99u8; 8];
        let vaddr1 = vpn1 * PAGESIZE; // 0
        cache.write(&mut ctx, vaddr1, &write_data);

        // Read through second alias at same offset in its page
        // Both map to cache line index 0
        let mut read_data = [0u8; 8];
        let vaddr2 = vpn2 * PAGESIZE; // 65536
        cache.read(&mut ctx, vaddr2, &mut read_data);

        assert_eq!(read_data, write_data, "Aliases should see the same data");
    }

    #[test]
    fn test_aliasing_no_dirty_aliases_coexist() {
        let mut cache = DataCache::default();
        let mut ctx = MockContext::new();

        // Create aliasing scenario - two virtual pages to same physical page
        // Use VPN 0 and VPN 16 which map to same cache line indices
        let vpn1 = 0;
        let vpn2 = 16;
        let ppn = 10;

        ctx.map_page(vpn1, ppn);
        ctx.map_page(vpn2, ppn);

        // Initialize all lines in the physical page
        for i in 0..(PAGESIZE / LINESIZE) {
            ctx.init_physical_line(ppn * (PAGESIZE / LINESIZE) + i, 0x00);
        }

        // Write through first alias (makes it dirty)
        let vaddr1 = vpn1 * PAGESIZE; // 0
        cache.write(&mut ctx, vaddr1, &[0xAAu8; 8]);

        // Access through second alias at the same offset within the page
        // This should evict the first alias (since it's dirty and we can't have dirty
        // aliases)
        let vaddr2 = vpn2 * PAGESIZE; // 65536
        let mut data = [0u8; 8];
        cache.read(&mut ctx, vaddr2, &mut data);

        // Both addresses map to the same cache line index
        let line_index = (vaddr1 / LINESIZE) % LINES;
        assert_eq!(
            cache.phys_tag[line_index], ppn,
            "Line should be tagged with the physical page"
        );

        // The virtual tag should be for the second virtual address
        let expected_virt_tag = (vaddr2 / LINESIZE) / LINES;
        assert_eq!(
            cache.virt_tag[line_index], expected_virt_tag,
            "Virtual tag should be updated to second alias"
        );

        // The data read should match what was written (since both point to same
        // physical location)
        assert_eq!(data, [0xAAu8; 8], "Should see the data that was written");
    }

    #[test]
    fn test_lazy_invalidation_revalidate() {
        let mut cache = DataCache::default();
        let mut ctx = MockContext::new();

        // Set up initial mapping
        ctx.map_page(0, 0);
        for i in 0..(PAGESIZE / LINESIZE) {
            ctx.init_physical_line(i, 0xAA);
        }

        // Access to populate cache (read from offset 8 to avoid address bytes)
        let mut data1 = [0u8; 8];
        cache.read(&mut ctx, 8, &mut data1);

        // Verify it's in cache with valid virtual tag
        let line_index = (8 / LINESIZE) % LINES;
        assert!(
            cache.virt_tag_valid[line_index],
            "Virtual tag should be valid"
        );

        // Simulate TLB flush / page table update
        cache.revalidate_virt();

        // All virtual tags should be invalid now
        assert!(
            !cache.virt_tag_valid[line_index],
            "Virtual tag should be invalidated"
        );

        // Change the mapping to different physical page
        ctx.map_page(0, 1);
        for i in 0..(PAGESIZE / LINESIZE) {
            ctx.init_physical_line((PAGESIZE / LINESIZE) + i, 0xBB);
        }

        // Next access should revalidate using physical tag lookup
        // and see the mapping changed, causing a refill
        let mut data2 = [0u8; 8];
        cache.read(&mut ctx, 8, &mut data2);

        // Data should be different (from new physical page)
        assert_ne!(data1[0], data2[0], "Should read from new physical page");
        assert_eq!(data2[0], 0xBB, "Should read from physical page 1");
    }

    #[test]
    fn test_lazy_invalidation_same_mapping() {
        let mut cache = DataCache::default();
        let mut ctx = MockContext::new();

        ctx.map_page(0, 0);
        ctx.init_physical_line(0, 0xCC);

        // Access to populate cache
        let mut data1 = [0u8; 8];
        cache.read(&mut ctx, 0, &mut data1);

        // Invalidate virtual tags
        cache.revalidate_virt();

        // Access again with SAME mapping
        let mut data2 = [0u8; 8];
        cache.read(&mut ctx, 0, &mut data2);

        // Should revalidate successfully and return same data
        assert_eq!(
            data1, data2,
            "Same mapping should revalidate and return same data"
        );
        assert!(cache.virt_tag_valid[0], "Virtual tag should be revalidated");
    }

    #[test]
    fn test_full_line_write_vs_partial() {
        let mut cache = DataCache::default();
        let mut ctx = MockContext::new();

        ctx.map_page(0, 0);
        ctx.init_physical_line(0, 0x00);

        // Partial write (should fill the line first)
        cache.write(&mut ctx, 0, &[0x42u8; 8]);

        // Full line write (could optimize to not fill)
        let full_line = [0x99u8; LINESIZE];
        cache.write(&mut ctx, LINESIZE, &full_line);

        // Both should work correctly
        let mut partial_read = [0u8; 8];
        cache.read(&mut ctx, 0, &mut partial_read);
        assert_eq!(partial_read, [0x42u8; 8]);

        let mut full_read = [0u8; LINESIZE];
        cache.read(&mut ctx, LINESIZE, &mut full_read);
        assert_eq!(full_read, full_line);
    }

    #[test]
    #[should_panic(expected = "crosses two cache lines")]
    fn test_line_crossing_read_panics() {
        let mut cache = DataCache::default();
        let mut ctx = MockContext::new();

        ctx.map_page(0, 0);

        // Try to read across a cache line boundary
        let mut data = [0u8; 16];
        cache.read(&mut ctx, LINESIZE - 8, &mut data);
    }

    #[test]
    #[should_panic(expected = "crosses two cache lines")]
    fn test_line_crossing_write_panics() {
        let mut cache = DataCache::default();
        let mut ctx = MockContext::new();

        ctx.map_page(0, 0);

        // Try to write across a cache line boundary
        cache.write(&mut ctx, LINESIZE - 8, &[0x42u8; 16]);
    }

    #[test]
    fn test_multiple_pages_same_cache_set() {
        let mut cache = DataCache::default();
        let mut ctx = MockContext::new();

        // Map multiple virtual pages to different physical pages
        // Use consecutive VPNs (which won't all conflict at same cache line)
        for vpn in 0..10 {
            ctx.map_page(vpn, vpn);
            // Initialize all lines in each physical page
            for i in 0..(PAGESIZE / LINESIZE) {
                ctx.init_physical_line(vpn * (PAGESIZE / LINESIZE) + i, vpn as u8);
            }
        }

        // Access first line of each page
        // These will have different cache indices since VPNs are consecutive
        for vpn in 0..10 {
            let addr = vpn * PAGESIZE + 8;
            let mut data = [0u8; 8];
            cache.read(&mut ctx, addr, &mut data);
            // The init pattern puts the address info in first 8 bytes,
            // but at offset 8+ it should have the vpn pattern
            assert_eq!(data[0], vpn as u8, "Should read correct page data");
        }

        // Access them again - none should have been evicted since they don't conflict
        for vpn in 0..10 {
            let addr = vpn * PAGESIZE + 8;
            let mut data = [0u8; 8];
            cache.read(&mut ctx, addr, &mut data);
            assert_eq!(data[0], vpn as u8, "Should still read correct page data");
        }
    }

    #[test]
    fn test_writeback_preserves_data() {
        let mut cache = DataCache::default();
        let mut ctx = MockContext::new();

        ctx.map_page(0, 0);
        ctx.map_page(16, 1); // Map the VPN for evicting address

        // Initialize physical memory
        for i in 0..(PAGESIZE / LINESIZE) {
            ctx.init_physical_line(i, 0x00);
            ctx.init_physical_line((PAGESIZE / LINESIZE) + i, 0x00);
        }

        // Write unique pattern to first page
        let pattern = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        cache.write(&mut ctx, 0, &pattern);

        // Force eviction by accessing same cache index in different page
        let evicting_addr = LINES * LINESIZE;
        let mut temp = [0u8; 8];
        cache.read(&mut ctx, evicting_addr, &mut temp);

        // Verify the pattern was written back to physical memory
        let phys_line = ctx.get_physical_line(0).expect("Should have written back");
        assert_eq!(
            phys_line[0..8],
            pattern,
            "Writeback should preserve exact data"
        );
    }

    #[test]
    fn test_clean_line_no_writeback() {
        let mut cache = DataCache::default();
        let mut ctx = MockContext::new();

        ctx.map_page(0, 0);
        ctx.map_page(16, 1); // Map the VPN for evicting address (65536 / 4096 = 16)

        // Initialize physical memory for both pages
        for i in 0..(PAGESIZE / LINESIZE) {
            ctx.init_physical_line(i, 0xAA);
            ctx.init_physical_line((PAGESIZE / LINESIZE) + i, 0xBB);
        }

        // Read only (no write, so line stays clean)
        let mut data = [0u8; 8];
        cache.read(&mut ctx, 0, &mut data);

        ctx.reset_stats();

        // Evict by accessing different page at same cache index
        let evicting_addr = LINES * LINESIZE;
        cache.read(&mut ctx, evicting_addr, &mut data);

        // Clean line should NOT be written back
        assert_eq!(
            ctx.write_count, 0,
            "Clean line should not trigger writeback"
        );
    }

    #[test]
    fn test_direct_mapped_conflict() {
        let mut cache = DataCache::default();
        let mut ctx = MockContext::new();

        // Two addresses that map to the same cache line but different pages
        ctx.map_page(0, 0);
        ctx.map_page(16, 1); // VPN for LINES * LINESIZE

        // Initialize with distinct patterns (avoiding first 8 bytes which have address
        // info)
        for i in 0..(PAGESIZE / LINESIZE) {
            ctx.init_physical_line(i, 0xAA);
            ctx.init_physical_line((PAGESIZE / LINESIZE) + i, 0xBB);
        }

        let addr1 = 0;
        let addr2 = LINES * LINESIZE; // Same cache index, different page

        // Access first address
        let mut data1 = [0u8; 8];
        cache.read(&mut ctx, addr1 + 8, &mut data1); // Read from offset 8 to avoid address bytes
        assert_eq!(data1[0], 0xAA);

        // Access second address (should evict first)
        let mut data2 = [0u8; 8];
        cache.read(&mut ctx, addr2 + 8, &mut data2);
        assert_eq!(data2[0], 0xBB);

        // Access first again (should evict second)
        let mut data3 = [0u8; 8];
        cache.read(&mut ctx, addr1 + 8, &mut data3);
        assert_eq!(data3[0], 0xAA);
    }

    #[test]
    fn test_different_sizes() {
        let mut cache = DataCache::default();
        let mut ctx = MockContext::new();

        ctx.map_page(0, 0);
        ctx.init_physical_line(0, 0x00);

        // Test 1-byte access
        cache.write(&mut ctx, 0, &[0x11u8]);
        let mut byte = [0u8; 1];
        cache.read(&mut ctx, 0, &mut byte);
        assert_eq!(byte[0], 0x11);

        // Test 4-byte access
        cache.write(&mut ctx, 4, &[0x22u8; 4]);
        let mut word = [0u8; 4];
        cache.read(&mut ctx, 4, &mut word);
        assert_eq!(word, [0x22u8; 4]);

        // Test 8-byte access
        cache.write(&mut ctx, 8, &[0x33u8; 8]);
        let mut dword = [0u8; 8];
        cache.read(&mut ctx, 8, &mut dword);
        assert_eq!(dword, [0x33u8; 8]);

        // Verify all coexist in same line
        cache.read(&mut ctx, 0, &mut byte);
        assert_eq!(byte[0], 0x11);
    }

    #[test]
    fn test_stress_aliasing() {
        let mut cache = DataCache::default();
        let mut ctx = MockContext::new();

        // Create many aliases to the same physical page
        // Use VPNs that are multiples of 16 (LINES / (PAGESIZE/LINESIZE))
        // These will map to the same cache line indices
        let ppn = 100;
        let num_aliases = 5; // Reduced to avoid too much complexity
        for i in 0..num_aliases {
            let vpn = i * 16; // 0, 16, 32, 48, 64
            ctx.map_page(vpn, ppn);
        }

        // Initialize all lines in the physical page
        for i in 0..(PAGESIZE / LINESIZE) {
            ctx.init_physical_line(ppn * (PAGESIZE / LINESIZE) + i, 0x00);
        }

        // Write through different aliases (use offset 8 to avoid address pattern)
        for i in 0..num_aliases {
            let vpn = i * 16;
            let addr = vpn * PAGESIZE + 8;
            let value = (i as u8).wrapping_mul(17); // Unique pattern per alias
            cache.write(&mut ctx, addr, &[value; 8]);

            // Immediately read back through same alias
            let mut data = [0u8; 8];
            cache.read(&mut ctx, addr, &mut data);
            assert_eq!(data[0], value, "Should read back written value");
        }

        // Force writeback by accessing a different page at the same cache line index
        // This will evict the dirty line and write it back
        let evict_vpn = 80; // Different from 0,16,32,48,64
        ctx.map_page(evict_vpn, 200); // Different PPN
        for i in 0..(PAGESIZE / LINESIZE) {
            ctx.init_physical_line(200 * (PAGESIZE / LINESIZE) + i, 0xFF);
        }
        let mut dummy = [0u8; 8];
        cache.read(&mut ctx, evict_vpn * PAGESIZE + 8, &mut dummy);

        // Now the last write should be in physical memory
        let final_value = ((num_aliases - 1) as u8).wrapping_mul(17);
        let phys_line = ctx.get_physical_line(ppn * (PAGESIZE / LINESIZE)).unwrap();
        assert_eq!(
            phys_line[8], final_value,
            "Physical memory should have last written value"
        );
    }
}
