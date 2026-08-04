use crate::cpu::Uop;

/// Maximum number of uops in a single cached basic block.
///
/// Only a ceiling, not a target: blocks stop at the first *taken* branch, so
/// what actually gets stored is the trace that ran, and the mean stored length
/// is around 8.  Raising the ceiling therefore costs little and lets
/// straight-line code -- where a block really can run 30+ uops before control
/// leaves -- keep going.  Measured against the previous build, interleaved:
///
/// | workload            | len 16, decode-ahead | len 48, trace |
/// |---------------------|----------------------|---------------|
/// | Geekbench 5         |                310.2 |         332.0 |
/// | Debian boot         |                186.9 |         206.8 |
///
/// The two changes are complementary: trace termination is what stops a
/// bigger ceiling from wasting decode work and slots, and before it a
/// ceiling of 48 made the Debian boot *slower* (155 MIPS), because blocks
/// were padded out to 48 uops of which ~9 ever ran.
///
/// Slots are no longer fixed-size -- see `SLOT_UOPS` -- so a long block costs
/// only the slots it actually uses.
pub const MAX_BLOCK_LEN: usize = 48;

/// Default total uop capacity, for every front end.
///
/// This matters far more than it looks.  Measured booting the Debian demo
/// image (2 G instructions of kernel + systemd, deterministic clock):
///
/// | entries | MIPS | conflict misses/Mi |
/// |---------|------|--------------------|
/// |   8 192 |  107 |             19 782 |
/// |  32 768 |  145 |              7 599 |
/// |  65 536 |  165 |              3 512 |
/// | 131 072 |  173 |              1 820 |
/// | 262 144 |  171 |              1 126 |
///
/// A Linux workload has a far bigger hot code footprint than the old busybox
/// images this was first tuned on, and starving the cache costs more than any
/// micro-optimisation in the executor.  Past 131 072 the falling conflict-miss
/// rate no longer pays for the cold misses that refilling a larger cache
/// costs after each full flush -- still true with spanning slots: 393 216
/// measured *worse* on the Debian boot (215.0 vs 217.5 MIPS).
///
/// The figures above were taken when a block occupied a whole `MAX_BLOCK_LEN`
/// slot.  With `SLOT_UOPS` the same 2.4 MB holds twice as many blocks, which
/// is where the win came from -- not from spending more memory.
pub const DEFAULT_UOP_ENTRIES: usize = 131_072;

/// Uops per cache slot.
///
/// A block occupies as many *consecutive* slots as it needs, so this is the
/// quantum of allocation, not a ceiling on block length.  It trades internal
/// fragmentation (a block wastes up to `SLOT_UOPS - 1` uops of its last slot)
/// against tag overhead: one 8-byte tag plus one continuation byte per slot,
/// which at a small value costs more memory than the padding it saves.
///
/// Swept on the Debian boot, interleaved against the fixed-slot build (212.5):
///
/// | `SLOT_UOPS` | slots | MIPS  |
/// |-------------|-------|-------|
/// |           4 | 32768 | 204.6 |
/// |           8 | 16384 | 210.3 |
/// |          16 |  8192 | 214.7 |
/// |          20 |  8192 | 218.5 |
/// |          24 |  8192 | 217.7 |
/// |          28 |  8192 | 216.4 |
/// |          32 |  4096 | 212.1 |
/// |          48 |  4096 | 211.6 |
///
/// What the table really shows is the slot *count*: 20/24/28 all round to 8192
/// slots and all win; 32/48 round to 4096 and all match the old build.  The
/// gain is twice as many blocks resident in the same 2.4 MB, not finer
/// packing for its own sake -- below 16 the per-slot tag overhead takes it
/// back, and shrinking the slot further only buys more of that.
pub const SLOT_UOPS: usize = 24;

/// Cache mapping strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheMode {
    /// Direct-mapped: one slot per index.
    Direct,
    /// 2-way skew-associative: two ways with different hash functions.
    Skew,
}

/// Scratch buffer used while building a block, before it is copied into the
/// cache's flat uop storage.  Terminated by the first `Op::End` sentinel.
///
/// This is a build-time local, not the storage layout: the cache itself packs
/// uops contiguously into `SLOT_UOPS`-sized slots.
#[derive(Clone)]
pub struct BasicBlock {
    pub uops: [Uop; MAX_BLOCK_LEN],
}

impl Default for BasicBlock {
    fn default() -> Self {
        Self {
            uops: [Uop::default(); MAX_BLOCK_LEN],
        }
    }
}

/// Fixed-size basic-block uop cache with configurable mapping strategy.
pub struct BbCache {
    tags: Vec<u64>,
    /// Flat uop storage: slot `i` owns `data[i * SLOT_UOPS ..]`.
    /// Over-allocated by one maximal block so that a block starting in the
    /// last slot can be read as a full-length slice without a bounds check.
    data: Vec<Uop>,
    /// `0` for a free or head slot, otherwise the distance back to the head of
    /// the block that occupies this slot.  Only consulted when placing a
    /// block, never on the execution path.
    cont: Vec<u8>,
    /// Number of entries per way.
    sets: usize,
    /// Mask for indexing into a way (sets - 1).
    mask: usize,
    mode: CacheMode,
    /// Round-robin replacement counter for skew mode.
    replace_ctr: u8,
    /// Total number of slots (constant after construction).
    capacity: usize,
    /// Number of currently occupied (non-INVALID) slots.
    occupied: usize,
    /// Number of block-level cache hits.
    pub block_hits: u64,
    /// Total instructions executed from cached blocks (`insn_hits` /
    /// `block_hits` = avg block len).
    pub insn_hits: u64,
    /// Miss where the slot held `INVALID_TAG` — cold fill after a flush.
    pub cold_misses: u64,
    /// Miss where the slot held a *different* valid key — conflict eviction.
    pub conflict_misses: u64,
    /// Branch uops executed where the branch was not taken.
    pub untaken_branches: u64,
    /// Full cache clears (FENCE.I, SFENCE.VMA x0/x0, SATP PPN/mode change).
    pub flush_full: u64,
    /// Targeted flushes by ASID (SFENCE.VMA x0/rs2).
    pub flush_asid: u64,
    /// Targeted flushes by virtual page (SFENCE.VMA rs1/x0).
    pub flush_vpage: u64,
    /// Targeted flushes by virtual page + ASID (SFENCE.VMA rs1/rs2).
    pub flush_vpage_asid: u64,
    /// EXPERIMENT: how long the blocks actually stored are, indexed by uop
    /// count.  A slot costs a full `MAX_BLOCK_LEN` whatever this says, so the
    /// gap between this distribution and 16 is the storage being wasted.
    pub inserted_len: [u64; MAX_BLOCK_LEN + 1],
}

impl BbCache {
    /// Create a new cache.
    ///
    /// `total_uop_entries` is the total uop-equivalent capacity; it is divided
    /// by `MAX_BLOCK_LEN` internally to get the number of block slots.
    /// The result is rounded up to a power of two.
    /// In `Skew` mode, block slots are split equally between two ways.
    #[must_use]
    pub fn new(total_uop_entries: usize, mode: CacheMode) -> Self {
        let block_slots = (total_uop_entries / SLOT_UOPS).max(1);
        let sets = match mode {
            CacheMode::Direct => block_slots.next_power_of_two(),
            CacheMode::Skew => (block_slots / 2).max(1).next_power_of_two(),
        };
        let n = match mode {
            CacheMode::Direct => sets,
            CacheMode::Skew => sets * 2,
        };
        Self {
            tags: vec![INVALID_TAG; n],
            data: vec![Uop::default(); n * SLOT_UOPS + MAX_BLOCK_LEN + 1],
            cont: vec![0; n],
            sets,
            mask: sets - 1,
            mode,
            replace_ctr: 0,
            capacity: n,
            occupied: 0,
            block_hits: 0,
            insn_hits: 0,
            cold_misses: 0,
            conflict_misses: 0,
            untaken_branches: 0,
            flush_full: 0,
            flush_asid: 0,
            flush_vpage: 0,
            flush_vpage_asid: 0,
            inserted_len: [0; MAX_BLOCK_LEN + 1],
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    #[inline]
    const fn index0(&self, key: u64) -> usize { key as usize & self.mask }

    #[allow(clippy::cast_possible_truncation)]
    #[inline]
    const fn index1(&self, key: u64) -> usize {
        // Fold page-number bits [23:12] into offset bits [11:0].
        //
        // Any two addresses that alias in way 0 (same bits [11:0], i.e. same
        // page offset but different pages) necessarily have *different*
        // bits [23:12], so they are guaranteed to land on different way-1
        // slots — providing true skew for exactly the dominant conflict
        // pattern.
        let k = key as usize;
        (k ^ (k >> 12)) & self.mask | self.sets
    }

    /// Look up `key` and return its slot index on a hit, or `None` on a miss.
    /// Miss stats (`cold_misses` / `conflict_misses`) are updated on a miss.
    /// The caller is responsible for updating `block_hits` / `insn_hits` on a
    /// hit.
    #[inline]
    pub fn probe(&mut self, key: u64) -> Option<usize> {
        let i0 = self.index0(key);
        if self.tags[i0] == key {
            return Some(i0);
        }
        if self.mode == CacheMode::Skew {
            let i1 = self.index1(key);
            if self.tags[i1] == key {
                return Some(i1);
            }
            // Cold if both candidate slots are empty; conflict otherwise.
            if self.tags[i0] == INVALID_TAG && self.tags[i1] == INVALID_TAG {
                self.cold_misses += 1;
            } else {
                self.conflict_misses += 1;
            }
        } else if self.tags[i0] == INVALID_TAG {
            self.cold_misses += 1;
        } else {
            self.conflict_misses += 1;
        }
        None
    }

    /// Return a shared reference to the block at `slot` (as returned by
    /// `probe`).
    #[inline]
    #[must_use]
    pub fn block_at(&self, slot: usize) -> &[Uop] {
        let base = slot * SLOT_UOPS;
        &self.data[base..=base + MAX_BLOCK_LEN]
    }

    /// Invalidate the block whose head is `h`, clearing the continuation marks
    /// of every slot it spans.
    fn invalidate_head(&mut self, h: usize) {
        if self.tags[h] != INVALID_TAG {
            self.tags[h] = INVALID_TAG;
            self.occupied -= 1;
        }
        let mut k = h + 1;
        while k < self.capacity && self.cont[k] as usize == k - h {
            self.cont[k] = 0;
            k += 1;
        }
    }

    /// Invalidate whatever occupies `slot`, following a continuation back to
    /// its head so a block is never left half-overwritten.
    fn evict_at(&mut self, slot: usize) { self.invalidate_head(slot - self.cont[slot] as usize); }

    /// Claim `n` consecutive slots starting at `i`, evicting anything there.
    fn claim(&mut self, i: usize, n: usize, key: u64) {
        for j in i..(i + n).min(self.capacity) {
            if self.cont[j] != 0 || self.tags[j] != INVALID_TAG {
                self.evict_at(j);
            }
        }
        self.tags[i] = key;
        self.occupied += 1;
        for j in 1..n {
            if i + j < self.capacity {
                self.cont[i + j] = u8::try_from(j).unwrap_or(0);
            }
        }
    }

    /// How many free slots start at `i`, up to `n`.
    fn free_run(&self, i: usize, n: usize) -> usize {
        (0..n)
            .take_while(|&j| {
                i + j < self.capacity && self.tags[i + j] == INVALID_TAG && self.cont[i + j] == 0
            })
            .count()
    }

    #[inline]
    pub fn insert(&mut self, key: u64, block: &BasicBlock) {
        let len = block
            .uops
            .iter()
            .take_while(|u| u.op != crate::generated_riscv_decoder::Op::End)
            .count();
        self.inserted_len[len] += 1;
        // +1 so there is always room for the `End` sentinel: the executor
        // relies on it to stop before running into the next block's uops.
        let n_slots = (len + 1).div_ceil(SLOT_UOPS);

        let i0 = self.index0(key);
        let i = if self.mode == CacheMode::Skew {
            let i1 = self.index1(key);
            // Prefer whichever way can take the block without evicting; fall
            // back to round-robin, as before.
            if self.free_run(i0, n_slots) == n_slots {
                i0
            } else if self.free_run(i1, n_slots) == n_slots {
                i1
            } else {
                let w = self.replace_ctr & 1;
                self.replace_ctr = self.replace_ctr.wrapping_add(1);
                if w == 0 { i0 } else { i1 }
            }
        } else {
            i0
        };

        self.claim(i, n_slots, key);
        let base = i * SLOT_UOPS;
        self.data[base..base + len].copy_from_slice(&block.uops[..len]);
        self.data[base + len] = Uop::default();
    }

    pub fn clear(&mut self) {
        self.flush_full += 1;
        self.tags.fill(INVALID_TAG);
        self.cont.fill(0);
        self.occupied = 0;
    }

    /// Flush S-mode entries whose ASID (stored in bits [63:48] of the key)
    /// matches.
    ///
    /// M-mode entries (bit 0 set) and kernel-VA entries (bits [63:48] = 0xFFFF,
    /// a consequence of the OR-based global encoding) are left intact.
    pub fn flush_asid(&mut self, asid: u16) {
        self.flush_asid += 1;
        let asid_bits = u64::from(asid) << 48;
        let asid_mask = 0xFFFF_u64 << 48;
        for i in 0..self.capacity {
            let t = self.tags[i];
            if t != INVALID_TAG && t & 1 == 0 && t & asid_mask == asid_bits {
                self.invalidate_head(i);
            }
        }
    }

    /// Flush S-mode entries whose VA page (bits [47:12] of the key) matches,
    /// regardless of ASID.
    pub fn flush_vpage(&mut self, page_addr: u64) {
        self.flush_vpage += 1;
        // Mask out ASID bits [63:48] and page-offset bits [11:0] for comparison.
        let va_mask = !(0xFFFF_u64 << 48) & !0xFFF_u64;
        let page_base = page_addr & va_mask;
        for i in 0..self.capacity {
            let t = self.tags[i];
            if t != INVALID_TAG && t & 1 == 0 && t & va_mask == page_base {
                self.invalidate_head(i);
            }
        }
    }

    /// Flush the single S-mode entry matching both a specific VA page and ASID.
    pub fn flush_vpage_asid(&mut self, page_addr: u64, asid: u16) {
        self.flush_vpage_asid += 1;
        let va_mask = !(0xFFFF_u64 << 48) & !0xFFF_u64;
        let page_base = page_addr & va_mask;
        let asid_bits = u64::from(asid) << 48;
        let asid_mask = 0xFFFF_u64 << 48;
        for i in 0..self.capacity {
            let t = self.tags[i];
            if t != INVALID_TAG
                && t & 1 == 0
                && t & asid_mask == asid_bits
                && t & va_mask == page_base
            {
                self.invalidate_head(i);
            }
        }
    }

    #[must_use]
    pub const fn stats(&self) -> UopCacheStats {
        UopCacheStats {
            hits: self.insn_hits,
            block_hits: self.block_hits,
            untaken_branches: self.untaken_branches,
            cold_misses: self.cold_misses,
            conflict_misses: self.conflict_misses,
            flush_full: self.flush_full,
            flush_asid: self.flush_asid,
            flush_vpage: self.flush_vpage,
            flush_vpage_asid: self.flush_vpage_asid,
            occupied: self.occupied,
            capacity: self.capacity,
        }
    }

    /// Distribution of stored block lengths, indexed by uop count.
    ///
    /// Deliberately not part of [`UopCacheStats`], which is copied per block
    /// while the HPM counters are live.
    #[must_use]
    pub const fn inserted_len(&self) -> &[u64; MAX_BLOCK_LEN + 1] { &self.inserted_len }
}

const INVALID_TAG: u64 = u64::MAX;

#[derive(Clone, Copy, Default)]
pub struct UopCacheStats {
    /// Total instructions executed from cached blocks (= `insn_hits`).
    pub hits: u64,
    pub block_hits: u64,
    pub untaken_branches: u64,
    pub cold_misses: u64,
    pub conflict_misses: u64,
    pub flush_full: u64,
    pub flush_asid: u64,
    pub flush_vpage: u64,
    pub flush_vpage_asid: u64,
    pub occupied: usize,
    pub capacity: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flush_vpage_matches_high_canonical_kernel_pages() {
        let mut cache = BbCache::new(MAX_BLOCK_LEN * 4, CacheMode::Direct);
        let va = 0xffff_ffc0_1234_5678;
        let key = va;

        cache.insert(key, &BasicBlock::default());
        assert!(cache.probe(key).is_some());

        cache.flush_vpage(va & !0xfff);
        assert!(cache.probe(key).is_none());
    }

    #[test]
    fn flush_vpage_asid_masks_asid_bits_from_requested_page() {
        let mut cache = BbCache::new(MAX_BLOCK_LEN * 4, CacheMode::Direct);
        let va = 0x0000_1234_5678;
        let asid = 0x42;
        let key = va | (u64::from(asid) << 48);

        cache.insert(key, &BasicBlock::default());
        assert!(cache.probe(key).is_some());

        cache.flush_vpage_asid(va & !0xfff, asid);
        assert!(cache.probe(key).is_none());
    }
}
