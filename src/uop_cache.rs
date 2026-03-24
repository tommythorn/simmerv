use crate::cpu::Uop;

/// Maximum number of uops in a single cached basic block.
pub const MAX_BLOCK_LEN: usize = 16;

/// Cache mapping strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheMode {
    /// Direct-mapped: one slot per index.
    Direct,
    /// 2-way skew-associative: two ways with different hash functions.
    Skew,
}

/// A cached sequence of decoded uops covering one basic block.
/// The block is terminated by the first `Op::End` sentinel uop.
#[derive(Clone)]
pub struct BasicBlock {
    pub uops: [Uop; MAX_BLOCK_LEN],
    /// Padding to avoid cache-set aliasing: 192 bytes (3 × 64-byte lines)
    /// causes heavy conflict misses in the host L1/L2; 196 bytes breaks the
    /// periodicity.  Do NOT remove.
    _cache_align_pad: [u8; 4],
}

impl Default for BasicBlock {
    fn default() -> Self {
        Self {
            uops: [Uop::default(); MAX_BLOCK_LEN],
            _cache_align_pad: [0; 4],
        }
    }
}

/// Fixed-size basic-block uop cache with configurable mapping strategy.
pub struct BbCache {
    tags: Vec<u64>,
    data: Vec<BasicBlock>,
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
    /// Ring buffer of (`lookup_key`, `evicted_tag`) pairs from recent conflict
    /// misses.
    conflict_log: [(u64, u64); 8],
    conflict_log_len: usize,
}

impl BbCache {
    const CONFLICT_LOG_SIZE: usize = 8;

    /// Create a new cache.
    ///
    /// `total_uop_entries` is the total uop-equivalent capacity; it is divided
    /// by `MAX_BLOCK_LEN` internally to get the number of block slots.
    /// The result is rounded up to a power of two.
    /// In `Skew` mode, block slots are split equally between two ways.
    #[must_use]
    pub fn new(total_uop_entries: usize, mode: CacheMode) -> Self {
        let block_slots = (total_uop_entries / MAX_BLOCK_LEN).max(1);
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
            data: vec![BasicBlock::default(); n],
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
            conflict_log: [(0, 0); Self::CONFLICT_LOG_SIZE],
            conflict_log_len: 0,
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
                self.log_conflict(key, self.tags[i0], self.tags[i1]);
                self.conflict_misses += 1;
            }
        } else if self.tags[i0] == INVALID_TAG {
            self.cold_misses += 1;
        } else {
            self.log_conflict(key, self.tags[i0], INVALID_TAG);
            self.conflict_misses += 1;
        }
        None
    }

    /// Return a shared reference to the block at `slot` (as returned by
    /// `probe`).
    #[inline]
    #[must_use]
    pub fn block_at(&self, slot: usize) -> &BasicBlock { &self.data[slot] }

    /// Record a conflict miss in the log (first `CONFLICT_LOG_SIZE` only).
    fn log_conflict(&mut self, key: u64, tag0: u64, tag1: u64) {
        if self.conflict_log_len < Self::CONFLICT_LOG_SIZE {
            // Pick the non-INVALID evicted tag as the "other" address.
            let evicted = if tag0 == INVALID_TAG { tag1 } else { tag0 };
            self.conflict_log[self.conflict_log_len] = (key, evicted);
            self.conflict_log_len += 1;
            if self.conflict_log_len == Self::CONFLICT_LOG_SIZE {
                self.dump_conflict_log();
            }
        }
    }

    fn dump_conflict_log(&self) {
        // Write directly to stderr so the output is never swallowed by log
        // filters and never overwritten by the speedometer's ANSI escapes.
        eprintln!(
            "uop$ first {} conflict misses (key → evicted):",
            Self::CONFLICT_LOG_SIZE
        );
        for (i, &(key, evicted)) in self.conflict_log[..self.conflict_log_len]
            .iter()
            .enumerate()
        {
            let key_m = if key & 1 != 0 { 'M' } else { 'S' };
            let ev_m = if evicted & 1 != 0 { 'M' } else { 'S' };
            // Strip M-mode bit and ASID bits for display.
            let key_va = key & !(0xFFFF_u64 << 48) & !1;
            let ev_va = evicted & !(0xFFFF_u64 << 48) & !1;
            let same_offset = (key_va ^ ev_va).trailing_zeros() >= 12;
            let note = if same_offset {
                " ← same page offset"
            } else {
                ""
            };
            eprintln!("  [{i}] {key_m}:{key_va:#018x} vs {ev_m}:{ev_va:#018x}{note}");
        }
    }

    #[inline]
    pub fn insert(&mut self, key: u64, block: &BasicBlock) {
        match self.mode {
            CacheMode::Direct => {
                let i = self.index0(key);
                if self.tags[i] == INVALID_TAG {
                    self.occupied += 1;
                }
                self.tags[i] = key;
                self.data[i] = block.clone();
            }
            CacheMode::Skew => {
                let i0 = self.index0(key);
                let i1 = self.index1(key);
                // Prefer an empty slot
                let i = if self.tags[i0] == INVALID_TAG {
                    i0
                } else if self.tags[i1] == INVALID_TAG {
                    i1
                } else {
                    let w = self.replace_ctr & 1;
                    self.replace_ctr = self.replace_ctr.wrapping_add(1);
                    if w == 0 { i0 } else { i1 }
                };
                if self.tags[i] == INVALID_TAG {
                    self.occupied += 1;
                }
                self.tags[i] = key;
                self.data[i] = block.clone();
            }
        }
    }

    pub fn clear(&mut self) {
        self.flush_full += 1;
        self.tags.fill(INVALID_TAG);
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
        for tag in &mut self.tags {
            if *tag & 1 == 0 && *tag & asid_mask == asid_bits {
                *tag = INVALID_TAG;
                self.occupied -= 1;
            }
        }
    }

    /// Flush S-mode entries whose VA page (bits [47:12] of the key) matches,
    /// regardless of ASID.
    pub fn flush_vpage(&mut self, page_addr: u64) {
        self.flush_vpage += 1;
        let page_base = page_addr & !0xFFF_u64;
        // Mask out ASID bits [63:48] and page-offset bits [11:0] for comparison.
        let va_mask = !(0xFFFF_u64 << 48) & !0xFFF_u64;
        for tag in &mut self.tags {
            if *tag & 1 == 0 && *tag & va_mask == page_base {
                *tag = INVALID_TAG;
                self.occupied -= 1;
            }
        }
    }

    /// Flush the single S-mode entry matching both a specific VA page and ASID.
    pub fn flush_vpage_asid(&mut self, page_addr: u64, asid: u16) {
        self.flush_vpage_asid += 1;
        let page_base = page_addr & !0xFFF_u64;
        let va_mask = !(0xFFFF_u64 << 48) & !0xFFF_u64;
        let asid_bits = u64::from(asid) << 48;
        let asid_mask = 0xFFFF_u64 << 48;
        for tag in &mut self.tags {
            if *tag & 1 == 0 && *tag & asid_mask == asid_bits && *tag & va_mask == page_base {
                *tag = INVALID_TAG;
                self.occupied -= 1;
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
// [Uop; 16]=192 + _cache_align_pad(4) = 196
const _: () = assert!(std::mem::size_of::<BasicBlock>() == 196);
