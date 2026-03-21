use crate::cpu::Uop;

/// Cache mapping strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheMode {
    /// Direct-mapped: one slot per index.
    Direct,
    /// 2-way skew-associative: two ways with different hash functions.
    Skew,
}

/// Fixed-size uop cache with configurable mapping strategy.
pub struct UopCache {
    tags: Vec<u64>,
    data: Vec<Uop>,
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
    pub hits: u64,
    /// Miss where the slot held `INVALID_TAG` — cold fill after a flush.
    pub cold_misses: u64,
    /// Miss where the slot held a *different* valid key — conflict eviction.
    pub conflict_misses: u64,
    /// Full cache clears (FENCE.I, SFENCE.VMA x0/x0, SATP PPN/mode change).
    pub flush_full: u64,
    /// Targeted flushes by ASID (SFENCE.VMA x0/rs2).
    pub flush_asid: u64,
    /// Targeted flushes by virtual page (SFENCE.VMA rs1/x0).
    pub flush_vpage: u64,
    /// Targeted flushes by virtual page + ASID (SFENCE.VMA rs1/rs2).
    pub flush_vpage_asid: u64,
    /// Ring buffer of (`lookup_key`, `evicted_tag`) pairs from recent conflict
    /// misses.  Filled on the first `CONFLICT_LOG_SIZE` conflicts and never
    /// overwritten, so a single glance reveals the chronic offenders.
    conflict_log: [(u64, u64); Self::CONFLICT_LOG_SIZE],
    conflict_log_len: usize,
}

impl UopCache {
    const CONFLICT_LOG_SIZE: usize = 8;

    /// Create a new cache.
    ///
    /// `total_entries` is rounded up to a power of two.
    /// In `Skew` mode, entries are split equally between two ways.
    #[must_use]
    pub fn new(total_entries: usize, mode: CacheMode) -> Self {
        let sets = match mode {
            CacheMode::Direct => total_entries.next_power_of_two(),
            CacheMode::Skew => (total_entries / 2).max(1).next_power_of_two(),
        };
        let n = match mode {
            CacheMode::Direct => sets,
            CacheMode::Skew => sets * 2,
        };
        Self {
            tags: vec![INVALID_TAG; n],
            data: vec![Uop::default(); n],
            sets,
            mask: sets - 1,
            mode,
            replace_ctr: 0,
            capacity: n,
            occupied: 0,
            hits: 0,
            cold_misses: 0,
            conflict_misses: 0,
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
        // pattern.  The previous >> 16 fold was useless for OpenSBI and
        // compact kernel code because bits [31:16] are constant across the
        // entire text range (0x8000 / 0xFFFF respectively), making index1
        // just index0 XOR a constant.
        let k = key as usize;
        (k ^ (k >> 12)) & self.mask | self.sets
    }

    #[inline]
    pub fn get(&mut self, key: u64) -> Option<&Uop> {
        let i0 = self.index0(key);
        if self.tags[i0] == key {
            self.hits += 1;
            return Some(&self.data[i0]);
        }
        if self.mode == CacheMode::Skew {
            let i1 = self.index1(key);
            if self.tags[i1] == key {
                self.hits += 1;
                return Some(&self.data[i1]);
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
    pub fn insert(&mut self, key: u64, uop: Uop) {
        match self.mode {
            CacheMode::Direct => {
                let i = self.index0(key);
                if self.tags[i] == INVALID_TAG {
                    self.occupied += 1;
                }
                self.tags[i] = key;
                self.data[i] = uop;
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
                self.data[i] = uop;
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
            hits: self.hits,
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
    pub hits: u64,
    pub cold_misses: u64,
    pub conflict_misses: u64,
    pub flush_full: u64,
    pub flush_asid: u64,
    pub flush_vpage: u64,
    pub flush_vpage_asid: u64,
    pub occupied: usize,
    pub capacity: usize,
}
