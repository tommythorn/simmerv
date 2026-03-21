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
    pub hits: u64,
    pub misses: u64,
    pub flushes: u64,
}

const INVALID_TAG: u64 = u64::MAX;

impl UopCache {
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
            hits: 0,
            misses: 0,
            flushes: 0,
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    #[inline]
    const fn index0(&self, key: u64) -> usize { key as usize & self.mask }

    #[allow(clippy::cast_possible_truncation)]
    #[inline]
    const fn index1(&self, key: u64) -> usize {
        // Different hash for way 1: XOR-fold upper bits
        let k = key as usize;
        (k ^ (k >> 16)) & self.mask | self.sets
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
        }
        self.misses += 1;
        None
    }

    #[inline]
    pub fn insert(&mut self, key: u64, uop: Uop) {
        match self.mode {
            CacheMode::Direct => {
                let i = self.index0(key);
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
                self.tags[i] = key;
                self.data[i] = uop;
            }
        }
    }

    pub fn clear(&mut self) {
        self.flushes += 1;
        self.tags.fill(INVALID_TAG);
    }

    #[must_use]
    pub const fn stats(&self) -> UopCacheStats {
        UopCacheStats {
            hits: self.hits,
            misses: self.misses,
            flushes: self.flushes,
        }
    }
}

#[derive(Clone, Copy, Default)]
pub struct UopCacheStats {
    pub hits: u64,
    pub misses: u64,
    pub flushes: u64,
}
