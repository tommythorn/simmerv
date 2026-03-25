#![allow(clippy::inline_always)]

const PERM_R: u16 = 1 << 0;
const PERM_U: u16 = 1 << 3;
const PERM_G: u16 = 1 << 4;
const PERM_ASID_SHIFT: u32 = 5;

const INVALID_VPAGE: u32 = u32::MAX;
/// Invalid perm sentinel — has `PERM_G` set so `flush_asid`'s `p & !15 == asid
/// << SHIFT` check naturally skips it (bit 4 is set on the left but never on
/// the right).
const INVALID_PERM: u16 = PERM_G;

/// Direct-mapped TLB with `SETS` entries.
pub struct Tlb<const SETS: usize> {
    vpage: [u32; SETS],
    ppage: [u32; SETS],
    perm: [u16; SETS],
    pub misses: u64,
}

/// Direct-mapped dTLB with `SETS` entries.
///
/// Stores a RAM region index and page byte offset instead of a physical page
/// number so that hits can access memory directly without scanning
/// `Mmu::memory`. MMIO pages are never inserted.
pub struct DTlb<const SETS: usize> {
    vpage: [u32; SETS],
    mem_idx: [u8; SETS],
    page_byte_offset: [u64; SETS],
    perm: [u16; SETS],
    pub misses: u64,
}

/// Pack permission bits for a TLB entry.
///
/// `xwr` is bits [2:0] = X|W|R from PTE, `user` is PTE U bit, `global` is PTE G
/// bit.
#[must_use]
#[inline]
pub fn pack_perm(xwr: u8, user: bool, global: bool, asid: u16) -> u16 {
    let mut p = u16::from(xwr & 7);
    if user {
        p |= PERM_U;
    }
    if global {
        p |= PERM_G;
    }
    p | (asid << PERM_ASID_SHIFT)
}

/// Check whether `perm` grants the requested access.
///
/// `access_shift`: 0=Read, 1=Write, 2=Execute.
/// `prv_is_user`: true if effective privilege is U-mode.
/// `sum`: true if SUM bit is set in mstatus.
/// `mxr`: true if MXR bit is set in mstatus.
#[must_use]
#[inline(always)]
pub const fn check_perm(
    perm: u16,
    access_shift: u32,
    prv_is_user: bool,
    sum: bool,
    mxr: bool,
) -> bool {
    let mut xwr = perm; // Technically `& 7` but we aren't looking at the rest
    // MXR: make execute-only pages also readable
    if mxr {
        xwr |= (xwr >> 2) & PERM_R;
    }

    // Access type check
    if xwr & 1 << access_shift == 0 {
        return false;
    }

    // Privilege check
    if prv_is_user {
        perm & PERM_U != 0
    } else {
        perm & PERM_U == 0 || sum
    }
}

impl<const SETS: usize> Default for Tlb<SETS> {
    fn default() -> Self { Self::new() }
}

impl<const SETS: usize> Tlb<SETS> {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            vpage: [INVALID_VPAGE; SETS],
            ppage: [0; SETS],
            perm: [INVALID_PERM; SETS],
            misses: 0,
        }
    }

    /// Look up a virtual page number. Returns `(ppage, perm)` on hit.
    #[must_use]
    #[inline(always)]
    pub const fn lookup(&self, vpage: u32, asid: u16) -> Option<(u32, u16)> {
        let idx = vpage as usize & (SETS - 1);
        if self.vpage[idx] == vpage {
            let p = self.perm[idx];
            if p & PERM_G != 0 || (p >> PERM_ASID_SHIFT) == asid {
                return Some((self.ppage[idx], p));
            }
        }
        None
    }

    /// Insert an entry. `perm` should be produced by `pack_perm`.
    #[inline(always)]
    pub const fn insert(&mut self, vpage: u32, ppage: u32, perm: u16, _asid: u16) {
        let idx = vpage as usize & (SETS - 1);
        self.vpage[idx] = vpage;
        self.ppage[idx] = ppage;
        self.perm[idx] = perm;
    }

    /// Flush all entries.
    pub const fn flush_all(&mut self) {
        self.vpage = [INVALID_VPAGE; SETS];
        self.perm = [INVALID_PERM; SETS];
    }

    /// Flush entries matching the given ASID (skip global and invalid entries).
    pub fn flush_asid(&mut self, asid: u16) {
        let target = asid << PERM_ASID_SHIFT;
        for i in 0..SETS {
            if self.perm[i] & !0xF == target {
                self.vpage[i] = INVALID_VPAGE;
                self.perm[i] = INVALID_PERM;
            }
        }
    }

    /// Flush the entry for the given virtual page (all ASIDs).
    pub const fn flush_vpage(&mut self, vpage: u32) {
        let idx = vpage as usize & (SETS - 1);
        if self.vpage[idx] == vpage {
            self.vpage[idx] = INVALID_VPAGE;
            self.perm[idx] = INVALID_PERM;
        }
    }

    /// Flush the entry for the given virtual page and ASID.
    pub const fn flush_vpage_asid(&mut self, vpage: u32, asid: u16) {
        let idx = vpage as usize & (SETS - 1);
        if self.vpage[idx] == vpage {
            let p = self.perm[idx];
            if p & !0xF == (asid << PERM_ASID_SHIFT) {
                self.vpage[idx] = INVALID_VPAGE;
                self.perm[idx] = INVALID_PERM;
            }
        }
    }
}

impl<const SETS: usize> Default for DTlb<SETS> {
    fn default() -> Self { Self::new() }
}

impl<const SETS: usize> DTlb<SETS> {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            vpage: [INVALID_VPAGE; SETS],
            mem_idx: [0; SETS],
            page_byte_offset: [0u64; SETS],
            perm: [INVALID_PERM; SETS],
            misses: 0,
        }
    }

    /// Look up a virtual page number. Returns `(mem_idx, page_byte_offset,
    /// perm)` on hit.
    #[must_use]
    #[inline(always)]
    pub const fn lookup(&self, vpage: u32, asid: u16) -> Option<(u8, u64, u16)> {
        let idx = vpage as usize & (SETS - 1);
        if self.vpage[idx] == vpage {
            let p = self.perm[idx];
            if p & PERM_G != 0 || (p >> PERM_ASID_SHIFT) == asid {
                return Some((self.mem_idx[idx], self.page_byte_offset[idx], p));
            }
        }
        None
    }

    /// Insert a RAM entry. `perm` should be produced by `pack_perm`.
    /// `page_byte_offset` is `(pa & !0xfff) - region.start`.
    #[inline(always)]
    pub const fn insert(
        &mut self,
        vpage: u32,
        mem_idx: u8,
        page_byte_offset: u64,
        perm: u16,
        _asid: u16,
    ) {
        let idx = vpage as usize & (SETS - 1);
        self.vpage[idx] = vpage;
        self.mem_idx[idx] = mem_idx;
        self.page_byte_offset[idx] = page_byte_offset;
        self.perm[idx] = perm;
    }

    /// Flush all entries.
    pub const fn flush_all(&mut self) {
        self.vpage = [INVALID_VPAGE; SETS];
        self.perm = [INVALID_PERM; SETS];
    }

    /// Flush entries matching the given ASID (skip global and invalid entries).
    pub fn flush_asid(&mut self, asid: u16) {
        let target = asid << PERM_ASID_SHIFT;
        for i in 0..SETS {
            if self.perm[i] & !0xF == target {
                self.vpage[i] = INVALID_VPAGE;
                self.perm[i] = INVALID_PERM;
            }
        }
    }

    /// Flush the entry for the given virtual page (all ASIDs).
    pub const fn flush_vpage(&mut self, vpage: u32) {
        let idx = vpage as usize & (SETS - 1);
        if self.vpage[idx] == vpage {
            self.vpage[idx] = INVALID_VPAGE;
            self.perm[idx] = INVALID_PERM;
        }
    }

    /// Flush the entry for the given virtual page and ASID.
    pub const fn flush_vpage_asid(&mut self, vpage: u32, asid: u16) {
        let idx = vpage as usize & (SETS - 1);
        if self.vpage[idx] == vpage {
            let p = self.perm[idx];
            if p & !0xF == (asid << PERM_ASID_SHIFT) {
                self.vpage[idx] = INVALID_VPAGE;
                self.perm[idx] = INVALID_PERM;
            }
        }
    }
}
