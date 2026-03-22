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

struct TlbWay<const SETS: usize> {
    vpage: [u32; SETS],
    ppage: [u32; SETS],
    perm: [u16; SETS],
}

impl<const SETS: usize> TlbWay<SETS> {
    const fn new() -> Self {
        Self {
            vpage: [INVALID_VPAGE; SETS],
            ppage: [0; SETS],
            perm: [INVALID_PERM; SETS],
        }
    }
}

pub struct Tlb<const SETS: usize> {
    ways: [TlbWay<SETS>; 2],
    replace_ctr: u8,
    pub misses: u64,
}

/// Hash a (vpage, asid) pair to a way slot index in `0..SETS`.
#[inline(always)]
fn index_way<const SETS: usize>(way: usize, vpage: u32, asid: u16) -> usize {
    let a = u32::from(asid);
    let h = if way == 0 {
        vpage ^ a
    } else {
        vpage ^ (vpage >> 8) ^ (a << 4)
    };
    h as usize & (SETS - 1)
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
    let mut xwr = perm & 7;
    // MXR: make execute-only pages also readable
    if mxr {
        xwr |= (xwr >> 2) & PERM_R;
    }
    // Access type check
    if (xwr >> access_shift) & 1 == 0 {
        return false;
    }
    // Privilege check
    let is_user_page = perm & PERM_U != 0;
    if prv_is_user {
        if !is_user_page {
            return false;
        }
    } else if is_user_page && !sum {
        return false;
    }
    true
}

impl<const SETS: usize> Default for Tlb<SETS> {
    fn default() -> Self { Self::new() }
}

impl<const SETS: usize> Tlb<SETS> {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ways: [TlbWay::new(), TlbWay::new()],
            replace_ctr: 0,
            misses: 0,
        }
    }

    /// Look up a virtual page number. Returns `(ppage, perm)` on hit.
    #[must_use]
    #[inline(always)]
    pub fn lookup(&self, vpage: u32, asid: u16) -> Option<(u32, u16)> {
        for (way_idx, way) in self.ways.iter().enumerate() {
            let idx = index_way::<SETS>(way_idx, vpage, asid);
            if way.vpage[idx] == vpage {
                let p = way.perm[idx];
                let entry_asid = p >> PERM_ASID_SHIFT;
                if p & PERM_G != 0 || entry_asid == asid {
                    return Some((way.ppage[idx], p));
                }
            }
        }
        None
    }

    /// Insert an entry. `perm` should be produced by `pack_perm`.
    #[inline]
    pub fn insert(&mut self, vpage: u32, ppage: u32, perm: u16, asid: u16) {
        let idx0 = index_way::<SETS>(0, vpage, asid);
        let idx1 = index_way::<SETS>(1, vpage, asid);
        let way_idx = if self.ways[0].vpage[idx0] == INVALID_VPAGE {
            0
        } else if self.ways[1].vpage[idx1] == INVALID_VPAGE {
            1
        } else {
            let w = (self.replace_ctr & 1) as usize;
            self.replace_ctr = self.replace_ctr.wrapping_add(1);
            w
        };
        let idx = if way_idx == 0 { idx0 } else { idx1 };
        self.ways[way_idx].vpage[idx] = vpage;
        self.ways[way_idx].ppage[idx] = ppage;
        self.ways[way_idx].perm[idx] = perm;
    }

    /// Flush all entries.
    pub fn flush_all(&mut self) {
        for way in &mut self.ways {
            way.vpage = [INVALID_VPAGE; SETS];
            way.perm = [INVALID_PERM; SETS];
        }
    }

    /// Flush entries matching the given ASID (skip global and invalid entries).
    ///
    /// Because `INVALID_PERM` has `PERM_G` set (bit 4), `p & !0xF` will have
    /// bit 4 set for invalid entries, while `asid << PERM_ASID_SHIFT` never
    /// has bit 4 set.  Global entries similarly have bit 4 set.  So the single
    /// comparison naturally skips both.
    pub fn flush_asid(&mut self, asid: u16) {
        let target = asid << PERM_ASID_SHIFT;
        for way in &mut self.ways {
            for i in 0..SETS {
                if way.perm[i] & !0xF == target {
                    way.vpage[i] = INVALID_VPAGE;
                    way.perm[i] = INVALID_PERM;
                }
            }
        }
    }

    /// Flush entries matching the given virtual page (all ASIDs).
    pub fn flush_vpage(&mut self, vpage: u32) {
        for way in &mut self.ways {
            for i in 0..SETS {
                if way.vpage[i] == vpage {
                    way.vpage[i] = INVALID_VPAGE;
                    way.perm[i] = INVALID_PERM;
                }
            }
        }
    }

    /// Flush entries matching both the given virtual page and ASID.
    pub fn flush_vpage_asid(&mut self, vpage: u32, asid: u16) {
        for (way_idx, way) in self.ways.iter_mut().enumerate() {
            let idx = index_way::<SETS>(way_idx, vpage, asid);
            if way.vpage[idx] == vpage {
                let p = way.perm[idx];
                if p & PERM_G == 0 && (p >> PERM_ASID_SHIFT) == asid {
                    way.vpage[idx] = INVALID_VPAGE;
                    way.perm[idx] = INVALID_PERM;
                }
            }
        }
    }
}
