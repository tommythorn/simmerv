//! Two 128 KiB data caches of two direct-mapped 64 KiB ways whose ways are
//! both looked up on every access, so every hit is a fast hit and no line
//! moves on a hit.
//!
//! [`Virt`]: both ways virtually tagged. Way 0 is indexed by VA[15:6], way 1 by
//! an xor-fold of the virtual line; tags carry an epoch that `SFENCE.VMA` and
//! `satp` writes advance. A miss translates through a miss-path TLB, then
//! looks for the physical line at way 0's 16 colours of its row and in a
//! physically indexed, set-associative reverse directory that names the way-1
//! slot of every way-1 line. A line found there under a stale epoch or
//! another virtual address is re-stamped into the slot its new address
//! selects, which is a move unless that is where it already is. The
//! directory is inclusive: a full directory set evicts a way-1 line.
//!
//! [`Pipt`]: both ways physically tagged, way 0 indexed by PA[15:6] and way 1
//! by an xor-fold of the physical line; every access is translated first
//! (see [`Xtlb`]), and a physical line has exactly two possible slots.
//!
//! Both place a new line in the less recently used of its two candidate
//! slots; [`Virt`] also has a variant that fills way 0 unless the way-0
//! candidate has been hit since it was last considered.

use super::F_PF;
use super::NO_LINE;
use super::Sa;
use super::Xlat;
use super::page_key;
use super::sized_key;
use std::fmt::Write as _;

const SETS: usize = 1024;
const ROWS: usize = 64;
const F_REUSE: u8 = 16;

#[derive(Clone, Copy)]
struct Slot {
    pa: u64,
    va: u64,
    epoch: u32,
    stamp: u64,
    flags: u8,
}

const EMPTY: Slot = Slot {
    pa: NO_LINE,
    va: NO_LINE,
    epoch: 0,
    stamp: 0,
    flags: 0,
};

const fn fold(line: u64) -> u64 { line ^ line >> 10 ^ line >> 20 }

/// Prefetch-effectiveness counters shared by the models.
#[derive(Default)]
struct Pf {
    issued: u64,
    useful: u64,
    lookups: u64,
    walks: u64,
}

/// Both ways virtually tagged, with a physical reverse directory for way 1.
pub struct Virt {
    pub name: String,
    pub degree: i64,
    reuse: bool,
    w0: Vec<Slot>,
    w1: Vec<Slot>,
    /// Directory: `(physical line, way-1 slot, stamp)`, `dways` per set.
    d: Vec<(u64, usize, u64)>,
    dways: usize,
    epoch: u32,
    clk: u64,
    t4: Sa,
    t2: Sa,
    hit0: u64,
    hit1: u64,
    dram: u64,
    by_pa: u64,
    restamp: u64,
    moves: u64,
    dlook: u64,
    forced: u64,
    lookups: u64,
    walks: u64,
    pte_reads: u64,
    pte_dram: u64,
    pf: Pf,
}

impl Virt {
    pub fn new(reuse: bool, dentries: usize, degree: i64) -> Self {
        let mut name = format!("B-{}-D{dentries}", if reuse { "reuse" } else { "LRU" });
        if degree > 0 {
            let _ = write!(name, "-RPT64d{degree}");
        }
        Self {
            name,
            degree,
            reuse,
            w0: vec![EMPTY; SETS],
            w1: vec![EMPTY; SETS],
            d: vec![(NO_LINE, 0, 0); dentries],
            dways: 4,
            epoch: 1,
            clk: 0,
            t4: Sa::new(2048, 4),
            t2: Sa::new(64, 64),
            hit0: 0,
            hit1: 0,
            dram: 0,
            by_pa: 0,
            restamp: 0,
            moves: 0,
            dlook: 0,
            forced: 0,
            lookups: 0,
            walks: 0,
            pte_reads: 0,
            pte_dram: 0,
            pf: Pf::default(),
        }
    }

    const fn i0(vl: u64) -> usize { vl as usize & (SETS - 1) }
    const fn i1(vl: u64) -> usize { fold(vl) as usize & (SETS - 1) }
    fn dset(&self, pl: u64) -> usize {
        let sets = self.d.len() / self.dways;
        (fold(pl) as usize & (sets - 1)) * self.dways
    }

    pub fn flush(&mut self) {
        self.epoch += 1;
        self.t4.flush();
        self.t2.flush();
    }

    fn live(&self, s: &Slot, vl: u64) -> bool {
        s.pa != NO_LINE && s.va == vl && s.epoch == self.epoch
    }

    fn d_remove(&mut self, pl: u64) {
        let b = self.dset(pl);
        for e in &mut self.d[b..b + self.dways] {
            if e.0 == pl {
                e.0 = NO_LINE;
                return;
            }
        }
    }

    fn evict1(&mut self, j: usize) {
        let s = self.w1[j];
        if s.pa != NO_LINE {
            self.d_remove(s.pa);
        }
        self.w1[j] = EMPTY;
    }

    /// Enter way-1 slot `j`, now holding `pl`, in the directory; a full set
    /// evicts the way-1 line of its least recently entered member.
    fn d_insert(&mut self, pl: u64, j: usize) {
        let b = self.dset(pl);
        let mut v = b;
        for k in b..b + self.dways {
            if self.d[k].0 == NO_LINE {
                v = k;
                break;
            }
            if self.d[k].2 < self.d[v].2 {
                v = k;
            }
        }
        if self.d[v].0 != NO_LINE {
            self.forced += 1;
            let slot = self.d[v].1;
            self.d[v].0 = NO_LINE;
            self.w1[slot] = EMPTY;
        }
        self.d[v] = (pl, j, self.clk);
    }

    /// The slot holding physical line `pl`: way 0's colours of its row, then
    /// the directory.
    fn find(&mut self, pl: u64) -> Option<(u8, usize)> {
        self.dlook += 1;
        let row = pl as usize % ROWS;
        if let Some(j) = (0..16)
            .map(|c| c * ROWS + row)
            .find(|&j| self.w0[j].pa == pl)
        {
            return Some((0, j));
        }
        let b = self.dset(pl);
        self.d[b..b + self.dways]
            .iter()
            .find(|e| e.0 == pl)
            .map(|e| (1, e.1))
    }

    fn place(&mut self, vl: u64, pl: u64, flags: u8) {
        let (i, j) = (Self::i0(vl), Self::i1(vl));
        let new = Slot {
            pa: pl,
            va: vl,
            epoch: self.epoch,
            stamp: self.clk,
            flags,
        };
        let to_w0 = if self.reuse {
            let reused = self.w0[i].pa != NO_LINE && self.w0[i].flags & F_REUSE != 0;
            if reused {
                self.w0[i].flags &= !F_REUSE;
            }
            !reused
        } else {
            self.w0[i].pa == NO_LINE
                || (self.w1[j].pa != NO_LINE && self.w0[i].stamp <= self.w1[j].stamp)
        };
        if to_w0 {
            self.w0[i] = new;
        } else {
            self.evict1(j);
            self.w1[j] = new;
            self.d_insert(pl, j);
        }
    }

    fn translate(&mut self, x: &Xlat, va: u64, prefetch: bool) {
        if x.shift == 30 {
            return;
        }
        let hit = if x.shift == 21 {
            let (k, i) = sized_key(va, 21);
            self.t2.access(k, i, 0)
        } else {
            let (k, i) = page_key(va);
            self.t4.access(k, i, 0)
        };
        if prefetch {
            self.pf.lookups += 1;
        } else {
            self.lookups += 1;
        }
        if !hit {
            if prefetch {
                self.pf.walks += 1;
            } else {
                self.walks += 1;
            }
            for k in 0..x.nlev as usize {
                self.pte(x.pte[k] >> 6);
            }
        }
    }

    fn pte(&mut self, pl: u64) {
        self.clk += 1;
        self.pte_reads += 1;
        if self.find(pl).is_some() {
            return;
        }
        self.pte_dram += 1;
        let j = fold(pl) as usize & (SETS - 1);
        self.evict1(j);
        self.w1[j] = Slot {
            pa: pl,
            va: NO_LINE,
            epoch: 0,
            stamp: self.clk,
            flags: 0,
        };
        self.d_insert(pl, j);
    }

    fn use_line(&mut self, f: u8) -> u8 {
        if f & F_PF != 0 {
            self.pf.useful += 1;
        }
        f & !F_PF
    }

    pub fn demand(&mut self, va: u64, pa: u64, x: Option<&Xlat>) {
        self.clk += 1;
        let vl = va >> 6;
        let (i, j) = (Self::i0(vl), Self::i1(vl));
        if self.live(&self.w0[i], vl) {
            self.hit0 += 1;
            let f = self.use_line(self.w0[i].flags);
            self.w0[i].flags = f | F_REUSE;
            self.w0[i].stamp = self.clk;
            return;
        }
        if self.live(&self.w1[j], vl) {
            self.hit1 += 1;
            let f = self.use_line(self.w1[j].flags);
            self.w1[j].flags = f;
            self.w1[j].stamp = self.clk;
            return;
        }
        if let Some(x) = x {
            self.translate(x, va, false);
        }
        let pl = pa >> 6;
        let stamp = |s: Slot, epoch, clk| Slot {
            va: vl,
            epoch,
            stamp: clk,
            ..s
        };
        match self.find(pl) {
            Some((0, k)) => {
                self.by_pa += 1;
                let mut line = self.w0[k];
                line.flags = self.use_line(line.flags);
                self.w0[k] = EMPTY;
                if k == i {
                    self.restamp += 1;
                } else {
                    self.moves += 1;
                }
                self.w0[i] = stamp(line, self.epoch, self.clk);
            }
            Some((_, k)) => {
                self.by_pa += 1;
                let mut line = self.w1[k];
                line.flags = self.use_line(line.flags);
                if k == j {
                    self.restamp += 1;
                    self.w1[j] = stamp(line, self.epoch, self.clk);
                } else {
                    self.moves += 1;
                    self.evict1(k);
                    self.evict1(j);
                    self.w1[j] = stamp(line, self.epoch, self.clk);
                    self.d_insert(pl, j);
                }
            }
            None => {
                self.dram += 1;
                self.place(vl, pl, 0);
            }
        }
    }

    /// A prefetch of virtual address `t`, physical line `pl`; `lookup` is its
    /// translation when it crosses into another page.
    pub fn prefetch(&mut self, t: u64, pl: u64, lookup: Option<&Xlat>) {
        self.clk += 1;
        let vl = t >> 6;
        if self.live(&self.w0[Self::i0(vl)], vl) || self.live(&self.w1[Self::i1(vl)], vl) {
            return;
        }
        if let Some(x) = lookup {
            self.translate(x, t, true);
        }
        if self.find(pl).is_some() {
            return;
        }
        self.pf.issued += 1;
        self.place(vl, pl, F_PF);
    }

    pub fn raw(&self, o: &mut String) {
        let _ = writeln!(
            o,
            "VIRTRAW {} hit0={} hit1={} dram={} by_pa={} restamp={} moves={} dlook={} forced={} lookups={} walks={} pte_reads={} pte_dram={} issued={} useful={} pf_lookups={} pf_walks={}",
            self.name,
            self.hit0,
            self.hit1,
            self.dram,
            self.by_pa,
            self.restamp,
            self.moves,
            self.dlook,
            self.forced,
            self.lookups,
            self.walks,
            self.pte_reads,
            self.pte_dram,
            self.pf.issued,
            self.pf.useful,
            self.pf.lookups,
            self.pf.walks
        );
    }
}

/// Both ways physically tagged; translated before the lookup, by today's
/// 16-entry direct-mapped dTLB in front of the second-level tables, whose
/// walks read their PTEs through this cache and which page-crossing
/// prefetches look up.
pub struct Pipt {
    pub name: String,
    pub degree: i64,
    pub tlb: Xtlb,
    w0: Vec<Slot>,
    w1: Vec<Slot>,
    clk: u64,
    hit0: u64,
    hit1: u64,
    dram: u64,
    pte_reads: u64,
    pte_dram: u64,
    pf: Pf,
}

impl Pipt {
    pub fn new(degree: i64) -> Self {
        Self {
            name: if degree > 0 {
                format!("PIPT-skew-RPT64d{degree}")
            } else {
                "PIPT-skew".to_string()
            },
            degree,
            tlb: Xtlb::new(16, 1, true),
            w0: vec![EMPTY; SETS],
            w1: vec![EMPTY; SETS],
            clk: 0,
            hit0: 0,
            hit1: 0,
            dram: 0,
            pte_reads: 0,
            pte_dram: 0,
            pf: Pf::default(),
        }
    }

    const fn slots(pl: u64) -> (usize, usize) {
        (pl as usize & (SETS - 1), fold(pl) as usize & (SETS - 1))
    }

    fn present(&self, pl: u64) -> bool {
        let (i, j) = Self::slots(pl);
        self.w0[i].pa == pl || self.w1[j].pa == pl
    }

    fn fill(&mut self, pl: u64, flags: u8) {
        let (i, j) = Self::slots(pl);
        let new = Slot {
            pa: pl,
            va: NO_LINE,
            epoch: 0,
            stamp: self.clk,
            flags,
        };
        if self.w0[i].pa == NO_LINE
            || (self.w1[j].pa != NO_LINE && self.w0[i].stamp <= self.w1[j].stamp)
        {
            self.w0[i] = new;
        } else {
            self.w1[j] = new;
        }
    }

    /// A read or write of physical line `pl`.
    pub fn demand(&mut self, pl: u64) {
        self.clk += 1;
        let (i, j) = Self::slots(pl);
        for (way, k) in [(0, i), (1, j)] {
            let s = if way == 0 {
                &mut self.w0[k]
            } else {
                &mut self.w1[k]
            };
            if s.pa == pl {
                s.stamp = self.clk;
                if s.flags & F_PF != 0 {
                    s.flags &= !F_PF;
                    self.pf.useful += 1;
                }
                if way == 0 {
                    self.hit0 += 1;
                } else {
                    self.hit1 += 1;
                }
                return;
            }
        }
        self.dram += 1;
        self.fill(pl, 0);
    }

    pub fn pte(&mut self, pl: u64) {
        self.clk += 1;
        self.pte_reads += 1;
        if !self.present(pl) {
            self.pte_dram += 1;
            self.fill(pl, 0);
        }
    }

    /// Translate a data access at `va`; a walk reads its PTEs through here.
    pub fn translate(&mut self, x: &Xlat, va: u64) {
        if self.tlb.access(x, va) {
            for k in 0..x.nlev as usize {
                self.pte(x.pte[k] >> 6);
            }
        }
    }

    /// A prefetch of virtual address `t`, physical line `pl`; `lookup` is its
    /// translation when it crosses into another page, which then goes
    /// through the second-level TLB.
    pub fn prefetch(&mut self, t: u64, pl: u64, lookup: Option<&Xlat>) {
        self.clk += 1;
        if let Some(x) = lookup {
            self.pf.lookups += 1;
            if self.tlb.prefetch(x, t) {
                self.pf.walks += 1;
                for k in 0..x.nlev as usize {
                    self.pte(x.pte[k] >> 6);
                }
            }
        }
        if self.present(pl) {
            return;
        }
        self.pf.issued += 1;
        self.fill(pl, F_PF);
    }

    pub fn raw(&self, o: &mut String) {
        let _ = writeln!(
            o,
            "PIPTRAW {} hit0={} hit1={} dram={} l1miss={} walks={} pte_reads={} pte_dram={} issued={} useful={} pf_lookups={} pf_walks={}",
            self.name,
            self.hit0,
            self.hit1,
            self.dram,
            self.tlb.l1miss,
            self.tlb.walks,
            self.pte_reads,
            self.pte_dram,
            self.pf.issued,
            self.pf.useful,
            self.pf.lookups,
            self.pf.walks
        );
    }
}

/// A first-level dTLB in front of a second level of a 2048-entry 4-way table
/// for 4 KiB (and NAPOT) leaves and a 64-entry fully associative table for
/// 2 MiB leaves.
pub struct Xtlb {
    pub name: String,
    l1: Sa,
    l1_page_keyed: bool,
    l2_4k: Sa,
    l2_2m: Sa,
    l1miss: u64,
    walks: u64,
}

impl Xtlb {
    pub fn new(entries: usize, ways: usize, page_keyed: bool) -> Self {
        let l1 = Sa::new(entries, ways);
        Self {
            name: format!("L1-{}", l1.name().replace(' ', "")),
            l1,
            l1_page_keyed: page_keyed,
            l2_4k: Sa::new(2048, 4),
            l2_2m: Sa::new(64, 64),
            l1miss: 0,
            walks: 0,
        }
    }

    pub fn flush(&mut self) {
        self.l1.flush();
        self.l2_4k.flush();
        self.l2_2m.flush();
    }

    fn l2(&mut self, x: &Xlat, va: u64) -> bool {
        if x.shift == 21 {
            let (k, i) = sized_key(va, 21);
            self.l2_2m.access(k, i, 0)
        } else {
            let (k, i) = page_key(va);
            self.l2_4k.access(k, i, 0)
        }
    }

    /// Translate a data access; returns whether it walked.
    pub fn access(&mut self, x: &Xlat, va: u64) -> bool {
        if x.shift == 30 {
            return false;
        }
        let (k, i) = if self.l1_page_keyed {
            page_key(va)
        } else {
            sized_key(va, x.shift)
        };
        if self.l1.access(k, i, 0) {
            return false;
        }
        self.l1miss += 1;
        if self.l2(x, va) {
            return false;
        }
        self.walks += 1;
        true
    }

    /// A prefetch's translation through the second level only; returns
    /// whether it walked.
    pub fn prefetch(&mut self, x: &Xlat, va: u64) -> bool {
        let walked = x.shift != 30 && !self.l2(x, va);
        if walked {
            self.walks += 1;
        }
        walked
    }

    pub fn raw(&self, o: &mut String) {
        let _ = writeln!(
            o,
            "XTLBRAW {} l1miss={} walks={}",
            self.name, self.l1miss, self.walks
        );
    }
}
