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
//! With `ptag1`, way 1 is still indexed by the virtual line but tagged only by
//! the physical line: when way 0 misses, way 1's line is returned
//! speculatively and confirmed (or not) by the physical address from the
//! miss-path TLB.
//!
//! [`Pipt`]: both ways physically tagged, way 0 indexed by PA[15:6] and way 1
//! by an xor-fold of the physical line; every access is translated first
//! (see [`Xtlb`]), and a physical line has exactly two possible slots.
//!
//! Placement between a new line's two candidate slots is one of [`Place`].

use super::Cache;
use super::F_PF;
use super::NO_LINE;
use super::Repl;
use super::Sa;
use super::Xlat;
use super::page_key;
use super::sized_key;
use std::fmt::Write as _;

const SETS: usize = 1024;
const ROWS: usize = 64;
const F_REUSE: u8 = 16;
/// Not-recently-used state: set when a line is filled or hit.
const F_USED: u8 = 32;

/// Which of its two candidate slots a new line fills.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Place {
    /// The less recently used of the two.
    Lru,
    /// Way 0, unless its line has been hit since it was last considered.
    Reuse,
    /// The one whose used bit is clear, way 0 if both are; if both are set,
    /// clear both and fill way 0.
    NruW0,
    /// As `NruW0`, but fill way 1 when both used bits are set.
    NruW1,
    /// As `NruW0`, but fill the earlier-filled one when both are set.
    NruOlder,
}

/// Whether a new line goes to way-0 candidate `a` rather than way-1
/// candidate `b` (`Place::Reuse` is decided by the caller).
fn choose(a: &mut Slot, b: &mut Slot, place: Place) -> bool {
    if a.pa == NO_LINE {
        return true;
    }
    if b.pa == NO_LINE {
        return false;
    }
    match place {
        Place::Lru | Place::Reuse => a.stamp <= b.stamp,
        _ => {
            if a.flags & F_USED == 0 {
                return true;
            }
            if b.flags & F_USED == 0 {
                return false;
            }
            a.flags &= !F_USED;
            b.flags &= !F_USED;
            match place {
                Place::NruW1 => false,
                Place::NruOlder => a.filled <= b.filled,
                _ => true,
            }
        }
    }
}

#[derive(Clone, Copy)]
struct Slot {
    pa: u64,
    va: u64,
    epoch: u32,
    stamp: u64,
    /// When the line was filled.
    filled: u64,
    flags: u8,
}

const EMPTY: Slot = Slot {
    pa: NO_LINE,
    va: NO_LINE,
    epoch: 0,
    stamp: 0,
    filled: 0,
    flags: 0,
};

const fn fold(line: u64) -> u64 { line ^ line >> 10 ^ line >> 20 }

/// Physical second-level caches (bytes, ways, hashed index) behind a
/// first-level model, unless `SIMMERV_WSET_L2` lists others as
/// `<KiB>k<ways>[h]`, comma-separated (`h`: the index is xor-folded).
const L2SZ: [(usize, usize, bool); 3] = [
    (512 << 10, 8, false),
    (1 << 20, 16, false),
    (2 << 20, 16, false),
];

/// A dirty line: written since it was filled.
const F_DIRTY: u8 = 64;

fn l2_sizes() -> Vec<(usize, usize, bool)> {
    let Some(v) = std::env::var_os("SIMMERV_WSET_L2") else {
        return L2SZ.to_vec();
    };
    v.to_string_lossy()
        .split(',')
        .filter_map(|e| {
            let (kib, rest) = e.split_once('k')?;
            let hashed = rest.ends_with('h');
            let ways = rest.trim_end_matches('h').parse().ok()?;
            Some((kib.parse::<usize>().ok()? << 10, ways, hashed))
        })
        .collect()
}

/// Second-level caches of every size in [`l2_sizes`], each seeing every line
/// the first level fetches from below it and every dirty line it evicts.
/// Counted per cache: DRAM reads for data and for instruction fetches, and
/// DRAM writes (dirty second-level victims).
struct L2s {
    sz: Vec<(usize, usize, bool)>,
    c: Vec<Cache>,
    miss: Vec<u64>,
    imiss: Vec<u64>,
    wr: Vec<u64>,
}

impl L2s {
    fn new() -> Self {
        let sz = l2_sizes();
        Self {
            c: sz
                .iter()
                .map(|&(b, w, hashed)| Cache {
                    hashed,
                    ..Cache::new(b, w)
                })
                .collect(),
            miss: vec![0; sz.len()],
            imiss: vec![0; sz.len()],
            wr: vec![0; sz.len()],
            sz,
        }
    }

    fn read(&mut self, pl: u64, insn: bool) {
        for k in 0..self.c.len() {
            if self.c[k].lookup(pl).is_none() {
                if insn {
                    self.imiss[k] += 1;
                } else {
                    self.miss[k] += 1;
                }
                if let Some((_, f)) = self.c[k].fill_victim(pl, 0)
                    && f & F_DIRTY != 0
                {
                    self.wr[k] += 1;
                }
            }
        }
    }

    fn fetch(&mut self, pl: u64) { self.read(pl, false); }

    /// A line fetched by the instruction cache.
    pub fn ifetch(&mut self, pl: u64) { self.read(pl, true); }

    /// A dirty line evicted from the first level: a whole-line write, which
    /// allocates without a read.
    fn writeback(&mut self, pl: u64) {
        for k in 0..self.c.len() {
            match self.c[k].lookup(pl) {
                Some(i) => self.c[k].flag[i] |= F_DIRTY,
                None => {
                    if let Some((_, f)) = self.c[k].fill_victim(pl, F_DIRTY)
                        && f & F_DIRTY != 0
                    {
                        self.wr[k] += 1;
                    }
                }
            }
        }
    }

    fn raw(&self, o: &mut String) {
        for (k, &(b, w, h)) in self.sz.iter().enumerate() {
            let n = format!("l2_{}k{w}w{}", b >> 10, if h { "h" } else { "" });
            let _ = write!(
                o,
                " {n}={} {n}_i={} {n}_wr={}",
                self.miss[k], self.imiss[k], self.wr[k]
            );
        }
    }
}

/// Direct-mapped 4 KiB tables of 2048 and 4096 entries (indexed by the low
/// VPN bits), each beside a 32-entry direct-mapped and a 64-entry fully
/// associative 2 MiB table.
pub struct DmTlbs {
    t4: [Sa; 2],
    t2: [Sa; 2],
    lookups: u64,
}

impl DmTlbs {
    pub fn new() -> Self {
        Self {
            t4: [Sa::new(2048, 1), Sa::new(4096, 1)],
            t2: [Sa::new(32, 1), Sa::new(64, 64)],
            lookups: 0,
        }
    }
    pub fn flush(&mut self) {
        for t in self.t4.iter_mut().chain(self.t2.iter_mut()) {
            t.flush();
        }
    }
    pub fn access(&mut self, x: &Xlat, va: u64) {
        self.lookups += 1;
        if x.shift == 21 {
            let (k, i) = sized_key(va, 21);
            for t in &mut self.t2 {
                t.access(k, i, 0);
            }
        } else if x.shift != 30 {
            let (k, i) = page_key(va);
            for t in &mut self.t4 {
                t.access(k, i, 0);
            }
        }
    }
    pub fn raw(&self, o: &mut String, name: &str) {
        let _ = writeln!(
            o,
            "DMTLBRAW {name} lookups={} m4k2048={} m4k4096={} m2m32dm={} m2m64fa={}",
            self.lookups,
            self.t4[0].miss[0],
            self.t4[1].miss[0],
            self.t2[0].miss[0],
            self.t2[1].miss[0]
        );
    }
}

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
    place: Place,
    ptag1: bool,
    /// Direct-mapped TLBs on this cache's way-0 misses.
    dm: DmTlbs,
    spec: u64,
    misspec: u64,
    misspec_miss: u64,
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
    /// Way 1 indexed like way 0 (a plain 2-way cache); its lines are found
    /// by physical line at way 1's 16 colours of the row, as way 0's are.
    straight: bool,
    /// A directory entry's way within its set is the low bits of its way-1
    /// slot, so it is written without a search; a new way-1 line whose entry
    /// is taken goes to way 0 instead (no forced evictions).
    dslot: bool,
    /// Way-1 fills that went to way 0 because their directory entry was taken.
    dfall: u64,
    l2: L2s,
}

impl Virt {
    pub fn new(ptag1: bool, place: Place, dentries: usize, degree: i64) -> Self {
        let mut name = format!(
            "{}-{}-D{dentries}",
            if ptag1 { "Bp" } else { "B" },
            match place {
                Place::Lru => "LRU".to_string(),
                Place::Reuse => "reuse".to_string(),
                p => format!("{p:?}"),
            }
        );
        if degree > 0 {
            let _ = write!(name, "-RPT64d{degree}");
        }
        Self {
            name,
            degree,
            place,
            ptag1,
            dm: DmTlbs::new(),
            spec: 0,
            misspec: 0,
            misspec_miss: 0,
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
            straight: false,
            dslot: false,
            dfall: 0,
            l2: L2s::new(),
        }
    }

    /// Way 1 indexed like way 0: a plain 2-way cache.
    pub fn straight(mut self) -> Self {
        self.straight = true;
        self.name = format!("straight-{:?}", self.place);
        self
    }

    /// Directory entries placed by their way-1 slot, no forced evictions.
    pub fn dslot(mut self) -> Self {
        self.dslot = true;
        self.name.push_str("-slot");
        self
    }

    const fn i0(vl: u64) -> usize { vl as usize & (SETS - 1) }
    fn i1(&self, vl: u64) -> usize {
        if self.straight {
            Self::i0(vl)
        } else {
            fold(vl) as usize & (SETS - 1)
        }
    }
    fn dset(&self, pl: u64) -> usize {
        let sets = self.d.len() / self.dways;
        (fold(pl) as usize & (sets - 1)) * self.dways
    }

    pub fn flush(&mut self) {
        self.epoch += 1;
        self.t4.flush();
        self.t2.flush();
        self.dm.flush();
    }

    fn live(&self, s: &Slot, vl: u64) -> bool {
        s.pa != NO_LINE && s.va == vl && s.epoch == self.epoch
    }

    fn d_remove(&mut self, pl: u64) {
        if self.straight {
            return;
        }
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

    /// Whether a new way-1 line `pl` at slot `j` must go to way 0 instead: its
    /// directory entry is taken by another line than the one `j` holds now.
    fn d_taken(&self, pl: u64, j: usize) -> bool {
        if !self.dslot {
            return false;
        }
        let e = self.d[self.dset(pl) + (j & (self.dways - 1))];
        e.0 != NO_LINE && e.0 != self.w1[j].pa
    }

    /// Enter way-1 slot `j`, now holding `pl`, in the directory; a full set
    /// evicts the way-1 line of its least recently entered member.
    fn d_insert(&mut self, pl: u64, j: usize) {
        if self.straight {
            return;
        }
        let b = self.dset(pl);
        if self.dslot {
            let k = b + (j & (self.dways - 1));
            assert!(self.d[k].0 == NO_LINE, "wset: directory slot taken");
            self.d[k] = (pl, j, self.clk);
            return;
        }
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
        if self.straight {
            return (0..16)
                .map(|c| c * ROWS + row)
                .find(|&j| self.w1[j].pa == pl)
                .map(|j| (1, j));
        }
        let b = self.dset(pl);
        self.d[b..b + self.dways]
            .iter()
            .find(|e| e.0 == pl)
            .map(|e| (1, e.1))
    }

    fn place(&mut self, vl: u64, pl: u64, flags: u8) {
        let (i, j) = (Self::i0(vl), self.i1(vl));
        let new = Slot {
            pa: pl,
            va: vl,
            epoch: self.epoch,
            stamp: self.clk,
            filled: self.clk,
            flags: flags | F_USED,
        };
        let to_w0 = if self.place == Place::Reuse {
            let reused = self.w0[i].pa != NO_LINE && self.w0[i].flags & F_REUSE != 0;
            if reused {
                self.w0[i].flags &= !F_REUSE;
            }
            !reused
        } else {
            choose(&mut self.w0[i], &mut self.w1[j], self.place)
        };
        if to_w0 {
            self.w0[i] = new;
        } else if self.d_taken(pl, j) {
            self.dfall += 1;
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
            self.dm.access(x, va);
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
        self.l2.fetch(pl);
        let j = fold(pl) as usize & (SETS - 1);
        let line = Slot {
            pa: pl,
            va: NO_LINE,
            epoch: 0,
            stamp: self.clk,
            filled: self.clk,
            flags: F_USED,
        };
        if self.straight || self.d_taken(pl, j) {
            // by PA in its own colour: way 0 at the PA's set
            self.dfall += u64::from(!self.straight);
            self.w0[Self::i0(pl)] = line;
            return;
        }
        self.evict1(j);
        self.w1[j] = Slot {
            pa: pl,
            va: NO_LINE,
            epoch: 0,
            stamp: self.clk,
            filled: self.clk,
            flags: F_USED,
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
        let (i, j) = (Self::i0(vl), self.i1(vl));
        if self.live(&self.w0[i], vl) {
            self.hit0 += 1;
            let f = self.use_line(self.w0[i].flags);
            self.w0[i].flags = f | F_REUSE | F_USED;
            self.w0[i].stamp = self.clk;
            return;
        }
        let pl = pa >> 6;
        if !self.ptag1 && self.live(&self.w1[j], vl) {
            self.hit1 += 1;
            let f = self.use_line(self.w1[j].flags);
            self.w1[j].flags = f | F_USED;
            self.w1[j].stamp = self.clk;
            return;
        }
        let spec = self.ptag1 && self.w1[j].pa != NO_LINE;
        if spec {
            self.spec += 1;
        }
        if let Some(x) = x {
            self.translate(x, va, false);
        }
        if self.ptag1 && self.w1[j].pa == pl {
            self.hit1 += 1;
            let f = self.use_line(self.w1[j].flags);
            self.w1[j] = Slot {
                va: vl,
                epoch: self.epoch,
                stamp: self.clk,
                flags: f | F_USED,
                ..self.w1[j]
            };
            return;
        }
        if spec {
            self.misspec += 1;
        }
        let stamp = |s: Slot, epoch, clk| Slot {
            va: vl,
            epoch,
            stamp: clk,
            flags: s.flags | F_USED,
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
                    if self.d_taken(pl, j) {
                        self.dfall += 1;
                        self.w0[i] = stamp(line, self.epoch, self.clk);
                    } else {
                        self.evict1(j);
                        self.w1[j] = stamp(line, self.epoch, self.clk);
                        self.d_insert(pl, j);
                    }
                }
            }
            None => {
                self.dram += 1;
                self.l2.fetch(pl);
                if spec {
                    self.misspec_miss += 1;
                }
                self.place(vl, pl, 0);
            }
        }
    }

    /// A prefetch of virtual address `t`, physical line `pl`; `lookup` is its
    /// translation when it crosses into another page.
    pub fn prefetch(&mut self, t: u64, pl: u64, lookup: Option<&Xlat>) {
        self.clk += 1;
        let vl = t >> 6;
        if self.live(&self.w0[Self::i0(vl)], vl)
            || (!self.ptag1 && self.live(&self.w1[self.i1(vl)], vl))
        {
            return;
        }
        if let Some(x) = lookup {
            self.translate(x, t, true);
        }
        if self.find(pl).is_some() {
            return;
        }
        self.pf.issued += 1;
        self.l2.fetch(pl);
        self.place(vl, pl, F_PF);
    }

    pub fn raw(&self, o: &mut String) {
        let _ = writeln!(
            o,
            "VIRTRAW {} spec={} misspec={} misspec_miss={} hit0={} hit1={} dram={} by_pa={} restamp={} moves={} dlook={} forced={} lookups={} walks={} pte_reads={} pte_dram={} issued={} useful={} pf_lookups={} pf_walks={} dfall={}",
            self.name,
            self.spec,
            self.misspec,
            self.misspec_miss,
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
            self.pf.walks,
            self.dfall
        );
        o.pop();
        self.l2.raw(o);
        o.push('\n');
        self.dm.raw(o, &self.name);
    }
}

/// Both ways physically tagged; translated before the lookup, by today's
/// 16-entry direct-mapped dTLB in front of the second-level tables, whose
/// walks read their PTEs through this cache and which page-crossing
/// prefetches look up.
pub struct Pipt {
    pub name: String,
    pub degree: i64,
    place: Place,
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
    l2: L2s,
    /// In place of the two skewed ways: a set-associative LRU cache of
    /// page-sized ways (64 sets), alias-free under a virtual index.
    sa: Option<Cache>,
}

impl Pipt {
    /// An alias-free VIPT cache of `kib` KiB: `kib / 4` ways of 64 sets,
    /// replaced by `repl`.
    pub(crate) fn vipt(kib: usize, repl: Repl) -> Self {
        let mut name = format!("VIPT-{kib}K-{}w", kib / 4);
        if repl != Repl::Lru {
            let _ = write!(name, "-{repl:?}");
        }
        Self {
            name,
            sa: Some(Cache {
                repl,
                ..Cache::new(kib << 10, kib / 4)
            }),
            ..Self::new(0, Place::Lru)
        }
    }

    pub fn new(degree: i64, place: Place) -> Self {
        let mut name = "PIPT-skew".to_string();
        if place != Place::Lru {
            let _ = write!(name, "-{place:?}");
        }
        if degree > 0 {
            let _ = write!(name, "-RPT64d{degree}");
        }
        Self {
            name,
            degree,
            place,
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
            l2: L2s::new(),
            sa: None,
        }
    }

    const fn slots(pl: u64) -> (usize, usize) {
        (pl as usize & (SETS - 1), fold(pl) as usize & (SETS - 1))
    }

    fn present(&self, pl: u64) -> bool {
        if let Some(c) = &self.sa {
            return c.contains(pl);
        }
        let (i, j) = Self::slots(pl);
        self.w0[i].pa == pl || self.w1[j].pa == pl
    }

    fn fill(&mut self, pl: u64, flags: u8) {
        if let Some(c) = &mut self.sa {
            if let Some((v, f)) = c.fill_victim(pl, flags)
                && f & F_DIRTY != 0
            {
                self.l2.writeback(v);
            }
            return;
        }
        let (i, j) = Self::slots(pl);
        let new = Slot {
            pa: pl,
            va: NO_LINE,
            epoch: 0,
            stamp: self.clk,
            filled: self.clk,
            flags: flags | F_USED,
        };
        let slot = if choose(&mut self.w0[i], &mut self.w1[j], self.place) {
            &mut self.w0[i]
        } else {
            &mut self.w1[j]
        };
        let old = std::mem::replace(slot, new);
        if old.pa != NO_LINE && old.flags & F_DIRTY != 0 {
            self.l2.writeback(old.pa);
        }
    }

    /// A line the instruction cache fetches from below it.
    pub fn ifetch(&mut self, pl: u64) { self.l2.ifetch(pl); }

    /// A read or write of physical line `pl`; a write leaves the line dirty.
    pub fn demand(&mut self, pl: u64, write: bool) {
        self.clk += 1;
        let dirty = if write { F_DIRTY } else { 0 };
        if let Some(c) = &mut self.sa {
            if let Some(i) = c.lookup(pl) {
                c.flag[i] |= dirty;
                self.hit0 += 1;
            } else {
                self.dram += 1;
                self.l2.fetch(pl);
                self.fill(pl, dirty);
            }
            return;
        }
        let (i, j) = Self::slots(pl);
        for (way, k) in [(0, i), (1, j)] {
            let s = if way == 0 {
                &mut self.w0[k]
            } else {
                &mut self.w1[k]
            };
            if s.pa == pl {
                s.stamp = self.clk;
                s.flags |= F_USED | dirty;
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
        self.l2.fetch(pl);
        self.fill(pl, dirty);
    }

    pub fn pte(&mut self, pl: u64) {
        self.clk += 1;
        self.pte_reads += 1;
        if !self.present(pl) {
            self.pte_dram += 1;
            self.l2.fetch(pl);
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
        self.l2.fetch(pl);
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
        o.pop();
        self.l2.raw(o);
        o.push('\n');
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
