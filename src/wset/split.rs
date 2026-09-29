//! A 128 KiB data cache of two direct-mapped 64 KiB ways with a single copy
//! of every physical line:
//!
//! * way 0 is indexed by VA[15:6] and tagged by the virtual line, so a hit
//!   needs no translation; its virtual tags carry an epoch that `SFENCE.VMA`
//!   and `satp` writes advance;
//! * way 1 is indexed by a hash of the physical line and tagged by it, and is
//!   reached only after a way-0 miss and a translation.
//!
//! A way-0 miss translates through a miss-path TLB (a 4 KiB table plus a
//! separate 2 MiB table), then looks for the line in way 1 and at the 16
//! colours of its row in way 0 (a synonym, or a line whose epoch is stale).
//! Only when both fail is it a memory miss. Physical-only accesses (page-walk
//! reads) look in the same two places and fill way 1.
//!
//! Fill policies:
//! * `P1` puts a new line in the less recently used of its two candidate slots
//!   and never moves a line;
//! * `P2` fills way 0, demotes the way-0 victim to its hashed slot in way 1,
//!   and swaps on every way-1 hit;
//! * `P3` fills and demotes like `P2` but never promotes: a way-1 hit stays;
//! * `P4` is `P3` plus a reuse bit per way-1 line: the second way-1 hit swaps
//!   as in `P2`;
//! * `P5` never moves a line: a way-0 hit sets the line's reuse bit, and a new
//!   line fills way 0 unless the way-0 candidate's reuse bit is set, in which
//!   case the bit is cleared and the new line fills way 1;
//! * `P6` never moves a line: a load or store whose PC the stride table holds
//!   with a steady stride over 64 bytes fills way 1, anything else way 0;
//! * `P6r` is `P6` with `P5`'s rule for the fills that are not strided.
//!
//! In every policy but `P1` a prefetched line fills way 1 directly. A prefetch
//! in the trigger's 4 KiB page reuses the trigger's translation; only a
//! page-crossing prefetch looks up the TLB.

use super::F_PF;
use super::NO_LINE;
use super::Sa;
use super::Xlat;
use super::page_key;
use super::sized_key;
use std::fmt::Write as _;

const SETS: usize = 1024;
const ROWS: u64 = 64;

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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Policy {
    P1,
    P2,
    P3,
    P4,
    P5,
    P6,
    P6r,
}

impl Policy {
    /// Whether a way-0 victim moves to way 1 rather than leaving the cache.
    const fn demotes(self) -> bool { matches!(self, Self::P2 | Self::P3 | Self::P4) }
}

/// A reuse bit: on a way-1 line, set by its first way-1 hit (`P4`); on a
/// way-0 line, set by a way-0 hit (`P5`, `P6r`).
const F_REUSE: u8 = 16;

/// What a translation lookup table serves.
#[derive(Clone, Copy)]
enum Kind {
    /// Every leaf, one entry per 4 KiB page.
    All,
    /// 4 KiB and NAPOT leaves, one entry per 4 KiB page.
    Small,
    /// 2 MiB leaves.
    Mega,
}

struct Obs {
    kind: Kind,
    t: Sa,
    lookups: u64,
}

pub struct Split {
    pub name: String,
    pub policy: Policy,
    /// Stride prefetch degree (0 = none).
    pub degree: i64,
    /// Whether a prefetch whose translation misses the TLB walks (else it is
    /// dropped).
    pub may_walk: bool,
    /// Prefetch only strides over 64 bytes.
    pub nonunit_only: bool,
    w0: Vec<Slot>,
    w1: Vec<Slot>,
    clk: u64,
    epoch: u32,
    t4: Sa,
    t2: Sa,
    obs: Vec<Obs>,

    hit0: [u64; 3],
    hit1: [u64; 3],
    syn: u64,
    dram: [u64; 3],
    moves: u64,
    pte_reads: u64,
    pte_hit: u64,
    pte_dram: u64,
    lookups: u64,
    walks: u64,
    giga: u64,
    pf_lookups: u64,
    pf_walks: u64,
    pf_dropped: u64,
    issued: u64,
    issued_cross: u64,
    useful: u64,
    useless: u64,
}

impl Split {
    pub fn new(policy: Policy, degree: i64, nonunit_only: bool, observe: bool) -> Self {
        let may_walk = true;
        let mut name = format!("{policy:?}");
        if degree > 0 {
            let _ = write!(
                name,
                " RPT64 d{degree} {}",
                if nonunit_only { "non-unit" } else { "may-walk" }
            );
        }
        let mut obs = vec![];
        if observe {
            obs.push(Obs {
                kind: Kind::All,
                t: Sa::new(16, 1),
                lookups: 0,
            });
            for w in [1, 4] {
                obs.push(Obs {
                    kind: Kind::Small,
                    t: Sa::new(2048, w),
                    lookups: 0,
                });
            }
            for n in [32, 64, 128] {
                for w in [1, n] {
                    obs.push(Obs {
                        kind: Kind::Mega,
                        t: Sa::new(n, w),
                        lookups: 0,
                    });
                }
            }
        }
        Self {
            name,
            policy,
            degree,
            may_walk,
            nonunit_only,
            w0: vec![EMPTY; SETS],
            w1: vec![EMPTY; SETS],
            clk: 0,
            epoch: 1,
            t4: Sa::new(2048, 4),
            t2: Sa::new(64, 64),
            obs,
            hit0: [0; 3],
            hit1: [0; 3],
            syn: 0,
            dram: [0; 3],
            moves: 0,
            pte_reads: 0,
            pte_hit: 0,
            pte_dram: 0,
            lookups: 0,
            walks: 0,
            giga: 0,
            pf_lookups: 0,
            pf_walks: 0,
            pf_dropped: 0,
            issued: 0,
            issued_cross: 0,
            useful: 0,
            useless: 0,
        }
    }

    const fn h(line: u64) -> usize { (line ^ line >> 10 ^ line >> 20) as usize & (SETS - 1) }

    const fn i0(vline: u64) -> usize { vline as usize & (SETS - 1) }

    /// `SFENCE.VMA` or a `satp` change: way-0 tags go stale, the TLBs empty.
    pub fn flush(&mut self) {
        self.epoch += 1;
        self.t4.flush();
        self.t2.flush();
        for o in &mut self.obs {
            o.t.flush();
        }
    }

    fn evict(&mut self, s: Slot) {
        if s.pa != NO_LINE && s.flags & F_PF != 0 {
            self.useless += 1;
        }
    }

    /// Move `s` from way 0 to its hashed slot in way 1.
    fn demote(&mut self, s: Slot) {
        if s.pa == NO_LINE {
            return;
        }
        let h = Self::h(s.pa);
        let old = self.w1[h];
        self.evict(old);
        self.w1[h] = Slot {
            flags: s.flags & !F_REUSE,
            ..s
        };
        self.moves += 1;
    }

    /// Make room at way-0 slot `i` for another line.
    fn displace(&mut self, i: usize) {
        let o = self.w0[i];
        self.w0[i] = EMPTY;
        if self.policy.demotes() {
            self.demote(o);
        } else {
            self.evict(o);
        }
    }

    fn use_line(&mut self, flags: &mut u8) {
        if *flags & F_PF != 0 {
            self.useful += 1;
            *flags = 0;
        }
    }

    /// Where the physical line `pl` is, if anywhere: `(way, slot)`.
    fn find(&self, pl: u64) -> Option<(u8, usize)> {
        let h = Self::h(pl);
        if self.w1[h].pa == pl {
            return Some((1, h));
        }
        let row = (pl % ROWS) as usize;
        (0..16)
            .map(|c| c * ROWS as usize + row)
            .find(|&j| self.w0[j].pa == pl)
            .map(|j| (0, j))
    }

    /// Place a line fetched from memory. `strided`: the access's PC has a
    /// steady stride over 64 bytes.
    fn fill(&mut self, vl: u64, pl: u64, flags: u8, strided: bool) {
        let prefetch = flags & F_PF != 0;
        let i = Self::i0(vl);
        let new = Slot {
            pa: pl,
            va: vl,
            epoch: self.epoch,
            stamp: self.clk,
            flags,
        };
        let h = Self::h(pl);
        let reused = self.w0[i].pa != NO_LINE && self.w0[i].flags & F_REUSE != 0;
        let to_w0 = match self.policy {
            Policy::P1 => self.w0[i].pa == NO_LINE || self.w0[i].stamp <= self.w1[h].stamp,
            Policy::P2 | Policy::P3 | Policy::P4 => !prefetch,
            Policy::P5 => !prefetch && !reused,
            Policy::P6 => !prefetch && !strided,
            Policy::P6r => !prefetch && !strided && !reused,
        };
        if !prefetch && reused && matches!(self.policy, Policy::P5 | Policy::P6r) {
            self.w0[i].flags &= !F_REUSE;
        }
        if to_w0 {
            self.displace(i);
            self.w0[i] = new;
        } else {
            let old = self.w1[h];
            self.evict(old);
            self.w1[h] = new;
        }
    }

    /// A physical-only read (a page-walk PTE).
    fn pte(&mut self, pl: u64) {
        self.clk += 1;
        self.pte_reads += 1;
        if let Some((w, j)) = self.find(pl) {
            self.pte_hit += 1;
            let clk = self.clk;
            if w == 1 {
                self.w1[j].stamp = clk;
            } else {
                self.w0[j].stamp = clk;
            }
            return;
        }
        self.pte_dram += 1;
        let h = Self::h(pl);
        let old = self.w1[h];
        self.evict(old);
        self.w1[h] = Slot {
            pa: pl,
            va: NO_LINE,
            epoch: 0,
            stamp: self.clk,
            flags: 0,
        };
    }

    /// Look the page up in the miss-path TLB; on a miss walk (reading the
    /// PTEs through this cache) unless a prefetch may not. Returns whether a
    /// translation is available.
    fn translate(&mut self, x: &Xlat, va: u64, prefetch: bool) -> bool {
        if x.shift == 30 {
            self.giga += 1;
            return true;
        }
        let mega = x.shift == 21;
        let (pk, pidx) = page_key(va);
        let (sk, sidx) = sized_key(va, x.shift);
        if !prefetch {
            for o in &mut self.obs {
                match (o.kind, mega) {
                    (Kind::All, _) => {
                        o.lookups += 1;
                        o.t.access(pk, pidx, 0);
                    }
                    (Kind::Small, false) => {
                        o.lookups += 1;
                        o.t.access(pk, pidx, 0);
                    }
                    (Kind::Mega, true) => {
                        o.lookups += 1;
                        o.t.access(sk, sidx, 0);
                    }
                    _ => {}
                }
            }
        }
        let t = if mega { &mut self.t2 } else { &mut self.t4 };
        let hit = if mega {
            t.access(sk, sidx, 0)
        } else {
            t.access(pk, pidx, 0)
        };
        if prefetch {
            self.pf_lookups += 1;
        } else {
            self.lookups += 1;
        }
        if hit {
            return true;
        }
        if prefetch {
            if !self.may_walk {
                self.pf_dropped += 1;
                return false;
            }
            self.pf_walks += 1;
        } else {
            self.walks += 1;
        }
        for j in 0..x.nlev as usize {
            self.pte(x.pte[j] >> 6);
        }
        true
    }

    /// A demand access; `x` is its translation (`None` when untranslated).
    pub fn demand(&mut self, va: u64, pa: u64, x: Option<&Xlat>, prv: usize, strided: bool) {
        self.clk += 1;
        let clk = self.clk;
        let vl = va >> 6;
        let i = Self::i0(vl);
        let s = self.w0[i];
        if s.pa != NO_LINE && s.epoch == self.epoch && s.va == vl {
            self.hit0[prv] += 1;
            let mut f = s.flags;
            self.use_line(&mut f);
            self.w0[i].flags = f | F_REUSE;
            self.w0[i].stamp = clk;
            return;
        }
        if let Some(x) = x {
            self.translate(x, va, false);
        }
        let pl = pa >> 6;
        match self.find(pl) {
            Some((1, h)) => {
                self.hit1[prv] += 1;
                let mut line = self.w1[h];
                self.use_line(&mut line.flags);
                line.stamp = clk;
                let promote = match self.policy {
                    Policy::P1 | Policy::P3 | Policy::P5 | Policy::P6 | Policy::P6r => false,
                    Policy::P2 => true,
                    Policy::P4 => line.flags & F_REUSE != 0,
                };
                line.flags |= F_REUSE;
                if promote {
                    line.flags &= !F_REUSE;
                    self.w1[h] = EMPTY;
                    self.moves += 1;
                    self.displace(i);
                    self.w0[i] = Slot {
                        va: vl,
                        epoch: self.epoch,
                        ..line
                    };
                } else {
                    self.w1[h] = line;
                }
            }
            Some((_, j)) => {
                self.syn += 1;
                let mut line = self.w0[j];
                self.use_line(&mut line.flags);
                self.w0[j] = EMPTY;
                if j != i {
                    self.displace(i);
                }
                self.w0[i] = Slot {
                    va: vl,
                    epoch: self.epoch,
                    stamp: clk,
                    ..line
                };
            }
            None => {
                self.dram[prv] += 1;
                self.fill(vl, pl, 0, strided);
            }
        }
    }

    /// A stride prefetch of virtual address `t` whose physical line is `pl`.
    /// `lookup` is its translation when it crosses into another page, which
    /// then goes through the TLB.
    pub fn prefetch(&mut self, t: u64, pl: u64, lookup: Option<&Xlat>) {
        self.clk += 1;
        let vl = t >> 6;
        let s = self.w0[Self::i0(vl)];
        if s.pa != NO_LINE && s.epoch == self.epoch && s.va == vl {
            return;
        }
        if let Some(x) = lookup
            && !self.translate(x, t, true)
        {
            return;
        }
        if self.find(pl).is_some() {
            return;
        }
        self.issued += 1;
        if lookup.is_some() {
            self.issued_cross += 1;
        }
        self.fill(vl, pl, F_PF, false);
    }

    /// Demand DRAM misses, for coverage.
    pub fn dram_total(&self) -> u64 { self.dram.iter().sum() }

    pub fn report(&self, o: &mut String, n: u64, base: Option<u64>) {
        let pki = |v: u64| v as f64 * 1000.0 / n.max(1) as f64;
        let sum = |a: &[u64; 3]| a.iter().sum::<u64>();
        let _ = writeln!(
            o,
            "{:<34} {:>8.2} {:>8.3} {:>8.4} {:>8.3} {:>8.3} {:>7.3} {:>7.4} {:>8.3} {:>8.3} {:>7.3}",
            self.name,
            pki(sum(&self.hit0)),
            pki(sum(&self.hit1)),
            pki(self.syn),
            pki(self.dram_total()),
            pki(self.moves),
            pki(self.pte_reads),
            pki(self.pte_dram),
            pki(self.lookups),
            pki(self.walks),
            pki(self.giga),
        );
        if self.degree > 0 {
            let cover = base.map_or(0.0, |b| {
                (b as f64 - self.dram_total() as f64) * 100.0 / b.max(1) as f64
            });
            let _ = writeln!(
                o,
                "{:<34} prefetch: issued {:.3} (x-page {:.3}) useful {:.3} accuracy {:.1}% coverage {:.1}%; prefetch TLB lookups {:.3} walks {:.3} dropped {:.3} (per kinsn)",
                "",
                pki(self.issued),
                pki(self.issued_cross),
                pki(self.useful),
                self.useful as f64 * 100.0 / self.issued.max(1) as f64,
                cover,
                pki(self.pf_lookups),
                pki(self.pf_walks),
                pki(self.pf_dropped),
            );
        }
        let _ = writeln!(
            o,
            "{:<34} counts: way0 U {} S {} M {} | way1 U {} S {} M {} | DRAM U {} S {} M {} | synonym moves {} | moves {} | PTE reads {} hit {} DRAM {}",
            "",
            self.hit0[0],
            self.hit0[1],
            self.hit0[2],
            self.hit1[0],
            self.hit1[1],
            self.hit1[2],
            self.dram[0],
            self.dram[1],
            self.dram[2],
            self.syn,
            self.moves,
            self.pte_reads,
            self.pte_hit,
            self.pte_dram
        );
        let _ = writeln!(
            o,
            "SPLITRAW {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {}",
            self.name.replace(' ', "_"),
            sum(&self.hit0),
            sum(&self.hit1),
            self.syn,
            self.dram_total(),
            self.moves,
            self.lookups,
            self.walks,
            self.pte_reads,
            self.pte_dram,
            self.issued,
            self.issued_cross,
            self.useful,
            self.pf_lookups,
            self.pf_walks,
            self.pf_dropped
        );
        for ob in &self.obs {
            let what = match ob.kind {
                Kind::All => "all leaves, per 4K",
                Kind::Small => "4K+NAPOT leaves",
                Kind::Mega => "2M leaves",
            };
            let _ = writeln!(
                o,
                "{:<34}   TLB {:<10} ({what:<18}) lookups {:>9.3} misses {:>9.4} per kinsn ({} misses)",
                "",
                ob.t.name(),
                pki(ob.lookups),
                pki(ob.t.miss[0]),
                ob.t.miss[0]
            );
        }
    }
}
