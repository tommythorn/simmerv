//! Memory-behaviour statistics for a window of execution (the `wset` feature).
//!
//! Records, for every data access and every instruction fetch in the window,
//! enough to answer three questions without writing a trace:
//!
//! * the working set: distinct 4 KiB pages, 2 MiB regions and 64-byte lines per
//!   window of 1 M / 10 M / 100 M / 1 G instructions, and the leaf page size
//!   that translated each access;
//! * translation reach: LRU stack distances over translation keys (every
//!   fully-associative TLB size at once), a set of set-associative and
//!   two-level TLB organisations, the walks a 16-entry direct-mapped TLB
//!   performs, and what a page-walk cache would save on those walks;
//! * prefetchability: a 128 KiB 2-way 64-byte-line data cache, per-PC address
//!   deltas, and next-line and PC-indexed stride prefetchers simulated against
//!   it; plus a virtually tagged data cache and instruction cache whose miss
//!   streams feed their own TLB models.
//!
//! Inert unless `SIMMERV_WSET` names an output directory. Further knobs:
//! `SIMMERV_WSET_LEN` (instructions to measure, default 8 G),
//! `SIMMERV_WSET_FIRST` (an early snapshot, default 50 M) and
//! `SIMMERV_WSET_EVERY` (a periodic snapshot, default 1 G). Counts start at the
//! first instruction executed. Each snapshot is a text report in the output
//! directory; measuring stops at `SIMMERV_WSET_LEN`.
//!
//! Sampling instead of one window: `SIMMERV_WSET_PERIOD` (with
//! `SIMMERV_WSET_START`, `SIMMERV_WSET_WARM`, `SIMMERV_WSET_MEASURE` and
//! `SIMMERV_WSET_STOP`, all instruction counts from the first instruction plus
//! `SIMMERV_WSET_BASE`) runs the models only in windows starting every period:
//! a warm-up, a report `w-<N>`, the measured stretch, and a report `m-<N>`.
//! Reports are cumulative, so a window is the difference of its two. Between
//! windows the hook only counts down.
//!
//! `SIMMERV_WSET_LITE` keeps only the split cache, the plain 2-way caches and
//! the 16-entry TLB.
//!
//! Translation facts come from a side-effect-free Sv39 walk of the live page
//! tables, cached per `(satp, 4 KiB page)` and invalidated by every
//! `SFENCE.VMA` and `satp` write. The TLB models have no ASIDs: they are
//! flushed on every `SFENCE.VMA` and on every `satp` write that changes it.
#![allow(
    clippy::pedantic,
    clippy::nursery,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_lines,
    clippy::needless_range_loop
)]

mod split;

use crate::mmu::Mmu;
use fnv::FnvHashMap;
use split::Policy;
use split::Split;
use std::fmt::Write as _;
use std::path::PathBuf;

/// Instruction windows for the working-set distributions.
const WIN: [u64; 4] = [1_000_000, 10_000_000, 100_000_000, 1_000_000_000];
const WIN_NAME: [&str; 4] = ["1M", "10M", "100M", "1G"];
/// Fully-associative TLB sizes reported from the stack distances.
const FA: [usize; 17] = [
    16, 32, 64, 128, 192, 256, 264, 272, 288, 320, 384, 448, 512, 768, 1024, 2048, 4096,
];
const STACK_CAP: usize = 4096;
/// Set-associative TLBs over all data accesses: (entries, ways).
const SA_ALL: [(usize, usize); 13] = [
    (16, 1),
    (32, 4),
    (64, 4),
    (64, 8),
    (128, 4),
    (256, 4),
    (512, 4),
    (1024, 4),
    (1024, 8),
    (2048, 4),
    (2048, 8),
    (4096, 4),
    (4096, 8),
];
/// Set-associative TLBs over cache-miss streams.
const SA_MISS: [(usize, usize); 6] = [
    (1024, 4),
    (1024, 8),
    (2048, 4),
    (2048, 8),
    (4096, 4),
    (4096, 8),
];
/// Second-level TLBs behind each first level.
const L2: [(usize, usize); 4] = [(512, 4), (1024, 4), (2048, 4), (2048, 8)];
/// Page-walk cache sizes (fully associative, LRU, non-leaf PTEs).
const PWC: [usize; 7] = [2, 4, 8, 16, 32, 64, 256];

const U: usize = 0;
const S: usize = 1;
const M: usize = 2;
const PRV_NAME: [&str; 3] = ["U", "S", "M"];

const KEY_VALID: u64 = 1 << 63;
const VA_MASK: u64 = (1 << 39) - 1;

/// One 4 KiB page's translation as the walk finds it.
#[derive(Clone, Copy, Default)]
pub struct Xlat {
    /// Leaf page size, log2: 12, 16 (NAPOT), 21 or 30.
    pub shift: u8,
    /// PTEs read by the walk.
    pub nlev: u8,
    /// Physical addresses of the PTEs read, root first.
    pub pte: [u64; 3],
    /// Physical address of the 4 KiB page.
    pub pa: u64,
}

#[derive(Clone, Copy, Default)]
struct ShadowEnt {
    satp: u64,
    vpn: u64,
    generation: u32,
    x: Xlat,
}

const fn size_idx(shift: u8) -> usize {
    match shift {
        12 => 0,
        16 => 1,
        21 => 2,
        _ => 3,
    }
}
const SIZE_NAME: [&str; 4] = ["4K", "64K", "2M", "1G"];

/// A translation key honouring the leaf size, and its set-index bits.
const fn sized_key(va: u64, shift: u8) -> (u64, u64) {
    let vpn = (va & VA_MASK) >> shift;
    (KEY_VALID | (shift as u64) << 56 | vpn, vpn)
}

/// A translation key per 4 KiB page, whatever the leaf size.
const fn page_key(va: u64) -> (u64, u64) {
    let vpn = (va & VA_MASK) >> 12;
    (KEY_VALID | vpn, vpn)
}

/// LRU stack; `access` returns the reuse distance (`cap` for a cold miss or one
/// deeper than the stack).
struct Stack {
    v: Vec<u64>,
    cap: usize,
}

impl Stack {
    fn new(cap: usize) -> Self {
        Self {
            v: Vec::with_capacity(cap),
            cap,
        }
    }
    fn access(&mut self, key: u64) -> usize {
        if let Some(p) = self.v.iter().position(|&k| k == key) {
            self.v[..=p].rotate_right(1);
            p
        } else {
            if self.v.len() < self.cap {
                self.v.push(key);
            } else {
                *self.v.last_mut().unwrap() = key;
            }
            self.v.rotate_right(1);
            self.cap
        }
    }
    fn flush(&mut self) { self.v.clear(); }
}

/// Stack-distance histogram per privilege.
struct Curve {
    st: Stack,
    hist: [Vec<u64>; 2],
    lookups: [u64; 2],
}

impl Curve {
    fn new() -> Self {
        Self {
            st: Stack::new(STACK_CAP),
            hist: [vec![0; STACK_CAP + 1], vec![0; STACK_CAP + 1]],
            lookups: [0; 2],
        }
    }
    fn access(&mut self, key: u64, prv: usize) {
        let d = self.st.access(key);
        self.hist[prv][d] += 1;
        self.lookups[prv] += 1;
    }
    fn misses(&self, prv: usize, size: usize) -> u64 { self.hist[prv][size..].iter().sum() }
}

/// Set-associative LRU structure of keys.
struct Sa {
    sets: usize,
    ways: usize,
    tag: Vec<u64>,
    age: Vec<u64>,
    clk: u64,
    miss: [u64; 2],
}

impl Sa {
    fn new(entries: usize, ways: usize) -> Self {
        Self {
            sets: entries / ways,
            ways,
            tag: vec![0; entries],
            age: vec![0; entries],
            clk: 0,
            miss: [0; 2],
        }
    }
    /// Look up and, on a miss, insert. Returns whether it hit.
    fn access(&mut self, key: u64, idx: u64, prv: usize) -> bool {
        self.clk += 1;
        let base = (idx as usize & (self.sets - 1)) * self.ways;
        let set = base..base + self.ways;
        if let Some(w) = self.tag[set.clone()].iter().position(|&t| t == key) {
            self.age[base + w] = self.clk;
            return true;
        }
        self.miss[prv] += 1;
        let mut victim = base;
        for i in set {
            if self.tag[i] == 0 {
                victim = i;
                break;
            }
            if self.age[i] < self.age[victim] {
                victim = i;
            }
        }
        self.tag[victim] = key;
        self.age[victim] = self.clk;
        false
    }
    /// Whether `key` is present, without touching the replacement state.
    fn probe(&self, key: u64, idx: u64) -> bool {
        let base = (idx as usize & (self.sets - 1)) * self.ways;
        self.tag[base..base + self.ways].contains(&key)
    }
    fn flush(&mut self) { self.tag.fill(0); }
    fn name(&self) -> String {
        let n = self.sets * self.ways;
        if self.ways == 1 {
            format!("{n} DM")
        } else if self.sets == 1 {
            format!("{n} FA")
        } else {
            format!("{n} {}-way", self.ways)
        }
    }
}

/// A first-level TLB backed by a second level.
struct Two {
    l1: Sa,
    l1_page_keyed: bool,
    l2: Sa,
}

const F_PF: u8 = 1;
const F_CROSS: u8 = 2;
const F_NONUNIT: u8 = 4;
const F_W: u8 = 8;
const NO_LINE: u64 = u64::MAX;

/// Set-associative LRU cache of line numbers, with per-line flags.
struct Cache {
    sets: usize,
    ways: usize,
    /// Index by the line number XOR-folded with the bits above the index,
    /// instead of by its low bits.
    hashed: bool,
    tag: Vec<u64>,
    age: Vec<u64>,
    flag: Vec<u8>,
    clk: u64,
}

impl Cache {
    fn new(bytes: usize, ways: usize) -> Self {
        let lines = bytes / 64;
        Self {
            sets: lines / ways,
            ways,
            hashed: false,
            tag: vec![NO_LINE; lines],
            age: vec![0; lines],
            flag: vec![0; lines],
            clk: 0,
        }
    }
    fn set(&self, line: u64) -> usize {
        let bits = self.sets.trailing_zeros();
        let i = if self.hashed {
            line ^ line >> bits ^ line >> (2 * bits)
        } else {
            line
        };
        (i as usize & (self.sets - 1)) * self.ways
    }
    fn lookup(&mut self, line: u64) -> Option<usize> {
        self.clk += 1;
        let base = self.set(line);
        for i in base..base + self.ways {
            if self.tag[i] == line {
                self.age[i] = self.clk;
                return Some(i);
            }
        }
        None
    }
    fn contains(&self, line: u64) -> bool {
        let base = self.set(line);
        self.tag[base..base + self.ways].contains(&line)
    }
    /// Insert as most recent; returns the evicted line's flags, if any.
    fn fill(&mut self, line: u64, flags: u8) -> Option<u8> {
        self.clk += 1;
        let base = self.set(line);
        let mut victim = base;
        for i in base..base + self.ways {
            if self.tag[i] == NO_LINE {
                victim = i;
                break;
            }
            if self.age[i] < self.age[victim] {
                victim = i;
            }
        }
        let old = (self.tag[victim] != NO_LINE).then_some(self.flag[victim]);
        self.tag[victim] = line;
        self.age[victim] = self.clk;
        self.flag[victim] = flags;
        old
    }
}

/// PC-indexed stride table (reference prediction table).
struct Rpt {
    pc: Vec<u64>,
    last: Vec<u64>,
    stride: Vec<i64>,
    conf: Vec<u8>,
}

impl Rpt {
    fn new(n: usize) -> Self {
        Self {
            pc: vec![0; n],
            last: vec![0; n],
            stride: vec![0; n],
            conf: vec![0; n],
        }
    }
    /// Train on an access; returns the stride to prefetch with once the same
    /// non-zero delta has been seen twice in a row.
    fn train(&mut self, pc: u64, va: u64) -> Option<i64> {
        let i = (pc >> 1) as usize & (self.pc.len() - 1);
        if self.pc[i] != pc {
            self.pc[i] = pc;
            self.last[i] = va;
            self.stride[i] = 0;
            self.conf[i] = 0;
            return None;
        }
        let d = va.wrapping_sub(self.last[i]) as i64;
        self.last[i] = va;
        if d == self.stride[i] {
            self.conf[i] = (self.conf[i] + 1).min(3);
        } else if self.conf[i] <= 1 {
            self.stride[i] = d;
            self.conf[i] = 0;
        } else {
            self.conf[i] -= 1;
        }
        (self.conf[i] >= 2 && self.stride[i] != 0).then_some(self.stride[i])
    }
}

/// A physically indexed data cache, optionally with a prefetcher.
struct Pf {
    name: String,
    cache: Cache,
    next_line: bool,
    /// Which stride table trains it, if any.
    rpt: Option<usize>,
    degree: i64,
    nonunit_only: bool,
    /// A page-crossing prefetch is issued only when its page hits in this
    /// TLB model (`Gate`), and is dropped otherwise.
    gate: Option<Gate>,
    dropped_gate: u64,
    miss: [u64; 3],
    pte_miss: u64,
    issued: u64,
    useful: u64,
    useless: u64,
    issued_cross: u64,
    useful_cross: u64,
    issued_nonunit: u64,
    useful_nonunit: u64,
}

impl Pf {
    fn new(
        name: &str,
        next_line: bool,
        rpt: Option<usize>,
        degree: i64,
        nonunit_only: bool,
    ) -> Self {
        Self {
            name: name.to_string(),
            cache: Cache::new(128 << 10, 2),
            next_line,
            rpt,
            degree,
            nonunit_only,
            gate: None,
            dropped_gate: 0,
            miss: [0; 3],
            pte_miss: 0,
            issued: 0,
            useful: 0,
            useless: 0,
            issued_cross: 0,
            useful_cross: 0,
            issued_nonunit: 0,
            useful_nonunit: 0,
        }
    }
    fn fill(&mut self, line: u64, flags: u8) {
        if let Some(f) = self.cache.fill(line, flags)
            && f & F_PF != 0
        {
            self.useless += 1;
        }
    }
}

#[derive(Clone, Copy)]
enum Gate {
    /// The 16-entry direct-mapped per-4 KiB TLB.
    Rtl,
    /// `sa_all[i]`.
    Sa(usize),
}

/// Distinct keys per instruction window.
struct Ws {
    map: FnvHashMap<u64, [u32; 4]>,
    cnt: [Vec<u32>; 4],
}

impl Ws {
    fn new() -> Self {
        Self {
            map: FnvHashMap::default(),
            cnt: [vec![], vec![], vec![], vec![]],
        }
    }
    fn touch(&mut self, key: u64, w: &[u32; 4]) {
        let e = self.map.entry(key).or_insert([u32::MAX; 4]);
        for i in 0..4 {
            if e[i] != w[i] {
                e[i] = w[i];
                let c = &mut self.cnt[i];
                let j = w[i] as usize;
                if c.len() <= j {
                    c.resize(j + 1, 0);
                }
                c[j] += 1;
            }
        }
    }
}

#[derive(Default)]
struct PcEnt {
    prv: u8,
    last: u64,
    delta: i64,
    seen: bool,
    cls: [u64; 5],
    mcls: [u64; 5],
    miss: u64,
    deltas: Vec<(i64, u64, u64)>,
    other: u64,
}

const CLS_NAME: [&str; 5] = [
    "first",
    "same line",
    "next line (+-1 line)",
    "const non-unit stride",
    "irregular",
];

/// Returned by [`Wset::insn`] when the recorder is finished.
pub const DROP: u64 = u64::MAX;

#[derive(Clone, Copy)]
struct Sample {
    period: u64,
    warm: u64,
    measure: u64,
    stop: u64,
    start_at: u64,
}

pub struct Wset {
    dir: PathBuf,
    lite: bool,
    sample: Option<Sample>,
    /// Instructions since the first, plus `SIMMERV_WSET_BASE`.
    abs: u64,
    active: bool,
    len: u64,
    first: u64,
    every: u64,
    n: u64,
    next_event: u64,
    first_done: bool,
    next_dump: u64,
    dumps: u32,
    pub(crate) insns: [u64; 3],
    pc: u64,
    new_insn: bool,
    last_line: u64,
    last_page: u64,
    last_ws: (u64, u32),
    last_iline: u64,

    shadow: Vec<ShadowEnt>,
    generation: u32,
    walk_fail: u64,
    sfences: u64,
    satp_changes: u64,

    acc: [[u64; 2]; 3],
    dup: u64,
    by_size: [[u64; 4]; 2],

    ws_page: [Ws; 2],
    ws_region: [Ws; 2],
    ws_line: [Ws; 2],
    ws_pte: Ws,
    ws_imiss_page: Ws,

    fa_sized: Curve,
    fa_page: Curve,
    sa_all: Vec<Sa>,
    sa_rtl: Sa,
    two: Vec<Two>,
    walks: [u64; 2],
    walk_refs: u64,
    pwc: Stack,
    pwc_refs: [u64; PWC.len()],
    nonleaf: FnvHashMap<u64, ()>,

    rpt: [Rpt; 2],
    pfs: Vec<Pf>,

    pcs: FnvHashMap<u64, PcEnt>,
    cls_tot: [[u64; 5]; 3],
    mcls_tot: [[u64; 5]; 3],

    vcache: Cache,
    vmiss: [u64; 3],
    perm_up: [u64; 2],
    fa_filt: Curve,
    sa_filt: Vec<Sa>,

    icache: Cache,
    iacc: [u64; 3],
    imiss: [u64; 3],
    fa_imiss: Curve,
    fa_unified: Curve,
    sa_unified: Vec<Sa>,

    split: Vec<Split>,
}

fn env_count(name: &str, default: u64) -> u64 {
    let Ok(s) = std::env::var(name) else {
        return default;
    };
    let s = s.trim();
    let (d, k) = match s.as_bytes().last() {
        Some(b'k' | b'K') => (&s[..s.len() - 1], 1_000),
        Some(b'm' | b'M') => (&s[..s.len() - 1], 1_000_000),
        Some(b'g' | b'G') => (&s[..s.len() - 1], 1_000_000_000),
        _ => (s, 1),
    };
    d.parse::<u64>().map_or(default, |v| v * k)
}

const SHADOW_BITS: u32 = 18;

impl Wset {
    /// The recorder, if `SIMMERV_WSET` asks for one.
    #[must_use]
    pub fn from_env() -> Option<Box<Self>> {
        let dir = PathBuf::from(std::env::var_os("SIMMERV_WSET")?);
        std::fs::create_dir_all(&dir).ok()?;
        let lite = std::env::var_os("SIMMERV_WSET_LITE").is_some();
        let abs = env_count("SIMMERV_WSET_BASE", 0);
        let sample = std::env::var_os("SIMMERV_WSET_PERIOD").map(|_| Sample {
            period: env_count("SIMMERV_WSET_PERIOD", 0).max(1),
            warm: env_count("SIMMERV_WSET_WARM", 50_000_000),
            measure: env_count("SIMMERV_WSET_MEASURE", 500_000_000),
            stop: env_count("SIMMERV_WSET_STOP", u64::MAX),
            start_at: env_count("SIMMERV_WSET_START", 0),
        });
        let (len, first, every) = if sample.is_some() {
            (u64::MAX, u64::MAX, u64::MAX)
        } else {
            (
                env_count("SIMMERV_WSET_LEN", 8_000_000_000),
                env_count("SIMMERV_WSET_FIRST", 50_000_000),
                env_count("SIMMERV_WSET_EVERY", 1_000_000_000),
            )
        };
        let pfs = vec![
            Pf::new("none", false, None, 0, false),
            Pf::new("next-line (tagged)", true, None, 0, false),
            Pf::new("RPT16 d1", false, Some(0), 1, false),
            Pf::new("RPT16 d2", false, Some(0), 2, false),
            Pf::new("RPT16 d4", false, Some(0), 4, false),
            Pf::new("RPT64 d1", false, Some(1), 1, false),
            Pf::new("RPT64 d2", false, Some(1), 2, false),
            Pf::new("RPT64 d4", false, Some(1), 4, false),
            Pf::new("RPT64 d2 non-unit only", false, Some(1), 2, true),
            Pf::new("next-line + RPT64 d2 non-unit", true, Some(1), 2, true),
            Pf::new("next-line + RPT64 d4", true, Some(1), 4, false),
            Pf::new("RPT64 d2, 128K 8-way", false, Some(1), 2, false),
        ];
        let mut pfs = pfs;
        pfs.push(Pf {
            cache: Cache::new(128 << 10, 8),
            ..Pf::new("none, 128K 8-way", false, None, 0, false)
        });
        pfs.push(Pf {
            cache: Cache::new(128 << 10, 16),
            ..Pf::new("none, 128K 16-way", false, None, 0, false)
        });
        let n = pfs.len();
        pfs[n - 3].cache = Cache::new(128 << 10, 8);
        let hashed = Cache {
            hashed: true,
            ..Cache::new(128 << 10, 2)
        };
        pfs.push(Pf {
            cache: hashed,
            ..Pf::new("none, 128K 2-way hashed index", false, None, 0, false)
        });
        let hashed = Cache {
            hashed: true,
            ..Cache::new(128 << 10, 2)
        };
        pfs.push(Pf {
            cache: hashed,
            ..Pf::new(
                "RPT64 d2, 128K 2-way hashed index",
                false,
                Some(1),
                2,
                false,
            )
        });
        for (name, g) in [
            ("16 DM", Gate::Rtl),
            ("64 4-way", Gate::Sa(2)),
            ("256 4-way", Gate::Sa(5)),
            ("512 4-way", Gate::Sa(6)),
            ("1024 4-way", Gate::Sa(7)),
        ] {
            pfs.push(Pf {
                gate: Some(g),
                ..Pf::new(
                    &format!("RPT64 d2, x-page iff {name} hit"),
                    false,
                    Some(1),
                    2,
                    false,
                )
            });
        }
        if lite {
            pfs.truncate(1);
        }
        let mut two = vec![];
        for &(e, w) in &L2 {
            two.push(Two {
                l1: Sa::new(16, 1),
                l1_page_keyed: true,
                l2: Sa::new(e, w),
            });
        }
        for &(e, w) in &L2 {
            two.push(Two {
                l1: Sa::new(64, 64),
                l1_page_keyed: false,
                l2: Sa::new(e, w),
            });
        }
        let w = Self {
            dir,
            lite,
            sample,
            abs,
            active: true,
            len,
            first,
            every,
            n: 0,
            next_event: first.min(every).min(len),
            first_done: false,
            next_dump: every,
            dumps: 0,
            insns: [0; 3],
            pc: 0,
            new_insn: false,
            last_line: NO_LINE,
            last_page: NO_LINE,
            last_ws: (NO_LINE, u32::MAX),
            last_iline: NO_LINE,
            shadow: vec![ShadowEnt::default(); 1 << SHADOW_BITS],
            generation: 1,
            walk_fail: 0,
            sfences: 0,
            satp_changes: 0,
            acc: [[0; 2]; 3],
            dup: 0,
            by_size: [[0; 4]; 2],
            ws_page: [Ws::new(), Ws::new()],
            ws_region: [Ws::new(), Ws::new()],
            ws_line: [Ws::new(), Ws::new()],
            ws_pte: Ws::new(),
            ws_imiss_page: Ws::new(),
            fa_sized: Curve::new(),
            fa_page: Curve::new(),
            sa_all: SA_ALL.iter().map(|&(e, w)| Sa::new(e, w)).collect(),
            sa_rtl: Sa::new(16, 1),
            two,
            walks: [0; 2],
            walk_refs: 0,
            pwc: Stack::new(PWC[PWC.len() - 1]),
            pwc_refs: [0; PWC.len()],
            nonleaf: FnvHashMap::default(),
            rpt: [Rpt::new(16), Rpt::new(64)],
            pfs,
            pcs: FnvHashMap::default(),
            cls_tot: [[0; 5]; 3],
            mcls_tot: [[0; 5]; 3],
            vcache: Cache::new(128 << 10, 2),
            vmiss: [0; 3],
            perm_up: [0; 2],
            fa_filt: Curve::new(),
            sa_filt: SA_MISS.iter().map(|&(e, w)| Sa::new(e, w)).collect(),
            icache: Cache::new(128 << 10, 2),
            iacc: [0; 3],
            imiss: [0; 3],
            fa_imiss: Curve::new(),
            fa_unified: Curve::new(),
            sa_unified: SA_MISS.iter().map(|&(e, w)| Sa::new(e, w)).collect(),
            split: {
                let policies = [Policy::P1, Policy::P2, Policy::P3, Policy::P4];
                let mut v: Vec<Split> = policies
                    .iter()
                    .map(|&p| Split::new(p, 0, true, true))
                    .collect();
                v.extend(policies.iter().map(|&p| Split::new(p, 2, true, false)));
                v
            },
        };
        eprintln!(
            "wset: recording {len} instructions into {}",
            w.dir.display()
        );
        Some(Box::new(w))
    }

    /// An `SFENCE.VMA` (`fence`) or a changed `satp`: the TLB models, the
    /// page-walk cache and the translation cache all start over.
    pub fn flush(&mut self, fence: bool) {
        if fence {
            self.sfences += 1;
        } else {
            self.satp_changes += 1;
        }
        self.generation += 1;
        self.last_page = NO_LINE;
        self.fa_sized.st.flush();
        self.fa_page.st.flush();
        self.fa_filt.st.flush();
        self.fa_imiss.st.flush();
        self.fa_unified.st.flush();
        for t in self
            .sa_all
            .iter_mut()
            .chain(self.sa_filt.iter_mut())
            .chain(self.sa_unified.iter_mut())
        {
            t.flush();
        }
        self.sa_rtl.flush();
        for t in &mut self.two {
            t.l1.flush();
            t.l2.flush();
        }
        self.pwc.flush();
        for s in &mut self.split {
            s.flush();
        }
    }

    fn xlat(&mut self, mmu: &mut Mmu, va: u64) -> Option<Xlat> {
        let vpn = (va & VA_MASK) >> 12;
        let satp = mmu.satp;
        let h = (vpn ^ (vpn >> SHADOW_BITS) ^ satp.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 40)
            as usize
            & ((1 << SHADOW_BITS) - 1);
        let e = &self.shadow[h];
        if e.generation == self.generation && e.vpn == vpn && e.satp == satp {
            return Some(e.x);
        }
        let x = mmu.wset_walk(va)?;
        self.shadow[h] = ShadowEnt {
            satp,
            vpn,
            generation: self.generation,
            x,
        };
        Some(x)
    }

    fn windows(&self) -> [u32; 4] {
        let mut w = [0; 4];
        for i in 0..4 {
            w[i] = (self.n / WIN[i]) as u32;
        }
        w
    }

    /// Sampling: the transitions between idle, warm-up and measurement.
    /// Returns the instructions to stay idle for, or [`DROP`].
    fn sample_step(&mut self) -> Option<u64> {
        let s = self.sample?;
        let abs = self.abs;
        if abs < s.start_at {
            self.active = false;
            self.abs = s.start_at;
            return Some(s.start_at - abs);
        }
        self.active = true;
        if abs == s.start_at + s.warm {
            self.dump(&format!("w-{abs:013}"));
        }
        if abs < s.start_at + s.warm + s.measure {
            return None;
        }
        self.dump(&format!("m-{abs:013}"));
        let next = s.start_at + s.period;
        if next >= s.stop {
            eprintln!("wset: sampling done at {abs}");
            return Some(DROP);
        }
        self.sample = Some(Sample {
            start_at: next,
            ..s
        });
        self.active = false;
        self.abs = next;
        Some(next - abs)
    }

    /// One instruction about to execute at `pc`. Returns 0 to go on, a number
    /// of instructions to stay idle for, or [`DROP`] once the recorder is done.
    pub fn insn(&mut self, mmu: &mut Mmu, pc: u64, prv: usize, translated: bool) -> u64 {
        if let Some(idle) = self.sample_step() {
            return idle;
        }
        if self.n >= self.next_event && !self.event() {
            return DROP;
        }
        self.abs += 1;
        self.n += 1;
        self.insns[prv] += 1;
        self.pc = pc;
        self.new_insn = true;
        let line = (pc >> 6) | ((prv as u64) << 60);
        if self.lite || line == self.last_iline {
            return 0;
        }
        self.last_iline = line;
        self.iacc[prv] += 1;
        if self.icache.lookup(line).is_some() {
            return 0;
        }
        self.icache.fill(line, 0);
        self.imiss[prv] += 1;
        if translated && let Some(x) = self.xlat(mmu, pc) {
            let (k, idx) = sized_key(pc, x.shift);
            let p = prv.min(S);
            self.fa_imiss.access(k, p);
            self.fa_unified.access(k, p);
            for t in &mut self.sa_unified {
                t.access(k, idx, p);
            }
            let w = self.windows();
            self.ws_imiss_page.touch(k, &w);
        }
        0
    }

    fn event(&mut self) -> bool {
        if !self.first_done && self.n >= self.first {
            self.first_done = true;
            self.dump(&format!("first-{}", self.first));
        }
        if self.n >= self.next_dump && self.n < self.len {
            self.dumps += 1;
            self.dump(&format!("at-{}", self.n));
            self.next_dump += self.every;
        }
        if self.n >= self.len {
            self.dump("final");
            eprintln!("wset: done at {} instructions", self.n);
            return false;
        }
        self.next_event = self.len.min(self.next_dump);
        if !self.first_done {
            self.next_event = self.next_event.min(self.first);
        }
        true
    }

    /// A data access at `va` that translated to `pa`.
    pub fn data(
        &mut self,
        mmu: &mut Mmu,
        va: u64,
        pa: u64,
        write: bool,
        prv: usize,
        translated: bool,
    ) {
        if !self.active {
            return;
        }
        let vline = va >> 6;
        if !self.new_insn && vline == self.last_line {
            self.dup += 1;
            return;
        }
        self.new_insn = false;
        self.last_line = vline;
        self.acc[prv][usize::from(write)] += 1;
        let pline = pa >> 6;

        // Translation, TLB models and the walks of the 16-entry direct-mapped
        // TLB, whose PTE reads go through the data caches first.
        let mut xl = None;
        if translated {
            match self.xlat(mmu, va) {
                Some(x) => xl = Some(x),
                None => self.walk_fail += 1,
            }
        }
        if let Some(x) = xl {
            self.by_size[prv][size_idx(x.shift)] += 1;
            let page = (va & VA_MASK) >> 12;
            if page != self.last_page {
                self.last_page = page;
                self.tlbs(&x, va, prv);
            }
        }

        // Data caches and prefetchers.
        let rpt_out = [
            self.rpt[0].train(self.pc, va),
            self.rpt[1].train(self.pc, va),
        ];
        let mut base_miss = false;
        for i in 0..self.pfs.len() {
            let pf = &mut self.pfs[i];
            let mut trigger = false;
            match pf.cache.lookup(pline) {
                Some(s) => {
                    let f = pf.cache.flag[s];
                    if f & F_PF != 0 {
                        pf.useful += 1;
                        if f & F_CROSS != 0 {
                            pf.useful_cross += 1;
                        }
                        if f & F_NONUNIT != 0 {
                            pf.useful_nonunit += 1;
                        }
                        pf.cache.flag[s] = 0;
                        trigger = true;
                    }
                }
                None => {
                    pf.miss[prv] += 1;
                    pf.fill(pline, 0);
                    trigger = true;
                    if i == 0 {
                        base_miss = true;
                    }
                }
            }
            if pf.next_line && trigger {
                self.prefetch(mmu, i, va, pa, 64, translated);
            }
            let pf = &self.pfs[i];
            if let Some(t) = pf.rpt
                && let Some(stride) = rpt_out[t]
                && (!pf.nonunit_only || stride.unsigned_abs() > 64)
            {
                for k in 1..=pf.degree {
                    self.prefetch(mmu, i, va, pa, stride.wrapping_mul(k), translated);
                }
            }
        }

        // The split virtual/physical cache, and its stride prefetches.
        for s in &mut self.split {
            s.demand(va, pa, xl.as_ref(), prv);
        }
        if let Some(stride) = rpt_out[1] {
            // A target in the trigger's page takes the trigger's translation;
            // one in another page is translated through the TLB.
            let mut targets = [None; 4];
            for k in 0..4 {
                let t = va.wrapping_add(stride.wrapping_mul(k as i64 + 1) as u64);
                if t >> 6 == va >> 6 {
                    continue;
                }
                targets[k] = if !translated {
                    Some((t, t >> 6, None))
                } else if t >> 12 == va >> 12 {
                    Some((t, ((pa & !0xfff) | (t & 0xfff)) >> 6, None))
                } else {
                    self.xlat(mmu, t)
                        .map(|x| (t, (x.pa | (t & 0xfff)) >> 6, Some(x)))
                };
            }
            for s in &mut self.split {
                for &(t, pl, x) in targets.iter().take(s.degree as usize).flatten() {
                    s.prefetch(t, pl, x.as_ref());
                }
            }
        }

        // Virtually tagged data cache: its misses are the translation lookups
        // of a design that translates only on the miss path.
        let vkey = vline & ((1 << 58) - 1) | ((prv as u64) << 60);
        match self.vcache.lookup(vkey) {
            Some(s) => {
                if write && self.vcache.flag[s] & F_W == 0 {
                    self.vcache.flag[s] |= F_W;
                    if prv < M {
                        self.perm_up[prv] += 1;
                    }
                }
            }
            None => {
                self.vcache.fill(vkey, if write { F_W } else { 0 });
                self.vmiss[prv] += 1;
                if let Some(x) = xl {
                    let (k, idx) = sized_key(va, x.shift);
                    self.fa_filt.access(k, prv);
                    self.fa_unified.access(k, prv);
                    for t in &mut self.sa_filt {
                        t.access(k, idx, prv);
                    }
                    for t in &mut self.sa_unified {
                        t.access(k, idx, prv);
                    }
                }
            }
        }

        if self.lite {
            return;
        }

        // Per-PC deltas.
        let e = self.pcs.entry(self.pc).or_default();
        e.prv = prv as u8;
        let cls = if !e.seen {
            e.seen = true;
            0
        } else {
            let d = va.wrapping_sub(e.last) as i64;
            let ld = (va >> 6).wrapping_sub(e.last >> 6) as i64;
            let c = if ld == 0 {
                1
            } else if ld == 1 || ld == -1 {
                2
            } else if d == e.delta {
                3
            } else {
                4
            };
            e.delta = d;
            if ld != 0 {
                let m = u64::from(base_miss);
                if let Some(p) = e.deltas.iter().position(|t| t.0 == d) {
                    e.deltas[p].1 += 1;
                    e.deltas[p].2 += m;
                } else if e.deltas.len() < 24 {
                    e.deltas.push((d, 1, m));
                } else {
                    e.other += 1;
                }
            }
            c
        };
        e.last = va;
        e.cls[cls] += 1;
        self.cls_tot[prv][cls] += 1;
        if base_miss {
            e.miss += 1;
            e.mcls[cls] += 1;
            self.mcls_tot[prv][cls] += 1;
        }

        // Working sets.
        if prv < M {
            let w = self.windows();
            if self.last_ws != (vline, w[0]) {
                self.last_ws = (vline, w[0]);
                let tag = (prv as u64) << 63;
                let a = va & VA_MASK;
                self.ws_line[prv].touch(tag | a >> 6, &w);
                self.ws_page[prv].touch(tag | a >> 12, &w);
                self.ws_region[prv].touch(tag | a >> 21, &w);
            }
        }
    }

    /// Issue a prefetch for `va + delta` into prefetcher `i`'s cache.
    fn prefetch(
        &mut self,
        mmu: &mut Mmu,
        i: usize,
        va: u64,
        pa: u64,
        delta: i64,
        translated: bool,
    ) {
        let t = va.wrapping_add(delta as u64);
        if t >> 6 == va >> 6 {
            return;
        }
        let cross = t >> 12 != va >> 12;
        let tpa = if !cross {
            (pa & !0xfff) | (t & 0xfff)
        } else if !translated {
            t
        } else {
            let Some(x) = self.xlat(mmu, t) else {
                return;
            };
            if let Some(g) = self.pfs[i].gate {
                let (pk, pidx) = page_key(t);
                let (sk, sidx) = sized_key(t, x.shift);
                let hit = match g {
                    Gate::Rtl => self.sa_rtl.probe(pk, pidx),
                    Gate::Sa(j) => self.sa_all[j].probe(sk, sidx),
                };
                if !hit {
                    self.pfs[i].dropped_gate += 1;
                    return;
                }
            }
            x.pa | (t & 0xfff)
        };
        let pf = &mut self.pfs[i];
        let line = tpa >> 6;
        if pf.cache.contains(line) {
            return;
        }
        let nonunit = delta.unsigned_abs() > 64;
        let mut f = F_PF;
        pf.issued += 1;
        if cross {
            f |= F_CROSS;
            pf.issued_cross += 1;
        }
        if nonunit {
            f |= F_NONUNIT;
            pf.issued_nonunit += 1;
        }
        pf.fill(line, f);
    }

    fn tlbs(&mut self, x: &Xlat, va: u64, prv: usize) {
        let (sk, sidx) = sized_key(va, x.shift);
        let (pk, pidx) = page_key(va);
        if self.lite {
            if !self.sa_rtl.access(pk, pidx, prv) {
                self.walks[prv] += 1;
                self.walk_refs += u64::from(x.nlev);
                for j in 0..x.nlev as usize {
                    let line = x.pte[j] >> 6;
                    for pf in &mut self.pfs {
                        if pf.cache.lookup(line).is_none() {
                            pf.pte_miss += 1;
                            pf.fill(line, 0);
                        }
                    }
                }
            }
            return;
        }
        self.fa_sized.access(sk, prv);
        self.fa_page.access(pk, prv);
        for t in &mut self.sa_all {
            t.access(sk, sidx, prv);
        }
        for t in &mut self.two {
            let (k1, i1) = if t.l1_page_keyed {
                (pk, pidx)
            } else {
                (sk, sidx)
            };
            if !t.l1.access(k1, i1, prv) {
                t.l2.access(sk, sidx, prv);
            }
        }
        if self.sa_rtl.access(pk, pidx, prv) {
            return;
        }
        // The walk: every PTE read is a data-cache read.
        self.walks[prv] += 1;
        let nlev = x.nlev as usize;
        self.walk_refs += nlev as u64;
        let w = self.windows();
        for j in 0..nlev {
            let line = x.pte[j] >> 6;
            self.ws_pte.touch(line, &w);
            for pf in &mut self.pfs {
                if pf.cache.lookup(line).is_none() {
                    pf.pte_miss += 1;
                    pf.fill(line, 0);
                }
            }
        }
        // Page-walk cache over the non-leaf PTEs: a hit on level j's PTE
        // leaves only the reads below it.
        let mut deepest = [usize::MAX; 3];
        for j in 0..nlev.saturating_sub(1) {
            deepest[j] = self.pwc.access(x.pte[j]);
            self.nonleaf.insert(x.pte[j], ());
        }
        for (s, &size) in PWC.iter().enumerate() {
            let mut refs = nlev;
            for j in 0..nlev.saturating_sub(1) {
                if deepest[j] < size {
                    refs = nlev - 1 - j;
                }
            }
            self.pwc_refs[s] += refs as u64;
        }
    }

    fn dump(&self, tag: &str) {
        let path = self.dir.join(format!("{tag}.txt"));
        let r = self.report(tag);
        if let Err(e) = std::fs::write(&path, r) {
            eprintln!("wset: {}: {e}", path.display());
        } else {
            eprintln!("wset: wrote {}", path.display());
        }
    }

    fn report(&self, tag: &str) -> String {
        let mut o = String::new();
        let n = self.n.max(1);
        let pki = |v: u64| v as f64 * 1000.0 / n as f64;
        let _ = writeln!(o, "# wset report {tag}");
        let _ = writeln!(
            o,
            "RAW n {} abs {} straight_pa_dram {} straight_va_dram {} walks16 {} accesses {}",
            self.n,
            self.abs,
            self.pfs[0].miss.iter().sum::<u64>(),
            self.vmiss.iter().sum::<u64>(),
            self.walks[U] + self.walks[S],
            self.acc.iter().flatten().sum::<u64>()
        );
        let _ = writeln!(
            o,
            "insns {} (U {} S {} M {})",
            self.n, self.insns[U], self.insns[S], self.insns[M]
        );
        let _ = writeln!(
            o,
            "sfence.vma {}  satp changes {}  walk failures {}  same-insn same-line records merged {}",
            self.sfences, self.satp_changes, self.walk_fail, self.dup
        );
        let _ = writeln!(o, "\n## data accesses (loads+AMO reads / stores)");
        for p in 0..3 {
            let _ = writeln!(
                o,
                "{} loads {} stores {} per-kinsn {:.1}",
                PRV_NAME[p],
                self.acc[p][0],
                self.acc[p][1],
                pki(self.acc[p][0] + self.acc[p][1])
            );
        }
        let _ = writeln!(o, "\n## leaf page size per access");
        for p in 0..2 {
            let t: u64 = self.by_size[p].iter().sum::<u64>().max(1);
            let _ = write!(o, "{}", PRV_NAME[p]);
            for s in 0..4 {
                let _ = write!(
                    o,
                    "  {} {} ({:.2}%)",
                    SIZE_NAME[s],
                    self.by_size[p][s],
                    self.by_size[p][s] as f64 * 100.0 / t as f64
                );
            }
            let _ = writeln!(o);
        }

        let _ = writeln!(
            o,
            "\n## working set: distinct keys per window (complete windows only): windows mean median max; whole = distinct over the run"
        );
        let mut ws_line = |name: &str, ws: &Ws| {
            let _ = write!(o, "{name:<22} whole {:>10}", ws.map.len());
            for i in 0..4 {
                let full = (self.n / WIN[i]) as usize;
                let mut v: Vec<u32> = (0..full)
                    .map(|j| ws.cnt[i].get(j).copied().unwrap_or(0))
                    .collect();
                if v.is_empty() {
                    let _ = write!(o, " | {}: -", WIN_NAME[i]);
                    continue;
                }
                v.sort_unstable();
                let mean = v.iter().map(|&x| u64::from(x)).sum::<u64>() as f64 / v.len() as f64;
                let _ = write!(
                    o,
                    " | {}: n={} mean {:.0} med {} max {}",
                    WIN_NAME[i],
                    v.len(),
                    mean,
                    v[v.len() / 2],
                    v[v.len() - 1]
                );
            }
            let _ = writeln!(o);
        };
        for p in 0..2 {
            ws_line(&format!("{} 4K pages", PRV_NAME[p]), &self.ws_page[p]);
            ws_line(&format!("{} 2M regions", PRV_NAME[p]), &self.ws_region[p]);
            ws_line(&format!("{} 64B lines", PRV_NAME[p]), &self.ws_line[p]);
        }
        ws_line("PTE lines (16DM walks)", &self.ws_pte);
        ws_line("I$-miss pages", &self.ws_imiss_page);

        let curve = |o: &mut String, name: &str, c: &Curve| {
            let _ = writeln!(
                o,
                "\n### {name}: lookups U {} S {} ({:.1} per kinsn)",
                c.lookups[U],
                c.lookups[S],
                pki(c.lookups[U] + c.lookups[S])
            );
            let _ = writeln!(o, "entries   misses_U   misses_S   MPKI_total  (MPKI_U)");
            for &s in &FA {
                let (mu, ms) = (c.misses(U, s), c.misses(S, s));
                let _ = writeln!(
                    o,
                    "{s:>7} {mu:>10} {ms:>10} {:>10.3} {:>10.3}",
                    pki(mu + ms),
                    pki(mu)
                );
            }
        };
        let sa = |o: &mut String, t: &Sa| {
            let _ = writeln!(
                o,
                "{:>12} {:>10} {:>10} {:>10.3} {:>10.3}",
                t.name(),
                t.miss[U],
                t.miss[S],
                pki(t.miss[U] + t.miss[S]),
                pki(t.miss[U])
            );
        };
        let _ = writeln!(
            o,
            "\n## TLB over all translated data accesses (U+S share one TLB; misses booked by privilege)"
        );
        curve(
            &mut o,
            "fully associative LRU, keys by leaf size",
            &self.fa_sized,
        );
        curve(
            &mut o,
            "fully associative LRU, one key per 4 KiB page whatever the leaf size",
            &self.fa_page,
        );
        let _ = writeln!(
            o,
            "\n### set-associative LRU, keys by leaf size, indexed by the leaf VPN"
        );
        let _ = writeln!(
            o,
            "      config   misses_U   misses_S  MPKI_total  (MPKI_U)"
        );
        for t in &self.sa_all {
            sa(&mut o, t);
        }
        let _ = writeln!(
            o,
            "\n### 16 DM keyed and indexed per 4 KiB page (tag = full VPN)"
        );
        sa(&mut o, &self.sa_rtl);
        let _ = writeln!(o, "\n### two-level: L1 misses and walks (L2 misses)");
        for t in &self.two {
            let l1 = if t.l1_page_keyed {
                "16 DM per-4K"
            } else {
                "64 FA sized"
            };
            let _ = writeln!(
                o,
                "L1 {l1:<13} L1miss {:>10} ({:.3} PKI)  L2 {:<10} walks U {:>9} S {:>9} ({:.3} PKI, {:.1}% of L1 misses)",
                t.l1.miss[U] + t.l1.miss[S],
                pki(t.l1.miss[U] + t.l1.miss[S]),
                t.l2.name(),
                t.l2.miss[U],
                t.l2.miss[S],
                pki(t.l2.miss[U] + t.l2.miss[S]),
                (t.l2.miss[U] + t.l2.miss[S]) as f64 * 100.0
                    / (t.l1.miss[U] + t.l1.miss[S]).max(1) as f64
            );
        }
        let walks = self.walks[U] + self.walks[S];
        let _ = writeln!(
            o,
            "\n## walks of the 16 DM per-4K TLB: U {} S {} ({:.3} PKI); PTE reads {} ({:.2}/walk)",
            self.walks[U],
            self.walks[S],
            pki(walks),
            self.walk_refs,
            self.walk_refs as f64 / walks.max(1) as f64
        );
        let _ = writeln!(o, "distinct non-leaf PTEs {}", self.nonleaf.len());
        let _ = writeln!(o, "PWC entries  PTE reads  per walk  saved");
        for (s, &size) in PWC.iter().enumerate() {
            let _ = writeln!(
                o,
                "{size:>11} {:>10} {:>9.3} {:>6.1}%",
                self.pwc_refs[s],
                self.pwc_refs[s] as f64 / walks.max(1) as f64,
                (self.walk_refs - self.pwc_refs[s]) as f64 * 100.0 / self.walk_refs.max(1) as f64
            );
        }

        let base = &self.pfs[0];
        let base_dm = base.miss[U] + base.miss[S] + base.miss[M];
        let _ = writeln!(
            o,
            "\n## data cache 128 KiB 2-way 64 B LRU, physically indexed; PTE reads of the 16 DM walks included"
        );
        let _ = writeln!(
            o,
            "demand misses U {} S {} M {} ({:.3} MPKI); PTE-read misses {} of {} ({:.2}%)",
            base.miss[U],
            base.miss[S],
            base.miss[M],
            pki(base_dm),
            base.pte_miss,
            self.walk_refs,
            base.pte_miss as f64 * 100.0 / self.walk_refs.max(1) as f64
        );
        let _ = writeln!(
            o,
            "\n## prefetchers (same cache; coverage = demand misses removed vs none; accuracy = useful/issued)"
        );
        let _ = writeln!(
            o,
            "{:<36} {:>11} {:>8} {:>7} {:>11} {:>11} {:>7} {:>10} {:>10} {:>10} {:>10} {:>9} {:>10}",
            "prefetcher",
            "dmd_misses",
            "MPKI",
            "cover",
            "issued",
            "useful",
            "acc",
            "iss_cross",
            "use_cross",
            "iss_nonu",
            "use_nonu",
            "pte_miss",
            "gate_drop"
        );
        for pf in &self.pfs {
            let dm = pf.miss[U] + pf.miss[S] + pf.miss[M];
            let _ = writeln!(
                o,
                "{:<36} {:>11} {:>8.3} {:>6.1}% {:>11} {:>11} {:>6.1}% {:>10} {:>10} {:>10} {:>10} {:>9} {:>10}",
                pf.name,
                dm,
                pki(dm),
                (base_dm as f64 - dm as f64) * 100.0 / base_dm.max(1) as f64,
                pf.issued,
                pf.useful,
                pf.useful as f64 * 100.0 / pf.issued.max(1) as f64,
                pf.issued_cross,
                pf.useful_cross,
                pf.issued_nonunit,
                pf.useful_nonunit,
                pf.pte_miss,
                pf.dropped_gate
            );
        }
        for p in 0..3 {
            let _ = writeln!(
                o,
                "\n## per-PC delta classes, {} accesses (count, and weighted by base D$ misses)",
                PRV_NAME[p]
            );
            let t: u64 = self.cls_tot[p].iter().sum::<u64>().max(1);
            let tm: u64 = self.mcls_tot[p].iter().sum::<u64>().max(1);
            for c in 0..5 {
                let _ = writeln!(
                    o,
                    "{:<24} {:>12} {:>6.2}%   misses {:>10} {:>6.2}%",
                    CLS_NAME[c],
                    self.cls_tot[p][c],
                    self.cls_tot[p][c] as f64 * 100.0 / t as f64,
                    self.mcls_tot[p][c],
                    self.mcls_tot[p][c] as f64 * 100.0 / tm as f64
                );
            }
        }
        let mut top: Vec<(&u64, &PcEnt)> = self.pcs.iter().collect();
        top.sort_by_key(|(_, e)| std::cmp::Reverse(e.miss));
        let _ = writeln!(
            o,
            "\n## top 30 PCs by base D$ misses ({} static PCs)",
            self.pcs.len()
        );
        for (pc, e) in top.iter().take(30) {
            let acc: u64 = e.cls.iter().sum();
            let _ = writeln!(
                o,
                "pc {pc:#x} {} accesses {} misses {} ({:.2}% of all) classes [first/same/next/stride/irreg] {:?} miss-classes {:?}",
                PRV_NAME[e.prv as usize],
                acc,
                e.miss,
                e.miss as f64 * 100.0 / base_dm.max(1) as f64,
                e.cls,
                e.mcls
            );
            let mut d = e.deltas.clone();
            d.sort_by_key(|t| std::cmp::Reverse(t.1));
            let _ = write!(o, "   deltas(count,misses):");
            for (delta, c, m) in d.iter().take(8) {
                let _ = write!(o, " {delta}:{c},{m}");
            }
            let _ = writeln!(o, " other:{}", e.other);
        }

        let vm = self.vmiss[U] + self.vmiss[S];
        let _ = writeln!(
            o,
            "\n## virtually tagged D$ 128 KiB 2-way: misses U {} S {} M {} ({:.3} PKI U+S); first stores to a load-filled line U {} S {} ({:.3} PKI)",
            self.vmiss[U],
            self.vmiss[S],
            self.vmiss[M],
            pki(vm),
            self.perm_up[U],
            self.perm_up[S],
            pki(self.perm_up[U] + self.perm_up[S])
        );
        curve(
            &mut o,
            "TLB over VT-D$ misses, fully associative LRU",
            &self.fa_filt,
        );
        let _ = writeln!(
            o,
            "      config   misses_U   misses_S  MPKI_total  (MPKI_U)"
        );
        for t in &self.sa_filt {
            sa(&mut o, t);
        }
        let _ = writeln!(
            o,
            "\n## I$ 128 KiB 2-way virtually tagged: line fetches U {} S {} M {}, misses U {} S {} M {} ({:.3} PKI)",
            self.iacc[U],
            self.iacc[S],
            self.iacc[M],
            self.imiss[U],
            self.imiss[S],
            self.imiss[M],
            pki(self.imiss[U] + self.imiss[S] + self.imiss[M])
        );
        curve(
            &mut o,
            "TLB over I$ misses only, fully associative LRU",
            &self.fa_imiss,
        );
        curve(
            &mut o,
            "unified TLB over VT-D$ misses + I$ misses, fully associative LRU",
            &self.fa_unified,
        );
        let _ = writeln!(
            o,
            "      config   misses_U   misses_S  MPKI_total  (MPKI_U)"
        );
        for t in &self.sa_unified {
            sa(&mut o, t);
        }

        let vm_all = self.vmiss[U] + self.vmiss[S] + self.vmiss[M];
        let find = |name: &str| {
            self.pfs
                .iter()
                .find(|p| p.name == name)
                .map_or(0, |p| p.miss.iter().sum::<u64>())
        };
        let _ = writeln!(
            o,
            "\n## split cache: way 0 64 KiB direct-mapped virtual, way 1 64 KiB direct-mapped physical hashed, single copy"
        );
        let _ = writeln!(
            o,
            "baselines, demand misses per kinsn: VA-indexed 2-way straight {:.3} | PA 2-way straight {:.3} | PA 2-way hashed {:.3} | PA 2-way hashed + RPT64 d2 {:.3}",
            pki(vm_all),
            pki(find("none")),
            pki(find("none, 128K 2-way hashed index")),
            pki(find("RPT64 d2, 128K 2-way hashed index"))
        );
        let _ = writeln!(
            o,
            "per kinsn: {:<23} {:>8} {:>8} {:>8} {:>8} {:>8} {:>7} {:>7} {:>8} {:>8} {:>7}",
            "model",
            "way0hit",
            "way1hit",
            "synmove",
            "DRAM",
            "moves",
            "PTErd",
            "PTEdram",
            "TLBlook",
            "walks",
            "1Gleaf"
        );
        for s in &self.split {
            let base = self
                .split
                .iter()
                .find(|b| b.degree == 0 && b.policy == s.policy)
                .map(Split::dram_total);
            s.report(&mut o, self.n, base);
        }
        o
    }
}
