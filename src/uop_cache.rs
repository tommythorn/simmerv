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
///
/// On the Ubuntu boot the ceiling truncates 1.3% of insertions and 1.1% of
/// executions (`inserted_len` / `dyn_len` at index 48), i.e. ~421 k of 33 M
/// stored blocks are exactly 48 uops and were cut off there.  Raising it trades
/// that 1% for more stored tail in every long block, which is why it sits where
/// the two curves above crossed rather than higher.
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
///
/// Re-confirmed on the Ubuntu boot with the spanning-slot layout, interleaved
/// at 131 072 vs 262 144 (three rep-pairs each): 221.9 / 221.8 / 220.7 against
/// 223.2 / 221.8 / 224.7 MIPS.  Doubling buys ~0.8%, inside run-to-run noise,
/// while doubling the cache and the invalidation scan with it -- so 131 072
/// stays.  The trend is what matters: below this the hit rate falls fast
/// (65536 -> 95.1%, 32768 -> 92.2% from-cache), above it the curve is flat.
/// 131 072 is the knee of that curve, not a peak beyond it.
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
///
/// Re-measured on the Ubuntu boot, at a fixed 131072 entries so the arms differ
/// only in the quantum (interleaved, 2 reps each):
///
/// | `SLOT_UOPS` | slots | MIPS        | insert waste | conflicts | from-cache |
/// |-------------|-------|-------------|--------------|-----------|------------|
/// |          24 |  8192 | 222.7, 219.2|         61%  |    32.0 M |      97.0% |
/// |          16 |  8192 | 222.1, 221.6|         46%  |    34.0 M |      96.7% |
/// |           8 | 16384 | 216.4, 216.6|         25%  |    25.7 M |      97.1% |
/// |           6 | 32768 | 212.9, 209.6|         18%  |    15.1 M |      98.0% |
///
/// This inverts the naive reading of the fragmentation numbers.  Finer slots do
/// what they promise -- waste falls 61% -> 18%, conflict misses halve, the hit
/// rate rises to 98% -- and it is still a loss, because *every* slot is walked
/// by the invalidation scans and there are ~318 k of them per Ubuntu boot.  At
/// ~one host cycle per slot examined (measured: 0.28 ns) the scan is 1.6% of
/// the run at 8192 slots and 6.2% at 32768, which is the whole 4.4% the two
/// worst arms lose.  Shrinking the slot to reclaim waste, then, costs more in
/// flush traffic than the reclaimed entries are worth.  16 is the neutral
/// point: same slot count, so same scan, and the extra slots per block cancel
/// the fragmentation win against the extra conflict misses.
pub const SLOT_UOPS: usize = 24;

/// Directory entries, derived from the store size.
///
/// Not derived from anything deeper: `store_uops / 6` is the pairing the
/// study's "config 04" measured, and the port preserves it rather than
/// inventing a rule. At 196 608 store uops that is 32 768 entries = 16 384 sets
/// x 2 ways.
const DIR_PER_STORE_UOPS: usize = 6;

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
/// This is a build-time local, not the storage layout: the cache packs uops
/// contiguously into the ring, one span per block.
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

const INVALID_TAG: u64 = u64::MAX;

// `meta` packs a directory entry's ring offset, block length and age state into
// one `u32`: 18 bits of offset (2^17 < 196 608 <= 2^18), 6 bits of length
// (0..=48) and 2 bits of state.  With a 64-bit tag that is 12 B/entry.
const META_OFF_BITS: u32 = 18;
const META_OFF_MASK: u32 = (1 << META_OFF_BITS) - 1;
const META_LEN_SHIFT: u32 = META_OFF_BITS;
const META_LEN_MASK: u32 = 0x3F;
const META_STATE_SHIFT: u32 = META_OFF_BITS + 6;

/// Age state.  A block is allocated `AGE0`; displaced as `AGE0` it is copied
/// forward as `AGE1` (one reprieve); a hit while `AGE1` promotes it, which buys
/// one more reprieve; displaced as `AGE1` it is dropped.
const S_AGE0: u32 = 1;
const S_AGE1: u32 = 2;
const S_PROMOTE: u32 = 3;

#[inline]
const fn pack_meta(off: u32, len: u32, state: u32) -> u32 {
    off | (len << META_LEN_SHIFT) | (state << META_STATE_SHIFT)
}

/// One ring allocation, in the order the head made it.
///
/// `start` is monotone; the physical offset is `start % r`.  The block carries
/// its own key, and that key plus the offset *is* the back-pointer: a directory
/// slot reused since either holds a different key or holds this one at a
/// different offset, so an orphaned allocation reads as orphaned without a
/// generation counter stored anywhere.
#[derive(Clone, Copy)]
struct Alloc {
    key: u64,
    start: u64,
    /// Span in uops, including the `End` sentinel.
    span: u32,
}

/// A pending ring write: a fresh block, or a copy forward of a displaced one.
struct PendingWrite {
    slot: u32,
    tag: u64,
    /// Block length in uops, *not* the span.
    len: u32,
    state: u32,
    /// Staged uops for a copy forward.  `None` for a fresh insert, whose uops
    /// come from the caller's `BasicBlock`.
    ///
    /// A copy forward cannot simply read its source out of the store when it
    /// runs: see [`BbCache::read_span`].
    staged: Option<Box<[Uop]>>,
}

/// Two-stage basic-block uop cache: a skewed, tag-carrying **directory** with
/// one entry per block, feeding a dense, tagless **ring** of uops.
///
/// The previous design welded the index size to the store size --
/// `sets = entries / SLOT_UOPS / ways` -- so there was no way to buy a bigger
/// index without buying a bigger store, and the array sat at ~68% occupancy
/// with a third of it empty while lookups still missed.  Here the directory
/// holds `(tag, offset, length, state)` and the ring holds only uops,
/// bump-allocated, so the two are sized independently.
///
/// A ring entry is live exactly while the write head has not lapped its start.
/// Validity needs no stored flag, no sequence number and no invalidation on the
/// read path -- the allocation queue *is* the liveness proof.
///
/// **Area.**  The store is unchanged at 196 608 uops x 12 B = 2304 KiB; the
/// directory replaces the old tags-plus-continuation array at 32 768 entries x
/// 16 B (8 tag + 4 `meta` + 4 `stamp`) = 512 KiB, for 2816 KiB against the slot
/// design's 2376 KiB -- **+18.5%** for ~4x the directory.  The stamp is a third
/// of that overhead and is what a skewed directory costs to order by use; see
/// `stamp`.
pub struct BbCache {
    // ── stage 1: the directory ──────────────────────────────────────────────
    /// One tag per directory entry; `INVALID_TAG` is free.
    tags: Vec<u64>,
    /// `off | len << 18 | state << 24` -- see `pack_meta`.
    meta: Vec<u32>,
    /// Last-use stamp per directory *entry*, from `clock`.
    ///
    /// Not one bit per set, which is what a set-associative directory would
    /// need: the ways here are *skewed*, so `key`'s two candidate slots sit in
    /// two different sets and there is no shared set whose bit could order
    /// them.  Ordering two entries that share no set needs a per-entry stamp,
    /// and that is what makes the directory 16 B/entry rather than 12 -- see
    /// the area note on [`BbCache`].
    stamp: Vec<u32>,
    /// Monotone use counter feeding `stamp`.  Deliberately `u32` and
    /// deliberately wrapping: see [`Self::pick_dir_slot`].
    clock: u32,

    // ── stage 2: the ring ───────────────────────────────────────────────────
    /// Dense uop store, `r + MAX_BLOCK_LEN + 1` long.  The tail beyond `r`
    /// mirrors the first `MAX_BLOCK_LEN + 1` uops so a span that straddles the
    /// end of the ring is still readable as one contiguous slice -- see
    /// [`Self::write_span`].
    data: Vec<Uop>,
    /// Ring size in uops.  The physical offset of monotone position `p` is
    /// `p % r`.
    r: u64,
    /// Monotone write head.  Only `Self::clear` moves it backwards.
    head: u64,
    /// Live allocations in the order the head made them.
    q: std::collections::VecDeque<Alloc>,
    /// Copy-forward cascade, drained FIFO so a copy lands after the write that
    /// displaced it.
    pending: std::collections::VecDeque<PendingWrite>,
    /// The uops the in-flight write replaced, and where they lived.  Non-empty
    /// only between a write and the end of the reclaim it triggers; see
    /// [`Self::read_span`].
    snap: Vec<Uop>,
    snap_dst: usize,
    /// The directory slot the in-flight write owns; its entry reads from the
    /// store rather than the snapshot.
    snap_slot: usize,

    /// Number of directory entries per way.
    sets: usize,
    /// Mask for indexing into a way (`sets - 1`).
    mask: usize,
    mode: CacheMode,
    /// Total number of directory entries (constant after construction).
    capacity: usize,
    /// Number of currently occupied (non-`INVALID_TAG`) directory entries.
    occupied: usize,

    /// Number of block-level cache hits.
    pub block_hits: u64,
    /// Total instructions executed from cached blocks (`insn_hits` /
    /// `block_hits` = avg block len).
    pub insn_hits: u64,
    /// Miss where every candidate way was empty -- cold fill after a flush.
    pub cold_misses: u64,
    /// Miss where some candidate way held a *different* valid key.
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
    /// Blocks copied forward to earn a second lap.
    pub copies: u64,
    /// Blocks dropped at displacement, having had their reprieve.
    pub drops: u64,
    /// Allocations swept whose directory entry had already gone away.
    pub orphans: u64,
    /// Allocations the head has lapped, all told.  Equals
    /// `copies + drops + orphans`: every swept allocation takes exactly one of
    /// those three exits.
    pub swept_allocs: u64,
    /// Ring uops the head has lapped, all told.  Live spans plus this equals
    /// everything ever allocated, absent a full flush (which restarts the
    /// ring).
    pub swept_uops: u64,
    /// Uops swept whose directory entry had already gone away.  A cumulative
    /// total with no matching subtraction: the head visits every offset exactly
    /// once a lap, so counting orphans where the head meets them -- rather than
    /// where the entry was removed -- is what makes the total impossible to
    /// drift.
    pub dead_uops: u64,
    /// EXPERIMENT: how long the blocks actually stored are, indexed by uop
    /// count.  Measured on the Ubuntu boot: mean stored length is 9.3 uops and
    /// mean *executed* length 8.8, and the two agree bucket for bucket, which
    /// is the trace termination working -- a stored tail that never runs would
    /// make the static mean exceed the dynamic one.
    pub inserted_len: [u64; MAX_BLOCK_LEN + 1],
    /// EXPERIMENT: how long the blocks were when *executed*, indexed by the
    /// number of uops run before control left the block.  Same shape as
    /// `inserted_len`, but counted per execution rather than per insertion, so
    /// it is weighted by how often each block ran -- which is the distribution
    /// that decides whether the store is a good fit.
    pub dyn_len: [u64; MAX_BLOCK_LEN + 1],
}

impl BbCache {
    /// Create a new cache.
    ///
    /// `total_uop_entries` is the total uop-equivalent capacity.  The ring is
    /// `next_pow2(total / SLOT_UOPS) * SLOT_UOPS` uops -- unchanged from the
    /// slot design, so the store footprint is identical -- and the directory is
    /// sized from it at one entry per [`DIR_PER_STORE_UOPS`] store uops, split
    /// equally between the ways in `Skew` mode.
    #[must_use]
    pub fn new(total_uop_entries: usize, mode: CacheMode) -> Self {
        let block_slots = (total_uop_entries / SLOT_UOPS).max(1).next_power_of_two();
        let store_uops = block_slots * SLOT_UOPS;
        let dir_entries = (store_uops / DIR_PER_STORE_UOPS).max(1);
        let ways = match mode {
            CacheMode::Direct => 1,
            CacheMode::Skew => 2,
        };
        let sets = (dir_entries / ways).max(1).next_power_of_two();
        let n = sets * ways;
        let r = store_uops as u64;
        Self {
            tags: vec![INVALID_TAG; n],
            meta: vec![0; n],
            stamp: vec![0; n],
            clock: 0,
            // The shadow tail: one maximal span past the end of the ring, so a
            // straddling block is one contiguous slice.
            data: vec![Uop::default(); store_uops + MAX_BLOCK_LEN + 1],
            r,
            head: 0,
            q: std::collections::VecDeque::new(),
            pending: std::collections::VecDeque::new(),
            snap: Vec::with_capacity(MAX_BLOCK_LEN + 1),
            snap_dst: 0,
            snap_slot: usize::MAX,
            sets,
            mask: sets - 1,
            mode,
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
            copies: 0,
            drops: 0,
            orphans: 0,
            swept_allocs: 0,
            swept_uops: 0,
            dead_uops: 0,
            inserted_len: [0; MAX_BLOCK_LEN + 1],
            dyn_len: [0; MAX_BLOCK_LEN + 1],
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    #[inline]
    const fn index0(&self, key: u64) -> usize { key as usize & self.mask }

    #[allow(clippy::cast_possible_truncation)]
    #[inline]
    const fn index1(&self, key: u64) -> usize {
        // The way-1 index is `k & mask` XOR a few bits of `k >> 12`: one
        // shifter and one XOR, off the critical path.
        //
        // The property that has to hold is that two addresses aliasing in way 0
        // are still *distinct* in way 1. Aliasing in way 0 means equal index
        // bits, i.e. the same page offset but a different page; the first
        // differing bit is therefore bit 12 or above. Bits [23:12] are the page
        // number, so folding them down carries that difference into the index
        // and sends the two to different way-1 slots — true skew for exactly
        // the dominant conflict pattern.
        //
        // `>> 12` and not `>> 8`: at this directory's geometry `>> 8` was
        // measured at -0.49% on GB6 and +0.63% *worse* on GB5, a sign flip
        // inside half a percent.  It is a real ~17% win at 16 384 sets and that
        // is a separate, separately measured change.
        let k = key as usize;
        (k ^ (k >> 12)) & self.mask | self.sets
    }

    /// The `w`-th candidate directory slot for `key`.
    #[inline]
    const fn index_of(&self, w: usize, key: u64) -> usize {
        if w == 0 {
            self.index0(key)
        } else {
            self.index1(key)
        }
    }

    #[inline]
    const fn ways(&self) -> usize {
        match self.mode {
            CacheMode::Direct => 1,
            CacheMode::Skew => 2,
        }
    }

    /// Stamp `slot` as just used.
    #[inline]
    fn touch(&mut self, slot: usize) {
        self.clock = self.clock.wrapping_add(1);
        self.stamp[slot] = self.clock;
    }

    /// Look up `key` and return its directory slot on a hit, or `None` on a
    /// miss.  Miss stats are updated on a miss; the caller updates
    /// `block_hits` / `insn_hits` on a hit.
    ///
    /// A hit *is* the use signal, so advancing `AGE1` to `PROMOTE` costs two
    /// bits and no extra access -- which is the whole reason the state machine
    /// is free.
    #[inline]
    pub fn probe(&mut self, key: u64) -> Option<usize> {
        let ways = self.ways();
        let mut any_occupied = false;
        for w in 0..ways {
            let i = self.index_of(w, key);
            if self.tags[i] == key {
                if self.meta[i] >> META_STATE_SHIFT == S_AGE1 {
                    self.meta[i] =
                        (self.meta[i] & !(3 << META_STATE_SHIFT)) | (S_PROMOTE << META_STATE_SHIFT);
                }
                self.touch(i);
                return Some(i);
            }
            if self.tags[i] != INVALID_TAG {
                any_occupied = true;
            }
        }
        if any_occupied {
            self.conflict_misses += 1;
        } else {
            self.cold_misses += 1;
        }
        None
    }

    /// Return a shared reference to the block at `slot` (as returned by
    /// `probe`), exactly `len + 1` uops including the `End` sentinel.
    ///
    /// No over-read and no length test: the directory stores the length, and
    /// the shadow tail makes a straddling span contiguous.
    #[inline]
    #[must_use]
    pub fn block_at(&self, slot: usize) -> &[Uop] {
        let m = self.meta[slot];
        let off = (m & META_OFF_MASK) as usize;
        let len = ((m >> META_LEN_SHIFT) & META_LEN_MASK) as usize;
        &self.data[off..=off + len]
    }

    /// Empty a directory slot.
    ///
    /// The ring space is deliberately *not* reclaimed: the head meets it on its
    /// next lap and reclaims it then, and it is that meeting -- not this
    /// removal -- that `dead_uops` counts.  The asymmetry is load-bearing.
    #[inline]
    fn dir_clear(&mut self, slot: usize) {
        if self.tags[slot] != INVALID_TAG {
            self.tags[slot] = INVALID_TAG;
            self.occupied -= 1;
        }
        self.meta[slot] = 0;
    }

    /// The directory slot for `key` that names ring offset `start % r`, if that
    /// block is still live.
    ///
    /// This is the whole back-pointer test: the key comes from the block's own
    /// allocation record, the offset from where the head wrote it, and a slot
    /// reused since fails one or the other.
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    fn live_slot(&self, key: u64, start: u64) -> Option<usize> {
        let off = (start % self.r) as u32;
        for w in 0..self.ways() {
            let i = self.index_of(w, key);
            if self.tags[i] == key && self.meta[i] & META_OFF_MASK == off {
                return Some(i);
            }
        }
        None
    }

    /// Choose a directory slot for `key`, evicting the least recently used of
    /// its ways.  An evicted entry's ring space becomes a hole: nothing
    /// reclaims it, it is simply never referenced again and the head writes
    /// over it a lap later.
    ///
    /// A free way always wins, and the stamps are only consulted when every way
    /// is occupied.  That ordering is not an optimisation -- it is what the
    /// measured design does, and dropping it costs real hits: evicting the LRU
    /// way while a free way sat next to it moved this prefix by 0.34% of
    /// lookups, in the direction of more cold and fewer conflict misses.
    ///
    /// One property is inherited deliberately: **the clock is `u32` and it
    /// wraps.**  Comparing stamps with `<` across a wrap inverts the order, so
    /// roughly once every 4.3 G updates a handful of evictions pick the wrong
    /// way.  Widening it would be a different cache and a separate experiment.
    fn pick_dir_slot(&mut self, key: u64) -> usize {
        let ways = self.ways();
        if ways == 1 {
            let i = self.index0(key);
            self.dir_clear(i);
            return i;
        }
        // A free way first: a directory entry costs nothing to fill and
        // everything to evict.
        for w in 0..ways {
            let i = self.index_of(w, key);
            if self.tags[i] == INVALID_TAG {
                return i;
            }
        }
        let mut victim = self.index_of(0, key);
        let mut best = self.stamp[victim];
        for w in 1..ways {
            let i = self.index_of(w, key);
            if self.stamp[i] < best {
                best = self.stamp[i];
                victim = i;
            }
        }
        self.dir_clear(victim);
        victim
    }

    /// Write `span` uops at ring offset `dst`, keeping the shadow tail in step.
    ///
    /// The store is `r + MAX_BLOCK_LEN + 1` long, so `data[dst..dst + span]` is
    /// always in bounds and always contiguous.  Two cases need a fix-up
    /// afterwards, and they are the same edge seen from either side:
    ///
    /// * the span straddled the end of the ring, so the part written past `r`
    ///   has to be mirrored down to the front, which is where readers of
    ///   *later* laps will look for it;
    /// * the span landed in the first `MAX_BLOCK_LEN + 1` uops, which are the
    ///   ones mirrored at the end, so the tail copy has to be refreshed or a
    ///   straddling read from the previous lap would see stale uops.
    ///
    /// The head crosses that band once per lap, so this costs ~321 fix-ups on
    /// a full GB5 run.
    #[allow(clippy::cast_possible_truncation)]
    fn fix_shadow(&mut self, dst: usize, span: usize) {
        let r = self.r as usize;
        let end = dst + span;
        if end > r {
            self.data.copy_within(r..end, 0);
        } else if dst <= MAX_BLOCK_LEN {
            let hi = end.min(MAX_BLOCK_LEN + 1);
            self.data.copy_within(dst..hi, r + dst);
        }
    }

    /// Read the `n` uops at ring offset `off`, seeing through the write this
    /// call is in the middle of.
    ///
    /// **This is the one place the study's model cannot guide the port**, and
    /// getting it wrong is silent.  The model accounts for space positionally
    /// and never touches bytes, so a "copy forward" there is just another write
    /// with the same key at the new head -- no source, no data movement.  In a
    /// real store the source is very much real, and it is *already gone* by the
    /// time the model would read it:
    ///
    /// an entry is displaced exactly when `start < head - r`, and since it was
    /// alive before this write it also had `start >= head_before - r`.  So its
    /// start lies inside the monotone window this write just consumed -- the
    /// write that displaced a block is the write that overwrote its first uops.
    ///
    /// (A tempting argument says the source and destination are more than a lap
    /// apart so they cannot overlap.  That is true of the *monotone* positions
    /// and false of the physical ones: a monotone distance of `r + d` is a
    /// physical distance of `d`, and `d` here is a handful of uops.)
    ///
    /// So `place` snapshots the span it is about to overwrite, and a read that
    /// lands in that span is served from the snapshot instead of the store.
    /// Only the current write's span can need this: a displacement is raised by
    /// the write that laps it, and nothing later in the cascade has run yet.
    ///
    /// The snapshot is *not* consulted for the in-flight write's own directory
    /// slot: that entry describes the block written moments ago, whose uops are
    /// the ones now in the store.  See the caller.
    ///
    /// The source is *not* always the displaced allocation.  A block that
    /// missed and was re-inserted has a fresh allocation under the same key,
    /// and at `start == head - r` that allocation sits at the very offset the
    /// old one did -- so the directory resolves to the entry written moments
    /// ago, whose uops are intact in the store and whose length may differ from
    /// the lapped allocation's.  Reading by the directory's `(off, len)` rather
    /// than by the allocation's span is what makes those two cases one case.
    // `r` is the ring size in uops -- 196 608 at the shipped capacity, and
    // bounded by the store allocation in every case -- so it is a `usize`
    // already in all but type.
    #[allow(clippy::cast_possible_truncation)]
    fn read_span(&self, off: usize, n: usize) -> Box<[Uop]> {
        let r = self.r as usize;
        let mut out = Vec::with_capacity(n);
        for j in 0..n {
            let p = (off + j) % r;
            // Distance forward from the in-flight write's start, modulo the
            // ring: inside its span means the store already holds new uops.
            let i = (p + r - self.snap_dst) % r;
            out.push(if i < self.snap.len() {
                self.snap[i]
            } else {
                self.data[p]
            });
        }
        out.into_boxed_slice()
    }

    /// Perform one pending write: claim ring space, fill it, and let the head
    /// motion displace whatever it laps.
    #[allow(clippy::cast_possible_truncation, clippy::needless_pass_by_value)]
    fn place(&mut self, w: PendingWrite, fresh: Option<&BasicBlock>) {
        let len = w.len as usize;
        let span = len + 1; // + the `End` sentinel
        let dst = (self.head % self.r) as usize;
        let new_head = self.head + span as u64;

        // Before a single uop is overwritten, save the span this write will
        // destroy, so a copy forward raised below can still read it.  See
        // `read_span`.
        self.snap.clear();
        self.snap.extend_from_slice(&self.data[dst..dst + span]);
        self.snap_dst = dst;

        let slot = w.slot as usize;
        self.snap_slot = slot;
        if self.tags[slot] == INVALID_TAG {
            self.occupied += 1;
        }
        self.tags[slot] = w.tag;
        #[allow(clippy::cast_possible_truncation)]
        let off = dst as u32;
        self.meta[slot] = pack_meta(off, w.len, w.state);
        self.touch(slot);

        // Fill the span: the block's uops then the sentinel.
        match (&w.staged, fresh) {
            (Some(uops), _) => {
                self.data[dst..dst + span].copy_from_slice(uops);
            }
            (None, Some(block)) => {
                self.data[dst..dst + len].copy_from_slice(&block.uops[..len]);
                self.data[dst + len] = Uop::default();
            }
            (None, None) => unreachable!("a write is either a copy forward or a fresh block"),
        }
        self.fix_shadow(dst, span);

        self.q.push_back(Alloc {
            key: w.tag,
            start: self.head,
            #[allow(clippy::cast_possible_truncation)]
            span: span as u32,
        });
        self.head = new_head;
        self.reclaim();
        // The snapshot is only valid for the duration of its own write.
        self.snap.clear();
    }

    /// Free everything whose start the head has now lapped.
    ///
    /// The death test is on the entry's **start**, not its end: ring space is
    /// recycled one lap on, so an entry allocated at monotone `s` is dead once
    /// the head is past `s + r`.  Testing the end instead would kill the entry
    /// just written, whose end *is* the head.  The same test also covers the
    /// head landing inside an entry -- a block is read from its start, and its
    /// start is gone.
    fn reclaim(&mut self) {
        let dead_line = self.head.saturating_sub(self.r);
        let mut dead: Vec<Alloc> = Vec::new();
        while let Some(f) = self.q.front() {
            if f.start >= dead_line {
                break;
            }
            let f = *f;
            self.q.pop_front();
            dead.push(f);
        }
        for f in dead {
            self.swept_allocs += 1;
            self.swept_uops += u64::from(f.span);
            self.displace(f);
        }
    }

    /// Displacement is where policy acts: the head is about to lap a known
    /// entry, so its state is consulted here and a reprieve is just a copy
    /// forward.  Nothing is scanned, and no second access is needed to notice a
    /// use.
    fn displace(&mut self, f: Alloc) {
        let Some(slot) = self.live_slot(f.key, f.start) else {
            // Orphaned: the directory stopped pointing here before the head
            // arrived, so these uops have been unreachable ever since.
            self.orphans += 1;
            self.dead_uops += u64::from(f.span);
            return;
        };
        let m = self.meta[slot];
        let state = m >> META_STATE_SHIFT;
        let len = (m >> META_LEN_SHIFT) & META_LEN_MASK;
        match state {
            // First displacement: one reprieve, as `AGE1`.
            // A promotion with no slow ring is just another reprieve.
            S_AGE0 | S_PROMOTE => {
                let off = (m & META_OFF_MASK) as usize;
                let n = len as usize + 1;
                // Which allocation does this directory entry describe?  Usually
                // an older one, whose uops this write destroyed -- read those
                // through the snapshot.  But a block that missed and was
                // re-inserted has a fresh allocation under the same key, and at
                // `start == head - r` it lands on the very offset the lapped
                // one had, so the entry resolves to the write in flight.  Its
                // uops are the ones in the store, not the ones displaced.
                let uops = if slot == self.snap_slot {
                    self.data[off..off + n].into()
                } else {
                    self.read_span(off, n)
                };
                self.copies += 1;
                self.pending.push_back(PendingWrite {
                    #[allow(clippy::cast_possible_truncation)]
                    slot: slot as u32,
                    tag: f.key,
                    len,
                    state: S_AGE1,
                    staged: Some(uops),
                });
            }
            // Displaced twice with no use in between: gone.
            _ => {
                self.drops += 1;
                self.dir_clear(slot);
            }
        }
    }

    /// Insert `block` under `key`, allocating ring space at the head and
    /// running the displacement cascade it causes.
    pub fn insert(&mut self, key: u64, block: &BasicBlock) {
        let len = block
            .uops
            .iter()
            .take_while(|u| u.op != crate::generated_riscv_decoder::Op::End)
            .count();
        self.inserted_len[len] += 1;

        let slot = self.pick_dir_slot(key);
        #[allow(clippy::cast_possible_truncation)]
        let w = PendingWrite {
            slot: slot as u32,
            tag: key,
            len: len as u32,
            state: S_AGE0,
            staged: None,
        };
        self.place(w, Some(block));
        // Drain the copy-forward cascade: a copy lands after the write that
        // displaced it, and may displace further entries in turn.
        while let Some(w) = self.pending.pop_front() {
            self.place(w, None);
        }
    }

    pub fn clear(&mut self) {
        self.flush_full += 1;
        self.tags.fill(INVALID_TAG);
        self.meta.fill(0);
        self.occupied = 0;
        self.q.clear();
        // The ring is dead space now; restart it so directory offsets stay
        // meaningful against the cleared directory.
        self.head = 0;
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
        self.sweep(|t| t & 1 == 0 && t & asid_mask == asid_bits);
    }

    /// Flush S-mode entries whose VA page (bits [47:12] of the key) matches,
    /// regardless of ASID.
    pub fn flush_vpage(&mut self, page_addr: u64) {
        self.flush_vpage += 1;
        // Mask out ASID bits [63:48] and page-offset bits [11:0] for
        // comparison.
        let va_mask = !(0xFFFF_u64 << 48) & !0xFFF_u64;
        let page_base = page_addr & va_mask;
        self.sweep(|t| t & 1 == 0 && t & va_mask == page_base);
    }

    /// Flush the single S-mode entry matching both a specific VA page and ASID.
    pub fn flush_vpage_asid(&mut self, page_addr: u64, asid: u16) {
        self.flush_vpage_asid += 1;
        let va_mask = !(0xFFFF_u64 << 48) & !0xFFF_u64;
        let page_base = page_addr & va_mask;
        let asid_bits = u64::from(asid) << 48;
        let asid_mask = 0xFFFF_u64 << 48;
        self.sweep(|t| t & 1 == 0 && t & asid_mask == asid_bits && t & va_mask == page_base);
    }

    /// Linear tag scan over the directory, clearing every match.
    ///
    /// The directory is 4x the entry count the slot design scanned, which is
    /// the one measured way this organisation loses: these three flushes are
    /// O(directory).  It is a plain `u64` equality test over a dense array, so
    /// the fallback if it shows up in a profile is an explicit wide compare --
    /// see the handoff.  Note the ring space is *not* reclaimed here; the head
    /// does that one lap later.
    fn sweep(&mut self, hit: impl Fn(u64) -> bool) {
        for i in 0..self.capacity {
            let t = self.tags[i];
            if t != INVALID_TAG && hit(t) {
                self.dir_clear(i);
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

    /// Distribution of *executed* block lengths: how many uops each block ran
    /// before control left it.  Counted per execution, so it is weighted by how
    /// often each block ran rather than by how many blocks exist.
    #[must_use]
    pub const fn dyn_len(&self) -> &[u64; MAX_BLOCK_LEN + 1] { &self.dyn_len }

    /// Record one execution of an `n`-uop block.  Called from the
    /// block-executor hot loop, so it is a single array bump -- but that
    /// bump still costs ~1.8% on an Ubuntu boot, so it is behind the
    /// `bb-hist` feature and off by default.
    #[cfg(feature = "bb-hist")]
    #[inline]
    pub const fn record_dyn_len(&mut self, n: usize) {
        if n <= MAX_BLOCK_LEN {
            self.dyn_len[n] += 1;
        }
    }

    /// Ring size in uops -- the store the live blocks are competing for.
    #[must_use]
    pub const fn ring_uops(&self) -> u64 { self.r }

    /// Walk the directory and report `(live_blocks, stored_uops)`.
    ///
    /// Everything the directory points at is live by construction, so this is a
    /// tag scan and a sum of lengths -- there is no slot arithmetic left to do.
    /// `stored_uops` counts each block's uops plus its `End` sentinel, so
    /// `stored_uops` over [`Self::ring_uops`] is the fraction of the store that
    /// is reachable; the rest is entries the directory has dropped that the
    /// head has not yet lapped.
    #[must_use]
    pub fn residency(&self) -> (usize, u64) {
        let mut blocks = 0;
        let mut stored_uops = 0_u64;
        for i in 0..self.capacity {
            if self.tags[i] != INVALID_TAG {
                blocks += 1;
                stored_uops += u64::from((self.meta[i] >> META_LEN_SHIFT) & META_LEN_MASK) + 1;
            }
        }
        (blocks, stored_uops)
    }
}

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
    // Test code builds blocks from small integer literals and unwraps lookups
    // it has just made; neither is worth defensive arithmetic here.
    #![allow(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::expect_used,
        clippy::needless_range_loop
    )]

    use super::*;
    use crate::generated_riscv_decoder::Op;

    /// A block of `len` uops, each tagged with `imm` so it can be identified
    /// when it is read back.
    fn block(len: usize, mark: i32) -> BasicBlock {
        let mut b = BasicBlock::default();
        for (i, u) in b.uops.iter_mut().enumerate().take(len) {
            u.op = Op::Addi;
            u.imm = mark + i as i32;
        }
        if len < MAX_BLOCK_LEN {
            b.uops[len].op = Op::End;
        }
        b
    }

    /// Read a block back and check it is exactly the uops that went in, with
    /// the sentinel on the end.
    fn assert_block(cache: &BbCache, slot: usize, len: usize, mark: i32) {
        let got = cache.block_at(slot);
        assert_eq!(got.len(), len + 1, "span is len + sentinel");
        for i in 0..len {
            assert_eq!(got[i].imm, mark + i as i32, "uop {i} of block {mark}");
            assert_eq!(got[i].op, Op::Addi);
        }
        assert_eq!(got[len].op, Op::End, "sentinel terminates block {mark}");
    }

    fn skew() -> BbCache { BbCache::new(DEFAULT_UOP_ENTRIES, CacheMode::Skew) }

    #[test]
    fn geometry_matches_the_ported_design() {
        let c = skew();
        assert_eq!(
            c.ring_uops(),
            196_608,
            "store is unchanged from the slot design"
        );
        assert_eq!(
            c.capacity, 32_768,
            "directory is one entry per 6 store uops"
        );
        assert_eq!(c.sets, 16_384, "16384 sets x 2 ways");
        assert_eq!(c.data.len(), 196_608 + MAX_BLOCK_LEN + 1, "shadow tail");
    }

    #[test]
    fn roundtrips_a_block() {
        let mut c = skew();
        c.insert(0x1000, &block(7, 100));
        let slot = c.probe(0x1000).expect("just inserted");
        assert_block(&c, slot, 7, 100);
    }

    /// The store-wrap case the shadow tail exists for: run several laps past
    /// the end of the ring and read *every* live block back, checking each is
    /// the uops that went in rather than a shredded copy.
    ///
    /// Checked over the whole directory rather than per insert, because the
    /// allocation that lands on the ring's end is as likely to be a
    /// copy-forward as one of ours.
    #[test]
    fn blocks_straddling_the_ring_end_read_back_whole() {
        let mut c = skew();
        let r = c.ring_uops();
        // Span 47 does not divide the 196 608-uop ring, so spans walk off the
        // end rather than tiling it exactly (span 48 would divide it and never
        // straddle at all).
        let len = 46;
        let span = len as u64 + 1;
        let n = r / span * 3;
        for i in 0..n {
            c.insert(0x4000 + i * 0x1000, &block(len, (i as i32) * 1000));
        }

        let mut straddled = 0;
        let mut checked = 0;
        for slot in 0..c.capacity {
            if c.tags[slot] == INVALID_TAG {
                continue;
            }
            let m = c.meta[slot];
            let off = u64::from(m & META_OFF_MASK);
            let blen = ((m >> META_LEN_SHIFT) & META_LEN_MASK) as usize;
            if off + blen as u64 + 1 > r {
                straddled += 1;
            }
            // Self-consistent readback: the uops were written as a run of
            // consecutive `imm`s, so a span reassembled from the wrong bytes
            // fails the progression even without knowing which block it is.
            let got = c.block_at(slot);
            assert_eq!(got.len(), blen + 1);
            let mark = got[0].imm;
            for (i, u) in got[..blen].iter().enumerate() {
                assert_eq!(u.op, Op::Addi, "slot {slot} uop {i} is not a stored uop");
                assert_eq!(u.imm, mark + i as i32, "slot {slot} uop {i} is shredded");
            }
            assert_eq!(got[blen].op, Op::End, "slot {slot} lost its sentinel");
            checked += 1;
        }
        assert!(
            checked > 100,
            "only {checked} live blocks; test proves little"
        );
        assert!(straddled > 0, "no live block straddled the ring end");
    }

    /// Liveness: an entry dies when the head laps its start, and re-inserting
    /// it then misses.
    #[test]
    fn a_block_dies_when_the_head_laps_it() {
        let mut c = skew();
        let victim = 0x2000;
        c.insert(victim, &block(8, 1));
        assert!(c.probe(victim).is_some());

        // Push a full ring of uops through without ever touching `victim`, so
        // it is never promoted and cannot survive on a reprieve.
        let len = 40;
        let span = len as u64 + 1;
        let laps = c.ring_uops() / span + 2;
        for i in 0..laps {
            c.insert(0x8000_0000 + i * 0x1000, &block(len, 7));
        }
        assert!(c.probe(victim).is_none(), "lapped entry must be gone");
    }

    /// A block used once per lap is copied forward instead of dropped -- and
    /// the copy has to carry the right uops, which is the case the model cannot
    /// check because it stores none.
    #[test]
    fn a_used_block_is_copied_forward_with_its_uops_intact() {
        let mut c = skew();
        let keeper = 0x3000;
        c.insert(keeper, &block(9, 500));

        let len = 40;
        let span = len as u64 + 1;
        let per_lap = c.ring_uops() / span + 1;
        // Three laps, touching `keeper` often enough to keep earning reprieves.
        for lap in 0..3 {
            for i in 0..per_lap {
                c.insert(0x9000_0000 + (lap * per_lap + i) * 0x1000, &block(len, 7));
                if let Some(slot) = c.probe(keeper) {
                    // Whenever it is still resident, its uops must be the ones
                    // that were inserted -- never a shredded copy.
                    assert_block(&c, slot, 9, 500);
                }
            }
        }
        assert!(
            c.copies > 0,
            "no copy forward happened; test proves nothing"
        );
    }

    /// Every allocation the head laps is accounted exactly once, as a copy, a
    /// drop, or dead uops -- there is no path that loses one.
    #[test]
    fn every_lapped_allocation_is_accounted_once() {
        let mut c = skew();
        let len = 12;
        for i in 0..40_000_u64 {
            c.insert(0xA000_0000 + i * 0x40, &block(len, i as i32));
        }
        assert!(
            c.swept_allocs > 0,
            "nothing was lapped; test proves nothing"
        );
        assert_eq!(
            c.copies + c.drops + c.orphans,
            c.swept_allocs,
            "every swept allocation takes exactly one exit"
        );
        assert_eq!(
            c.q.iter().map(|a| u64::from(a.span)).sum::<u64>() + c.swept_uops,
            c.head,
            "live ring uops + swept uops must equal everything ever allocated"
        );
    }

    /// The aliasing case, built exactly rather than hoped for.
    ///
    /// This is what survived the first cut of this file and only surfaced 570 s
    /// into a Geekbench run, in Clang.  A block that misses and is re-inserted
    /// gets a fresh allocation under the same key, and when the old allocation
    /// sits exactly one lap back, the new one lands on the very offset the old
    /// one had.  The displacement of the *old* allocation then resolves to the
    /// directory entry written moments ago -- same key, same offset, but a
    /// different length.  Keying the copy source off the displaced allocation
    /// made that a length mismatch; serving it from the snapshot of overwritten
    /// uops made it copy the *old* block's uops under the new block's tag.
    ///
    /// Constructed here: insert `X` at head 0, fill the ring so the head
    /// returns to offset 0 having advanced exactly one lap, then re-insert `X`
    /// with a different length.  Nothing is displaced during the first lap, so
    /// the head lands where the arithmetic says it will.
    #[test]
    fn a_key_reinserted_exactly_one_lap_later_keeps_its_new_uops() {
        let mut c = skew();
        let r = c.ring_uops() as usize;
        let key = 0x10_0040;
        let (first, second) = (10, 30);

        c.insert(key, &block(first, mark_for(key)));

        // Filler must not land on either of `key`'s two directory slots, or the
        // entry under test is evicted before the re-insert and the case never
        // arises.  Any key does for the ring arithmetic, so skip the ones that
        // collide.
        let (k0, k1) = (c.index_of(0, key), c.index_of(1, key));
        let mut next = 0x8000_0000_u64;
        let mut fresh_key = move |c: &BbCache| loop {
            next += 0x40;
            if c.index_of(0, next) != k0
                && c.index_of(1, next) != k1
                && c.index_of(0, next) != k1
                && c.index_of(1, next) != k0
            {
                return next;
            }
        };

        // Fill to exactly one lap: spans of 12, then bare sentinels to land on
        // the offset `key` started at.
        let mut used = first + 1;
        while used + 12 <= r {
            let k = fresh_key(&c);
            c.insert(k, &block(11, mark_for(k)));
            used += 12;
        }
        while used < r {
            let k = fresh_key(&c);
            c.insert(k, &block(0, mark_for(k)));
            used += 1;
        }
        assert_eq!(
            c.head as usize, r,
            "filler must land the head on exactly one lap"
        );
        assert_eq!(
            c.copies, 0,
            "nothing should be displaced during the first lap"
        );
        assert!(
            c.probe(key).is_some(),
            "filler evicted the key; test is void"
        );

        // Drop the directory entry while leaving its ring space allocated --
        // which is exactly what a targeted flush does, and what makes the
        // re-insert resolve to the *new* entry rather than the old one.
        c.flush_vpage(key & !0xfff);
        assert!(c.probe(key).is_none());
        let head_before = c.head;
        assert_eq!(
            head_before as usize, r,
            "a flush must not reclaim ring space"
        );

        // The re-insert: same key, same offset, a different length.  The old
        // allocation is lapped by this very write, and the directory entry it
        // resolves to is the one just written.
        c.insert(key, &block(second, mark_for(key)));
        assert!(
            c.copies > 0,
            "the re-insert did not displace the old allocation"
        );

        let slot = c.probe(key).expect("re-inserted");
        let got = c.block_at(slot);
        assert_eq!(got.len(), second + 1, "the new length, not the old one");
        for (j, u) in got[..second].iter().enumerate() {
            assert_eq!(
                u.imm,
                mark_for(key) + j as i32,
                "uop {j} is not the new block"
            );
        }
        assert_eq!(got[second].op, Op::End);
        check_directory(&c);
    }

    /// The `imm` a block stored under `key` starts at, so a readback can tell
    /// whether the uops under a tag are that tag's block.
    fn mark_for(key: u64) -> i32 { ((key & 0xffff) as i32) * 64 }

    /// Every live directory entry holds its own block, whole.
    fn check_directory(c: &BbCache) {
        for slot in 0..c.capacity {
            if c.tags[slot] == INVALID_TAG {
                continue;
            }
            let m = c.meta[slot];
            let blen = ((m >> META_LEN_SHIFT) & META_LEN_MASK) as usize;
            let got = c.block_at(slot);
            assert_eq!(got.len(), blen + 1, "slot {slot} span");
            assert_eq!(got[blen].op, Op::End, "slot {slot} lost its sentinel");
            let want = mark_for(c.tags[slot]);
            if blen > 0 {
                assert_eq!(
                    got[0].imm, want,
                    "slot {slot} holds another key's uops (tag {:#x})",
                    c.tags[slot]
                );
            }
            for (i, u) in got[..blen].iter().enumerate() {
                assert_eq!(u.op, Op::Addi, "slot {slot} uop {i}");
                assert_eq!(u.imm, want + i as i32, "slot {slot} uop {i} is shredded");
            }
        }
    }

    #[test]
    fn flush_vpage_matches_high_canonical_kernel_pages() {
        let mut cache = BbCache::new(MAX_BLOCK_LEN * 4, CacheMode::Direct);
        let va = 0xffff_ffc0_1234_5678;
        cache.insert(va, &block(3, 1));
        assert!(cache.probe(va).is_some());
        cache.flush_vpage(va & !0xfff);
        assert!(cache.probe(va).is_none());
    }

    #[test]
    fn flush_vpage_asid_masks_asid_bits_from_requested_page() {
        let mut cache = BbCache::new(MAX_BLOCK_LEN * 4, CacheMode::Direct);
        let va = 0x0000_1234_5678;
        let asid = 0x42;
        let key = va | (u64::from(asid) << 48);
        cache.insert(key, &block(3, 1));
        assert!(cache.probe(key).is_some());
        cache.flush_vpage_asid(va & !0xfff, asid);
        assert!(cache.probe(key).is_none());
    }

    /// A flush clears directory entries and must *not* reclaim ring space --
    /// the head does that a lap later.  The asymmetry is what keeps the
    /// orphan accounting from drifting.
    #[test]
    fn a_flush_does_not_move_the_head() {
        let mut c = skew();
        for i in 0..100_u64 {
            c.insert(0xB000_0000 + i * 0x1000, &block(10, 1));
        }
        let head = c.head;
        c.flush_vpage(0xB000_0000);
        assert_eq!(c.head, head, "flush must not reclaim ring space");
        assert!(c.occupied < 100, "flush must have cleared entries");
    }

    /// A full flush restarts the ring, so stale offsets can never be read.
    #[test]
    fn clear_restarts_the_ring_and_the_directory() {
        let mut c = skew();
        for i in 0..100_u64 {
            c.insert(0xC000_0000 + i * 0x1000, &block(10, 1));
        }
        c.clear();
        assert_eq!(c.head, 0);
        assert_eq!(c.occupied, 0);
        assert!(c.q.is_empty());
        assert!(c.probe(0xC000_0000).is_none());
    }

    /// `Direct` is way 0 alone.
    #[test]
    fn direct_mode_uses_one_way() {
        let mut c = BbCache::new(DEFAULT_UOP_ENTRIES, CacheMode::Direct);
        assert_eq!(c.ways(), 1);
        assert_eq!(c.capacity, c.sets);
        c.insert(0x1000, &block(5, 3));
        let slot = c.probe(0x1000).expect("just inserted");
        assert_eq!(slot, c.index0(0x1000));
        assert_block(&c, slot, 5, 3);
    }

    /// A hit promotes an `AGE1` entry, which is what buys it another reprieve.
    #[test]
    fn a_hit_promotes_an_aged_entry() {
        let mut c = skew();
        c.insert(0x5000, &block(4, 9));
        let slot = c.probe(0x5000).expect("just inserted");
        // Force it to AGE1 as a displacement would.
        c.meta[slot] = (c.meta[slot] & !(3 << META_STATE_SHIFT)) | (S_AGE1 << META_STATE_SHIFT);
        c.probe(0x5000).expect("still resident");
        assert_eq!(c.meta[slot] >> META_STATE_SHIFT, S_PROMOTE);
    }
}
