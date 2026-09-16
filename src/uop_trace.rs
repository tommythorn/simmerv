//! Window recorder for the uop-cache *reference stream*.
//!
//! One record per block **execution**, on both the hit and the miss path, so
//! replaying the file reproduces the exact sequence of block lookups the
//! executor performed.  A record is `(key, len)`:
//!
//! * `key` is the full tagged key `step_block` probes with -- block VA, ASID in
//!   bits [63:48], M-mode bit 0 -- deliberately *not* pre-hashed, because the
//!   index function is one of the things the replay is meant to vary.
//! * `len` is the number of uops the block executed, which is the span it would
//!   occupy in a densely packed ring.  `len == 0` is an escape code meaning the
//!   lookup missed and deliberately did **not** insert (the block faulted
//!   part-way); real blocks always execute at least one uop.
//!
//! Invalidation is part of the reference stream, not an implementation detail:
//! a `SFENCE.VMA` drops entries a replay would otherwise still find, and on a
//! Linux boot the full flushes alone discard more live blocks than the entire
//! miss count.  So the file also carries *control records* -- same encoding,
//! but with the length field set to [`CONTROL`], which no block length ever is,
//! followed by an opcode and its operands.  The event happens at the cycle of
//! the probe it precedes.
//!
//! The decoded uops themselves are not recorded.  Cache-organisation questions
//! -- hash, associativity, replacement, ring packing -- are fully determined by
//! the `(key, len)` stream, and dropping the uops is what takes a record from
//! ~179 B to ~2 B.
//!
//! Encoding is `varint(len)` then `zigzag-varint(key - prev_key)`, so a hot
//! loop whose blocks are a few hundred bytes apart costs 2-3 bytes per record
//! before any general-purpose compression.  The length leads because it is the
//! record's type tag: with the delta first, a delta that happens to zigzag to
//! the control code would be indistinguishable from a control record, and
//! `zigzag(-128)` really is 255.  Records are buffered and flushed in
//! [`FLUSH_AT`] chunks; the writer is streaming, so the replay never needs to
//! seek.
//!
//! Enabled by environment, because the recorder is inert unless asked for and
//! threading it through `Emulator::new` would put a diagnostic in a public
//! signature:
//!
//! * `SIMMERV_TRACE`     -- output path; the recorder is off unless this is set
//! * `SIMMERV_TRACE_ARM` -- first cycle to record (default 0)
//! * `SIMMERV_TRACE_END` -- first cycle to *stop* recording (default: never;
//!   the cycle the run ended on is written back into the header on close, so
//!   the window is still complete without having to guess it up front)
//!
//! The cycle window is how a caller captures one subtest: on a Geekbench run
//! the Clang interval is known to span `[171_750_848_445, 180_630_164_423)`
//! cycles on the default configuration, which is ~1.09 G records.
//!
//! Cost when disarmed is one compare and a store of `prev_key`; when armed it
//! is the varint encode plus a buffer push.  This is a diagnostic, not a
//! statistic worth shipping -- cf. the `bb-hist` feature's measured ~1.8%.

use std::fs::File;
use std::io::BufWriter;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::io::{self};

/// Magic + version, so a replay can refuse a file it does not understand.
const MAGIC: &[u8; 4] = b"STRC";
/// 2 added the control (flush) records.  The mark opcode was added later
/// *within* v2 rather than as a version 3: the opcode space is the extension
/// point, and a reader that does not know opcode 5 reports it as an unknown
/// control record rather than misreading the stream, so old files stay
/// readable and new ones fail loudly.
const VERSION: u32 = 2;

/// Length field marking a control record rather than a block.  A block is 1-48
/// uops and 0 is the non-inserting miss, so 255 can only be a control record --
/// and because the length leads every record, a decoder can tell the two apart
/// without knowing anything else.
const CONTROL: u64 = 255;

/// Opcodes for control records, in the order `IcacheFlushKind` declares them.
const OP_FULL: u64 = 1;
const OP_ASID: u64 = 2;
const OP_VPAGE: u64 = 3;
const OP_VPAGE_ASID: u64 = 4;
const OP_MARK: u64 = 5;

/// An invalidation, mirroring `cpu::IcacheFlushKind`.  Duplicated rather than
/// imported so this module stays independent of the CPU it observes.
#[derive(Clone, Copy, Debug)]
pub enum Flush {
    Full,
    Asid(u16),
    /// A virtual page address; the low 12 bits are ignored by the cache.
    Vpage(u64),
    VpageAsid(u64, u16),
}

/// Bytes buffered before the writer is flushed.  Large enough that the syscall
/// cost disappears against the per-record encode.
const FLUSH_AT: usize = 4 << 20;

/// Encode `v` as LEB128.
// Truncating to a byte is the encoding: each step emits the low seven bits
// plus a continuation flag.
#[allow(clippy::cast_possible_truncation)]
#[inline]
fn put_uvarint(buf: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        buf.push((v as u8) | 0x80);
        v >>= 7;
    }
    buf.push(v as u8);
}

/// Map a signed delta onto an unsigned one so small negative deltas stay short.
/// Branch-free, and the shift is arithmetic so a negative `v` fills with ones.
// Reinterpreting the bits is the point: zigzag is defined on the encoding, not
// on the numeric value.
#[allow(clippy::cast_sign_loss)]
#[inline]
const fn zigzag(v: i64) -> u64 { ((v << 1) ^ (v >> 63)) as u64 }

pub struct UopTracer {
    out: BufWriter<File>,
    buf: Vec<u8>,
    /// First cycle recorded (inclusive).
    arm: u64,
    /// First cycle *not* recorded (exclusive).
    end: u64,
    /// Cycle of the most recent record of any kind, written back into the
    /// header on close when the window was left open.  Without it the header
    /// says the window runs to `u64::MAX` and a replay cannot rate the final
    /// interval against the cycles it actually took.
    last_cycle: u64,
    /// Last key seen, recorded or not, so the first armed record's delta stays
    /// small even if the window opens long after execution began.
    prev_key: u64,
    /// Records written, and bytes emitted, for the summary on drop.
    records: u64,
    /// Control records written, reported separately because a replay that
    /// silently dropped them looks like a working replay with fewer misses.
    flushes: u64,
    marks: u64,
    bytes: u64,
    /// Set on the first write error; recording stops rather than propagating,
    /// because `step_block` has no way to report an I/O failure (its `Result`
    /// is a RISC-V exception).
    broken: bool,
}

impl UopTracer {
    /// Build a recorder from the environment, or `None` when `SIMMERV_TRACE`
    /// is unset.  A failure to open the output file is reported on stderr and
    /// disables recording rather than aborting the run.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        let path = std::env::var("SIMMERV_TRACE").ok()?;
        let arm = env_u64("SIMMERV_TRACE_ARM").unwrap_or(0);
        let end = env_u64("SIMMERV_TRACE_END").unwrap_or(u64::MAX);

        let file = match File::create(&path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("uop-trace: cannot create {path}: {e}; recording disabled");
                return None;
            }
        };

        let mut buf = Vec::with_capacity(FLUSH_AT + 64);
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&VERSION.to_le_bytes());
        buf.extend_from_slice(&arm.to_le_bytes());
        buf.extend_from_slice(&end.to_le_bytes());

        eprintln!("uop-trace: recording cycles [{arm}, {end}) to {path}");
        Some(Self {
            out: BufWriter::with_capacity(FLUSH_AT, file),
            buf,
            arm,
            end,
            last_cycle: arm,
            prev_key: 0,
            records: 0,
            flushes: 0,
            marks: 0,
            bytes: 0,
            broken: false,
        })
    }

    /// Record one block execution.  `key` is the probed cache key and `len` the
    /// number of uops executed.
    #[inline]
    pub fn record(&mut self, cycle: u64, key: u64, len: u32) {
        if self.broken {
            return;
        }
        self.last_cycle = self.last_cycle.max(cycle);
        if cycle < self.arm {
            // Track the key even while disarmed so the window's first delta is
            // relative to real execution rather than to zero.
            self.prev_key = key;
            return;
        }
        if cycle >= self.end {
            return;
        }

        // The wrap is deliberate: the delta between two keys is a signed
        // distance, and `zigzag` maps it back to a short unsigned encoding.
        #[allow(clippy::cast_possible_wrap)]
        let delta = key.wrapping_sub(self.prev_key) as i64;
        self.prev_key = key;
        // Length first, then the delta: the length is the record's type tag,
        // and it has to lead or a delta that zigzags to the control
        // code is indistinguishable from a control record.  It is not
        // hypothetical -- `zigzag(-128) == 255`, and a block 128 bytes
        // *before* the previous one is an ordinary backward branch.
        put_uvarint(&mut self.buf, u64::from(len));
        put_uvarint(&mut self.buf, zigzag(delta));
        self.records += 1;

        if self.buf.len() >= FLUSH_AT {
            self.flush();
        }
    }

    fn flush(&mut self) {
        if self.broken || self.buf.is_empty() {
            return;
        }
        let n = self.buf.len();
        if let Err(e) = self.out.write_all(&self.buf) {
            eprintln!("uop-trace: write failed: {e}; recording disabled");
            self.broken = true;
            return;
        }
        self.buf.clear();
        self.bytes += n as u64;
    }

    /// Record an invalidation.  Deliberately does not touch `prev_key`: the key
    /// delta chain is over *lookups*, and a flush is not one.
    #[inline]
    pub fn record_flush(&mut self, cycle: u64, f: Flush) {
        if self.broken || cycle < self.arm || cycle >= self.end {
            return;
        }
        self.last_cycle = self.last_cycle.max(cycle);
        put_uvarint(&mut self.buf, CONTROL);
        self.flushes += 1;
        match f {
            Flush::Full => put_uvarint(&mut self.buf, OP_FULL),
            Flush::Asid(a) => {
                put_uvarint(&mut self.buf, OP_ASID);
                put_uvarint(&mut self.buf, u64::from(a));
            }
            Flush::Vpage(p) => {
                put_uvarint(&mut self.buf, OP_VPAGE);
                put_uvarint(&mut self.buf, p);
            }
            Flush::VpageAsid(p, a) => {
                put_uvarint(&mut self.buf, OP_VPAGE_ASID);
                put_uvarint(&mut self.buf, p);
                put_uvarint(&mut self.buf, u64::from(a));
            }
        }
        if self.buf.len() >= FLUSH_AT {
            self.flush();
        }
    }

    /// Record a workload boundary -- a subtest banner, a phase change.
    ///
    /// A replay can then attribute its counters to the interval the work came
    /// from instead of reporting one number for the whole run, which matters on
    /// GB5: Clang is 1.4% of cycles but 93% of the conflict misses, so a
    /// suite-wide aggregate is Clang plus forty billion free lookups and says
    /// almost nothing about the other eighteen subtests.
    ///
    /// The name is carried inline rather than as an index into a table the
    /// writer and reader would have to agree on, so the file stays
    /// self-describing.  A banner is ~10 bytes and there are ~20 per suite, so
    /// the cost is nothing against 100 GB of lookups.
    ///
    /// Like a flush, this deliberately does not touch `prev_key`: the delta
    /// chain is over lookups, and a mark is not one.
    #[inline]
    pub fn record_mark(&mut self, cycle: u64, name: &str) {
        if self.broken || cycle < self.arm || cycle >= self.end {
            return;
        }
        self.last_cycle = self.last_cycle.max(cycle);
        put_uvarint(&mut self.buf, CONTROL);
        put_uvarint(&mut self.buf, OP_MARK);
        // The cycle comes along so a replay can report *rates* per interval --
        // misses per million executions -- rather than only totals.  A subtest
        // that is 1.4% of the suite's cycles and 93% of its misses is only
        // legible as a rate.
        put_uvarint(&mut self.buf, cycle);
        let bytes = name.as_bytes();
        put_uvarint(&mut self.buf, bytes.len() as u64);
        self.buf.extend_from_slice(bytes);
        self.marks += 1;
        if self.buf.len() >= FLUSH_AT {
            self.flush();
        }
    }
}

fn env_u64(name: &str) -> Option<u64> {
    let raw = std::env::var(name).ok()?;
    match raw.parse() {
        Ok(v) => Some(v),
        Err(e) => {
            eprintln!("uop-trace: {name}={raw:?} is not a u64 ({e}); ignoring");
            None
        }
    }
}

impl Drop for UopTracer {
    // The summary line reports sizes and a mean; f64's mantissa is ample for a
    // byte count and the ratio is printed to two decimals.
    #[allow(clippy::cast_precision_loss)]
    fn drop(&mut self) {
        self.flush();
        if let Err(e) = self.out.flush() {
            eprintln!("uop-trace: final flush failed: {e}");
        }
        // Close the window.  The header has to be written before the run, so
        // when the recorder was never told where to stop the true end is only
        // known here -- and a replay needs it to rate the final interval
        // against the cycles that interval took.  A failure means the output is
        // not seekable (a pipe, say); the header then keeps its sentinel and
        // the replay reports that interval without per-cycle rates rather than
        // inventing them.
        if self.end == u64::MAX && !self.broken {
            let f = self.out.get_mut();
            if f.seek(SeekFrom::Start(16)).is_ok()
                && f.write_all(&self.last_cycle.to_le_bytes()).is_ok()
            {
                self.end = self.last_cycle;
            }
        }
        if self.broken {
            eprintln!(
                "uop-trace: INCOMPLETE after {} records, {} flushes",
                self.records, self.flushes
            );
        } else {
            eprintln!(
                "uop-trace: {} records, {} flushes, {} marks, {:.1} MiB ({:.2} B/record)",
                self.records,
                self.flushes,
                self.marks,
                self.bytes as f64 / (1024.0 * 1024.0),
                if self.records == 0 {
                    0.0
                } else {
                    self.bytes as f64 / self.records as f64
                }
            );
        }
    }
}

/// Error type kept for symmetry with the rest of the crate; the recorder itself
/// only ever reports through stderr.
pub type TraceResult<T> = io::Result<T>;
