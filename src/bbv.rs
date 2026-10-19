//! Basic-block vectors for `SimPoint`-style sampling (`--bbv`).
//!
//! Every block execution adds the instructions it ran to its block's count;
//! at the end of each interval of `every` retired instructions the counts are
//! projected onto `DIMS` fixed pseudo-random directions and written as one
//! line:
//!
//! ```text
//! <seqno at the interval's end> <instructions counted> <v0> ... <v14>
//! ```
//!
//! `SimPoint` clusters the intervals by their normalised block vectors after a
//! random projection to about 15 dimensions; the projection is linear, so
//! projecting here and normalising later is the same thing, and an interval's
//! line is a few hundred bytes however many blocks ran in it. A block is its
//! uop-cache key (the block's address, the ASID above bit 48, bit 0 for
//! M-mode), so two processes' code at one address stay apart.

use std::collections::HashMap;
use std::fs::File;
use std::io::BufWriter;
use std::io::Write;

/// The projection's dimensions.
pub const DIMS: usize = 15;

pub struct Bbv {
    every: u64,
    next: u64,
    counts: HashMap<u64, u64>,
    out: BufWriter<File>,
}

impl Bbv {
    /// Write an interval every `every` instructions to `path`.
    ///
    /// # Errors
    /// Returns an error if `path` cannot be created.
    pub fn new(every: u64, path: &str) -> std::io::Result<Self> {
        Ok(Self {
            every,
            next: every,
            counts: HashMap::new(),
            out: BufWriter::new(File::create(path)?),
        })
    }

    /// One block execution: `n` instructions of block `key`, with `seqno`
    /// retired after it.
    #[inline]
    pub fn add(&mut self, key: u64, n: u32, seqno: u64) {
        *self.counts.entry(key).or_insert(0) += u64::from(n);
        if seqno >= self.next {
            self.emit(seqno);
            while self.next <= seqno {
                self.next += self.every;
            }
        }
    }

    /// Write the interval ending at `seqno` and start the next.
    pub fn emit(&mut self, seqno: u64) {
        let mut v = [0.0f64; DIMS];
        let mut total = 0u64;
        for (key, count) in self.counts.drain() {
            total += count;
            #[allow(clippy::cast_precision_loss)] // a weight, not a count to recover
            let c = count as f64;
            for (d, x) in v.iter_mut().enumerate() {
                *x = c.mul_add(direction(key, d), *x);
            }
        }
        if total == 0 {
            return;
        }
        let _ = write!(self.out, "{seqno} {total}");
        for x in v {
            let _ = write!(self.out, " {x:.6e}");
        }
        let _ = writeln!(self.out);
    }
}

impl Drop for Bbv {
    fn drop(&mut self) { let _ = self.out.flush(); }
}

/// Component `d` of block `key`'s fixed direction, uniform in [-1, 1):
/// splitmix64 of the pair, so the same block always projects the same way.
fn direction(key: u64, d: usize) -> f64 {
    let mut z = key ^ (d as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^= z >> 31;
    #[allow(clippy::cast_precision_loss)]
    let unit = (z >> 11) as f64 / (1u64 << 53) as f64;
    2.0f64.mul_add(unit, -1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directions_are_fixed_and_bounded() {
        for key in [0u64, 1, 0x8000_0000, u64::MAX] {
            for d in 0..DIMS {
                let x = direction(key, d);
                assert!((-1.0..1.0).contains(&x));
                assert!((x - direction(key, d)).abs() == 0.0);
            }
        }
        assert!((direction(1, 0) - direction(2, 0)).abs() > 0.0);
    }
}
