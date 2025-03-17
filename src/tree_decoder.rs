/// Decoder Tree takes a list of (mask,data,value) patterns a
/// generates a good (optimal?) tree.  For the fastest possible
/// decoder we assume an unrolled decoder of fixed depth.  This
/// also implies that some branches have trial leafs.
///
/// The final result is compressed and represented as a linear
/// table of u16.
///
/// Todo:
/// - compress interiour levels too (might not be worthwhile)
/// - MAYBE: switch to relative encoding; this is only a win if it
///   enables using u8 instead of u16
/// - Replace the compress expander table with actual compressed
///   instructions and fold compressed decoding into this.  This
///   is expected to be a big win as the D$ pressure will down down
///   significantly.

#[derive(Debug)]
enum DecoderTree {
    L(usize, usize, Vec<usize>),
    N(usize, usize, Vec<DecoderTree>),
}

impl DecoderTree {
    #[allow(clippy::unwrap_used)]
    #[allow(clippy::missing_panics_doc)]
    fn flatten(&self, tab: &mut Vec<u16>) -> u16 {
        // [[[2 3 5 7],
        //   [0 0 1 0]],
        //  [[11 22 33 44]
        //   [99 88 77 66]]]
        //  --> L0 L1 L00 L01 L10 L11    2 3 5 7 0 0 1 0   11 22 33 44  99 88 77 66
        //  --> 2  4  6   10  14  18     2 3 5 7 0 0 1 0   11 22 33 44  99 88 77 66
        match self {
            Self::L(start, size, insns) => {
                // Expensive search for an existing useful option
                let start = u16::try_from(*start).unwrap();
                let mask = u16::try_from((1 << size) - 1).unwrap();

                'outer: for i in 0..tab.len() - insns.len() - 2 {
                    if tab[i] != start || tab[i + 1] != mask {
                        continue;
                    }
                    for (j, insn) in insns.iter().enumerate() {
                        if tab[i + 2 + j] != u16::try_from(*insn).unwrap() {
                            continue 'outer;
                        }
                    }

                    log::info!(
                        "** We appear to have found a match at {i}, saving {} entries!",
                        insns.len() + 2
                    );
                    return u16::try_from(i).unwrap();
                }

                let p = tab.len();
                tab.push(start);
                tab.push(mask);
                for insn in insns {
                    tab.push(u16::try_from(*insn).unwrap());
                }
                u16::try_from(p).unwrap()
            }
            Self::N(start, size, dts) => {
                let p = tab.len();
                tab.push(u16::try_from(*start).unwrap());
                tab.push(u16::try_from((1 << size) - 1).unwrap());
                for _ in dts {
                    tab.push(9999);
                }
                let mut pd = p + 2;
                for d in dts {
                    tab[pd] = d.flatten(tab);
                    pd += 1;
                }
                u16::try_from(p).unwrap()
            }
        }
    }
}

#[must_use]
pub fn new(patterns: &[(u32, u32, usize)]) -> Vec<u16> {
    let dt = search("", patterns, patterns.len() - 1, 2);
    let mut fdt = Vec::new();
    dt.flatten(&mut fdt);
    fdt
}

#[must_use]
pub const fn patmatch(fdt: &[u16], word: u32) -> usize {
    let w = word as usize;

    let p: usize = fdt[2 + ((w >> 2) & 31)] as usize;

    let start = fdt[p];
    let mask = fdt[p + 1] as usize;
    let p = fdt[p + 2 + ((w >> start) & mask)] as usize;

    let start = fdt[p];
    let mask = fdt[p + 1] as usize;
    fdt[p + 2 + ((w >> start) & mask)] as usize
}

#[allow(clippy::assigning_clones)]
#[allow(clippy::needless_range_loop)]
#[allow(clippy::missing_panics_doc)]
#[must_use]
fn search(
    prefix: &str,
    patterns: &[(u32, u32, usize)],
    sentinel: usize,
    depth: usize,
) -> DecoderTree {
    let mut best_size = 0;
    let mut best_start = 0;
    let mut best_cost = !0;
    let mut best_partition = Vec::new();
    let mut partition_count = Vec::new();
    let mut partition = Vec::new();

    // Search through different size of fields at different starting posisions
    'outer: for size in 0..=9 {
        let mask: u32 = (1 << size) - 1;
        for start in 0..=32 - size {
            let shifted_mask = if start >= 32 { 0 } else { mask << start };

            partition_count.clear();
            partition.clear();
            partition_count.resize(1 << size, 0);
            for _ in 0..1 << size {
                partition.push(vec![]);
            }

            for c in 0..1 << size {
                let word = if start >= 32 { 0 } else { c << start };
                for (mask, data, p) in patterns {
                    if shifted_mask & mask & word == shifted_mask & data {
                        partition_count[c as usize] += 1;
                        partition[c as usize].push((
                            mask & !shifted_mask,
                            data & !shifted_mask,
                            *p,
                        ));
                    }
                }
            }

            let cost = partition_count.iter().map(|s| s * s * s * s).sum::<usize>() + size;
            if cost < best_cost {
                best_size = size;
                best_start = start;
                best_cost = cost;
                best_partition = partition.clone();
                if best_cost == patterns.len() {
                    break 'outer;
                }
            }
        }
    }

    log::trace!("Best size {best_size}");

    if depth == 0 {
        // We have reached the bottom; each partition better at most have a single member
        // We reserve the last entry for illegal instructions
        let mut res = vec![];
        for p in &best_partition {
            if p.is_empty() {
                res.push(sentinel);
            } else if p.len() == 1 {
                res.push(p[0].2);
            } else {
                panic!("We weren't able to generate a tree decoder");
            }
        }
        assert_eq!(1 << best_size, best_partition.len());
        assert_eq!(1 << best_size, res.len());
        return DecoderTree::L(best_start, best_size, res);
    }

    let mut res = vec![];
    // Recursively find the subpartitions
    for p in 0..1 << best_size {
        let prefix = format!("{prefix}[{best_start}+{best_size}]={p} ");
        let n = search(&prefix, &best_partition[p], sentinel, depth - 1);
        res.push(n);
    }
    assert_eq!(1 << best_size, best_partition.len());
    assert_eq!(1 << best_size, res.len());
    DecoderTree::N(best_start, best_size, res)
}
