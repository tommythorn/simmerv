//! Flattened device tree (FDT/DTB) surgery for the initial ramdisk.
//!
//! A guest kernel finds its ramdisk through the `linux,initrd-start` and
//! `linux,initrd-end` properties of `/chosen`.  Nothing generates those today:
//! `src/device/dts.dts` has no `/chosen` initrd properties and neither does the
//! `linux/with-initrd.dtb` recipe the README documents, which is why booting an
//! initramfs means hand-maintaining a `.dtb` with a frozen address in it.
//!
//! So they have to be inserted at run time, which means rebuilding the blob.
//! There is no room for an in-place write: every tree in this project has zero
//! slack after the strings block (`totalsize == off_dt_strings +
//! size_dt_strings`, measured on `dtb.dtb` 2400+474=2874, `dtb-v.dtb`
//! 2520+474=2994 and `linux/tiny128.dtb` 1624+415=2039), so a single inserted
//! property overflows `totalsize` by construction.
//!
//! The shape of the code here is deliberate: **one walk** of the tree yields
//! everything the edit needs ([`InitrdSlot`]), and the edit is then a byte
//! splice driven entirely by that struct.  A separate "how much will this
//! grow?" probe plus a separate "do the edit" pass would be two traversals that
//! must agree byte-for-byte about depth tracking, `/chosen` detection and
//! nameoff resolution -- and a 3 KiB structure that two functions disagree
//! about is silently corrupted rather than obviously broken.
//!
//! The growth is a function of the *input* tree alone (how many properties are
//! missing, how many names are not already interned, the root's
//! `#address-cells`), never of the addresses being written.  That is what lets
//! the caller resolve the chicken-and-egg between "the ramdisk's address
//! depends on the tree's final size" and "the tree's contents depend on the
//! ramdisk's address" in a single pass instead of iterating to a fixed point.

use anyhow::Result;
use anyhow::bail;

/// Physical address the ramdisk starts at, as read by
/// `early_init_dt_scan_chosen`.
pub const INITRD_START: &str = "linux,initrd-start";
/// One past the ramdisk's last byte.
pub const INITRD_END: &str = "linux,initrd-end";

const FDT_MAGIC: u32 = 0xd00d_feed;
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_END: u32 = 9;

/// `/chosen`'s `#address-cells` value when the root does not state one.  Two
/// cells is the convention every tree in this project uses, matching
/// `#address-cells = <2>` in `dts.dts`.
const DEFAULT_ADDR_CELLS: u32 = 2;

fn read_u32(data: &[u8], off: usize) -> u32 {
    data.get(off..off + 4).map_or(0, |bytes| {
        u32::from_be_bytes(bytes.try_into().unwrap_or([0; 4]))
    })
}

/// Offset of the NUL-terminated string starting at `off`, or `None` if it runs
/// off the end of `data`.
fn cstr_end(data: &[u8], off: usize) -> Option<usize> {
    data.get(off..)?
        .iter()
        .position(|&b| b == 0)
        .map(|i| off + i)
}

/// Name of the property at `nameoff`, or `None` if it is out of range.
fn name_at(data: &[u8], nameoff: usize) -> Option<&[u8]> {
    // `nameoff` is relative to the strings block, which the caller has already
    // shown to lie inside `data`.
    let end = cstr_end(data, nameoff)?;
    data.get(nameoff..end)
}

/// `nameoff` of `name` in the strings block, if it is already interned.
///
/// Reusing an existing entry keeps `size_dt_strings` -- and therefore the
/// growth this module reports -- correct for a tree that mentions the property
/// somewhere other than `/chosen`, or that was assembled by a tool which
/// interns names it does not use.
fn find_string(strings: &[u8], name: &str) -> Option<usize> {
    let mut i = 0;
    while i < strings.len() {
        let end = cstr_end(strings, i)?;
        if strings.get(i..end) == Some(name.as_bytes()) {
            return Some(i);
        }
        i = end + 1;
    }
    None
}

/// What one walk of a device tree tells us about inserting the ramdisk
/// properties.
#[derive(Debug, Clone)]
pub struct InitrdSlot {
    /// File offset of the `FDT_END_NODE` token that closes `/chosen`.
    ///
    /// This is where the properties go.  Inserting *after* the token would
    /// attach them to the root node instead, where `early_init_dt_scan_chosen`
    /// would never look -- a silent failure that still parses cleanly.
    chosen_end_node: usize,
    /// Root `#address-cells`: the number of 32-bit cells per address value.
    addr_cells: u32,
    /// File offset of the strings block, and its length.
    off_dt_strings: usize,
    size_dt_strings: usize,
    /// Length of the structure block, so a splice can be shown to stay inside
    /// it.
    size_dt_struct: usize,
    /// `nameoff`s of names already present in the strings block, if any.
    start_nameoff: Option<usize>,
    end_nameoff: Option<usize>,
}

impl InitrdSlot {
    /// Number of 32-bit cells in one address value.
    #[must_use]
    pub const fn addr_cells(&self) -> u32 { self.addr_cells }

    /// Bytes the blob grows by when both properties are inserted.
    ///
    /// A property is `FDT_PROP`(4) + `len`(4) + `nameoff`(4) + value
    /// (`4 * addr_cells`), and each name not already interned costs its length
    /// plus the NUL.  With `#address-cells = <2>` and both names new -- the
    /// shipped trees -- that is `2 * 20 + 19 + 17 = 76`.
    #[must_use]
    pub fn growth(&self) -> usize {
        let per_prop = 12 + 4 * self.addr_cells as usize;
        let mut total = 0;
        for (name, nameoff) in [
            (INITRD_START, self.start_nameoff),
            (INITRD_END, self.end_nameoff),
        ] {
            total += per_prop;
            if nameoff.is_none() {
                total += name.len() + 1;
            }
        }
        total
    }

    /// The blob with both properties set to `[start, end)`, `growth()` bytes
    /// longer than `dtb`.
    ///
    /// The addresses are the *only* thing that varies between calls: every
    /// structural decision here follows from the fields [`analyze_initrd_slot`]
    /// recorded.
    ///
    /// # Errors
    /// If an address does not fit in the tree's `#address-cells`, or if the
    /// recorded offsets do not describe a coherent blob.
    #[allow(clippy::cast_possible_truncation)] // FDT fields are 32-bit by definition
    pub fn embed(&self, dtb: &[u8], start: u64, end: u64) -> Result<Vec<u8>> {
        let cells = self.addr_cells as usize;
        let value = |v: u64| -> Result<Vec<u8>> {
            // An address wider than the tree can express must be reported, not
            // truncated: a silently shortened value would place the ramdisk
            // somewhere the caller never asked for.  Guarded because
            // `32 * cells` reaches 64 for the two-cell case, where every u64
            // already fits and shifting by the full width would be UB-adjacent
            // rather than merely useless.
            let bits = 32 * cells;
            if bits < 64 && v >> bits != 0 {
                bail!(
                    "address {v:#x} does not fit in {cells} 32-bit cell(s); \
                     the device tree's #address-cells is too small"
                );
            }
            let mut out = Vec::with_capacity(cells * 4);
            for cell in (0..cells).rev() {
                out.extend_from_slice(&(((v >> (32 * cell)) as u32).to_be_bytes()));
            }
            Ok(out)
        };

        // Assign each name its `nameoff`, appending only what is missing, and
        // build the two property records in the same order so the offsets
        // agree.
        let mut strings_added = 0;
        let mut appended = Vec::new();
        let mut records = Vec::with_capacity(2 * (12 + cells * 4));
        for (name, existing, addr) in [
            (INITRD_START, self.start_nameoff, start),
            (INITRD_END, self.end_nameoff, end),
        ] {
            let nameoff = existing.unwrap_or_else(|| {
                let off = self.size_dt_strings + strings_added;
                strings_added += name.len() + 1;
                appended.extend_from_slice(name.as_bytes());
                appended.push(0);
                off
            });
            records.extend_from_slice(&FDT_PROP.to_be_bytes());
            records.extend_from_slice(&((cells * 4) as u32).to_be_bytes());
            records.extend_from_slice(&(nameoff as u32).to_be_bytes());
            records.extend_from_slice(&value(addr)?);
        }

        let struct_added = records.len();
        let mut out = Vec::with_capacity(dtb.len() + struct_added + strings_added);
        // Everything before `/chosen`'s END_NODE, then the new properties, then
        // the rest -- which shifts up by `struct_added`.  That shift is the
        // whole reason `off_dt_strings` has to be rewritten below: the strings
        // block lives after the structure block in the same buffer, so growing
        // the structure physically moves it.
        out.extend_from_slice(&dtb[..self.chosen_end_node]);
        out.extend_from_slice(&records);
        out.extend_from_slice(&dtb[self.chosen_end_node..]);

        // Append the new names at the *end* of the strings block, so every
        // existing `nameoff` -- which is an offset from the block's start --
        // keeps pointing at the same string.
        let names_at = self.off_dt_strings + struct_added + self.size_dt_strings;
        if names_at > out.len() {
            bail!("internal error: strings block ends past the end of the tree");
        }
        out.splice(names_at..names_at, appended);

        // The four header words that describe the geometry.  `off_dt_struct`,
        // `off_mem_rsvmap` and the version fields are untouched, and the
        // zero-slack relation `totalsize == off_dt_strings + size_dt_strings`
        // is preserved exactly.
        out[4..8]
            .copy_from_slice(&((dtb.len() + struct_added + strings_added) as u32).to_be_bytes());
        out[12..16].copy_from_slice(&((self.off_dt_strings + struct_added) as u32).to_be_bytes());
        out[32..36].copy_from_slice(&((self.size_dt_strings + strings_added) as u32).to_be_bytes());
        out[36..40].copy_from_slice(&((self.size_dt_struct + struct_added) as u32).to_be_bytes());
        Ok(out)
    }
}

/// The `/memreserve/` ranges a tree declares, as `(start, end)` pairs.
///
/// `dts.dts` reserves `[0x80000000, 0x80200000)` for the firmware, and a
/// ramdisk written there corrupts `OpenSBI` in a way that presents as a hang
/// with no diagnostic.  Read from the tree rather than hardcoded so a custom
/// `-d` tree's own reservations are honoured.  Best-effort: a malformed
/// reservation block yields no ranges, since the caller only uses this to
/// refuse a placement.
#[must_use]
pub fn mem_reserve_ranges(dtb: &[u8]) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    if dtb.len() < 40 || read_u32(dtb, 0) != FDT_MAGIC {
        return out;
    }
    let off = read_u32(dtb, 16) as usize;
    let mut pos = off;
    // The reservation block is always 2 cells of address and 2 of size,
    // regardless of the root's #address-cells / #size-cells, and is terminated
    // by an all-zero entry.
    while let (Some(addr), Some(size)) = (dtb.get(pos..pos + 8), dtb.get(pos + 8..pos + 16)) {
        let (addr, size) = (
            u64::from_be_bytes(addr.try_into().unwrap_or([0; 8])),
            u64::from_be_bytes(size.try_into().unwrap_or([0; 8])),
        );
        if addr == 0 && size == 0 {
            break;
        }
        // A range that wraps is nonsense; skip it rather than refuse a
        // placement because of arithmetic on bad input.
        if let Some(end) = addr.checked_add(size) {
            out.push((addr, end));
        }
        pos += 16;
    }
    out
}

/// The four block offsets the edit needs, after checking that they describe a
/// blob whose blocks can be moved together.
///
/// The edit splices into the structure block and assumes the strings block
/// follows it in the same buffer, so a shift moves both and every existing
/// `nameoff` -- an offset from the strings block's start -- keeps resolving.
/// A tree with the blocks the other way round would need each `nameoff`
/// rebased; refuse rather than guess.
fn validate_header(dtb: &[u8]) -> Result<(usize, usize, usize, usize)> {
    let totalsize = read_u32(dtb, 4) as usize;
    let off_dt_struct = read_u32(dtb, 8) as usize;
    let off_dt_strings = read_u32(dtb, 12) as usize;
    let size_dt_strings = read_u32(dtb, 32) as usize;
    let size_dt_struct = read_u32(dtb, 36) as usize;

    if totalsize > dtb.len() {
        bail!(
            "device tree claims {totalsize} bytes but only {} are present",
            dtb.len()
        );
    }
    let (Some(struct_end), Some(strings_end)) = (
        off_dt_struct.checked_add(size_dt_struct),
        off_dt_strings.checked_add(size_dt_strings),
    ) else {
        bail!("device tree block offsets overflow");
    };
    if struct_end > dtb.len() || strings_end > dtb.len() {
        bail!(
            "device tree blocks run past the end: struct [{off_dt_struct:#x}, {struct_end:#x}), \
             strings [{off_dt_strings:#x}, {strings_end:#x}), size {:#x}",
            dtb.len()
        );
    }
    if off_dt_strings < struct_end {
        bail!(
            "device tree strings block at {off_dt_strings:#x} precedes the end of the \
             structure block at {struct_end:#x}; this layout is not supported"
        );
    }
    Ok((
        off_dt_struct,
        off_dt_strings,
        size_dt_strings,
        size_dt_struct,
    ))
}

/// Walk `dtb` far enough to place the ramdisk properties.
///
/// Rejects anything it cannot faithfully edit.  A device tree is an input, not
/// an invariant, so every one of these is a reportable error rather than an
/// assertion -- and each of them is a tree whose edit would otherwise produce a
/// blob that still parses but describes the wrong machine.
///
/// # Errors
/// If the blob is too short or lacks FDT magic, if its block offsets do not
/// describe a tree whose structure block precedes its strings block, if there
/// is no `/chosen` node, if the root's `#address-cells` is neither 1 nor 2, or
/// if `/chosen` already defines either ramdisk property.
pub fn analyze_initrd_slot(dtb: &[u8]) -> Result<InitrdSlot> {
    if dtb.len() < 40 {
        bail!(
            "device tree is {} bytes, too short for an FDT header",
            dtb.len()
        );
    }
    if read_u32(dtb, 0) != FDT_MAGIC {
        bail!(
            "device tree has bad magic {:#010x} (expected {FDT_MAGIC:#010x})",
            read_u32(dtb, 0)
        );
    }

    let (off_dt_struct, off_dt_strings, size_dt_strings, size_dt_struct) = validate_header(dtb)?;
    let struct_end = off_dt_struct + size_dt_struct;
    let strings = dtb
        .get(off_dt_strings..off_dt_strings + size_dt_strings)
        .unwrap_or(&[]);
    let start_nameoff = find_string(strings, INITRD_START);
    let end_nameoff = find_string(strings, INITRD_END);

    let mut addr_cells = None;
    let mut chosen_end_node = None;
    let mut chosen_depth: Option<u32> = None;
    let mut depth: u32 = 0;
    let mut pos = off_dt_struct;

    while pos + 4 <= struct_end {
        let token_at = pos;
        let token = read_u32(dtb, pos);
        pos += 4;
        match token {
            FDT_BEGIN_NODE => {
                let Some(end) = cstr_end(dtb, pos) else {
                    bail!("unterminated node name at {pos:#x}");
                };
                let name = dtb.get(pos..end).unwrap_or(&[]);
                pos = (end + 1 + 3) & !3;
                depth += 1;
                // `/chosen` is a direct child of the root, so it opens at depth
                // 2.
                if depth == 2 && name == b"chosen" {
                    chosen_depth = Some(depth);
                }
            }
            FDT_END_NODE => {
                if chosen_depth == Some(depth) {
                    chosen_end_node = Some(token_at);
                    chosen_depth = None;
                }
                depth = depth.saturating_sub(1);
            }
            FDT_PROP => {
                if pos + 8 > struct_end {
                    bail!("truncated property header at {pos:#x}");
                }
                let len = read_u32(dtb, pos) as usize;
                let nameoff = read_u32(dtb, pos + 4) as usize;
                let value_at = pos + 8;
                pos = value_at + ((len + 3) & !3);
                let Some(name) = name_at(dtb, off_dt_strings + nameoff) else {
                    bail!("property with out-of-range nameoff {nameoff} at {token_at:#x}");
                };
                // The root's `#address-cells` decides how wide an address value
                // is; it is a property of depth 1, and `/chosen` is depth 2.
                if depth == 1 && name == b"#address-cells" && len == 4 {
                    addr_cells = Some(read_u32(dtb, value_at));
                }
                if chosen_depth == Some(depth) && depth == 2 {
                    for prop in [INITRD_START, INITRD_END] {
                        if name == prop.as_bytes() {
                            // Refused rather than overwritten. The tree is
                            // stating where its ramdisk lives; silently moving
                            // it would leave the two disagreeing, and the guest
                            // would read whichever the kernel happened to keep.
                            bail!(
                                "/chosen already defines {prop} ({len} byte(s) at {value_at:#x}); \
                                 this device tree pins its own ramdisk address, so placing \
                                 one would contradict it. Remove the property to let the \
                                 emulator choose an address, or keep this tree and supply \
                                 no ramdisk of your own"
                            );
                        }
                    }
                }
            }
            FDT_END => break,
            _ => {} // FDT_NOP (4), and anything else, carries no structure
        }
    }

    let Some(chosen_end_node) = chosen_end_node else {
        bail!("device tree has no /chosen node; cannot advertise a ramdisk");
    };
    let addr_cells = addr_cells.unwrap_or(DEFAULT_ADDR_CELLS);
    if addr_cells != 1 && addr_cells != 2 {
        bail!(
            "device tree root declares #address-cells = <{addr_cells}>; only 1 or 2 are \
             supported, and an ambiguous address width would corrupt the ramdisk properties"
        );
    }

    Ok(InitrdSlot {
        chosen_end_node,
        addr_cells,
        off_dt_strings,
        size_dt_strings,
        size_dt_struct,
        start_nameoff,
        end_nameoff,
    })
}
