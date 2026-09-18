//! The `--append` mechanism: forcing `/chosen/bootargs` into a device tree.
//!
//! Real trees from the repo, for the same reason `initrd.rs` uses them: the
//! shipped blobs have zero slack after the strings block
//! (`totalsize == off_dt_strings + size_dt_strings`), so rewriting a property
//! has to rebuild the blob with every offset moving consistently. Unlike the
//! ramdisk properties, a command line *replaces* whatever the tree declared,
//! and the replacement is usually a different length -- so both the grow and
//! the shrink path have to keep the header self-consistent.

// Every fallible call here is asserted on, so a failure aborts the test with
// the offending value in the panic message.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use simmerv::fdt;

const DTB: &[u8] = include_bytes!("../src/device/dtb.dtb");
const DTB_V: &[u8] = include_bytes!("../src/device/dtb-v.dtb");

fn header(dtb: &[u8]) -> [u32; 10] {
    let mut out = [0u32; 10];
    for (i, word) in out.iter_mut().enumerate() {
        *word = u32::from_be_bytes(dtb[i * 4..i * 4 + 4].try_into().unwrap());
    }
    out
}

/// `bootargs` as the tree reports it, found by walking rather than by trusting
/// the offsets the edit just rewrote.
fn bootargs_of(dtb: &[u8]) -> Option<String> {
    let h = header(dtb);
    let (off_struct, off_strings) = (h[2] as usize, h[3] as usize);
    let struct_end = off_struct + h[9] as usize;
    let mut pos = off_struct;
    let mut depth = 0u32;
    let mut in_chosen = None;
    while pos + 4 <= struct_end {
        let token = u32::from_be_bytes(dtb[pos..pos + 4].try_into().unwrap());
        pos += 4;
        match token {
            1 => {
                let end = dtb[pos..].iter().position(|&b| b == 0).unwrap() + pos;
                depth += 1;
                if depth == 2 && &dtb[pos..end] == b"chosen" {
                    in_chosen = Some(depth);
                }
                pos = (end + 1 + 3) & !3;
            }
            2 => {
                if in_chosen == Some(depth) {
                    in_chosen = None;
                }
                depth = depth.saturating_sub(1);
            }
            3 => {
                let len = u32::from_be_bytes(dtb[pos..pos + 4].try_into().unwrap()) as usize;
                let nameoff =
                    u32::from_be_bytes(dtb[pos + 4..pos + 8].try_into().unwrap()) as usize;
                let value_at = pos + 8;
                pos = value_at + ((len + 3) & !3);
                let name_at = off_strings + nameoff;
                let name_end = dtb[name_at..].iter().position(|&b| b == 0).unwrap() + name_at;
                if in_chosen == Some(depth) && &dtb[name_at..name_end] == b"bootargs" {
                    let value = &dtb[value_at..value_at + len - 1];
                    return Some(String::from_utf8(value.to_vec()).unwrap());
                }
            }
            9 => break,
            _ => {}
        }
    }
    None
}

/// `totalsize == off_dt_strings + size_dt_strings` and
/// `off_dt_strings == off_dt_struct + size_dt_struct`: the zero-slack relation
/// the shipped trees have, which an inconsistent edit would break while still
/// producing a blob that parses.
fn assert_coherent(dtb: &[u8]) {
    let h = header(dtb);
    let (totalsize, off_struct, off_strings) = (h[1] as usize, h[2] as usize, h[3] as usize);
    let (size_strings, size_struct) = (h[8] as usize, h[9] as usize);
    assert_eq!(totalsize, dtb.len(), "totalsize disagrees with the buffer");
    assert_eq!(
        totalsize,
        off_strings + size_strings,
        "strings block does not end at the end of the blob"
    );
    assert_eq!(
        off_strings,
        off_struct + size_struct,
        "structure block does not end where the strings block starts"
    );
}

fn set(dtb: &[u8], args: &str) -> Vec<u8> {
    fdt::analyze_bootargs_slot(dtb).unwrap().embed(dtb, args).unwrap()
}

#[test]
fn shipped_trees_already_have_a_command_line() {
    for dtb in [DTB, DTB_V] {
        assert!(fdt::analyze_bootargs_slot(dtb).unwrap().had_bootargs());
        assert!(bootargs_of(dtb).is_some());
    }
}

#[test]
fn replacing_with_a_shorter_line_keeps_the_blob_coherent() {
    let original = bootargs_of(DTB).unwrap();
    let short = "root=/dev/vda1 rw";
    assert!(short.len() < original.len(), "test needs a shorter line");
    let out = set(DTB, short);
    assert_eq!(bootargs_of(&out).as_deref(), Some(short));
    assert_coherent(&out);
    assert!(out.len() < DTB.len(), "a shorter line should shrink the blob");
}

#[test]
fn replacing_with_a_longer_line_keeps_the_blob_coherent() {
    let long = format!("root=/dev/vda1 rw init=/bench-init.sh {}", "x".repeat(300));
    let out = set(DTB, &long);
    assert_eq!(bootargs_of(&out).as_deref(), Some(long.as_str()));
    assert_coherent(&out);
    assert!(out.len() > DTB.len(), "a longer line should grow the blob");
}

#[test]
fn every_other_property_survives_the_edit() {
    // `stdout-path` and `rng-seed` follow `bootargs` in `/chosen`, so a splice
    // that mismeasured the replaced record would corrupt them -- and a wrong
    // `nameoff` base would rename them rather than break the parse.
    let out = set(DTB, "root=/dev/vda1 rw");
    let before = dtc_names(DTB);
    let after = dtc_names(&out);
    assert_eq!(before, after, "property names changed across the edit");
}

/// Every property name in the tree, in walk order.
fn dtc_names(dtb: &[u8]) -> Vec<String> {
    let h = header(dtb);
    let (off_struct, off_strings) = (h[2] as usize, h[3] as usize);
    let struct_end = off_struct + h[9] as usize;
    let mut pos = off_struct;
    let mut names = Vec::new();
    while pos + 4 <= struct_end {
        let token = u32::from_be_bytes(dtb[pos..pos + 4].try_into().unwrap());
        pos += 4;
        match token {
            1 => {
                let end = dtb[pos..].iter().position(|&b| b == 0).unwrap() + pos;
                pos = (end + 1 + 3) & !3;
            }
            3 => {
                let len = u32::from_be_bytes(dtb[pos..pos + 4].try_into().unwrap()) as usize;
                let nameoff =
                    u32::from_be_bytes(dtb[pos + 4..pos + 8].try_into().unwrap()) as usize;
                pos = pos + 8 + ((len + 3) & !3);
                let name_at = off_strings + nameoff;
                let name_end = dtb[name_at..].iter().position(|&b| b == 0).unwrap() + name_at;
                names.push(String::from_utf8(dtb[name_at..name_end].to_vec()).unwrap());
            }
            9 => break,
            _ => {}
        }
    }
    names
}

#[test]
fn a_nul_in_the_command_line_is_refused() {
    // Device tree strings are NUL-terminated, so an embedded NUL would silently
    // truncate the line the kernel actually sees.
    let slot = fdt::analyze_bootargs_slot(DTB).unwrap();
    assert!(slot.embed(DTB, "root=/dev/vda1\0rw").is_err());
}

#[test]
fn a_tree_without_chosen_is_refused() {
    // Truncating the blob to its header leaves valid magic and no /chosen.
    let mut stunted = DTB[..40].to_vec();
    stunted[36..40].copy_from_slice(&0u32.to_be_bytes()); // size_dt_struct = 0
    stunted[32..36].copy_from_slice(&0u32.to_be_bytes()); // size_dt_strings = 0
    stunted[4..8].copy_from_slice(&40u32.to_be_bytes()); // totalsize
    stunted[8..12].copy_from_slice(&40u32.to_be_bytes()); // off_dt_struct
    stunted[12..16].copy_from_slice(&40u32.to_be_bytes()); // off_dt_strings
    assert!(fdt::analyze_bootargs_slot(&stunted).is_err());
}
