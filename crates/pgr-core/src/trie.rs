//! Export trie construction (TDD §3.3; M3 "full export trie" + re-exports).
//!
//! The trie is built from the sorted export list with a range-partition
//! walk: sorted names share prefixes contiguously, so every edge is created
//! once, in final compressed form — no single-character expansion, no edge
//! splitting, no per-insert child-vector churn. Building is `O(Σ name bytes)`
//! after the sort, and the whole structure is a pure function of the export
//! set (determinism policy §4.3).
//!
//! Node layout (dyld/ld64 form): `ULEB terminal_size`, terminal info, `u8
//! child_count`, then per child `substring, 0x00, ULEB offset`. Regular
//! terminals carry `ULEB flags, ULEB address` (image-base-relative);
//! re-export terminals (M3) carry `ULEB flags|REEXPORT, ULEB ordinal,
//! imported-name NUL` — the name is omitted when it equals the export name.

use crate::LinkError;

/// Export flag: the node re-exports a symbol from another dylib (M3).
pub const EXPORT_SYMBOL_FLAGS_REEXPORT: u32 = 0x08;

/// Export flag: weak definition (`N_WEAK_DEF` passthrough).
pub const EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION: u32 = 0x01;

/// One terminal export entry (names borrowed — zero-copy from the interner).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export<'a> {
    /// Symbol name (with the C underscore).
    pub name: &'a [u8],
    /// Terminal payload.
    pub info: ExportInfo<'a>,
}

/// Terminal payload: an in-image export address or an M3 re-export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportInfo<'a> {
    /// `ULEB flags, ULEB address` (dyld resolves `base + address`).
    Regular {
        /// `EXPORT_SYMBOL_FLAGS_*` bits.
        flags: u32,
        /// Absolute export vaddr (the builder subtracts the image base).
        address: u64,
    },
    /// Re-export from the dylib at 1-based `ordinal` in this image's dylib
    /// list (M3; `-reexport_library`).
    Reexport {
        /// 1-based dylib ordinal.
        ordinal: u64,
        /// The original name in the re-exported dylib (empty slice = same
        /// name).
        imported_name: &'a [u8],
    },
}

/// Pre-resolved terminal (addresses made base-relative once, up front).
enum Term {
    Regular { flags: u32, rel: u64 },
    Reexport { ordinal: u64, name: Vec<u8> },
}

/// Builds the export-trie payload from `exports`.
///
/// The list is stably sorted by name (deterministic regardless of input
/// order) and exact-name duplicates collapse to the first occurrence.
///
/// # Errors
/// [`LinkError::Internal`] when a regular export address sits below the
/// image base (a caller bug, not user input).
pub fn build(exports: &mut Vec<Export<'_>>, image_base: u64) -> Result<Vec<u8>, LinkError> {
    if exports.is_empty() {
        return Ok(Vec::new());
    }
    // Multikey (radix) quicksort: symbol names share long prefixes, so
    // byte-wise three-way partitioning beats memcmp comparators by skipping
    // each group's shared prefix. The (name, original index) total order is
    // deterministic regardless of input order — equal names keep input
    // order, so the first definition of a duplicate wins.
    sort_exports(exports);
    exports.dedup_by(|a, b| a.name == b.name);

    let terms: Vec<Term> = exports
        .iter()
        .map(|e| match &e.info {
            ExportInfo::Regular { flags, address } => {
                let rel = checked_sub_base(*address, image_base, e.name)?;
                Ok(Term::Regular { flags: *flags, rel })
            }
            ExportInfo::Reexport {
                ordinal,
                imported_name,
            } => Ok(Term::Reexport {
                ordinal: *ordinal,
                // Same-name re-exports omit the redundant string (dyld
                // defaults the imported name to the export name).
                name: if imported_name.is_empty() || *imported_name == e.name {
                    Vec::new()
                } else {
                    (*imported_name).to_vec()
                },
            }),
        })
        .collect::<Result<_, _>>()?;

    // Contiguous name pool: every edge substring is a slice of this buffer.
    // One exact-size allocation; bounded per-name copies without capacity
    // checks. The trailing NUL sentinels double as the inter-name separator.
    let pool_bytes: usize = exports.iter().map(|e| e.name.len() + 1).sum();
    let mut pool: Vec<u8> = vec![0u8; pool_bytes];
    let mut spans: Vec<(u32, u32)> = Vec::with_capacity(exports.len());
    let mut at = 0usize;
    for e in exports.iter() {
        spans.push((at as u32, e.name.len() as u32));
        pool[at..at + e.name.len()].copy_from_slice(e.name);
        at += e.name.len() + 1;
    }

    // Flat node arena, preorder (children get higher indices than parents).
    #[derive(Clone, Copy, Debug)]
    struct Node {
        export: u32, // exports index + 1 (0 = pure prefix node)
        edge_start: u32,
        edge_count: u32,
    }
    #[derive(Clone, Copy, Debug)]
    struct Edge {
        sub: (u32, u32), // pool range
        child: u32,      // patched by the child frame
    }
    #[derive(Clone, Copy)]
    struct Frame {
        lo: u32,
        hi: u32,
        depth: u32,
        edge_slot: u32,
        parent: u32,
    }

    let mut nodes: Vec<Node> = Vec::with_capacity(exports.len() * 2);
    let mut edges: Vec<Edge> = Vec::with_capacity(exports.len() * 2);
    let mut parent_of: Vec<u32> = Vec::new(); // grows with nodes
    // Per-node size tables, accumulated during the walk (no second pass):
    // `static_size` = terminal + substrings + fixed bytes, `dyn_size` =
    // Σ child-offset widths (starts at the 4-byte upper bound per child).
    let term_sz = |export: u32| -> usize {
        if export == 0 {
            return 0;
        }
        match &terms[export as usize - 1] {
            Term::Regular { flags, rel } => uleb_len(u64::from(*flags)) + uleb_len(*rel),
            Term::Reexport { ordinal, name } => {
                uleb_len(u64::from(EXPORT_SYMBOL_FLAGS_REEXPORT))
                    + uleb_len(*ordinal)
                    + if name.is_empty() { 0 } else { name.len() + 1 }
            }
        }
    };
    let mut static_size: Vec<usize> = Vec::with_capacity(exports.len() * 2);
    let mut dyn_size: Vec<u32> = Vec::with_capacity(exports.len() * 2);
    // Scratch reused across nodes (clear keeps the capacity; the walk is
    // allocation-free after warm-up).
    let mut group_scratch: Vec<(u32, u32, u32)> = Vec::with_capacity(64); // (lo, hi, lcp)
    let mut frame_scratch: Vec<Frame> = Vec::with_capacity(64);
    let mut stack: Vec<Frame> = vec![Frame {
        lo: 0,
        hi: exports.len() as u32,
        depth: 0,
        edge_slot: u32::MAX,
        parent: u32::MAX,
    }];
    while let Some(f) = stack.pop() {
        let node_idx = nodes.len() as u32;
        nodes.push(Node {
            export: 0,
            edge_start: edges.len() as u32,
            edge_count: 0,
        });
        parent_of.push(u32::MAX);
        if f.edge_slot != u32::MAX {
            edges[f.edge_slot as usize].child = node_idx;
            parent_of[node_idx as usize] = f.parent;
        }
        let mut lo = f.lo;
        // Terminal: a name that *is* the current prefix sorts before its
        // extensions, so one check covers the whole range.
        if lo < f.hi && spans[lo as usize].1 == f.depth {
            nodes[node_idx as usize].export = lo + 1;
            lo += 1;
        }
        // Partition the remaining range by the byte at `depth`; each group's
        // shared prefix beyond `depth` becomes one compressed edge.
        group_scratch.clear();
        while lo < f.hi {
            let base = spans[lo as usize].0;
            let b = pool[base as usize + f.depth as usize];
            let mut mid = lo + 1;
            while mid < f.hi && pool[spans[mid as usize].0 as usize + f.depth as usize] == b {
                mid += 1;
            }
            // Shared prefix beyond `depth`: scan the range endpoints from
            // depth+1. Sortedness guarantees every name in [lo, mid) agrees
            // on whatever the endpoints agree on.
            let mut l = f.depth + 1;
            loop {
                let first = spans[lo as usize];
                let last = spans[mid as usize - 1];
                if first.1 == l || last.1 == l {
                    break;
                }
                if pool[first.0 as usize + l as usize] != pool[last.0 as usize + l as usize] {
                    break;
                }
                l += 1;
            }
            group_scratch.push((lo, mid, l));
            lo = mid;
        }
        let edge_start = edges.len() as u32;
        let mut sub_bytes = 0usize;
        for (glo, _ghi, l) in &group_scratch {
            let base = spans[*glo as usize].0;
            let sub_len = (*l - f.depth) as usize;
            sub_bytes += sub_len + 1;
            edges.push(Edge {
                sub: (base + f.depth, base + *l),
                child: 0,
            });
        }
        // Push reversed so the LIFO stack processes groups in edge order.
        frame_scratch.clear();
        for (k, (glo, ghi, l)) in group_scratch.iter().enumerate() {
            frame_scratch.push(Frame {
                lo: *glo,
                hi: *ghi,
                depth: *l,
                edge_slot: edge_start + k as u32,
                parent: node_idx,
            });
        }
        for fr in frame_scratch.iter().rev() {
            stack.push(*fr);
        }
        let count = edges.len() as u32 - edge_start;
        nodes[node_idx as usize].edge_count = count;
        // Terminal head (size byte + info) + child-count byte + substrings.
        let t = term_sz(nodes[node_idx as usize].export);
        let head = if t == 0 { 1 } else { uleb_len(t as u64) };
        static_size.push(head + t + 1 + sub_bytes);
        // Every child offset starts at its 4-byte upper-bound width.
        dyn_size.push(count * 4);
    }

    // ---- offset fixpoint (ld64's updateOffset): a child's ULEB width
    // depends on its offset, which depends on upstream widths. Each node
    // keeps one packed row (static size | Σ child widths | offset | width),
    // so a pass is a single streaming sweep over one contiguous array.
    // Widths start at the 4-byte upper bound (offsets in a trie under 2^28
    // bytes fit): pass 1 overshoots, widths only shrink from there, and the
    // fixpoint converges in a handful of passes.
    #[repr(C)]
    struct Row {
        stat: u32,
        dynw: u32,
        off: u32,
        width: u8,
        parent: u32,
    }
    let n_nodes = nodes.len();
    let mut rows: Vec<Row> = static_size
        .into_iter()
        .zip(dyn_size)
        .zip(parent_of)
        .map(|((st, dy), parent)| Row {
            stat: st as u32,
            dynw: dy,
            off: 0,
            width: 4,
            parent,
        })
        .collect();
    let mut passes = 0usize;
    loop {
        passes += 1;
        let mut changed = false;
        let mut next = 0u32;
        for i in 0..n_nodes {
            let r = &mut rows[i];
            let new_off = next;
            next = next.saturating_add(r.stat.saturating_add(r.dynw));
            if r.off != new_off {
                changed = true;
                r.off = new_off;
                let w = uleb_len(u64::from(new_off)) as u8;
                if w != r.width {
                    let d = i64::from(w) - i64::from(r.width);
                    r.width = w;
                    let parent = r.parent;
                    if parent != u32::MAX {
                        // Signed delta: starting from the upper bound, the
                        // first passes shrink widths.
                        let p = &mut rows[parent as usize];
                        p.dynw = (i64::from(p.dynw) + d) as u32;
                    }
                }
            }
        }
        if !changed || passes >= 10 {
            break;
        }
    }
    // Final consistent assignment (a no-op once converged): widths reflect
    // the final offsets, so one flat sweep sizes the payload exactly.
    let mut next = 0usize;
    for r in rows.iter_mut() {
        r.off = next as u32;
        next = next.saturating_add(r.stat.saturating_add(r.dynw) as usize);
    }
    let total = next;
    let offs: Vec<u32> = rows.iter().map(|r| r.off).collect();

    // ---- serialize (allocation-free: ULEBs are written in place) ----
    fn write_uleb(buf: &mut [u8], at: &mut usize, mut v: u64) {
        loop {
            let mut byte = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                byte |= 0x80;
            }
            buf[*at] = byte;
            *at += 1;
            if v == 0 {
                return;
            }
        }
    }
    let mut out = vec![0u8; total];
    for (i, n) in nodes.iter().enumerate() {
        let mut w = offs[i] as usize;
        let t = term_sz(n.export);
        if t == 0 {
            out[w] = 0;
            w += 1;
        } else {
            write_uleb(&mut out, &mut w, t as u64);
            match &terms[n.export as usize - 1] {
                Term::Regular { flags, rel } => {
                    write_uleb(&mut out, &mut w, u64::from(*flags));
                    write_uleb(&mut out, &mut w, *rel);
                }
                Term::Reexport { ordinal, name } => {
                    write_uleb(&mut out, &mut w, u64::from(EXPORT_SYMBOL_FLAGS_REEXPORT));
                    write_uleb(&mut out, &mut w, *ordinal);
                    if !name.is_empty() {
                        out[w..w + name.len()].copy_from_slice(name);
                        w += name.len();
                        out[w] = 0;
                        w += 1;
                    }
                }
            }
        }
        out[w] = n.edge_count as u8;
        w += 1;
        for k in 0..n.edge_count as usize {
            let e = &edges[n.edge_start as usize + k];
            let sub = &pool[e.sub.0 as usize..e.sub.1 as usize];
            out[w..w + sub.len()].copy_from_slice(sub);
            w += sub.len();
            out[w] = 0;
            w += 1;
            write_uleb(&mut out, &mut w, u64::from(offs[e.child as usize]));
        }
    }
    Ok(out)
}

/// Multikey quicksort over the export list (Bentley–Sedgewick): three-way
/// partitioning on the byte at `depth`, recursing only on the byte groups.
/// The original-index tiebreak makes the result a pure function of the
/// multiset — no dependence on pivot luck or sort stability.
fn sort_exports(exports: &mut Vec<Export<'_>>) {
    let mut idx: Vec<u32> = (0..exports.len() as u32).collect();
    mkqs(exports, &mut idx, 0);
    let sorted: Vec<Export> = idx
        .into_iter()
        .map(|i| exports[i as usize].clone())
        .collect();
    *exports = sorted;
}

/// The comparison key at `depth`: `None` when the name ended (shortest
/// first), `Some(byte)` otherwise.
fn name_key(name: &[u8], depth: usize) -> Option<u8> {
    name.get(depth).copied()
}

const MKQS_CUTOFF: usize = 24;

fn mkqs(exports: &[Export<'_>], idx: &mut [u32], depth: usize) {
    if idx.len() <= MKQS_CUTOFF {
        idx.sort_by(|&a, &b| {
            let (x, y) = (&exports[a as usize], &exports[b as usize]);
            x.name.cmp(y.name).then(a.cmp(&b))
        });
        return;
    }
    // Median-of-three pivot on the byte at `depth` (None sorts first).
    let (k0, k1, k2) = (
        name_key(exports[idx[0] as usize].name, depth),
        name_key(exports[idx[idx.len() / 2] as usize].name, depth),
        name_key(exports[idx[idx.len() - 1] as usize].name, depth),
    );
    let pivot = if (k0 <= k1 && k1 <= k2) || (k2 <= k1 && k1 <= k0) {
        k1
    } else if (k1 <= k0 && k0 <= k2) || (k2 <= k0 && k0 <= k1) {
        k0
    } else {
        k2
    };
    let (mut lt, mut gt, mut i) = (0usize, idx.len(), 0usize);
    while i < gt {
        let k = name_key(exports[idx[i] as usize].name, depth);
        match k.cmp(&pivot) {
            core::cmp::Ordering::Less => {
                idx.swap(lt, i);
                lt += 1;
                i += 1;
            }
            core::cmp::Ordering::Equal => i += 1,
            core::cmp::Ordering::Greater => {
                gt -= 1;
                idx.swap(i, gt);
            }
        }
    }
    mkqs(exports, &mut idx[..lt], depth);
    if pivot.is_some() {
        // The equal group shares the pivot byte: advance one byte deeper.
        mkqs(exports, &mut idx[lt..gt], depth + 1);
    } else {
        // All names ended at this depth: they are identical, so the
        // original-index tiebreak fully orders the group.
        idx[lt..gt].sort_unstable();
    }
    mkqs(exports, &mut idx[gt..], depth);
}

/// The address subtraction must stay in-range; a negative would corrupt the
/// ULEB stream, so it is an internal error (caller bug, not user input).
fn checked_sub_base(address: u64, image_base: u64, name: &[u8]) -> Result<u64, LinkError> {
    address
        .checked_sub(image_base)
        .ok_or_else(|| LinkError::Internal {
            message: format!(
                "export \"{}\" address {address:#x} below the image base {image_base:#x}",
                String::from_utf8_lossy(name)
            ),
        })
}

/// ULEB128 encoded length of `v` (one leading-zero count; `0` is one byte).
fn uleb_len(v: u64) -> usize {
    let bits = (64 - v.leading_zeros()) as usize;
    if bits == 0 { 1 } else { bits.div_ceil(7) }
}

#[cfg(test)]
mod tests {
    use super::{
        EXPORT_SYMBOL_FLAGS_REEXPORT, EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION, Export, ExportInfo,
        build,
    };
    use pgr_format::trie;

    fn reg(name: &'static str, address: u64) -> Export<'static> {
        Export {
            name: name.as_bytes(),
            info: ExportInfo::Regular { flags: 0, address },
        }
    }

    fn parse(bytes: &[u8]) -> Vec<trie::TrieExport> {
        trie::exports(bytes).unwrap()
    }

    #[test]
    fn empty_export_set_builds_an_empty_payload() {
        assert!(build(&mut Vec::new(), 0).unwrap().is_empty());
    }

    #[test]
    fn exports_round_trip_through_the_format_parser() {
        let mut exports = vec![
            reg("_main", 0x1_0000_0100),
            reg("_greet", 0x1_0000_0040),
            reg("_msg", 0x1_0000_0080),
        ];
        let out = build(&mut exports, 0x1_0000_0000).unwrap();
        let parsed = parse(&out);
        let names: Vec<Vec<u8>> = parsed.iter().map(|e| e.name.clone()).collect();
        assert_eq!(
            names,
            vec![b"_greet".to_vec(), b"_main".to_vec(), b"_msg".to_vec()]
        );
        assert_eq!(parsed[1].address, Some(0x100)); // relative: 0x100 - base
        assert_eq!(parsed[2].address, Some(0x80));
    }

    #[test]
    fn image_base_zero_matches_dylib_contract() {
        let mut exports = vec![reg("_f", 0x1234)];
        let out = build(&mut exports, 0).unwrap();
        assert_eq!(parse(&out)[0].address, Some(0x1234));
    }

    #[test]
    fn determinism_is_independent_of_input_order() {
        let mut a = vec![reg("_b", 2), reg("_a", 1), reg("_c", 3)];
        let mut b = vec![reg("_c", 3), reg("_a", 1), reg("_b", 2)];
        assert_eq!(build(&mut a, 0).unwrap(), build(&mut b, 0).unwrap());
    }

    #[test]
    fn duplicate_names_collapse_to_the_first() {
        let mut a = vec![reg("_d", 7), reg("_d", 9)];
        let parsed = parse(&build(&mut a, 0).unwrap());
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].address, Some(7), "first (input-order) wins");
    }

    #[test]
    fn prefix_names_become_separate_terminals() {
        // "_ab" is a strict prefix of "_abc": the "_ab" terminal sits on the
        // path to "_abc".
        let mut exports = vec![reg("_abc", 0x30), reg("_ab", 0x10)];
        let out = build(&mut exports, 0).unwrap();
        let parsed = parse(&out);
        let names: Vec<Vec<u8>> = parsed.iter().map(|e| e.name.clone()).collect();
        assert_eq!(names, vec![b"_ab".to_vec(), b"_abc".to_vec()]);
        assert_eq!(parsed[0].address, Some(0x10));
        assert_eq!(parsed[1].address, Some(0x30));
    }

    #[test]
    fn shared_prefixes_compress_into_multi_byte_edges() {
        let owned: Vec<String> = (0..64).map(|i| format!("_pgr_symbol_{i:04}_xxx")).collect();
        let mut names: Vec<Export> = owned
            .iter()
            .enumerate()
            .map(|(i, n)| Export {
                name: n.as_bytes(),
                info: ExportInfo::Regular {
                    flags: 0,
                    address: (i * 8) as u64,
                },
            })
            .collect();
        let out = build(&mut names, 0).unwrap();
        let total_bytes: usize = (0..64)
            .map(|i| format!("_pgr_symbol_{i:04}_xxx").len())
            .sum();
        assert!(
            out.len() < total_bytes,
            "trie {} bytes vs {} name bytes (uncompressed?)",
            out.len(),
            total_bytes
        );
        assert_eq!(parse(&out).len(), 64);
    }

    #[test]
    fn reexport_round_trips_with_ordinal_and_name() {
        let mut exports = vec![Export {
            name: b"_re",
            info: ExportInfo::Reexport {
                ordinal: 2,
                imported_name: b"_orig",
            },
        }];
        let out = build(&mut exports, 0).unwrap();
        let parsed = parse(&out);
        assert_eq!(parsed[0].flags, u64::from(EXPORT_SYMBOL_FLAGS_REEXPORT));
        assert_eq!(parsed[0].reexport_ordinal, Some(2));
        assert_eq!(parsed[0].imported_name, b"_orig");
        assert_eq!(parsed[0].address, None);
    }

    #[test]
    fn reexport_with_matching_name_omits_the_string() {
        let build_with = |imported: &'static [u8]| {
            let mut exports = vec![Export {
                name: b"_s",
                info: ExportInfo::Reexport {
                    ordinal: 1,
                    imported_name: imported,
                },
            }];
            build(&mut exports, 0).unwrap()
        };
        assert_eq!(
            build_with(b"_s"),
            build_with(b""),
            "same-name re-exports drop the redundant string"
        );
        let parsed = parse(&build_with(b""));
        assert_eq!(parsed[0].imported_name, b"_s", "walker defaults the name");
    }

    #[test]
    fn weak_flag_survives_the_round_trip() {
        let mut exports = vec![Export {
            name: b"_w",
            info: ExportInfo::Regular {
                flags: EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION,
                address: 8,
            },
        }];
        let out = build(&mut exports, 0).unwrap();
        assert_eq!(parse(&out)[0].flags, 1);
    }

    #[test]
    fn single_character_names_build_a_flat_root() {
        let mut exports = vec![reg("_a", 1), reg("_b", 2), reg("_c", 3)];
        let out = build(&mut exports, 0).unwrap();
        let parsed = parse(&out);
        assert_eq!(parsed.len(), 3);
        assert!(out.len() < 40, "flat root: {}", out.len());
    }

    #[test]
    fn export_below_image_base_is_an_internal_error() {
        let err = build(&mut vec![reg("_x", 4)], 0x10).unwrap_err();
        assert!(err.to_string().contains("below the image base"), "{err}");
    }
}
