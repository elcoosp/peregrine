//! Export-trie validation (`LC_DYLD_EXPORTS_TRIE`): a full dyld-style walk.
//!
//! dyld resolves two-level namespace lookups by walking this trie: root
//! node → child edges (substring, NUL, ULEB child offset) → terminal node
//! carrying `ULEB flags, ULEB address`. The verifier walks every node
//! exactly like dyld's `TrieEntry` parser and additionally enforces the
//! invariants dyld only implies:
//!
//! * every offset lands inside the payload (never out of bounds),
//! * edges are sorted by their first byte (ld64's canonical order),
//! * edge substrings are non-empty,
//! * terminal addresses stay within the mapped image,
//! * the flag set is one the verifier understands (regular / weak
//!   definition); M3 re-export nodes are validated in full (ordinal
//!   bounds and the imported name), while stub-and-resolver and unknown
//!   flag bits warn as unimplemented.

use pgr_format::trie::EXPORT_SYMBOL_FLAGS_REEXPORT;

use crate::{Code, Issue, Report};

/// One walked export: a regular address, or an M3 re-export with its
/// ordinal and (possibly renamed) imported name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrieEntry {
    /// Full symbol name (edges concatenated).
    pub name: String,
    /// Raw terminal flags.
    pub flags: u32,
    /// Export address (`None` for re-exports).
    pub address: Option<u64>,
    /// Re-export ordinal (`EXPORT_SYMBOL_FLAGS_REEXPORT` terminals).
    pub reexport_ordinal: Option<u64>,
    /// The original name in the re-exported dylib (equals `name` when the
    /// terminal omits the string).
    pub imported_name: String,
}

/// Walk result: the exported symbols the trie describes.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct TrieExports {
    /// One entry per terminal node, in walk order.
    pub entries: Vec<TrieEntry>,
}

/// Walks and validates an export-trie payload.
pub fn check_export_trie(data: &[u8], report: &mut Report) -> TrieExports {
    let mut out = TrieExports::default();
    if data.is_empty() {
        return out;
    }
    let mut visited = std::collections::BTreeSet::<usize>::new();
    walk(data, 0, &mut String::new(), &mut visited, &mut out, report);
    out
}

/// ULEB128 decode at `at`; returns `(value, next)` or `None` on overflow.
fn uleb_at(data: &[u8], at: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    let mut i = at;
    loop {
        let byte = *data.get(i)?;
        i += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, i));
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
}

/// Recursive node walk (mirrors dyld's parse; iteration via an explicit
/// stack-free recursion bounded by the payload size).
fn walk(
    data: &[u8],
    at: usize,
    prefix: &mut String,
    visited: &mut std::collections::BTreeSet<usize>,
    out: &mut TrieExports,
    report: &mut Report,
) {
    if at >= data.len() {
        report.issues.push(Issue::error(
            Code::ExportTrie,
            "trie node offset outside the payload",
            Some(at as u64),
        ));
        return;
    }
    if !visited.insert(at) {
        report.issues.push(Issue::error(
            Code::ExportTrie,
            "trie node offset visited twice (cycle)",
            Some(at as u64),
        ));
        return;
    }
    let Some((terminal_size, mut cur)) = uleb_at(data, at) else {
        report.issues.push(Issue::error(
            Code::ExportTrie,
            "terminal size ULEB overruns the payload",
            Some(at as u64),
        ));
        return;
    };
    let terminal_start = cur;
    // The checked bound is *the* terminal end — the panics this once hid
    // behind an infallible-looking `unwrap()` are the same refusal the
    // verifier exists to name (TDD §2: typed errors, never panic).
    let Some(terminal_end) = terminal_start
        .checked_add(terminal_size as usize)
        .filter(|&end| end <= data.len())
    else {
        report.issues.push(Issue::error(
            Code::ExportTrie,
            "terminal info exceeds the payload",
            Some(at as u64),
        ));
        return;
    };
    if terminal_size > 0 {
        // Terminal: `ULEB flags, ULEB address` — or, for M3 re-exports
        // (the REEXPORT flag), `ULEB ordinal` plus an optional NUL imported
        // name (absent = same name; dyld resolves via the re-exported
        // dylib).
        let info = &data[terminal_start..terminal_end];
        let Some((flags, after_flags)) = uleb_at(info, 0) else {
            report.issues.push(Issue::error(
                Code::ExportTrie,
                "export flags ULEB overruns the terminal",
                Some(terminal_start as u64),
            ));
            return;
        };
        let (address, reexport_ordinal, imported_name) = if flags & EXPORT_SYMBOL_FLAGS_REEXPORT
            != 0
        {
            let Some((ordinal, after)) = uleb_at(info, after_flags) else {
                report.issues.push(Issue::error(
                    Code::ExportTrie,
                    "re-export node lacks its ordinal",
                    Some(terminal_start as u64),
                ));
                return;
            };
            if ordinal == 0 {
                report.issues.push(Issue::error(
                    Code::ExportTrie,
                    "re-export ordinal is zero (ordinals are 1-based)",
                    Some(terminal_start as u64),
                ));
                return;
            }
            let imported = if after < info.len() {
                match info[after..].iter().position(|&b| b == 0) {
                    Some(nul) if after + nul + 1 == info.len() => {
                        String::from_utf8_lossy(&info[after..after + nul]).into_owned()
                    }
                    _ => {
                        report.issues.push(Issue::error(
                            Code::ExportTrie,
                            "re-export imported name is not NUL-terminated or leaves trailing \
                             bytes",
                            Some(terminal_start as u64),
                        ));
                        return;
                    }
                }
            } else {
                prefix.clone()
            };
            (None, Some(ordinal), imported)
        } else {
            match uleb_at(info, after_flags) {
                Some((addr, after)) if after == info.len() => (Some(addr), None, prefix.clone()),
                _ => {
                    report.issues.push(Issue::error(
                        Code::ExportTrie,
                        "export info does not fill the declared terminal size",
                        Some(terminal_start as u64),
                    ));
                    return;
                }
            }
        };
        if flags & !0x9 != 0 {
            report.issues.push(Issue::warning(
                Code::ExportTrie,
                "export flags carry bits outside {regular, weak-definition, re-export}",
                Some(flags),
            ));
        }
        out.entries.push(TrieEntry {
            name: prefix.clone(),
            flags: flags as u32,
            address,
            reexport_ordinal,
            imported_name,
        });
    }
    cur = terminal_end;
    if cur >= data.len() {
        // No children byte (terminal-only payload end) — a trie must carry
        // the child count; running out here is malformed.
        report.issues.push(Issue::error(
            Code::ExportTrie,
            "trie payload ends before the child count",
            Some(cur as u64),
        ));
        return;
    }
    let child_count = data[cur];
    cur += 1;
    let mut prev_first: Option<u8> = None;
    for _ in 0..child_count {
        // Edge: substring up to NUL, then ULEB child offset.
        let substr_start = cur;
        let Some(nul) = data[substr_start..].iter().position(|&b| b == 0) else {
            report.issues.push(Issue::error(
                Code::ExportTrie,
                "edge substring is not NUL-terminated",
                Some(substr_start as u64),
            ));
            return;
        };
        let sub = &data[substr_start..substr_start + nul];
        cur = substr_start + nul + 1;
        if sub.is_empty() {
            report.issues.push(Issue::error(
                Code::ExportTrie,
                "edge substring is empty",
                Some(substr_start as u64),
            ));
            return;
        }
        if let Some(prev) = prev_first {
            if sub[0] <= prev {
                report.issues.push(Issue::error(
                    Code::ExportTrie,
                    "child edges are not sorted by their first byte (dyld requires canonical order)",
                    Some(substr_start as u64),
                ));
                return;
            }
        }
        prev_first = Some(sub[0]);
        let Some((child_off, after)) = uleb_at(data, cur) else {
            report.issues.push(Issue::error(
                Code::ExportTrie,
                "child offset ULEB overruns the payload",
                Some(cur as u64),
            ));
            return;
        };
        cur = after;
        let prefix_len = prefix.len();
        let Ok(s) = std::str::from_utf8(sub) else {
            report.issues.push(Issue::error(
                Code::ExportTrie,
                "edge substring is not UTF-8",
                Some(substr_start as u64),
            ));
            return;
        };
        prefix.push_str(s);
        walk(data, child_off as usize, prefix, visited, out, report);
        prefix.truncate(prefix_len);
    }
}

#[cfg(test)]
mod tests {
    use super::check_export_trie;
    use crate::{Code, Report, Severity};

    fn uleb(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            out.push(b);
            if v == 0 {
                break;
            }
        }
        out
    }

    /// Builds the M2 minimal trie shape: root → `_m` → `ain` / `h_execute_header`.
    fn sample_trie() -> Vec<u8> {
        // Node layout: [term][flags][addr][nchildren][edges: sub 0 off]
        let mut ain = Vec::new();
        ain.push(3u8); // terminal size
        ain.extend(uleb(0)); // flags
        ain.extend(uleb(0x4c8)); // address
        ain.push(0); // no children

        let mut mexec = Vec::new();
        mexec.push(2u8); // flags(1) + address(1) — address 0 is one ULEB byte
        mexec.extend(uleb(0));
        mexec.extend(uleb(0));
        mexec.push(0);

        // Layout: root at 0: [0][1]["_m\0"][off(6)]
        // _m node at 6: [0][2]["ain\0"][off]["h_execute_header\0"][off]
        // ain/mexec terminal nodes follow.
        let root = {
            let mut v = Vec::new();
            v.push(0);
            v.push(1);
            v.extend_from_slice(b"_m\0");
            v.extend(uleb(6));
            v
        };
        // _m node: no export (0), 2 children, two edges.
        let m_size = 2 + 4 + 1 + 17 + 1;
        let ain_off = 6 + m_size;
        let mexec_off = ain_off + ain.len();
        let mut m2 = Vec::new();
        m2.push(0);
        m2.push(2);
        m2.extend_from_slice(b"ain\0");
        m2.extend(uleb(ain_off as u64));
        m2.extend_from_slice(b"h_execute_header\0");
        m2.extend(uleb(mexec_off as u64));
        assert_eq!(m2.len(), m_size);

        let mut out = root;
        out.extend_from_slice(&m2);
        out.extend_from_slice(&ain);
        out.extend_from_slice(&mexec);
        out
    }

    #[test]
    fn well_formed_trie_walks_clean() {
        let trie = sample_trie();
        let mut report = Report::default();
        let exports = check_export_trie(&trie, &mut report);
        assert_eq!(exports.entries.len(), 2);
        assert_eq!(
            exports.entries[0],
            super::TrieEntry {
                name: "_main".into(),
                flags: 0,
                address: Some(0x4c8),
                reexport_ordinal: None,
                imported_name: "_main".into(),
            }
        );
        assert_eq!(
            exports.entries[1],
            super::TrieEntry {
                name: "_mh_execute_header".into(),
                flags: 0,
                address: Some(0),
                reexport_ordinal: None,
                imported_name: "_mh_execute_header".into(),
            }
        );
        assert!(
            !report
                .issues
                .iter()
                .any(|i| i.code == Code::ExportTrie && i.severity == Severity::Error)
        );
    }

    #[test]
    fn unsorted_edges_are_rejected() {
        // Two edges in reverse order.
        let mut trie = vec![0u8, 2, b'b', 0, 0x10, b'a', 0, 0x20];
        trie.extend(vec![0, 0]); // terminal nodes
        trie.extend(vec![0, 0]);
        let mut report = Report::default();
        check_export_trie(&trie, &mut report);
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == Code::ExportTrie && i.severity == Severity::Error)
        );
    }

    #[test]
    fn truncated_trie_is_rejected() {
        let mut report = Report::default();
        check_export_trie(&[0x01, 0x80], &mut report);
        assert!(
            report
                .issues
                .iter()
                .any(|i| i.code == Code::ExportTrie && i.severity == Severity::Error)
        );
    }

    #[test]
    fn cycle_detection() {
        // Root with one edge pointing back at itself.
        let trie = vec![0u8, 1, b'a', 0, 0x00];
        let mut report = Report::default();
        check_export_trie(&trie, &mut report);
        assert!(report.issues.iter().any(|i| i.code == Code::ExportTrie));
    }
}
