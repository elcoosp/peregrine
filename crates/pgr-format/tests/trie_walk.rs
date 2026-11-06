//! M3 acceptance tests for the export-trie walker (`pgr_format::trie`): the
//! driver's Mach-O dylib scan reads exports through this parser, so it must
//! be total (never panic), dyld-shaped (ULEB, NUL edges, prefix accumulation)
//! and re-export aware (M3: `flags & 0x08` nodes carry an ordinal + the
//! imported name).
//!
//! Fixture: a recursive builder serializes the root at payload offset 0 and
//! back-patches 5-byte ULEB child-offset placeholders, so child nodes can be
//! declared inline in any order.

use pgr_format::trie::TrieExport;

/// ULEB128 encoding (test-side twin of the layout encoder).
fn uleb(mut v: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
    out
}

/// ULEB128 fixed at five bytes (offsets up to 2^32-1 fit; placeholders are
/// patchable because the width never changes).
fn uleb5(v: u64) -> [u8; 5] {
    let mut out = [0u8; 5];
    for (k, b) in out.iter_mut().enumerate() {
        *b = ((v >> (7 * k)) & 0x7f) as u8;
        if k < 4 {
            *b |= 0x80;
        }
    }
    out
}

/// A trie node: optional terminal info and named children.
struct N {
    terminal: Option<Vec<u8>>,
    children: Vec<(Vec<u8>, N)>,
}

/// Serializes `n` into `out`; returns the offset `n` landed at.
fn emit(n: &N, out: &mut Vec<u8>) -> usize {
    let at = out.len();
    match &n.terminal {
        None => out.push(0),
        Some(info) => {
            out.extend_from_slice(&uleb(info.len() as u64));
            out.extend_from_slice(info);
        }
    }
    out.push(n.children.len() as u8);
    let mut patches = Vec::new();
    for (sub, _) in &n.children {
        // Record the position of the offset ULEB (after the substring+NUL).
        patches.push(out.len() + sub.len() + 1);
        out.extend_from_slice(sub);
        out.push(0);
        out.extend_from_slice(&uleb5(0));
    }
    for ((_, child), p) in n.children.iter().zip(patches) {
        let off = emit(child, out);
        out[p..p + 5].copy_from_slice(&uleb5(off as u64));
    }
    at
}

fn build(root: &N) -> Vec<u8> {
    let mut out = Vec::new();
    emit(root, &mut out);
    out
}

fn walk(bytes: &[u8]) -> Result<Vec<TrieExport>, pgr_format::FormatError> {
    pgr_format::trie::exports(bytes)
}

fn regular(flags: u64, address: u64) -> Vec<u8> {
    [uleb(flags), uleb(address)].concat()
}

#[test]
fn empty_payload_has_no_exports() {
    assert_eq!(walk(&[]).unwrap(), Vec::new());
}

#[test]
fn single_export_round_trips() {
    let root = N {
        terminal: None,
        children: vec![(
            b"_foo".to_vec(),
            N {
                terminal: Some(regular(0, 0x1234)),
                children: vec![],
            },
        )],
    };
    let out = walk(&build(&root)).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].name, b"_foo");
    assert_eq!(out[0].flags, 0);
    assert_eq!(out[0].address, Some(0x1234));
    assert_eq!(out[0].reexport_ordinal, None);
    assert_eq!(out[0].imported_name, b"_foo");
}

#[test]
fn shared_prefix_names_accumulate() {
    // Root → "_a" → { "bc" (weak terminal), "x" (regular terminal) }.
    let root = N {
        terminal: None,
        children: vec![(
            b"_a".to_vec(),
            N {
                terminal: None,
                children: vec![
                    (
                        b"bc".to_vec(),
                        N {
                            terminal: Some(regular(1, 0x20)),
                            children: vec![],
                        },
                    ),
                    (
                        b"x".to_vec(),
                        N {
                            terminal: Some(regular(0, 0x10)),
                            children: vec![],
                        },
                    ),
                ],
            },
        )],
    };
    let out = walk(&build(&root)).unwrap();
    let names: Vec<Vec<u8>> = out.iter().map(|e| e.name.clone()).collect();
    assert_eq!(names, vec![b"_abc".to_vec(), b"_ax".to_vec()]);
    assert_eq!(out[0].flags, 1, "weak flag recorded");
    assert_eq!(out[0].address, Some(0x20));
    assert_eq!(out[1].address, Some(0x10));
}

#[test]
fn reexport_node_carries_ordinal_and_imported_name() {
    let root = N {
        terminal: None,
        children: vec![(
            b"_exp".to_vec(),
            N {
                terminal: Some([uleb(0x08), uleb(2), b"_orig".to_vec(), vec![0]].concat()),
                children: vec![],
            },
        )],
    };
    let out = walk(&build(&root)).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].name, b"_exp");
    assert_eq!(out[0].reexport_ordinal, Some(2));
    assert_eq!(out[0].imported_name, b"_orig");
    assert_eq!(out[0].address, None, "re-exports carry no address");
}

#[test]
fn reexport_without_imported_name_uses_the_export_name() {
    let root = N {
        terminal: None,
        children: vec![(
            b"_same".to_vec(),
            N {
                terminal: Some([uleb(0x08), uleb(3)].concat()),
                children: vec![],
            },
        )],
    };
    let out = walk(&build(&root)).unwrap();
    assert_eq!(out[0].imported_name, b"_same", "name defaults to itself");
}

#[test]
fn truncated_and_oversized_inputs_error_not_panic() {
    // Malformed shapes must error, never panic.
    let payloads: Vec<Vec<u8>> = vec![
        vec![0x80],                         // dangling ULEB continuation
        vec![0x01],                         // terminal size 1 but no info
        vec![0x00, 0x01],                   // prefix node, child count 1, no edge
        vec![0x00, 0x01, b'a', 0x00],       // edge without the offset ULEB
        vec![0x00, 0x01, b'a', 0x00, 0x7f], // child offset 127 out of bounds
        vec![0x02, 0x00],                   // terminal overruns the payload
    ];
    for p in &payloads {
        let _ = walk(p).unwrap_err();
    }
    // Fuzz-ish sweep: every truncation of a valid trie either parses or
    // errors — never panics.
    let valid = build(&N {
        terminal: None,
        children: vec![(
            b"_x".to_vec(),
            N {
                terminal: Some(regular(0, 0x400)),
                children: vec![],
            },
        )],
    });
    for k in 0..valid.len() {
        let _ = walk(&valid[..k]).unwrap_or_default();
    }
}

#[test]
fn node_offset_visited_twice_errors() {
    // Two edges pointing at the same node: aliased offsets are a cycle.
    let shared = || N {
        terminal: Some(regular(0, 1)),
        children: vec![],
    };
    let root = N {
        terminal: None,
        children: vec![(b"a".to_vec(), shared()), (b"b".to_vec(), shared())],
    };
    let bytes = build(&root);
    // Manually alias: repoint the second edge at the first child. The
    // children serialize back-to-back; find both offsets by walking edges.
    let first_child = child_offset_of(&bytes, 0, 0);
    let second_edge = second_edge_offset_byte(&bytes, 0);
    let mut patched = bytes.clone();
    let enc = uleb5(first_child as u64);
    patched[second_edge..second_edge + 5].copy_from_slice(&enc);
    assert!(walk(&patched).is_err(), "aliased child offsets are a cycle");
}

/// The payload offset of child `k` of the node at `at`.
fn child_offset_of(bytes: &[u8], at: usize, k: usize) -> usize {
    let mut i = at;
    let ts = bytes[i] as usize;
    i += 1 + ts + 1; // size uleb + terminal + child count
    for j in 0..=k {
        while bytes[i] != 0 {
            i += 1;
        }
        i += 1; // NUL
        if j == k {
            return decode_uleb5(bytes, i);
        }
        i += 5; // fixed-width fixture offset
    }
    unreachable!("child not found")
}

/// The byte position of the offset ULEB of the second edge of node `at`.
fn second_edge_offset_byte(bytes: &[u8], at: usize) -> usize {
    let mut i = at;
    let ts = bytes[i] as usize;
    i += 1 + ts + 1;
    while bytes[i] != 0 {
        i += 1;
    }
    i += 1 + 5;
    i
}

fn decode_uleb5(bytes: &[u8], at: usize) -> usize {
    let mut v = 0u64;
    for k in 0..5 {
        v |= u64::from(bytes[at + k] & 0x7f) << (7 * k);
    }
    v as usize
}

#[test]
fn load_command_classifier_knows_lc_reexport_dylib() {
    use pgr_format::LoadCommandKind;
    assert_eq!(
        LoadCommandKind::from_cmd(pgr_format::consts::LC_REEXPORT_DYLIB),
        LoadCommandKind::ReexportDylib
    );
    assert_ne!(
        LoadCommandKind::from_cmd(pgr_format::consts::LC_REEXPORT_DYLIB),
        LoadCommandKind::LoadDylib
    );
}
