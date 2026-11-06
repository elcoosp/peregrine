//! Export-trie build benchmark (M3 perf gate, roadmap §10.3 M3 row):
//! "Export trie build < 10 ms for 10⁵ exports (or parallelized if not)".
//!
//! Two implementations are measured:
//!
//! * `legacy` — the M2 insert-with-splitting builder (single-character
//!   edges, per-insert child-vector clones), kept verbatim as the baseline
//!   the M3 rewrite had to beat;
//! * `pgr_core::trie::build` — the M3 range-partition builder (compressed
//!   edges, flat arenas).
//!
//! The corpus mirrors real export surfaces: linker-visible C symbols plus
//! an ObjC-style heavy-shared-prefix block (the worst case for tries).

use criterion::{BenchmarkId, Criterion, Throughput};

/// One export entry for either builder.
struct Case {
    name: Vec<u8>,
    address: u64,
}

/// Deterministic export corpus: `_pgr_fn_<set>_<i>` plus an ObjC-ish block.
fn corpus(n: usize) -> Vec<Case> {
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        if i % 4 == 0 {
            out.push(Case {
                name: format!("_OBJC_CLASS_$_Peregrine{i:06}").into_bytes(),
                address: (i * 8) as u64,
            });
        } else {
            out.push(Case {
                name: format!("_pgr_fn_{:06}_body", i).into_bytes(),
                address: (i * 8) as u64,
            });
        }
    }
    out
}

fn to_exports(cases: &[Case]) -> Vec<pgr_core::trie::Export<'_>> {
    cases
        .iter()
        .map(|c| pgr_core::trie::Export {
            name: &c.name,
            info: pgr_core::trie::ExportInfo::Regular {
                flags: 0,
                address: c.address,
            },
        })
        .collect()
}

fn to_syms(cases: &[Case]) -> Vec<(Vec<u8>, u64)> {
    cases.iter().map(|c| (c.name.clone(), c.address)).collect()
}

// ---------------------------------------------------------------------------
// The M2 baseline builder, copied verbatim from `layout.rs` before the M3
// rewrite (it built from `[OutputSymbol]`; the bench adapter feeds it
// `(name, absolute address)` pairs and the image base).
// ---------------------------------------------------------------------------

fn legacy_build(symbols: &[(Vec<u8>, u64)], image_base: u64) -> Vec<u8> {
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
    #[derive(Debug)]
    struct Node {
        export: Option<(u32, u64)>,
        children: Vec<(Vec<u8>, usize)>,
    }
    let mut nodes: Vec<Node> = vec![Node {
        export: None,
        children: Vec::new(),
    }];

    let mut exports: Vec<&(Vec<u8>, u64)> = symbols.iter().collect();
    exports.sort_by(|a, b| a.0.cmp(&b.0));
    exports.dedup_by(|a, b| a.0 == b.0);

    for (name, value) in exports {
        let address = value.wrapping_sub(image_base);
        let flags = 0u32;
        let mut cur = 0usize;
        let mut rest = &name[..];
        'insert: while !rest.is_empty() {
            let mut advanced = false;
            for (sub, child) in nodes[cur].children.clone() {
                let common = sub
                    .iter()
                    .zip(rest.iter())
                    .position(|(a, b)| a != b)
                    .unwrap_or(sub.len().min(rest.len()));
                if common > 0 {
                    if common < sub.len() {
                        let tail = sub[common..].to_vec();
                        let intermediate = Node {
                            export: None,
                            children: vec![(tail, child)],
                        };
                        let inter_idx = nodes.len();
                        nodes.push(intermediate);
                        nodes[cur].children.retain(|(s, _)| s != &sub);
                        nodes[cur]
                            .children
                            .push((sub[..common].to_vec(), inter_idx));
                        nodes[cur].children.sort_by(|a, b| a.0.cmp(&b.0));
                        cur = inter_idx;
                    } else {
                        cur = child;
                    }
                    rest = &rest[common..];
                    advanced = true;
                    break;
                }
            }
            if advanced {
                continue 'insert;
            }
            let child_idx = nodes.len();
            nodes.push(Node {
                export: None,
                children: Vec::new(),
            });
            nodes[cur].children.push((rest[..1].to_vec(), child_idx));
            nodes[cur].children.sort_by(|a, b| a.0.cmp(&b.0));
            cur = child_idx;
            rest = &rest[1..];
        }
        nodes[cur].export = Some((flags, address));
    }

    #[derive(Clone, Default)]
    struct Offsets {
        offset: Vec<usize>,
        total: usize,
    }
    let mut off = Offsets {
        offset: vec![0usize; nodes.len()],
        total: 0,
    };
    let mut pass = 0usize;
    loop {
        let terminal: Vec<usize> = nodes
            .iter()
            .map(|n| match n.export {
                None => 0,
                Some((flags, address)) => uleb(u64::from(flags)).len() + uleb(address).len(),
            })
            .collect();
        let mut next = 0usize;
        for i in 0..nodes.len() {
            off.offset[i] = next;
            let node_size = terminal[i]
                + if terminal[i] == 0 {
                    1
                } else {
                    uleb(terminal[i] as u64).len()
                }
                + 1
                + nodes[i]
                    .children
                    .iter()
                    .map(|(sub, child)| sub.len() + 1 + uleb(off.offset[*child] as u64).len())
                    .sum::<usize>();
            next += node_size;
        }
        if off.total == next || pass > 8 {
            off.total = next;
            break;
        }
        off.total = next;
        pass += 1;
    }

    let terminal: Vec<usize> = nodes
        .iter()
        .map(|n| match n.export {
            None => 0,
            Some((flags, address)) => uleb(u64::from(flags)).len() + uleb(address).len(),
        })
        .collect();
    let mut out = vec![0u8; off.total];
    for (i, n) in nodes.iter().enumerate() {
        let mut w = off.offset[i];
        if terminal[i] > 0 {
            let t = uleb(terminal[i] as u64);
            out[w..w + t.len()].copy_from_slice(&t);
            w += t.len();
            let (flags, address) = n.export.expect("terminal size implies export");
            let fb = uleb(u64::from(flags));
            out[w..w + fb.len()].copy_from_slice(&fb);
            w += fb.len();
            let ab = uleb(address);
            out[w..w + ab.len()].copy_from_slice(&ab);
            w += ab.len();
        } else {
            out[w] = 0;
            w += 1;
        }
        out[w] = n.children.len() as u8;
        w += 1;
        for (sub, child) in &n.children {
            out[w..w + sub.len()].copy_from_slice(sub);
            w += sub.len();
            out[w] = 0;
            w += 1;
            let ob = uleb(off.offset[*child] as u64);
            out[w..w + ob.len()].copy_from_slice(&ob);
            w += ob.len();
        }
    }
    out
}

/// Measures both builders over the 10³/10⁴/10⁵ export corpora.
fn bench_trie(c: &mut Criterion) {
    let mut group = c.benchmark_group("export_trie_build");
    const IMAGE_BASE: u64 = 0; // dylib convention (M3); exec adds 4 GiB of zeroes
    for n in [1_000usize, 10_000, 100_000] {
        let cases = corpus(n);
        let bytes: u64 = cases.iter().map(|c| c.name.len() as u64).sum();
        group.throughput(Throughput::Bytes(bytes));
        let syms = to_syms(&cases);
        group.bench_with_input(BenchmarkId::new("legacy_m2", n), &syms, |b, s| {
            b.iter(|| legacy_build(s, IMAGE_BASE));
        });
        let exports = to_exports(&cases);
        group.bench_with_input(BenchmarkId::new("m3_partition", n), &exports, |b, e| {
            // Every iteration restores the caller-side order, so each run
            // measures sort + build from the same input state.
            b.iter(|| {
                let mut input = e.clone();
                pgr_core::trie::build(&mut input, IMAGE_BASE)
            });
        });
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_trie(&mut criterion);
    criterion.final_summary();
}
