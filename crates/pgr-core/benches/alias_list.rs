//! The alias-list bench (M101): the link cost across the alias table
//! the `-alias_list` file form composes — the empty table (the pre-M101
//! default) and two composed tables (8 and 64 pairs) over the same
//! corpus (64 objects, 256 rebase slots). The file form's pairs ride
//! the SAME `AliasTable` seam the `-alias` flags always pushed (the
//! M24 bench pinned the flag form's shape) — this bench pins the
//! composed table's plan shape beside the default, the rung's own
//! "one body, two names" cost.
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox, like the knob-parity benches before it.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::alias::{Alias, AliasTable};
use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};

const OBJECTS: usize = 64;
const REBASES_PER_OBJECT: usize = 4;

/// `OBJECTS` small objects: one `_main`-candidate each (only the first
/// carries the entry), plus a `__data` rebase table so the fixup
/// planner, the trie and the symtab all ride the plan the composed
/// aliases land on.
fn corpus() -> Vec<LinkInput> {
    use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
    (0..OBJECTS)
        .map(|i| {
            let mut b = ObjectBuilder::new(&format!("obj_{i:03}.o"));
            let n_fns = if i == 0 { 2 } else { 4 };
            let text = b.add_section(ObjectSection::text(
                "__text",
                [0xC0u8, 0x03, 0x5F, 0xD6].repeat(n_fns),
                vec![],
            ));
            let mut first_fn = 0usize;
            for f in 0..n_fns {
                let idx = b.add_symbol(ObjectSymbol::Defined {
                    name: if i == 0 && f == 0 {
                        "_main".to_string()
                    } else {
                        format!("_fn_{i:03}_{f}")
                    },
                    section_index: text,
                    value: (f * 4) as u64,
                    weak: false,
                });
                if i == 0 && f == 0 {
                    first_fn = idx;
                }
            }
            let data = b.add_section(ObjectSection::data(
                "__data",
                vec![0u8; REBASES_PER_OBJECT * 8],
                vec![],
            ));
            let target = b.sym_index(first_fn);
            for r in 0..REBASES_PER_OBJECT {
                b.section_mut(data)
                    .relocs
                    .push(ObjectReloc::unsigned(target).at((r * 8) as u32));
            }
            LinkInput {
                name: format!("obj_{i:03}.o"),
                bytes: b.build().expect("the bench object builds"),
            }
        })
        .collect()
}

/// The composed table: `count` pairs pointing at distinct defined
/// bodies (the file form's rows — one alias per defined name, the
/// duplicate refusal the seam pays keeping every entry distinct).
fn composed(count: usize) -> AliasTable {
    let mut t = AliasTable::new();
    for i in 0..count {
        let obj = i / 2;
        let f = i % 2;
        let definition = if obj == 0 {
            if f == 0 { "_main" } else { "_fn_000_1" }
        } else {
            &format!("_fn_{obj:03}_{f}")
        };
        let alias = format!("_shim_{i:03}");
        t.push(Alias::from_parts(&alias, definition).expect("the bench pair validates"))
            .expect("the bench pairs are distinct");
    }
    t
}

fn link_with(aliases: &AliasTable) -> usize {
    let cfg = LinkConfig {
        filetype: OutputType::Dylib,
        install_name: Some("@rpath/libbench.dylib".into()),
        aliases: aliases.clone(),
        ..LinkConfig::default()
    };
    let inputs = corpus();
    link(black_box(&inputs), &[], &cfg)
        .expect("the corpus links")
        .layout
        .file_size as usize
}

fn bench_alias_list(c: &mut Criterion) {
    // The smoke gates: the composed table grows the file by its rows
    // (one symtab row + one trie terminal per pair, 16 bytes of strtab
    // per name) — the bench would otherwise measure a moving shape.
    let empty = AliasTable::new();
    let eight = composed(8);
    let sixty_four = composed(64);
    let plain = link_with(&empty);
    let eight_size = link_with(&eight);
    let large_size = link_with(&sixty_four);
    assert!(eight_size > plain, "the composed rows grow the image");
    assert!(large_size > eight_size, "more pairs, more rows");
    let mut group = c.benchmark_group("alias_list");
    group.throughput(Throughput::Elements(OBJECTS as u64));
    let variants: [(&str, &AliasTable); 3] = [
        ("no_aliases_default", &empty),
        ("composed_8", &eight),
        ("composed_64", &sixty_four),
    ];
    for (name, table) in variants {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            table,
            |b, table| {
                b.iter(|| {
                    let size = link_with(table);
                    black_box(size);
                });
            },
        );
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_alias_list(&mut criterion);
    criterion.final_summary();
}
