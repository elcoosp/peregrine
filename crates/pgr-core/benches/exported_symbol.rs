//! The singular-export-filter bench (M100): the link cost across the
//! composed filter table — the no-filter default beside a composed
//! only-list and a composed hide-list (64 exact entries each, the shape
//! the `-exported_symbol`/`-unexported_symbol` flags and the list files
//! compose into) over the same 64-object corpus. The composed table
//! feeds the unchanged M14 seam — the visibility closure pays one
//! matcher walk per planned export name — so the honest expectation is
//! parity-or-under for the gated variants (fewer trie entries to
//! encode, the same symtab walk).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox, like the knob-parity benches before it.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::export_filter::SymbolPattern;
use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

const OBJECTS: usize = 64;
const FNS_PER_OBJECT: usize = 4;
const REBASES_PER_OBJECT: usize = 4;

/// The corpus: 64 objects, 4 exported bodies each (256 names), one
/// `__data` rebase table per object so the fixup planner, the symtab
/// and the trie all ride the plan the filter gates.
fn object(i: usize) -> Vec<u8> {
    let mut b = ObjectBuilder::new(&format!("obj{i:02}.o"));
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(FNS_PER_OBJECT),
        Vec::new(),
    ));
    let first_fn = b.add_symbol(ObjectSymbol::Defined {
        name: format!("_fn_{i:02}_0"),
        section_index: text,
        value: 0,
        weak: false,
    });
    for f in 1..FNS_PER_OBJECT {
        b.add_symbol(ObjectSymbol::Defined {
            name: format!("_fn_{i:02}_{f}"),
            section_index: text,
            value: (f * 4) as u64,
            weak: false,
        });
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
    b.build().expect("the bench object builds")
}

/// The corpus's own name list, in emission order (the filter entries
/// the flags compose: every fourth body, 64 entries).
fn filter_names() -> Vec<Vec<u8>> {
    (0..OBJECTS)
        .filter(|i| i % 2 == 0)
        .flat_map(|i| (0..2).map(move |f| format!("_fn_{i:02}_{f}").into_bytes()))
        .collect()
}

fn inputs() -> Vec<LinkInput> {
    (0..OBJECTS)
        .map(|i| LinkInput {
            name: format!("obj{i:02}.o"),
            bytes: object(i),
        })
        .collect()
}

fn link_with(only: Option<&[Vec<u8>]>, hide: &[Vec<u8>]) -> usize {
    let cfg = LinkConfig {
        filetype: OutputType::Dylib,
        install_name: Some("@rpath/libbench.dylib".into()),
        exported_only: only.map(|names| {
            names
                .iter()
                .map(|n| SymbolPattern::parse(n).expect("the bench entry parses"))
                .collect()
        }),
        unexported: hide
            .iter()
            .map(|n| SymbolPattern::parse(n).expect("the bench entry parses"))
            .collect(),
        ..LinkConfig::default()
    };
    let corpus = inputs();
    link(black_box(&corpus), &[], &cfg)
        .expect("the corpus links")
        .layout
        .file_size as usize
}

fn bench_exported_symbol(c: &mut Criterion) {
    let names = filter_names();
    // The smoke gates: the composed table gates exactly the names it
    // selects (the only-list halves the trie's terminal count; the
    // hide-list keeps the symtab rows and shrinks the trie) — the bench
    // would otherwise measure a moving shape.
    let plain = link_with(None, &[]);
    let only = link_with(Some(&names), &[]);
    let hide = link_with(None, &names);
    assert_ne!(plain, only, "the only-list reshapes the export surface");
    assert_ne!(plain, hide, "the hide-list reshapes the export surface");
    let mut group = c.benchmark_group("exported_symbol");
    group.throughput(Throughput::Elements(OBJECTS as u64));
    let variants: [(&str, Option<&[Vec<u8>]>, &[Vec<u8>]); 3] = [
        ("no_filter_default", None, &[]),
        ("only_64_exact", Some(&names), &[]),
        ("hide_64_exact", None, &names),
    ];
    for (name, only, hide) in variants {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &(only, hide),
            |b, (only, hide)| {
                b.iter(|| {
                    let size = link_with(*only, hide);
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
    bench_exported_symbol(&mut criterion);
    criterion.final_summary();
}
