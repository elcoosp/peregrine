//! The link-map bench (M11 rung 2): the same corpus's plan rendered to
//! the structured map and to text. The builder walks the plan's own
//! tables (segments, sections, the emission-order symtab) and sorts each
//! section's rows once — the cost rides the symbol count, not the byte
//! count. The M55 rung adds the JSON interchange's cost beside it: the
//! compact render (the writer's escape rules, one line) and the strict
//! reader's round trip (parse back to the structured map), the same
//! shape the report-JSON pair rides.
//!
//! Baseline note (docs/BENCHMARKS.md): recorded honestly as a
//! shape-parity gate on the dev sandbox — the map is a reporting seam,
//! so the gate pins "reporting never regresses into the link's hot
//! path" rather than a win.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link};
use pgr_core::map::build_link_map;

/// One subsection-split object: `n` functions of one ret each.
fn object(name: &str, stem: &str, n: usize) -> Vec<u8> {
    use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
    let mut b = ObjectBuilder::new(name).set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(n),
        vec![],
    ));
    b.add_section(ObjectSection::data("__data", vec![0u8; 16], vec![]));
    for i in 0..n {
        b.add_symbol(ObjectSymbol::Defined {
            name: format!("_{stem}_f{i:03}"),
            section_index: text,
            value: (i * 4) as u64,
            weak: false,
        });
    }
    b.build().expect("the bench object builds")
}

const OBJECTS: usize = 12;
const FNS: usize = 256;

fn bench_map(c: &mut Criterion) {
    let mut group = c.benchmark_group("link_map");
    let inputs: Vec<LinkInput> = (0..OBJECTS)
        .map(|o| {
            let name = format!("obj{o:02}.o");
            let stem = format!("obj{o:02}");
            LinkInput {
                name: name.clone(),
                bytes: object(&name, &stem, FNS),
            }
        })
        .collect();
    group.throughput(Throughput::Elements((OBJECTS * FNS) as u64));
    group.bench_with_input(
        BenchmarkId::new("build_render", OBJECTS * FNS),
        &inputs,
        |b, inputs| {
            let cfg = LinkConfig {
                entry_symbol: "_obj00_f000".into(),
                ..LinkConfig::default()
            };
            b.iter(|| {
                let result = link(black_box(inputs), &[], &cfg).expect("the corpus links");
                let map = build_link_map(&result.layout, &result.interner);
                black_box(map.render().len());
            });
        },
    );
    group.finish();
}

/// The M55 JSON-interchange cost over the same corpus: the compact write
/// (render) and the strict reader's round trip (write + parse), each
/// beside the text render's group above. The interchange is a reporting
/// seam too — the gate pins its cost to the symbol count it renders.
fn bench_map_json(c: &mut Criterion) {
    let mut group = c.benchmark_group("link_map_json");
    let inputs: Vec<LinkInput> = (0..OBJECTS)
        .map(|o| {
            let name = format!("obj{o:02}.o");
            let stem = format!("obj{o:02}");
            LinkInput {
                name: name.clone(),
                bytes: object(&name, &stem, FNS),
            }
        })
        .collect();
    group.throughput(Throughput::Elements((OBJECTS * FNS) as u64));
    for name in ["write", "write_read"] {
        group.bench_with_input(
            BenchmarkId::new(name.to_string(), OBJECTS * FNS),
            &name,
            |b, name| {
                b.iter(|| {
                    let result = link(black_box(&inputs), &[], &cfg()).expect("the corpus links");
                    let map = build_link_map(&result.layout, &result.interner);
                    let json = map.render_json();
                    if *name == "write_read" {
                        let parsed =
                            pgr_core::map::parse_link_map_json(&json).expect("the map parses");
                        black_box(parsed.segments.len());
                    } else {
                        black_box(json.len());
                    }
                });
            },
        );
    }
    group.finish();
}

/// The shared link config (entry `_obj00_f000`, the corpus's first symbol).
fn cfg() -> LinkConfig {
    LinkConfig {
        entry_symbol: "_obj00_f000".into(),
        ..LinkConfig::default()
    }
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_map(&mut criterion);
    bench_map_json(&mut criterion);
    criterion.final_summary();
}
