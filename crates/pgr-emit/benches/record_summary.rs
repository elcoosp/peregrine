//! The M13 record-inspector bench: the read surface's cost beside the
//! write side it mirrors, over one real recorded link (the M9 bench
//! corpus shape: two objects, cross-references, a signed image).
//!
//! The point is the *shape* of the seam, not a claim about absolute
//! costs: the inspector must stay cheap against the link it summarizes
//! — a build system asks it between relinks, so it pays for itself only
//! while reading a record costs far less than making one. The bench
//! pins that honesty: `record_and_encode` (the write side) beside
//! `read_record` (the frame + decode) and `of_render` (the summary).
//! Numbers live in docs/BENCHMARKS.md (M13 section).

use criterion::{Criterion, Throughput};
use pgr_core::InputObject;
use pgr_core::layout::{Layout, LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link_cached};
use pgr_emit::build_image_fused;
use pgr_emit::incremental::{LinkRecord, RecordSummary, read_record_bytes};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// One object: a text blob, a data blob, defined symbols and
/// cross-object references (the emit bench's corpus shape, scaled down).
fn object(seed: usize, symbols: usize) -> ObjectBuilder {
    let text = vec![0x2Au8; 2048];
    let mut b = ObjectBuilder::new(&format!("bench_{seed}.o"));
    let text_idx = b.add_section(ObjectSection::text("__text", text, Vec::new()));
    let data_idx = b.add_section(ObjectSection::data(
        "__data",
        vec![0u8; symbols * 8],
        Vec::new(),
    ));
    for i in 0..symbols {
        b.add_symbol(ObjectSymbol::Defined {
            name: format!("_fn_{seed}_{i}"),
            section_index: text_idx,
            value: (i * 8 % 2048) as u64,
            weak: false,
        });
    }
    let ref_seed = if seed == 0 { 0 } else { seed - 1 };
    for i in 0..symbols {
        let r = b.add_symbol(ObjectSymbol::Undefined {
            name: format!("_fn_{ref_seed}_{i}"),
            weak_ref: false,
        });
        let t = b.sym_index(r);
        b.section_mut(data_idx)
            .relocs
            .push(ObjectReloc::unsigned(t).at((i * 8) as u32));
    }
    if seed == 0 {
        b.add_symbol(ObjectSymbol::Defined {
            name: "_main".into(),
            section_index: text_idx,
            value: 0,
            weak: false,
        });
    }
    b
}

/// Links the corpus once and returns everything the record path needs.
fn recorded_link() -> (LinkRecord, Layout, Vec<InputObject>, Vec<u8>) {
    let cfg = LinkConfig {
        ident: "record-summary-bench".into(),
        filetype: OutputType::Execute,
        ..LinkConfig::default()
    };
    let inputs: Vec<LinkInput> = [object(0, 64), object(1, 64)]
        .iter()
        .enumerate()
        .map(|(i, b)| LinkInput {
            name: format!("bench_{i}.o"),
            bytes: b.build().expect("the fixture builds"),
        })
        .collect();
    let result =
        link_cached(&inputs, &[], &cfg, Parallelism::Auto, None).expect("the corpus links clean");
    let image = build_image_fused(&result.layout, &result.objects).expect("the image emits");
    let record = LinkRecord::record(&result.layout, &result.objects, &image, None)
        .expect("the image records");
    (record, result.layout, result.objects, image)
}

fn bench_record_summary(c: &mut Criterion) {
    let (record, layout, objects, image) = recorded_link();
    let encoded = record.encode();
    let span_bytes: u64 = record.spans.runs.iter().map(|s| s.len).sum::<u64>()
        + record.spans.synths.iter().map(|s| s.len).sum::<u64>()
        + record.spans.blobs.iter().map(|s| s.len).sum::<u64>();

    let mut group = c.benchmark_group("record_summary");
    group.throughput(Throughput::Bytes(span_bytes.max(1)));
    group.bench_function("record_and_encode", |b| {
        b.iter(|| {
            LinkRecord::record(&layout, &objects, &image, None)
                .expect("the image records")
                .encode()
        });
    });
    group.bench_function("read_record", |b| {
        b.iter(|| read_record_bytes(&encoded).expect("the frame reads"));
    });
    group.bench_function("of_render", |b| {
        b.iter(|| RecordSummary::of(&record).render());
    });
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_record_summary(&mut criterion);
    criterion.final_summary();
}
