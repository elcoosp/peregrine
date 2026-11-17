//! The load-provenance bench (M57): the S7 archive pull with the
//! `-why_load` record riding — a full pull (every member admitted by
//! the reference fixpoint) over a 16- and a 64-member archive, the
//! reference-driven lazy pull beside the `-all_load` eager family.
//!
//! The record is one entry per pulled member, built from data the pull
//! already had (the M54 convention: the pass re-derives nothing), so
//! the shape gate is the report's own size — exactly the pulled-member
//! count — and the honest expectation is parity across the decisions
//! (the decision is one enum variant per member).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape gate on the
//! dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::ids::FileId;
use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkArchive, LinkArchiveMember, Parallelism, link_from_objects};
use pgr_core::object::InputObject;

/// Members in the bench archive (16 and 64).
const SIZES: [usize; 2] = [16, 64];

/// One archive member: defines `_m{i}` over a small `__text`.
fn member(i: usize) -> Vec<u8> {
    use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
    let mut b = ObjectBuilder::new(&format!("m{i:03}.o"));
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: format!("_m{i}"),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the bench member builds")
}

/// The `main.o` referencing every member's export through one data
/// pointer each (the full-pull corpus — every ranlib entry reached).
fn main_object(members: usize) -> Vec<u8> {
    use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
    let mut b = ObjectBuilder::new("main.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let mut targets = Vec::new();
    for i in 0..members {
        let idx = b.add_symbol(ObjectSymbol::Undefined {
            name: format!("_m{i}"),
            weak_ref: false,
        });
        targets.push(idx as u32);
    }
    b.add_section(ObjectSection::data(
        "__data",
        vec![0u8; members * 8],
        targets
            .iter()
            .enumerate()
            .map(|(r, sym)| ObjectReloc::unsigned(*sym).at((r * 8) as u32))
            .collect(),
    ));
    b.build().expect("the bench object builds")
}

/// The archive: `members` members back to back, the ranlib index naming
/// each definition.
fn archive(members: usize) -> LinkArchive {
    let mut bytes = Vec::new();
    let mut index = Vec::new();
    let mut spans = Vec::new();
    for i in 0..members {
        let off = bytes.len() as u64;
        let obj = member(i);
        let size = obj.len() as u64;
        index.push((format!("_m{i}").into_bytes(), i as u32));
        bytes.extend_from_slice(&obj);
        spans.push((off, size));
    }
    LinkArchive {
        name: "libbench.a".into(),
        index,
        members: spans
            .into_iter()
            .enumerate()
            .map(|(i, (off, size))| LinkArchiveMember {
                name: format!("m{i:03}.o"),
                offset: off,
                size,
            })
            .collect(),
        bytes,
        all_load: false,
    }
}

/// The parsed `main.o` for a member count.
fn arena(members: usize) -> Vec<InputObject> {
    vec![
        InputObject::parse(FileId(0), "main.o", main_object(members))
            .expect("the bench object parses"),
    ]
}

fn bench_why_load(c: &mut Criterion) {
    let mut group = c.benchmark_group("why_load");
    for members in SIZES {
        // The shape gate, asserted once outside the timed loop: the
        // report carries exactly the pulled members (the full pull).
        let result = link_from_objects(
            arena(members),
            &[archive(members)],
            &LinkConfig {
                filetype: OutputType::Execute,
                ..LinkConfig::default()
            },
            Parallelism::Serial,
            None,
        )
        .expect("the bench corpus links");
        assert_eq!(
            result.loads.members.len(),
            members,
            "one report row per pulled member"
        );
        assert!(
            result.loads.members.iter().all(|m| matches!(
                m.decision,
                pgr_core::provenance::LoadDecision::Reference { .. }
            )),
            "the reference-driven pull names its seeds"
        );

        group.throughput(Throughput::Elements(members as u64));
        group.bench_with_input(
            BenchmarkId::new("pull", members),
            &members,
            |b, &members| {
                b.iter(|| {
                    let result = link_from_objects(
                        arena(members),
                        &[archive(members)],
                        &LinkConfig {
                            filetype: OutputType::Execute,
                            ..LinkConfig::default()
                        },
                        Parallelism::Serial,
                        None,
                    )
                    .expect("the bench corpus links");
                    black_box(result.loads.members.len());
                });
            },
        );
        group.bench_with_input(BenchmarkId::new("render", members), &members, |b, _| {
            b.iter(|| {
                black_box(result.loads.render().len());
                black_box(result.loads.render_json().len());
            });
        });
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_why_load(&mut criterion);
    criterion.final_summary();
}
