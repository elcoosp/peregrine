//! The dtrace DOF section processing bench (M118): the link cost across
//! the `-dtrace` decision — the default carries a `__dtrace_dof`
//! (`S_DTRACE_DOF`) section's bytes verbatim (every pre-knob link
//! byte-identical), the decision carries the section too (the
//! classification recognizes the payload, never drops it — the emit
//! validates the `DOF` header at emit), and a corpus without a
//! `__dtrace_dof` section links byte-identical under either face (the
//! decision never moves a byte it has nothing to validate). The smoke
//! gates also pin the distinct-from-debug contract: under `-S` the
//! dtrace payload rides (the debug strip never drops a payload the
//! decision recognized).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox, like the knob-parity benches before it.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::consts::S_DTRACE_DOF;
use pgr_format::dof::DOF_MAGIC;

const OBJECTS: usize = 32;

/// `OBJECTS` objects: `_main` in the first; each carries a
/// `__dtrace_dof` (`S_DTRACE_DOF`) section whose head carries the `DOF`
/// identification magic — the payload the decision recognizes and the
/// emit validates.
fn corpus() -> Vec<LinkInput> {
    (0..OBJECTS)
        .map(|i| {
            let mut b = ObjectBuilder::new(&format!("dtrace_{i:03}.o"));
            let text = b.add_section(ObjectSection::text(
                "__text",
                [0xC0u8, 0x03, 0x5F, 0xD6].repeat(if i == 0 { 4 } else { 2 }),
                vec![],
            ));
            b.add_symbol(ObjectSymbol::Defined {
                name: if i == 0 {
                    "_main".into()
                } else {
                    format!("_fn_{i}")
                },
                section_index: text,
                value: 0,
                weak: false,
            });
            // The DOF payload: 32 bytes, the identification magic at the
            // head (covers the DOF_ID_SIZE identification region).
            let mut dof = vec![0u8; 32];
            dof[..DOF_MAGIC.len()].copy_from_slice(&DOF_MAGIC);
            let dof_sect = b.add_section(ObjectSection::text("__dtrace_dof", dof, vec![]));
            b.section_mut(dof_sect).flags = S_DTRACE_DOF;
            LinkInput {
                name: format!("dtrace_{i:03}.o"),
                bytes: b.build().expect("the bench object builds"),
            }
        })
        .collect()
}

/// A plain corpus: no `__dtrace_dof` machinery at all (the byte-identity
/// lock's subject).
fn plain_corpus() -> Vec<LinkInput> {
    (0..OBJECTS)
        .map(|i| {
            let mut b = ObjectBuilder::new(&format!("plain_{i:03}.o"));
            let text = b.add_section(ObjectSection::text(
                "__text",
                [0xC0u8, 0x03, 0x5F, 0xD6].repeat(if i == 0 { 4 } else { 1 }),
                vec![],
            ));
            b.add_symbol(ObjectSymbol::Defined {
                name: if i == 0 {
                    "_main".into()
                } else {
                    format!("_fn_{i}")
                },
                section_index: text,
                value: 0,
                weak: false,
            });
            LinkInput {
                name: format!("plain_{i:03}.o"),
                bytes: b.build().expect("the bench object builds"),
            }
        })
        .collect()
}

fn bench_dtrace(c: &mut Criterion) {
    // The smoke gates first: the corpus carries its `__dtrace_dof`
    // section under the default and under the decision (the
    // classification recognizes the payload, never drops it); the
    // payload rides under `-S` too (distinct from the debug class); the
    // plain corpus links byte-identical under either face.
    let inputs = corpus();
    let plan_for = |inputs: &[LinkInput], dtrace: bool, strip_debug: bool| {
        link(
            inputs,
            &[],
            &LinkConfig {
                filetype: OutputType::Execute,
                dtrace,
                strip_debug,
                ..LinkConfig::default()
            },
        )
        .expect("the corpus links")
        .layout
    };
    let carried = plan_for(&inputs, false, false);
    let validated = plan_for(&inputs, true, false);
    let distinct = plan_for(&inputs, true, true);
    assert!(
        carried
            .sections
            .iter()
            .any(|s| s.name == "__dtrace_dof" && s.seg_name == "__TEXT"),
        "the default carries the __dtrace_dof section"
    );
    assert!(
        validated
            .sections
            .iter()
            .any(|s| s.name == "__dtrace_dof" && s.seg_name == "__TEXT"),
        "the decision carries the __dtrace_dof section (validated at emit)"
    );
    assert!(
        distinct
            .sections
            .iter()
            .any(|s| s.name == "__dtrace_dof" && s.seg_name == "__TEXT"),
        "the dtrace payload is distinct from the debug class (rides under -S)"
    );
    assert!(
        validated.dtrace,
        "the layout carries the dtrace decision (the echo the emit reads)"
    );
    let plain = plain_corpus();
    assert_eq!(
        plan_for(&plain, false, false).header_bytes,
        plan_for(&plain, true, false).header_bytes,
        "a corpus without a dtrace section links byte-identical under either face"
    );

    let mut group = c.benchmark_group("dtrace");
    group.throughput(Throughput::Elements(OBJECTS as u64));
    let decisions = [("carried_default", false), ("validated", true)];
    for (name, dtrace) in decisions {
        group.bench_with_input(
            BenchmarkId::new("link_32_objects", name),
            &dtrace,
            |b, &dtrace| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        filetype: OutputType::Execute,
                        dtrace,
                        ..LinkConfig::default()
                    };
                    let result = link(black_box(&inputs), &[], &cfg).expect("the corpus links");
                    black_box(result.layout.linkedit.uuid_at);
                });
            },
        );
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_dtrace(&mut criterion);
    criterion.final_summary();
}
