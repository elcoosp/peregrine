//! The ObjC-pull bench (M43): the link cost across the `-ObjC`
//! decision over an archive-heavy corpus — the reference-driven default
//! (the metadata members nothing references stay unparsed), the named
//! pull (the class/category members join in member file order, their
//! own undefineds continue the fixpoint) and `-all_load` over the same
//! corpus (every member parses) — the three points pin where the
//! decision sits: the pull costs one prefix walk over the ranlib table
//! every link already parses plus the members it admits, so the honest
//! expectation is a ladder (default ≤ pull ≤ `all_load`), never a
//! regression of the default shape. The same corpus shape the M21–M42
//! parity benches share.
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkArchive, LinkArchiveMember, LinkInput, link};
use pgr_fixtures::{ArchiveBuilder, ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

const OBJECTS: usize = 64;
const CLASS_MEMBERS: usize = 32;

/// `OBJECTS` direct objects: one `_main` candidate (only the first
/// carries it), one `__data` bind slot each against a name the archive
/// carries — the reference that seeds the pull.
fn corpus() -> Vec<LinkInput> {
    (0..OBJECTS)
        .map(|i| {
            let mut b = ObjectBuilder::new(&format!("obj_{i:03}.o"));
            let text = b.add_section(ObjectSection::text(
                "__text",
                [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
                vec![],
            ));
            b.add_symbol(ObjectSymbol::Defined {
                name: if i == 0 {
                    "_main".into()
                } else {
                    format!("_fn_{i:03}")
                },
                section_index: text,
                value: 0,
                weak: false,
            });
            let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
            let undef = b.add_symbol(ObjectSymbol::Undefined {
                name: "_used_000".into(),
                weak_ref: false,
            });
            let slot = b.sym_index(undef);
            b.section_mut(data)
                .relocs
                .push(ObjectReloc::unsigned(slot).at(0));
            LinkInput {
                name: format!("obj_{i:03}.o"),
                bytes: b.build().expect("the bench object builds"),
            }
        })
        .collect()
}

/// `libclasses.a`: half the members implement an Objective-C class
/// (`_OBJC_CLASS_$_Class_<i>` beside a referenced provider name), half
/// define plain externals — the ladder's middle point pulls the class
/// members only, the top parses everything.
fn archive() -> (Vec<u8>, LinkArchive) {
    let mut builder = ArchiveBuilder::new("libclasses.a");
    for i in 0..OBJECTS {
        if i < CLASS_MEMBERS {
            let mut b = ObjectBuilder::new(&format!("cls_{i:03}.o"));
            let text = b.add_section(ObjectSection::text(
                "__text",
                [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
                vec![],
            ));
            b.add_symbol(ObjectSymbol::Defined {
                name: format!("_OBJC_CLASS_$_Class_{i:03}"),
                section_index: text,
                value: 0,
                weak: false,
            });
            b.add_symbol(ObjectSymbol::Defined {
                name: if i == 0 {
                    "_used_000".into()
                } else {
                    format!("_cls_ref_{i:03}")
                },
                section_index: text,
                value: 8,
                weak: false,
            });
            builder.add_member(
                &format!("cls_{i:03}.o"),
                b.build().expect("the bench member builds"),
            );
        } else {
            let mut b = ObjectBuilder::new(&format!("plain_{i:03}.o"));
            let text = b.add_section(ObjectSection::text(
                "__text",
                [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
                vec![],
            ));
            b.add_symbol(ObjectSymbol::Defined {
                name: format!("_plain_{i:03}"),
                section_index: text,
                value: 0,
                weak: false,
            });
            builder.add_member(
                &format!("plain_{i:03}.o"),
                b.build().expect("the bench member builds"),
            );
        }
    }
    let bytes = builder.build();
    let parsed = pgr_format::parse_archive(&bytes).expect("the bench archive parses");
    let arch = LinkArchive {
        name: "libclasses.a".into(),
        index: parsed
            .index
            .iter()
            .map(|e| (e.name.clone().into_bytes(), e.member))
            .collect(),
        members: parsed
            .members
            .iter()
            .map(|m| LinkArchiveMember {
                name: m.name.clone(),
                offset: m.offset,
                size: m.size,
            })
            .collect(),
        bytes: bytes.clone(),
        all_load: false,
    };
    (bytes, arch)
}

fn bench_objc(c: &mut Criterion) {
    let inputs = corpus();
    let (_bytes, mut arch) = archive();
    let mut group = c.benchmark_group("objc");
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for (name, objc, all_load) in [
        ("reference_driven", false, false),
        ("objc_pull", true, false),
        ("all_load", false, true),
    ] {
        arch.all_load = all_load;
        let archives = vec![arch.clone()];
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &(objc, archives),
            |b, &(objc, ref archives)| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        filetype: OutputType::Execute,
                        objc,
                        ..LinkConfig::default()
                    };
                    let result =
                        link(black_box(&inputs), archives, &cfg).expect("the corpus links");
                    black_box(&result.layout);
                });
            },
        );
    }
    group.finish();
}

fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_objc(&mut criterion);
    criterion.final_summary();
}
