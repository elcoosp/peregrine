//! The GCC-era ObjC-pull bench (M49): the link cost across the `-ObjC`
//! decision over the M43 corpus shape with the metadata half split
//! into the two families — 16 modern class members
//! (`_OBJC_CLASS_$_Class_<i>`) and 16 GCC-era class members
//! (`.objc_class_name_Class_<i>`) beside 32 plain members. The widened
//! classifier walks the same ranlib table the default link already
//! parses (one prefix walk either way), so the honest expectation is
//! the M43 ladder unchanged: reference-driven ≤ pull ≤ `all_load`,
//! with the pull admitting both families (32 members, the same middle
//! point the M43 bench priced).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox, like the knob-parity benches before it.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkArchive, LinkArchiveMember, LinkInput, link};
use pgr_fixtures::{ArchiveBuilder, ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

const OBJECTS: usize = 64;
const METADATA_MEMBERS: usize = 32;
const MODERN_MEMBERS: usize = 16;

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

/// `libpre2.a`: the first `MODERN_MEMBERS` members implement a class
/// under the modern emitter's symbol (the M43 family), the next
/// `METADATA_MEMBERS - MODERN_MEMBERS` under the GCC-era C symbol (the
/// M49 family), and the rest define plain externals — the pull admits
/// both metadata families, the plain members stay reference-driven.
fn archive() -> (Vec<u8>, LinkArchive) {
    let mut builder = ArchiveBuilder::new("libpre2.a");
    for i in 0..OBJECTS {
        let mut b = ObjectBuilder::new(&format!("mbr_{i:03}.o"));
        let text = b.add_section(ObjectSection::text(
            "__text",
            [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
            vec![],
        ));
        let class_sym = if i < MODERN_MEMBERS {
            format!("_OBJC_CLASS_$_Class_{i:03}")
        } else if i < METADATA_MEMBERS {
            format!(".objc_class_name_Class_{i:03}")
        } else {
            format!("_plain_{i:03}")
        };
        b.add_symbol(ObjectSymbol::Defined {
            name: class_sym,
            section_index: text,
            value: 0,
            weak: false,
        });
        b.add_symbol(ObjectSymbol::Defined {
            name: if i == 0 {
                "_used_000".into()
            } else {
                format!("_mbr_ref_{i:03}")
            },
            section_index: text,
            value: 8,
            weak: false,
        });
        builder.add_member(
            &format!("mbr_{i:03}.o"),
            b.build().expect("the bench member builds"),
        );
    }
    let bytes = builder.build();
    let parsed = pgr_format::parse_archive(&bytes).expect("the bench archive parses");
    let arch = LinkArchive {
        name: "libpre2.a".into(),
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

/// Counts the image's defined externals — the smoke gate reads the
/// pulled members' symbols off the symtab (both families' class
/// symbols ride under the pull; nothing metadata-named rides under the
/// default).
fn defined_externals(result: &pgr_core::link::LinkResult) -> usize {
    result.layout.symbols.iter().filter(|s| s.external).count()
}

fn bench_objc_pre2(c: &mut Criterion) {
    let inputs = corpus();
    let (_bytes, mut arch) = archive();
    // The smoke gates: the pull admits exactly the two metadata
    // families (each member adds one class symbol beside its provider
    // row — the count moves by the family, never the scan), and the
    // default stays reference-driven.
    let mut pull = |objc: bool, all_load: bool| -> usize {
        arch.all_load = all_load;
        let cfg = LinkConfig {
            filetype: OutputType::Execute,
            ident: "bench".into(),
            objc,
            ..LinkConfig::default()
        };
        let result =
            link(black_box(&inputs), &[arch.clone()], &cfg).expect("the bench corpus links");
        defined_externals(&result)
    };
    let reference_driven = pull(false, false);
    let objc_pull = pull(true, false);
    // Member 0 defines the referenced `_used_000`, so its two rows ride
    // the reference-driven pull already; the other 31 metadata members
    // each add two externals (class symbol + provider row) under the
    // knob — the exact arithmetic pins both families' admission.
    assert_eq!(
        objc_pull - reference_driven,
        2 * (METADATA_MEMBERS - 1),
        "the pull admits exactly the remaining metadata members (both \
         families), two externals each"
    );
    let mut group = c.benchmark_group("objc_pre2");
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
                        ident: "bench".into(),
                        objc,
                        ..LinkConfig::default()
                    };
                    let result = link(black_box(&inputs), black_box(archives), &cfg)
                        .expect("the bench corpus links");
                    black_box(result.layout.file_size);
                });
            },
        );
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_objc_pre2(&mut criterion);
    criterion.final_summary();
}
