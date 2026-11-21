//! The weak-import-refusal bench (M50): the link cost across the
//! `-no_weak_imports` decision — the runtime-lookup fallthrough default
//! beside the named refusal over the same 64-object corpus whose every
//! weak reference resolves at link time (against the weak-loaded
//! dylib's export). A resolved weak bind is not a runtime lookup — the
//! knob never fires on it — so the honest expectation is parity and
//! byte-identical output (the smoke gate pins both): the decision
//! prices one weak-bit read per unresolved name in the walk's cold
//! lane, and the refusal lane itself is the tests' observable, not a
//! bench shape.
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox, like the knob-parity benches before it.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_core::resolve::Dylib;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

const OBJECTS: usize = 64;

/// One object: a `ret` body, one exported symbol and a `__data` bind
/// slot whose relocation references the weak `_maybe` name (the
/// `N_WEAK_REF` reference the decision reads — every object carries
/// one, so the walk's weak lane is the measured surface).
fn object(i: usize) -> Vec<u8> {
    let mut b = ObjectBuilder::new(&format!("obj{i:02}.o"));
    let sect = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6], // ret
        Vec::new(),
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: if i == 0 {
            "_main".into()
        } else {
            format!("_fn_{i:02}")
        },
        section_index: sect,
        value: 0,
        weak: false,
    });
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    let undef = b.add_symbol(ObjectSymbol::Undefined {
        name: "_maybe".into(),
        weak_ref: true,
    });
    let slot = b.sym_index(undef);
    b.section_mut(data)
        .relocs
        .push(ObjectReloc::unsigned(slot).at(0));
    b.build().expect("the bench object builds")
}

/// The weak-loaded dylib whose export resolves every `_maybe` reference
/// at link time (the bind carries weakness; dyld never looks it up).
fn weak_dylib() -> Dylib {
    Dylib {
        install_name: "@rpath/libw.dylib".into(),
        current_version: 0,
        compatibility_version: 0,
        exports: vec![b"_maybe".to_vec()],
        weak: true,
        reexport: false,
        needed: false,
        hidden: false,
        lazy: false,
        upward: false,
    }
}

fn link_with(no_weak_imports: bool) -> (usize, usize) {
    let cfg = LinkConfig {
        filetype: OutputType::Execute,
        no_weak_imports,
        dylibs: vec![weak_dylib()],
        ..LinkConfig::default()
    };
    let inputs: Vec<LinkInput> = (0..OBJECTS)
        .map(|i| LinkInput {
            name: format!("obj{i:02}.o"),
            bytes: object(i),
        })
        .collect();
    let layout = link(black_box(&inputs), &[], &cfg)
        .expect("the corpus links")
        .layout;
    (layout.file_size as usize, layout.header_bytes.len())
}

fn bench_no_weak_imports(c: &mut Criterion) {
    // The smoke gates: a resolved weak bind plans identical bytes under
    // both decisions (the knob prices the runtime lookup, not the
    // weakness — the image never changes).
    let (default_size, default_header) = link_with(false);
    let (named_size, named_header) = link_with(true);
    assert_eq!(default_size, named_size, "the file size holds");
    assert_eq!(
        default_header, named_header,
        "a resolved weak bind plans identical bytes under both decisions"
    );
    let mut group = c.benchmark_group("no_weak_imports");
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for (name, no_weak_imports) in [
        ("lookup_fallthrough_default", false),
        ("refusal_named", true),
    ] {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &no_weak_imports,
            |b, &no_weak_imports| {
                b.iter(|| {
                    let (_size, header) = link_with(no_weak_imports);
                    black_box(header);
                });
            },
        );
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_no_weak_imports(&mut criterion);
    criterion.final_summary();
}
