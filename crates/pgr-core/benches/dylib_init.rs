//! The dylib-initializer bench (M48): the link cost across the
//! `-init <symbol>` decision — the no-command default beside the named
//! initializer over the same dylib corpus (64 objects, one exported
//! body each, the first object defining the `_my_init` symbol). The
//! decision rides the identity block — one 72-byte command and one
//! interner lookup — so the honest expectation is parity-or-under for
//! the default (the shape-parity gate) and a fixed 72-byte header delta
//! when the command rides (the header block grows, nothing else moves).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox, like the knob-parity benches before it.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

const OBJECTS: usize = 64;

/// One object: a `ret` body and one exported symbol; object 0 carries
/// `_main`-shaped `_my_init` and `_api`. No cross-object binds — the
/// corpus measures the identity-block decision, not the bind walk.
fn object(i: usize) -> Vec<u8> {
    let mut b = ObjectBuilder::new(&format!("obj{i:02}.o"));
    let sect = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6], // ret
        Vec::new(),
    ));
    if i == 0 {
        b.add_symbol(ObjectSymbol::Defined {
            name: "_my_init".into(),
            section_index: sect,
            value: 0,
            weak: false,
        });
        b.add_symbol(ObjectSymbol::Defined {
            name: "_api".into(),
            section_index: sect,
            value: 0,
            weak: false,
        });
    }
    b.add_symbol(ObjectSymbol::Defined {
        name: format!("_fn_{i:02}"),
        section_index: sect,
        value: 0,
        weak: false,
    });
    b.build().expect("the bench object builds")
}

fn link_with(init: Option<&str>) -> (usize, usize) {
    let cfg = LinkConfig {
        filetype: OutputType::Dylib,
        install_name: Some("@rpath/libbench.dylib".into()),
        init_symbol: init.map(String::from),
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
    // (file size, header block size). The command rides inside the
    // reserved header region, so the file size is unchanged — the
    // header block (32 + sizeofcmds) is where the 72 bytes land.
    (layout.file_size as usize, layout.header_bytes.len())
}

fn bench_dylib_init(c: &mut Criterion) {
    // The smoke gate first: the named command is exactly the 72-byte
    // header-block delta (the file size holds — the region's alignment
    // slack absorbs the command; the bench would otherwise measure a
    // moving shape).
    let (named_size, named_header) = link_with(Some("_my_init"));
    let (plain_size, plain_header) = link_with(None);
    assert_eq!(named_size, plain_size, "the file size holds");
    assert_eq!(
        named_header - plain_header,
        72,
        "the LC_ROUTINES_64 delta is the fixed 72-byte header block"
    );
    let mut group = c.benchmark_group("dylib_init");
    group.throughput(Throughput::Elements(OBJECTS as u64));
    for (name, init) in [("no_init_default", None), ("init_named", Some("_my_init"))] {
        group.bench_with_input(
            BenchmarkId::new("link_64_objects", name),
            &init,
            |b, init| {
                b.iter(|| {
                    let (_size, header) = link_with(*init);
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
    bench_dylib_init(&mut criterion);
    criterion.final_summary();
}
