//! The executable-override bench (M120): the link cost across the
//! `-executable` decision — the default `Execute` filetype carries the
//! executable shape (`__PAGEZERO`, `LC_MAIN`, no `LC_ID_DYLIB`), and the
//! explicit `-executable` override forces `OutputType::Execute` (the same
//! shape, every pre-knob link byte-identical). The smoke gates pin the
//! contract: the override carries `MH_EXECUTE`, `__PAGEZERO` first,
//! `LC_MAIN` and no `LC_ID_DYLIB`, and the default and the override link
//! byte-identical (the decision never moves the bytes).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox, like the knob-parity benches before it.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::consts::MH_EXECUTE;
use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64};

const OBJECTS: usize = 32;

/// `OBJECTS` objects: `_main` in the first; each carries one defined
/// `_fn_N` — the executable corpus the `LC_MAIN` entry names.
fn corpus() -> Vec<LinkInput> {
    (0..OBJECTS)
        .map(|i| {
            let mut b = ObjectBuilder::new(&format!("ex_{i:03}.o"));
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
            LinkInput {
                name: format!("ex_{i:03}.o"),
                bytes: b.build().expect("the bench object builds"),
            }
        })
        .collect()
}

/// The executable contract the layout carries: `MH_EXECUTE`, `__PAGEZERO`
/// first, `LC_MAIN` present, no `LC_ID_DYLIB`.
fn exec_shape(layout: &pgr_core::Layout) -> (u32, bool, bool, bool) {
    let bytes = &layout.header_bytes;
    let hdr = MachHeader64::parse(bytes).expect("the header parses");
    let mut it = LoadCommandIter::new(bytes, MachHeader64::SIZE, hdr.ncmds, hdr.sizeofcmds)
        .expect("the load-command iter builds");
    let mut pagezero_first = false;
    let mut has_main = false;
    let mut has_id_dylib = false;
    let mut first_segment = true;
    while let Ok(Some(cmd)) = it.next_command() {
        match cmd.kind {
            LoadCommandKind::Segment64 => {
                if first_segment {
                    let name = cmd
                        .bytes
                        .get(8..24)
                        .map(|b| {
                            String::from_utf8_lossy(b)
                                .trim_end_matches('\0')
                                .to_string()
                        })
                        .unwrap_or_default();
                    pagezero_first = name == "__PAGEZERO";
                    first_segment = false;
                }
            }
            LoadCommandKind::Main => has_main = true,
            LoadCommandKind::IdDylib => has_id_dylib = true,
            _ => {}
        }
    }
    (hdr.filetype, pagezero_first, has_main, has_id_dylib)
}

fn bench_executable(c: &mut Criterion) {
    // The smoke gates first: the default and the override both carry the
    // executable contract (MH_EXECUTE, __PAGEZERO first, LC_MAIN, no
    // LC_ID_DYLIB) and link byte-identical (the decision never moves the
    // bytes — the override forces Execute, which is the default).
    let inputs = corpus();
    let plan_for = |inputs: &[LinkInput], executable: bool| {
        link(
            inputs,
            &[],
            &LinkConfig {
                filetype: OutputType::Execute,
                executable,
                ..LinkConfig::default()
            },
        )
        .expect("the corpus links")
        .layout
    };
    let default = plan_for(&inputs, false);
    let explicit = plan_for(&inputs, true);
    let (ft, pz, main, id) = exec_shape(&explicit);
    assert_eq!(ft, MH_EXECUTE, "the override carries MH_EXECUTE");
    assert!(pz, "the override carries __PAGEZERO first");
    assert!(main, "the override carries LC_MAIN");
    assert!(
        !id,
        "the override carries no LC_ID_DYLIB (an executable's identity is LC_MAIN)"
    );
    assert_eq!(
        default.header_bytes, explicit.header_bytes,
        "the default and the override link byte-identical"
    );

    let mut group = c.benchmark_group("executable");
    group.throughput(Throughput::Elements(OBJECTS as u64));
    let decisions = [("default", false), ("executable", true)];
    for (name, executable) in decisions {
        group.bench_with_input(
            BenchmarkId::new("link_32_objects", name),
            &executable,
            |b, &executable| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        filetype: OutputType::Execute,
                        executable,
                        ..LinkConfig::default()
                    };
                    let result = link(black_box(&inputs), &[], &cfg).expect("the corpus links");
                    black_box(result.layout.header_bytes.len());
                });
            },
        );
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_executable(&mut criterion);
    criterion.final_summary();
}
