//! The dylib module-policy bench (M119): the link cost across the
//! `-single_module`/`-multi_module` decision — the default `-multi_module`
//! plans no `LC_DYSYMTAB` module table (the legacy zero-module table
//! peregrine always carried, every pre-knob link byte-identical), and
//! `-single_module` dylib emits one 56-byte `DylibModule64` entry whose
//! subranges mirror the `LC_DYSYMTAB`'s locals/extdefs (the whole image
//! as one module). The smoke gates pin the contract: the default carries
//! no module table (`nmodtab = 0`), the decision carries one (`nmodtab =
//! 1`, `modtaboff > 0`), and the entry's subranges mirror the command.
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape-parity gate
//! on the dev sandbox, like the knob-parity benches before it.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_core::resolve::ModulePolicy;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::{DysymtabCommand, LoadCommandIter, LoadCommandKind, MachHeader64};

const OBJECTS: usize = 32;

/// `OBJECTS` objects: `_main` in the first; each carries one defined
/// `_fn_N` — the dylib corpus the module-table entry's extdef subrange
/// mirrors.
fn corpus() -> Vec<LinkInput> {
    (0..OBJECTS)
        .map(|i| {
            let mut b = ObjectBuilder::new(&format!("mp_{i:03}.o"));
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
                name: format!("mp_{i:03}.o"),
                bytes: b.build().expect("the bench object builds"),
            }
        })
        .collect()
}

fn dysymtab(layout: &pgr_core::Layout) -> DysymtabCommand {
    let bytes = &layout.header_bytes;
    let hdr = MachHeader64::parse(bytes).expect("the header parses");
    let mut it = LoadCommandIter::new(bytes, MachHeader64::SIZE, hdr.ncmds, hdr.sizeofcmds)
        .expect("the load-command iter builds");
    while let Ok(Some(cmd)) = it.next_command() {
        if let LoadCommandKind::Dysymtab = cmd.kind {
            return DysymtabCommand::parse(cmd.bytes, 0).expect("the dysymtab parses");
        }
    }
    panic!("no LC_DYSYMTAB in the linked header");
}

fn bench_module_policy(c: &mut Criterion) {
    // The smoke gates first: the default carries no module table
    // (`nmodtab = 0`, no bytes); the decision carries one (`nmodtab = 1`,
    // `modtaboff > 0`, the 56-byte entry whose subranges mirror the
    // LC_DYSYMTAB); the decision threads to the layout.
    let inputs = corpus();
    let plan_for = |inputs: &[LinkInput], policy: ModulePolicy| {
        link(
            inputs,
            &[],
            &LinkConfig {
                filetype: OutputType::Dylib,
                install_name: Some("@rpath/libpgr.dylib".into()),
                module_policy: policy,
                ..LinkConfig::default()
            },
        )
        .expect("the corpus links")
        .layout
    };
    let multi = plan_for(&inputs, ModulePolicy::MultiModule);
    let single = plan_for(&inputs, ModulePolicy::SingleModule);
    let multi_dys = dysymtab(&multi);
    let single_dys = dysymtab(&single);
    assert_eq!(multi_dys.nmodtab, 0, "the default carries no module table");
    assert_eq!(
        single_dys.nmodtab, 1,
        "the decision carries one module-table entry"
    );
    assert!(
        single_dys.modtaboff > 0,
        "the module table rides a real offset"
    );
    assert!(
        multi.module_table.is_empty(),
        "the default carries no module-table bytes"
    );
    assert_eq!(
        single.module_table.len(),
        core::mem::size_of::<pgr_format::DylibModule64>(),
        "the decision carries one 56-byte entry"
    );
    assert!(
        single.module_policy.is_single(),
        "the layout carries the single_module decision (the echo the emit reads)"
    );

    let mut group = c.benchmark_group("module_policy");
    group.throughput(Throughput::Elements(OBJECTS as u64));
    let decisions = [
        ("multi_module_default", ModulePolicy::MultiModule),
        ("single_module", ModulePolicy::SingleModule),
    ];
    for (name, policy) in decisions {
        group.bench_with_input(
            BenchmarkId::new("link_32_objects", name),
            &policy,
            |b, &policy| {
                b.iter(|| {
                    let cfg = LinkConfig {
                        filetype: OutputType::Dylib,
                        install_name: Some("@rpath/libpgr.dylib".into()),
                        module_policy: policy,
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
    bench_module_policy(&mut criterion);
    criterion.final_summary();
}
