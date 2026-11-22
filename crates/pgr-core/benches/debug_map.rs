//! M129 — the debug-map stabs bench: the symtab-build throughput (ns)
//! and the output symtab bytes over a generated corpus (>=128 objects ×
//! \>=2k symbols with stabs). The bench measures a **real** cost (the
//! symtab builder's walk over the stab-carrying corpus, the stab
//! re-addressing onto placed live atoms), not a byte-parity assertion —
//! the gate is the debug map's own build, recorded in
//! `docs/BENCHMARKS.md`.
//!
//! Run: `cargo bench -p pgr-core --bench debug_map`

use criterion::{BenchmarkId, Criterion, Throughput};
use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectStab, ObjectSymbol};
use std::hint::black_box;

/// Builds one stab-carrying object with `n_symbols` defined functions,
/// each with a `N_FUN` begin/end pair, plus the `N_SO`/`N_OSO`/`N_GSYM`
/// anchors — the shape the debug-map plan re-addresses onto placed live
/// atoms. Symbol names are prefixed with the object's index so the
/// corpus's strong definitions do not collide across objects.
fn stab_object(obj_idx: usize, n_symbols: usize) -> Vec<u8> {
    let name = format!("obj_{obj_idx}.o");
    let mut b = ObjectBuilder::new(&name).set_subsections_via_symbols(true);
    // `__text` with `n_symbols` 4-byte functions (ret each).
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(n_symbols),
        Vec::new(),
    ));
    b.add_stab(ObjectStab::So {
        path: format!("{name}.c"),
    });
    b.add_stab(ObjectStab::Oso { path: name.clone() });
    for i in 0..n_symbols {
        // The first symbol of the first object is `_main` (the entry the
        // executable link requires); the rest are `_fn_<obj>_<i>`.
        let sym_name = if obj_idx == 0 && i == 0 {
            "_main".to_string()
        } else {
            format!("_fn_{obj_idx}_{i}")
        };
        b.add_symbol(ObjectSymbol::Defined {
            name: sym_name.clone(),
            section_index: text,
            value: (i * 4) as u64,
            weak: false,
        });
        b.add_stab(ObjectStab::Fun {
            name: sym_name,
            section_index: text,
            value: (i * 4) as u64,
        });
        b.add_stab(ObjectStab::FunEnd { size: 4 });
        b.add_stab(ObjectStab::Gsym {
            name: if obj_idx == 0 && i == 0 {
                "_main".to_string()
            } else {
                format!("_fn_{obj_idx}_{i}")
            },
        });
    }
    b.build().expect("the fixture object builds")
}

/// Builds a corpus of `n_objects` stab-carrying objects, each with
/// `n_symbols` defined functions with `N_FUN` pairs.
fn stab_corpus(n_objects: usize, n_symbols: usize) -> Vec<LinkInput> {
    (0..n_objects)
        .map(|i| {
            let name = format!("obj_{i}.o");
            LinkInput {
                name: name.clone(),
                bytes: stab_object(i, n_symbols),
            }
        })
        .collect()
}

/// The symtab-build throughput bench: links the stab-carrying corpus
/// and measures the full link's wall time (the symtab builder's walk
/// over the stab-carrying corpus rides inside `link`). The `black_box`
/// keeps the layout and the emitted bytes live so the optimizer cannot
/// elide the symtab build.
fn bench_symtab_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("debug_map_symtab_build");
    // The corpus scales: 128 objects × 2k symbols (the floor the task
    // names), then 256 × 2k to price the scaling.
    for (n_objects, n_symbols) in [(128, 2048), (256, 2048)] {
        let corpus = stab_corpus(n_objects, n_symbols);
        let input_count = n_objects * n_symbols;
        group.throughput(Throughput::Elements(input_count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{n_objects}x{n_symbols}")),
            &corpus,
            |bencher, corpus| {
                bencher.iter(|| {
                    let cfg = LinkConfig::default();
                    let result = link(corpus, &[], &cfg).expect("the link runs");
                    // The symtab is `result.layout.symbols`; the bench
                    // measures the build that produced it (the debug-map
                    // stabs re-addressed onto the placed live atoms ride
                    // inside this build).
                    black_box(&result.layout.symbols);
                    // The emitted image's symtab bytes — the output size
                    // the bench records beside the throughput.
                    let image = pgr_emit::build_image(&result.layout, &result.objects)
                        .expect("the image emits");
                    let symtab_bytes = symtab_byte_len(&image);
                    black_box(symtab_bytes);
                });
            },
        );
    }
    group.finish();
}

/// Reads the output symtab's byte length from the image (the
/// `LC_SYMTAB`'s `nsyms * 16` — the size the bench records beside the
/// throughput).
fn symtab_byte_len(image: &[u8]) -> usize {
    let Ok(hdr) = pgr_format::MachHeader64::parse(image) else {
        return 0;
    };
    let Ok(mut it) = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    ) else {
        return 0;
    };
    while let Ok(Some(cmd)) = it.next_command() {
        if let pgr_format::LoadCommandKind::Symtab = cmd.kind
            && let Ok(st) = pgr_format::SymtabCommand::parse(cmd.bytes, 0)
        {
            return st.nsyms as usize * 16;
        }
    }
    0
}

fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_symtab_build(&mut criterion);
    criterion.final_summary();
}
