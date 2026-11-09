//! Relocatable object emit benchmark (M10 rung 1, roadmap §10.4 row M10):
//! `build_object_image` over a corpus shaped so every sub-pass does honest
//! work — wide multi-tile `__text` blobs, branch/pointer relocations
//! re-pointed through the resolution, cross-object symbol references and
//! the grouped symbol table (locals, winner-backed globals, open
//! undefineds).
//!
//! The comparator is the same corpus's full fused image link: the `-r`
//! rung skips Pass 3's segment layout, the fixup packer and the signature
//! rebuild, so its per-byte cost against the full link is the honest
//! shape of "emit an input, not an image".

use criterion::{Criterion, Throughput};
use pgr_core::layout::LinkConfig;
use pgr_core::{LinkInput, link_reloc};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// One wide object: a multi-tile text blob with branch relocs, a data
/// blob with pointer slots, cross-object symbol references (the same
/// shape the emit bench uses, so the two runs' numbers read side by side).
fn bench_object(seed: u64, symbols: usize, text_kib: usize) -> ObjectBuilder {
    let text = vec![0x2Au8; text_kib * 1024];
    let mut b = ObjectBuilder::new(&format!("bench_{seed}.o"));
    let text_idx = b.add_section(ObjectSection::text("__text", text, Vec::new()));
    let data_idx = b.add_section(ObjectSection::data(
        "__data",
        vec![0u8; symbols * 8],
        Vec::new(),
    ));
    for i in 0..symbols {
        b.add_symbol(ObjectSymbol::Defined {
            name: format!("_bench_fn_{seed}_{i}"),
            section_index: text_idx,
            value: (i * 8 % (text_kib * 1024)) as u64,
            weak: false,
        });
    }
    let ref_seed = if seed == 1 { seed } else { seed - 1 };
    for i in 0..symbols {
        let r = b.add_symbol(ObjectSymbol::Undefined {
            name: format!("_bench_fn_{ref_seed}_{i}"),
            weak_ref: false,
        });
        let t = b.sym_index(r);
        b.section_mut(text_idx)
            .relocs
            .push(ObjectReloc::branch26(t).at(((i * 8) % (text_kib * 1024)) as u32));
        b.section_mut(data_idx)
            .relocs
            .push(ObjectReloc::unsigned(t).at((i * 8) as u32));
    }
    if seed == 1 {
        b.add_symbol(ObjectSymbol::Defined {
            name: "_main".into(),
            section_index: text_idx,
            value: 0,
            weak: false,
        });
    }
    b
}

fn corpus(objects: usize, symbols: usize, text_kib: usize) -> (Vec<LinkInput>, usize) {
    let mut inputs = Vec::with_capacity(objects);
    let mut total = 0usize;
    for seed in 1..=objects as u64 {
        let bytes = bench_object(seed, symbols, text_kib).build().unwrap();
        total += bytes.len();
        inputs.push(LinkInput {
            name: format!("bench_{seed}.o"),
            bytes,
        });
    }
    (inputs, total)
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();

    let (inputs, total) = corpus(16, 512, 32);
    let cfg = LinkConfig {
        ident: "pgr-emit-bench".into(),
        ..LinkConfig::default()
    };
    let linked = link_reloc(&inputs, &[], &cfg, pgr_core::Parallelism::Auto).unwrap();

    // The gate precondition, asserted once at bench setup: the emitted
    // object re-parses as an input (the self-consumption contract).
    let object = pgr_emit::build_object_image(&linked, &cfg).unwrap();
    let reparsed = link_reloc(
        &[LinkInput {
            name: "out.o".into(),
            bytes: object.clone(),
        }],
        &[],
        &cfg,
        pgr_core::Parallelism::Auto,
    )
    .unwrap();
    assert!(
        reparsed
            .resolution
            .def(reparsed.interner.lookup(b"_main").unwrap())
            .is_some(),
        "the emitted object must be a working input"
    );

    let mut group = criterion.benchmark_group("pgr-emit/object");
    group.sample_size(20);
    group.measurement_time(core::time::Duration::from_secs(4));
    group.throughput(Throughput::Bytes(total as u64));
    group.bench_function("build_object_image/16x512sym-32kib", |b| {
        b.iter(|| pgr_emit::build_object_image(&linked, &cfg).unwrap());
    });
    group.finish();
}
