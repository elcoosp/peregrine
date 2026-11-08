//! M9 incremental-relink benchmark (architecture doc §10.4 row M9; §7.3
//! Stage C tier 1): the edit–relink loop the in-place patch path exists
//! for — one function's body changes in a large corpus, and the relink
//! must touch a vanishing fraction of the output.
//!
//! What the warm incremental relink skips against the full relink: the
//! fused emit and the 4 KiB page hashing of every clean tile, and the
//! write of every clean 16 KiB page (the clone is copy-on-write on APFS —
//! `std::fs::copy` resolves to `fclonefileat` there; on reflink-less
//! filesystems the clone degrades to a full copy, which the recorded
//! verdict calls out honestly). What it still pays: Pass 0 mapping, the
//! parse (the Stage A POI cache is orthogonal and off here), Passes 2–3,
//! the dirty-tile emit and the `CodeDirectory` rebuild from the merged hash
//! table.
//!
//! The correctness gate (patched == full emit, byte-identical) is asserted
//! in `tests/m9_incremental.rs` and `pgr-emit/tests/incremental.rs`, not
//! here.

use criterion::{Criterion, Throughput};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::path::{Path, PathBuf};

/// One content-heavy object: 256 KiB of `__text` (the write-heavy shape —
/// the output pages dominate the image), a handful of symbols and
/// cross-object branch/pointer sites so the patch stream is real.
fn bench_object(seed: u64, text_kib: usize, flip: bool, ext_swap: bool) -> ObjectBuilder {
    let mut text = vec![0xD5u8, 0x03, 0x20, 0x1F]; // nop
    text.resize(text_kib * 1024, 0xD5);
    // The "edited function body": eight words flipped in place, halfway
    // through the object's text (same size — the frozen skeleton is the
    // point of the tier-1 bench; the mid-corpus offset keeps the dirty
    // tile out of the header page).
    if flip {
        let base = (text_kib * 1024) / 2 + 16;
        for i in 0..8 {
            let at = base + i * 4;
            text[at] = 0xAA;
            text[at + 1] ^= 0x55;
        }
    }
    let mut b = ObjectBuilder::new(&format!("bench_{seed}.o"));
    let text_idx = b.add_section(ObjectSection::text(
        "__text",
        text,
        // Two real branch sites into the previous object (obj 1 branches
        // into itself so the corpus never has an unresolved name).
        {
            // 16 defined + 16 undefined symbols; the branch sites land on
            // undefined indices 16 and 24 (the previous object's exports).
            let sym_idx = |k: u32| 16 + k;
            vec![
                ObjectReloc::branch26(sym_idx(0)).at(32),
                ObjectReloc::branch26(sym_idx(8)).at(64),
            ]
        },
    ));
    let data_idx = b.add_section(ObjectSection::data("__data", vec![0u8; 16], vec![]));
    for i in 0..16u32 {
        b.add_symbol(ObjectSymbol::Defined {
            name: format!("_bench_fn_{seed}_{i}"),
            section_index: text_idx,
            value: u64::from(i) * 256,
            weak: false,
        });
    }
    let ref_seed = if seed == 1 { seed } else { seed - 1 };
    for i in 0..16u32 {
        b.add_symbol(ObjectSymbol::Undefined {
            name: format!("_bench_fn_{ref_seed}_{i}"),
            weak_ref: false,
        });
    }
    // The dylib import surface (resolved from libbench.dylib): baseline
    // binds one extern through one `__data` pointer; the swapped variant
    // re-points that slot at a NEW import and binds the original one slot
    // later — first-use order would renumber the original's ordinal (and
    // rewrite its bind word); the anchored relink keeps the table.
    let ext_primary = b.add_symbol(ObjectSymbol::Undefined {
        name: "_bench_ext_a".into(),
        weak_ref: false,
    });
    let ext_secondary = b.add_symbol(ObjectSymbol::Undefined {
        name: "_bench_ext_b".into(),
        weak_ref: false,
    });
    if ext_swap {
        b.section_mut(data_idx).relocs = vec![
            ObjectReloc::unsigned(b.sym_index(ext_primary)).at(0),
            ObjectReloc::unsigned(b.sym_index(ext_secondary)).at(8),
        ];
    } else {
        b.section_mut(data_idx).relocs =
            vec![ObjectReloc::unsigned(b.sym_index(ext_secondary)).at(0)];
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

const OBJECTS: u64 = 32;
const TEXT_KIB: usize = 256;

fn bench_corpus(dir: &Path) -> (Vec<PathBuf>, u64) {
    // The extern-provider dylib (the linker's own -dylib path builds it,
    // so the export trie is real).
    let mut lib_b = ObjectBuilder::new("libbench.o");
    let lib_text = lib_b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    lib_b.add_symbol(ObjectSymbol::Defined {
        name: "_bench_ext_a".into(),
        section_index: lib_text,
        value: 0,
        weak: false,
    });
    lib_b.add_symbol(ObjectSymbol::Defined {
        name: "_bench_ext_b".into(),
        section_index: lib_text,
        value: 4,
        weak: false,
    });
    let lib_src = dir.join("libbench.o");
    std::fs::write(&lib_src, lib_b.build().unwrap()).unwrap();
    let lib_opts = pgr_driver::opts::Options {
        output: dir.join("libbench.dylib").display().to_string(),
        inputs: vec![lib_src.display().to_string()],
        config: pgr_core::layout::LinkConfig {
            filetype: pgr_core::layout::OutputType::Dylib,
            install_name: Some("@rpath/libbench.dylib".into()),
            ident: "incremental_bench_lib".into(),
            ..pgr_core::layout::LinkConfig::default()
        },
        ..pgr_driver::opts::Options::default()
    };
    pgr_driver::run(&lib_opts).unwrap();
    let lib_path = dir.join("libbench.dylib").display().to_string();

    let mut paths: Vec<PathBuf> = vec![PathBuf::from(lib_path)];
    let mut input_bytes = 0u64;
    for seed in 1..=OBJECTS {
        let p = dir.join(format!("inc_obj_{seed}.o"));
        let bytes = bench_object(seed, TEXT_KIB, false, false).build().unwrap();
        input_bytes += bytes.len() as u64;
        std::fs::write(&p, &bytes).unwrap();
        paths.push(p);
    }
    // Object 1's edited variants (the alternation keeps every timed
    // iteration a real edit→patch cycle).
    let flipped = bench_object(1, TEXT_KIB, true, false).build().unwrap();
    std::fs::write(dir.join("inc_obj_1_edited.o"), &flipped).unwrap();
    let import_swapped = bench_object(1, TEXT_KIB, false, true).build().unwrap();
    std::fs::write(dir.join("inc_obj_1_import.o"), &import_swapped).unwrap();
    (paths, input_bytes)
}

fn bench_incremental(c: &mut Criterion) {
    let dir = std::env::temp_dir().join("pgr_bench_incremental");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (objects, _input_bytes) = bench_corpus(&dir);

    let out = dir.join("app");
    let mut full = pgr_driver::opts::Options::default();
    for p in &objects {
        full.inputs.push(p.display().to_string());
    }
    full.output = out.display().to_string();
    full.config.ident = "incremental_bench".into();

    let mut inc = full.clone();
    inc.incremental = true;

    // The image size the relink benches pay for (the write-bound budget).
    let probe = pgr_driver::link_to_image(&full).unwrap();
    let image_bytes = probe.image.len() as u64;

    let mut group = c.benchmark_group("pgr-driver/incremental");
    group.sample_size(20);
    group.measurement_time(core::time::Duration::from_secs(6));
    group.throughput(Throughput::Bytes(image_bytes));

    group.bench_function("full_relink_8mib", |b| {
        b.iter(|| {
            let outcome = pgr_driver::run(&full).unwrap();
            std::hint::black_box(outcome);
        });
    });

    // Warm the record once (cold links fall back by design); every timed
    // iteration then alternates object 1 between the pristine and edited
    // variants — a real one-function edit each time.
    let warm = pgr_driver::run(&inc).unwrap();
    assert!(
        warm.patch.is_none(),
        "the warm-up link is the recorded full link"
    );

    let mut alternator = 0u32;
    group.bench_function("incremental_relink_8mib", |b| {
        b.iter(|| {
            alternator += 1;
            let mut edited = inc.clone();
            // Input 0 is the bench dylib; object 1 (the alternated input)
            // sits at index 1.
            edited.inputs[1] = dir
                .join(if alternator % 2 == 0 {
                    "inc_obj_1.o"
                } else {
                    "inc_obj_1_edited.o"
                })
                .display()
                .to_string();
            let outcome = pgr_driver::run(&edited).unwrap();
            let patch = outcome.patch.expect("the warm relink patches in place");
            std::hint::black_box(patch);
        });
    });

    // The import-churn bench: the same corpus, but the edit swaps object
    // 1's dylib import surface (one bind becomes two, sorted first by
    // address). With the anchored table the existing bind ordinal — and
    // its bind word on the data page — survives; the patch touches the
    // new slot's page and the LINKEDIT chunks only.
    let mut inc_import = full.clone();
    inc_import.incremental = true;
    let warm_import = pgr_driver::run(&inc_import).unwrap();
    assert!(
        warm_import.patch.is_none(),
        "the warm-up link is the recorded full link"
    );

    let mut import_alternator = 0u32;
    group.bench_function("incremental_add_import_8mib", |b| {
        b.iter(|| {
            import_alternator += 1;
            let mut edited = inc_import.clone();
            edited.inputs[1] = dir
                .join(if import_alternator % 2 == 0 {
                    "inc_obj_1.o"
                } else {
                    "inc_obj_1_import.o"
                })
                .display()
                .to_string();
            let outcome = pgr_driver::run(&edited).unwrap();
            let patch = outcome.patch.expect("the warm relink patches in place");
            std::hint::black_box(patch);
        });
    });

    // Reset to the pristine variant (the alternation's parity after the
    // timed loop is unknown), so the untouched bench is truly untouched.
    let reset = pgr_driver::run(&inc).unwrap();
    assert!(
        reset.patch.is_none_or(|p| p.dirty_tiles <= 2),
        "the reset relink must be (near-)idle"
    );

    group.bench_function("untouched_relink_8mib", |b| {
        b.iter(|| {
            let outcome = pgr_driver::run(&inc).unwrap();
            let patch = outcome.patch.expect("the untouched relink still plans");
            assert!(patch.untouched, "the same inputs must be a no-op");
            std::hint::black_box(patch);
        });
    });
    group.finish();

    // The bytes-written accounting (reported, not timed): the §7.3 gate is
    // "bytes written ∝ change size", and the patch outcome measures exactly
    // the pwritten bytes per relink.
    let mut patched_bytes = 0u64;
    let mut dirty_tiles = 0u32;
    for i in 0..20 {
        let mut edited = inc.clone();
        edited.inputs[0] = dir
            .join(if i % 2 == 0 {
                "inc_obj_1_edited.o"
            } else {
                "inc_obj_1.o"
            })
            .display()
            .to_string();
        let outcome = pgr_driver::run(&edited).unwrap();
        let patch = outcome.patch.expect("warm relink");
        patched_bytes += patch.bytes_patched;
        dirty_tiles = dirty_tiles.max(patch.dirty_tiles);
    }
    eprintln!(
        "incremental bench accounting: image {image_bytes} bytes; mean patched {} bytes/iter; max dirty tiles {dirty_tiles}",
        patched_bytes / 20
    );
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint
/// holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_incremental(&mut criterion);
    criterion.final_summary();
}
