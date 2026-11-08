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
/// The relayout bench's growth ladder: eight +64 KiB steps, then one
/// tier-1 reset link, cycling (see `bench_incremental`).
const LADDER_STEPS: usize = 8;

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
    // The relayout ladder: the same object grown in +64 KiB steps — each
    // step overflows the current anchor (the reserved slack is 10%) and
    // stays within the ladder's segment-relayout bound (growth beyond the
    // previous pad ≪ 1 MiB).
    for step in 1..=8usize {
        let grown = bench_object(1, TEXT_KIB + 64 * step, false, false)
            .build()
            .unwrap();
        std::fs::write(dir.join(format!("inc_obj_1_grown_{step}.o")), &grown).unwrap();
    }
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
    // new slot's page and the LINKEDIT chunks only. The previous bench's
    // alternation parity is unknown, so the state resets to pristine
    // first (the record is warm; every timed iteration is then a real
    // edit→patch cycle either way).
    let mut inc_import = full.clone();
    inc_import.incremental = true;
    pgr_driver::run(&inc_import).unwrap();

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

    // The segment-relayout bench (§7.3 ladder tier 2): the edit overflows
    // the anchor, the section re-pads naturally and everything behind it
    // shifts — the planner patches the moved suffix (clone resized, dirty
    // tiles + relocated CodeDirectory rewritten from the merged hash
    // table) instead of re-running the full link.
    //
    // The anchored skeleton holds any size a section has already carried,
    // so an alternating grown↔pristine cycle degenerates to tier 1 after
    // the first round trip. The bench therefore climbs a monotone ladder:
    // eight +64 KiB growth steps (each beyond the current anchor, each
    // within the ladder's segment-relayout bound), then one reset link
    // back to the pristine object (tier 1 — the anchor absorbs the
    // shrink), and the cycle repeats. The recorded mean is the honest
    // mix (8 tier-2 links : 1 tier-1 link); the accounting pass below
    // prints the per-step split.
    let mut ladder = 0usize;
    group.bench_function("segment_relayout_relink_8mib", |b| {
        b.iter(|| {
            ladder += 1;
            let position = ladder % (LADDER_STEPS + 1);
            let mut edited = inc.clone();
            edited.inputs[1] = if position == 0 {
                // The reset link: back to the pristine object.
                dir.join("inc_obj_1.o")
            } else {
                dir.join(format!("inc_obj_1_grown_{position}.o"))
            }
            .display()
            .to_string();
            let outcome = pgr_driver::run(&edited).unwrap();
            let patch = outcome.patch.expect("the relayout relink patches");
            std::hint::black_box(patch);
        });
    });

    // Reset to the pristine variant (the ladder's position after the
    // timed loop is unknown), so the untouched bench is truly untouched.
    // The shrink lands inside the grown anchor: a real tier-1 patch, but
    // bounded — never a whole-image rewrite.
    let reset = pgr_driver::run(&inc).unwrap();
    assert!(
        reset.patch.is_none_or(|p| p.dirty_tiles < p.total_tiles),
        "the reset relink must reuse most tiles"
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

    // The LINKEDIT-shrink bench (the relayout tier's shrink rung): an
    // UNSIGNED corpus (`-no_adhoc` — no signature boundary to anchor the
    // tail), object 1 alternating between a 512-local-symbol variant and
    // the pristine one. The heavy→pristine step shrinks the symtab and
    // string pool: the image tail comes down and the shrink rung patches
    // it (clone truncated, chunk tail re-emitted) instead of the full
    // link; the pristine→heavy step grows it back through the
    // LINKEDIT-overflow trigger. The recorded mean is the honest mix (1
    // shrink : 1 regrow); the accounting pass prints the per-direction
    // split. Separate output path: the unsigned record must not meet the
    // signed groups' accounting loops below.
    let heavy = {
        let mut b = bench_object(1, TEXT_KIB, false, false);
        for i in 0..512u32 {
            b.add_symbol(ObjectSymbol::Defined {
                name: format!("_bench_local_{i:04}"),
                section_index: 0,
                value: u64::from(i % 16) * 4,
                weak: false,
            });
        }
        let bytes = b.build().unwrap();
        let p = dir.join("inc_obj_1_heavy.o");
        std::fs::write(&p, &bytes).unwrap();
        p
    };

    let mut shrink = full.clone();
    shrink.incremental = true;
    shrink.config.adhoc = false;
    let shrink_out = dir.join("app_shrink");
    shrink.output = shrink_out.display().to_string();
    let shrink_probe = pgr_driver::link_to_image(&shrink).unwrap();
    let shrink_bytes = shrink_probe.image.len() as u64;
    // Warm the unsigned record (cold links fall back by design).
    let warm = pgr_driver::run(&shrink).unwrap();
    assert!(
        warm.patch.is_none(),
        "the shrink bench warm-up is the recorded full link"
    );

    let mut shrink_group = c.benchmark_group("pgr-driver/incremental_shrink");
    shrink_group.sample_size(20);
    shrink_group.measurement_time(core::time::Duration::from_secs(6));
    shrink_group.throughput(Throughput::Bytes(shrink_bytes));

    let mut shrink_alternator = 0u32;
    shrink_group.bench_function("linkedit_shrink_relink_8mib", |b| {
        b.iter(|| {
            shrink_alternator += 1;
            let mut edited = shrink.clone();
            edited.inputs[1] = dir
                .join(if shrink_alternator % 2 == 0 {
                    "inc_obj_1.o"
                } else {
                    "inc_obj_1_heavy.o"
                })
                .display()
                .to_string();
            let outcome = pgr_driver::run(&edited).unwrap();
            let patch = outcome.patch.expect("the shrink/regrow relink patches");
            assert!(
                patch.dirty_tiles < patch.total_tiles,
                "the tail edit must not rewrite the content tiles"
            );
            std::hint::black_box(patch);
        });
    });
    shrink_group.finish();

    // The shrink rung's accounting pass (reported, not timed): the
    // heavy→pristine direction is the shrink; its pwritten bytes are the
    // §7.3 "bytes ∝ change size" evidence for the rung. The timed loop's
    // parity is unknown, so the pass pins the state first (one pristine
    // relink), then measures the regrow and the shrink directions.
    let mut edited = shrink.clone();
    edited.inputs[1] = dir.join("inc_obj_1.o").display().to_string();
    let _parity = pgr_driver::run(&edited).unwrap();
    let mut edited = shrink.clone();
    edited.inputs[1] = heavy.display().to_string();
    let regrow = pgr_driver::run(&edited).unwrap();
    let regrow_patch = regrow.patch.expect("the regrow relink patches");
    assert!(
        regrow_patch.bytes_patched > 0 && !regrow_patch.untouched,
        "the regrow step must be a real edit→patch cycle"
    );
    let mut edited = shrink.clone();
    edited.inputs[1] = dir.join("inc_obj_1.o").display().to_string();
    let shrink_step = pgr_driver::run(&edited).unwrap();
    let shrink_patch = shrink_step.patch.expect("the shrink relink patches");
    assert!(
        shrink_patch.bytes_patched > 0 && !shrink_patch.untouched,
        "the shrink step must be a real edit→patch cycle"
    );
    eprintln!(
        "shrink accounting: image {shrink_bytes} bytes; heavy→pristine {} bytes patched ({} of {} tiles, size {} → {}); pristine→heavy {} bytes patched",
        shrink_patch.bytes_patched,
        shrink_patch.dirty_tiles,
        shrink_patch.total_tiles,
        regrow.file_size,
        shrink_step.file_size,
        regrow_patch.bytes_patched
    );
    assert!(
        shrink_step.file_size < regrow.file_size,
        "the shrink step must shrink the image ({} → {})",
        regrow.file_size,
        shrink_step.file_size
    );

    // The bytes-written accounting (reported, not timed): the §7.3 gate is
    // "bytes written ∝ change size", and the patch outcome measures exactly
    // the pwritten bytes per relink. Input 1 is the alternated object
    // (input 0 is the extern-provider dylib — replacing it would break the
    // link, which the pre-tier-2 accounting loop did by mistake).
    let mut patched_bytes = 0u64;
    let mut dirty_tiles = 0u32;
    for i in 0..20 {
        let mut edited = inc.clone();
        edited.inputs[1] = dir
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

    // The relayout ladder's accounting pass (reported, not timed): one
    // full cycle of the monotone growth ladder, printing each step's tier
    // (tier 2 shifts the skeleton; the reset link stays tier 1) and its
    // pwritten bytes — the §7.3 "bytes ∝ change size" evidence for the
    // new tier.
    let mut total_patched = 0u64;
    let mut total_tiles = 0u32;
    let mut image_bytes_final = image_bytes;
    for step in 1..=8usize {
        let mut edited = inc.clone();
        edited.inputs[1] = dir
            .join(format!("inc_obj_1_grown_{step}.o"))
            .display()
            .to_string();
        let outcome = pgr_driver::run(&edited).unwrap();
        let patch = outcome.patch.expect("the ladder relink patches");
        total_patched += patch.bytes_patched;
        total_tiles = total_tiles.max(patch.dirty_tiles);
        image_bytes_final = outcome.file_size;
        eprintln!(
            "relayout ladder step {step}: +64 KiB → {} bytes patched ({} of {} tiles dirty)",
            patch.bytes_patched, patch.dirty_tiles, patch.total_tiles
        );
    }
    let reset_outcome = pgr_driver::run(&inc).unwrap();
    let reset_patch = reset_outcome.patch.expect("the reset relink patches");
    eprintln!(
        "relayout ladder reset: {} bytes patched ({} of {} tiles dirty, tier 1)",
        reset_patch.bytes_patched, reset_patch.dirty_tiles, reset_patch.total_tiles
    );
    eprintln!(
        "relayout ladder accounting: image grew to {image_bytes_final} bytes; mean patched {} bytes/growth-step; max dirty tiles {total_tiles}",
        total_patched / 8
    );
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint
/// holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_incremental(&mut criterion);
    criterion.final_summary();
}
