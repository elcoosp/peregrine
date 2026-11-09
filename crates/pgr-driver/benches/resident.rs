//! M8 resident-server benchmark (architecture doc §10.4 row M8): the
//! warm-relink path the milestone is for — a repeated link over unchanged
//! inputs through `pgrd` — against the one-shot pipeline.
//!
//! What the resident path skips on a warm iteration: the Mach-O parse of
//! every direct input (POI frames decode instead), the input file
//! *transfer* (blob negotiation sends manifests only) and the fresh output
//! allocation (the fused emit reuses the session buffer). What it still
//! pays: Pass 0 mapping, hashing, interning, Passes 2–3, the fused emit and
//! the wire round-trip. The M8 correctness gate (byte-identity with the
//! one-shot link) is asserted in `tests/m8_resident.rs`, not here.

use criterion::{Criterion, Throughput};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

/// One synthetic input object (the `link.rs` bench shape, tilted
/// **parse-heavy**: 2 048 symbols and a large symtab/name table per ~40 KiB
/// file, few relocation sites — Pass 1's symbol decode dominates the bytes,
/// which is exactly the share the resident session removes).
fn bench_object(seed: u64, symbols: usize, text_kib: usize) -> ObjectBuilder {
    bench_object_data(seed, symbols, text_kib, 0)
}

/// The same object with a tunable `__data` payload byte: the byte-distinct,
/// equally-valid variant the fusion bench alternates (a real edit each
/// timed iteration).
fn bench_object_data(seed: u64, symbols: usize, text_kib: usize, data_byte: u8) -> ObjectBuilder {
    let text = vec![0u8; text_kib * 1024];
    let mut b = ObjectBuilder::new(&format!("bench_{seed}.o"));
    let text_idx = b.add_section(ObjectSection::text("__text", text, Vec::new()));
    let data_idx = b.add_section(ObjectSection::data(
        "__data",
        vec![data_byte; 8],
        Vec::new(),
    ));
    for i in 0..symbols {
        b.add_symbol(ObjectSymbol::Defined {
            name: format!("_bench_fn_{seed}_{i}"),
            section_index: text_idx,
            value: ((i * 8) % (text_kib * 1024)) as u64,
            weak: false,
        });
    }
    // References point at the previous object's symbols (object 1
    // self-references so the corpus never has an unresolved name); a few
    // branch sites carry them.
    let ref_seed = if seed == 1 { seed } else { seed - 1 };
    for i in 0..symbols {
        b.add_symbol(ObjectSymbol::Undefined {
            name: format!("_bench_fn_{ref_seed}_{i}"),
            weak_ref: false,
        });
    }
    // A few branch sites (16) carry the cross-object references; their
    // targets spread across the undefined-symbol range.
    for k in 0..16usize {
        let site = k * 4;
        let sym_idx = symbols + k * (symbols / 16);
        b.section_mut(text_idx)
            .relocs
            .push(ObjectReloc::branch26(sym_idx as u32).at(site as u32));
    }
    b.section_mut(data_idx)
        .relocs
        .push(ObjectReloc::unsigned(0).at(0));
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

fn bench_corpus(objects: usize, symbols: usize, text_kib: usize) -> (Vec<Vec<u8>>, usize) {
    let mut out = Vec::with_capacity(objects);
    let mut total = 0usize;
    for seed in 1..=objects as u64 {
        let bytes = bench_object(seed, symbols, text_kib).build().unwrap();
        total += bytes.len();
        out.push(bytes);
    }
    (out, total)
}

/// Starts an in-process daemon and waits for the socket.
fn start_daemon(sock: &PathBuf) {
    let owned = sock.clone();
    std::thread::spawn(move || {
        let _ = pgr_daemon::serve(&owned, Duration::from_secs(300));
    });
    for _ in 0..500 {
        if UnixStream::connect(sock).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("daemon socket never came up");
}

fn bench_resident(c: &mut Criterion) {
    let dir = std::env::temp_dir().join("pgr_bench_resident");
    std::fs::create_dir_all(&dir).unwrap();

    // 64 objects x 2 048 symbols x 2 KiB text: the parse-heavy shape — the
    // symbol tables dominate the bytes, so Pass 1 (which the resident
    // session removes) is the largest single share of the pipeline.
    let corpus = bench_corpus(64, 2_048, 2);
    let files: &Vec<Vec<u8>> = &corpus.0;
    let total: usize = corpus.1;

    let mut base = pgr_driver::opts::Options::default();
    for (i, bytes) in files.iter().enumerate() {
        let p = dir.join(format!("resident_obj_{i}.o"));
        std::fs::write(&p, bytes).unwrap();
        base.inputs.push(p.display().to_string());
    }
    base.output = dir.join("resident_out.bin").display().to_string();
    base.config.ident = "resident_bench".into();

    let sock = dir.join("bench.sock");
    start_daemon(&sock);

    let mut resident = base.clone();
    resident.resident = true;
    resident.resident_socket = Some(sock.display().to_string());

    let mut group = c.benchmark_group("pgr-driver/resident");
    group.sample_size(20);
    group.measurement_time(core::time::Duration::from_secs(4));
    group.throughput(Throughput::Bytes(total as u64));

    group.bench_function("one_shot_64_objects", |b| {
        b.iter(|| {
            let image = pgr_driver::link_to_bytes(&base).unwrap();
            std::hint::black_box(image.len());
        });
    });
    // Warm relink: the daemon's session is hot from the first call; every
    // iteration measures prepare → hash → negotiate → decode → link → emit
    // → wire (the real edit-relink loop minus the edit).
    group.bench_function("resident_warm_64_objects", |b| {
        b.iter(|| {
            let image = pgr_driver::link_to_bytes(&resident).unwrap();
            std::hint::black_box(image.len());
        });
    });
    group.finish();

    bench_resident_fusion(c, &dir, &base);
    bench_resident_fusion_audited(c, &dir, &base);
}

/// M9 GA fusion benchmark (architecture doc §7.3 + §10.4 M9): the
/// edit→relink loop served by the resident session — `-resident
/// -incremental` through `run()`, the daemon's §7.3 ladder patching in
/// memory over warm POIs and the client writing the file.
///
/// Every timed iteration is a real edit: object 1 alternates between the
/// pristine and a byte-distinct (data-payload) variant, so each relink
/// dirties one tile plus the re-sign. Since the §7.2 output-residency
/// rung (wire v5) the warm cycle moves only the change: the previous
/// output is the session's resident state (no re-upload) and the reply
/// is the changed-tile stream (asserted here, byte-identity gated in
/// `tests/m9_resident_fusion.rs`).
fn bench_resident_fusion(
    c: &mut Criterion,
    dir: &std::path::Path,
    base: &pgr_driver::opts::Options,
) {
    // The edited variant of object seed 1 (the corpus's object files only,
    // so `inputs[0]` is `resident_obj_0.o` = seed 1). Its own output name
    // keeps the sidecar state apart from the plain resident groups above.
    let edited = bench_object_data(1, 2_048, 2, 0xFF).build().unwrap();
    let edited_path = dir.join("resident_obj_0_edited.o");
    std::fs::write(&edited_path, &edited).unwrap();

    let sock = dir.join("bench-fusion.sock");
    start_daemon(&sock);

    let mut fusion = base.clone();
    fusion.resident = true;
    fusion.resident_socket = Some(sock.display().to_string());
    fusion.incremental = true;
    fusion.output = dir.join("resident_fusion_out.bin").display().to_string();
    // A stale sidecar from an earlier bench run describes a different
    // output state — the warm-up link must be the recorded full link.
    let stale = dir.join("resident_fusion_out.bin.pgr-inc");
    let _ = std::fs::remove_file(&stale);

    let mut group = c.benchmark_group("pgr-driver/resident-fusion");
    group.sample_size(20);
    group.measurement_time(core::time::Duration::from_secs(6));

    // Warm the record once (the cold link is the recorded full link).
    let warm = pgr_driver::run(&fusion).unwrap();
    assert!(
        warm.patch.is_none(),
        "the warm-up link is the recorded full link"
    );

    let mut alternator = 0u32;
    group.bench_function("fusion_relink_64_objects", |b| {
        b.iter(|| {
            alternator += 1;
            let mut edited_opts = fusion.clone();
            edited_opts.inputs[0] = dir
                .join(if alternator % 2 == 0 {
                    "resident_obj_0.o"
                } else {
                    "resident_obj_0_edited.o"
                })
                .display()
                .to_string();
            let outcome = pgr_driver::run(&edited_opts).unwrap();
            let patch = outcome
                .patch
                .expect("the warm fusion relink patches in place");
            // v5 (the §7.2 rung): the warm cycle's reply is the
            // changed-tile stream — a fraction of the image.
            match outcome.transport {
                Some(pgr_daemon::Transport::Tiles { tiles, bytes }) => {
                    assert!(
                        tiles > 0 && bytes < outcome.file_size,
                        "the stream is a fraction ({} tiles, {} of {} bytes)",
                        tiles,
                        bytes,
                        outcome.file_size
                    );
                    std::hint::black_box((tiles, bytes));
                }
                other => panic!("the warm relink rides the tile stream, got {other:?}"),
            }
            std::hint::black_box(patch);
        });
    });
    group.finish();
}

/// M9 GA rung 2 benchmark (wire v4): the same edit→relink loop as
/// [`bench_resident_fusion`], with `-incremental-verify` served by the
/// daemon — the audit (byte-identity against the reference emit plus the
/// strict verifier) runs inside the session over its warm POIs and the
/// verdict crosses the wire. The overhead against the unaudited fusion
/// group is the rung's honest price: the reference emit plus the verifier
/// pass per audited relink. The verdict's correctness is gated in
/// `tests/m9_resident_fusion.rs`, not here.
fn bench_resident_fusion_audited(
    c: &mut Criterion,
    dir: &std::path::Path,
    base: &pgr_driver::opts::Options,
) {
    let edited = bench_object_data(1, 2_048, 2, 0xFF).build().unwrap();
    let edited_path = dir.join("resident_obj_0_edited.o");
    if !edited_path.exists() {
        std::fs::write(&edited_path, &edited).unwrap();
    }

    let sock = dir.join("bench-fusion-audited.sock");
    start_daemon(&sock);

    let mut audited = base.clone();
    audited.resident = true;
    audited.resident_socket = Some(sock.display().to_string());
    audited.incremental = true;
    audited.incremental_verify = true;
    audited.output = dir
        .join("resident_fusion_audited_out.bin")
        .display()
        .to_string();
    let stale = dir.join("resident_fusion_audited_out.bin.pgr-inc");
    let _ = std::fs::remove_file(&stale);

    let mut group = c.benchmark_group("pgr-driver/resident-fusion-audited");
    group.sample_size(20);
    group.measurement_time(core::time::Duration::from_secs(6));

    let warm = pgr_driver::run(&audited).unwrap();
    assert!(
        warm.patch.is_none(),
        "the warm-up link is the recorded full link"
    );

    let mut alternator = 0u32;
    group.bench_function("fusion_relink_audited_64_objects", |b| {
        b.iter(|| {
            alternator += 1;
            let mut edited_opts = audited.clone();
            edited_opts.inputs[0] = dir
                .join(if alternator % 2 == 0 {
                    "resident_obj_0.o"
                } else {
                    "resident_obj_0_edited.o"
                })
                .display()
                .to_string();
            let outcome = pgr_driver::run(&edited_opts).unwrap();
            outcome
                .patch
                .expect("the warm audited relink patches in place");
            let audit = outcome.audit.expect("the audited relink serves the audit");
            assert!(audit.identity_ok && audit.verify_ok, "clean audit");
            std::hint::black_box(audit);
        });
    });
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint
/// holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_resident(&mut criterion);
    criterion.final_summary();
}
