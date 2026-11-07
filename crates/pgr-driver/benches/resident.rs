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
    let text = vec![0u8; text_kib * 1024];
    let mut b = ObjectBuilder::new(&format!("bench_{seed}.o"));
    let text_idx = b.add_section(ObjectSection::text("__text", text, Vec::new()));
    let data_idx = b.add_section(ObjectSection::data("__data", vec![0u8; 8], Vec::new()));
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
        })
    });
    // Warm relink: the daemon's session is hot from the first call; every
    // iteration measures prepare → hash → negotiate → decode → link → emit
    // → wire (the real edit-relink loop minus the edit).
    group.bench_function("resident_warm_64_objects", |b| {
        b.iter(|| {
            let image = pgr_driver::link_to_bytes(&resident).unwrap();
            std::hint::black_box(image.len());
        })
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
