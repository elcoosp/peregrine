//! The byte-touching parse bench — the parser-rate caveat's own pricing.
//!
//! docs/BENCHMARKS.md, "Conditions & harness": "`summarize` walks
//! _metadata tables_, not section payload — these are metadata-walk
//! rates, not DRAM streaming. The byte-touching parse starts well below
//! them." This bench prices that number over the byte-touching corpus
//! the generator produces: one object whose section payload carries the
//! file (the gate matrix pins the 99% payload dominance), at 1/16/64 MiB
//! payloads, with the metadata-walk control (the recorded rates' 4 KiB
//! shape) beside it.
//!
//! The benched unit is the byte-touching parse's own floor: the
//! structural walk (`pgr_format::summarize`) plus the payload stream
//! every real parse pays — the speed-of-light bound (the performance
//! architecture doc §1.1) a payload-dominated file forces. The raw walk
//! alone stays flat at ~30 ns across a 4 KiB and a 64 MiB file — that
//! flatness IS the caveat (the metadata tables are all it reads); the
//! floor rows beside it are the memory-bound rate the recorded GB/s sit
//! "well below". `Throughput::Bytes` denominates by the file's own size.

use std::hint::black_box;

use criterion::{Criterion, Throughput};
use pgr_fixtures::{CorpusPreset, CorpusSpec, build_corpus};

/// Builds one byte-touching corpus object at `text_kib` KiB of payload.
fn byte_touch_object(text_kib: usize) -> Vec<u8> {
    let spec = CorpusSpec {
        text_kib: Some(text_kib),
        ..CorpusSpec::new(CorpusPreset::ByteTouching)
    };
    let contents = build_corpus(&spec).expect("the byte-touching corpus builds");
    let (name, bytes) = &contents.files[0];
    assert_eq!(name, "obj_0001.o", "the byte-touching corpus is one object");
    assert!(
        contents.manifest.payload_bytes * 100 >= contents.manifest.file_bytes * 99,
        "the corpus is payload-dominated (the gate matrix pins the shape)"
    );
    bytes.clone()
}

/// The byte-touching parse's floor: the structural walk plus the payload
/// stream — the input bytes a real parse cannot avoid touching. The
/// stream reads word-wide (the `memcpy`-shaped floor, not a serial
/// per-byte chain) so the row prices the memory path, not an ALU bound.
fn parse_with_payload_stream(bytes: &[u8]) -> (u32, u64) {
    let summary = pgr_format::summarize(bytes).expect("the object summarizes");
    // The stream: every byte of the file, folded word-wide so the walk
    // cannot elide — the memory-bound half the floor prices.
    let (mut acc, mut bytes_left) = (0u64, bytes);
    while bytes_left.len() >= 8 {
        let (word, rest) = bytes_left.split_at(8);
        acc = acc.wrapping_add(u64::from_le_bytes(
            word.try_into().expect("the chunk is 8 bytes"),
        ));
        bytes_left = rest;
    }
    for byte in bytes_left {
        acc = acc.wrapping_add(u64::from(*byte));
    }
    black_box(acc);
    (summary.sections, summary.file_size)
}

/// Prices the byte-touching floor beside the metadata-walk control.
fn bench_parse_bytes(c: &mut Criterion) {
    let mut group = c.benchmark_group("pgr-format/parse_bytes");
    group.sample_size(20);
    for (label, text_kib) in [
        ("byte_touch_floor_1mib", 1024),
        ("byte_touch_floor_16mib", 16 * 1024),
        ("byte_touch_floor_64mib", 64 * 1024),
    ] {
        let object = byte_touch_object(text_kib);
        group.throughput(Throughput::Bytes(object.len() as u64));
        group.bench_function(label, |b| {
            b.iter(|| parse_with_payload_stream(black_box(&object)));
        });
    }
    // The control: the recorded parser rates' shape (4 KiB payload, the
    // metadata tables carrying the file) — the walk alone, the number the
    // byte-touching rows sit "well below".
    let control = CorpusSpec {
        objects: Some(1),
        ..CorpusSpec::new(CorpusPreset::ManyTiny)
    };
    let contents = build_corpus(&control).expect("the control corpus builds");
    let (_, object) = &contents.files[0];
    group.throughput(Throughput::Bytes(object.len() as u64));
    group.bench_function("metadata_control_4kib", |b| {
        b.iter(|| {
            let summary =
                pgr_format::summarize(black_box(object.as_slice())).expect("the object summarizes");
            black_box((summary.sections, summary.symbols, summary.file_size));
        });
    });
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint
/// holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_parse_bytes(&mut criterion);
    criterion.final_summary();
}
