//! The wire-tail bench (M80): the link-map tail's encode/decode price
//! over served-shape documents — a small map (the two-segment hello
//! shape) and a build-system-scale map (64 sections with their symbol
//! rows, the render the `-map` sidecar carries). The tail rides an
//! IMAGE reply that carries pages of image bytes, so the honest
//! expectation is noise beside the transfer; the gate pins the codec's
//! own price (one present byte, one length-prefixed string — the wire
//! never re-shapes the face the client writes).
//!
//! Baseline note (docs/BENCHMARKS.md): recorded as a shape gate on the
//! dev sandbox.

use criterion::{BenchmarkId, Criterion, Throughput};
use std::hint::black_box;

use pgr_daemon::protocol::{decode_map_bytes, encode_map};

/// A served-shape map document: the small link's render (the segments,
/// the sections, the few symbol rows).
fn small_map() -> String {
    "# Link map: hello (the placed image's report)\n\n\
     ## Segments\n\n\
     __TEXT: vmaddr 0x0, 16384 bytes (fileoff 0)\n\
       __text: 16 bytes at 0x4000 (2 symbols)\n\
         _main at 0x4000 (main.o)\n\
         _greet at 0x4010 (greet.o)\n\
       __cstring: 19 bytes at 0x4020\n\
     __LINKEDIT: 512 bytes (fileoff 16384)\n"
        .to_string()
}

/// A served-shape map document at the build-system scale: 64 sections
/// with their symbol rows (the repeatable `-map` contract on a real
/// link).
fn large_map() -> String {
    use std::fmt::Write as _;
    let mut s = String::from("# Link map: app (the placed image's report)\n\n## Segments\n\n");
    for i in 0..64 {
        let _ = writeln!(
            s,
            "__TEXT,__text_{}: {} bytes at 0x{:x} (2 symbols)",
            i,
            16 * (i + 1),
            0x4000 + 64 * i,
        );
        let _ = writeln!(s, "  _fn_{i} at 0x{:x} (obj_{i}.o)", 0x4000 + 64 * i);
        let _ = writeln!(s, "  _msg_{i} at 0x{:x} (obj_{i}.o)", 0x4000 + 64 * i + 8);
    }
    s.push_str("__LINKEDIT: 4096 bytes (fileoff 16384)\n");
    s
}

fn bench_wire_map(c: &mut Criterion) {
    let mut group = c.benchmark_group("wire_map");
    for (name, document) in [("small", small_map()), ("large_64_sections", large_map())] {
        group.throughput(Throughput::Bytes(document.len() as u64));
        group.bench_function(BenchmarkId::new("encode", name), |b| {
            b.iter(|| {
                let mut body = Vec::with_capacity(64 + document.len());
                encode_map(&mut body, Some(black_box(&document)));
                black_box(body.len());
            });
        });
        group.bench_function(BenchmarkId::new("decode", name), |b| {
            let mut body = Vec::with_capacity(64 + document.len());
            encode_map(&mut body, Some(&document));
            b.iter(|| {
                let back = decode_map_bytes(black_box(&body)).expect("the tail decodes");
                black_box(back.expect("the document rides"));
            });
        });
        group.bench_function(BenchmarkId::new("encode_absent", name), |b| {
            b.iter(|| {
                let mut body = Vec::with_capacity(4);
                encode_map(&mut body, None);
                black_box(body.len());
            });
        });
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_wire_map(&mut criterion);
    criterion.final_summary();
}
