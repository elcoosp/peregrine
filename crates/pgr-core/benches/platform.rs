//! The platform-floor decision bench (M10 rung 3, slice 1): the
//! consumer-facing encoding decision
//! (`pgr_core::platform::FixupEncoding::for_target`) per
//! `-platform_version` platform, benched at a fixed deployment word so
//! rotation catches a shape regression. The decision is a floor compare
//! plus its tracing event — cheap by construction, and its cost rides
//! every consumer that asks before linking; no numbers are claimed in
//! docs/BENCHMARKS.md for it. The driver `platform` bench (M10 rung 2)
//! pins the link-side matrix; this one pins the consumer seam the same
//! rung family added.

use criterion::{BenchmarkId, Criterion};
use pgr_core::platform::FixupEncoding;
use pgr_format::consts::{
    PLATFORM_IOS, PLATFORM_MACOS, PLATFORM_TVOS, PLATFORM_VISIONOS, PLATFORM_WATCHOS,
};

/// The five linked platforms (the `-platform_version` surface), names
/// as the bench ids.
const PLATFORMS: [(&str, u32); 5] = [
    ("macos", PLATFORM_MACOS),
    ("ios", PLATFORM_IOS),
    ("tvos", PLATFORM_TVOS),
    ("watchos", PLATFORM_WATCHOS),
    ("visionos", PLATFORM_VISIONOS),
];

/// The macOS floor word (12.0.0) — a fixed deployment target, so the
/// only per-row variable is the platform's own floor.
const MINOS: u32 = 0x000C_0000;

fn bench_floor(c: &mut Criterion) {
    let mut group = c.benchmark_group("platform_floor");
    for (name, platform) in PLATFORMS {
        group.bench_with_input(
            BenchmarkId::new("for_target", name),
            &platform,
            |b, &platform| {
                b.iter(|| FixupEncoding::for_target(platform, MINOS));
            },
        );
    }
    group.finish();
}

/// Bench entry point (macro-free so the workspace `missing_docs` lint holds).
fn main() {
    let mut criterion = Criterion::default().configure_from_args();
    bench_floor(&mut criterion);
    criterion.final_summary();
}
