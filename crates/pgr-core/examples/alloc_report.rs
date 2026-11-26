//! The §9.3 per-PR allocation-count seam, runnable: one generated corpus
//! linked through the observed pipeline, both measurement faces riding
//! the one event stream (the M61 observer-pair shape — the time report
//! beside the allocation report), the per-pass allocation windows
//! rendered in both faces, and the DHAT document written beside them —
//! the valgrind-class tooling §9.3 names, its in-process Rust face.
//!
//! A build system drives this seam when it wants the §9.3 allocation
//! counts *as data* — the per-PR job reports the per-pass rows, the
//! nightly's alloc lane stores them, and the DHAT document is the
//! viewer's own artifact (open it in `dh_view.html` for the tree the
//! totals come from).
//!
//! ```sh
//! cargo run -p pgr-core --example alloc_report
//! ```

/// The example's global allocator: the DHAT seat (the §9.3 seat the
/// measurement binaries install). The profiler below is the recording
/// window.
#[global_allocator]
static DHAT: dhat::Alloc = dhat::Alloc;

use pgr_core::alloc_count::{AllocCollector, AllocSnapshot, AllocSource};
use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism};
use pgr_core::observe::{ObserverPair, TracingObserver};
use pgr_core::time_report::TimeCollector;
use pgr_fixtures::corpus::{CorpusPreset, CorpusSpec, build_corpus};

/// The DHAT seat's bridge — the seat consumer's own glue (the library
/// never links DHAT: the driver's dependency surface stays lean, perf
/// doc §8; the counting `unsafe` lives inside the seat crate, the
/// tree's `unsafe_code = "forbid"` gate stays intact). This file's
/// bridge is the copy the walk owns.
struct DhatSource;

impl AllocSource for DhatSource {
    fn sample(&self) -> AllocSnapshot {
        let stats = dhat::HeapStats::get();
        AllocSnapshot {
            blocks: stats.total_blocks,
            bytes: stats.total_bytes,
        }
    }
}

fn main() {
    // The many-tiny preset, quartered for a runnable walk — the
    // parameters are the sweep's knobs.
    let spec = CorpusSpec {
        objects: Some(8),
        ..CorpusSpec::new(CorpusPreset::ManyTiny)
    };
    let contents = build_corpus(&spec).expect("the corpus builds");
    let inputs: Vec<LinkInput> = contents
        .files
        .iter()
        .map(|(name, bytes)| LinkInput {
            name: name.clone(),
            bytes: bytes.clone(),
        })
        .collect();
    let cfg = LinkConfig {
        filetype: OutputType::Execute,
        ..LinkConfig::default()
    };

    // The recording window: the DHAT seat counts from here to the end
    // of `main` (the link's allocations inside it, the backtrace tree
    // the document carries included — the counted lane's own price).
    // The document writes to the temp dir, never the working tree.
    let document = std::env::temp_dir().join("pgr-alloc-report-dhat.json");
    let profiler = dhat::Profiler::builder().file_name(&document).build();

    // One observed run, both measurement faces (the M61 pair — the
    // time collector beside the allocation collector, one event
    // stream). The tracing bridge rides too, inert until a subscriber
    // installs: the house convention.
    let mut time = TimeCollector::default();
    let source = DhatSource;
    let mut allocs = AllocCollector::new(&source);
    let mut pair = ObserverPair::new(&mut time, &mut allocs);
    let mut tracing = TracingObserver;
    let mut both = ObserverPair::new(&mut pair, &mut tracing);
    let result = pgr_core::link_observed(&inputs, &[], &cfg, Parallelism::Auto, None, &mut both)
        .expect("the corpus links");
    let report = time.report();
    let allocations = allocs.finish();

    println!("{}", report.render());
    print!("{}", allocations.render());
    println!("{}", allocations.render_json());
    println!(
        "the plan's whole image: {} bytes — the counts above are the windows it was built in",
        result.layout.file_size
    );

    // The profiler drops: the DHAT document writes (the stderr summary
    // beside it — the seat's own report), the viewer's artifact.
    drop(profiler);
    println!("the DHAT document: {}", document.display());
}
