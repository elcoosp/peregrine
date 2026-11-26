//! The §9.3 budget gate, runnable: one generated corpus swept through
//! both lanes (the measured pool and the 1-thread reference the §2.1
//! metric needs), the recorded rows priced against the budgets — the
//! serial share per pass (`flush` exempt, the plan's own exception) and
//! the parallel efficiency of Passes 1/3/4 — with the verdict rendered
//! in both faces and a synthetic breach walking the fail-the-build face.
//!
//! A build system drives this seam when it wants the §9.3 budgets *as
//! data* — the nightly's runner reports the verdict, and the calibrated
//! rig job passes `enforce` (the `xtask sweep --budgets enforce` face)
//! so a breach fails the build.
//!
//! ```sh
//! cargo run -p pgr-core --example budget_gate
//! ```

use pgr_core::budget::{RssSample, check_report, check_rss, check_sweep, peak_rss_bytes};
use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism};
use pgr_core::sweep::{SweepPlan, run_sweep};
use pgr_fixtures::corpus::{CorpusPreset, CorpusSpec, build_corpus};

fn main() {
    // The many-tiny preset (the §9.2 "50-link many tiny links" row),
    // halved for a runnable walk — the parameters are the sweep's knobs.
    let spec = CorpusSpec {
        objects: Some(16),
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
    let plan = SweepPlan {
        label: "many-tiny-16".to_string(),
        runs: 3,
    };

    // The two lanes: the measured pool beside the 1-thread reference
    // (§2.1: a one-thread run's wall is its own thread-seconds — the
    // efficiency metric's numerator).
    let measured =
        run_sweep(&inputs, &[], &cfg, Parallelism::Auto, &plan).expect("the measured lane sweeps");
    let reference = run_sweep(&inputs, &[], &cfg, Parallelism::Serial, &plan)
        .expect("the reference lane sweeps");
    let threads = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);

    // The gate prices the recorded rows — the verdict is data, the
    // breach list is the build's fail decision under `enforce`.
    let verdict = check_sweep(
        "many-tiny-16",
        &measured.summary,
        Some(&reference.summary),
        threads,
    );
    print!("{}", verdict.render());
    println!("{}", verdict.render_json());

    // The `--time` face (§9.3: "Budgets enforced from `--time` JSON
    // output"): one run's rows priced against the run's own wall.
    let report = &measured.samples[0].report;
    let run_verdict = check_report("many-tiny-16/run-0", report);
    print!("{}", run_verdict.render());

    // The output bytes the RSS ratio is priced against: the measured
    // lane's last run emits through the fused tile path (the gate's
    // product, outside the measured wall — the §2.1 denominator).
    let last = measured.samples.last().expect("the lane recorded runs");
    let image = {
        // The lane's runs share one corpus and one plan — the link's
        // own product emits through the fused tile path, the gated
        // image the walk prices the RSS ratio against.
        let result = pgr_core::link::link(&inputs, &[], &cfg).expect("the corpus links");
        pgr_emit::build_image_fused(&result.layout, &result.objects).expect("the image emits")
    };
    let _ = last;

    // The fail-the-build face over a recorded row set that earned its
    // breach: a parse owning most of the wall (the skew the budget
    // exists to name). The rows are synthetic — the arithmetic, not the
    // clock, is what this walk pins.
    let skewed = pgr_core::sweep::SweepSummary {
        runs: 3,
        median_wall_us: 1_000,
        p95_wall_us: 1_000,
        min_wall_us: 1_000,
        max_wall_us: 1_000,
        phases: vec![pgr_core::sweep::SweepPhaseRow {
            phase: pgr_core::observe::Phase::Parse,
            median_us: 900,
        }],
    };
    let breached = check_sweep("skewed-shape", &skewed, None, threads);
    assert!(!breached.is_clean(), "the 900‰ parse breaches the budget");
    assert!(
        breached.render_json().contains("\"gate\":\"serial_share\""),
        "the breach names its gate"
    );
    print!("{}", breached.render());
    println!("enforce face: the nightly's `--budgets enforce` exits non-zero on this verdict");

    // The peak-RSS row (§2.2's note — "peak RSS ≤ 2.5× output (TDD
    // §10.5)"): the process's own high-water mark (the reader records
    // `None` where the platform does not expose it — the gate never
    // guesses) priced against the gated image's byte size, the §2.1
    // metric's denominator. The measured face beside the unmeasured
    // one, both rendered.
    let peak = peak_rss_bytes();
    let rss_verdict = check_rss(peak.map(|peak_bytes| RssSample {
        peak_bytes,
        output_bytes: u64::try_from(image.len()).unwrap_or(u64::MAX),
    }));
    print!("{}", rss_verdict.render());
    println!("{}", rss_verdict.render_json());
    println!(
        "enforce face: the rig job's `--budgets enforce` counts this row's breach beside the pass rows"
    );
}
