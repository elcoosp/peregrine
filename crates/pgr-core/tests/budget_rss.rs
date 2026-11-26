//! The peak-RSS budget row (the `pgr_core::budget` seam's third gate).
//!
//! Plan fidelity: the performance architecture doc §2.2's note —
//! "Pass-level budgets (enforced in CI, Section 9.3): no single-threaded
//! section above 15% of wall except flush; parallel efficiency ≥ 70% for
//! Passes 1, 3, 4 at 8 P-cores; **peak RSS ≤ 2.5× output (TDD §10.5)**" —
//! and TDD §10.5's own table ("Peak | ≈ 2.2–2.5× output size —
//! comparable to mold's ratio"). The §2.1 metric is "Peak RSS / output
//! size". The two `--time` budgets landed with the budget gate; the
//! peak-RSS budget is the row that seam had not priced yet.
//!
//! Gate matrix:
//! * the ratio prices the plan's own arithmetic — measured peak over
//!   output bytes, integer permille (no floats), breaching only over the
//!   2.5× limit (at the limit is clean);
//! * the gate never guesses — an unmeasured peak, a missing output size
//!   or a zero denominator records `None`, never a fabricated ratio
//!   (an unmeasurable gate is not a breach);
//! * the faces are the M55/M58 conventions — a deterministic text line
//!   and a one-line JSON interchange, fixed key order, whole numbers;
//! * the reader is honest — `peak_rss_bytes()` reads the process's own
//!   high-water mark where the platform exposes it (Linux `/proc`,
//!   `VmHWM`) and records `None` where it does not (the rig's numbers
//!   own macOS).

use pgr_core::budget::{RssSample, check_rss, peak_rss_bytes};

// ---- the ratio prices the plan's own arithmetic (§2.2 + §10.5) --------

/// §2.2's note, as a gate: "**peak RSS ≤ 2.5× output (TDD §10.5)**" —
/// the measured peak over the output's bytes, integer permille,
/// breaching only over the limit (at the limit is clean).
#[test]
fn rss_budget_prices_the_plan_ratio() {
    // 2.5× exactly — the budget's boundary is clean ("≤ 2.5×").
    let at_limit = check_rss(Some(RssSample {
        peak_bytes: 2500,
        output_bytes: 1_000,
    }));
    assert_eq!(at_limit.ratio_permille, Some(2500));
    assert!(!at_limit.breach, "at the limit is not a breach");

    // One permille over — the breach names the arithmetic.
    let over = check_rss(Some(RssSample {
        peak_bytes: 2501,
        output_bytes: 1_000,
    }));
    assert_eq!(over.ratio_permille, Some(2501));
    assert!(over.breach, "over the limit is a breach");

    // Comfortably under — clean.
    let under = check_rss(Some(RssSample {
        peak_bytes: 2_000_000,
        output_bytes: 1_000_000,
    }));
    assert_eq!(under.ratio_permille, Some(2000));
    assert!(!under.breach);
}

// ---- the gate never guesses (the budget seam's honesty convention) ----

#[test]
fn unmeasured_is_not_a_breach() {
    let verdict = check_rss(None);
    assert_eq!(verdict.ratio_permille, None, "no sample — no ratio");
    assert!(!verdict.breach, "an unmeasurable gate is not a breach");
}

#[test]
fn zero_output_is_unmeasured() {
    let verdict = check_rss(Some(RssSample {
        peak_bytes: 100,
        output_bytes: 0,
    }));
    assert_eq!(
        verdict.ratio_permille, None,
        "a zero denominator prices None, never a fabricated ratio"
    );
    assert!(!verdict.breach);
}

#[test]
fn zero_peak_is_unmeasured() {
    // A zero peak is the reader's "unavailable" face — pricing it would
    // fabricate a 0‰ ratio from nothing.
    let verdict = check_rss(Some(RssSample {
        peak_bytes: 0,
        output_bytes: 1_000,
    }));
    assert_eq!(verdict.ratio_permille, None);
    assert!(!verdict.breach);
}

// ---- the faces are the M55/M58 conventions -----------------------------

#[test]
fn the_faces_render_both_states() {
    let measured = check_rss(Some(RssSample {
        peak_bytes: 1_800_000,
        output_bytes: 1_000_000,
    }));
    let text = measured.render();
    assert!(
        text.contains("peak rss") && text.contains("1800 permille"),
        "the text face names the gate and the ratio: {text}"
    );
    assert!(text.contains("ok"), "the clean row says so: {text}");
    let json = measured.render_json();
    assert_eq!(
        json, "{\"peak_rss\":{\"ratio_permille\":1800,\"breach\":false}}",
        "the JSON face is the fixed-key one-line interchange: {json}"
    );

    let unmeasured = check_rss(None);
    let text = unmeasured.render();
    assert!(
        text.contains("not measured"),
        "the unmeasured face says so: {text}"
    );
    assert_eq!(
        unmeasured.render_json(),
        "{\"peak_rss\":null}",
        "the unmeasured JSON face is null"
    );
}

// ---- the reader is honest ----------------------------------------------

#[test]
fn the_reader_reads_this_process_or_records_none() {
    match peak_rss_bytes() {
        Some(peak) => {
            assert!(peak > 0, "the high-water mark is a measurement");
            // The process's own peak is at least the test binary's
            // resident set — a few MiB — and stays inside the machine.
            assert!(
                peak > 1_000_000,
                "VmHWM covers the whole process: {peak} bytes"
            );
        }
        None => {
            // The reader is honest where the platform does not expose
            // the high-water mark (non-Linux) — never a fabricated
            // zero.
            #[cfg(target_os = "linux")]
            panic!("Linux exposes VmHWM — the reader must read it");
            #[cfg(not(target_os = "linux"))]
            let _ = ();
        }
    }
}
