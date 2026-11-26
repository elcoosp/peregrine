//! The sweep's verify gate (the `pgr_emit::sweep` seam) — §9.3's
//! correctness half riding the run-gate seam.
//!
//! Plan fidelity: the performance architecture doc §9.3 — "**Correctness
//! stays first:** performance jobs never gate on unverified output —
//! every benchmark link is also run through `pgr-verify`." The sweep
//! seam (`pgr_core::sweep`) runs the observed pipeline and, since its
//! run-gate seam opened, hands each run's plan to a consumer gate
//! outside the measured wall. This crate already owned the two halves
//! the gate composes — the fused emit (`crate::tile::build_image_fused`
//! turns the run's Passes-1–3 plan into the image bytes) and the strict
//! verifier (`pgr_verify`, the M73 `-verify` gate's shape) — so the
//! gate lives here, one composition, no decision copy.
//!
//! [`VerifyGate`] is the gate: per run it emits the image from the run's
//! own plan, runs the strict pass over the bytes (warnings fail, the
//! signature hash recomputed), records the run's stats (the findings,
//! the parse-derived counters, the verify wall — its own measurement,
//! never a link-wall row), and refuses with the report's own lines when
//! the image fails — the sweep aborts, the ledger never records an
//! ungated measurement. [`run_verified_sweep`] is the one-call face the
//! nightly's runner rides: the sweep, gated, the outcome and the gate's
//! stats both carried.

use std::time::Instant;

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkArchive, LinkInput, Parallelism};
use pgr_core::sweep::{SweepOutcome, SweepPlan, SweepRunGate, run_sweep_gated};
use pgr_verify::{Options, verify};

use crate::tile::build_image_fused;

/// One run's verify stats: the strict pass's findings and the
/// parse-derived counters it read, plus the verify pass's own wall.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyStat {
    /// The run the stats rode (the sweep's run order).
    pub run: usize,
    /// Error-severity findings (the strict pass refuses on any).
    pub issues: usize,
    /// Warning-severity findings (the strict pass refuses on any —
    /// `Options::strict_warnings` is the gate's shape).
    pub warnings: usize,
    /// Symbol-table entries the strict pass read (the parse-derived
    /// counter — the image was really read).
    pub symbols: u32,
    /// Fixup slots the chain-walk simulation visited.
    pub fixup_slots: u64,
    /// Page hashes the strict pass recomputed.
    pub hash_pages: u64,
    /// The verify pass's own wall (its own measurement — never a
    /// link-wall row).
    pub verify_wall: std::time::Duration,
}

/// The sweep's verify gate: every run's image rides the strict
/// verifier ([`pgr_verify::verify`]) before the measurement records —
/// §9.3's "every benchmark link is also run through `pgr-verify`". The
/// gate composes the two halves this crate owns: the run's plan emits
/// through the fused tile path, the bytes ride the strict pass, a
/// failing verdict refuses with the report's own lines.
#[derive(Debug, Clone)]
pub struct VerifyGate {
    /// The verifier's options (the strict pass's shape).
    opts: Options,
    /// One stat per gated run, in run order (a refused run records
    /// nothing — the measurement never rode an ungated image).
    stats: Vec<VerifyStat>,
}

impl VerifyGate {
    /// A gate over the given verifier options (the strict pass's shape:
    /// `Options { strict_warnings: true, skip_hash_recompute: false }`).
    #[must_use]
    pub fn new(opts: Options) -> Self {
        Self {
            opts,
            stats: Vec::new(),
        }
    }

    /// The gated runs' stats, in run order.
    #[must_use]
    pub fn stats(&self) -> &[VerifyStat] {
        &self.stats
    }

    /// The gate's per-image face: the strict pass over one image's
    /// bytes — a clean verdict records the run's stat, a failing one
    /// refuses with the report's own lines (the run named). The fused
    /// emit (`on_run`'s composition) rides this face too; the
    /// different-code-path rule (the §11 shapes) gates through here.
    ///
    /// # Errors
    /// The verifier's own lines, prefixed with the run the gate was
    /// pricing — the wording a gate exists to name.
    pub fn verify_image(&mut self, run: usize, image: &[u8]) -> Result<(), String> {
        let started = Instant::now();
        let report = verify(image, &self.opts);
        let verify_wall = started.elapsed();
        let issues = report
            .issues
            .iter()
            .filter(|i| i.severity == pgr_verify::Severity::Error)
            .count();
        let warnings = report
            .issues
            .iter()
            .filter(|i| i.severity == pgr_verify::Severity::Warning)
            .count();
        if !report.is_ok(&self.opts) {
            let mut lines = Vec::with_capacity(report.issues.len() + 1);
            for issue in &report.issues {
                let severity = match issue.severity {
                    pgr_verify::Severity::Error => "error",
                    pgr_verify::Severity::Warning => "warning",
                };
                let anchor = issue
                    .offset
                    .map(|o| format!(" at 0x{o:X}"))
                    .unwrap_or_default();
                lines.push(format!("  {severity}: {}{anchor}", issue.message));
            }
            return Err(format!(
                "the strict verifier refused the run-{run} image ({} finding(s)):\n{}",
                report.issues.len(),
                lines.join("\n")
            ));
        }
        self.stats.push(VerifyStat {
            run,
            issues,
            warnings,
            symbols: report.stats.symbols,
            fixup_slots: report.stats.fixup_slots,
            hash_pages: report.stats.hash_pages,
            verify_wall,
        });
        Ok(())
    }
}

impl SweepRunGate for VerifyGate {
    fn on_run(&mut self, run: usize, result: &pgr_core::link::LinkResult) -> Result<(), String> {
        // The run's own plan is the image's source: the fused tile emit
        // (Passes 4's product) over the Passes-1–3 plan the sweep
        // measured. An emit refusal is the gate's refusal too — the
        // image the link planned is the image that ships.
        let image = build_image_fused(&result.layout, &result.objects)
            .map_err(|e| format!("the run-{run} image's fused emit refused: {e}"))?;
        self.verify_image(run, &image)
    }
}

/// A verified sweep: the outcome the sweep recorded (the walls and the
/// reduced rows — every run's image gated) beside the gate's stats (the
/// strict pass's own record).
#[derive(Debug, Clone)]
pub struct VerifiedSweep {
    /// The sweep's measurement (every run gated).
    pub outcome: SweepOutcome,
    /// The verify gate's stats, in run order.
    pub gate: VerifyGate,
}

/// Runs the observed pipeline `plan.runs` times over one corpus with
/// [`VerifyGate`] on every run — the nightly's face: the walls and rows
/// the §9.3 nightly contract records, each run's image first ridden
/// through the strict verifier, the sweep aborting on any failing
/// verdict (the ledger never records an ungated measurement).
///
/// # Errors
/// The sweep's own refusals ([`pgr_core::sweep::SweepError::Runs`],
/// [`pgr_core::sweep::SweepError::Link`]) and the gate's
/// ([`pgr_core::sweep::SweepError::Gate`] — the strict pass's lines, the
/// run named).
pub fn run_verified_sweep(
    inputs: &[LinkInput],
    archives: &[LinkArchive],
    cfg: &LinkConfig,
    parallel: Parallelism,
    plan: &SweepPlan,
    opts: &Options,
) -> Result<VerifiedSweep, pgr_core::sweep::SweepError> {
    let mut gate = VerifyGate::new(*opts);
    let outcome = run_sweep_gated(inputs, archives, cfg, parallel, plan, &mut gate)?;
    Ok(VerifiedSweep { outcome, gate })
}
