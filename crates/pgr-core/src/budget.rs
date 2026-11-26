//! The §9.3 budget gate (the `pgr_core::budget` seam) — the measurement
//! infrastructure's enforcement half.
//!
//! Plan fidelity: the performance architecture doc §9.3 — "**Budgets
//! enforced from `--time` JSON output:** per-pass wall, thread-seconds,
//! parallel efficiency; fail the build if the single-threaded fraction
//! exceeds 15% (except flush) or parallel efficiency drops below 70% on
//! Passes 1/3/4." — restated by §2.2 ("Pass-level budgets (enforced in
//! CI, Section 9.3): no single-threaded section above 15% of wall except
//! flush; parallel efficiency ≥ 70% for Passes 1, 3, 4 at 8 P-cores")
//! and docs/BENCHMARKS.md's "Budgets land in CI as they ship" row. The
//! sweep seam ([`crate::sweep`]) reduced and stored the nightly's rows
//! (the median/p95 half of the same section); this module is the budget
//! arithmetic the same rows feed.
//!
//! Two faces, one arithmetic:
//!
//! * **The sweep face** ([`check_sweep`]) prices the nightly's reduced
//!   rows: the measured lane's [`crate::sweep::SweepSummary`] against
//!   the wall it recorded, with the optional 1-thread reference run
//!   (the §2.1 metric's "thread-seconds at 1 thread" — a one-thread
//!   run's wall *is* its thread-seconds) beside it for the efficiency
//!   half.
//! * **The `--time` face** ([`check_report`]) prices one run's rows —
//!   the driver's report is the plan's named source — against the run's
//!   own wall (the total band when the caller measured it, the measured
//!   rows plus the emit band otherwise: the share column's own rule).
//!
//! The arithmetic is integer permille end to end (the time-report share
//! column's rule — no float rounding rides a gate), and the gate never
//! guesses: a pass one lane never reported, a zero wall on either side
//! or a zero-thread pool records an unmeasured row (`None`), never a
//! fabricated ratio — an unmeasurable gate is not a breach (the §9.1
//! rig job measures what a dev-class runner cannot; the honest runner
//! reports, the calibrated job enforces).
//!
//! The faces are the M55/M58 conventions: a deterministic text table a
//! build system can diff line by line, and a one-line JSON interchange
//! (fixed key order, whole numbers, the report-JSON escape rules).

use std::fmt::Write as _;

use crate::observe::Phase;
use crate::sweep::SweepSummary;
use crate::time_report::TimeReport;

/// The serial-fraction budget, in permille of the wall (§9.3: "fail the
/// build if the single-threaded fraction exceeds 15% (except flush)").
pub const SERIAL_SHARE_PERMILLE_MAX: u32 = 150;

/// The parallel-efficiency floor, in permille (§9.3: "parallel
/// efficiency drops below 70% on Passes 1/3/4"; the §2.1 metric).
pub const PARALLEL_EFFICIENCY_PERMILLE_MIN: u32 = 700;

/// One measured row's serial-fraction check: the row's median wall, its
/// share of the run's wall in permille, and the flag the budget
/// computes. The `flush` row rides with the flag always `false` — the
/// plan's own exception ("except flush": the pooled write is the wall's
/// tail by design), still counted in the denominator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerialShareRow {
    /// The phase (the M54 vocabulary — [`Phase::as_str`] is the token).
    pub phase: Phase,
    /// The row's median wall in µs (the summary's, verbatim).
    pub median_us: u64,
    /// The row's share of the run's wall, in integer permille.
    pub share_permille: u32,
    /// Whether the share exceeds [`SERIAL_SHARE_PERMILLE_MAX`] (`flush`
    /// is exempt — always `false` there).
    pub breach: bool,
}

/// One gated pass's parallel-efficiency check. `None` is "not
/// measurable" — the 1-thread reference never rode, the pass's row is
/// absent from a lane, a wall is zero, or the pool size is zero —
/// recorded, never guessed, and never a breach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EfficiencyRow {
    /// The phase (the M54 vocabulary — [`Phase::as_str`] is the token).
    pub phase: Phase,
    /// The §2.1 metric in integer permille: the 1-thread wall over
    /// N × the N-thread wall, when both lanes measured the pass.
    pub efficiency_permille: Option<u32>,
    /// Whether a measured ratio fell under
    /// [`PARALLEL_EFFICIENCY_PERMILLE_MIN`] (`false` when unmeasured).
    pub breach: bool,
}

/// What a breach broke: the gate, the measured value and the budget it
/// broke — the fix is the named budget, the value the evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreachKind {
    /// The serial-fraction gate: the row's share of the wall exceeded
    /// the limit (flush exempt).
    SerialShare {
        /// The measured share, in permille of the wall.
        share_permille: u32,
        /// The budget it broke ([`SERIAL_SHARE_PERMILLE_MAX`]).
        limit_permille: u32,
    },
    /// The parallel-efficiency gate: the pass's §2.1 ratio fell under
    /// the floor.
    ParallelEfficiency {
        /// The measured ratio, in permille.
        efficiency_permille: u32,
        /// The floor it broke ([`PARALLEL_EFFICIENCY_PERMILLE_MIN`]).
        floor_permille: u32,
    },
}

/// One breach: the phase and the gate it broke. A phase breaching both
/// gates rides two entries (each gate names its own evidence).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetBreach {
    /// The phase that breached (the M54 vocabulary).
    pub phase: Phase,
    /// The gate, the measured value and the budget.
    pub kind: BreachKind,
}

/// The budget verdict over one measured lane (and, when it rode, the
/// 1-thread reference beside it): every check's rows plus the breaches
/// the build fails on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetReport {
    /// The shape's name (the plan's label), verbatim.
    pub label: String,
    /// The measured lane's pool size — `None` on the report face (one
    /// run rode, no lane size is known to the rows).
    pub threads: Option<usize>,
    /// One row per measured phase, link order, `flush` exempt in place.
    pub serial_rows: Vec<SerialShareRow>,
    /// One row per gated pass the measured lane reported (link order).
    pub efficiency_rows: Vec<EfficiencyRow>,
    /// The breaches — empty when the budget holds.
    pub breaches: Vec<BudgetBreach>,
}

/// The passes the efficiency gate prices: §9.3's "Passes 1/3/4" in the
/// M54 vocabulary — the parse, archive-pull and intern rows are Pass 1's
/// bodies, layout is Pass 3's, emit is Pass 4's (the row the driver's
/// emit half reports since M68). Pass 2's resolve, the ladder's rows and
/// the flush are the gate's honest absences.
const EFFICIENCY_GATED: &[Phase] = &[
    Phase::Parse,
    Phase::ArchivePull,
    Phase::Intern,
    Phase::Layout,
    Phase::Emit,
];

/// The permille ratio of one wall over another, in integer permille —
/// the shared arithmetic of both gates (the time-report share column's
/// rule: `u128` intermediates, no float rounding). A zero denominator
/// prices as zero rather than dividing by zero.
fn permille(of_us: u64, wall_us: u128) -> u32 {
    if wall_us == 0 {
        return 0;
    }
    u32::try_from(u128::from(of_us) * 1_000 / wall_us).unwrap_or(u32::MAX)
}

impl BudgetReport {
    /// Whether the budget holds (no breach rode). An unmeasurable gate
    /// is not a breach — the verdict is honest about what it could not
    /// price, and the rig job measures the rest.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.breaches.is_empty()
    }

    /// Renders the verdict as the deterministic text table: the header
    /// (label, lane size, the clean/dirty word), the serial shares, the
    /// efficiency rows (or the honest absence line on the report face),
    /// then one line per breach — a build system can diff two verdicts'
    /// shapes line by line (the values are measurements; the rows and
    /// columns are not).
    #[must_use]
    pub fn render(&self) -> String {
        let mut s =
            String::with_capacity(160 + (self.serial_rows.len() + self.efficiency_rows.len()) * 48);
        let threads = match self.threads {
            Some(n) => format!("{n} threads"),
            None => "one report".to_string(),
        };
        let _ = writeln!(
            s,
            "budget verdict: {} ({}) — {}",
            self.label,
            threads,
            if self.is_clean() { "clean" } else { "DIRTY" }
        );
        let _ = writeln!(
            s,
            "  serial share (limit {SERIAL_SHARE_PERMILLE_MAX} permille, flush exempt):"
        );
        for row in &self.serial_rows {
            let _ = writeln!(
                s,
                "    {:<14} {:>6} permille  {}",
                row.phase.as_str(),
                row.share_permille,
                if row.breach { "OVER" } else { "ok" }
            );
        }
        if self.threads.is_none() {
            let _ = writeln!(
                s,
                "  parallel efficiency: not priced (one report rode — the 1-thread reference is the rig job's)"
            );
        } else {
            let _ = writeln!(
                s,
                "  parallel efficiency (floor {PARALLEL_EFFICIENCY_PERMILLE_MIN} permille, Passes 1/3/4):"
            );
            for row in &self.efficiency_rows {
                let (value, word) = match row.efficiency_permille {
                    Some(permille) => (
                        format!("{permille:>6} permille"),
                        if row.breach { "OVER" } else { "ok" }.to_string(),
                    ),
                    None => ("     -".to_string(), "n/a".to_string()),
                };
                let _ = writeln!(s, "    {:<14} {}  {}", row.phase.as_str(), value, word);
            }
        }
        if self.breaches.is_empty() {
            let _ = writeln!(s, "  breaches: none");
        } else {
            let _ = writeln!(s, "  breaches:");
            for breach in &self.breaches {
                let _ = writeln!(s, "    {}", breach_line(breach));
            }
        }
        s
    }

    /// Renders the verdict as the one-line JSON interchange: fixed key
    /// order (label, threads, clean, serial rows, efficiency rows,
    /// breaches), whole numbers only, the report-JSON escape rules.
    #[must_use]
    pub fn render_json(&self) -> String {
        let mut s = String::with_capacity(
            96 + (self.serial_rows.len() + self.efficiency_rows.len() + self.breaches.len()) * 64,
        );
        let _ = write!(
            s,
            "{{\"label\":{},\"threads\":",
            crate::map::escape_json(&self.label)
        );
        match self.threads {
            Some(n) => {
                let _ = write!(s, "{n}");
            }
            None => {
                s.push_str("null");
            }
        }
        let _ = write!(s, ",\"clean\":{},\"serial_rows\":[", self.is_clean());
        for (i, row) in self.serial_rows.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let _ = write!(
                s,
                "{{\"phase\":\"{}\",\"median_us\":{},\"share_permille\":{},\"breach\":{}}}",
                row.phase.as_str(),
                row.median_us,
                row.share_permille,
                row.breach
            );
        }
        s.push_str("],\"efficiency_rows\":[");
        for (i, row) in self.efficiency_rows.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let _ = write!(
                s,
                "{{\"phase\":\"{}\",\"efficiency_permille\":",
                row.phase.as_str()
            );
            match row.efficiency_permille {
                Some(permille) => {
                    let _ = write!(s, "{permille}");
                }
                None => {
                    s.push_str("null");
                }
            }
            let _ = write!(s, ",\"breach\":{}}}", row.breach);
        }
        s.push_str("],\"breaches\":[");
        for (i, breach) in self.breaches.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let _ = write!(
                s,
                "{{\"phase\":\"{}\",\"gate\":\"{}\",\"measured_permille\":{},\"budget_permille\":{}}}",
                breach.phase.as_str(),
                match breach.kind {
                    BreachKind::SerialShare { .. } => "serial_share",
                    BreachKind::ParallelEfficiency { .. } => "parallel_efficiency",
                },
                match breach.kind {
                    BreachKind::SerialShare { share_permille, .. } => share_permille,
                    BreachKind::ParallelEfficiency {
                        efficiency_permille,
                        ..
                    } => efficiency_permille,
                },
                match breach.kind {
                    BreachKind::SerialShare { limit_permille, .. } => limit_permille,
                    BreachKind::ParallelEfficiency { floor_permille, .. } => floor_permille,
                },
            );
        }
        s.push_str("]}");
        s
    }
}

/// The breach's one-line text face (the table's breach lines and the
/// fix-naming wording the refusals carry).
fn breach_line(breach: &BudgetBreach) -> String {
    match breach.kind {
        BreachKind::SerialShare {
            share_permille,
            limit_permille,
        } => format!(
            "{}: share {share_permille} permille > {limit_permille} permille (flush exempt)",
            breach.phase.as_str()
        ),
        BreachKind::ParallelEfficiency {
            efficiency_permille,
            floor_permille,
        } => format!(
            "{}: efficiency {efficiency_permille} permille < {floor_permille} permille",
            breach.phase.as_str()
        ),
    }
}

/// Prices one measured lane's reduced rows against the §9.3 budgets: the
/// serial-fraction gate over every measured phase (flush exempt in
/// place, still counted in the wall denominator) and — when the 1-thread
/// reference rode — the parallel-efficiency gate over the gated passes
/// both lanes reported. `threads` is the measured lane's pool size (≥ 1;
/// a zero pool measures nothing). The gate never guesses: an unmeasured
/// pass, a zero wall or a zero pool records `None`, never a ratio.
#[must_use]
pub fn check_sweep(
    label: &str,
    parallel: &SweepSummary,
    serial_reference: Option<&SweepSummary>,
    threads: usize,
) -> BudgetReport {
    let mut report = BudgetReport {
        label: label.to_string(),
        threads: Some(threads),
        serial_rows: Vec::with_capacity(parallel.phases.len()),
        efficiency_rows: Vec::with_capacity(EFFICIENCY_GATED.len()),
        breaches: Vec::new(),
    };
    // The serial-fraction gate: one row per measured phase, link order;
    // the wall denominator is the run's own median wall.
    for row in &parallel.phases {
        let share = permille(row.median_us, u128::from(parallel.median_wall_us));
        let exempt = row.phase == Phase::Flush;
        let breach = !exempt && share > SERIAL_SHARE_PERMILLE_MAX;
        report.serial_rows.push(SerialShareRow {
            phase: row.phase,
            median_us: row.median_us,
            share_permille: share,
            breach,
        });
        if breach {
            report.breaches.push(BudgetBreach {
                phase: row.phase,
                kind: BreachKind::SerialShare {
                    share_permille: share,
                    limit_permille: SERIAL_SHARE_PERMILLE_MAX,
                },
            });
        }
    }
    // The parallel-efficiency gate: the gated passes the measured lane
    // reported, in its own order, priced against the reference when it
    // rode (§2.1: the 1-thread wall over N × the N-thread wall).
    for row in &parallel.phases {
        if !EFFICIENCY_GATED.contains(&row.phase) {
            continue;
        }
        let measured = match serial_reference {
            Some(reference) => reference.phases.iter().find(|r| r.phase == row.phase),
            None => None,
        };
        let efficiency = match (measured, threads) {
            (Some(m), t) if m.median_us > 0 && row.median_us > 0 && t > 0 => {
                let pool_threads = u64::try_from(t).unwrap_or(u64::MAX);
                let pool_wall = u128::from(pool_threads) * u128::from(row.median_us);
                Some(permille(m.median_us, pool_wall))
            }
            _ => None,
        };
        let breach = efficiency.is_some_and(|e| e < PARALLEL_EFFICIENCY_PERMILLE_MIN);
        report.efficiency_rows.push(EfficiencyRow {
            phase: row.phase,
            efficiency_permille: efficiency,
            breach,
        });
        if let Some(permille_value) = efficiency.filter(|e| *e < PARALLEL_EFFICIENCY_PERMILLE_MIN) {
            report.breaches.push(BudgetBreach {
                phase: row.phase,
                kind: BreachKind::ParallelEfficiency {
                    efficiency_permille: permille_value,
                    floor_permille: PARALLEL_EFFICIENCY_PERMILLE_MIN,
                },
            });
        }
    }
    report
}

/// Prices one run's `--time` rows against the serial-fraction budget —
/// the plan's named source ("Budgets enforced from `--time` JSON
/// output"). The denominator is the run's own wall: the total band when
/// the caller measured it, the measured rows plus the emit band
/// otherwise (the share column's own rule). The efficiency half needs
/// the 1-thread reference beside this run, so the report face carries
/// none — the sweep face prices it.
#[must_use]
pub fn check_report(label: &str, report: &TimeReport) -> BudgetReport {
    let rows_us: u64 = report
        .phases
        .iter()
        .map(|e| u64::try_from(e.elapsed.as_micros()).unwrap_or(u64::MAX))
        .sum();
    let emit_us = report
        .emit
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX));
    let wall_us = report.total.map_or(rows_us.saturating_add(emit_us), |d| {
        u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
    });
    let mut verdict = BudgetReport {
        label: label.to_string(),
        threads: None,
        serial_rows: Vec::with_capacity(report.phases.len()),
        efficiency_rows: Vec::new(),
        breaches: Vec::new(),
    };
    for event in &report.phases {
        let event_us = u64::try_from(event.elapsed.as_micros()).unwrap_or(u64::MAX);
        let share = permille(event_us, u128::from(wall_us));
        let exempt = event.phase == Phase::Flush;
        let breach = !exempt && share > SERIAL_SHARE_PERMILLE_MAX;
        verdict.serial_rows.push(SerialShareRow {
            phase: event.phase,
            median_us: event_us,
            share_permille: share,
            breach,
        });
        if breach {
            verdict.breaches.push(BudgetBreach {
                phase: event.phase,
                kind: BreachKind::SerialShare {
                    share_permille: share,
                    limit_permille: SERIAL_SHARE_PERMILLE_MAX,
                },
            });
        }
    }
    verdict
}
