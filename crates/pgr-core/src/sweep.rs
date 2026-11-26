//! The shape-sweep harness (the `pgr_core::sweep` seam) — the nightly's
//! measurement core.
//!
//! Plan fidelity: docs/BENCHMARKS.md, "How to read these numbers" —
//! "**Known follow-ups**: … parameterized corpus generator behind an
//! `xtask` for nightly shape sweeps" — the generator
//! (the `pgr_fixtures::corpus` seam) and the `xtask`
//! `corpus` command landed; this module is the sweep they drive. The
//! acceptance contract is the performance architecture doc §9.3: "Nightly
//! (wall-clock, dedicated hardware): full corpus, 10 runs, median and
//! p95, vs baselines. Results stored and charted." — and §9.2's
//! "Baselines to run on every rig … commit the harness".
//!
//! The seam runs the observed pipeline ([`crate::link::link_observed`],
//! the M54 seam) `runs` times over one corpus, records each run's wall
//! and its own per-pass [`crate::time_report::TimeReport`], and reduces
//! the run set with the §9.3 arithmetic: the **median** is the lower
//! middle of the sorted walls (index `(n-1)/2` — integer-exact, no float
//! rounding), the **p95** is the nearest-rank element (`ceil(95·n/100)`,
//! 1-based). The same rules reduce every phase's per-run walls, in the
//! phases' first-seen (link) order — the §9.3 budgets' per-pass rows.
//! The reduction is pure: given the same recorded runs it answers the
//! same summary, so a gate can pin it without a clock.
//!
//! The stored face is the ledger ([`SweepOutcome::render_json`] /
//! [`ledger_json`] / [`write_ledger`]): one deterministic JSON line, the
//! M55/M58 interchange conventions (fixed key order, whole-microsecond
//! walls, the report-JSON escape rules), written with the strict reader
//! [`parse_ledger`] restoring it exactly — the round-trip convention the
//! map and time-report faces ride. A corrupt or hand-edited ledger
//! refuses with the byte position named; the file face refuses an
//! existing ledger (the nightly job writes one per-shape path per run —
//! a second write to the same path is a mistake, never an append).
//!
//! The comparison face is the delta ([`SweepDelta::between`], the §9.3
//! "vs baselines" half): the previous nightly's stored ledger beside the
//! current one's, the bands and the per-phase rows paired by token, the
//! moves in signed permille — integer math, no float rounding (the
//! time-report share column's rule). The render faces are the chart's
//! input; the labels must match, a cross-shape comparison refusing with
//! both names.

use std::fmt::Write as _;
use std::path::Path;
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::layout::LinkConfig;
use crate::link::{LinkArchive, LinkInput, LinkResult, Parallelism, link_observed};
use crate::observe::Phase;
use crate::time_report::{TimeCollector, TimeReport};

use crate::LinkError;

/// The sweep's plan: the shape's label and the run count. The §9.3
/// nightly contract names ten runs; the harness takes any count ≥ 1 (a
/// gate pins the reduction at one, ten and twenty-one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepPlan {
    /// The shape's name — the preset (and overrides) the corpus rode,
    /// rendered verbatim in the ledger.
    pub label: String,
    /// The run count (≥ 1 — zero refuses with the fix).
    pub runs: usize,
}

/// One recorded run: the pipeline's wall time and the per-pass report
/// the run's own [`TimeCollector`] kept (the M54 seam's rows — the sweep
/// adds nothing the pipeline did not report).
#[derive(Debug, Clone)]
pub struct SweepSample {
    /// The run's wall clock (Passes 1–3, the observed pipeline).
    pub wall: Duration,
    /// The per-pass rows the run reported.
    pub report: TimeReport,
}

/// One phase's reduced row: the phase and its per-run median wall, in
/// whole microseconds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepPhaseRow {
    /// The phase (the M54 vocabulary — [`Phase::as_str`] is the token).
    pub phase: Phase,
    /// The phase's per-run median wall, in µs.
    pub median_us: u64,
}

/// The run set's reduction: the §9.3 face of the sweep — median and p95
/// walls plus one reduced row per phase, in link order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SweepSummary {
    /// The runs the reduction read.
    pub runs: usize,
    /// The median run wall, in µs (the lower middle of the sorted walls).
    pub median_wall_us: u64,
    /// The nearest-rank p95 run wall, in µs.
    pub p95_wall_us: u64,
    /// The fastest run wall, in µs.
    pub min_wall_us: u64,
    /// The slowest run wall, in µs.
    pub max_wall_us: u64,
    /// One row per phase, in first-seen (link) order.
    pub phases: Vec<SweepPhaseRow>,
}

/// The stored face: the label, the run count and the summary — the data
/// [`parse_ledger`] restores from the JSON line the writer emits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepLedger {
    /// The shape's name, verbatim.
    pub label: String,
    /// The run count.
    pub runs: usize,
    /// The reduced summary.
    pub summary: SweepSummary,
}

/// A swept corpus: every run's sample (the wall and the run's own
/// per-pass report) plus the reduction over the run set.
#[derive(Debug, Clone)]
pub struct SweepOutcome {
    /// The shape's name (the plan's label).
    pub label: String,
    /// The run count (the plan's).
    pub runs: usize,
    /// One sample per run, in run order.
    pub samples: Vec<SweepSample>,
    /// The reduction over the samples (the §9.3 face).
    pub summary: SweepSummary,
}

/// The sweep's refusals: the plan's shape, the pipeline's own, the file
/// face's, and the ledger reader's (byte-positioned, the map reader's
/// convention).
#[derive(Debug, Error)]
pub enum SweepError {
    /// The plan carries zero runs — the nightly's contract is runs ≥ 1.
    #[error(
        "the sweep plans {runs} runs — plan at least one run (the §9.3 nightly contract is 10)"
    )]
    Runs {
        /// The refused count.
        runs: usize,
    },
    /// A sweep run's link refused (the pipeline's own wording).
    #[error("the sweep's link refused: {0}")]
    Link(#[from] LinkError),
    /// The ledger file could not be written.
    #[error("the sweep ledger at {path}: {source}")]
    Io {
        /// The path the write refused.
        path: String,
        /// The filesystem's own refusal.
        #[source]
        source: std::io::Error,
    },
    /// The ledger path already exists — the nightly writes one
    /// per-shape path per run, so a second write is a mistake.
    #[error("the sweep ledger {path} already exists — write to a fresh per-shape path")]
    Exists {
        /// The refused path.
        path: String,
    },
    /// The ledger JSON is not the shape the writer emits, at `at`.
    #[error("invalid sweep-ledger JSON at byte {at}: {detail}")]
    Ledger {
        /// The byte the reader refused.
        at: usize,
        /// What the reader expected there.
        detail: String,
    },
    /// A corpus archive refused the format reader's parse (the reader's
    /// own wording, the archive named).
    #[error("the sweep's archive {name}: {source}")]
    Archive {
        /// The archive file's name.
        name: String,
        /// The format reader's refusal.
        #[source]
        source: pgr_format::FormatError,
    },
    /// A run's gate refused (the consumer gate's own wording, the run
    /// named — §9.3's correctness half: the sweep never records an
    /// ungated measurement).
    #[error("the sweep's run-{run} gate refused: {reason}")]
    Gate {
        /// The run the gate refused.
        run: usize,
        /// The gate's own wording, verbatim.
        reason: String,
    },
    /// The two ledgers name different shapes — a cross-shape comparison
    /// is a caller mistake (the delta pairs one shape's own history).
    #[error(
        "the sweep ledgers name different shapes ({previous:?} vs {current:?}) — compare one shape's own history"
    )]
    LabelsDiffer {
        /// The previous ledger's label.
        previous: String,
        /// The current ledger's label.
        current: String,
    },
}

/// The wall's whole microseconds (the interchange's unit — the
/// `time_report` JSON face's own convention).
fn wall_us(d: Duration) -> u64 {
    (d.as_nanos() / 1_000) as u64
}

/// The sorted run set's lower median: index `(n-1)/2` of the ascending
/// walls — integer-exact, no float rounding (an even count takes the
/// lower of the two middles).
fn lower_median(sorted: &[u64]) -> u64 {
    sorted[(sorted.len() - 1) / 2]
}

/// The sorted run set's nearest-rank p95: element `ceil(95·n/100)`
/// (1-based) of the ascending walls — integer math over the rank ceil.
fn nearest_rank_p95(sorted: &[u64]) -> u64 {
    let rank = (95 * sorted.len()).div_ceil(100).max(1);
    sorted[rank - 1]
}

/// Reduces recorded runs into the §9.3 summary: the median and p95 walls
/// plus one reduced row per phase. The phases group in first-seen order
/// (a run's rows are the M54 seam's — link order), each phase's per-run
/// walls reduced with the same lower-median rule. Pure: the same samples
/// answer the same summary.
#[must_use]
pub fn reduce(label: &str, samples: &[SweepSample]) -> SweepSummary {
    let _ = label;
    let mut walls: Vec<u64> = samples.iter().map(|s| wall_us(s.wall)).collect();
    walls.sort_unstable();
    let mut phases: Vec<Phase> = Vec::new();
    let mut per_phase: Vec<Vec<u64>> = Vec::new();
    for s in samples {
        for e in &s.report.phases {
            if let Some(i) = phases.iter().position(|p| *p == e.phase) {
                per_phase[i].push(wall_us(e.elapsed));
            } else {
                phases.push(e.phase);
                per_phase.push(vec![wall_us(e.elapsed)]);
            }
        }
    }
    let rows = phases
        .drain(..)
        .zip(per_phase.drain(..))
        .map(|(phase, mut walls)| {
            walls.sort_unstable();
            SweepPhaseRow {
                phase,
                median_us: lower_median(&walls),
            }
        })
        .collect();
    SweepSummary {
        runs: samples.len(),
        median_wall_us: lower_median(&walls),
        p95_wall_us: nearest_rank_p95(&walls),
        min_wall_us: walls.first().copied().unwrap_or(0),
        max_wall_us: walls.last().copied().unwrap_or(0),
        phases: rows,
    }
}

/// Projects one corpus archive file onto the pipeline's
/// [`LinkArchive`] input — the ranlib table parsed (the S7 pull's own
/// index), the members carried raw, the pull deciding liveness. The
/// §9.2 archive-heavy row's file rides this projection, never the
/// direct inputs (an archive is not a Mach-O object — the parse
/// refusing it is the fix the projection exists to prevent).
///
/// # Errors
/// [`SweepError::Archive`] when the format reader refuses the bytes.
pub fn archive_input(name: &str, bytes: Vec<u8>) -> Result<LinkArchive, SweepError> {
    let parsed = pgr_format::parse_archive(&bytes).map_err(|source| SweepError::Archive {
        name: name.to_string(),
        source,
    })?;
    Ok(LinkArchive {
        name: name.to_string(),
        bytes,
        index: parsed
            .index
            .iter()
            .map(|e| (e.name.clone().into_bytes(), e.member))
            .collect(),
        members: parsed
            .members
            .iter()
            .map(|m| crate::LinkArchiveMember {
                name: m.name.clone(),
                offset: m.offset,
                size: m.size,
            })
            .collect(),
        all_load: false,
    })
}

/// The per-run gate a caller hangs on the sweep — §9.3's correctness
/// half ("performance jobs never gate on unverified output — every
/// benchmark link is also run through `pgr-verify`") as a consumer-side
/// seam, the M67 custom-check shape: the sweep runs the observed
/// pipeline and hands each run's plan to the gate *outside the measured
/// wall* (the gate reads the product, the measurement prices the
/// pipeline — the M54 parity contract holds), and a refusal aborts the
/// sweep ([`SweepError::Gate`], the gate's own wording verbatim). The
/// crate's `()` unit is the pass-through gate — the ungated sweep is
/// this trait's `Ok(())` arm, one shape with no decision copy. The
/// first consumer is `pgr_emit::sweep::VerifyGate` (the strict verifier
/// over each run's fused image).
pub trait SweepRunGate {
    /// One run's product: the plan Passes 1–3 planned (the image is the
    /// emit's to build from it). A refusal aborts the sweep — the
    /// measurement never rides an ungated image.
    ///
    /// # Errors
    /// The gate's own refusal, verbatim — the wording a gate exists to
    /// name (the fix is the gate's, not the sweep's).
    fn on_run(&mut self, run: usize, result: &LinkResult) -> Result<(), String>;
}

impl SweepRunGate for () {
    fn on_run(&mut self, _run: usize, _result: &LinkResult) -> Result<(), String> {
        Ok(())
    }
}

/// Runs the observed pipeline `plan.runs` times over one corpus, handing
/// each run's plan to `gate` outside the measured wall — the gated
/// sweep. See [`run_sweep`] for the measurement contract and
/// [`SweepRunGate`] for the gate's.
///
/// # Errors
/// [`SweepError::Runs`] on a zero-run plan, [`SweepError::Link`] when a
/// run's link refuses (the pipeline's own wording), and
/// [`SweepError::Gate`] when a run's gate refuses (the gate's own
/// wording, the run named).
pub fn run_sweep_gated(
    inputs: &[LinkInput],
    archives: &[LinkArchive],
    cfg: &LinkConfig,
    parallel: Parallelism,
    plan: &SweepPlan,
    gate: &mut dyn SweepRunGate,
) -> Result<SweepOutcome, SweepError> {
    if plan.runs == 0 {
        return Err(SweepError::Runs { runs: plan.runs });
    }
    let mut samples = Vec::with_capacity(plan.runs);
    for run in 0..plan.runs {
        let mut collector = TimeCollector::default();
        let started = Instant::now();
        let result = link_observed(inputs, archives, cfg, parallel, None, &mut collector);
        let wall = started.elapsed();
        // The link result is the pipeline's own product — the sweep
        // records the measurement, the caller's gates own the image.
        let result = result?;
        gate.on_run(run, &result)
            .map_err(|reason| SweepError::Gate { run, reason })?;
        let report = collector.report();
        samples.push(SweepSample { wall, report });
    }
    let summary = reduce(&plan.label, &samples);
    Ok(SweepOutcome {
        label: plan.label.clone(),
        runs: plan.runs,
        samples,
        summary,
    })
}

/// Runs the observed pipeline `plan.runs` times over one corpus and
/// records every run: the wall clock and the run's own
/// [`TimeCollector`] rows. The inputs are borrowed — the pipeline parses
/// them fresh each run (Pass 1's parse is the measured work), and no
/// POI cache rides (the sweep prices the uncached pipeline; a cached
/// sweep is a different measurement). Measuring is read-only: a swept
/// run is the plain observed run's rows (the M54 parity contract).
/// This is the pass-through gate's sweep — the ungated shape of
/// [`run_sweep_gated`]; a correctness gate rides [`SweepRunGate`] (the
/// §9.3 "every benchmark link is also run through `pgr-verify"` half).
///
/// # Errors
/// [`SweepError::Runs`] on a zero-run plan, [`SweepError::Link`] when a
/// run's link refuses (the pipeline's own wording).
pub fn run_sweep(
    inputs: &[LinkInput],
    archives: &[LinkArchive],
    cfg: &LinkConfig,
    parallel: Parallelism,
    plan: &SweepPlan,
) -> Result<SweepOutcome, SweepError> {
    run_sweep_gated(inputs, archives, cfg, parallel, plan, &mut ())
}

impl SweepOutcome {
    /// The stored face: the label, the run count and the summary.
    #[must_use]
    pub fn ledger(&self) -> SweepLedger {
        SweepLedger {
            label: self.label.clone(),
            runs: self.runs,
            summary: self.summary.clone(),
        }
    }

    /// Renders the deterministic text face: the shape, the run count, the
    /// reduced walls and one row per phase — the §9.3 face a human reads
    /// beside the stored JSON line. The walls render through the
    /// time-report's own table (the crate's one copy of the wall text).
    #[must_use]
    pub fn render(&self) -> String {
        let mut s = String::with_capacity(96 + self.summary.phases.len() * 48);
        let _ = writeln!(s, "the shape sweep: {} — {} runs", self.label, self.runs);
        let _ = writeln!(
            s,
            "  median wall  {}   p95 wall  {}   min wall  {}   max wall  {}",
            crate::time_report::wall_text(Duration::from_micros(self.summary.median_wall_us)),
            crate::time_report::wall_text(Duration::from_micros(self.summary.p95_wall_us)),
            crate::time_report::wall_text(Duration::from_micros(self.summary.min_wall_us)),
            crate::time_report::wall_text(Duration::from_micros(self.summary.max_wall_us)),
        );
        for row in &self.summary.phases {
            let _ = writeln!(
                s,
                "  {:<12} {}",
                row.phase.as_str(),
                crate::time_report::wall_text(Duration::from_micros(row.median_us)),
            );
        }
        s
    }

    /// Renders the stored ledger as the deterministic compact JSON line —
    /// [`ledger_json`] over the outcome's own data.
    #[must_use]
    pub fn render_json(&self) -> String {
        ledger_json(&self.label, self.runs, &self.summary)
    }
}

/// Renders the ledger's JSON line: fixed key order, one line, the
/// report-JSON escape rules (the label rides
/// [`crate::map::escape_json`]; the walls ride whole microseconds).
#[must_use]
pub fn ledger_json(label: &str, runs: usize, summary: &SweepSummary) -> String {
    let mut s = String::with_capacity(128 + summary.phases.len() * 40);
    let _ = write!(
        s,
        "{{\"label\":{},\"runs\":{},\"median_wall_us\":{},\"p95_wall_us\":{},\"min_wall_us\":{},\"max_wall_us\":{},\"phases\":[",
        // The escape rides its own quotes (the report-JSON rules).
        crate::map::escape_json(label),
        runs,
        summary.median_wall_us,
        summary.p95_wall_us,
        summary.min_wall_us,
        summary.max_wall_us,
    );
    for (i, row) in summary.phases.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let _ = write!(
            s,
            "{{\"phase\":\"{}\",\"median_us\":{}}}",
            row.phase.as_str(),
            row.median_us
        );
    }
    s.push_str("]}");
    s
}

/// Writes the ledger file: the JSON line plus a trailing newline. The
/// write refuses an existing path (the nightly job writes one per-shape
/// path per run) and creates the parent directories.
///
/// # Errors
/// [`SweepError::Exists`] when the path exists, [`SweepError::Io`] when
/// the filesystem refuses the write.
pub fn write_ledger(
    label: &str,
    runs: usize,
    summary: &SweepSummary,
    path: &Path,
) -> Result<u64, SweepError> {
    if path.exists() {
        return Err(SweepError::Exists {
            path: path.display().to_string(),
        });
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| SweepError::Io {
            path: path.display().to_string(),
            source,
        })?;
    }
    let mut line = ledger_json(label, runs, summary);
    line.push('\n');
    std::fs::write(path, line.as_bytes()).map_err(|source| SweepError::Io {
        path: path.display().to_string(),
        source,
    })?;
    Ok(line.len() as u64)
}

/// Parses the ledger JSON the writer emits — and the same rigid schema
/// any conforming writer produces (keys in any order, the ledger's exact
/// fields, no floats, no trailing commas). The reader restores the
/// writer's data exactly: the round-trip is gated in
/// `tests/shape_sweep.rs`.
///
/// # Errors
/// [`SweepError::Ledger`] on a malformed document (byte-positioned), on
/// unknown, duplicate or missing keys, and on a phase token the M54
/// vocabulary does not name.
pub fn parse_ledger(raw: &str) -> Result<SweepLedger, SweepError> {
    let mut rd = SweepLedgerReader {
        s: raw.as_bytes(),
        pos: 0,
    };
    let ledger = rd.parse_ledger()?;
    rd.skip_ws();
    if rd.pos != rd.s.len() {
        return rd.invalid("trailing bytes after the ledger object");
    }
    Ok(ledger)
}

/// The strict ledger reader: a recursive descent over the schema the
/// writer emits (byte-positioned refusals; integer-only numbers; unknown,
/// duplicate and missing keys refuse) — the map reader's convention.
struct SweepLedgerReader<'a> {
    /// The document bytes.
    s: &'a [u8],
    /// The cursor.
    pos: usize,
}

impl SweepLedgerReader<'_> {
    /// A shape refusal at the current byte.
    fn invalid<T>(&self, detail: impl Into<String>) -> Result<T, SweepError> {
        Err(SweepError::Ledger {
            at: self.pos,
            detail: detail.into(),
        })
    }

    /// Skips the JSON whitespace the compact writer never emits but a
    /// hand-edited document may carry.
    fn skip_ws(&mut self) {
        while matches!(self.s.get(self.pos), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    /// The next non-whitespace byte, or an end-of-document refusal.
    fn peek(&mut self) -> Result<u8, SweepError> {
        self.skip_ws();
        match self.s.get(self.pos) {
            Some(&b) => Ok(b),
            None => self.invalid("unexpected end of document"),
        }
    }

    /// Consumes the exact byte `c` (post-whitespace).
    fn expect(&mut self, c: u8) -> Result<(), SweepError> {
        let got = self.peek()?;
        if got != c {
            return self.invalid(format!("expected {:?}, found {:?}", c as char, got as char));
        }
        self.pos += 1;
        Ok(())
    }

    /// The next `"`key`":` pair inside an object: `Ok(None)` on the
    /// object's closing brace, the decoded key otherwise. `first` marks
    /// the object's opening field (a leading or trailing comma is the
    /// malformed shape).
    fn next_key(&mut self, first: bool) -> Result<Option<String>, SweepError> {
        if self.peek()? == b'}' {
            self.pos += 1;
            return Ok(None);
        }
        if !first {
            self.expect(b',')?;
            if self.peek()? == b'}' {
                return self.invalid("trailing comma in object");
            }
        }
        let key = self.parse_string()?;
        self.expect(b':')?;
        Ok(Some(key))
    }

    /// Fills one object's slot, refusing a duplicate key by name (the
    /// `at` is the cursor where the duplicate sat — read before the value
    /// parses).
    fn set<T>(
        at: usize,
        slot: &mut Option<T>,
        name: impl Into<String>,
        value: T,
    ) -> Result<(), SweepError> {
        if slot.is_some() {
            return Err(SweepError::Ledger {
                at,
                detail: format!("duplicate key {:?}", name.into()),
            });
        }
        *slot = Some(value);
        Ok(())
    }

    /// Requires one object's slot to be filled (the missing-field refusal
    /// names the key).
    fn require<T>(slot: Option<T>, name: &str) -> Result<T, SweepError> {
        slot.ok_or_else(|| SweepError::Ledger {
            at: 0,
            detail: format!("missing field {name:?}"),
        })
    }

    /// A JSON string: the writer's escapes decoded, multibyte UTF-8 kept
    /// verbatim, raw control bytes refused.
    fn parse_string(&mut self) -> Result<String, SweepError> {
        self.expect(b'"')?;
        crate::jsonstr::parse_json_string(self.s, &mut self.pos, "the ledger JSON must be UTF-8")
            .map_err(|e| SweepError::Ledger {
                at: e.at,
                detail: e.detail,
            })
    }

    /// A non-negative integer: digits only — the ledger schema carries no
    /// floats or exponents, and every value is u64.
    fn parse_u64(&mut self) -> Result<u64, SweepError> {
        let b = self.peek()?;
        if !b.is_ascii_digit() {
            return self.invalid(format!(
                "expected a non-negative integer, found {:?}",
                b as char
            ));
        }
        let start = self.pos;
        while matches!(self.s.get(self.pos), Some(d) if d.is_ascii_digit()) {
            self.pos += 1;
        }
        let digits =
            std::str::from_utf8(&self.s[start..self.pos]).map_err(|_| SweepError::Ledger {
                at: start,
                detail: "the ledger JSON must be UTF-8".into(),
            })?;
        digits.parse::<u64>().map_err(|_| SweepError::Ledger {
            at: start,
            detail: format!("{digits} exceeds u64"),
        })
    }

    /// The ledger object: the writer's seven fields, any order, each at
    /// most once, none missing.
    fn parse_ledger(&mut self) -> Result<SweepLedger, SweepError> {
        self.expect(b'{')?;
        let mut label: Option<String> = None;
        let mut runs: Option<usize> = None;
        let mut median: Option<u64> = None;
        let mut p95: Option<u64> = None;
        let mut min: Option<u64> = None;
        let mut max: Option<u64> = None;
        let mut phases: Option<Vec<SweepPhaseRow>> = None;
        let mut first = true;
        while let Some(key) = self.next_key(first)? {
            first = false;
            match key.as_str() {
                "label" => Self::set(self.pos, &mut label, "label", self.parse_string()?)?,
                "runs" => {
                    let raw = self.parse_u64()?;
                    let count = usize::try_from(raw).map_err(|_| SweepError::Ledger {
                        at: self.pos,
                        detail: format!("{raw} exceeds usize"),
                    })?;
                    Self::set(self.pos, &mut runs, "runs", count)?;
                }
                "median_wall_us" => {
                    Self::set(self.pos, &mut median, "median_wall_us", self.parse_u64()?)?;
                }
                "p95_wall_us" => Self::set(self.pos, &mut p95, "p95_wall_us", self.parse_u64()?)?,
                "min_wall_us" => Self::set(self.pos, &mut min, "min_wall_us", self.parse_u64()?)?,
                "max_wall_us" => Self::set(self.pos, &mut max, "max_wall_us", self.parse_u64()?)?,
                "phases" => Self::set(self.pos, &mut phases, "phases", self.parse_phases()?)?,
                other => {
                    return Err(SweepError::Ledger {
                        at: self.pos,
                        detail: format!(
                            "unknown key {other:?} — the ledger's fields are the writer's"
                        ),
                    });
                }
            }
        }
        let runs = Self::require(runs, "runs")?;
        Ok(SweepLedger {
            label: Self::require(label, "label")?,
            runs,
            summary: SweepSummary {
                runs,
                median_wall_us: Self::require(median, "median_wall_us")?,
                p95_wall_us: Self::require(p95, "p95_wall_us")?,
                min_wall_us: Self::require(min, "min_wall_us")?,
                max_wall_us: Self::require(max, "max_wall_us")?,
                phases: Self::require(phases, "phases")?,
            },
        })
    }

    /// The phases array: one `{"phase":…,"median_us":…}` row per reduced
    /// phase, the M54 tokens.
    fn parse_phases(&mut self) -> Result<Vec<SweepPhaseRow>, SweepError> {
        self.expect(b'[')?;
        let mut rows = Vec::new();
        if self.peek()? == b']' {
            self.pos += 1;
            return Ok(rows);
        }
        loop {
            self.expect(b'{')?;
            let mut phase: Option<Phase> = None;
            let mut median: Option<u64> = None;
            let mut first = true;
            while let Some(key) = self.next_key(first)? {
                first = false;
                match key.as_str() {
                    "phase" => {
                        let token = self.parse_string()?;
                        match Phase::from_token(&token) {
                            Some(p) => Self::set(self.pos, &mut phase, "phase", p)?,
                            None => {
                                return Err(SweepError::Ledger {
                                    at: self.pos,
                                    detail: format!(
                                        "unknown phase token {token:?} — the M54 vocabulary names the phases"
                                    ),
                                });
                            }
                        }
                    }
                    "median_us" => {
                        Self::set(self.pos, &mut median, "median_us", self.parse_u64()?)?;
                    }
                    other => {
                        return Err(SweepError::Ledger {
                            at: self.pos,
                            detail: format!(
                                "unknown key {other:?} — a phase row's fields are phase and median_us"
                            ),
                        });
                    }
                }
            }
            rows.push(SweepPhaseRow {
                phase: Self::require(phase, "phase")?,
                median_us: Self::require(median, "median_us")?,
            });
            match self.peek()? {
                b',' => {
                    self.pos += 1;
                    if self.peek()? == b']' {
                        return self.invalid("trailing comma in the phases array");
                    }
                }
                b']' => {
                    self.pos += 1;
                    return Ok(rows);
                }
                other => {
                    return self.invalid(format!("expected ',' or ']', found {:?}", other as char));
                }
            }
        }
    }
}

/// One reduced band's move: the previous and current walls (µs) and the
/// signed permille — `(current − previous)` as permille of the previous,
/// positive slower and negative faster. A zero previous renders zero
/// permille rather than dividing by zero (the share column's rule).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepBandDelta {
    /// The previous nightly's wall, in µs.
    pub previous_us: u64,
    /// The current nightly's wall, in µs.
    pub current_us: u64,
    /// The signed move, in permille.
    pub permille: i64,
}

/// One phase's paired row: the phase, either nightly's median wall (the
/// side a nightly lacks rides `None`), and the signed permille when both
/// sides rode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepPhaseDelta {
    /// The phase (the M54 vocabulary).
    pub phase: Phase,
    /// The previous nightly's median, in µs (`None` when new).
    pub previous_us: Option<u64>,
    /// The current nightly's median, in µs (`None` when gone).
    pub current_us: Option<u64>,
    /// The signed move, in permille (`None` when one side is absent).
    pub permille: Option<i64>,
}

/// The stored ledgers' comparison (§9.3: "vs baselines"): one shape's
/// own history, the bands and the per-phase rows paired, the moves in
/// signed permille — integer math, no float rounding (the time-report
/// share column's rule). The current ledger's phase order leads; a
/// phase the previous nightly lacked rides `previous_us: None`, a phase
/// it lost trails the paired rows with `current_us: None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepDelta {
    /// The shape's name (the ledgers' shared label).
    pub label: String,
    /// The run counts: the previous and the current nightly's.
    pub runs: (usize, usize),
    /// The median wall's move.
    pub median: SweepBandDelta,
    /// The p95 wall's move.
    pub p95: SweepBandDelta,
    /// The fastest wall's move.
    pub min: SweepBandDelta,
    /// The slowest wall's move.
    pub max: SweepBandDelta,
    /// One row per phase, the current order leading, the lost phases
    /// trailing.
    pub phases: Vec<SweepPhaseDelta>,
}

/// The signed permille move between two walls — integer math on u128
/// with an i64 span (a µs-scale corpus never approaches the bound); a
/// zero previous reads zero.
fn permille_move(previous: u64, current: u64) -> i64 {
    if previous == 0 {
        return 0;
    }
    let move_ = (i128::from(current) - i128::from(previous)) * 1_000 / i128::from(previous);
    let clamp = if move_ > 0 { i64::MAX } else { i64::MIN };
    i64::try_from(move_).unwrap_or(clamp)
}

/// The band delta (the walls always pair — the bands are the summary's).
fn band_delta(previous: u64, current: u64) -> SweepBandDelta {
    SweepBandDelta {
        previous_us: previous,
        current_us: current,
        permille: permille_move(previous, current),
    }
}

/// The phase row delta: the sides pair positionally by phase token; an
/// unmatched side carries `None` and no permille.
fn phase_delta(previous: Option<u64>, current: Option<u64>, phase: Phase) -> SweepPhaseDelta {
    let permille = match (previous, current) {
        (Some(p), Some(c)) => Some(permille_move(p, c)),
        _ => None,
    };
    SweepPhaseDelta {
        phase,
        previous_us: previous,
        current_us: current,
        permille,
    }
}

impl SweepDelta {
    /// Compares one shape's own history: the previous nightly's stored
    /// ledger beside the current one's. The labels must match (a
    /// cross-shape comparison refuses with both names); the phases pair
    /// by token — the current order leads, the lost phases trail.
    ///
    /// # Errors
    /// [`SweepError::LabelsDiffer`] when the two ledgers name different
    /// shapes.
    pub fn between(previous: &SweepLedger, current: &SweepLedger) -> Result<Self, SweepError> {
        if previous.label != current.label {
            return Err(SweepError::LabelsDiffer {
                previous: previous.label.clone(),
                current: current.label.clone(),
            });
        }
        let mut phases = Vec::with_capacity(current.summary.phases.len());
        for row in &current.summary.phases {
            let prior = previous
                .summary
                .phases
                .iter()
                .find(|p| p.phase == row.phase)
                .map(|p| p.median_us);
            phases.push(phase_delta(prior, Some(row.median_us), row.phase));
        }
        for row in &previous.summary.phases {
            if !current.summary.phases.iter().any(|p| p.phase == row.phase) {
                phases.push(phase_delta(Some(row.median_us), None, row.phase));
            }
        }
        Ok(Self {
            label: current.label.clone(),
            runs: (previous.runs, current.runs),
            median: band_delta(
                previous.summary.median_wall_us,
                current.summary.median_wall_us,
            ),
            p95: band_delta(previous.summary.p95_wall_us, current.summary.p95_wall_us),
            min: band_delta(previous.summary.min_wall_us, current.summary.min_wall_us),
            max: band_delta(previous.summary.max_wall_us, current.summary.max_wall_us),
            phases,
        })
    }

    /// Renders the deterministic text face: the shape and the run pair,
    /// one row per band and per phase, the signed permille riding the
    /// last column — the chart's face beside the stored JSON lines. A
    /// new phase renders its wall alone; a lost phase renders the
    /// previous wall alone.
    ///
    /// # Panics
    /// Never: a paired phase row carries both walls by construction (the
    /// `expect` guards an invariant [`SweepDelta::between`] builds — the
    /// arm is unreachable, and the `None`-sided rows take the other
    /// arms).
    #[must_use]
    pub fn render(&self) -> String {
        /// One band's row (the phase rows share the shape).
        fn band(s: &mut String, name: &str, d: &SweepBandDelta) {
            let _ = writeln!(
                s,
                "  {name:<12} {} → {}   ({:+}‰)",
                crate::time_report::wall_text(Duration::from_micros(d.previous_us)),
                crate::time_report::wall_text(Duration::from_micros(d.current_us)),
                d.permille,
            );
        }
        let mut s = String::with_capacity(128 + self.phases.len() * 48);
        let _ = writeln!(
            s,
            "the shape-sweep delta: {} ({} runs → {} runs)",
            self.label, self.runs.0, self.runs.1
        );
        band(&mut s, "median wall", &self.median);
        band(&mut s, "p95 wall", &self.p95);
        band(&mut s, "min wall", &self.min);
        band(&mut s, "max wall", &self.max);
        for row in &self.phases {
            match (row.previous_us, row.current_us) {
                (Some(p), Some(c)) => {
                    let _ = writeln!(
                        s,
                        "  {:<12} {} → {}   ({:+}‰)",
                        row.phase.as_str(),
                        crate::time_report::wall_text(Duration::from_micros(p)),
                        crate::time_report::wall_text(Duration::from_micros(c)),
                        row.permille.expect("both sides rode"),
                    );
                }
                (None, Some(c)) => {
                    let _ = writeln!(
                        s,
                        "  {:<12} (new) → {}",
                        row.phase.as_str(),
                        crate::time_report::wall_text(Duration::from_micros(c)),
                    );
                }
                (Some(p), None) => {
                    let _ = writeln!(
                        s,
                        "  {:<12} {} → (gone)",
                        row.phase.as_str(),
                        crate::time_report::wall_text(Duration::from_micros(p)),
                    );
                }
                (None, None) => {}
            }
        }
        s
    }

    /// Renders the delta as the deterministic compact JSON line: fixed
    /// key order, one line, the report-JSON escape rules (the label
    /// rides [`crate::map::escape_json`]). A new or lost phase's
    /// absent side rides `null` — the chart reads the pairing.
    #[must_use]
    pub fn render_json(&self) -> String {
        let band = |d: &SweepBandDelta| {
            format!(
                "{{\"previous_us\":{},\"current_us\":{},\"permille\":{}}}",
                d.previous_us, d.current_us, d.permille
            )
        };
        let mut s = String::with_capacity(160 + self.phases.len() * 72);
        let _ = write!(
            s,
            "{{\"label\":{},\"runs\":{{\"previous\":{},\"current\":{}}},\"median\":{},\"p95\":{},\"min\":{},\"max\":{},\"phases\":[",
            crate::map::escape_json(&self.label),
            self.runs.0,
            self.runs.1,
            band(&self.median),
            band(&self.p95),
            band(&self.min),
            band(&self.max),
        );
        for (i, row) in self.phases.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let side = |v: Option<u64>| match v {
                Some(us) => us.to_string(),
                None => "null".to_string(),
            };
            let _ = write!(
                s,
                "{{\"phase\":\"{}\",\"previous_us\":{},\"current_us\":{},\"permille\":{}}}",
                row.phase.as_str(),
                side(row.previous_us),
                side(row.current_us),
                match row.permille {
                    Some(p) => p.to_string(),
                    None => "null".to_string(),
                },
            );
        }
        s.push_str("]}");
        s
    }
}
