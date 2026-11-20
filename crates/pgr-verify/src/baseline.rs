//! The baseline gate (M13 rung 1): classify a fresh verification report
//! against the report from the last accepted image.
//!
//! Whole-image verification answers "is this image clean?" — the right
//! contract for a final gate, and the wrong one for a relink loop: an
//! image that shipped with two tolerated warnings fails every later
//! build on exactly those warnings, forever. A build system that
//! relinks incrementally needs the narrower question — **"what is new
//! since the image I last accepted?"** — and that is a diff, not a
//! verdict:
//!
//! * [`IssueIdentity`] names how a finding is recognized across
//!   reports (the matching policy);
//! * [`OffsetIdentity`] (the default) matches by issue code *and*
//!   anchor offset — position-aware, the strict reading;
//! * [`CodeIdentity`] matches by issue code alone — the finding that
//!   moved (a layout shift relocating the offending byte) keeps its
//!   identity;
//! * [`BaselineDelta::between`] classifies the two sides' issues into
//!   `introduced` / `resolved` / `surviving` as a multiset (duplicate
//!   keys count), deterministic in report order.
//!
//! The delta is a plain value: the CLI's `--baseline` flag is one
//! consumer, a build system driving the library is the other. The
//! computation rides the tracing seam (inert until a subscriber
//! installs — the workspace convention): one `debug` event names the
//! policy and the counts.
//!
//! The container rides the same gate since M96: a universal ("fat")
//! container's baseline document is the container's own `--json` output
//! — one whole-output report line per declared slice, the label naming
//! the window the line vouches for — and
//! [`UniversalDelta::between_slices`] pairs the lines with the table
//! rows (positional, window-checked) before one
//! [`BaselineDelta::between`] runs per slice, the M74 refusal ("the
//! baseline identity gates one image's offsets, never a slice table")
//! retired with its premise the M95 way.
//!
//! ```no_run
//! use pgr_verify::{CodeIdentity, Issue, OffsetIdentity, parse_report_json};
//!
//! let prev = parse_report_json(r#"{"issues":[]}"#).expect("baseline");
//! let next: Vec<Issue> = Vec::new();
//! let delta = pgr_verify::BaselineDelta::between(&prev.issues, &next, &OffsetIdentity);
//! assert!(delta.is_clean());
//! let _ = CodeIdentity; // the moved-finding policy, same shape
//! ```

use crate::universal::{SliceWindow, parse_slice_label};
use crate::{Issue, Report};

/// How a finding is recognized across two reports (the matching policy
/// a [`BaselineDelta::between`] run uses).
///
/// The identity is deliberately severity-blind: the delta's job is
/// "what is new", not "what got worse" — a site that survived reports
/// the same code at the same anchor, escalated or not. The report
/// itself still carries each issue's severity, so a gate that wants
/// escalation filters the introduced/resolved lists by severity.
pub trait IssueIdentity: Sync {
    /// The stable key an issue is matched across reports by.
    fn key(&self, issue: &Issue) -> IssueKey;

    /// The policy's canonical name (the tracing event and the CLI's
    /// baseline block carry it).
    fn name(&self) -> &'static str;
}

/// One finding's matching key: the issue code plus, under the
/// position-aware policies, its anchor offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IssueKey {
    /// The machine-checkable code (`signature_hash_mismatch`...).
    pub code: crate::Code,
    /// The anchor offset, when the policy is position-aware.
    pub offset: Option<u64>,
}

/// The default policy: a finding is its code **and** its anchor offset.
///
/// Strict reading — the same code appearing at a new site is a new
/// finding (the old site cleared). Right for gates over images whose
/// layout is stable, where an issue's offset moving means the issue
/// itself moved with the bytes.
#[derive(Debug, Clone, Copy, Default)]
pub struct OffsetIdentity;

impl IssueIdentity for OffsetIdentity {
    fn key(&self, issue: &Issue) -> IssueKey {
        IssueKey {
            code: issue.code,
            offset: issue.offset,
        }
    }

    fn name(&self) -> &'static str {
        "offset"
    }
}

/// The moved-finding policy: a finding is its code alone.
///
/// A layout shift relocates the offending byte without changing the
/// finding — under [`OffsetIdentity`] every relink that moved a section
/// would report the old finding resolved and a duplicate introduced.
/// The code-only identity survives the move, at the cost of treating
/// two distinct sites with the same code as one finding.
#[derive(Debug, Clone, Copy, Default)]
pub struct CodeIdentity;

impl IssueIdentity for CodeIdentity {
    fn key(&self, issue: &Issue) -> IssueKey {
        IssueKey {
            code: issue.code,
            offset: None,
        }
    }

    fn name(&self) -> &'static str {
        "code"
    }
}

/// The classification of one fresh report against one baseline.
///
/// Matching is a multiset: a key appearing twice on the next side and
/// once on the prev side yields one surviving and one introduced
/// finding — counts, not just sets. Every list is deterministic:
/// `introduced` in next-report order, `resolved` in prev-report order
/// (a report's issues are already sorted by anchor offset, so both
/// orders are stable across runs).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BaselineDelta {
    /// Findings present now that the baseline does not vouch for.
    pub introduced: Vec<Issue>,
    /// Baseline findings that cleared.
    pub resolved: Vec<Issue>,
    /// Findings the baseline already carried that are still present
    /// (the tolerated history — the reason the gate exists).
    pub surviving: usize,
}

impl BaselineDelta {
    /// Classifies `next` against `prev` under `identity`.
    ///
    /// The match is O(prev × next) — report issue counts are hundreds
    /// at the extreme, so the linear scan beats a hash map's ordering
    /// hazards and keeps the output order-stable by construction (the
    /// house determinism policy: nothing reads hash iteration order).
    #[must_use]
    pub fn between(prev: &[Issue], next: &[Issue], identity: &dyn IssueIdentity) -> Self {
        // matched[i] == true when prev[i] found its next-side partner.
        let mut matched = vec![false; prev.len()];
        let mut introduced = Vec::new();
        let mut surviving = 0usize;
        for issue in next {
            let key = identity.key(issue);
            let partner = prev
                .iter()
                .zip(matched.iter_mut())
                .find(|(p, taken)| !**taken && identity.key(p) == key);
            match partner {
                Some((_, taken)) => {
                    *taken = true;
                    surviving += 1;
                }
                None => introduced.push(issue.clone()),
            }
        }
        let resolved: Vec<Issue> = prev
            .iter()
            .zip(matched.iter())
            .filter(|(_, taken)| !**taken)
            .map(|(p, _)| p.clone())
            .collect();
        let delta = Self {
            introduced,
            resolved,
            surviving,
        };
        tracing::debug!(
            policy = identity.name(),
            introduced = delta.introduced.len(),
            resolved = delta.resolved.len(),
            surviving = delta.surviving,
            "baseline delta"
        );
        delta
    }

    /// True when the fresh report adds nothing the baseline does not
    /// vouch for — the `--fail-on new` gate.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.introduced.is_empty()
    }
}

/// One recorded slice in a container baseline document (M96): the label
/// the `--json` face wrote verbatim, the window its validated suffix
/// names (the pairing's identity — the reader refused any label that
/// names none), and that slice's report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerBaselineEntry {
    /// The line's label, verbatim (the writer's whole-output `file`
    /// field).
    pub label: String,
    /// The window the label's suffix names (the reader's own validation
    /// — the pairing checks this against the table row it pairs with).
    pub window: crate::universal::SliceWindow,
    /// The slice's own report.
    pub report: Report,
}

/// A container baseline document (M96): the container's own `--json`
/// face output — one whole-output report line per declared slice, in
/// table order. The M74 refusal ("the baseline identity gates one
/// image's offsets, never a slice table") retired with its premise, the
/// M95 way: the slices ride *inside* the audited file and every slice's
/// verdict is its own M13 report, so the face the user already records
/// is the baseline a relink gate reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerBaseline {
    /// One entry per recorded slice, in document order.
    pub entries: Vec<ContainerBaselineEntry>,
}

/// A container baseline refusal: where the document or the pairing died
/// and what the fix is (the house error convention).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContainerBaselineError {
    /// The document carries no report lines.
    #[error(
        "the baseline document carries no report lines (a container baseline is the \
         container's own --json output: verify it without --baseline and save the --json face)"
    )]
    Empty,
    /// A line is not the report shape.
    #[error("baseline line {line}: {source}")]
    Line {
        /// The 1-based line the reader died at.
        line: usize,
        /// The underlying parse refusal (the byte offset rides it).
        source: crate::ReportJsonError,
    },
    /// A line's label names no slice window — a hand-authored report
    /// cannot vouch for a row it does not name.
    #[error(
        "baseline line {line}: the label `{label}` names no slice window (a container \
         baseline is the container's own --json output: verify it without --baseline and \
         save the --json face — every line's label carries the slice identity)"
    )]
    LabelShape {
        /// The 1-based line the label rode.
        line: usize,
        /// The label as written.
        label: String,
    },
    /// The document and the container disagree on how many slices ride.
    #[error(
        "the baseline vouches for {baseline} slice(s) but the container declares {slices} \
         — the container's slice table changed since the baseline; re-record it (verify \
         without --baseline and save the --json face)"
    )]
    SliceCount {
        /// The container's declared slice count.
        slices: usize,
        /// The baseline's recorded slice count.
        baseline: usize,
    },
    /// A paired slice's window moved since the baseline named it — the
    /// document vouches for windows, not just a count.
    #[error(
        "slice {index}: the baseline vouches for window {baseline} but the container \
         declares {slice} — the container's shape moved since the baseline; re-record it \
         (verify without --baseline and save the --json face)"
    )]
    WindowMismatch {
        /// The table position the pairing rode.
        index: usize,
        /// The window the baseline line named.
        baseline: SliceWindow,
        /// The window the container's row declares.
        slice: SliceWindow,
    },
}

/// Reads a container baseline document ([`ContainerBaseline`], M96):
/// one whole-output report line per declared slice — exactly what the
/// container's `--json` face writes. Blank lines skip (the writer never
/// produces them; a trailing newline is not content), every other line
/// parses as the labeled form ([`crate::parse_labeled_report`], its
/// `file` key required) and its label must name a slice window
/// (`parse_slice_label` — a hand-authored line cannot vouch for a row
/// it does not name).
///
/// # Errors
/// [`ContainerBaselineError::Empty`] when no report lines ride;
/// [`ContainerBaselineError::Line`] naming the 1-based line and the
/// byte offset for a malformed one; [`ContainerBaselineError::LabelShape`]
/// for a line whose label names no window. Total — never panics.
pub fn parse_container_baseline(s: &str) -> Result<ContainerBaseline, ContainerBaselineError> {
    let mut entries = Vec::new();
    for (i, raw) in s.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let (label, report) =
            crate::parse_labeled_report(line).map_err(|source| ContainerBaselineError::Line {
                line: i + 1,
                source,
            })?;
        let window = parse_slice_label(&label).map(|parsed| SliceWindow {
            cputype: parsed.cputype,
            offset: parsed.offset,
            size: parsed.size,
        });
        let Some(window) = window else {
            return Err(ContainerBaselineError::LabelShape { line: i + 1, label });
        };
        entries.push(ContainerBaselineEntry {
            label,
            window,
            report,
        });
    }
    if entries.is_empty() {
        return Err(ContainerBaselineError::Empty);
    }
    tracing::debug!(
        slices = entries.len(),
        "container baseline: one report line per declared slice"
    );
    Ok(ContainerBaseline { entries })
}

/// One slice's classification against the baseline (M96): the table row
/// it rode and the [`BaselineDelta`] the row's report earned against the
/// paired entry (the run's own faces write the slice's label — the
/// pairing's identity is the window, which the gate agreed on first).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SliceDelta {
    /// The table row (the window the slice rode — the pairing's own
    /// identity, agreed with the baseline before any finding moved).
    pub arch: pgr_format::universal::FatArch,
    /// The row's delta against the paired baseline entry.
    pub delta: BaselineDelta,
}

/// The container's classification against a baseline (M96): one
/// [`SliceDelta`] per declared slice, in table order. `is_clean` is
/// every slice's — the container gate ships nothing a slice introduces,
/// the same rule [`crate::UniversalReport::is_ok`] applies to the verdict.
///
/// The pairing is positional and window-checked: line *i* pairs with
/// table row *i* (the M71 walk's order — the order the recording face
/// writes), and every paired line's label suffix must name the row's
/// exact window ([`SliceWindow`]). A baseline recorded from a container
/// whose slice table changed — slices added, dropped, or windows that
/// moved — refuses rather than pairing stale findings with fresh
/// windows; within an agreed window the user's [`IssueIdentity`]
/// policy runs exactly as the single-image gate's does.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UniversalDelta {
    /// The per-slice deltas, in table order.
    pub slices: Vec<SliceDelta>,
}

impl UniversalDelta {
    /// Classifies the container's verdict against the baseline under
    /// `identity` (M96): the pairing (positional, window-checked) first,
    /// then one [`BaselineDelta::between`] per slice — the same policies,
    /// the same multiset match, the same determinism the single-image
    /// gate rides, one slice at a time.
    ///
    /// # Errors
    /// [`ContainerBaselineError::SliceCount`] when the baseline names a
    /// different number of slices; [`ContainerBaselineError::WindowMismatch`]
    /// when a paired line's label names a window the row does not ride.
    pub fn between_slices(
        report: &crate::UniversalReport,
        baseline: &ContainerBaseline,
        identity: &dyn IssueIdentity,
    ) -> Result<Self, ContainerBaselineError> {
        if baseline.entries.len() != report.slices.len() {
            return Err(ContainerBaselineError::SliceCount {
                slices: report.slices.len(),
                baseline: baseline.entries.len(),
            });
        }
        let mut slices = Vec::with_capacity(report.slices.len());
        for (i, verdict) in report.slices.iter().enumerate() {
            let entry = &baseline.entries[i];
            // The document vouches for windows: the paired entry's
            // validated suffix must name the row's exact triple, or the
            // container's shape moved since the recording.
            let window = SliceWindow {
                cputype: verdict.arch.cputype,
                offset: verdict.arch.offset,
                size: verdict.arch.size,
            };
            if entry.window != window {
                return Err(ContainerBaselineError::WindowMismatch {
                    index: i,
                    baseline: entry.window,
                    slice: window,
                });
            }
            let delta =
                BaselineDelta::between(&entry.report.issues, &verdict.report.issues, identity);
            slices.push(SliceDelta {
                arch: verdict.arch,
                delta,
            });
        }
        let delta = Self { slices };
        tracing::debug!(
            slices = delta.slices.len(),
            policy = identity.name(),
            clean = delta.is_clean(),
            "container baseline delta"
        );
        Ok(delta)
    }

    /// True when no slice adds anything its baseline entry does not
    /// vouch for — the container's `--fail-on new` gate.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.slices.iter().all(|s| s.delta.is_clean())
    }
}

#[cfg(test)]
mod tests {
    use super::{BaselineDelta, CodeIdentity, IssueIdentity, IssueKey, OffsetIdentity};
    use crate::{Code, Issue};

    fn issue(code: Code, offset: Option<u64>) -> Issue {
        Issue::error(code, "probe", offset)
    }

    #[test]
    fn the_policies_disagree_exactly_on_the_offset() {
        let i = issue(Code::FixupsChain, Some(0x40));
        assert_eq!(
            OffsetIdentity.key(&i),
            IssueKey {
                code: Code::FixupsChain,
                offset: Some(0x40)
            }
        );
        assert_eq!(
            CodeIdentity.key(&i),
            IssueKey {
                code: Code::FixupsChain,
                offset: None
            }
        );
        assert_ne!(OffsetIdentity.name(), CodeIdentity.name());
    }

    #[test]
    fn null_and_present_offsets_are_distinct_sites() {
        let a = issue(Code::Suspicious, None);
        let b = issue(Code::Suspicious, Some(0));
        let delta = BaselineDelta::between(&[a], &[b], &OffsetIdentity);
        assert!(!delta.is_clean(), "an unanchored finding is its own site");
    }

    #[test]
    fn warnings_and_errors_on_one_site_match() {
        let w = Issue::warning(Code::Suspicious, "odd", Some(2));
        let e = Issue::error(Code::Suspicious, "odd", Some(2));
        let delta = BaselineDelta::between(&[w], &[e], &OffsetIdentity);
        assert!(delta.is_clean(), "the identity is severity-blind");
        assert_eq!(delta.surviving, 1);
    }

    mod container {
        use super::{BaselineDelta, OffsetIdentity};
        use crate::baseline::{
            ContainerBaseline, ContainerBaselineError, UniversalDelta, parse_container_baseline,
        };
        use crate::universal::{SliceVerdict, slice_label};
        use crate::{Code, Issue, Report, UniversalReport};
        use pgr_format::consts::CPU_TYPE_ARM64;
        use pgr_format::universal::FatArch;

        fn arch(offset: u64, size: u64) -> FatArch {
            FatArch {
                cputype: CPU_TYPE_ARM64,
                cpusubtype: 0,
                offset,
                size,
                align_log2: 12,
            }
        }

        fn container_report(slices: &[Vec<Issue>]) -> UniversalReport {
            UniversalReport {
                slices: slices
                    .iter()
                    .enumerate()
                    .map(|(i, issues)| SliceVerdict {
                        arch: arch(u64::try_from((i + 1) * 0x4000).expect("fits"), 0x4000),
                        report: Report {
                            issues: issues.clone(),
                            stats: crate::Stats::default(),
                        },
                    })
                    .collect(),
            }
        }

        fn baseline_for(slices: &[Vec<Issue>]) -> ContainerBaseline {
            let report = container_report(slices);
            let lines: Vec<String> = report
                .slices
                .iter()
                .enumerate()
                .map(|(i, verdict)| {
                    crate::to_json_with_file(
                        &slice_label("fat.dylib", i, &verdict.arch),
                        &verdict.report,
                    )
                })
                .collect();
            parse_container_baseline(&lines.join("\n")).expect("the document parses")
        }

        fn sig(offset: u64) -> Issue {
            Issue::error(
                Code::SignatureHashMismatch,
                "the page hash moved",
                Some(offset),
            )
        }

        #[test]
        fn the_record_face_output_is_the_baseline_document() {
            let document = baseline_for(&[vec![], vec![]]);
            assert_eq!(document.entries.len(), 2, "one entry per declared slice");
            let window = crate::universal::parse_slice_label(&document.entries[0].label)
                .expect("the label names the window");
            assert_eq!(window.offset, 0x4000, "the row's window rides the label");
        }

        #[test]
        fn the_pairing_gates_on_windows_before_findings() {
            let baseline = baseline_for(&[vec![], vec![]]);
            // The container's second slice rides a different window: the
            // pairing refuses before any delta runs.
            let mut moved = container_report(&[vec![], vec![]]);
            moved.slices[1].arch.offset = 0x9000;
            let err = UniversalDelta::between_slices(&moved, &baseline, &OffsetIdentity)
                .expect_err("the moved window refuses");
            match err {
                ContainerBaselineError::WindowMismatch {
                    index,
                    baseline,
                    slice,
                } => {
                    assert_eq!(index, 1);
                    assert_eq!(baseline.offset, 0x8000);
                    assert_eq!(slice.offset, 0x9000);
                }
                other => panic!("expected a window mismatch, got {other:?}"),
            }
        }

        #[test]
        fn a_slice_count_change_refuses() {
            let baseline = baseline_for(&[vec![], vec![]]);
            let one = container_report(&[vec![]]);
            let err = UniversalDelta::between_slices(&one, &baseline, &OffsetIdentity)
                .expect_err("the count change refuses");
            assert!(matches!(
                err,
                ContainerBaselineError::SliceCount {
                    slices: 1,
                    baseline: 2
                }
            ));
        }

        #[test]
        fn the_delta_classifies_each_slice_on_its_own() {
            let baseline = baseline_for(&[vec![sig(0x100)], vec![]]);
            // Slice 0's finding cleared (resolved); slice 1 grows a new
            // one (introduced) — the gate is slice 1's, not the whole.
            let next = container_report(&[vec![], vec![sig(0x200)]]);
            let delta = UniversalDelta::between_slices(&next, &baseline, &OffsetIdentity)
                .expect("the pairing agrees");
            assert!(delta.slices[0].delta.resolved.len() == 1, "resolved");
            assert!(delta.slices[0].delta.is_clean());
            assert_eq!(delta.slices[1].delta.introduced.len(), 1);
            assert!(!delta.is_clean(), "the container gate is every slice's");
        }

        #[test]
        fn blank_and_garbage_lines_name_their_line() {
            let err = parse_container_baseline("").expect_err("the empty document refuses");
            assert!(matches!(err, ContainerBaselineError::Empty));
            let err = parse_container_baseline(
                "{\"file\":\"app[slice 0 cputype 0x100000c at 0x0, 8 bytes]\",\"issues\":[]}\nnope\n",
            )
            .expect_err("the garbage line refuses");
            match err {
                ContainerBaselineError::Line { line, .. } => assert_eq!(line, 2),
                other => panic!("expected a line refusal, got {other:?}"),
            }
            let err = parse_container_baseline("{\"file\":\"x\",\"issues\":[]}\nnope\n")
                .expect_err("the unlabeled first line refuses");
            match err {
                ContainerBaselineError::LabelShape { line: 1, label } => assert_eq!(label, "x"),
                other => panic!("expected a label refusal, got {other:?}"),
            }
            // A line without the `file` key dies at the labeled reader
            // (the field is required), not at the label grammar.
            let err =
                parse_container_baseline("{\"issues\":[]}").expect_err("the keyless line refuses");
            match err {
                ContainerBaselineError::Line { line, .. } => assert_eq!(line, 1),
                other => panic!("expected a line refusal, got {other:?}"),
            }
        }

        #[test]
        fn the_multiset_survives_within_a_slice() {
            // Two findings at one site in the baseline, one now: one
            // survives, none introduced — the single-image multiset, one
            // slice at a time.
            let baseline = baseline_for(&[vec![sig(0x100), sig(0x100)], vec![]]);
            let next = container_report(&[vec![sig(0x100)], vec![]]);
            let delta = UniversalDelta::between_slices(&next, &baseline, &OffsetIdentity)
                .expect("the pairing agrees");
            assert_eq!(delta.slices[0].delta.surviving, 1);
            assert!(
                delta.slices[0].delta.introduced.is_empty(),
                "slice 0 introduced nothing"
            );
            assert_eq!(delta.slices[0].delta.resolved.len(), 1);
            let _ = BaselineDelta::default();
        }
    }
}
