//! M69 — the verifier's SARIF interchange: the M13 report JSON is the
//! house's own shape (one writer, one reader, gated), and the consumers
//! that read it today are the ones willing to speak Peregrine's dialect.
//! SARIF 2.1.0 is the shape the ecosystem already speaks — GitHub Code
//! Scanning, IDE problem panels and CI triage read it natively — so
//! [`render`] carries the [`Report`]'s findings into it: one result per
//! issue (`ruleId` the stable code token, `level` the severity, the
//! message verbatim, the anchor offset as a binary `region.byteOffset`).
//!
//! The face is a one-way writer — the SARIF reader is the consumer's
//! tooling, not ours — and the document keeps the house interchange
//! conventions: deterministic (two renders of one report are
//! byte-identical, the gate's own contract), one line, fixed key order,
//! the M13 escape rules ([`crate::report_json`]'s one copy). The rule
//! table rides one rule per distinct code in the report — the built-ins
//! in [`Code::ALL`]'s canonical order, the M67 custom tokens after them
//! in lexicographic order — so the document's key set is the report's
//! own, never the arrival order. An unanchored issue rides no location
//! (SARIF keeps the shape valid), a `Severity::Error` rides `error` and
//! a `Severity::Warning` rides `warning` (the only two severities the
//! verifier reports).
//!
//! The container verdict rides the same face since M95
//! ([`render_universal`]): one run per declared slice, in table order,
//! the rule table the union of the slices' codes, and every anchored
//! result riding a container-absolute `region.byteOffset` — the M75
//! CLI refusal ("a slice's anchors ride their own windows") had its
//! premise backwards, because the slices ride *inside* the audited file,
//! so re-anchoring is not re-shaping; the anchor names the file's own
//! bytes, which is what a triage tool reads.
//!
//! The baseline gate rides the same face since M97
//! ([`render_with_baseline`] / [`render_universal_with_baseline`]): the
//! M75 refusal ("the delta has no SARIF shape") had its premise backwards
//! too — SARIF 2.1.0 gives a result its own `baselineState`
//! (`new` / `unchanged` / `absent`), which is exactly the M13 delta's
//! three-way classification, so the whole-verdict document the gate
//! audited states the gate's own story, and a triage tool reads the
//! baseline diff natively.

use std::fmt::Write as _;

use crate::baseline::{BaselineDelta, ContainerBaseline};
use crate::report_json::escape;
use crate::{Code, Issue, Report, Severity, UniversalReport};

/// The SARIF 2.1.0 schema the document declares (the errata-2 os form).
const SARIF_SCHEMA: &str =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata2/os/sarif-schema-2.1.0.json";

/// The tool's identity in the run's driver block (the repo the tool ships
/// from — the README's own address).
const DRIVER_INFORMATION_URI: &str = "https://github.com/elcoosp/peregrine";

/// Renders the report as a deterministic SARIF 2.1.0 document: one line,
/// fixed key order, the M13 escape rules. `image` is the verified
/// artifact's name (the `artifactLocation.uri` every result points at —
/// the CLI passes the image path, a library consumer its own label).
#[must_use]
pub fn render(report: &Report, image: &str) -> String {
    let mut s = String::with_capacity(256 + report.issues.len() * 160);
    let _ = write!(
        s,
        "{{\"$schema\":{},\"version\":\"2.1.0\",\"runs\":[",
        escape(SARIF_SCHEMA),
    );
    write_run_prefix(&mut s, &distinct_codes(report), image);
    write_results(&mut s, report, image, 0);
    s.push_str("]}]}");
    s
}

/// Renders the container's whole verdict ([`UniversalReport`], M95) as
/// one deterministic SARIF 2.1.0 document: one run per declared slice,
/// in table order (the same order [`crate::verify_universal`] walks),
/// the rule table the union of the slices' codes — the built-ins in
/// [`Code::ALL`]'s canonical order, the custom tokens after them — and
/// every anchored result riding a **container-absolute**
/// `region.byteOffset` (`slice.offset + anchor`): the slices ride inside
/// the audited file, so the anchor names the file's own bytes, which is
/// what a triage tool reads. `image` is the verified artifact's name
/// (the CLI passes the container path, a library consumer its label).
///
/// The face keeps the M69 conventions: one line, fixed key order, the
/// M13 escape rules, an unanchored issue riding no location, and the
/// only two severities the verifier reports.
#[must_use]
pub fn render_universal(report: &UniversalReport, image: &str) -> String {
    let issues: usize = report.slices.iter().map(|s| s.report.issues.len()).sum();
    let mut s = String::with_capacity(256 + issues * 160);
    let _ = write!(
        s,
        "{{\"$schema\":{},\"version\":\"2.1.0\",\"runs\":[",
        escape(SARIF_SCHEMA),
    );
    let codes: Vec<&'static str> =
        distinct_codes_across(report.slices.iter().map(|slice| &slice.report));
    for (i, slice) in report.slices.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        write_run_prefix(&mut s, &codes, image);
        write_results(&mut s, &slice.report, image, slice.arch.offset);
        s.push_str("]}");
    }
    s.push_str("]}");
    s
}

/// One run's tool/artifact prefix, through the `results` array's opening
/// bracket (the writer `render` and [`render_universal`] share — the
/// driver identity and the artifact uri are the run's, the rule table
/// the caller's union).
fn write_run_prefix(s: &mut String, codes: &[&'static str], image: &str) {
    let _ = write!(
        s,
        "{{\"tool\":{{\"driver\":{{\"name\":\"pgr-verify\",\"version\":{},\"informationUri\":{},\"rules\":[",
        escape(env!("CARGO_PKG_VERSION")),
        escape(DRIVER_INFORMATION_URI),
    );
    for (i, code) in codes.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let _ = write!(s, "{{\"id\":{}}}", escape(code));
    }
    let _ = write!(
        s,
        "]}},\"artifacts\":[{{\"location\":{{\"uri\":{}}}}}],\"results\":[",
        escape(image),
    );
}

/// One run's results: one object per issue (`ruleId` the stable code
/// token, `level` the severity, the message verbatim, the anchor offset
/// `offset_bias + anchor` as a binary `region.byteOffset` — the bias
/// re-anchors a slice's window onto the container's own bytes, and is 0
/// for the single-image render). The baseline face's states ride the
/// same writer: `state` is `Some` exactly under
/// [`render_with_baseline`] / [`render_universal_with_baseline`], the
/// `baselineState` slot fixed after the message (the house fixed key
/// order — the M69 documents carry no state and stay byte-identical).
fn write_results(s: &mut String, report: &Report, image: &str, offset_bias: u64) {
    for (i, issue) in report.issues.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        write_result(s, issue, image, offset_bias, None);
    }
}

/// One result object: the shared writer every face composes.
fn write_result(
    s: &mut String,
    issue: &Issue,
    image: &str,
    offset_bias: u64,
    state: Option<BaselineState>,
) {
    let _ = write!(
        s,
        "{{\"ruleId\":{},\"level\":\"{}\",\"message\":{{\"text\":{}}}",
        escape(issue.code.as_str()),
        level(issue.severity),
        escape(&issue.message),
    );
    if let Some(state) = state {
        let _ = write!(s, ",\"baselineState\":\"{}\"", state.as_str());
    }
    if let Some(offset) = issue.offset {
        let anchor = offset_bias.wrapping_add(offset);
        let _ = write!(
            s,
            ",\"locations\":[{{\"physicalLocation\":{{\"artifactLocation\":{{\"uri\":{}}},\"region\":{{\"byteOffset\":{anchor}}}}}}}]",
            escape(image),
        );
    }
    s.push('}');
}

/// The severity's SARIF level (the enum's own two arms).
fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
    }
}

/// One result's state relative to the baseline (M97): SARIF 2.1.0's own
/// `baselineState` vocabulary — `new` (the finding the baseline does not
/// vouch for), `unchanged` (the tolerated history), `absent` (the
/// baseline finding that cleared) — which is exactly the M13 delta's
/// three-way classification, so the face needs no shape of its own (the
/// M75 refusal's premise, retired).
#[derive(Debug, Clone, Copy)]
enum BaselineState {
    /// The finding is fresh since the baseline.
    New,
    /// The finding rode the baseline and survives.
    Unchanged,
    /// The baseline finding cleared.
    Absent,
}

impl BaselineState {
    /// The document's token (SARIF 2.1.0's own enumeration).
    fn as_str(self) -> &'static str {
        match self {
            BaselineState::New => "new",
            BaselineState::Unchanged => "unchanged",
            BaselineState::Absent => "absent",
        }
    }
}

/// Classifies one report's issues against their delta (M97): a finding
/// is `new` exactly when it is one of the delta's `introduced` (matched
/// as a multiset, one consumption per pairing — a key the baseline
/// carried twice and the fresh report thrice rides one `unchanged` and
/// two `new`), and `unchanged` otherwise (the tolerated history). The
/// classification never invents a `new`: every report issue the
/// introduced list does not claim is one the baseline vouches for by
/// construction. The scan is O(issues × introduced) — the same deliberate
/// shape [`BaselineDelta::between`] runs, for the same reason (order
/// stability beats a hash map's hazards).
fn classify_states(
    report: &Report,
    delta: &BaselineDelta,
    identity: &dyn crate::IssueIdentity,
) -> Vec<BaselineState> {
    let mut introduced: Vec<crate::IssueKey> = delta
        .introduced
        .iter()
        .map(|issue| identity.key(issue))
        .collect();
    report
        .issues
        .iter()
        .map(|issue| {
            let key = identity.key(issue);
            match introduced.iter().position(|k| *k == key) {
                Some(at) => {
                    introduced.remove(at);
                    BaselineState::New
                }
                None => BaselineState::Unchanged,
            }
        })
        .collect()
}

/// Renders the report as a deterministic SARIF 2.1.0 document with the
/// baseline delta stated on every result (M97): the M69 conventions
/// hold unchanged (one line, fixed key order, the M13 escape rules, an
/// unanchored issue riding no location), and each result carries SARIF
/// 2.1.0's own `baselineState` — `new` / `unchanged` under `identity`
/// (the same policy the delta ran under), and the delta's `resolved`
/// findings ride `absent` after them, anchored at the **baseline
/// image's** own offsets (the gate audits the same artifact; a layout
/// shift that moved a cleared site rides under [`crate::CodeIdentity`],
/// which is what the policy is for). The rule table is the union of both
/// sides' codes — a resolved-only code still names itself, so a triage
/// tool sees the rule the absent finding rode.
#[must_use]
pub fn render_with_baseline(
    report: &Report,
    delta: &BaselineDelta,
    identity: &dyn crate::IssueIdentity,
    image: &str,
) -> String {
    let resolved_report = Report {
        issues: delta.resolved.clone(),
        stats: crate::Stats::default(),
    };
    let codes = distinct_codes_across([report, &resolved_report]);
    let states = classify_states(report, delta, identity);
    let mut s = String::with_capacity(256 + (report.issues.len() + delta.resolved.len()) * 200);
    let _ = write!(
        s,
        "{{\"$schema\":{},\"version\":\"2.1.0\",\"runs\":[",
        escape(SARIF_SCHEMA),
    );
    write_run_prefix(&mut s, &codes, image);
    let mut first = true;
    for (i, issue) in report.issues.iter().enumerate() {
        if !first {
            s.push(',');
        }
        first = false;
        write_result(&mut s, issue, image, 0, Some(states[i]));
    }
    for issue in &delta.resolved {
        if !first {
            s.push(',');
        }
        first = false;
        write_result(&mut s, issue, image, 0, Some(BaselineState::Absent));
    }
    s.push_str("]}]}");
    s
}

/// Renders the container's verdict with the baseline gate stated per
/// slice (M97): the M95 container face composed with the M96 pairing —
/// one run per declared slice, each run's results carrying SARIF 2.1.0's
/// `baselineState` against that slice's own delta (`new` / `unchanged`),
/// the slice's cleared baseline findings riding `absent` beside them,
/// anchored container-absolute (the M95 convention — the M96 window
/// agreement holds for the baseline's offsets too: the paired line
/// vouches for the same window, so slice-window-relative and
/// container-absolute agree on both sides). The rule table is the union
/// of every slice's two sides, named once per run.
///
/// # Errors
/// [`crate::ContainerBaselineError::SliceCount`] / [`crate::ContainerBaselineError::WindowMismatch`]
/// when the document and the container disagree (the M96 pairing's own
/// contract — the render never states findings against a window the
/// baseline does not vouch for).
pub fn render_universal_with_baseline(
    report: &UniversalReport,
    baseline: &ContainerBaseline,
    identity: &dyn crate::IssueIdentity,
    image: &str,
) -> Result<String, crate::ContainerBaselineError> {
    let delta = crate::UniversalDelta::between_slices(report, baseline, identity)?;
    let resolved_wraps: Vec<Report> = delta
        .slices
        .iter()
        .map(|slice| Report {
            issues: slice.delta.resolved.clone(),
            stats: crate::Stats::default(),
        })
        .collect();
    let codes = distinct_codes_across(
        report
            .slices
            .iter()
            .map(|slice| &slice.report)
            .chain(resolved_wraps.iter()),
    );
    let issues: usize = report
        .slices
        .iter()
        .map(|slice| slice.report.issues.len())
        .sum();
    let resolved: usize = resolved_wraps.iter().map(|r| r.issues.len()).sum();
    let mut s = String::with_capacity(256 + (issues + resolved) * 200);
    let _ = write!(
        s,
        "{{\"$schema\":{},\"version\":\"2.1.0\",\"runs\":[",
        escape(SARIF_SCHEMA),
    );
    for (i, slice_verdict) in report.slices.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        write_run_prefix(&mut s, &codes, image);
        let states = classify_states(&slice_verdict.report, &delta.slices[i].delta, identity);
        let mut first = true;
        for (k, issue) in slice_verdict.report.issues.iter().enumerate() {
            if !first {
                s.push(',');
            }
            first = false;
            write_result(
                &mut s,
                issue,
                image,
                slice_verdict.arch.offset,
                Some(states[k]),
            );
        }
        for issue in &delta.slices[i].delta.resolved {
            if !first {
                s.push(',');
            }
            first = false;
            write_result(
                &mut s,
                issue,
                image,
                slice_verdict.arch.offset,
                Some(BaselineState::Absent),
            );
        }
        s.push_str("]}");
    }
    s.push_str("]}");
    Ok(s)
}

/// The rule table's key set for one report: one entry per distinct code
/// in the report — the built-ins in [`Code::ALL`]'s canonical order, the
/// M67 custom tokens after them in lexicographic order (the document's
/// order is the report's content, never the arrival order).
fn distinct_codes(report: &Report) -> Vec<&'static str> {
    distinct_codes_across(std::iter::once(report))
}

/// The union table across several reports (the container verdict's one
/// table serving every run): the built-ins in [`Code::ALL`]'s canonical
/// order, the custom tokens after them in lexicographic order, each code
/// named once however many slices carry it.
fn distinct_codes_across<'a, I>(reports: I) -> Vec<&'static str>
where
    I: IntoIterator<Item = &'a Report>,
{
    let reports: Vec<&Report> = reports.into_iter().collect();
    let mut out = Vec::new();
    for code in Code::ALL {
        let token = code.as_str();
        if reports.iter().any(|report| {
            report
                .issues
                .iter()
                .any(|issue| issue.code.as_str() == token)
        }) {
            out.push(token);
        }
    }
    let mut customs: Vec<&'static str> = Vec::new();
    for report in &reports {
        for issue in &report.issues {
            if let Code::Custom(token) = issue.code
                && !customs.contains(&token)
                && !out.contains(&token)
            {
                customs.push(token);
            }
        }
    }
    customs.sort_unstable();
    out.extend(customs);
    out
}

/// The issue constructor re-exports keep this module's doc example honest
/// (the test matrix drives the real one; the module re-exports nothing).
#[cfg(test)]
mod tests {
    use super::*;
    use crate::IssueKey;
    use crate::baseline::{BaselineDelta, OffsetIdentity};

    #[test]
    fn the_level_arms_cover_the_severity() {
        assert_eq!(level(Severity::Error), "error");
        assert_eq!(level(Severity::Warning), "warning");
    }

    #[test]
    fn the_empty_report_is_the_smallest_valid_document() {
        let doc = render(&Report::default(), "app");
        assert!(doc.starts_with("{\"$schema\":\"https://docs.oasis-open.org"));
        assert!(doc.ends_with("\"results\":[]}]}"));
    }

    fn issue(code: Code, offset: Option<u64>) -> Issue {
        Issue::error(code, "probe", offset)
    }

    fn report_of(issues: &[Issue]) -> Report {
        Report {
            issues: issues.to_vec(),
            stats: crate::Stats::default(),
        }
    }

    #[test]
    fn the_states_classify_as_a_multiset() {
        // Two findings at one site in the fresh report, one introduced:
        // one `unchanged`, one `new` — the consumption is per pairing.
        let a = issue(Code::FixupsChain, Some(0x40));
        let report = report_of(&[a.clone(), a]);
        let delta = BaselineDelta::between(&[], &report.issues, &OffsetIdentity);
        assert_eq!(delta.introduced.len(), 2, "both sides are fresh");
        let delta = BaselineDelta {
            introduced: vec![issue(Code::FixupsChain, Some(0x40))],
            ..BaselineDelta::default()
        };
        let states = classify_states(
            &report_of(&[
                issue(Code::FixupsChain, Some(0x40)),
                issue(Code::FixupsChain, Some(0x40)),
            ]),
            &delta,
            &OffsetIdentity,
        );
        assert_eq!(
            states
                .iter()
                .filter(|s| matches!(s, BaselineState::New))
                .count(),
            1,
            "one pairing consumed one introduced"
        );
        assert_eq!(
            states
                .iter()
                .filter(|s| matches!(s, BaselineState::Unchanged))
                .count(),
            1,
            "the other rides the tolerated history"
        );
    }

    #[test]
    fn the_baseline_document_states_both_sides_and_determines() {
        let prev = report_of(&[
            issue(Code::FixupsChain, Some(0x40)),
            issue(Code::ExportTrie, Some(0x80)),
        ]);
        let next = report_of(&[issue(Code::ExportTrie, Some(0x80))]);
        let delta = BaselineDelta::between(&prev.issues, &next.issues, &OffsetIdentity);
        let doc = render_with_baseline(&next, &delta, &OffsetIdentity, "app");
        assert!(
            doc.contains("\"baselineState\":\"absent\""),
            "the cleared finding rides absent: {doc}"
        );
        assert!(
            doc.contains("\"baselineState\":\"unchanged\""),
            "the surviving finding rides unchanged: {doc}"
        );
        assert!(
            doc.contains("\"id\":\"fixups_chain\""),
            "the resolved-only code names itself in the rules: {doc}"
        );
        assert!(doc.ends_with("]}]}"), "one document, one run");
        let again = render_with_baseline(&next, &delta, &OffsetIdentity, "app");
        assert_eq!(doc, again, "two renders of one run are byte-identical");
    }

    #[test]
    fn the_keys_carry_the_state_in_fixed_order() {
        let next = report_of(&[issue(Code::Suspicious, Some(0x10))]);
        let delta = BaselineDelta::between(&[], &next.issues, &OffsetIdentity);
        let doc = render_with_baseline(&next, &delta, &OffsetIdentity, "app");
        let message_at = doc.find("\"message\"").expect("the message rides");
        let state_at = doc.find("\"baselineState\"").expect("the state rides");
        let locations_at = doc.find("\"locations\"").expect("the location rides");
        assert!(
            message_at < state_at && state_at < locations_at,
            "ruleId, level, message, baselineState, locations — the fixed order: {doc}"
        );
        let _ = IssueKey {
            code: Code::Suspicious,
            offset: None,
        };
    }
}
