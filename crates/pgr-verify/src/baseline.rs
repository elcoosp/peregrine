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
//! ```no_run
//! use pgr_verify::{CodeIdentity, Issue, OffsetIdentity, parse_report_json};
//!
//! let prev = parse_report_json(r#"{"issues":[]}"#).expect("baseline");
//! let next: Vec<Issue> = Vec::new();
//! let delta = pgr_verify::BaselineDelta::between(&prev.issues, &next, &OffsetIdentity);
//! assert!(delta.is_clean());
//! let _ = CodeIdentity; // the moved-finding policy, same shape
//! ```

use crate::Issue;

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
}
