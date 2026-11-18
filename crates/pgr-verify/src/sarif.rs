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

use std::fmt::Write as _;

use crate::report_json::escape;
use crate::{Code, Report, Severity};

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
        "{{\"$schema\":{},\"version\":\"2.1.0\",\"runs\":[{{\"tool\":{{\"driver\":{{\"name\":\"pgr-verify\",\"version\":{},\"informationUri\":{},\"rules\":[",
        escape(SARIF_SCHEMA),
        escape(env!("CARGO_PKG_VERSION")),
        escape(DRIVER_INFORMATION_URI),
    );
    for (i, code) in distinct_codes(report).iter().enumerate() {
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
    for (i, issue) in report.issues.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let _ = write!(
            s,
            "{{\"ruleId\":{},\"level\":\"{}\",\"message\":{{\"text\":{}}}",
            escape(issue.code.as_str()),
            level(issue.severity),
            escape(&issue.message),
        );
        if let Some(offset) = issue.offset {
            let _ = write!(
                s,
                ",\"locations\":[{{\"physicalLocation\":{{\"artifactLocation\":{{\"uri\":{}}},\"region\":{{\"byteOffset\":{offset}}}}}}}]",
                escape(image),
            );
        }
        s.push('}');
    }
    s.push_str("]}]}");
    s
}

/// The severity's SARIF level (the enum's own two arms).
fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
    }
}

/// The rule table's key set: one entry per distinct code in the report —
/// the built-ins in [`Code::ALL`]'s canonical order, the M67 custom
/// tokens after them in lexicographic order (the document's order is the
/// report's content, never the arrival order).
fn distinct_codes(report: &Report) -> Vec<&'static str> {
    let mut out = Vec::new();
    for code in Code::ALL {
        let token = code.as_str();
        if report
            .issues
            .iter()
            .any(|issue| issue.code.as_str() == token)
        {
            out.push(token);
        }
    }
    let mut customs: Vec<&'static str> = Vec::new();
    for issue in &report.issues {
        if let Code::Custom(token) = issue.code
            && !customs.contains(&token)
            && !out.contains(&token)
        {
            customs.push(token);
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
}
