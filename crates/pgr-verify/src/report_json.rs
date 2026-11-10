//! The report's JSON interchange shape (M13 rung 1): the machine-readable
//! form the `pgr-verify` CLI prints, moved into the library so the shape
//! has exactly one writer, one reader, and a round-trip gate.
//!
//! Before this module the report was write-only: the CLI hand-rolled its
//! JSON on the way out, and a build system that wanted to gate a relink
//! on "the issues from last time" had to re-parse the writer's output
//! outside the tree. The shape is now a library value:
//!
//! * [`to_json`] renders a [`Report`] (stats + issues, no file key);
//! * [`to_json_with_file`] renders the CLI's whole-output shape (the
//!   `file` key first) — the CLI calls this, so the wire format cannot
//!   drift between the binary and the library;
//! * [`parse_report_json`] reads either shape back (unknown keys are
//!   ignored, forward-compatible), refusing malformed input with a
//!   typed [`ReportJsonError`] that names the offense — the parser is
//!   total (never panics) like every reader in the workspace;
//! * [`to_json_with_baseline`] appends the baseline delta's machine
//!   block (the `--baseline` CLI surface).
//!
//! The escaping rules are the CLI writer's original ones, preserved
//! byte-for-byte: minimal JSON escapes plus `\uXXXX` for the remaining
//! control characters, no dependency on a JSON crate (the workspace
//! carries none).

use std::fmt::Write as _;

use crate::{Code, Issue, Report, Severity, Stats};

/// A [`parse_report_json`] refusal: where the input died and what the
/// reader expected there. The fix is in the message, not just the
/// verdict (the house error convention).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReportJsonError {
    /// The input is not the report shape at this byte.
    #[error("invalid report JSON at byte {at}: {detail}")]
    Syntax {
        /// Byte offset the parser died at.
        at: usize,
        /// What the parser expected there.
        detail: String,
    },
    /// A required field is missing, mistyped, or out of range.
    #[error("report JSON field `{name}`: {detail}")]
    Field {
        /// The offending field name.
        name: &'static str,
        /// What the field required.
        detail: String,
    },
}

/// Renders the report's body shape: `{"stats":{…},"issues":[…]}` — the
/// library form (no `file` key; the report carries no path).
#[must_use]
pub fn to_json(report: &Report) -> String {
    let mut s = String::with_capacity(256 + report.issues.len() * 64);
    s.push('{');
    write_fields(&mut s, report);
    s.push('}');
    s
}

/// Renders the CLI's whole-output shape: the `file` key first, then the
/// body ([`to_json`]). The CLI calls this so the wire format has one
/// writer.
#[must_use]
pub fn to_json_with_file(file: &str, report: &Report) -> String {
    let mut s = String::with_capacity(256 + report.issues.len() * 64);
    s.push('{');
    let _ = write!(s, "\"file\":{},", escape(file));
    write_fields(&mut s, report);
    s.push('}');
    s
}

/// Renders the CLI's baseline-gate shape: the whole output plus the
/// delta block (`"baseline"`) naming the policy, the introduced and
/// resolved findings, and the surviving count.
#[must_use]
pub fn to_json_with_baseline(
    file: &str,
    report: &Report,
    baseline: &crate::BaselineDelta,
    policy: &str,
) -> String {
    let mut s = String::with_capacity(384 + report.issues.len() * 64);
    s.push('{');
    let _ = write!(s, "\"file\":{},", escape(file));
    write_fields(&mut s, report);
    s.push_str(",\"baseline\":{\"policy\":");
    s.push_str(&escape(policy));
    s.push_str(",\"introduced\":[");
    write_issues(&mut s, &baseline.introduced);
    s.push_str("],\"resolved\":[");
    write_issues(&mut s, &baseline.resolved);
    let _ = write!(s, "],\"surviving\":{}}}", baseline.surviving);
    s.push('}');
    s
}

/// Writes `"stats":{…},"issues":[…]` (no braces) — the shared body of
/// every rendering above.
fn write_fields(s: &mut String, report: &Report) {
    let st = &report.stats;
    let _ = write!(
        s,
        "\"stats\":{{\"segments\":{},\"sections\":{},\"symbols\":{},\"fixup_slots\":{},\"hash_pages\":{}}},\"issues\":[",
        st.segments, st.sections, st.symbols, st.fixup_slots, st.hash_pages
    );
    write_issues(s, &report.issues);
    s.push(']');
}

/// Writes a comma-separated issue array's items (no brackets).
fn write_issues(s: &mut String, issues: &[Issue]) {
    for (i, issue) in issues.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        write_issue(s, issue);
    }
}

/// Writes one issue object (the shape every array in the format shares).
fn write_issue(s: &mut String, issue: &Issue) {
    let sev = match issue.severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
    };
    let offset = match issue.offset {
        Some(o) => o.to_string(),
        None => "null".to_owned(),
    };
    let _ = write!(
        s,
        "{{\"severity\":{},\"code\":{},\"message\":{},\"offset\":{}}}",
        escape(sev),
        escape(issue.code.as_str()),
        escape(&issue.message),
        offset
    );
}

/// Minimal JSON string escaping (the CLI writer's original rules):
/// the two mandatory escapes, the short forms, and `\uXXXX` for the
/// remaining control characters.
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Parses a report JSON document back into a [`Report`].
///
/// Accepts both rendered shapes: the library body ([`to_json`]) and the
/// CLI whole-output form (`"file"` first) — unknown keys are ignored so
/// the format can grow without breaking old baselines. Required: the
/// `issues` array (each item's `severity`, `code`, `message`); `offset`
/// defaults to null and `stats` to the zero report when absent, so a
/// hand-authored baseline stays readable.
///
/// # Errors
/// [`ReportJsonError::Syntax`] with the byte offset for structural
/// damage; [`ReportJsonError::Field`] naming the field for wrong types,
/// unknown codes, or out-of-range counters. The parser is total — it
/// never panics on any input (the workspace's reader contract).
pub fn parse_report_json(s: &str) -> Result<Report, ReportJsonError> {
    let mut p = Parser {
        b: s.as_bytes(),
        at: 0,
        depth: 0,
    };
    p.skip_ws();
    let report = p.parse_report()?;
    p.skip_ws();
    if p.at != p.b.len() {
        return Err(p.syntax("trailing content after the top-level object"));
    }
    Ok(report)
}

/// Recursion cap for nested containers (a hostile baseline cannot blow
/// the stack — the reader must survive arbitrary input).
const MAX_DEPTH: usize = 64;

struct Parser<'a> {
    b: &'a [u8],
    at: usize,
    depth: usize,
}

impl Parser<'_> {
    fn syntax(&self, detail: impl Into<String>) -> ReportJsonError {
        ReportJsonError::Syntax {
            at: self.at,
            detail: detail.into(),
        }
    }

    fn field(name: &'static str, detail: impl Into<String>) -> ReportJsonError {
        ReportJsonError::Field {
            name,
            detail: detail.into(),
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.at).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn expect(&mut self, c: u8) -> Result<(), ReportJsonError> {
        if self.peek() == Some(c) {
            self.at += 1;
            Ok(())
        } else {
            Err(self.syntax(format!("expected `{}`", c as char)))
        }
    }

    fn literal(&mut self, word: &str) -> Result<(), ReportJsonError> {
        if self.b[self.at..].starts_with(word.as_bytes()) {
            self.at += word.len();
            Ok(())
        } else {
            Err(self.syntax(format!("expected `{word}`")))
        }
    }

    /// Parses the top-level report object (the only object the reader
    /// interprets; every other object is skipped wholesale).
    fn parse_report(&mut self) -> Result<Report, ReportJsonError> {
        self.enter()?;
        self.expect(b'{')?;
        let mut report = Report::default();
        let mut seen_issues = false;
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.at += 1;
            self.leave();
            // The writer always emits the `issues` key; a report object
            // without it is a shape error, not the empty report.
            return Err(Self::field("issues", "required (the findings array)"));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            match key.as_str() {
                "issues" => {
                    report.issues = self.parse_issues()?;
                    seen_issues = true;
                }
                "stats" => report.stats = self.parse_stats()?,
                _ => self.skip_value()?,
            }
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    break;
                }
                _ => return Err(self.syntax("expected `,` or `}` in the report object")),
            }
        }
        self.leave();
        if seen_issues {
            Ok(report)
        } else {
            Err(Self::field("issues", "required (the findings array)"))
        }
    }

    fn parse_issues(&mut self) -> Result<Vec<Issue>, ReportJsonError> {
        self.enter()?;
        self.expect(b'[')?;
        let mut issues = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.at += 1;
            self.leave();
            return Ok(issues);
        }
        loop {
            self.skip_ws();
            issues.push(self.parse_issue()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    break;
                }
                _ => return Err(self.syntax("expected `,` or `]` in the issues array")),
            }
        }
        self.leave();
        Ok(issues)
    }

    fn parse_issue(&mut self) -> Result<Issue, ReportJsonError> {
        self.enter()?;
        self.expect(b'{')?;
        let mut severity: Option<Severity> = None;
        let mut code: Option<Code> = None;
        let mut message: Option<String> = None;
        let mut offset: Option<u64> = None;
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.at += 1;
            self.leave();
            return Err(Self::field("issues[]", "missing severity, code, message"));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            match key.as_str() {
                "severity" => {
                    let s = self.parse_string()?;
                    severity = Some(match s.as_str() {
                        "error" => Severity::Error,
                        "warning" => Severity::Warning,
                        other => {
                            return Err(Self::field(
                                "severity",
                                format!("`{other}` is not `error` or `warning`"),
                            ));
                        }
                    });
                }
                "code" => {
                    let s = self.parse_string()?;
                    code = Some(
                        Code::ALL
                            .iter()
                            .copied()
                            .find(|c| c.as_str() == s)
                            .ok_or_else(|| {
                                Self::field("code", format!("`{s}` names no issue code"))
                            })?,
                    );
                }
                "message" => message = Some(self.parse_string()?),
                "offset" => offset = self.parse_opt_u64("offset")?,
                _ => self.skip_value()?,
            }
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    break;
                }
                _ => return Err(self.syntax("expected `,` or `}` in the issue object")),
            }
        }
        self.leave();
        let severity =
            severity.ok_or_else(|| Self::field("severity", "required (`error` or `warning`)"))?;
        let code = code.ok_or_else(|| Self::field("code", "required (a canonical code)"))?;
        let message = message.ok_or_else(|| Self::field("message", "required (the human text)"))?;
        Ok(Issue {
            severity,
            code,
            message,
            offset,
        })
    }

    fn parse_stats(&mut self) -> Result<Stats, ReportJsonError> {
        self.enter()?;
        self.expect(b'{')?;
        let mut st = Stats::default();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.at += 1;
            self.leave();
            return Ok(st);
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            match key.as_str() {
                "segments" => st.segments = self.parse_u32("segments")?,
                "sections" => st.sections = self.parse_u32("sections")?,
                "symbols" => st.symbols = self.parse_u32("symbols")?,
                "fixup_slots" => st.fixup_slots = self.parse_u64_field("fixup_slots")?,
                "hash_pages" => st.hash_pages = self.parse_u64_field("hash_pages")?,
                _ => self.skip_value()?,
            }
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    break;
                }
                _ => return Err(self.syntax("expected `,` or `}` in the stats object")),
            }
        }
        self.leave();
        Ok(st)
    }

    fn parse_u32(&mut self, name: &'static str) -> Result<u32, ReportJsonError> {
        let v = self.parse_u64_field(name)?;
        u32::try_from(v).map_err(|_| Self::field(name, format!("{v} exceeds u32::MAX")))
    }

    fn parse_u64_field(&mut self, name: &'static str) -> Result<u64, ReportJsonError> {
        self.skip_ws();
        self.parse_u64(name)
    }

    /// `null | unsigned integer` (the `offset` shape).
    fn parse_opt_u64(&mut self, name: &'static str) -> Result<Option<u64>, ReportJsonError> {
        self.skip_ws();
        if self.peek() == Some(b'n') {
            self.literal("null")?;
            return Ok(None);
        }
        Ok(Some(self.parse_u64_field(name)?))
    }

    /// An unsigned JSON integer; floats, signs and exponents are not
    /// part of the report shape and are refused with the field named.
    fn parse_u64(&mut self, name: &'static str) -> Result<u64, ReportJsonError> {
        let start = self.at;
        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
            self.at += 1;
        }
        if self.at == start {
            return Err(self.syntax("expected a non-negative integer"));
        }
        let text = std::str::from_utf8(&self.b[start..self.at])
            .map_err(|_| self.syntax("invalid UTF-8 in a number"))?;
        text.parse::<u64>()
            .map_err(|_| Self::field(name, format!("`{text}` exceeds u64::MAX")))
    }

    fn parse_string(&mut self) -> Result<String, ReportJsonError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let Some(c) = self.peek() else {
                return Err(self.syntax("unterminated string"));
            };
            self.at += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    let Some(esc) = self.peek() else {
                        return Err(self.syntax("unterminated escape"));
                    };
                    self.at += 1;
                    match esc {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.parse_hex4()?;
                            let ch = if (0xD800..0xDC00).contains(&hi) {
                                // A surrogate pair: the low half must follow.
                                if self.peek() == Some(b'\\') {
                                    self.at += 1;
                                    self.expect(b'u')?;
                                    let lo = self.parse_hex4()?;
                                    let combined = 0x1_0000
                                        + ((u32::from(hi) - 0xD800) << 10)
                                        + (u32::from(lo) - 0xDC00);
                                    char::from_u32(combined)
                                        .ok_or_else(|| self.syntax("invalid surrogate pair"))?
                                } else {
                                    return Err(
                                        self.syntax("lone surrogate (expected the \\u low half)")
                                    );
                                }
                            } else {
                                char::from_u32(u32::from(hi))
                                    .ok_or_else(|| self.syntax("invalid \\u escape"))?
                            };
                            out.push(ch);
                        }
                        other => {
                            return Err(
                                self.syntax(format!("unknown escape `\\{}`", other as char))
                            );
                        }
                    }
                }
                c if c < 0x20 => return Err(self.syntax("raw control character in a string")),
                c if c < 0x80 => out.push(c as char),
                _ => {
                    // Multi-byte UTF-8: find the full sequence.
                    let start = self.at - 1;
                    let len = utf8_len(c);
                    let end = start + len;
                    let Some(slice) = self.b.get(start..end) else {
                        return Err(self.syntax("truncated UTF-8 sequence"));
                    };
                    let s = std::str::from_utf8(slice)
                        .map_err(|_| self.syntax("invalid UTF-8 in a string"))?;
                    out.push_str(s);
                    self.at = end;
                }
            }
        }
    }

    fn parse_hex4(&mut self) -> Result<u16, ReportJsonError> {
        if self.at + 4 > self.b.len() {
            return Err(self.syntax("truncated \\u escape"));
        }
        let hex = std::str::from_utf8(&self.b[self.at..self.at + 4])
            .map_err(|_| self.syntax("invalid \\u escape"))?;
        let v = u16::from_str_radix(hex, 16).map_err(|_| self.syntax("invalid \\u escape"))?;
        self.at += 4;
        Ok(v)
    }

    /// Skips any well-formed JSON value (unknown keys are ignored, not
    /// refused — the format grows forward-compatibly).
    fn skip_value(&mut self) -> Result<(), ReportJsonError> {
        self.enter()?;
        self.skip_ws();
        match self.peek() {
            Some(b'"') => {
                let _ = self.parse_string()?;
            }
            Some(b'{') => {
                self.at += 1;
                self.skip_ws();
                if self.peek() == Some(b'}') {
                    self.at += 1;
                } else {
                    loop {
                        self.skip_ws();
                        let _ = self.parse_string()?;
                        self.skip_ws();
                        self.expect(b':')?;
                        self.skip_value()?;
                        self.skip_ws();
                        match self.peek() {
                            Some(b',') => self.at += 1,
                            Some(b'}') => {
                                self.at += 1;
                                break;
                            }
                            _ => return Err(self.syntax("expected `,` or `}` in an object")),
                        }
                    }
                }
            }
            Some(b'[') => {
                self.at += 1;
                self.skip_ws();
                if self.peek() == Some(b']') {
                    self.at += 1;
                } else {
                    loop {
                        self.skip_value()?;
                        self.skip_ws();
                        match self.peek() {
                            Some(b',') => self.at += 1,
                            Some(b']') => {
                                self.at += 1;
                                break;
                            }
                            _ => return Err(self.syntax("expected `,` or `]` in an array")),
                        }
                    }
                }
            }
            Some(b't') => self.literal("true")?,
            Some(b'f') => self.literal("false")?,
            Some(b'n') => self.literal("null")?,
            Some(c) if c == b'-' || c.is_ascii_digit() => {
                if self.peek() == Some(b'-') {
                    self.at += 1;
                }
                while matches!(self.peek(), Some(c) if c.is_ascii_digit() || matches!(c, b'.' | b'e' | b'E' | b'+' | b'-'))
                {
                    self.at += 1;
                }
            }
            _ => return Err(self.syntax("expected a JSON value")),
        }
        self.leave();
        Ok(())
    }

    fn enter(&mut self) -> Result<(), ReportJsonError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(self.syntax("nested too deeply"));
        }
        Ok(())
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }
}

/// The UTF-8 sequence length for a lead byte (the input came from a
/// `&str`, so only the four valid lengths occur).
fn utf8_len(lead: u8) -> usize {
    match lead {
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::{ReportJsonError, escape, parse_report_json, to_json};
    use crate::{Code, Issue, Report};

    #[test]
    fn escape_produces_the_documented_short_forms() {
        assert_eq!(escape("a\"b\\c\nd\te"), "\"a\\\"b\\\\c\\nd\\te\"");
        assert_eq!(escape("\u{1}"), "\"\\u0001\"");
        assert_eq!(escape("café ✓"), "\"café ✓\"");
    }

    #[test]
    fn empty_report_round_trips() {
        let r = Report::default();
        assert_eq!(parse_report_json(&to_json(&r)).expect("parses"), r);
    }

    #[test]
    fn surrogate_pairs_survive_the_round_trip() {
        let mut r = Report::default();
        r.issues.push(Issue::error(
            Code::Suspicious,
            "astral: \u{1F4A3} and accented \u{e9}",
            None,
        ));
        let parsed = parse_report_json(&to_json(&r)).expect("parses");
        assert_eq!(parsed.issues[0].message, r.issues[0].message);
    }

    #[test]
    fn lone_surrogates_are_a_named_error() {
        let err = parse_report_json("{\"issues\":[],\"x\":\"\\ud800\"}")
            .expect_err("lone surrogate refused");
        assert!(matches!(err, ReportJsonError::Syntax { .. }));
    }

    #[test]
    fn deep_nesting_is_refused_not_blown() {
        // The depth cap lives in skip_value (unknown keys are skipped
        // wholesale) — the only path that recurses unboundedly.
        let deep = format!("{}{}", "[".repeat(80), "]".repeat(80));
        let err = parse_report_json(&format!("{{\"zzz\":{deep},\"issues\":[]}}"))
            .expect_err("depth cap refuses");
        assert!(err.to_string().contains("deeply"));
    }

    #[test]
    fn unknown_keys_are_ignored_forward_compatibly() {
        let parsed = parse_report_json(
            "{\"future\":{\"a\":[1,2,{\"b\":null}]},\"file\":\"x\",\"issues\":[],\"stats\":{}}",
        )
        .expect("unknown keys skipped");
        assert_eq!(parsed.issues.len(), 0);
    }
}
