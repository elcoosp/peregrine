//! Text-based dylib stub (`.tbd`) parsing — TAPI "pseudo-binary" v3 and v4.
//!
//! An `.tbd` file describes a dylib *without carrying its bytes*: the install
//! name (`LC_LOAD_DYLIB` content), the exported symbol list (the two-level
//! resolution domain, M2) and bookkeeping versions. The linker never reads a
//! dylib's code for a dynamic link — only these stubs — so this parser is the
//! whole Pass 0 surface for dylib inputs.
//!
//! Scope (M2, architecture doc §10.3 "M2 — Dynamic executable"):
//! * `tbd-version: 3` (`--- !tbd-tbd-version-3.0`) and `tbd-version: 4`
//!   (`--- !tapi-tbd`) documents,
//! * the `arm64-macos` target (other targets are filtered, not errors —
//!   real stubs list every platform),
//! * `install-name`, `current-version`, `compatibility-version`, `exports`
//!   (`symbols` + `weak-symbols`), `re-exports`, `parent-umbrella`,
//!   `undefineds` (parsed, reported, unused at M2),
//! * `flags: [ installapi / not_for_installapi ]` accepted and ignored.
//!
//! The file is a YAML *subset*: block mappings, block/flow sequences, scalar
//! strings (optionally single/double quoted), integer and dotted-version
//! scalars, `...`/`---` markers and `#` comments. Anything outside that
//! subset (anchors, tags beyond the two document markers, flow mappings,
//! multi-line block scalars) is rejected with a typed error rather than
//! mis-parsed. Like every format-layer parser, it is total: malformed or
//! malicious input produces an error, never a panic.

use crate::error::FormatError;

/// One exported symbol of a stub dylib.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TbdSymbol {
    /// Symbol name with its C-language underscore (`_printf`).
    pub name: String,
    /// Weak-exported symbol (`weak-symbols` group in the stub).
    pub weak: bool,
}

/// A parsed text-based dylib stub.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Tbd {
    /// TAPI pseudo-binary version (3 or 4).
    pub tbd_version: u8,
    /// Install name: the `LC_LOAD_DYLIB` string and the two-level namespace
    /// key for ordinals.
    pub install_name: String,
    /// `LC_LOAD_DYLIB` current version (`X.Y.Z` packed, 0 when absent).
    pub current_version: u32,
    /// `LC_LOAD_DYLIB` compatibility version (0 when absent).
    pub compatibility_version: u32,
    /// Exported symbols (regular + weak, in file order, deduplicated).
    pub exports: Vec<TbdSymbol>,
    /// `re-exports` install names (M3 consumes them; parsed and carried).
    pub re_exports: Vec<String>,
    /// `undefineds` symbol names (dyld resolves them at launch; unused at M2).
    pub undefineds: Vec<String>,
}

impl Tbd {
    /// True when the stub exports `name`.
    #[must_use]
    pub fn exports(&self, name: &[u8]) -> bool {
        self.exports.iter().any(|s| s.name.as_bytes() == name)
    }
}

/// Parses a `.tbd` document (v3 or v4).
///
/// # Errors
/// [`FormatError`] on any structural or semantic violation (missing
/// `install-name`, unknown keys, no `arm64-macos` target, non-scalar values,
/// truncated documents). The parser never panics on arbitrary input.
pub fn parse_tbd(bytes: &[u8]) -> Result<Tbd, FormatError> {
    let doc = std::str::from_utf8(bytes).map_err(|_| FormatError::Malformed {
        what: ".tbd content is not UTF-8".into(),
    })?;
    let mut lines = Lines::new(doc);

    // Document marker: v4 uses `--- !tapi-tbd`, v3 uses
    // `--- !tbd-tbd-version-3.0` (some tools also write v4 without a tag —
    // accept a bare `---` and let `tbd-version` decide).
    let mut version: Option<u8> = None;
    let marker = lines.next_marker()?;
    match marker.strip_prefix("---").unwrap_or("").trim() {
        "!tapi-tbd" => version = Some(4),
        "!tbd-tbd-version-3.0" => version = Some(3),
        "" => {}
        other => {
            return Err(FormatError::Malformed {
                what: format!("unknown .tbd document tag {other:?}"),
            });
        }
    }

    let mut tbd = Tbd::default();
    let mut exports: Option<Vec<TbdSymbol>> = None;
    while let Some(line) = lines.next_line()? {
        let content = content_of(line);
        if content.starts_with("---") {
            return Err(FormatError::Malformed {
                what: "second document in one .tbd".into(),
            });
        }
        if content == "..." {
            break;
        }
        let (key, value) = parse_key_value(content)?;
        match key {
            "tbd-version" => {
                let v = scalar_u64(value)?;
                if v != 3 && v != 4 {
                    return Err(FormatError::Malformed {
                        what: format!("unsupported tbd-version {v}"),
                    });
                }
                version = Some(u8::try_from(v).unwrap_or(0));
            }
            "install-name" => tbd.install_name = scalar_string(value)?.to_string(),
            "current-version" => tbd.current_version = packed_version(value)?,
            "compatibility-version" => tbd.compatibility_version = packed_version(value)?,
            "targets" => {
                let targets = flow_sequence(value)?;
                if !targets.iter().any(|t| t == "arm64-macos") {
                    return Err(FormatError::Malformed {
                        what: ".tbd has no arm64-macos target".into(),
                    });
                }
            }
            "flags" => {
                let _ = flow_sequence(value)?;
            }
            "parent-umbrella" | "objc-constraint" | "swift-abi-version" | "platforms" => {
                let _ = scalar_string(value)?;
            }
            "uuids" => {
                // v3: `- target: uuid` lines; parsed and ignored.
                let _ = block_groups(&mut lines, value)?;
            }
            "exports" | "re-exports" | "undefineds" => {
                let groups = block_groups(&mut lines, value)?;
                match key {
                    "re-exports" => {
                        for g in groups {
                            tbd.re_exports
                                .extend(g.symbols.into_iter().map(|(name, _)| name));
                        }
                    }
                    "undefineds" => {
                        for g in groups {
                            tbd.undefineds
                                .extend(g.symbols.into_iter().map(|(name, _)| name));
                        }
                    }
                    _ => {
                        exports = Some(
                            groups
                                .into_iter()
                                .flat_map(|g| g.symbols)
                                .map(|(name, weak)| TbdSymbol { name, weak })
                                .collect(),
                        );
                    }
                }
            }
            other => {
                return Err(FormatError::Malformed {
                    what: format!("unknown .tbd key {other:?}"),
                });
            }
        }
    }

    if tbd.install_name.is_empty() {
        return Err(FormatError::Malformed {
            what: ".tbd has no install-name".into(),
        });
    }
    tbd.tbd_version = version.unwrap_or(4);
    tbd.exports = dedup_exports(exports.unwrap_or_default());
    Ok(tbd)
}

/// Exported-symbol groups collected from an `exports:`/`re-exports:`
/// /`undefineds:` block.
#[derive(Debug, Default)]
struct SymbolGroup {
    /// Symbols of the group with their weak flags (`symbols` are regular,
    /// `weak-symbols` are weak).
    symbols: Vec<(String, bool)>,
}

/// Column of the first non-space character of a line.
fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start_matches(' ').len()
}

/// A content line: comment stripped, trailing whitespace trimmed.
fn content_of(line: &str) -> &str {
    let no_comment = match line.find(" #") {
        Some(at) if !line[..at].contains('"') => &line[..at],
        _ => line,
    };
    no_comment.trim_end()
}

/// Line cursor over the document: skips blank lines and comment lines,
/// keeps raw lines (indentation drives block-structure parsing).
struct Lines<'a> {
    /// The raw document lines (indentation drives block parsing).
    iter: std::str::Lines<'a>,
    peeked: Option<&'a str>,
    done: bool,
}

impl<'a> Lines<'a> {
    fn new(doc: &'a str) -> Self {
        Self {
            iter: doc.lines(),
            peeked: None,
            done: false,
        }
    }

    fn next_line(&mut self) -> Result<Option<&'a str>, FormatError> {
        loop {
            if self.done {
                return Ok(None);
            }
            let line = if let Some(l) = self.peeked.take() {
                l
            } else {
                let Some(l) = self.iter.next() else {
                    self.done = true;
                    return Ok(None);
                };
                l
            };
            let content = content_of(line).trim_start();
            if content.is_empty() || content.starts_with('#') {
                continue;
            }
            return Ok(Some(line));
        }
    }

    fn next_marker(&mut self) -> Result<&'a str, FormatError> {
        let line = self.next_line()?.ok_or(FormatError::Malformed {
            what: ".tbd is empty".into(),
        })?;
        let content = content_of(line);
        if !content.starts_with("---") {
            return Err(FormatError::Malformed {
                what: ".tbd does not start with a `---` document marker".into(),
            });
        }
        Ok(content)
    }
}

/// Splits `key: value` (the value may be empty for block constructs).
fn parse_key_value(line: &str) -> Result<(&str, &str), FormatError> {
    if line == "..." {
        return Ok(("...", ""));
    }
    let (key, value) = line.split_once(':').ok_or(FormatError::Malformed {
        what: format!("expected `key: value`, got {line:?}"),
    })?;
    Ok((key.trim(), value.trim()))
}

/// Parses a scalar string (quotes optional, backslash escapes in doubles).
fn scalar_string(value: &str) -> Result<&str, FormatError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(FormatError::Malformed {
            what: "expected a scalar value, found nothing".into(),
        });
    }
    if let Some(rest) = value.strip_prefix('\'') {
        let end = rest.split('\'').next().ok_or(FormatError::Malformed {
            what: "unterminated single-quoted scalar".into(),
        })?;
        return Ok(end);
    }
    if let Some(rest) = value.strip_prefix('"') {
        let end = rest.split('"').next().ok_or(FormatError::Malformed {
            what: "unterminated double-quoted scalar".into(),
        })?;
        return Ok(end);
    }
    Ok(value)
}

/// Parses a decimal scalar.
fn scalar_u64(value: &str) -> Result<u64, FormatError> {
    scalar_string(value)?
        .parse::<u64>()
        .map_err(|_| FormatError::Malformed {
            what: format!("expected a decimal scalar, got {value:?}"),
        })
}

/// Parses `[a, b, c]` flow sequences.
fn flow_sequence(value: &str) -> Result<Vec<String>, FormatError> {
    let value = value.trim();
    if !(value.starts_with('[') && value.ends_with(']')) {
        return Err(FormatError::Malformed {
            what: format!("expected a `[...]` flow sequence, got {value:?}"),
        });
    }
    let inner = &value[1..value.len() - 1];
    let mut out = Vec::new();
    for item in inner.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        out.push(scalar_string(item)?.to_string());
    }
    Ok(out)
}

/// Parses `X.Y.Z[.w]` version scalars into the packed
/// `X << 16 | Y << 8 | Z` form (w and beyond are folded into Z).
fn packed_version(value: &str) -> Result<u32, FormatError> {
    let text = scalar_string(value)?;
    let mut parts = text.split('.');
    let mut nums = [0u32; 3];
    for slot in &mut nums {
        match parts.next() {
            Some(p) if !p.is_empty() => {
                *slot = p
                    .parse::<u32>()
                    .map_err(|_| FormatError::Malformed {
                        what: format!("bad version component in {text:?}"),
                    })?
                    .min(0xff);
            }
            _ => break,
        }
    }
    if parts.next().is_some() {
        // Components beyond the third are folded: keep the low 8 bits of the
        // sum so `1.2.3.4` still round-trips through the packed value.
        let extra: u32 = parts
            .map(|p| p.parse::<u32>().unwrap_or(0))
            .sum::<u32>()
            .min(0xff);
        nums[2] = nums[2].saturating_add(extra).min(0xff);
    }
    Ok((nums[0] << 16) | (nums[1] << 8) | nums[2])
}

/// Parses a block-sequence of groups:
///
/// ```yaml
/// exports:
///   - targets: [ arm64-macos ]
///     symbols: [ _printf ]
///     weak-symbols: [ _weakfn ]      # v3 / v4 group key
/// ```
///
/// or the flat `undefineds` form:
///
/// ```yaml
/// undefineds:
///   - targets: [ arm64-macos ]
///     symbols: [ _dyld_get_program_sdk_version ]
/// ```
///
/// Returns one [`SymbolGroup`] per `- targets:` block; a bare `- _sym`
/// list (v3-style flat exports) becomes a single group.
fn block_groups(lines: &mut Lines<'_>, _intro: &str) -> Result<Vec<SymbolGroup>, FormatError> {
    let mut groups: Vec<SymbolGroup> = Vec::new();
    // The first group line establishes the block indent; sibling keys of a
    // group are indented deeper than its `-` marker, and any line at or left
    // of the group indent ends the block (peeked back for the main loop).
    let group_indent: Option<usize> = None;
    let _ = group_indent;
    let mut base_indent = usize::MAX;
    while let Some(line) = lines.next_line()? {
        let content = content_of(line);
        if content == "..." {
            lines.peeked = Some(line);
            break;
        }
        let ind = indent_of(line);
        let stripped = content.trim_start();
        if !stripped.starts_with('-') || (base_indent != usize::MAX && ind > base_indent) {
            // Either a stray top-level key (ends the block) or a deeper line
            // the group loop below already consumed — peek it back.
            lines.peeked = Some(line);
            break;
        }
        if base_indent == usize::MAX {
            base_indent = ind;
        }
        // `- key: value` or `- _symbol`.
        let rest = stripped[1..].trim_start();
        if let Some(sym) = rest.strip_prefix('_').filter(|s| !s.contains(':')) {
            if groups.is_empty() {
                groups.push(SymbolGroup::default());
            }
            groups[0]
                .symbols
                .push((format!("_{}", scalar_string(sym)?), false));
            continue;
        }
        let (key, value) = parse_key_value(rest)?;
        match key {
            "targets" => {
                // The group's target list: group-level filtering is M3
                // scope (M2 files are arm64-macos already gated at the top
                // level).
                let _ = flow_sequence(value)?;
                groups.push(SymbolGroup::default());
                let group_indent = ind;
                while let Some(line) = lines.next_line()? {
                    let content = content_of(line);
                    if indent_of(line) <= group_indent {
                        lines.peeked = Some(line);
                        break;
                    }
                    let (k, v) = parse_key_value(content)?;
                    match k {
                        "symbols" => {
                            if let Some(g) = groups.last_mut() {
                                for s in flow_sequence(v)? {
                                    g.symbols.push((s, false));
                                }
                            }
                        }
                        "weak-symbols" => {
                            if let Some(g) = groups.last_mut() {
                                for s in flow_sequence(v)? {
                                    g.symbols.push((s, true));
                                }
                            }
                        }
                        "objc-classes"
                        | "objc-ivars"
                        | "thread-local-symbols"
                        | "re-exports"
                        | "weak-re-exports"
                        | "symbols-unrestricted" => {
                            // Parsed for completeness, unused at M2.
                            let _ = flow_sequence(v)?;
                        }
                        other => {
                            return Err(FormatError::Malformed {
                                what: format!("unknown .tbd export-group key {other:?}"),
                            });
                        }
                    }
                }
            }
            other => {
                return Err(FormatError::Malformed {
                    what: format!("unknown .tbd group key {other:?}"),
                });
            }
        }
    }
    Ok(groups)
}

/// Sorts and deduplicates export symbols by name, keeping weak flags.
fn dedup_exports(mut exports: Vec<TbdSymbol>) -> Vec<TbdSymbol> {
    exports.sort_by(|a, b| a.name.cmp(&b.name));
    exports.dedup_by(|a, b| a.name == b.name);
    exports
}

#[cfg(test)]
mod tests {
    use super::{Tbd, TbdSymbol, parse_tbd};
    use crate::error::FormatError;

    fn v4(body: &str) -> Tbd {
        let doc = format!("--- !tapi-tbd\ntbd-version: 4\n{body}...\n");
        parse_tbd(doc.as_bytes()).expect("v4 document parses")
    }

    #[test]
    fn parses_v4_minimal() {
        let tbd = v4(
            "targets: [ arm64-macos ]\ninstall-name: /usr/lib/libSystem.B.dylib\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ _printf ]\n",
        );
        assert_eq!(tbd.tbd_version, 4);
        assert_eq!(tbd.install_name, "/usr/lib/libSystem.B.dylib");
        assert_eq!(
            tbd.exports,
            vec![TbdSymbol {
                name: "_printf".into(),
                weak: false
            }]
        );
        assert!(tbd.exports(b"_printf"));
        assert!(!tbd.exports(b"_puts"));
    }

    #[test]
    fn parses_v4_weak_symbols_group() {
        let tbd = v4(
            "targets: [ arm64-macos ]\ninstall-name: /usr/lib/libw.dylib\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ _a ]\n    weak-symbols: [ _b, _c ]\n",
        );
        assert_eq!(
            tbd.exports,
            vec![
                TbdSymbol {
                    name: "_a".into(),
                    weak: false
                },
                TbdSymbol {
                    name: "_b".into(),
                    weak: true
                },
                TbdSymbol {
                    name: "_c".into(),
                    weak: true
                },
            ]
        );
    }

    #[test]
    fn parses_v3_document() {
        let doc = "--- !tbd-tbd-version-3.0\ntbd-version: 3\ntargets: [ arm64-macos ]\nuuids: [ arm64-macos: 1234 ]\ninstall-name: /usr/lib/libold.dylib\ncurrent-version: 1.2.3\ncompatibility-version: 1.0.0\nobjc-constraint: none\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ _old, _elder ]\n    weak-symbols: [ _fuzzy ]\n...\n";
        let tbd = parse_tbd(doc.as_bytes()).expect("v3 document parses");
        assert_eq!(tbd.tbd_version, 3);
        assert_eq!(tbd.install_name, "/usr/lib/libold.dylib");
        assert_eq!(tbd.current_version, (1 << 16) | (2 << 8) | 3);
        assert_eq!(tbd.compatibility_version, 1 << 16);
        assert_eq!(tbd.exports.len(), 3);
    }

    #[test]
    fn parses_reexports_and_undefineds() {
        let tbd = v4(
            "targets: [ arm64-macos ]\ninstall-name: /usr/lib/libx.dylib\nre-exports:\n  - targets: [ arm64-macos ]\n    symbols: [ /usr/lib/liby.dylib ]\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ _x ]\nundefineds:\n  - targets: [ arm64-macos ]\n    symbols: [ _dyld_marker ]\n",
        );
        assert_eq!(tbd.re_exports, vec!["/usr/lib/liby.dylib"]);
        assert_eq!(tbd.undefineds, vec!["_dyld_marker"]);
    }

    #[test]
    fn filters_non_macos_targets_but_requires_one_macos() {
        // Two groups: the second targets arm64-ios only; the file still has
        // arm64-macos in `targets` and in group 1 — both groups parse.
        let tbd = v4(
            "targets: [ arm64-macos, arm64-ios ]\ninstall-name: /usr/lib/libm.dylib\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ _macos_only ]\n  - targets: [ arm64-ios ]\n    symbols: [ _ios_only ]\n",
        );
        assert!(tbd.exports(b"_macos_only"));
        // The ios-only symbol is still carried (target filtering inside
        // groups is M3 scope); the top-level gate is the `targets` list.
        assert!(tbd.exports(b"_ios_only"));
    }

    #[test]
    fn rejects_missing_macos_target() {
        let doc = "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-ios ]\ninstall-name: /ios/lib.dylib\nexports: []\n...\n";
        assert!(parse_tbd(doc.as_bytes()).is_err());
    }

    #[test]
    fn rejects_missing_install_name() {
        let doc = "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\nexports: []\n...\n";
        assert!(parse_tbd(doc.as_bytes()).is_err());
    }

    #[test]
    fn rejects_unknown_keys() {
        let doc = "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: /a.dylib\nmystery-key: 1\n...\n";
        assert!(parse_tbd(doc.as_bytes()).is_err());
    }

    #[test]
    fn rejects_unsupported_version() {
        let doc = "--- !tapi-tbd\ntbd-version: 2\ntargets: [ arm64-macos ]\ninstall-name: /a.dylib\n...\n";
        assert!(parse_tbd(doc.as_bytes()).is_err());
    }

    #[test]
    fn rejects_missing_document_marker() {
        let doc = "targets: [ arm64-macos ]\ninstall-name: /a.dylib\n";
        assert!(parse_tbd(doc.as_bytes()).is_err());
    }

    #[test]
    fn rejects_garbage_input_without_panicking() {
        for input in [
            &b""[..],
            b"---",
            b"--- !tapi-tbd",
            b"--- !tapi-tbd\ntbd-version: 4\nexports:\n  - [broken",
            b"--- !tapi-tbd\ntbd-version: 4\ninstall-name: ",
            b"\xff\xfe\x00garbage",
            b"--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: /a.dylib\nexports:\n  - targets: [ arm64-macos ]\n    unknown-key: 3\n...",
        ] {
            let _ = parse_tbd(input);
        }
    }

    #[test]
    fn parses_quoted_install_names_and_comments() {
        let doc = "# leading comment\n--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: \"/usr/lib/lib with spaces.dylib\" # trailing\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ _q ]\n...\n";
        let tbd = parse_tbd(doc.as_bytes()).expect("quoted document parses");
        assert_eq!(tbd.install_name, "/usr/lib/lib with spaces.dylib");
    }

    #[test]
    fn accepts_installapi_flag_and_dotted_versions() {
        let tbd = v4(
            "flags: [ installapi ]\ntargets: [ arm64-macos ]\ninstall-name: /v.dylib\ncurrent-version: 31.0.0\ncompatibility-version: 1.0.0\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ _v ]\n",
        );
        assert_eq!(tbd.current_version, (31 << 16));
    }

    #[test]
    fn format_error_is_displayed() {
        let err = parse_tbd(b"nonsense").unwrap_err();
        assert!(matches!(err, FormatError::Malformed { .. }));
        assert_ne!(err.to_string(), "");
    }
}
