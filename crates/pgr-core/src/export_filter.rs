//! The export-filter seam (M14): the `-exported_symbols_list` /
//! `-unexported_symbols_list` entries as *named patterns* instead of
//! exact-name byte strings.
//!
//! ld64's symbol-list files accept `*` wildcards; through M3 Peregrine
//! carried the exact-name subset (docs/COMPAT.md: "globs are a later
//! milestone"). This module names the widened subset: a
//! [`SymbolPattern`] is an exact name or a `*` glob — each `*` matches
//! any, possibly empty, run of bytes, every other byte matches
//! literally, and consecutive stars carry no extra meaning (`**` is
//! `*`). Anything else (`?`, brackets) is a literal byte: the subset is
//! deliberately the one ld64 file syntax every consumer already writes,
//! and the refusal surface stays with the parser, not the matcher.
//!
//! The layout's export-visibility closure reads the contract through
//! [`is_export_visible`]: the M3 semantics — the only-list gates the
//! export surface, the unexported list removes a name and marks it
//! `N_PEXT` — are unchanged; only the matching widened. An all-exact
//! filter selects exactly what the M3 byte-string lists selected, so
//! every M3 gate holds bit-for-bit (`tests/m14_export_filter.rs` pins
//! the plan-level identity).
//!
//! The matching is a pure function of `(patterns, name)` — nothing
//! reads hash iteration order (the §4.3 determinism policy) — and the
//! [`tracing`] event naming the filter's contract rides the layout's
//! install site, inert until a subscriber installs (the house
//! convention).

/// One entry of a `-exported_symbols_list` / `-unexported_symbols_list`
/// file (M14): an exact symbol name or a `*` wildcard glob.
///
/// The source bytes are kept verbatim so the wire (protocol v7)
/// round-trips the line the consumer wrote — `**` stays `**`, and an
/// error can quote the file's own text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolPattern {
    /// The M3 form: byte-for-byte equality with the symbol name.
    Exact(Vec<u8>),
    /// The M14 form: each `*` matches any (possibly empty) byte run,
    /// every other byte is literal. The bytes are the file's own line
    /// (stars included).
    Glob(Vec<u8>),
}

/// A pattern parse refusal: the fix is in the message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SymbolPatternError {
    /// An empty pattern matches nothing — a blank line the reader
    /// should have skipped, or a list reduced to comments.
    #[error("an empty pattern matches nothing; name a symbol or write a * wildcard")]
    Empty,
    /// Interior whitespace cannot appear in a Mach-O symbol name, so a
    /// whitespace-carrying line is a typo, not a very long symbol.
    #[error("pattern `{}` carries whitespace; Mach-O symbol names cannot contain spaces or tabs",
        String::from_utf8_lossy(.0))]
    Whitespace(Vec<u8>),
}

impl SymbolPattern {
    /// Parses one list-file line (already trimmed and comment-stripped
    /// by the reader): a line carrying at least one `*` is a glob,
    /// every other line is an exact name.
    ///
    /// # Errors
    /// [`SymbolPatternError::Empty`] on an empty line (the fix is the
    /// reader's: skip it) and [`SymbolPatternError::Whitespace`] on a
    /// line with interior spaces or tabs — Mach-O symbol names cannot
    /// carry either, so the line is a typo the consumer wants named.
    pub fn parse(line: &[u8]) -> Result<Self, SymbolPatternError> {
        if line.is_empty() {
            return Err(SymbolPatternError::Empty);
        }
        if line
            .iter()
            .any(|&b| b == b' ' || b == b'\t' || b == b'\r' || b == b'\n')
        {
            return Err(SymbolPatternError::Whitespace(line.to_vec()));
        }
        if line.contains(&b'*') {
            Ok(Self::Glob(line.to_vec()))
        } else {
            Ok(Self::Exact(line.to_vec()))
        }
    }

    /// Builds the M3 exact form.
    #[must_use]
    pub fn exact(name: &[u8]) -> Self {
        Self::Exact(name.to_vec())
    }

    /// The line as written (the wire round-trips these bytes).
    #[must_use]
    pub fn source(&self) -> &[u8] {
        match self {
            Self::Exact(bytes) | Self::Glob(bytes) => bytes,
        }
    }

    /// The classic iterative glob walk with single-star backtracking:
    /// each `*` greedily extends one byte at a time and rewinds to the
    /// last star on a mismatch — `O(pattern × name)` worst case,
    /// allocation-free, and a pure function of its inputs (§4.3).
    fn glob_walk(pattern: &[u8], name: &[u8]) -> bool {
        let (mut p, mut n) = (0usize, 0usize);
        let (mut star_p, mut star_n) = (usize::MAX, 0usize);
        while n < name.len() {
            if p < pattern.len() && pattern[p] == b'*' {
                star_p = p;
                star_n = n;
                p += 1;
            } else if p < pattern.len() && pattern[p] == name[n] {
                p += 1;
                n += 1;
            } else if star_p != usize::MAX {
                star_n += 1;
                n = star_n;
                p = star_p + 1;
            } else {
                return false;
            }
        }
        while p < pattern.len() && pattern[p] == b'*' {
            p += 1;
        }
        p == pattern.len()
    }
}

/// The seam the export-visibility closure reads: a single pattern (or a
/// whole list) answers "does this matcher select `name`?".
pub trait SymbolMatcher {
    /// Does this matcher select `name`?
    fn matches(&self, name: &[u8]) -> bool;
}

impl SymbolMatcher for SymbolPattern {
    fn matches(&self, name: &[u8]) -> bool {
        match self {
            Self::Exact(bytes) => bytes.as_slice() == name,
            Self::Glob(pattern) => Self::glob_walk(pattern, name),
        }
    }
}

impl<M: SymbolMatcher> SymbolMatcher for [M] {
    fn matches(&self, name: &[u8]) -> bool {
        self.iter().any(|m| m.matches(name))
    }
}

/// The M3 visibility contract over the widened matching: the
/// only-list, when present, gates (a name outside it never exports);
/// the unexported list removes (a name inside it never exports — the
/// symtab keeps it as an `N_PEXT` private, the trie drops it). With
/// neither list every name is visible.
#[must_use]
pub fn is_export_visible(
    exported_only: Option<&[SymbolPattern]>,
    unexported: &[SymbolPattern],
    name: &[u8],
) -> bool {
    if let Some(only) = exported_only {
        if !only.matches(name) {
            return false;
        }
    }
    !unexported.matches(name)
}

#[cfg(test)]
mod tests {
    use super::{SymbolMatcher, SymbolPattern, is_export_visible};

    #[test]
    fn exact_and_glob_forms_round_trip_their_source() {
        let exact = SymbolPattern::parse(b"_foo_add").unwrap();
        assert_eq!(exact.source(), b"_foo_add");
        let glob = SymbolPattern::parse(b"_foo_*").unwrap();
        assert_eq!(glob.source(), b"_foo_*");
        assert_eq!(
            SymbolPattern::parse(b"").unwrap_err().to_string(),
            "an empty pattern matches nothing; name a symbol or write a * wildcard"
        );
    }

    #[test]
    fn consecutive_stars_and_trailing_stars_match_like_one() {
        let p = SymbolPattern::parse(b"_a**b*").unwrap();
        assert!(p.matches(b"_ab"));
        assert!(p.matches(b"_axby"));
        assert!(p.matches(b"_abx"), "the trailing star absorbs the tail");
        assert!(!p.matches(b"_b"));
        // Without the trailing star, a longer tail cannot match.
        let hard = SymbolPattern::parse(b"_a**b").unwrap();
        assert!(hard.matches(b"_axb"));
        assert!(!hard.matches(b"_abx"));
    }

    #[test]
    fn the_walk_is_backtracking_not_greedy_locked() {
        // `_a*b` must match `_ab_b`: the first star extends over `b_`
        // after the literal `b` fails — the classic backtracking case a
        // greedy-only walk would refuse.
        let p = SymbolPattern::parse(b"_a*b").unwrap();
        assert!(p.matches(b"_ab_b"));
        assert!(p.matches(b"_ab"));
        assert!(!p.matches(b"_ba"));
    }

    #[test]
    fn visibility_contract_is_the_m3_one() {
        let only = [SymbolPattern::exact(b"_a")];
        let hidden = [SymbolPattern::parse(b"_h*").unwrap()];
        assert!(is_export_visible(None, &[], b"_x"));
        assert!(!is_export_visible(Some(&only), &[], b"_b"));
        assert!(is_export_visible(Some(&only), &[], b"_a"));
        // A name the only-list selects and the hidden list does not:
        // visible — the two lists compose exactly as the M3 closure did.
        assert!(is_export_visible(Some(&only), &hidden, b"_a"));
        assert!(!is_export_visible(Some(&only), &hidden, b"_hidden"));
    }
}
