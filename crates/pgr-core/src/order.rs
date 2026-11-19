//! The `-order_file` rank seam (M11 rung 1) and the `-sectorder`
//! composition face (M90).
//!
//! An order file names symbols (optionally scoped to one object file) and
//! the order they must appear in the output. ld64's parser also strips
//! per-architecture prefixes (`arm64:`/`x86_64:`/`i386:`/`arm:` kept only
//! when they match the target arch, `ppc:`/`ppc64:` dropped
//! unconditionally); Peregrine ships the **rank-based subset** TDD §12
//! named from the start: one symbol (or `object.o:symbol`) per line, `#`
//! comments, blank lines ignored — the arch prefixes stay the named
//! exclusion. The layout applies the ranks as a *stable sort* (§8.4:
//! "`-order_file` applies a stable sort by the order file's rank") —
//! ranked pieces land first in rank order, everything unranked keeps the
//! canonical input order behind them. Nothing reads a hash iteration
//! order: ranks come from the entry vector, lookups never enumerate the
//! tables.
//!
//! ld64's order sources feed ONE global rank table: `-order_file` and
//! `-sectorder <seg> <sect> <file>` both append their entries as the
//! flags parse (command-line order), and `-sectorder`'s (segment,
//! section) pair only names the face — an ordinary section's file rides
//! the same append ([`classify_section_order`]), `__TEXT,__cstring`
//! names the cstring-literal face, a `__TEXT,__literal*` section is the
//! warned no-op. [`SymbolOrder::compose`] is the seam that builds the
//! one table from the parsed sources.
//!
//! The parse is total (typed [`OrderFileError`], every failure names its
//! line) and the rank lookup is a pure function of `(object name, symbol
//! name)` — the driver builds the [`SymbolOrder`] from the parsed file
//! before Pass 3, and the layout consumes it read-only.

use std::collections::HashMap;

/// One order-file line: what it names and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderEntry {
    /// The symbol name exactly as written (ld64 matches Mach-O symbol
    /// names, leading underscore included).
    pub symbol: String,
    /// The object file the entry is scoped to (`foo.o:symbol`); `None`
    /// for a global entry. Matched against the input file's name.
    pub object: Option<String>,
    /// The 1-based line the entry came from (diagnostics).
    pub line: usize,
}

/// A parsed order file: the entries in file order (entry index = rank).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OrderFile {
    /// The entries in file order; the index is the rank.
    pub entries: Vec<OrderEntry>,
}

/// An order-file parse failure. Every variant names the line — the file
/// is small, the fix is local (the house error-context convention).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OrderFileError {
    /// The file carried no entries at all — an empty order file cannot
    /// rank anything and ld64 refuses it too.
    #[error("order file is empty (name at least one symbol per line)")]
    Empty,
    /// A line carried no symbol name (`foo.o:` with an empty tail).
    #[error("order file line {line}: empty symbol name (write `{hint}`)")]
    EmptySymbol {
        /// The 1-based line.
        line: usize,
        /// The corrected shape for the line's prefix.
        hint: String,
    },
    /// A line carried more than one colon (the `object:symbol` split is
    /// single-colon; anything else is not the rank-based subset).
    #[error(
        "order file line {line}: too many colons in {text:?} — the supported form is `symbol` or `object.o:symbol`"
    )]
    TooManyColons {
        /// The 1-based line.
        line: usize,
        /// The offending line text.
        text: String,
    },
    /// A duplicate symbol (same name, same scope): two ranks for one
    /// symbol is a contradiction — refuse instead of picking one.
    #[error(
        "order file line {line}: {symbol} is already ranked (line {first}); one rank per symbol"
    )]
    Duplicate {
        /// The 1-based line of the duplicate.
        line: usize,
        /// The duplicated symbol.
        symbol: String,
        /// The 1-based line of the first rank.
        first: usize,
    },
    /// A scoped entry whose object part is empty (`:symbol`).
    #[error(
        "order file line {line}: empty object name before `:` (write `symbol` for a global rank)"
    )]
    EmptyObject {
        /// The 1-based line.
        line: usize,
    },
}

impl OrderFile {
    /// Parses the order-file text (one symbol per line, `object.o:symbol`
    /// scoping, `#` comments, blank lines ignored).
    ///
    /// # Errors
    /// [`OrderFileError`] naming the offending line.
    pub fn parse(text: &str) -> Result<Self, OrderFileError> {
        let mut entries = Vec::new();
        let mut seen: HashMap<(Option<&str>, &str), usize> = HashMap::new();
        for (idx, raw) in text.lines().enumerate() {
            let line_no = idx + 1;
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (object, symbol) = match line.split_once(':') {
                Some((obj, sym)) => {
                    if sym.contains(':') {
                        return Err(OrderFileError::TooManyColons {
                            line: line_no,
                            text: line.to_string(),
                        });
                    }
                    if obj.is_empty() {
                        return Err(OrderFileError::EmptyObject { line: line_no });
                    }
                    (Some(obj.trim()), sym.trim())
                }
                None => (None, line),
            };
            if symbol.is_empty() {
                return Err(OrderFileError::EmptySymbol {
                    line: line_no,
                    hint: format!(
                        "{}:_symbol",
                        object.map_or_else(String::new, std::string::ToString::to_string)
                    ),
                });
            }
            let key = (object, symbol);
            if let Some(&first) = seen.get(&key) {
                return Err(OrderFileError::Duplicate {
                    line: line_no,
                    symbol: symbol.to_string(),
                    first,
                });
            }
            seen.insert(key, line_no);
            entries.push(OrderEntry {
                symbol: symbol.to_string(),
                object: object.map(str::to_string),
                line: line_no,
            });
        }
        if entries.is_empty() {
            return Err(OrderFileError::Empty);
        }
        Ok(Self { entries })
    }
}

/// The Pass-3 rank table built from a parsed [`OrderFile`]: lookups are
/// keyed by raw name bytes (the interner is not needed to build it, so
/// the driver can rank before Pass 1 interns).
///
/// Lookup precedence: an object-scoped entry for the object at hand wins
/// over a global entry for the same name; a name with no entry is
/// unranked. The rank value is the *entry index* — the file order is the
/// rank order, so a lower index sorts first.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SymbolOrder {
    /// Global (`symbol`) entries: name → entry index.
    global: HashMap<Vec<u8>, usize>,
    /// Scoped (`object.o:symbol`) entries: (object name, symbol) → entry index.
    scoped: HashMap<(String, Vec<u8>), usize>,
    /// The entries (for the unmatched-symbol report, in file order).
    entries: Vec<OrderEntry>,
}

impl SymbolOrder {
    /// Builds the rank table from a parsed order file. Later duplicate
    /// names cannot occur ([`OrderFile::parse`] refuses them).
    #[must_use]
    pub fn build(file: &OrderFile) -> Self {
        let mut global = HashMap::new();
        let mut scoped = HashMap::new();
        for (idx, entry) in file.entries.iter().enumerate() {
            match &entry.object {
                Some(obj) => {
                    scoped.insert((obj.clone(), entry.symbol.clone().into_bytes()), idx);
                }
                None => {
                    global.insert(entry.symbol.clone().into_bytes(), idx);
                }
            }
        }
        Self {
            global,
            scoped,
            entries: file.entries.clone(),
        }
    }

    /// Rebuilds the rank table from the entries themselves (M81): the
    /// wire's canonical form — the entries in rank order, each with its
    /// scope and its diagnostics line — is all the state the table
    /// carries, so a resident session restores exactly what the client
    /// built from its parsed file. The same shapes the parse refuses
    /// refuse here (an empty table cannot rank anything; two ranks for
    /// one symbol is a contradiction), so a table the wire carries is
    /// always a legal one.
    ///
    /// # Errors
    /// [`OrderFileError::Empty`] on an empty table (the codec encodes
    /// the absence instead),
    /// [`OrderFileError::Duplicate`] on two ranks for one symbol (the
    /// same `(object, symbol)` key twice — the lines named, the report
    /// reads like the cold lane's).
    pub fn from_entries(entries: Vec<OrderEntry>) -> Result<Self, OrderFileError> {
        if entries.is_empty() {
            return Err(OrderFileError::Empty);
        }
        // The duplicate walk (the table is small, the wire refuses
        // before any link runs): the same `(object, symbol)` key twice
        // is two ranks for one symbol — the parse's own refusal, the
        // lines carried so the report reads like the cold lane's. The
        // same name global AND scoped is the parse's own shape (the
        // scoped entry wins for its object), never a collision.
        let mut seen: HashMap<(Option<&str>, &[u8]), usize> = HashMap::new();
        for (idx, entry) in entries.iter().enumerate() {
            let key = (entry.object.as_deref(), entry.symbol.as_bytes());
            if let Some(&first) = seen.get(&key) {
                return Err(OrderFileError::Duplicate {
                    line: entry.line,
                    symbol: entry.symbol.clone(),
                    first: first.saturating_add(1),
                });
            }
            seen.insert(key, idx);
        }
        Ok(Self {
            global: entries
                .iter()
                .enumerate()
                .filter(|(_, e)| e.object.is_none())
                .map(|(idx, e)| (e.symbol.clone().into_bytes(), idx))
                .collect(),
            scoped: entries
                .iter()
                .enumerate()
                .filter_map(|(idx, e)| {
                    e.object
                        .as_ref()
                        .map(|obj| ((obj.clone(), e.symbol.clone().into_bytes()), idx))
                })
                .collect(),
            entries,
        })
    }

    /// The entry index (rank) for `name` in the object named `object` —
    /// `None` when the name is unranked. Scoped entries win over global
    /// ones for their object.
    #[must_use]
    pub fn rank_of(&self, object: &str, name: &[u8]) -> Option<usize> {
        if let Some(&idx) = self.scoped.get(&(object.to_string(), name.to_vec())) {
            return Some(idx);
        }
        self.global.get(name).copied()
    }

    /// The parsed entries in file order (the rank order).
    #[must_use]
    pub fn entries(&self) -> &[OrderEntry] {
        &self.entries
    }

    /// Composes the sources into one rank table (M90): the entries ride
    /// in source order, each source's entries in file order — ld64's own
    /// semantics (`-order_file` and `-sectorder` append into one global
    /// table as the flags parse, command-line order). Scoped entries
    /// keep their object scope and the lookup precedence is unchanged
    /// (a scoped entry wins for its object); the merged entries carry
    /// their own files' diagnostic lines. A name two sources rank
    /// refuses with both sources and both lines named — the file
    /// parse's own per-file refusal, taken across the sources.
    ///
    /// # Errors
    /// [`OrderComposeError::Empty`] when no source carries an entry,
    /// [`OrderComposeError::Duplicate`] when two sources rank one name.
    pub fn compose(sources: &[OrderSource<'_>]) -> Result<Self, OrderComposeError> {
        let mut global: HashMap<Vec<u8>, usize> = HashMap::new();
        let mut scoped: HashMap<(String, Vec<u8>), usize> = HashMap::new();
        let mut merged: Vec<OrderEntry> = Vec::new();
        // The cross-source duplicate walk: `(symbol, object scope)` is
        // the rank key (the same shape the file parse keys); the value
        // names the first source and line, so the refusal reads like the
        // file parse's own (the house error-context convention).
        let mut seen: HashMap<(&str, Option<&str>), (&str, usize)> = HashMap::new();
        for source in sources {
            for entry in &source.file.entries {
                let key = (entry.symbol.as_str(), entry.object.as_deref());
                if let Some(&(first_source, first_line)) = seen.get(&key) {
                    return Err(OrderComposeError::Duplicate {
                        symbol: entry.symbol.clone(),
                        first_source: first_source.to_string(),
                        first_line,
                        second_source: source.name.to_string(),
                        second_line: entry.line,
                    });
                }
                seen.insert(key, (source.name, entry.line));
                let rank = merged.len();
                match &entry.object {
                    Some(obj) => {
                        scoped.insert((obj.clone(), entry.symbol.clone().into_bytes()), rank);
                    }
                    None => {
                        global.insert(entry.symbol.clone().into_bytes(), rank);
                    }
                }
                merged.push(entry.clone());
            }
        }
        if merged.is_empty() {
            return Err(OrderComposeError::Empty);
        }
        Ok(Self {
            global,
            scoped,
            entries: merged,
        })
    }
}

/// One composed source (M90): the parsed file beside the name the
/// duplicate refusal names — an [`OrderSource`] is one order-bearing
/// flag instance in command-line order (an `-order_file` path, or a
/// `-sectorder` pair whose classification named the rank-append face).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrderSource<'a> {
    /// The source's name (the `-order_file` path as written, or the
    /// `-sectorder <seg> <sect>` pseudo-source) — the refusal names it,
    /// the fix is local.
    pub name: &'a str,
    /// The parsed file; its entries ride in file order.
    pub file: &'a OrderFile,
}

/// A rank-table composition failure (M90): the sources' entries append
/// into one table, and a name two sources rank is a contradiction — the
/// file parse refuses it per file, the composition refuses it across
/// them, both sources named.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OrderComposeError {
    /// No source carried an entry (an empty source list, or every
    /// source hand-built empty — the file parse refuses an empty file,
    /// so only constructed sources reach this).
    #[error(
        "no order source carries an entry (name at least one symbol per line, in one file per source)"
    )]
    Empty,
    /// Two sources rank one name — the contradiction, both sources and
    /// both lines named.
    #[error(
        "{first_source} line {first_line} and {second_source} line {second_line} both rank {symbol}; one rank per symbol across the order sources"
    )]
    Duplicate {
        /// The doubled symbol name.
        symbol: String,
        /// The first source's name.
        first_source: String,
        /// The 1-based line in the first source.
        first_line: usize,
        /// The second source's name.
        second_source: String,
        /// The 1-based line in the second source.
        second_line: usize,
    },
}

/// Which face ld64's `-sectorder` serves for a (segment, section) pair
/// (M90): the mirror of ld64's `parseSectionOrderFile` walk. The rank
/// append ignores the section information entirely ("append all symbol
/// names to global order file") — the pair names the face, never a
/// layout scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionOrderClass {
    /// The global rank-append face: the file parses with the same
    /// grammar as `-order_file` and its entries join the one rank table
    /// in command-line order.
    RankAppend,
    /// The cstring-literal face (`__TEXT,__cstring` exactly): ld64
    /// orders the section's literals by the file's escape-decoded lines.
    CstringLiteral,
    /// The literal no-op face (every `__TEXT,__literal*` section): ld64
    /// warns ("sorting of __literal[4,8,16] sections not supported") and
    /// ranks nothing — the file is never read.
    LiteralNotSupported,
}

/// Classifies a `-sectorder` (segment, section) pair (M90) — the
/// `parseSectionOrderFile` walk, named so a build system composes order
/// sources the way the driver does.
///
/// The rank append is the face for every pair that is neither the
/// `__TEXT,__cstring` cstring face nor a `__TEXT,__literal*` no-op —
/// `__DATA,__cstring` is an ordinary section (ld64's own strcmp pair
/// gates the cstring face on `__TEXT`).
#[must_use]
pub fn classify_section_order(segment: &str, section: &str) -> SectionOrderClass {
    if segment != "__TEXT" {
        return SectionOrderClass::RankAppend;
    }
    if section == "__cstring" {
        SectionOrderClass::CstringLiteral
    } else if section.starts_with("__literal") {
        SectionOrderClass::LiteralNotSupported
    } else {
        SectionOrderClass::RankAppend
    }
}

/// The `-sectorder __TEXT __cstring` rank table (M91): the file's lines
/// are literal *contents* — ld64's cstring mode (`parseOrderFile` with
/// `cstring = true`), escape-decoded and ranked. The line rules are the
/// mode's own: leading whitespace rides (a line that starts with spaces
/// is a literal, never a comment), trailing whitespace trims, `#`
/// comments only at column 0 (a mid-line `#` is literal in this mode),
/// and a blank line skips (ld64's parser pushes an empty entry there —
/// the empty literal ranks nothing, so the skip is the honest reading
/// and the compat row names it). The escape set follows ld64's
/// `cstringSymbolName`: the named controls, `\\`, `\?`, `\"`, `\x` hex
/// and octal runs (both truncated to the byte the format carries), and
/// an unknown escape riding verbatim; `\'` decodes as the quote —
/// ld64's own table maps it to `\r`, an evident upstream typo the
/// compat row names.
///
/// The decoded bytes are the rank key: the D4 canonical instances sort
/// by content rank (a stable pass — the unranked literals keep their
/// first-use order behind them), and a rank matches a literal's content
/// with the NUL terminator exclusive (an entry never carries it; the
/// layout looks the atom's bytes up through [`CstringOrder::rank_of`],
/// which strips one trailing NUL defensively).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CstringOrder {
    /// The decoded literal contents in rank order (the entry index is
    /// the rank).
    entries: Vec<Vec<u8>>,
}

/// A cstring rank-table rebuild refusal (M91): the wire's canonical
/// form — the decoded literal contents in rank order — cannot carry two
/// ranks for one literal (the file parse refuses the same shape with
/// the lines named; the rebuilt table names the rank positions).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("cstring rank entries {second} and {first} carry the same literal; one rank per literal")]
pub struct CstringRankDuplicate {
    /// The 1-based rank position of the first entry.
    pub first: usize,
    /// The 1-based rank position of the duplicate.
    pub second: usize,
}

impl CstringOrder {
    /// Parses the cstring-mode order text: one escape-decoded literal
    /// content per line (the line rules in the type doc).
    ///
    /// # Errors
    /// [`OrderFileError::Empty`] on a file that carries no entry,
    /// [`OrderFileError::Duplicate`] on two ranks for one literal (the
    /// lines named — the file is small, the fix is local).
    pub fn parse(text: &str) -> Result<Self, OrderFileError> {
        let mut entries: Vec<Vec<u8>> = Vec::new();
        let mut seen: HashMap<Vec<u8>, usize> = HashMap::new();
        for (idx, raw) in text.split('\n').enumerate() {
            let line_no = idx + 1;
            // The cstring mode's column-0 comment rule (a `#` after
            // whitespace is a literal — the mode's own shape).
            if raw.starts_with('#') {
                continue;
            }
            // Trailing whitespace trims; leading rides.
            let line = raw.trim_end();
            if line.is_empty() {
                continue;
            }
            let decoded = decode_cstring_line(line.as_bytes());
            if let Some(&first) = seen.get(&decoded) {
                return Err(OrderFileError::Duplicate {
                    line: line_no,
                    symbol: String::from_utf8_lossy(&decoded).into_owned(),
                    first,
                });
            }
            seen.insert(decoded.clone(), line_no);
            entries.push(decoded);
        }
        if entries.is_empty() {
            return Err(OrderFileError::Empty);
        }
        Ok(Self { entries })
    }

    /// Rebuilds the rank table from the decoded entries themselves
    /// (M91): the wire's canonical form — the contents in rank order —
    /// is all the state the table carries, so a resident session
    /// restores exactly what the client built from its parsed file.
    ///
    /// # Errors
    /// [`CstringRankDuplicate`] on two ranks for one literal (the rank
    /// positions named — the file parse's own refusal, the wire's
    /// shape).
    pub fn from_entries(entries: Vec<Vec<u8>>) -> Result<Self, CstringRankDuplicate> {
        let mut seen: HashMap<&[u8], usize> = HashMap::with_capacity(entries.len());
        for (idx, entry) in entries.iter().enumerate() {
            if let Some(&first) = seen.get(entry.as_slice()) {
                return Err(CstringRankDuplicate {
                    first: first + 1,
                    second: idx + 1,
                });
            }
            seen.insert(entry.as_slice(), idx);
        }
        Ok(Self { entries })
    }

    /// The rank for a literal's content bytes — `None` when the content
    /// is unranked. One trailing NUL strips before the lookup (the
    /// atoms carry their terminator; the entries never do).
    #[must_use]
    pub fn rank_of(&self, content: &[u8]) -> Option<usize> {
        let key: &[u8] = if content.last() == Some(&0) {
            &content[..content.len() - 1]
        } else {
            content
        };
        self.entries.iter().position(|e| e == key)
    }

    /// The decoded entries in rank order.
    #[must_use]
    pub fn entries(&self) -> &[Vec<u8>] {
        &self.entries
    }
}

/// Decodes one cstring-mode line (the `cstringSymbolName` escape set,
/// byte-level: multi-byte UTF-8 rides because no escape byte is
/// non-ASCII).
fn decode_cstring_line(line: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(line.len());
    let mut i = 0usize;
    while i < line.len() {
        let b = line[i];
        if b != b'\\' {
            out.push(b);
            i += 1;
            continue;
        }
        i += 1;
        let Some(&esc) = line.get(i) else {
            // A trailing backslash rides verbatim.
            out.push(b'\\');
            break;
        };
        i += 1;
        match esc {
            b'n' => out.push(b'\n'),
            b't' => out.push(b'\t'),
            b'v' => out.push(0x0B),
            b'b' => out.push(0x08),
            b'r' => out.push(b'\r'),
            b'f' => out.push(0x0C),
            b'a' => out.push(0x07),
            b'\\' => out.push(b'\\'),
            b'?' => out.push(b'?'),
            b'\'' => out.push(b'\''),
            b'"' => out.push(b'"'),
            b'x' => {
                // The hex run: every consecutive hex digit, truncated
                // to the byte the format carries.
                let mut value: u32 = 0;
                let mut digits = 0usize;
                while let Some(&d) = line.get(i) {
                    let digit = match d {
                        b'0'..=b'9' => u32::from(d - b'0'),
                        b'a'..=b'f' => u32::from(d - b'a') + 10,
                        b'A'..=b'F' => u32::from(d - b'A') + 10,
                        _ => break,
                    };
                    value = value.wrapping_mul(16).wrapping_add(digit);
                    digits += 1;
                    i += 1;
                }
                if digits > 0 {
                    out.push(value as u8);
                } else {
                    // `\x` with no digits rides verbatim (the escape
                    // marker and the x).
                    out.push(b'\\');
                    out.push(b'x');
                }
            }
            b'0'..=b'9' => {
                // The octal run (leading digit already consumed).
                let mut value = u32::from(esc - b'0');
                while let Some(&d) = line.get(i) {
                    if !d.is_ascii_digit() {
                        break;
                    }
                    value = value.wrapping_mul(8).wrapping_add(u32::from(d - b'0'));
                    i += 1;
                }
                out.push(value as u8);
            }
            _ => {
                // The unknown escape rides verbatim — the backslash and
                // the char (the house reading of ld64's in-place
                // rewrite; the compat row names it).
                out.push(b'\\');
                out.push(esc);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_reads_entries_in_order() {
        let f = OrderFile::parse("# startup order\n_main\n_helper\n\nlib.o:_local\n").unwrap();
        assert_eq!(f.entries.len(), 3);
        assert_eq!(f.entries[0].symbol, "_main");
        assert_eq!(f.entries[0].line, 2);
        assert_eq!(f.entries[1].symbol, "_helper");
        assert_eq!(f.entries[2].symbol, "_local");
        assert_eq!(f.entries[2].object.as_deref(), Some("lib.o"));
    }

    #[test]
    fn parse_refuses_the_named_shapes() {
        assert_eq!(OrderFile::parse(""), Err(OrderFileError::Empty));
        assert_eq!(
            OrderFile::parse("# only a comment\n"),
            Err(OrderFileError::Empty)
        );
        assert_eq!(
            OrderFile::parse("lib.o:\n"),
            Err(OrderFileError::EmptySymbol {
                line: 1,
                hint: "lib.o:_symbol".into()
            })
        );
        assert!(matches!(
            OrderFile::parse("a:b:c\n"),
            Err(OrderFileError::TooManyColons { line: 1, .. })
        ));
        assert!(matches!(
            OrderFile::parse(":_sym\n"),
            Err(OrderFileError::EmptyObject { line: 1 })
        ));
        let dup = OrderFile::parse("_main\n_main\n").unwrap_err();
        assert_eq!(
            dup,
            OrderFileError::Duplicate {
                line: 2,
                symbol: "_main".into(),
                first: 1
            }
        );
    }

    #[test]
    fn ranks_prefer_the_scoped_entry() {
        let f = OrderFile::parse("_shared\nfirst.o:_shared\nfirst.o:_own\n").unwrap();
        let order = SymbolOrder::build(&f);
        assert_eq!(order.rank_of("first.o", b"_shared"), Some(1));
        assert_eq!(order.rank_of("second.o", b"_shared"), Some(0));
        assert_eq!(order.rank_of("first.o", b"_own"), Some(2));
        assert_eq!(order.rank_of("second.o", b"_own"), None);
        assert_eq!(order.rank_of("first.o", b"_unranked"), None);
    }

    #[test]
    fn entries_carry_the_file_order() {
        let f = OrderFile::parse("_b\n_a\n").unwrap();
        let order = SymbolOrder::build(&f);
        let names: Vec<&str> = order.entries().iter().map(|e| e.symbol.as_str()).collect();
        assert_eq!(names, ["_b", "_a"]);
    }

    // ---- M90: the -sectorder composition --------------------------------

    #[test]
    fn classification_names_the_faces() {
        assert_eq!(
            classify_section_order("__DATA", "__text"),
            SectionOrderClass::RankAppend
        );
        assert_eq!(
            classify_section_order("__TEXT", "__text"),
            SectionOrderClass::RankAppend
        );
        assert_eq!(
            classify_section_order("__TEXT", "__cstring"),
            SectionOrderClass::CstringLiteral
        );
        assert_eq!(
            classify_section_order("__DATA", "__cstring"),
            SectionOrderClass::RankAppend,
            "the cstring face is the __TEXT pair only"
        );
        assert_eq!(
            classify_section_order("__TEXT", "__literal8"),
            SectionOrderClass::LiteralNotSupported
        );
    }

    #[test]
    fn compose_appends_in_source_order_and_refuses_duplicates() {
        let a = OrderFile::parse("_first\n_a_only\n").unwrap();
        let b = OrderFile::parse("b.o:_second\n").unwrap();
        let sources = [
            OrderSource {
                name: "a.txt",
                file: &a,
            },
            OrderSource {
                name: "sectorder __TEXT __text",
                file: &b,
            },
        ];
        let table = SymbolOrder::compose(&sources).expect("the sources compose");
        let names: Vec<&str> = table.entries().iter().map(|e| e.symbol.as_str()).collect();
        assert_eq!(names, ["_first", "_a_only", "_second"]);
        assert_eq!(table.rank_of("b.o", b"_second"), Some(2));
        assert_eq!(table.rank_of("c.o", b"_second"), None);

        // A name two sources rank is the contradiction — both sources
        // and both lines named.
        let b = OrderFile::parse("_first\n").unwrap();
        let err = SymbolOrder::compose(&[
            OrderSource {
                name: "a.txt",
                file: &a,
            },
            OrderSource {
                name: "sectorder __TEXT __text",
                file: &b,
            },
        ])
        .unwrap_err();
        assert_eq!(
            err,
            OrderComposeError::Duplicate {
                symbol: "_first".into(),
                first_source: "a.txt".into(),
                first_line: 1,
                second_source: "sectorder __TEXT __text".into(),
                second_line: 1,
            }
        );
        assert_eq!(SymbolOrder::compose(&[]), Err(OrderComposeError::Empty));
    }

    // ---- M81: the rank table crosses the wire (from_entries) ------------

    #[test]
    fn from_entries_restores_the_ranks() {
        // The wire's table is the entries in rank order — the rebuilt
        // lookup answers exactly what the parsed file's table answers
        // (the codec's round-trip contract; the `rank_of` faces agree).
        let f = OrderFile::parse("_shared\nfirst.o:_shared\nfirst.o:_own\n").unwrap();
        let built = SymbolOrder::build(&f);
        let restored =
            SymbolOrder::from_entries(built.entries().to_vec()).expect("the table rebuilds");
        assert_eq!(built, restored, "the entries rebuild the same table");
        assert_eq!(restored.rank_of("first.o", b"_shared"), Some(1));
        assert_eq!(restored.rank_of("second.o", b"_shared"), Some(0));
        assert_eq!(restored.rank_of("first.o", b"_own"), Some(2));
        assert_eq!(restored.rank_of("second.o", b"_own"), None);
    }

    #[test]
    fn from_entries_refuses_the_named_shapes() {
        // An empty table cannot rank anything (the parse's own refusal,
        // mirrored at the wire — the codec encodes `None` instead).
        assert_eq!(
            SymbolOrder::from_entries(Vec::new()),
            Err(OrderFileError::Empty)
        );
        // Two ranks for one symbol is a contradiction — the same
        // refusal the file parse carries, the lines named (the wire
        // carries them, so the report reads like the cold lane's).
        let dup = SymbolOrder::from_entries(vec![
            OrderEntry {
                symbol: "_main".into(),
                object: None,
                line: 1,
            },
            OrderEntry {
                symbol: "_main".into(),
                object: None,
                line: 2,
            },
        ])
        .unwrap_err();
        assert_eq!(
            dup,
            OrderFileError::Duplicate {
                line: 2,
                symbol: "_main".into(),
                first: 1
            }
        );
        // The same name global AND scoped for one object is the parse's
        // own shape (the scoped entry wins for its object) — a rebuilt
        // table keeps it, the lookup faces agree with [`SymbolOrder::build`].
        let mixed = SymbolOrder::from_entries(vec![
            OrderEntry {
                symbol: "_shared".into(),
                object: None,
                line: 1,
            },
            OrderEntry {
                symbol: "_shared".into(),
                object: Some("a.o".into()),
                line: 2,
            },
        ])
        .expect("the parse's own shape rebuilds");
        assert_eq!(mixed.rank_of("a.o", b"_shared"), Some(1));
        assert_eq!(mixed.rank_of("b.o", b"_shared"), Some(0));
        // A scoped duplicate (same object, same symbol, twice) is the
        // contradiction the file parse refuses — mirrored at the wire.
        let dup = SymbolOrder::from_entries(vec![
            OrderEntry {
                symbol: "_own".into(),
                object: Some("a.o".into()),
                line: 1,
            },
            OrderEntry {
                symbol: "_own".into(),
                object: Some("a.o".into()),
                line: 2,
            },
        ])
        .unwrap_err();
        assert!(
            matches!(dup, OrderFileError::Duplicate { line: 2, .. }),
            "{dup:?}"
        );
    }
}
