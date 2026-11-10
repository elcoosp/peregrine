//! The `-order_file` rank seam (M11 rung 1).
//!
//! An order file names symbols (optionally scoped to one object file) and
//! the order they must appear in the output. ld64's full semantics include
//! wildcards and section directives; Peregrine ships the **rank-based
//! subset** TDD §12 named from the start: one symbol (or
//! `object.o:symbol`) per line, `#` comments, blank lines ignored. The
//! layout applies the ranks as a *stable sort* (§8.4: "`-order_file`
//! applies a stable sort by the order file's rank") — ranked pieces land
//! first in rank order, everything unranked keeps the canonical input
//! order behind them. Nothing reads a hash iteration order: ranks come
//! from the entry vector, lookups never enumerate the tables.
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
}
