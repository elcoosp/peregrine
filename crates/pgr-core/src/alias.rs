//! The symbol-alias seam as a nameable decision (M24): the
//! `-alias <alias_name> <definition_name>` pairs stop being an
//! unnameable symtab/trie shape and become a validated table on
//! [`crate::layout::LinkConfig`] — the extra exported symbol names
//! ld64's `-alias` creates, each pointing at the same definition as the
//! named symbol (an ABI shim: the old name keeps resolving, the image
//! ships one body). The alias rides the symtab as a defined external
//! row carrying the definition's section, value and weak mark, and
//! joins the export trie at the definition's address — dyld resolves
//! both names to one body.
//!
//! The decision is *validated, not defaulted*: both names must be
//! non-empty and NUL-free (the symtab strings are C strings — an
//! interior NUL would silently truncate the name to a different one),
//! and the two names must be distinct (an alias of itself is a
//! tautology — a silently dropped decision). A name enters the table
//! once as an alias (a repeated alias is a typo — the second row would
//! be a silently dropped or doubly-shipped decision). The default is
//! the empty table — every pre-M24 link is byte-identical.
//!
//! The knob refuses where it cannot land: the relocatable output
//! carries the input symtab verbatim (an alias is an image-surface
//! decision), and the layout re-checks the two image-shaped refusals so
//! no library caller can plan them either — an alias of a name no input
//! defines (the fix names the misspelling), and an alias name already
//! defined in the image (one symtab row per external name: the
//! duplicate would silently shadow). The driver surface refuses at
//! parse time; the layout re-checks so the seam holds everywhere.

/// One validated alias: the new exported name and the definition it
/// points at (both raw symbol names, mangled form — the `_` prefix
/// included).
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alias {
    alias: String,
    definition: String,
}

impl Alias {
    /// Validates one `-alias` pair: non-empty, NUL-free names, distinct
    /// halves. The refusal names the fix (the house error convention) —
    /// the driver renders it as miette help text, the wire maps it to a
    /// malformed frame.
    ///
    /// # Errors
    /// [`AliasError::Malformed`] on an empty name or an identity alias,
    /// [`AliasError::Nul`] on an interior NUL.
    pub fn from_parts(alias: &str, definition: &str) -> Result<Self, AliasError> {
        for (which, name) in [("alias", alias), ("definition", definition)] {
            if name.contains('\0') {
                return Err(AliasError::Nul {
                    raw: format!("{alias} {definition}"),
                    which: which.to_string(),
                });
            }
            if name.is_empty() {
                return Err(AliasError::Malformed {
                    raw: format!("{alias} {definition}"),
                });
            }
        }
        if alias == definition {
            return Err(AliasError::Malformed {
                raw: format!("{alias} {definition}"),
            });
        }
        tracing::debug!(alias, definition, "the alias seam names an export");
        Ok(Self {
            alias: alias.to_string(),
            definition: definition.to_string(),
        })
    }

    /// The new exported name (the symtab row and trie node).
    #[must_use]
    pub fn alias(&self) -> &str {
        &self.alias
    }

    /// The defined name the alias points at.
    #[must_use]
    pub fn definition(&self) -> &str {
        &self.definition
    }
}

/// The alias table: the ordered pair list an image link plans with
/// (flag order — the symtab rows land in the order the flags named
/// them, the deterministic order the seam's tests pin). Constructed
/// entry-by-entry so an [`AliasTable`] in hand is always a legal list
/// (validated pairs, no duplicate alias names — one decision per name).
/// The default is empty: every pre-M24 link plans byte-identically.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AliasTable {
    entries: Vec<Alias>,
}

impl AliasTable {
    /// The empty list (the pre-M24 default).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Adds a validated alias. A duplicate alias name refuses — the
    /// second row would be a silently dropped or doubly-shipped
    /// decision.
    ///
    /// # Errors
    /// [`AliasError::Duplicate`] when `entry`'s alias name is already
    /// in the list.
    pub fn push(&mut self, entry: Alias) -> Result<(), AliasError> {
        if self.entries.iter().any(|e| e.alias == entry.alias) {
            return Err(AliasError::Duplicate {
                name: entry.alias.clone(),
            });
        }
        self.entries.push(entry);
        Ok(())
    }

    /// True when no alias rides the list (the pre-M24 shape).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The alias count (the emitted symtab rows and trie nodes).
    #[must_use]
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// The aliases in flag order (the emit order).
    pub fn iter(&self) -> std::slice::Iter<'_, Alias> {
        self.entries.iter()
    }
}

impl IntoIterator for AliasTable {
    type Item = Alias;
    type IntoIter = std::vec::IntoIter<Alias>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

impl<'a> IntoIterator for &'a AliasTable {
    type Item = &'a Alias;
    type IntoIter = std::slice::Iter<'a, Alias>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

/// An alias refusal: the message names the fix (the grammar the flag
/// accepts), never just the verdict.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AliasError {
    /// A pair without its `-alias <alias_name> <definition_name>`
    /// grammar: an empty name (no symbol) or the two halves equal (an
    /// identity alias — a tautology dyld would resolve the same, so
    /// emitting it would be a silently dropped decision).
    #[error(
        "invalid alias {raw:?}: the grammar is -alias <alias_name> <definition_name> — \
         two non-empty names, distinct halves"
    )]
    Malformed {
        /// The refused pair as written.
        raw: String,
    },
    /// The symtab strings are C strings: an interior NUL would silently
    /// truncate the name to a different one.
    #[error(
        "invalid alias {raw:?}: the {which} must be free of NUL bytes — \
         the symtab carries C strings"
    )]
    Nul {
        /// The refused pair as written.
        raw: String,
        /// Which half carried the NUL (`alias` or `definition`).
        which: String,
    },
    /// The seam names a name once; a repeat is a typo — the second row
    /// would be a silently dropped or doubly-shipped decision.
    #[error(
        "duplicate alias name {name:?}: the seam names a name once — \
         drop the repeated entry"
    )]
    Duplicate {
        /// The refused name.
        name: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairs_validate_and_keep_flag_order() {
        let e = Alias::from_parts("_shim", "_lib_fn").expect("ok");
        assert_eq!(e.alias(), "_shim");
        assert_eq!(e.definition(), "_lib_fn");
        let mut t = AliasTable::new();
        t.push(Alias::from_parts("_a", "_x").expect("ok"))
            .expect("first lands");
        t.push(Alias::from_parts("_b", "_y").expect("ok"))
            .expect("second lands");
        let aliases: Vec<&str> = t.iter().map(Alias::alias).collect();
        assert_eq!(aliases, ["_a", "_b"], "flag order holds");
        assert_eq!(t.count(), 2);
        assert!(!t.is_empty());
    }

    #[test]
    fn refusals_and_duplicates_name_the_fix() {
        assert!(Alias::from_parts("", "_x").is_err());
        assert!(Alias::from_parts("_a", "").is_err());
        assert!(Alias::from_parts("_a\0x", "_y").is_err());
        assert!(Alias::from_parts("_a", "_y\0").is_err());
        assert!(Alias::from_parts("_same", "_same").is_err());
        let mut t = AliasTable::new();
        t.push(Alias::from_parts("_dup", "_x").expect("ok"))
            .expect("first lands");
        let err = t
            .push(Alias::from_parts("_dup", "_y").expect("ok"))
            .expect_err("duplicate refuses");
        assert!(err.to_string().contains("_dup"), "{err}");
        assert!(!t.is_empty() && t.count() == 1);
    }
}
