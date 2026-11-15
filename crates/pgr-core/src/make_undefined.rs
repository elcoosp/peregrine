//! The make-undefined seam as a nameable decision (M39): the `-U
//! <name>` entries ld64 defines stop being an unnameable Pass-2 shape
//! and become a validated table on [`crate::layout::LinkConfig`] — the
//! symbols that are treated as undefined *as they are linked*, so a
//! definition this image carries stops answering references and the
//! name binds where the `-undefined` policy sends it (a dylib export,
//! the bundle's host, or the runtime's dynamic lookup). The canonical
//! use is the overridable symbol: the archive's strong `_f` keeps
//! compiling in, but `-U _f -undefined dynamic_lookup` lets the host's
//! own definition win at load time.
//!
//! The decision rides Pass 2, at the definition-install step: a marked
//! name never installs (an `N_SECT` definition or a common alike), so
//! the symtab row, the export-trie node and the `__common` slot the
//! definition would have claimed all drop, and the defining atom loses
//! its liveness root (a `-dead_strip` link drops the body nothing
//! references anymore). References to a marked name follow the
//! `-undefined` policy like any unresolved name — under the default
//! `-undefined error` the link refuses with the fix; under
//! `-undefined dynamic_lookup` the bind rides the flat-lookup ordinal.
//!
//! The decision is *validated, not defaulted*: a name must be non-empty
//! (an empty name is a typo, not a symbol) and free of interior NULs
//! (the symtab string cannot carry one), a name enters the table once
//! (a repeated decision is a typo), and every name must land on a
//! definition some input object carries — a name nothing defines has
//! nothing to strip (the vacuous decision refuses with the misspelling
//! named, the `-alias` convention). The default is the empty table —
//! every pre-M39 link is byte-identical.
//!
//! The knob refuses where it cannot land: the relocatable output
//! carries its input symbol table verbatim (the Pass-2 decision has
//! nothing to strip). The driver surface refuses at parse time; the
//! library re-checks so no caller can plan the shape either.

/// One validated make-undefined decision: the symbol name (the C
/// spelling, leading underscore included) that stops being a definition.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MakeUndefinedName {
    name: String,
}

impl MakeUndefinedName {
    /// Validates one `-U` name: non-empty, NUL-free. The refusal names
    /// the fix (the house error convention) — the driver renders it as
    /// miette help text, the wire maps it to a malformed frame.
    ///
    /// # Errors
    /// [`MakeUndefinedError::Empty`] on an empty name,
    /// [`MakeUndefinedError::Nul`] on an interior NUL.
    pub fn from_flag(raw: &str) -> Result<Self, MakeUndefinedError> {
        if raw.is_empty() {
            return Err(MakeUndefinedError::Empty);
        }
        if raw.contains('\0') {
            return Err(MakeUndefinedError::Nul {
                raw: raw.to_string(),
            });
        }
        tracing::debug!(name = raw, "the make-undefined seam marks a symbol");
        Ok(Self {
            name: raw.to_string(),
        })
    }

    /// The marked symbol's name (the C spelling the symtab carries).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// A `-U` refusal: the message names the fix (the grammar the flag
/// accepts), never just the verdict.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MakeUndefinedError {
    /// An empty name is a typo, not a symbol.
    #[error(
        "invalid -U name: empty — the decision names a symbol (C symbols \
         carry the leading underscore, e.g. -U _f)"
    )]
    Empty,
    /// The symtab string cannot carry an interior NUL — the name would
    /// silently truncate to a different symbol.
    #[error(
        "invalid -U name {raw:?}: an interior NUL cannot ride the symbol \
         table — the name would truncate to a different symbol"
    )]
    Nul {
        /// The refused name as written.
        raw: String,
    },
    /// A repeated decision is a typo — one mark per name.
    #[error(
        "invalid -U name {raw}: the name is already marked — one decision \
         per symbol; drop the repeated -U"
    )]
    Duplicate {
        /// The refused name as written.
        raw: String,
    },
}

/// The make-undefined table: the `-U` decisions in flag order. The
/// default is the empty table — every pre-M39 link is byte-identical.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MakeUndefined {
    names: Vec<MakeUndefinedName>,
}

impl MakeUndefined {
    /// The empty table (the pre-M39 default).
    #[must_use]
    pub const fn new() -> Self {
        Self { names: Vec::new() }
    }

    /// Adds one decision, refusing a repeated name (one mark per
    /// symbol — the duplicate is a typo).
    ///
    /// # Errors
    /// [`MakeUndefinedError::Duplicate`] when the name is already marked.
    pub fn push(&mut self, entry: MakeUndefinedName) -> Result<(), MakeUndefinedError> {
        if self.names.iter().any(|e| e.name == entry.name) {
            return Err(MakeUndefinedError::Duplicate { raw: entry.name });
        }
        self.names.push(entry);
        Ok(())
    }

    /// True when no decision rides the link.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// The number of decisions.
    #[must_use]
    pub fn count(&self) -> usize {
        self.names.len()
    }

    /// The decisions in flag order.
    pub fn iter(&self) -> std::slice::Iter<'_, MakeUndefinedName> {
        self.names.iter()
    }

    /// The marked names in flag order (the wire payload, the driver's
    /// stage validation).
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.names.iter().map(MakeUndefinedName::name).collect()
    }
}

impl<'a> IntoIterator for &'a MakeUndefined {
    type Item = &'a MakeUndefinedName;
    type IntoIter = std::slice::Iter<'a, MakeUndefinedName>;

    fn into_iter(self) -> Self::IntoIter {
        self.names.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::{MakeUndefined, MakeUndefinedError, MakeUndefinedName};

    #[test]
    fn names_validate_and_keep_the_shape() {
        let f = MakeUndefinedName::from_flag("_f").expect("valid");
        assert_eq!(f.name(), "_f");
        assert!(matches!(
            MakeUndefinedName::from_flag(""),
            Err(MakeUndefinedError::Empty)
        ));
        assert!(matches!(
            MakeUndefinedName::from_flag("_bad\0name"),
            Err(MakeUndefinedError::Nul { .. })
        ));
    }

    #[test]
    fn the_table_is_a_set() {
        let mut t = MakeUndefined::new();
        t.push(MakeUndefinedName::from_flag("_f").expect("valid"))
            .expect("lands");
        t.push(MakeUndefinedName::from_flag("_g").expect("valid"))
            .expect("lands");
        assert_eq!(t.count(), 2);
        assert_eq!(t.names(), vec!["_f", "_g"]);
        assert!(matches!(
            t.push(MakeUndefinedName::from_flag("_f").expect("valid")),
            Err(MakeUndefinedError::Duplicate { .. })
        ));
    }
}
