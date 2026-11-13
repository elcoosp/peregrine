//! The dyld-environment seam as a nameable decision (M22): the
//! `-dyld_env DYLD_<var>=<value>` pairs an executable exports stop
//! being an unnameable load-command shape and become a validated table
//! on [`crate::layout::LinkConfig`] — the `LC_DYLD_ENVIRONMENT`
//! commands dyld reads from the main executable to start the image with
//! the named variables set (the loader-configuration command; dyld
//! honors `DYLD_`-prefixed variables from it and ignores the rest).
//! The commands ride the loader-configuration adjacency right after
//! `LC_MAIN` (which loader, entry and stack — then what the loader
//! exports). The driver's flag names the pairs on the command line;
//! the daemon wire (v15) carries the list so a resident relink exports
//! the variables the client asked for.
//!
//! The decision is *validated, not defaulted*: a pair must name a
//! `DYLD_`-prefixed variable and exactly one `=` separator (the
//! ld64/lld `-dyld_env DYLD_<var>=<value>` grammar — anything else dyld
//! ignores, so emitting it would be a silently dropped knob), the
//! variable must be non-empty past the prefix (`DYLD_=` names no
//! variable), and the `lc_str` cannot carry an interior NUL (the C
//! string would silently truncate to a different pair). The value may
//! be empty and may itself carry `=` (everything after the first `=`
//! is the value — the same split lld pays). A variable enters the
//! table once (a repeated variable is a typo — dyld keeps its first
//! encounter, so the loser would be a silently dropped decision). The
//! default is the empty table — every pre-M22 link is byte-identical.
//!
//! The knob refuses where it cannot land: dyld reads the command from
//! the main executable only — a dylib, a bundle and the relocatable
//! output carry no environment to export. The driver surface refuses
//! at parse time; the layout re-checks so no library caller can plan
//! the shape either.

/// One validated environment pair: the `VAR=VALUE` string (written at
/// the command's `lc_str` offset, the `dylinker_command` struct's C
/// string). The variable/value split is re-derivable from the first
/// `=`.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DyldEnvEntry {
    raw: String,
}

impl DyldEnvEntry {
    /// Validates one `-dyld_env` pair: `DYLD_`-prefixed non-empty
    /// variable, one `=` separator, NUL-free. The refusal names the fix
    /// (the house error convention) — the driver renders it as miette
    /// help text, the wire maps it to a malformed frame.
    ///
    /// # Errors
    /// [`DyldEnvError::Malformed`] on a missing `=`, a missing
    /// `DYLD_` prefix or an empty variable name,
    /// [`DyldEnvError::Nul`] on an interior NUL.
    pub fn from_flag(raw: &str) -> Result<Self, DyldEnvError> {
        if raw.contains('\0') {
            return Err(DyldEnvError::Nul {
                raw: raw.to_string(),
            });
        }
        let Some((var, _value)) = raw.split_once('=') else {
            return Err(DyldEnvError::Malformed {
                raw: raw.to_string(),
            });
        };
        let Some(name) = var.strip_prefix("DYLD_") else {
            return Err(DyldEnvError::Malformed {
                raw: raw.to_string(),
            });
        };
        if name.is_empty() {
            return Err(DyldEnvError::Malformed {
                raw: raw.to_string(),
            });
        }
        tracing::debug!(var, "the dyld-environment seam exports a variable");
        Ok(Self {
            raw: raw.to_string(),
        })
    }

    /// The variable name (everything before the first `=`).
    #[must_use]
    pub fn var(&self) -> &str {
        self.raw
            .split_once('=')
            .map_or(self.raw.as_str(), |(v, _)| v)
    }

    /// The value (everything after the first `=` — possibly empty).
    #[must_use]
    pub fn value(&self) -> &str {
        self.raw.split_once('=').map_or("", |(_, v)| v)
    }

    /// The pair as written (`VAR=VALUE` — the `lc_str` the command
    /// writes).
    #[must_use]
    pub fn pair(&self) -> &str {
        &self.raw
    }

    /// The command's byte size: the 12-byte fixed part (`cmd`,
    /// `cmdsize`, `lc_str` offset — the `dylinker_command` struct, the
    /// `LC_RPATH` shape), the pair inline with its NUL, 8-byte aligned.
    #[must_use]
    pub fn cmd_size(&self) -> usize {
        align8(12 + self.raw.len() + 1)
    }
}

fn align8(n: usize) -> usize {
    n.div_ceil(8) * 8
}

/// The environment table: the ordered pair list an executable link
/// plans with (flag order — the commands land in the order the flags
/// named them, the deterministic order the seam's tests pin).
/// Constructed entry-by-entry so a [`DyldEnv`] in hand is always a
/// legal list (validated pairs, no duplicate variables — one decision
/// per variable). The default is empty: every pre-M22 link plans
/// byte-identically.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DyldEnv {
    entries: Vec<DyldEnvEntry>,
}

impl DyldEnv {
    /// The empty list (the pre-M22 default).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Adds a validated pair. A duplicate variable refuses — dyld keeps
    /// its first encounter, so a repeated variable is a silently
    /// dropped decision, not a second command.
    ///
    /// # Errors
    /// [`DyldEnvError::Duplicate`] when `entry`'s variable is already
    /// in the list.
    pub fn push(&mut self, entry: DyldEnvEntry) -> Result<(), DyldEnvError> {
        if self.entries.iter().any(|e| e.var() == entry.var()) {
            return Err(DyldEnvError::Duplicate {
                var: entry.var().to_string(),
            });
        }
        self.entries.push(entry);
        Ok(())
    }

    /// True when no pair rides the list (the pre-M22 shape).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The pair count (the emitted command count).
    #[must_use]
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// The pairs in flag order (the emit order).
    pub fn iter(&self) -> std::slice::Iter<'_, DyldEnvEntry> {
        self.entries.iter()
    }

    /// The list's total command size (the sizing formula's row).
    #[must_use]
    pub fn region_size(&self) -> usize {
        self.entries.iter().map(DyldEnvEntry::cmd_size).sum()
    }
}

impl IntoIterator for DyldEnv {
    type Item = DyldEnvEntry;
    type IntoIter = std::vec::IntoIter<DyldEnvEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

impl<'a> IntoIterator for &'a DyldEnv {
    type Item = &'a DyldEnvEntry;
    type IntoIter = std::slice::Iter<'a, DyldEnvEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

/// A dyld-environment refusal: the message names the fix (the grammar
/// the flag accepts), never just the verdict.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DyldEnvError {
    /// A pair without its `DYLD_<var>=<value>` grammar: no `=`
    /// separator, no `DYLD_` prefix, or an empty variable name — all
    /// shapes dyld ignores (a silently dropped knob if emitted).
    #[error(
        "invalid dyld_env pair {raw:?}: the grammar is -dyld_env DYLD_<var>=<value> — \
         a DYLD_-prefixed variable, one = separator, a non-empty variable name"
    )]
    Malformed {
        /// The refused pair as written.
        raw: String,
    },
    /// The command's `lc_str` is a C string: an interior NUL would
    /// silently truncate the pair to a different one.
    #[error(
        "invalid dyld_env pair {raw:?}: the pair must be free of NUL bytes — \
         the command carries a C string"
    )]
    Nul {
        /// The refused pair as written.
        raw: String,
    },
    /// The seam exports a variable once; a repeat is a typo — dyld
    /// keeps its first encounter, so the loser would be silently
    /// dropped.
    #[error(
        "duplicate dyld_env variable {var:?}: the seam exports a variable once — \
         drop the repeated entry"
    )]
    Duplicate {
        /// The refused variable.
        var: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairs_validate_and_size_the_lc_str_shape() {
        let e = DyldEnvEntry::from_flag("DYLD_PRINT_LIBRARIES=1").expect("ok");
        assert_eq!(e.var(), "DYLD_PRINT_LIBRARIES");
        assert_eq!(e.value(), "1");
        assert_eq!(e.pair(), "DYLD_PRINT_LIBRARIES=1");
        assert_eq!(e.cmd_size(), 40);
        assert_eq!(
            DyldEnvEntry::from_flag("DYLD_A=1").expect("ok").cmd_size(),
            24
        );
    }

    #[test]
    fn refusals_and_duplicates_name_the_fix() {
        assert!(DyldEnvEntry::from_flag("DYLD_PRINT_LIBRARIES").is_err());
        assert!(DyldEnvEntry::from_flag("PATH=/bin").is_err());
        assert!(DyldEnvEntry::from_flag("DYLD_=x").is_err());
        assert!(DyldEnvEntry::from_flag("DYLD_A=a\0b").is_err());
        let mut t = DyldEnv::new();
        t.push(DyldEnvEntry::from_flag("DYLD_A=1").expect("ok"))
            .expect("first lands");
        let err = t
            .push(DyldEnvEntry::from_flag("DYLD_A=2").expect("ok"))
            .expect_err("duplicate refuses");
        assert!(err.to_string().contains("DYLD_A"), "{err}");
        assert!(!t.is_empty() && t.count() == 1);
    }
}
