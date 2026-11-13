//! The dylib client seam as a nameable decision (M21): the
//! `-sub_client <name>` entries an identity-block dylib carries stop
//! being an unnameable load-command shape and become a validated table
//! on [`crate::layout::LinkConfig`] — the `LC_SUB_CLIENT` commands dyld
//! reads to let a named requesting image link the dylib when its
//! linkage is restricted. The commands ride the identity block right
//! after the M20 umbrella region (`LC_SUB_UMBRELLA`/`LC_SUB_LIBRARY`),
//! the ld64-canonical adjacency. The driver's flag names the clients on
//! the command line; the daemon wire (v14) carries the list so a
//! resident relink emits the clients the client (the linking image)
//! asked for.
//!
//! The decision is *validated, not defaulted*: a client name must be
//! non-empty (an empty name is a typo, not a client) and free of
//! interior NULs (the command's `lc_str` cannot carry one — the C
//! string would silently truncate to a different client), and a name
//! enters the table once (a repeated client is a typo). The default is
//! the empty table — every pre-M21 link is byte-identical.
//!
//! The knob refuses where it cannot land: the clients are a dylib's
//! identity block — an executable, a bundle and the relocatable output
//! carry no sub commands. The driver surface refuses at parse time; the
//! layout re-checks so no library caller can plan the shape either.

/// One validated client of the identity block: the name (the requesting
/// image's own name — an install-name style string, written at the
/// command's `lc_str` offset).
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubClientEntry {
    name: String,
}

impl SubClientEntry {
    /// Validates one `-sub_client` name: non-empty, NUL-free. The
    /// refusal names the fix (the house error convention) — the driver
    /// renders it as miette help text, the wire maps it to a malformed
    /// frame.
    ///
    /// # Errors
    /// [`SubClientError::Empty`] on an empty name,
    /// [`SubClientError::Nul`] on an interior NUL.
    pub fn from_flag(raw: &str) -> Result<Self, SubClientError> {
        if raw.is_empty() {
            return Err(SubClientError::Empty);
        }
        if raw.contains('\0') {
            return Err(SubClientError::Nul {
                raw: raw.to_string(),
            });
        }
        tracing::debug!(name = raw, "the client seam names a client");
        Ok(Self {
            name: raw.to_string(),
        })
    }

    /// The client's name (the `lc_str` the command writes).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The command's byte size: the 12-byte fixed part (`cmd`,
    /// `cmdsize`, `lc_str` offset — the `LC_RPATH` shape), the name
    /// inline with its NUL, 8-byte aligned.
    #[must_use]
    pub fn cmd_size(&self) -> usize {
        align8(12 + self.name.len() + 1)
    }
}

fn align8(n: usize) -> usize {
    n.div_ceil(8) * 8
}

/// The client table: the ordered client list a dylib link plans with
/// (flag order — the commands land in the order the flags named them,
/// the deterministic order the seam's tests pin). Constructed
/// entry-by-entry so a [`SubClient`] in hand is always a legal list
/// (validated names, no duplicates — one decision per name). The
/// default is empty: every pre-M21 link plans byte-identically.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubClient {
    entries: Vec<SubClientEntry>,
}

impl SubClient {
    /// The empty list (the pre-M21 default).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Adds a validated client. Duplicate names refuse — a repeated
    /// client is a typo, not a second command.
    ///
    /// # Errors
    /// [`SubClientError::Duplicate`] when `entry`'s name is already in
    /// the list.
    pub fn push(&mut self, entry: SubClientEntry) -> Result<(), SubClientError> {
        if self.entries.iter().any(|c| c.name == entry.name) {
            return Err(SubClientError::Duplicate { name: entry.name });
        }
        self.entries.push(entry);
        Ok(())
    }

    /// True when no client rides the list (the pre-M21 shape).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The client count (the emitted command count).
    #[must_use]
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// The clients in flag order (the emit order).
    pub fn iter(&self) -> std::slice::Iter<'_, SubClientEntry> {
        self.entries.iter()
    }

    /// The list's total command size (the sizing formula's row).
    #[must_use]
    pub fn region_size(&self) -> usize {
        self.entries.iter().map(SubClientEntry::cmd_size).sum()
    }
}

impl IntoIterator for SubClient {
    type Item = SubClientEntry;
    type IntoIter = std::vec::IntoIter<SubClientEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

impl<'a> IntoIterator for &'a SubClient {
    type Item = &'a SubClientEntry;
    type IntoIter = std::slice::Iter<'a, SubClientEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

/// A sub-client refusal: the message names the fix (the grammar the
/// flag accepts), never just the verdict.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SubClientError {
    /// An empty name is the absence of a client, not a decision — name
    /// the requesting image's name.
    #[error(
        "invalid sub_client name: the name must be non-empty — \
         name the requesting image's name (e.g. -sub_client client.app)"
    )]
    Empty,
    /// The command's `lc_str` is a C string: an interior NUL would
    /// silently truncate the client to a different name.
    #[error(
        "invalid sub_client name {raw:?}: the name must be free of NUL bytes — \
         the command carries a C string"
    )]
    Nul {
        /// The refused name as written.
        raw: String,
    },
    /// The seam names a client once; a repeat is a typo — drop it.
    #[error(
        "duplicate sub_client {name:?}: the seam names a client once — \
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
    fn clients_validate_and_size_the_lc_str_shape() {
        let c = SubClientEntry::from_flag("client.app").expect("ok");
        assert_eq!(c.name(), "client.app");
        assert_eq!(c.cmd_size(), 24);
        assert_eq!(SubClientEntry::from_flag("a").expect("ok").cmd_size(), 16);
    }

    #[test]
    fn refusals_and_duplicates_name_the_fix() {
        assert!(SubClientEntry::from_flag("").is_err());
        assert!(SubClientEntry::from_flag("a\0b").is_err());
        let mut t = SubClient::new();
        t.push(SubClientEntry::from_flag("client.app").expect("ok"))
            .expect("first lands");
        let err = t
            .push(SubClientEntry::from_flag("client.app").expect("ok"))
            .expect_err("duplicate refuses");
        assert!(err.to_string().contains("client.app"), "{err}");
        assert!(!t.is_empty() && t.count() == 1);
    }
}
