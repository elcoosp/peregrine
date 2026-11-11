//! The dylib umbrella region as a nameable decision (M20): the
//! `-sub_umbrella <name>` / `-sub_library <name>` members an umbrella
//! dylib carries beside its `LC_ID_DYLIB` stop being the `LATER_FLAGS`
//! backlog and become a validated table on [`crate::layout::LinkConfig`]
//! — the `LC_SUB_UMBRELLA`/`LC_SUB_LIBRARY` commands dyld reads to load
//! the umbrella when a member is requested by name. The driver's flags
//! name the members on the command line; the daemon wire (v13) carries
//! the table so a resident relink emits the region the client asked
//! for.
//!
//! The decision is *validated, not defaulted*: a member name must be
//! non-empty (an empty name is a typo, not a member) and free of
//! interior NULs (the command's `lc_str` cannot carry one — the C
//! string would silently truncate to a different member), and a name
//! enters the table once (a repeated member is a typo; the same name
//! under both kinds is still one member — the commands name the same
//! region). The default is the empty table — every pre-M20 link is
//! byte-identical.
//!
//! The knob refuses where it cannot land: the region is a dylib's
//! identity block — an executable, a bundle and the relocatable output
//! carry no sub commands. The driver surface refuses at parse time; the
//! layout re-checks so no library caller can plan the shape either.

use pgr_format::consts::{LC_SUB_LIBRARY, LC_SUB_UMBRELLA};

/// The umbrella-region command family: the two member kinds ld64
/// accepts on an umbrella dylib.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UmbrellaKind {
    /// `LC_SUB_UMBRELLA` (`-sub_umbrella`): a sub-umbrella member —
    /// another framework umbrella the umbrella names.
    SubUmbrella,
    /// `LC_SUB_LIBRARY` (`-sub_library`): a sub-library member — the
    /// region's non-framework half.
    SubLibrary,
}

impl UmbrellaKind {
    /// The load-command opcode this member emits.
    #[must_use]
    pub const fn opcode(self) -> u32 {
        match self {
            Self::SubUmbrella => LC_SUB_UMBRELLA,
            Self::SubLibrary => LC_SUB_LIBRARY,
        }
    }
}

impl std::fmt::Display for UmbrellaKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl UmbrellaKind {
    /// The wire byte the daemon protocol encodes (v13).
    #[must_use]
    pub const fn wire(self) -> u8 {
        match self {
            Self::SubUmbrella => 0,
            Self::SubLibrary => 1,
        }
    }

    /// Decodes the wire byte (v13). `None` on an unknown kind — the
    /// frame maps to a malformed refusal, never a guessed member.
    #[must_use]
    pub const fn from_wire(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::SubUmbrella),
            1 => Some(Self::SubLibrary),
            _ => None,
        }
    }

    /// The flag the member rides (the surface the refusal names).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SubUmbrella => "sub-umbrella",
            Self::SubLibrary => "sub-library",
        }
    }
}

/// One validated member of the umbrella region: the kind (which command
/// carries it) and the name (the member's dylib name — an install-name
/// style string, written at the command's `lc_str` offset).
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UmbrellaMember {
    kind: UmbrellaKind,
    name: String,
}

impl UmbrellaMember {
    /// Validates one `-sub_umbrella`/`-sub_library` name: non-empty,
    /// NUL-free. The refusal names the fix (the house error
    /// convention) — the driver renders it as miette help text, the
    /// wire maps it to a malformed frame.
    ///
    /// # Errors
    /// [`UmbrellaError::Empty`] on an empty name,
    /// [`UmbrellaError::Nul`] on an interior NUL.
    pub fn from_flag(kind: UmbrellaKind, raw: &str) -> Result<Self, UmbrellaError> {
        if raw.is_empty() {
            return Err(UmbrellaError::Empty { kind });
        }
        if raw.contains('\0') {
            return Err(UmbrellaError::Nul {
                kind,
                raw: raw.to_string(),
            });
        }
        tracing::debug!(
            kind = kind.as_str(),
            name = raw,
            "the umbrella region names a member"
        );
        Ok(Self {
            kind,
            name: raw.to_string(),
        })
    }

    /// The member's kind (which command carries it).
    #[must_use]
    pub const fn kind(&self) -> UmbrellaKind {
        self.kind
    }

    /// The member's name (the `lc_str` the command writes).
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

/// The umbrella region: the ordered member table a dylib link plans
/// with (flag order — the commands land in the order the flags named
/// them, the deterministic order the region's tests pin). Constructed
/// member-by-member so a [`Umbrella`] in hand is always a legal table
/// (validated names, no duplicates — one decision per name across both
/// kinds). The default is empty: every pre-M20 link plans byte-identically.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Umbrella {
    members: Vec<UmbrellaMember>,
}

impl Umbrella {
    /// The empty table (the pre-M20 default).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            members: Vec::new(),
        }
    }

    /// Adds a validated member. Duplicate names refuse — the same name
    /// under either kind is the same region decision, and a repeat is
    /// a typo, not a second command.
    ///
    /// # Errors
    /// [`UmbrellaError::Duplicate`] when `member`'s name is already in
    /// the table.
    pub fn push(&mut self, member: UmbrellaMember) -> Result<(), UmbrellaError> {
        if self.members.iter().any(|m| m.name == member.name) {
            return Err(UmbrellaError::Duplicate {
                kind: member.kind,
                name: member.name,
            });
        }
        self.members.push(member);
        Ok(())
    }

    /// True when no member rides the region (the pre-M20 shape).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// The member count (the emitted command count).
    #[must_use]
    pub fn count(&self) -> usize {
        self.members.len()
    }

    /// The members in flag order (the emit order).
    pub fn iter(&self) -> std::slice::Iter<'_, UmbrellaMember> {
        self.members.iter()
    }

    /// The region's total command size (the sizing formula's row).
    #[must_use]
    pub fn region_size(&self) -> usize {
        self.members.iter().map(UmbrellaMember::cmd_size).sum()
    }
}

impl IntoIterator for Umbrella {
    type Item = UmbrellaMember;
    type IntoIter = std::vec::IntoIter<UmbrellaMember>;

    fn into_iter(self) -> Self::IntoIter {
        self.members.into_iter()
    }
}

impl<'a> IntoIterator for &'a Umbrella {
    type Item = &'a UmbrellaMember;
    type IntoIter = std::slice::Iter<'a, UmbrellaMember>;

    fn into_iter(self) -> Self::IntoIter {
        self.members.iter()
    }
}

/// An umbrella-member refusal: the message names the fix (the grammar
/// the flag accepts), never just the verdict.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UmbrellaError {
    /// An empty name is the absence of a member, not a decision — name
    /// the member's dylib name.
    #[error(
        "invalid {kind} member: the name must be non-empty — \
         name the member's dylib name (e.g. -sub_umbrella MySub.framework)"
    )]
    Empty {
        /// The kind the empty name rode.
        kind: UmbrellaKind,
    },
    /// The command's `lc_str` is a C string: an interior NUL would
    /// silently truncate the member to a different name.
    #[error(
        "invalid {kind} member {raw:?}: the name must be free of NUL bytes — \
         the command carries a C string"
    )]
    Nul {
        /// The kind the name rode.
        kind: UmbrellaKind,
        /// The refused name as written.
        raw: String,
    },
    /// The region names a member once; the same name under both kinds
    /// is still one member — drop the repeat.
    #[error(
        "duplicate umbrella member {name:?}: the region names a member once — \
         drop the repeated {kind} entry"
    )]
    Duplicate {
        /// The kind of the refused repeat.
        kind: UmbrellaKind,
        /// The refused name.
        name: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn members_validate_and_size_the_lc_str_shape() {
        let m = UmbrellaMember::from_flag(UmbrellaKind::SubUmbrella, "libsub.dylib").expect("ok");
        assert_eq!(m.kind(), UmbrellaKind::SubUmbrella);
        assert_eq!(m.name(), "libsub.dylib");
        assert_eq!(m.cmd_size(), 32);
        // The wire kinds round-trip; an unknown byte refuses.
        assert_eq!(
            UmbrellaKind::from_wire(UmbrellaKind::SubLibrary.wire()),
            Some(UmbrellaKind::SubLibrary)
        );
        assert!(UmbrellaKind::from_wire(2).is_none());
        // The opcodes are the vendored constants.
        assert_eq!(UmbrellaKind::SubUmbrella.opcode(), LC_SUB_UMBRELLA);
        assert_eq!(UmbrellaKind::SubLibrary.opcode(), LC_SUB_LIBRARY);
    }

    #[test]
    fn refusals_and_duplicates_name_the_fix() {
        assert!(UmbrellaMember::from_flag(UmbrellaKind::SubUmbrella, "").is_err());
        assert!(UmbrellaMember::from_flag(UmbrellaKind::SubLibrary, "a\0b").is_err());
        let mut t = Umbrella::new();
        t.push(UmbrellaMember::from_flag(UmbrellaKind::SubUmbrella, "libdup.dylib").expect("ok"))
            .expect("first lands");
        let err = t
            .push(UmbrellaMember::from_flag(UmbrellaKind::SubLibrary, "libdup.dylib").expect("ok"))
            .expect_err("duplicate refuses");
        assert!(err.to_string().contains("libdup.dylib"), "{err}");
        assert!(!t.is_empty() && t.count() == 1);
    }
}
