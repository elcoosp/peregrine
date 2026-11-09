//! The platform surface as a nameable decision (M10 rung 3, slice 1,
//! roadmap §10.4 row M10): rung 2 plumbed the five platforms through the
//! driver (`-platform_version`), the layout floor
//! ([`crate::layout::chained_fixups_min_minos`]) and the verifier's
//! build-version gate, but the fixup-encoding decision itself was only
//! observable by running Pass 3 — or by re-deriving the floor table, the
//! duplication drift this seam closes. [`FixupEncoding::for_target`]
//! names the decision for a (`-platform_version` platform, deployment
//! target) pair from the *same* table the layout encodes — one table,
//! two readers — so build systems, incremental planners and doc
//! generators read the encoding without linking, and the below-floor
//! answer rides a tracing event (the house observability convention:
//! inert until a subscriber installs).

use crate::layout::chained_fixups_min_minos;

/// The fixup encoding Pass 3 plans for a link target: dyld's chained
/// fixup words, or the M6 classic rebase/bind opcode streams. The
/// encoding flips with the deployment floor; the fixups themselves do
/// not (TDD §3.6 invariant 3 — the fallback changes the encoding, never
/// the fixups).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FixupEncoding {
    /// `LC_DYLD_CHAINED_FIXUPS` chain words — at or above the platform's
    /// deployment floor (`macos` ≥ 12.0, `ios`/`tvos` ≥ 15.0, `watchos`
    /// ≥ 8.0, `visionos` ≥ 1.0).
    ChainedFixups,
    /// Classic `LC_DYLD_INFO_ONLY` rebase/bind opcode streams — below
    /// the floor (the M6 legacy path, platform-aware since rung 2).
    ClassicOpcodes,
}

impl FixupEncoding {
    /// The encoding a `-platform_version <platform>` link at deployment
    /// target `minos` (the packed `X.Y.Z` word, major << 16) plans with.
    /// Reads the per-platform floor from
    /// [`crate::layout::chained_fixups_min_minos`] — one table, two
    /// readers — and names the decision on the tracing seam so a debug
    /// subscriber sees every flip.
    #[must_use]
    pub fn for_target(platform: u32, minos: u32) -> Self {
        let floor = chained_fixups_min_minos(platform);
        let encoding = if minos >= floor {
            Self::ChainedFixups
        } else {
            Self::ClassicOpcodes
        };
        tracing::debug!(
            platform,
            minos,
            floor,
            ?encoding,
            "the fixup encoding decision names itself"
        );
        encoding
    }

    /// The deployment floor the decision rides on — the same word
    /// [`crate::layout::chained_fixups_min_minos`] returns, exposed for
    /// consumers that display the boundary next to the decision (the
    /// layout's own reader; never a second table).
    #[must_use]
    pub fn floor_for(platform: u32) -> u32 {
        chained_fixups_min_minos(platform)
    }
}
