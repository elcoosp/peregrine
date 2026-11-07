//! M8-c — slack-aware layout (architecture doc §10.4 row M8; §7.3
//! "layout stability").
//!
//! An incremental relink wants a changed atom to *fit where it was*. The
//! clean linker packs sections exactly; this module reserves growth room:
//! every user-content output section is padded by a policy-chosen amount
//! (a percentage of the section size clamped to `[min, max]`, aligned to
//! the section's alignment), so a modest edit relinks without moving a
//! single downstream section.
//!
//! Scope and honesty:
//!
//! * Slack is **opt-in** ([`LinkConfig::layout_slack`] stays `None` by
//!   default) — the deterministic clean-link bytes are untouched, per the
//!   §7.3 determinism policy ("clean links remain bit-deterministic,
//!   always").
//! * Padding is zero fill: the emit buffer is zero-allocated, so padded
//!   tails need no extra emit work and sign/signature hashing sees
//!   deterministic bytes.
//! * Synthetic sections (`__got`, `__stubs`, `__chain_starts`) are never
//!   padded: their sizes are contract-coupled to the fixup plan, the
//!   indirect symbol table and the `__chain_starts` mirror.
//! * The fallback ladder (`fits`) is the pure decision function the M9
//!   change-propagation planner calls when a changed atom overflows its
//!   section's slack.

use crate::layout::LinkConfig;

/// Section-growth reservation policy (M8-c).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlackPolicy {
    /// Growth room for `__TEXT` sections, percent of the section size.
    pub text_percent: u32,
    /// Growth room for `__DATA_CONST`/`__DATA` sections, percent.
    pub data_percent: u32,
    /// Lower clamp on the pad (bytes) — tiny sections still get room.
    pub min_bytes: u64,
    /// Upper clamp on the pad (bytes) — huge sections don't over-reserve.
    pub max_bytes: u64,
}

impl Default for SlackPolicy {
    fn default() -> Self {
        // §7.3 defaults: ~10% of text, ~5% of data, "tuned from real edit
        // histories" once spike S9 runs; the clamps keep pathological
        // sections (a 4-byte stub section, a 1 GiB literal pool) sane.
        Self {
            text_percent: 10,
            data_percent: 5,
            min_bytes: 4096,
            max_bytes: 1 << 20,
        }
    }
}

/// The §7.3 fallback ladder for a changed section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutFallback {
    /// The new content fits the previously padded section size: nothing
    /// downstream moves; pages are patched in place (M9).
    InPlace,
    /// The section overflowed its slack; re-lay out that segment (later
    /// sections shift, but the segment's place in the image holds).
    SegmentRelayout,
    /// Give up and run the full clean link (always available, always
    /// correct — §7.3 "the fallback must always be available").
    CleanLink,
}

impl SlackPolicy {
    /// The padded output-section size for a section whose content needs
    /// `size` bytes and aligns to `1 << align_log2`. Padding never
    /// under-fills: the returned size is at least `size`.
    #[must_use]
    pub fn pad_section(&self, segment: &str, size: u64, align_log2: u32) -> u64 {
        if !Self::is_padded_section(segment, "") || size == 0 {
            return size;
        }
        let percent = match segment {
            "__TEXT" => self.text_percent,
            _ => self.data_percent,
        };
        let pad = (size / 100)
            .saturating_mul(u64::from(percent))
            .clamp(self.min_bytes, self.max_bytes);
        let align = 1u64 << align_log2.min(31);
        (size.saturating_add(pad)).div_ceil(align) * align
    }

    /// The §7.3 fallback decision for one changed section: `prev_content`
    /// was the section's content before the edit, `prev_padded` its on-disk
    /// (padded) size, `new_content` what the edit needs now.
    ///
    /// Ladder: the section absorbed the edit → in place; the edit is small
    /// in absolute terms (within one full max-pad) → re-layout that segment;
    /// anything larger escalates to the clean link (always available,
    /// always correct).
    #[must_use]
    pub fn fits(&self, prev_content: u64, new_content: u64, prev_padded: u64) -> LayoutFallback {
        if new_content <= prev_padded || new_content <= prev_content {
            return LayoutFallback::InPlace;
        }
        let growth = new_content - prev_padded;
        if growth <= self.max_bytes {
            LayoutFallback::SegmentRelayout
        } else {
            LayoutFallback::CleanLink
        }
    }

    /// True when an output section of `segment` may carry padding. The
    /// synthetic sections' sizes are contract-coupled (fixup plan, indirect
    /// symbol table, `__chain_starts` mirror) and are excluded by name in
    /// the layout pass; this predicate is the segment-level gate.
    #[must_use]
    pub fn is_padded_section(segment: &str, _name: &str) -> bool {
        matches!(segment, "__TEXT" | "__DATA_CONST" | "__DATA")
    }
}

/// Convenience re-export so [`LinkConfig`] consumers can name the field
/// type without importing the module.
impl LinkConfig {
    /// True when the layout reserves slack (M8-c; false = v1.0 exact
    /// packing).
    #[must_use]
    pub const fn has_layout_slack(&self) -> bool {
        self.layout_slack.is_some()
    }
}
