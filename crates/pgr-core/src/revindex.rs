//! M8-a — the reverse reference index (architecture doc §10.4 row M8,
//! built at full links per §7.3 step 3).
//!
//! Change propagation (§7.3) needs the *dependents* of a symbol: when a
//! symbol's owner changes in an incremental relink, every relocation that
//! references it must be reapplied. This index records, for every interned
//! symbol, the `(file, input section, relocation offset)` sites that point
//! at it — built in one pass over the parsed objects, before layout, and
//! reusable across links inside the resident server.
//!
//! Determinism: sites are collected in file order, section order, then
//! relocation order and deduplicated through a total-ordered sort, so the
//! index is a pure function of the inputs (§4.3) — the parallel passes may
//! build it concurrently without changing a single byte of it.
//!
//! Memory shape: one `BTreeMap<u32, Vec<RefSite>>` keyed by name id. Queries
//! are O(log n) + a slice read; the M9 patch planner walks the slice to find
//! every dependent atom of a changed definition.

use crate::deadstrip::LiveSet;
use crate::ids::{FileId, StringId};
use crate::object::{InputObject, RelocTarget};
use std::collections::BTreeMap;

/// One reference site: the relocation at `offset` within `(file, in_sect)`
/// targets an external symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RefSite {
    /// Owning input file (command-line order).
    pub file: FileId,
    /// Input section index within the file.
    pub in_sect: usize,
    /// Relocation offset within the input section.
    pub offset: u64,
}

/// Symbol → referencing sites (M8-a). Built over parsed objects; sites are
/// sorted and deduplicated.
#[derive(Debug, Default, Clone)]
pub struct ReverseIndex {
    sites: BTreeMap<u32, Vec<RefSite>>,
    total: usize,
}

impl ReverseIndex {
    /// Builds the index over every external relocation in every input
    /// section (no liveness filtering).
    #[must_use]
    pub fn build_all(objects: &[InputObject]) -> Self {
        Self::build_impl(objects, None)
    }

    /// [`ReverseIndex::build_all`] with the M5 live set active: references
    /// from dead atoms are dropped — they contribute no relocations after
    /// dead-strip and no dependents in an incremental patch plan.
    #[must_use]
    pub fn build(objects: &[InputObject], live: &LiveSet) -> Self {
        Self::build_impl(objects, Some(live))
    }

    fn build_impl(objects: &[InputObject], live: Option<&LiveSet>) -> Self {
        let mut sites: BTreeMap<u32, Vec<RefSite>> = BTreeMap::new();
        for obj in objects {
            for (si, sect) in obj.sections.iter().enumerate() {
                for r in &sect.relocs {
                    let RelocTarget::Extern(id) = r.target else {
                        continue;
                    };
                    if let Some(live) = live {
                        let ranges = obj.atoms_of(si);
                        if !ranges.is_empty() {
                            let idx = ranges
                                .partition_point(|range| range.start <= u64::from(r.offset))
                                .saturating_sub(1);
                            if live.is_atom_dead(obj.file.0, si, ranges[idx].start) {
                                continue;
                            }
                        }
                    }
                    sites.entry(id.0).or_default().push(RefSite {
                        file: obj.file,
                        in_sect: si,
                        offset: u64::from(r.offset),
                    });
                }
            }
        }
        let mut total = 0usize;
        for list in sites.values_mut() {
            // Dedup (a symbol can be referenced by several reloc fields of
            // one site record after pair resolution) and total-order the
            // list: the index never depends on collection order.
            list.sort_unstable();
            list.dedup();
            total += list.len();
        }
        Self { sites, total }
    }

    /// Every recorded site referencing `id`, ascending.
    #[must_use]
    pub fn sites(&self, id: StringId) -> &[RefSite] {
        self.sites.get(&id.0).map_or(&[], Vec::as_slice)
    }

    /// The referenced symbols, ascending by name id.
    pub fn referenced_symbols(&self) -> impl Iterator<Item = StringId> + '_ {
        self.sites.keys().map(|k| StringId(*k))
    }

    /// Number of distinct referenced symbols.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sites.len()
    }

    /// True when no symbol is referenced.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sites.is_empty()
    }

    /// Total reference sites across all symbols.
    #[must_use]
    pub const fn total_sites(&self) -> usize {
        self.total
    }
}
