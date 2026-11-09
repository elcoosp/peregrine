//! M9 tier-2b — the per-symbol change-propagation planner (architecture
//! doc §7.3 step 3; roadmap row M9 GA "per-symbol change propagation, the
//! reverse-index tier"). The tier-1 patch planner diffs *bytes* (span
//! digests); this module supplies the missing *semantic* half: which
//! output bytes a changed parse is *allowed* to move.
//!
//! The pipeline (§7.3 steps 1–3, decision core only — the incremental
//! resolve itself stays GA scope):
//!
//! 1. **seeds** — [`section_digests`] hashes every input section of the
//!    linked parse; the relink diffs the recorded table against the new
//!    parse's. A section whose digest moved (or appeared/vanished) is a
//!    seed: *something* the previous record cannot vouch for changed in
//!    that input section.
//! 2. **dependents** — every external symbol defined in a seed section
//!    walks the M8-a [`ReverseIndex`] (built `build_all`: the
//!    over-approximation is deliberate — a stale prediction costs one
//!    full-link fallback, a missed dependent costs a stale byte). Each
//!    referencing site lands in an output piece; the piece's file range
//!    predicts.
//! 3. **scope** — the seed sections' own placements plus the dependents'
//!    placements, merged into sorted output-file ranges
//!    ([`PropagationScope::ranges`]). The patch planner's propagation gate
//!    checks every dirty content tile against them; a tile no range covers
//!    is a change the parse cannot explain (the stale-record shape) and
//!    falls back to the full link instead of patching blind.
//!
//! Determinism (§4.3): seeds, sites and ranges are collected in
//! command-line file order, section order and relocation order, then
//! total-ordered — the scope is a pure function of the inputs, parallel
//! schedules change nothing.

use crate::layout::Layout;
use crate::object::InputObject;
use crate::revindex::ReverseIndex;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

/// One input section's change-detection digest, keyed by `(file,
/// section)` — the record's table (M9 tier 2b). Files are command-line
/// order ([`crate::ids::FileId`]); sections are parse order. The digest
/// covers the section's **content bytes plus its symbol records** (name,
/// value, flag bits — the §7.3 "diff atom sets" step at section
/// granularity): a moved definition retargets its dependents' patch
/// values without moving a byte, so the seeds must see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionDigest {
    /// Owning input file (command-line order).
    pub file: u32,
    /// Input section index within the file.
    pub in_sect: usize,
    /// SHA-256 over the section's framed `(content | symbols)` state
    /// (zerofill sections frame the empty content — they contribute no
    /// file bytes).
    pub sha: [u8; 32],
}

/// The propagation planner's product: what a changed parse is *allowed* to
/// move in the output. `seeds` names the changed input sections; `ranges`
/// is the sorted union of the seeds' own placements and their dependents'
/// (the reverse-index closure) as output file ranges.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PropagationScope {
    /// Changed input sections as `(file, in_sect)`, ascending.
    pub seeds: Vec<(u32, usize)>,
    /// Predicted dirty output ranges (file offsets), ascending, possibly
    /// overlapping — every placed piece the closure reached contributes
    /// its whole piece range.
    pub ranges: Vec<Range<u64>>,
}

/// Hashes every input section of the linked parse: one [`SectionDigest`]
/// per `(file, section)`, in parse order (already total-ordered). The
/// digest frames the section's content bytes and every symbol it owns —
/// content and atom-set changes both move it.
#[must_use]
pub fn section_digests(objects: &[InputObject]) -> Vec<SectionDigest> {
    objects
        .iter()
        .flat_map(|obj| {
            obj.sections.iter().enumerate().map(move |(in_sect, sect)| {
                let mut h = Sha256::new();
                h.update(sect.bytes(&obj.bytes));
                // The section's symbol records in parse order: name, value
                // and the flag bits resolution and dead-strip read.
                for (i, s) in obj.symbols.iter().enumerate() {
                    if s.section != Some(in_sect) {
                        continue;
                    }
                    let name = obj
                        .peek_symbol_names()
                        .get(i)
                        .map_or(&[][..], Vec::as_slice);
                    h.update((name.len() as u64).to_le_bytes());
                    h.update(name);
                    h.update(s.value.to_le_bytes());
                    h.update([
                        u8::from(s.external),
                        u8::from(s.stab),
                        u8::from(s.weak_def),
                        u8::from(s.weak_ref),
                        u8::from(s.alt_entry),
                    ]);
                }
                SectionDigest {
                    file: obj.file.0,
                    in_sect,
                    sha: h.finalize().into(),
                }
            })
        })
        .collect()
}

/// Diffs the recorded digest table against the new parse: every section
/// whose digest moved (or appeared/vanished), ascending — the §7.3 step-1
/// seeds. The byte planner and the M9 tier-2c resolve reuse share the
/// same seed computation: one notion of "changed", two consumers.
#[must_use]
pub fn seeds(prev: &[SectionDigest], objects: &[InputObject]) -> Vec<(u32, usize)> {
    // The recorded table keyed by placement; the new parse digested the
    // same way so the diff is a plain map walk (deterministic, no hashes).
    let recorded: BTreeMap<(u32, usize), &[u8; 32]> =
        prev.iter().map(|d| ((d.file, d.in_sect), &d.sha)).collect();
    let current = section_digests(objects);

    let mut out: Vec<(u32, usize)> = Vec::new();
    for d in &current {
        match recorded.get(&(d.file, d.in_sect)) {
            Some(prev_sha) if **prev_sha == d.sha => {}
            _ => out.push((d.file, d.in_sect)),
        }
    }
    // Sections that vanished from the parse (removed inputs/sections) are
    // seeds too — the record vouches for bytes that no longer exist.
    for &key in recorded.keys() {
        let exists = current.iter().any(|d| (d.file, d.in_sect) == key);
        if !exists {
            out.push(key);
        }
    }
    out.sort_unstable();
    out
}

/// Plans the change-propagation scope: seeds = the recorded digests' diff
/// against the new parse, dependents = the reverse index's referencing
/// sites, ranges = their placed output pieces. With no seeds the scope is
/// empty (an unchanged parse predicts nothing — the untouched relink's
/// contract).
#[must_use]
pub fn predict(
    prev: &[SectionDigest],
    objects: &[InputObject],
    layout: &Layout,
) -> PropagationScope {
    let seeds = seeds(prev, objects);
    if seeds.is_empty() {
        return PropagationScope::default();
    }

    // The over-approximating reverse index (no liveness filter): every
    // external reference site of every changed definition predicts, dead
    // or alive — the gate's cost of a wrong prediction is one fallback,
    // the cost of a missed one is a stale byte.
    let index = ReverseIndex::build_all(objects);

    // Placed output pieces indexed by `(file, in_sect)` — the lookup the
    // closure walks sites through — plus, per seed input section, the
    // **containing output section's extent**: a seed piece that grows
    // inside its reserved slack shifts every sibling piece behind it in
    // the same output section (§7.3 layout stability — the anchored
    // section holds, its internal piece layout re-packs), so the scope
    // must vouch for the whole section, not just the seed piece.
    let mut pieces: BTreeMap<(u32, usize), Vec<Range<u64>>> = BTreeMap::new();
    let mut containers: BTreeMap<(u32, usize), Vec<Range<u64>>> = BTreeMap::new();
    for sect in &layout.sections {
        let extent = sect.file_off..sect.file_off + sect.size;
        for piece in &sect.pieces {
            let start = sect.file_off + piece.offset;
            pieces
                .entry((piece.file.0, piece.in_sect))
                .or_default()
                .push(start..start + piece.size);
            containers
                .entry((piece.file.0, piece.in_sect))
                .or_default()
                .push(extent.clone());
        }
    }

    let mut ranges: Vec<Range<u64>> = Vec::new();
    // Defined externals indexed by their owning `(file, in_sect)` — one
    // pass over the parse, O(1) per seed.
    let mut defined: BTreeMap<(u32, usize), BTreeSet<crate::ids::StringId>> = BTreeMap::new();
    for obj in objects {
        for symbol in &obj.symbols {
            if symbol.external
                && !symbol.stab
                && let Some(in_sect) = symbol.section
            {
                defined
                    .entry((obj.file.0, in_sect))
                    .or_default()
                    .insert(symbol.name);
            }
        }
    }
    for (file, in_sect) in &seeds {
        // The seed's own placement plus its containing output section's
        // extent (the shifted siblings ride along).
        if let Some(own) = containers.get(&(*file, *in_sect)) {
            ranges.extend(own.iter().cloned());
        }
        if let Some(own) = pieces.get(&(*file, *in_sect)) {
            ranges.extend(own.iter().cloned());
        }
        // Dependents: every external symbol defined in the seed section,
        // every site that references it, its owning piece.
        for name in defined.get(&(*file, *in_sect)).into_iter().flatten() {
            for site in index.sites(*name) {
                if let Some(dep) = pieces.get(&(site.file.0, site.in_sect)) {
                    // Conservative at piece granularity: the site's piece
                    // range covers every relocation the piece carries,
                    // not just the site's own bytes.
                    ranges.extend(dep.iter().cloned());
                }
            }
        }
    }
    ranges.sort_unstable_by_key(|r| (r.start, r.end));
    ranges.dedup();
    PropagationScope { seeds, ranges }
}
