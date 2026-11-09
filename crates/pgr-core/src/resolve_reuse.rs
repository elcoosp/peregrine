//! M9 tier-2c — the incremental resolve over the propagation index
//! (architecture doc §7.3 step 3; roadmap row M9 GA: "the incremental
//! resolve over the propagation index ... remains GA scope").
//!
//! The tier-2b planner scopes *bytes* (the patch planner's propagation
//! gate); this module reuses the Pass-2 *decisions*. A relink that re-ran
//! the full [`crate::resolve::Resolution::install`] rebuilt the whole
//! winner table — re-classifying and re-deciding every external symbol of
//! every input — even when the propagation scope vouched that all but a
//! few sections were untouched. The §7.3 shape instead:
//!
//! 1. **shape guard** — the recorded snapshot vouches for a file list and
//!    a dylib export surface; either moving renumbers identities the
//!    reuse path cannot re-derive, so [`plan_reuse`] refuses
//!    ([`ReuseFallback`]) and the relink resolves in full (the ladder's
//!    bottom rung);
//! 2. **seeds** — the section-digest diff (`crate::propagate::seeds`)
//!    names the changed input sections, as for the byte planner;
//! 3. **reuse** — every recorded winner whose defining symbol sits in an
//!    unchanged file is copied verbatim: the digest vouches that the
//!    symbol table is byte-identical, so the `(file, symbol)` position
//!    keys the recorded decision and the relink parse already holds the
//!    name id — no name-keyed join anywhere on the hot path;
//! 4. **re-decide** — every name the seeds touch (a recorded or fresh
//!    candidate in a seeded file) replays the full precedence rules over
//!    *all* its candidates: recorded non-seed candidates plus the seed
//!    files' fresh ones, in `(file, symbol)` order;
//! 5. **merge** — reference sites re-walk the parse (undefined externals
//!    in file order — the recorded site set is digest-vouched to equal the
//!    relink parse's own) and the dylib install + undefined policy run
//!    exactly as in the full path.
//!
//! The contract is equality: [`install_reused`]'s resolution must be
//! [`crate::resolve::Resolution::equivalent`] to the full one (gated in
//! `tests/m9_resolve_reuse.rs`, including a randomized edit walk), or the
//! plan refuses. The M9 GA rung wires the record side: the link record's
//! v5 section carries the snapshot ([`ResolveReuseSeed`]), the relink's
//! `LinkConfig` hands it to the pipeline's Pass 2 through
//! [`crate::link::link_cached`], and a refused plan falls back to the full
//! resolve — the same path tier 2b took into the patch planner.

use crate::LinkError;
use crate::ids::StringId;
use crate::interner::Interner;
use crate::object::InputObject;
use crate::propagate::seeds;
use crate::resolve::{DefLite, Dylib, Resolution, ResolutionSnapshot, UndefinedPolicy};
use std::collections::BTreeSet;

/// The recorded Pass-2 state a relink reuses through
/// `LinkConfig::resolve_reuse` (M9 GA rung — the resolve's record-side
/// wiring): the resolution snapshot (the record's **v5** section) plus the
/// parse's section-digest table (the record's **v3** section) the seeds
/// diff against. Both sections ride the same `LinkRecord` payload, so the
/// relink hands them over together; `None` (every clean link, and records
/// from before the wiring) resolves in full.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveReuseSeed {
    /// The previous link's resolution snapshot: the candidate stream and
    /// the winning decisions the reuse path copies or replays.
    pub snapshot: ResolutionSnapshot,
    /// The previous parse's section-digest table: the diff baseline the
    /// change-propagation seeds come from.
    pub digests: Vec<crate::propagate::SectionDigest>,
}

/// Why the reuse plan refused: the snapshot's vouched shape moved, and the
/// §7.3 ladder answers with the full resolve (always available, always
/// correct).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReuseFallback {
    /// The input file list moved (count or command-line names): every
    /// recorded `(file, symbol)` identity is up for renumbering.
    FileListChanged,
    /// The dylib export set moved: two-level ordinals are position-in-list
    /// assignments the recorded map cannot inherit.
    DylibSetChanged,
}

impl core::fmt::Display for ReuseFallback {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::FileListChanged => {
                write!(
                    f,
                    "input file list moved: recorded file identities no longer line up"
                )
            }
            Self::DylibSetChanged => {
                write!(
                    f,
                    "dylib export set moved: recorded ordinals cannot be inherited"
                )
            }
        }
    }
}

/// The reuse plan [`plan_reuse`] products and [`install_reused`] consumes:
/// the seeds, the names re-decided through the precedence replay (with
/// their interned ids, so the resolver never binary-searches the name
/// table), and the winner count that rides the record verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReusePlan {
    /// Changed input sections (the digest diff), ascending — the
    /// propagation seeds, byte planner and resolve reuse alike.
    pub seeds: Vec<(u32, usize)>,
    /// Names with a candidate in a seeded file (recorded or fresh),
    /// sorted and deduplicated: re-decided through the full precedence
    /// replay, never copied.
    pub redecide: Vec<Vec<u8>>,
    /// The interned ids of [`ReusePlan::redecide`], sorted — the hot-path
    /// membership set the copy walk checks per symbol.
    pub redecide_ids: Vec<u32>,
    /// Recorded winners outside the seeds: copied verbatim.
    pub reused: usize,
}

/// Plans the incremental resolve: shape-guard the recorded snapshot, diff
/// the section digests into seeds, and split the name space into
/// re-decided (seed-touched) and reused (digest-vouched) winners. A pure
/// function of the recorded state and the new parse (§4.3).
///
/// # Errors
/// [`ReuseFallback`] when the reuse shape moved — the caller falls back to
/// the full resolve.
pub fn plan_reuse(
    recorded: &ResolutionSnapshot,
    prev: &[crate::propagate::SectionDigest],
    interner: &Interner,
    objects: &[InputObject],
    dylibs: &[Dylib],
) -> Result<ReusePlan, ReuseFallback> {
    // 1. Shape guard: the snapshot's per-file identity must line up with
    //    the relink's parse exactly — a moved list renumbers FileIds and
    //    the winner slots' `(file, symbol)` keys with them.
    if recorded.file_names.len() != objects.len() {
        return Err(ReuseFallback::FileListChanged);
    }
    for (name, obj) in recorded.file_names.iter().zip(objects) {
        if name.as_slice() != obj.name.as_bytes() {
            return Err(ReuseFallback::FileListChanged);
        }
    }
    // 2. Dylib export surface: two-level ordinals inherit only when the
    //    flattened export list is byte-identical.
    let flat_exports: Vec<Vec<u8>> = dylibs
        .iter()
        .flat_map(|d| d.exports.iter().cloned())
        .collect();
    if flat_exports != recorded.dylib_export_names {
        return Err(ReuseFallback::DylibSetChanged);
    }

    // 3. Seeds: the same digest diff the byte planner runs. The resolve
    //    scope is file-granular (a seeded file's whole candidate set
    //    replays): the over-approximation costs a replay, a missed one
    //    costs a stale decision — the same trade the reverse index makes.
    let seed_sections = seeds(prev, objects);
    let seed_files: BTreeSet<u32> = seed_sections.iter().map(|(file, _)| *file).collect();

    // 4. The re-decide set: names with a recorded candidate in a seeded
    //    file (their old candidate stream is stale) plus names with a
    //    fresh candidate in a seeded file (a new challenger the recorded
    //    winners never saw).
    let redecide: Vec<Vec<u8>> = {
        let mut set: BTreeSet<Vec<u8>> = BTreeSet::new();
        for (name, cand) in &recorded.candidates {
            if seed_files.contains(&cand.file) {
                set.insert(name.clone());
            }
        }
        for obj in objects.iter().filter(|o| seed_files.contains(&o.file.0)) {
            for s in &obj.symbols {
                if s.stab || !s.external || !(s.is_defined() || s.is_common()) {
                    continue;
                }
                set.insert(interner.bytes(s.name).to_vec());
            }
        }
        set.into_iter().collect()
    };

    // 5. The reuse count: recorded winners outside the seeds whose name
    //    the re-decide set cannot touch. The slot positions are
    //    digest-vouched, so the relink parse's symbol at the same position
    //    carries the same name; the id set keeps the check on u32 compares.
    let redecide_ids: Vec<u32> = redecide
        .iter()
        .filter_map(|n| interner.lookup(n))
        .map(|id| id.0)
        .collect();
    let mut reused = 0usize;
    for (file, slots) in recorded.winner_slots.iter().enumerate() {
        if seed_files.contains(&(file as u32)) {
            continue;
        }
        let obj = &objects[file];
        for (sym, slot) in slots.iter().enumerate() {
            if slot.is_some()
                && redecide_ids
                    .binary_search(&obj.symbols[sym].name.0)
                    .is_err()
            {
                reused += 1;
            }
        }
    }

    Ok(ReusePlan {
        seeds: seed_sections,
        redecide_ids,
        redecide,
        reused,
    })
}

/// Installs the reused resolution: recorded winners ride verbatim outside
/// the seeds (O(1) per symbol through the `(file, symbol)` slot matrix),
/// seed-touched names replay the precedence rules over their complete
/// candidate stream (recorded non-seed candidates + the seed files' fresh
/// candidates, `(file, symbol)`-ordered), reference sites re-walk the
/// parse in file order, and the dylib install + undefined policy run as
/// in the full path.
///
/// # Errors
/// [`LinkError::Symbol`] when the replay reaches the duplicate-strong
/// error the full walk would reach, [`LinkError::Internal`] when a reused
/// winner's slot points outside the relink parse (an invariant break —
/// the caller falls back), or the undefined-policy error the full path
/// lands on.
pub fn install_reused(
    plan: &ReusePlan,
    recorded: &ResolutionSnapshot,
    interner: &Interner,
    objects: &[InputObject],
    dylibs: &[Dylib],
    policy: UndefinedPolicy,
) -> Result<Resolution, LinkError> {
    let seed_files: BTreeSet<u32> = plan.seeds.iter().map(|(file, _)| *file).collect();
    // The hot-path membership check runs per external symbol of every
    // unchanged file — the plan's sorted id list keeps it on u32 compares,
    // and the replay's name→id joins run through a small hot map instead
    // of the interner's byte table.
    let redecide_ids = &plan.redecide_ids;
    let mut redecide_map: Vec<(Vec<u8>, u32)> = plan
        .redecide_ids
        .iter()
        .map(|id| (interner.bytes(StringId(*id)).to_vec(), *id))
        .collect();
    redecide_map.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    let mut res = Resolution::default();

    // 1. Reuse: walk the relink parse's unchanged files; every symbol with
    //    a recorded winner in its slot carries that decision verbatim (the
    //    digest table vouches the symbol table is byte-identical, so the
    //    position keys the same definition).
    for (file, obj) in objects.iter().enumerate() {
        if seed_files.contains(&(file as u32)) {
            continue;
        }
        let Some(slots) = recorded.winner_slots.get(file) else {
            return Err(LinkError::Internal {
                message: "snapshot has no winner slots for a vouched file".into(),
            });
        };
        for (sym, s) in obj.symbols.iter().enumerate() {
            if s.stab || !s.external || !(s.is_defined() || s.is_common()) {
                continue;
            }
            let Some(Some(lite)) = slots.get(sym) else {
                continue; // a losing candidate — the replay owns this name
            };
            if redecide_ids.binary_search(&s.name.0).is_ok() {
                continue; // the seeds touched this name — re-decided below
            }
            res.copy_winner(s.name.0, lite);
        }
    }
    // 2. Re-decide: the seed-touched names replay the precedence rules
    //    over their complete candidate stream — recorded non-seed
    //    candidates plus the seed files' fresh candidates — in (file,
    //    symbol) order, exactly the order the full walk reaches them.
    let mut replay: Vec<(Vec<u8>, DefLite)> = Vec::new();
    // Candidates are name-sorted (the capture's order), so each re-decide
    // name's recorded stream is one binary-searched group — the scan
    // visits only the seeded handful, never the whole candidate list.
    for name in &plan.redecide {
        let Ok(start) = recorded
            .candidates
            .binary_search_by(|probe| probe.0.cmp(name))
        else {
            continue; // the name has no recorded candidates (fresh only)
        };
        for (group, cand) in &recorded.candidates[start..] {
            if group != name {
                break;
            }
            if !seed_files.contains(&cand.file) {
                replay.push((group.clone(), cand.clone()));
            }
        }
    }
    for obj in objects.iter().filter(|o| seed_files.contains(&o.file.0)) {
        for (i, s) in obj.symbols.iter().enumerate() {
            if s.stab || !s.external || !(s.is_defined() || s.is_common()) {
                continue;
            }
            replay.push((interner.bytes(s.name).to_vec(), DefLite::of(obj, i)));
        }
    }
    replay.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| (a.1.file, a.1.sym).cmp(&(b.1.file, b.1.sym)))
    });
    for (name, cand) in &replay {
        let Ok(idx) = redecide_map.binary_search_by(|probe| probe.0.cmp(name)) else {
            continue; // the name vanished with its seeded candidates
        };
        res.replay_candidate(redecide_map[idx].1, cand)?;
    }
    // 3. References: the recorded site set is digest-vouched to equal the
    //    relink parse's own, so re-walk the parse in file order — the
    //    walk order the full path pushes sites in.
    for obj in objects {
        for (i, s) in obj.symbols.iter().enumerate() {
            if s.stab || !s.external || s.is_defined() || s.is_common() {
                continue; // undefined references only
            }
            res.merge_reference(s.name.0, (obj.file, i));
        }
    }
    // 4. The dylib surface and the undefined policy run exactly as the
    //    full path runs them.
    let export_ids: Vec<StringId> = dylibs
        .iter()
        .flat_map(|d| d.exports.iter())
        .filter_map(|name| interner.lookup(name))
        .collect();
    res.install_dylibs(dylibs, &export_ids);
    res.require_all_resolved(interner, objects, policy)?;
    Ok(res)
}
