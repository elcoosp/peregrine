//! `-dead_strip` (M5, D12 — architecture doc §10.3 row M5): mark-sweep
//! liveness over the D1 atoms.
//!
//! ld64 semantics: dead code is data-flow from *roots* — the entry point,
//! `-u` load symbols, every extern definition when the output exports
//! (dylibs/bundles), `__mod_init_func` pointer sections, and every section
//! carrying `S_ATTR_NO_DEAD_STRIP`. From the roots, the mark phase follows
//! relocation edges: an atom referenced from a live atom is live. Dead
//! atoms leave the layout entirely; the M4 copy-run coalescing then breaks
//! runs exactly at the stripped pieces (perf doc §4.3's promise).
//!
//! Granularity: objects carrying `MH_SUBSECTIONS_VIA_SYMBOLS` strip at
//! symbol-boundary atoms (D1); every other object strips at whole-section
//! granularity (one synthesized atom). `S_CSTRING_LITERALS` sections are
//! string atoms (D4), so unreferenced literals strip too.
//!
//! Cost discipline (the perf gate: dead-strip adds ≤ 30% to the link): the
//! edge graph is built in one pass per section — relocations are bucketed
//! into their atoms with a binary search, never a per-atom rescan — and
//! liveness queries are O(log atoms). The mark pass is single-threaded and
//! deterministic: the live set is a pure function of the inputs, so the
//! output is independent of `PGR_JOBS` (gated in tests).
//!
//! Undefined references from dead atoms are NOT suppressed
//! (`require_all_resolved` runs before layout, matching the M1–M4
//! semantics): dead-strip changes *what is placed*, not *what resolves*.

use crate::ids::StringId;
use crate::interner::Interner;
use crate::layout::LinkConfig;
use crate::object::{InputObject, RelocKind, RelocTarget};
use crate::resolve::{Rank, Resolution};
use pgr_format::consts::{S_ATTR_NO_DEAD_STRIP, S_MOD_INIT_FUNC_POINTERS, SECTION_TYPE_MASK};

/// The live set: per-file atom grids plus live commons. A pure function of
/// the inputs (determinism policy §4.3).
#[derive(Debug, Default)]
pub struct LiveSet {
    /// `live[file][sect][atom]`.
    live: Vec<Vec<Vec<bool>>>,
    /// `starts[file][sect][atom]` — the section-relative start of each atom
    /// index (parallel to `live`; the identity layout queries by).
    starts: Vec<Vec<Vec<u64>>>,
    /// Live common symbols (name ids).
    commons: std::collections::BTreeSet<u32>,
    /// Whether dead-strip is active (`cfg.dead_strip`).
    active: bool,
}

impl LiveSet {
    /// True when dead-strip is active and the atom starting at `atom_start`
    /// of `(file, sect)` is dead. Unknown atoms count as live — the piece
    /// builder queries atoms from the same `atoms_of` table the mark pass
    /// indexed, so a miss means the mark pass never saw it (treat as live).
    #[must_use]
    pub fn is_atom_dead(&self, file: u32, sect: usize, atom_start: u64) -> bool {
        if !self.active {
            return false;
        }
        let Some(starts) = self.starts.get(file as usize).and_then(|f| f.get(sect)) else {
            return false;
        };
        let Ok(idx) = starts.binary_search(&atom_start) else {
            return false;
        };
        !self.live[file as usize][sect][idx]
    }

    /// True when the common symbol is dead (only meaningful when active).
    #[must_use]
    pub fn is_common_dead(&self, id: StringId) -> bool {
        self.active && !self.commons.contains(&id.0)
    }

    /// True when dead-strip is active.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }
}

/// One liveness node: the atom `atom` of `(file, sect)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Node {
    file: u32,
    sect: u32,
    atom: u32,
}

/// Computes the live set (M5/D12). Runs after Pass 2's install.
#[must_use]
pub fn compute(
    objects: &[InputObject],
    res: &Resolution,
    interner: &Interner,
    cfg: &LinkConfig,
) -> LiveSet {
    if !cfg.dead_strip {
        return LiveSet::default();
    }

    // ---- node grids (identity: the materialized atoms tables) ---------------
    let mut live: Vec<Vec<Vec<bool>>> = Vec::with_capacity(objects.len());
    let mut starts: Vec<Vec<Vec<u64>>> = Vec::with_capacity(objects.len());
    for obj in objects {
        let mut f_live = Vec::with_capacity(obj.sections.len());
        let mut f_starts = Vec::with_capacity(obj.sections.len());
        for si in 0..obj.sections.len() {
            let ranges = obj.atoms_of(si);
            f_starts.push(ranges.iter().map(|r| r.start).collect());
            f_live.push(vec![false; ranges.len()]);
        }
        live.push(f_live);
        starts.push(f_starts);
    }
    // Containment with clamping: references into inter-atom padding keep the
    // preceding atom alive (conservative — never strips a target).
    let node_of = |file: u32, sect: u32, off: u64| -> Option<Node> {
        let s = starts.get(file as usize)?.get(sect as usize)?;
        if s.is_empty() {
            return None;
        }
        let idx = s.partition_point(|&start| start <= off).saturating_sub(1);
        Some(Node {
            file,
            sect,
            atom: idx as u32,
        })
    };
    let def_node = |def: &crate::resolve::Def| -> Option<Node> {
        let s = def.section?;
        node_of(def.file.0, s as u32, def.value)
    };

    // ---- in-section target offset of one relocation --------------------------
    let addend_of = |obj: &InputObject, sect_idx: usize, r: &crate::object::DecodedReloc| -> u64 {
        match r.kind {
            RelocKind::Page21 { addend } | RelocKind::PageOff12 { addend } => {
                u64::try_from(addend).unwrap_or(u64::MAX)
            }
            // The classic Mach-O inline addend lives in the slot bytes.
            RelocKind::Unsigned | RelocKind::Subtractor { .. } => {
                let at = obj.sections[sect_idx].data.start as usize + r.offset as usize;
                obj.bytes
                    .get(at..at + 8)
                    .and_then(|b| <[u8; 8]>::try_from(b).ok())
                    .map(u64::from_le_bytes)
                    .unwrap_or(u64::MAX)
            }
            _ => 0,
        }
    };

    // ---- edges: one pass per section, relocations bucketed into atoms -------
    // `edges[file][sect][atom]` = the atoms this atom's relocations reach;
    // `common_refs[file][sect][atom]` = the commons it references.
    let mut edges: Vec<Vec<Vec<Vec<Node>>>> = Vec::with_capacity(objects.len());
    let mut common_refs: Vec<Vec<Vec<Vec<u32>>>> = Vec::with_capacity(objects.len());
    for (fi, obj) in objects.iter().enumerate() {
        let mut f_edges = Vec::with_capacity(obj.sections.len());
        let mut f_commons = Vec::with_capacity(obj.sections.len());
        for (si, sect) in obj.sections.iter().enumerate() {
            let atom_count = starts[fi][si].len();
            let mut per_atom: Vec<Vec<Node>> = vec![Vec::new(); atom_count];
            let mut per_atom_commons: Vec<Vec<u32>> = vec![Vec::new(); atom_count];
            for r in &sect.relocs {
                let at = u64::from(r.offset);
                let idx = starts[fi][si]
                    .partition_point(|&s| s <= at)
                    .saturating_sub(1);
                match r.target {
                    RelocTarget::Extern(id) => {
                        if let Some(def) = res.def(id) {
                            if def.rank == Rank::Common {
                                per_atom_commons[idx].push(id.0);
                            } else if let Some(target) = def_node(def) {
                                per_atom[idx].push(target);
                            }
                        }
                    }
                    RelocTarget::Section(tsi) => {
                        let addend = addend_of(obj, si, r);
                        if let Some(target) = node_of(fi as u32, tsi as u32, addend) {
                            per_atom[idx].push(target);
                        }
                    }
                }
            }
            f_edges.push(per_atom);
            f_commons.push(per_atom_commons);
        }
        edges.push(f_edges);
        common_refs.push(f_commons);
    }

    // ---- roots ----------------------------------------------------------------
    let mut roots: Vec<Node> = Vec::new();
    let mut root_commons: Vec<u32> = Vec::new();
    {
        let mut root_name = |id: StringId| {
            if let Some(def) = res.def(id) {
                if def.rank == Rank::Common {
                    root_commons.push(id.0);
                } else if let Some(node) = def_node(def) {
                    roots.push(node);
                }
            }
        };
        if cfg.filetype.is_executable() {
            if let Some(id) = interner.lookup(cfg.entry_symbol.as_bytes()) {
                root_name(id);
            }
        } else {
            // Dylibs/bundles export their surface: every definition is a root.
            for (id, _def) in res.definitions() {
                root_name(id);
            }
        }
        for sym in &cfg.load_symbols {
            if let Some(id) = interner.lookup(sym) {
                root_name(id);
            }
        }
    }
    // `__mod_init_func` / `S_ATTR_NO_DEAD_STRIP` sections stay whole.
    for (fi, obj) in objects.iter().enumerate() {
        for (si, sect) in obj.sections.iter().enumerate() {
            let init_ptrs = sect.flags & SECTION_TYPE_MASK == S_MOD_INIT_FUNC_POINTERS;
            if init_ptrs || sect.flags & S_ATTR_NO_DEAD_STRIP != 0 {
                for atom in 0..live[fi][si].len() {
                    roots.push(Node {
                        file: fi as u32,
                        sect: si as u32,
                        atom: atom as u32,
                    });
                }
            }
        }
    }

    // ---- mark phase (worklist BFS over the pre-built edges) -------------------
    let mut commons: std::collections::BTreeSet<u32> = root_commons.into_iter().collect();
    let mut work: Vec<Node> = Vec::new();
    for node in roots {
        if let Some(slot) = live
            .get_mut(node.file as usize)
            .and_then(|f| f.get_mut(node.sect as usize))
            .and_then(|s| s.get_mut(node.atom as usize))
        {
            if !*slot {
                *slot = true;
                work.push(node);
            }
        }
    }
    while let Some(node) = work.pop() {
        let (targets, refs) = (
            &edges[node.file as usize][node.sect as usize][node.atom as usize],
            &common_refs[node.file as usize][node.sect as usize][node.atom as usize],
        );
        commons.extend(refs.iter().copied());
        for &target in targets {
            if let Some(slot) = live
                .get_mut(target.file as usize)
                .and_then(|f| f.get_mut(target.sect as usize))
                .and_then(|s| s.get_mut(target.atom as usize))
            {
                if !*slot {
                    *slot = true;
                    work.push(target);
                }
            }
        }
    }

    LiveSet {
        live,
        starts,
        commons,
        active: true,
    }
}
