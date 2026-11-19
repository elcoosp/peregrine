//! `-dead_strip` (M5, D12 — architecture doc §10.3 row M5): mark-sweep
//! liveness over the D1 atoms.
//!
//! ld64 semantics: dead code is data-flow from *roots* — the entry point,
//! `-u` load symbols, every extern definition when the output exports
//! (dylibs/bundles), `__mod_init_func` pointer sections, and every section
//! carrying `S_ATTR_NO_DEAD_STRIP` (the `-no_dead_strip_inits_and_terms`
//! decision, M52, widens the same treatment to the `S_MOD_TERM_FUNC_POINTERS`
//! sections — the termination routines never strip under the named flag).
//! From the roots, the mark phase follows
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
use pgr_format::consts::{
    S_ATTR_NO_DEAD_STRIP, S_MOD_INIT_FUNC_POINTERS, S_MOD_TERM_FUNC_POINTERS, SECTION_TYPE_MASK,
};

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
    /// `why[file][sect][atom]` — the first way the atom went live (M92,
    /// the liveness query's record). Extracted through
    /// [`LiveSet::take_liveness`] once the mark finished; the passes
    /// that consume the live set never read it.
    why: Vec<Vec<Vec<Option<LiveWhy>>>>,
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

    /// Extracts the M92 why-record (the mark's first-marker table) into
    /// the queryable [`LivenessIndex`]: `Some` exactly when the strip
    /// ran (an inactive mark recorded nothing — there is no strip to
    /// explain). The extraction moves the record out of the live set
    /// (`std::mem::take`); the passes that consume the live set
    /// afterwards never read it, and the layout is planned after the
    /// extraction — the plan and the record cannot disagree.
    pub(crate) fn take_liveness(&mut self) -> Option<LivenessIndex> {
        if !self.active {
            self.why = Vec::new();
            return None;
        }
        Some(LivenessIndex {
            why: std::mem::take(&mut self.why),
            active: true,
        })
    }
}

/// One liveness node: the atom `atom` of `(file, sect)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Node {
    pub(crate) file: u32,
    pub(crate) sect: u32,
    pub(crate) atom: u32,
}

/// One edge the mark follows: the atom's relocation reaches `target`
/// through the relocation at `site` (the M8-a `RefSite` shape), naming
/// `via` when the relocation targeted an external symbol (a
/// section-targeted relocation names nothing — the target's own
/// definition is the name the walk renders). Recorded beside the target
/// on its first mark — the liveness query's hop (`crate::why_live`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Edge {
    target: Node,
    via: Option<StringId>,
    site: crate::revindex::RefSite,
}

/// Why an atom went live (M92): the root that named it, or the first
/// reference the mark followed to it. One record per atom — the first
/// marker wins (the worklist's own order, deterministic per §4.3), and
/// the walk reads exactly the chain the strip believes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LiveWhy {
    /// A root: `kind` names the decision that kept the atom whole,
    /// `via` the symbol that named it (the entry symbol, the `-u` mark,
    /// the alias's definition — `None` for the whole-section roots,
    /// which name no symbol).
    Root {
        kind: LiveRootKind,
        via: Option<StringId>,
    },
    /// A reference: `from` is the live atom whose relocation reached
    /// this one (the chain's next hop), `via` the referenced symbol
    /// (`None` for a section-targeted relocation), `site` the
    /// relocation's `(file, section, offset)`.
    ReferencedBy {
        from: Node,
        via: Option<StringId>,
        site: crate::revindex::RefSite,
    },
}

/// The decision that rooted an atom (the M5 root set, named per
/// decision — the query's last line names one of these).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveRootKind {
    /// The executable's entry symbol (`-e`, the `_main` default).
    Entry,
    /// The dylib/bundle export surface: every definition is a root.
    ExportedSurface,
    /// A `-u` load symbol.
    LoadSymbol,
    /// An `-alias` definition (the aliased body ships, M24).
    Alias,
    /// `-export_dynamic` (M46): every global definition in the main
    /// executable is a root.
    ExportDynamic,
    /// An `S_MOD_INIT_FUNC_POINTERS` section (the initializer
    /// routines never strip).
    InitSection,
    /// An `S_MOD_TERM_FUNC_POINTERS` section kept whole by
    /// `-no_dead_strip_inits_and_terms` (M52).
    TermSection,
    /// A section carrying `S_ATTR_NO_DEAD_STRIP`.
    NoDeadStripSection,
    /// The compact-unwind table's personality/LSDA anchor (M34).
    UnwindAnchor,
}

/// The mark phase's why-record, extracted from the
/// [`LiveSet`] once the mark finished (M92):
/// the liveness query (`crate::why_live`) walks it from a queried
/// definition back to its root. `Some` exactly when the strip ran —
/// a link without `-dead_strip` has no strip to explain — and the
/// record never feeds a pass: the layout is planned before the
/// extraction, the plan and the record cannot disagree.
#[derive(Debug, Default)]
pub struct LivenessIndex {
    /// `why[file][sect][atom]` — the first way the atom went live.
    why: Vec<Vec<Vec<Option<LiveWhy>>>>,
    /// The strip ran (mirrors `LiveSet::active`).
    active: bool,
}

impl LivenessIndex {
    /// True when the strip ran (the record's premise).
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// The recorded reason `(file, sect)`'s atom `atom` went live, if
    /// the mark saw it (an unknown atom was never marked — the query
    /// reads the verdict off the grid's miss).
    #[must_use]
    pub(crate) fn node_why(&self, file: u32, sect: usize, atom: usize) -> Option<&LiveWhy> {
        self.why
            .get(file as usize)
            .and_then(|f| f.get(sect))
            .and_then(|s| s.get(atom))
            .and_then(|w| w.as_ref())
    }
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
    let mut why: Vec<Vec<Vec<Option<LiveWhy>>>> = Vec::with_capacity(objects.len());
    for obj in objects {
        let mut f_live = Vec::with_capacity(obj.sections.len());
        let mut f_starts = Vec::with_capacity(obj.sections.len());
        let mut f_why = Vec::with_capacity(obj.sections.len());
        for si in 0..obj.sections.len() {
            let ranges = obj.atoms_of(si);
            f_starts.push(ranges.iter().map(|r| r.start).collect());
            f_live.push(vec![false; ranges.len()]);
            f_why.push(vec![None; ranges.len()]);
        }
        live.push(f_live);
        starts.push(f_starts);
        why.push(f_why);
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
                    .map_or(u64::MAX, u64::from_le_bytes)
            }
            _ => 0,
        }
    };

    // ---- edges: one pass per section, relocations bucketed into atoms -------
    // `edges[file][sect][atom]` = the atoms this atom's relocations reach
    // (each edge carrying the relocation site and the referenced name —
    // the M92 why-record's hop); `common_refs[file][sect][atom]` = the
    // commons it references.
    let mut edges: Vec<Vec<Vec<Vec<Edge>>>> = Vec::with_capacity(objects.len());
    let mut common_refs: Vec<Vec<Vec<Vec<u32>>>> = Vec::with_capacity(objects.len());
    for (fi, obj) in objects.iter().enumerate() {
        let mut f_edges = Vec::with_capacity(obj.sections.len());
        let mut f_commons = Vec::with_capacity(obj.sections.len());
        for (si, sect) in obj.sections.iter().enumerate() {
            let atom_count = starts[fi][si].len();
            let mut per_atom: Vec<Vec<Edge>> = vec![Vec::new(); atom_count];
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
                                per_atom[idx].push(Edge {
                                    target,
                                    via: Some(id),
                                    site: crate::revindex::RefSite {
                                        file: obj.file,
                                        in_sect: si,
                                        offset: u64::from(r.offset),
                                    },
                                });
                            }
                        }
                    }
                    RelocTarget::Section(tsi) => {
                        let addend = addend_of(obj, si, r);
                        if let Some(target) = node_of(fi as u32, tsi as u32, addend) {
                            per_atom[idx].push(Edge {
                                target,
                                via: None,
                                site: crate::revindex::RefSite {
                                    file: obj.file,
                                    in_sect: si,
                                    offset: u64::from(r.offset),
                                },
                            });
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
    // M92: each root carries the decision that named it (the
    // `LiveRootKind` the query's last line renders) and, where the
    // decision names a symbol, the symbol itself.
    let mut roots: Vec<(Node, LiveWhy)> = Vec::new();
    let mut root_commons: Vec<u32> = Vec::new();
    {
        let mut root_name = |id: StringId, kind: LiveRootKind| {
            if let Some(def) = res.def(id) {
                if def.rank == Rank::Common {
                    root_commons.push(id.0);
                } else if let Some(node) = def_node(def) {
                    roots.push((
                        node,
                        LiveWhy::Root {
                            kind,
                            via: Some(id),
                        },
                    ));
                }
            }
        };
        if cfg.filetype.is_executable() {
            if let Some(id) = interner.lookup(cfg.entry_symbol.as_bytes()) {
                root_name(id, LiveRootKind::Entry);
            }
        } else {
            // Dylibs/bundles export their surface: every definition is a root.
            for (id, _def) in res.definitions() {
                root_name(id, LiveRootKind::ExportedSurface);
            }
        }
        for sym in &cfg.load_symbols {
            if let Some(id) = interner.lookup(sym) {
                root_name(id, LiveRootKind::LoadSymbol);
            }
        }
        // M24: an alias names the definition in the image's export
        // surface — the definition is a root even when nothing else
        // references it (the ld64 shape: the aliased name keeps
        // resolving, so the body must ship).
        for alias in &cfg.aliases {
            if let Some(id) = interner.lookup(alias.definition().as_bytes()) {
                root_name(id, LiveRootKind::Alias);
            }
        }
        // M46: `-export_dynamic` — every global definition in the main
        // executable is a root (ld64's man page: "Preserves all global
        // symbols in main executables during dead stripping"). The
        // `dlsym`/plugin surface is a runtime contract the static
        // fixpoint cannot see; the decision is executable-only (a
        // dylib's and a bundle's strip already roots every definition,
        // the refusals keep the knob honest) and the default (`false`)
        // widens nothing.
        if cfg.export_dynamic && cfg.filetype.is_executable() {
            for (id, _def) in res.definitions() {
                root_name(id, LiveRootKind::ExportDynamic);
            }
        }
    }
    // `__mod_init_func` / `S_ATTR_NO_DEAD_STRIP` sections stay whole.
    // M52: `-no_dead_strip_inits_and_terms` widens the same
    // whole-section root treatment to the termination-pointer sections —
    // ld64's "The linker never dead strips initialization and
    // termination routines"; the init half has been the house default
    // since M5, the term half joins on the named decision, and the
    // default keeps every pre-M52 link byte-identical.
    for (fi, obj) in objects.iter().enumerate() {
        for (si, sect) in obj.sections.iter().enumerate() {
            let init_ptrs = sect.flags & SECTION_TYPE_MASK == S_MOD_INIT_FUNC_POINTERS;
            let term_ptrs = sect.flags & SECTION_TYPE_MASK == S_MOD_TERM_FUNC_POINTERS;
            if init_ptrs
                || (cfg.no_dead_strip_inits_and_terms && term_ptrs)
                || sect.flags & S_ATTR_NO_DEAD_STRIP != 0
            {
                let kind = if init_ptrs {
                    LiveRootKind::InitSection
                } else if term_ptrs {
                    LiveRootKind::TermSection
                } else {
                    LiveRootKind::NoDeadStripSection
                };
                for atom in 0..live[fi][si].len() {
                    roots.push((
                        Node {
                            file: fi as u32,
                            sect: si as u32,
                            atom: atom as u32,
                        },
                        LiveWhy::Root { kind, via: None },
                    ));
                }
            }
        }
    }
    // M34: the compact-unwind table's personality and LSDA references
    // keep their targets alive (ld64 semantics — the section names
    // functions the unwinder calls and data the exception tables read;
    // a stripped target would leave the section pointing at bytes the
    // image dropped). The annotated functions themselves are NOT roots
    // — a dead function's row drops with its placement, the same
    // shape the M30 dice carriage rides.
    for (fi, obj) in objects.iter().enumerate() {
        for e in &obj.compact_unwind {
            for value in [e.personality, e.lsda] {
                if value == 0 {
                    continue;
                }
                for (si, sect) in obj.sections.iter().enumerate() {
                    if sect.segment == "__TEXT"
                        && sect.size > 0
                        && sect.addr <= value
                        && value < sect.addr + sect.size
                        && let Some(node) = node_of(fi as u32, si as u32, value - sect.addr)
                    {
                        roots.push((
                            node,
                            LiveWhy::Root {
                                kind: LiveRootKind::UnwindAnchor,
                                via: None,
                            },
                        ));
                    }
                }
            }
        }
    }

    // ---- mark phase (worklist BFS over the pre-built edges) -------------------
    // M92: the first way an atom goes live is recorded beside the mark —
    // the root's decision, or the reference (referrer, referenced name,
    // site) that reached it first. The worklist's own order picks the
    // first marker (deterministic per §4.3); the record never feeds a
    // pass, the liveness decision it documents is the pass's own.
    let mut commons: std::collections::BTreeSet<u32> = root_commons.into_iter().collect();
    let mut work: Vec<Node> = Vec::new();
    for (node, reason) in roots {
        if let Some(slot) = live
            .get_mut(node.file as usize)
            .and_then(|f| f.get_mut(node.sect as usize))
            .and_then(|s| s.get_mut(node.atom as usize))
        {
            if !*slot {
                *slot = true;
                if let Some(why_slot) = why
                    .get_mut(node.file as usize)
                    .and_then(|f| f.get_mut(node.sect as usize))
                    .and_then(|s| s.get_mut(node.atom as usize))
                {
                    *why_slot = Some(reason);
                }
                work.push(node);
            }
        }
    }
    while let Some(node) = work.pop() {
        let (outgoing, common_syms) = (
            &edges[node.file as usize][node.sect as usize][node.atom as usize],
            &common_refs[node.file as usize][node.sect as usize][node.atom as usize],
        );
        commons.extend(common_syms.iter().copied());
        for edge in outgoing {
            if let Some(slot) = live
                .get_mut(edge.target.file as usize)
                .and_then(|f| f.get_mut(edge.target.sect as usize))
                .and_then(|s| s.get_mut(edge.target.atom as usize))
            {
                if !*slot {
                    *slot = true;
                    if let Some(why_slot) = why
                        .get_mut(edge.target.file as usize)
                        .and_then(|f| f.get_mut(edge.target.sect as usize))
                        .and_then(|s| s.get_mut(edge.target.atom as usize))
                    {
                        *why_slot = Some(LiveWhy::ReferencedBy {
                            from: node,
                            via: edge.via,
                            site: edge.site,
                        });
                    }
                    work.push(edge.target);
                }
            }
        }
    }

    LiveSet {
        live,
        starts,
        commons,
        active: true,
        why,
    }
}
