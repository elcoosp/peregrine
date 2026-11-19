//! M92 — the liveness-provenance query (`-why_live <symbol>`): ld64's
//! flag — previously unknown on the surface — is the M5 mark-sweep's own
//! decision made nameable, the third provenance face beside
//! `-why_export` (M56) and `-why_load` (M57): *why is this symbol still
//! live under `-dead_strip`?*
//!
//! The mark phase records, from data it already had, the first way each
//! atom went live — the root that named it (the entry point, the
//! export surface, `-u`, an alias, `__mod_init_func`, a `no_dead_strip`
//! section, the unwind anchors) or the reference that reached it first
//! (the referrer atom, the referenced name, the relocation site) — and
//! carries the record out on [`crate::LinkResult::liveness`] as a
//! [`LivenessIndex`]. The query walks that record from the queried
//! definition back to its root: one keeper per hop, in the walk's own
//! order, terminated by the root decision. The seam is read-only — the
//! record never feeds a pass (the layout is planned after the
//! extraction) and the query re-derives nothing beyond the name-to-atom
//! containment the piece builder's own atom tables answer — so a
//! queried link plans the identical layout (the parity gate is the
//! seam's own contract, `tests/m92_why_live.rs`).
//!
//! The verdicts are honest at both ends: an unreferenced definition
//! answers `Dead` (the strip drops it — the verdict is the answer, not
//! an error), and the refusals name their premise — a name nothing
//! interned (the M56 misspelling convention), a name that binds against
//! a dylib export (no link-time atom to walk), a link that never
//! carried `-dead_strip` (no strip to explain; a vacuous answer is
//! never silently empty).
//!
//! The interchange face follows the M55 convention: the `render_json`
//! method is the deterministic compact writer (fixed key order, one
//! line, the report-JSON escape rules), `render` the diffable text
//! face — a build system ships the chains to any JSON tooling without
//! a custom parser.

use crate::deadstrip::{LiveWhy, LivenessIndex};
use crate::ids::StringId;
use crate::interner::Interner;
use crate::object::InputObject;
use crate::provenance::{DefinitionSource, definition_source, definition_source_json};
use crate::resolve::Resolution;
use std::collections::BTreeMap;

// `LiveRootKind` rides this module's public surface beside the verdict
// that carries it (the query's last line names one of these).
pub use crate::deadstrip::LiveRootKind;

/// The liveness verdict for the queried name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveVerdict {
    /// The strip keeps it: `chain` names the keepers, walk order (the
    /// queried atom's keeper first, the root's referrer last) and `root`
    /// the decision that rooted the topmost atom.
    Live {
        /// One hop per keeper: the atom whose first reference (or root
        /// decision) kept the previous hop alive. Empty when the
        /// queried definition is itself a root.
        chain: Vec<LiveWhyStep>,
        /// The decision that rooted the chain's topmost atom.
        root: LiveRootKind,
    },
    /// The strip drops it: nothing references the definition
    /// (transitively) from a root — the honest answer to *why is this
    /// live?* is that it isn't.
    Dead,
}

/// One hop of a live chain: the atom whose first reference kept the
/// previous hop alive, named through the arena the link already parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveWhyStep {
    /// The referencing atom's defining symbol (`None` for an atom no
    /// external definition names — a section-local keeper).
    pub referrer_symbol: Option<String>,
    /// The name the reference used (`None` for a section-targeted
    /// relocation — the target's own definition is the referenced name).
    pub via: Option<String>,
    /// The referencing file's name.
    pub file: String,
    /// The referencing input section's `(segment, name)`.
    pub section: (String, String),
    /// The relocation's offset within the input section.
    pub offset: u64,
}

/// Why the queried name is live under the strip: the definition the
/// resolution installed and the chain that keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhyLiveExplanation {
    /// The queried name (with the C underscore, verbatim).
    pub name: String,
    /// The definition the Pass-2 resolution installed (the M56 shape).
    pub definition: DefinitionSource,
    /// The verdict: the chain that keeps it, or the strip's drop.
    pub verdict: LiveVerdict,
}

/// The query's refusals: the vacuous decision named (the house
/// convention — a misspelling or a premise mismatch is never silently
/// empty).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WhyLiveError {
    /// The queried name nothing interned — no input defines it and no
    /// input references it.
    #[error(
        "why_live {name}: no input defines or references it — check the spelling \
         (C symbols carry the leading underscore)"
    )]
    UnknownSymbol {
        /// The refused name, verbatim.
        name: String,
    },
    /// The link never carried `-dead_strip`: every definition rode, no
    /// chain exists to name. The premise is the fix.
    #[error(
        "why_live {name}: the link did not carry -dead_strip — every definition rode, \
         so there is no liveness chain to name (add -dead_strip to make the question real)"
    )]
    NotStripped {
        /// The queried name, verbatim.
        name: String,
    },
    /// The name resolves, but no link-time atom carries it: a dylib
    /// export serves the bind (the two-level namespace's provider) or a
    /// link-time common owns the bytes — the strip never kept or
    /// dropped an atom of it, so no chain exists to walk.
    #[error(
        "why_live {name}: no in-image definition walks — the name binds against a \
         dylib export or a link-time common, nothing the strip kept or dropped"
    )]
    NotDefinedHere {
        /// The queried name, verbatim.
        name: String,
    },
}

/// Answers *why is this symbol live under `-dead_strip`?* over a
/// completed link's products: the mark phase's why-record
/// ([`crate::LinkResult::liveness`]), the parsed arena, the Pass-2
/// resolution and the interner (`LinkResult` carries all of them).
///
/// # Errors
/// [`WhyLiveError::UnknownSymbol`] when nothing interned the name (the
/// misspelling is named, the C-underscore hint is the fix),
/// [`WhyLiveError::NotStripped`] when the link never carried
/// `-dead_strip`, and [`WhyLiveError::NotDefinedHere`] when the name
/// resolves against a dylib export or a link-time common (no
/// link-time atom to walk).
pub fn explain_live(
    index: &LivenessIndex,
    objects: &[InputObject],
    res: &Resolution,
    interner: &Interner,
    name: &str,
) -> Result<WhyLiveExplanation, WhyLiveError> {
    let Some(id) = interner.lookup(name.as_bytes()) else {
        return Err(WhyLiveError::UnknownSymbol {
            name: name.to_string(),
        });
    };
    let definition = definition_source(id, objects, res);
    if !index.is_active() {
        return Err(WhyLiveError::NotStripped {
            name: name.to_string(),
        });
    }
    let Some(node) = definition_node(id, objects, res) else {
        return Err(WhyLiveError::NotDefinedHere {
            name: name.to_string(),
        });
    };
    // The keeper's name, per node: the arena's own atom tables answer
    // the containment (the piece builder queries the same ranges), the
    // resolution's definition map names the winners — first name wins
    // on a shared atom (the iteration is the map's own id order,
    // deterministic per §4.3).
    let mut names: BTreeMap<(u32, usize, usize), StringId> = BTreeMap::new();
    for (def_id, _) in res.definitions() {
        if let Some(node) = definition_node(def_id, objects, res) {
            names.entry(node).or_insert(def_id);
        }
    }
    let mut chain: Vec<LiveWhyStep> = Vec::new();
    let mut cursor = node;
    let mut root: Option<LiveRootKind> = None;
    loop {
        match index.node_why(cursor.0, cursor.1, cursor.2) {
            Some(LiveWhy::Root { kind, .. }) => {
                root = Some(*kind);
                break;
            }
            Some(LiveWhy::ReferencedBy { from, via, site }) => {
                let (file, section) = objects.get(site.file.0 as usize).map_or_else(
                    || ("<unknown>".to_string(), ("?".to_string(), "?".to_string())),
                    |obj| {
                        let sect = obj.sections.get(site.in_sect).map_or_else(
                            || ("?".to_string(), "?".to_string()),
                            |s| (s.segment.clone(), s.name.clone()),
                        );
                        (obj.name.clone(), sect)
                    },
                );
                chain.push(LiveWhyStep {
                    referrer_symbol: names
                        .get(&(from.file, from.sect as usize, from.atom as usize))
                        .map(|id| interner.name(*id)),
                    via: via.as_ref().map(|id| interner.name(*id)),
                    file,
                    section,
                    offset: site.offset,
                });
                cursor = (from.file, from.sect as usize, from.atom as usize);
            }
            // Unreachable on a completed link (every live atom carries a
            // record; the parents strictly precede the marked, so the
            // walk cannot cycle) — the honest fallback is the verdict
            // the grid's miss states.
            None => break,
        }
    }
    let verdict = match root {
        Some(kind) => LiveVerdict::Live { chain, root: kind },
        None => LiveVerdict::Dead,
    };
    tracing::debug!(
        symbol = %name,
        hops = match &verdict {
            LiveVerdict::Live { chain, .. } => chain.len(),
            LiveVerdict::Dead => 0,
        },
        "the why-live query answered"
    );
    Ok(WhyLiveExplanation {
        name: name.to_string(),
        definition,
        verdict,
    })
}

/// The definition's atom node (`(file, sect, atom)` — the mark grids'
/// own addressing), or `None` when no link-time atom carries it: a
/// dylib export, a dynamic lookup, a link-time common. The containment
/// mirrors the mark pass's own node lookup (clamping keeps a
/// definition at an inter-atom boundary on its atom).
fn definition_node(
    id: crate::ids::StringId,
    objects: &[InputObject],
    res: &Resolution,
) -> Option<(u32, usize, usize)> {
    let def = res.def(id)?;
    let si = def.section?;
    let obj = objects.get(def.file.0 as usize)?;
    let ranges = obj.atoms_of(si);
    if ranges.is_empty() {
        return None;
    }
    let idx = ranges
        .partition_point(|range| range.start <= def.value)
        .saturating_sub(1);
    Some((def.file.0, si, idx))
}

impl LiveRootKind {
    /// The interchange's `kind` token.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Entry => "entry",
            Self::ExportedSurface => "export_surface",
            Self::LoadSymbol => "load_symbol",
            Self::Alias => "alias",
            Self::ExportDynamic => "export_dynamic",
            Self::InitSection => "init_section",
            Self::TermSection => "term_section",
            Self::NoDeadStripSection => "no_dead_strip_section",
            Self::UnwindAnchor => "unwind_anchor",
        }
    }

    /// The text face's stable line (the decision named, the flag
    /// beside it where one exists).
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Self::Entry => "the entry point (-e)",
            Self::ExportedSurface => "the export surface (dylib/bundle)",
            Self::LoadSymbol => "a -u load symbol",
            Self::Alias => "an -alias definition",
            Self::ExportDynamic => "-export_dynamic",
            Self::InitSection => "an initializer-pointer section (__mod_init_func)",
            Self::TermSection => "a termination-pointer section (-no_dead_strip_inits_and_terms)",
            Self::NoDeadStripSection => "a no_dead_strip section",
            Self::UnwindAnchor => "the compact-unwind table (personality/LSDA)",
        }
    }
}

impl WhyLiveExplanation {
    /// Renders the answer as deterministic text: the verdict line, then
    /// one keeper per hop in the walk's own order, then the root
    /// decision — a build system can diff two answers line by line.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(128 + self.chain_len() * 96);
        match &self.verdict {
            LiveVerdict::Live { chain, root } => {
                let _ = writeln!(s, "{}: kept by the strip", self.name);
                for step in chain {
                    let keeper = step.referrer_symbol.as_deref().map_or_else(
                        || "an unnamed atom".to_string(),
                        std::string::ToString::to_string,
                    );
                    let via = step.via.as_deref().map_or_else(
                        || "a section-local reference".to_string(),
                        |name| format!("via {name}"),
                    );
                    let _ = writeln!(
                        s,
                        "  kept by {} ({},{},{}) at 0x{:x} ({via})",
                        keeper, step.file, step.section.0, step.section.1, step.offset
                    );
                }
                let _ = writeln!(s, "  rooted at {}", root.describe());
            }
            LiveVerdict::Dead => {
                let _ = writeln!(s, "{}: dropped by the strip", self.name);
            }
        }
        s
    }

    /// Renders the answer as deterministic, compact JSON (M92): fixed
    /// key order, one line, the report-JSON escape rules — the house
    /// interchange writer (the M56 definition object rides verbatim).
    #[must_use]
    pub fn render_json(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(128 + self.chain_len() * 128);
        let _ = write!(
            s,
            "{{\"name\":{},\"definition\":{}",
            crate::map::escape_json(&self.name),
            definition_source_json(&self.definition)
        );
        match &self.verdict {
            LiveVerdict::Live { chain, root } => {
                let _ = write!(s, ",\"verdict\":{{\"kind\":\"live\",\"chain\":[");
                for (i, step) in chain.iter().enumerate() {
                    if i > 0 {
                        s.push(',');
                    }
                    let _ = write!(
                        s,
                        "{{\"referrer\":{},\"via\":{},\"file\":{},\"segment\":{},\
                         \"section\":{},\"offset\":{}}}",
                        step.referrer_symbol
                            .as_deref()
                            .map_or("null".to_string(), crate::map::escape_json),
                        step.via
                            .as_deref()
                            .map_or("null".to_string(), crate::map::escape_json),
                        crate::map::escape_json(&step.file),
                        crate::map::escape_json(&step.section.0),
                        crate::map::escape_json(&step.section.1),
                        step.offset,
                    );
                }
                let _ = write!(s, "],\"root\":{{\"kind\":\"{}\"}}}}", root.as_str());
            }
            LiveVerdict::Dead => {
                s.push_str(",\"verdict\":{\"kind\":\"dead\"}}");
            }
        }
        s
    }

    /// The chain's hop count (the capacity hint and the tracing field).
    fn chain_len(&self) -> usize {
        match &self.verdict {
            LiveVerdict::Live { chain, .. } => chain.len(),
            LiveVerdict::Dead => 0,
        }
    }
}
