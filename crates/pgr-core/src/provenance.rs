//! M56 — the symbol-reference provenance query (`-why_export`): the
//! reverse reference index the M8 propagation planner keeps private
//! becomes a nameable, typed answer a library consumer and the driver
//! can read — *why is this symbol exported?*
//!
//! A query names two things the passes already computed:
//!
//! * the definition the Pass-2 resolution installed — the input file and
//!   section it came from (direct object or pulled archive member), the
//!   dylib export that serves it (the two-level namespace's provider),
//!   or the loader's dynamic lookup (flat namespace /
//!   `-undefined dynamic_lookup`);
//! * every reference site the link saw — the M8-a index's
//!   `(file, input section, relocation offset)` records, in the index's
//!   own ascending order, one record per `(file, section, offset)`.
//!
//! M57 rides the same seam on the load side: *why did this input ride
//! the link?* — the S7 archive pull's per-member decision (the
//! reference whose fixpoint round reached it, the `-all_load`/`-force_load`
//! eager family, the `-ObjC` metadata pull) and, under
//! `-dead_strip_dylibs`, every input dylib's carriage — recorded by the
//! pull itself (the pass already knows why it admits a member; the
//! record costs one entry per pulled member) and carried on
//! [`crate::LinkResult::loads`].
//!
//! The seam is read-only: it consumes the pipeline's products (the
//! parsed arena, the resolution, the interner — [`crate::LinkResult`]
//! carries them since M56) and re-derives nothing; a queried link plans
//! the identical layout (the parity gate is the seam's own contract,
//! `tests/m56_provenance.rs` / `tests/m57_why_load.rs`). An `-alias`
//! name is an export-surface row riding the definition it names — query
//! the definition's own name (the alias table is the caller's decision
//! surface, not the resolution's).
//!
//! The interchange face follows the M55 convention: the `render_json`
//! methods are the deterministic compact writers (fixed key order, one
//! line, the report-JSON escape rules), so a build system ships the
//! answers to any JSON tooling without a custom parser.

use crate::interner::Interner;
use crate::object::InputObject;
use crate::resolve::{Rank, Resolution};
use crate::revindex::{RefSite, ReverseIndex};

/// Why the queried name is exported: the definition the resolution
/// installed and every reference site the link saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefExplanation {
    /// The queried name (with the C underscore, verbatim).
    pub name: String,
    /// The definition the Pass-2 resolution installed.
    pub definition: DefinitionSource,
    /// Every reference site, in the index's ascending order
    /// (file order, section order, offset order; deduplicated).
    pub sites: Vec<RefSiteReport>,
}

/// The definition's provider: where the resolution's winner came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefinitionSource {
    /// A definition in a parsed input — a direct object or a pulled
    /// archive member (the member's own name rides; the archive it rode
    /// in on is the pull's story, not the definition's).
    Input {
        /// The defining file's name (the object's own diagnostics name).
        file: String,
        /// The defining input section's `(segment, name)` — `None` for a
        /// common (the `__common` slot is a link-time synthesis).
        section: Option<(String, String)>,
        /// The definition rank the resolution installed (the precedence
        /// that won the name).
        rank: Rank,
        /// `N_WEAK_DEF` on the winner.
        weak: bool,
        /// The definition's value: the section-relative address for an
        /// `N_SECT` definition, the requested size for a common.
        value: u64,
    },
    /// A dylib export: the two-level namespace bind — the first load in
    /// command order exporting the name serves the reference.
    Dylib {
        /// The providing dylib's install name (the two-level key).
        install_name: String,
        /// The load's weakness (`-weak_library`).
        weak: bool,
    },
    /// The loader resolves the name at launch (flat namespace or
    /// `-undefined dynamic_lookup`): no link-time definition exists.
    DynamicLookup,
    /// Nothing installed and nothing delegated: the resolution is
    /// mid-flight (the query's contract is a completed link —
    /// `-undefined error` refuses before any image ships).
    Unresolved,
}

/// One reference site, named: the M8-a `RefSite` with the file and
/// input section the index's ids resolve to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefSiteReport {
    /// The referencing file's name.
    pub file: String,
    /// The referencing input section's `(segment, name)`.
    pub section: (String, String),
    /// The relocation's offset within the input section.
    pub offset: u64,
}

/// The query's refusals: the vacuous decision named (the house
/// convention — a misspelling is never silently empty).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProvenanceError {
    /// The queried name nothing interned — no input defines it and no
    /// input references it.
    #[error(
        "why_export {name}: no input defines or references it — check the spelling \
         (C symbols carry the leading underscore)"
    )]
    UnknownSymbol {
        /// The refused name, verbatim.
        name: String,
    },
}

/// Answers *why is this symbol exported?* over a completed link's
/// products: the reference index (built once per link —
/// [`ReverseIndex::build_all`]), the parsed arena, the Pass-2
/// resolution and the interner ([`crate::LinkResult`] carries all
/// three since M56).
///
/// # Errors
/// [`ProvenanceError::UnknownSymbol`] when nothing interned the name
/// (the misspelling is named, the C-underscore hint is the fix).
pub fn explain_export(
    index: &ReverseIndex,
    objects: &[InputObject],
    res: &Resolution,
    interner: &Interner,
    name: &str,
) -> Result<RefExplanation, ProvenanceError> {
    let Some(id) = interner.lookup(name.as_bytes()) else {
        return Err(ProvenanceError::UnknownSymbol {
            name: name.to_string(),
        });
    };
    let definition = definition_source(id, objects, res);
    let sites: Vec<RefSiteReport> = index
        .sites(id)
        .iter()
        .map(|site| site_report(site, objects))
        .collect();
    tracing::debug!(
        symbol = %name,
        sites = sites.len(),
        "the why-export query answered"
    );
    Ok(RefExplanation {
        name: name.to_string(),
        definition,
        sites,
    })
}

/// The resolution's winner, named (the def's ids resolved through the
/// arena the link already parsed). A dylib export never installs a
/// `Def` — the two-level bind rides the resolution's ordinal map — so
/// the provider is named through [`Resolution::dylib_ordinal`].
fn definition_source(
    id: crate::ids::StringId,
    objects: &[InputObject],
    res: &Resolution,
) -> DefinitionSource {
    if let Some(def) = res.def(id) {
        let Some(obj) = objects.get(def.file.0 as usize) else {
            return DefinitionSource::Unresolved;
        };
        let section = def
            .section
            .and_then(|si| obj.sections.get(si))
            .map(|sect| (sect.segment.clone(), sect.name.clone()));
        return DefinitionSource::Input {
            file: obj.name.clone(),
            section,
            rank: def.rank,
            weak: def.weak,
            value: def.value,
        };
    }
    if res.is_dynamic_lookup(id) {
        return DefinitionSource::DynamicLookup;
    }
    if let Some(ordinal) = res.dylib_ordinal(id) {
        let Some(dylib) = res.dylibs().get(usize::from(ordinal - 1)) else {
            return DefinitionSource::Unresolved;
        };
        return DefinitionSource::Dylib {
            install_name: dylib.install_name.clone(),
            weak: dylib.weak,
        };
    }
    DefinitionSource::Unresolved
}

/// The index's site record, named through the arena.
fn site_report(site: &RefSite, objects: &[InputObject]) -> RefSiteReport {
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
    RefSiteReport {
        file,
        section,
        offset: site.offset,
    }
}

/// The rank's stable token (the provenance JSON's vocabulary).
fn rank_str(rank: Rank) -> &'static str {
    match rank {
        Rank::Strong => "strong",
        Rank::WeakDef => "weak_def",
        Rank::ArchiveStrong => "archive_strong",
        Rank::ArchiveWeak => "archive_weak",
        Rank::Common => "common",
        Rank::DylibExport => "dylib_export",
    }
}

impl DefinitionSource {
    /// The interchange's `kind` token.
    fn kind(&self) -> &'static str {
        match self {
            Self::Input { .. } => "input",
            Self::Dylib { .. } => "dylib",
            Self::DynamicLookup => "dynamic_lookup",
            Self::Unresolved => "unresolved",
        }
    }
}

impl RefExplanation {
    /// Renders the answer as deterministic text: the definition line,
    /// then every site in the index's order, then the site count — a
    /// build system can diff two answers line by line.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(256 + self.sites.len() * 64);
        match &self.definition {
            DefinitionSource::Input {
                file,
                section,
                rank,
                weak,
                ..
            } => {
                let at = section.as_ref().map_or_else(
                    || "a link-time common".to_string(),
                    |(seg, name)| format!("({seg},{name})"),
                );
                let _ = writeln!(
                    s,
                    "{}: defined in {} {} [{}{}]",
                    self.name,
                    file,
                    at,
                    rank_str(*rank),
                    if *weak { ", weak" } else { "" },
                );
            }
            DefinitionSource::Dylib { install_name, weak } => {
                let _ = writeln!(
                    s,
                    "{}: exported by {}{}",
                    self.name,
                    install_name,
                    if *weak { " (weak load)" } else { "" },
                );
            }
            DefinitionSource::DynamicLookup => {
                let _ = writeln!(
                    s,
                    "{}: resolved by dyld at launch (dynamic lookup)",
                    self.name
                );
            }
            DefinitionSource::Unresolved => {
                let _ = writeln!(
                    s,
                    "{}: no link-time definition (the resolution kept it open)",
                    self.name
                );
            }
        }
        for site in &self.sites {
            let _ = writeln!(
                s,
                "  referenced by {} ({},{}) at 0x{:x}",
                site.file, site.section.0, site.section.1, site.offset,
            );
        }
        let _ = writeln!(s, "  {} reference site(s)", self.sites.len());
        s
    }

    /// Renders the answer as deterministic, compact JSON (M56): fixed
    /// key order, one line, the report-JSON escape rules — the house
    /// interchange writer (`pgr-verify`'s `report_json`, shared here
    /// through the map's escape). A build system reads the definition
    /// and its reference sites without a custom parser.
    #[must_use]
    pub fn render_json(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(128 + self.sites.len() * 96);
        let _ = write!(s, "{{\"name\":{},", crate::map::escape_json(&self.name));
        match &self.definition {
            DefinitionSource::Input {
                file,
                section,
                rank,
                weak,
                value,
            } => {
                let _ = write!(
                    s,
                    "\"definition\":{{\"kind\":\"input\",\"file\":{},\"segment\":{},\"section\":{},\
                     \"rank\":\"{}\",\"weak\":{},\"value\":{}}}",
                    crate::map::escape_json(file),
                    section
                        .as_ref()
                        .map_or("null".to_string(), |(seg, _)| crate::map::escape_json(seg)),
                    section.as_ref().map_or("null".to_string(), |(_, name)| {
                        crate::map::escape_json(name)
                    }),
                    rank_str(*rank),
                    weak,
                    value,
                );
            }
            DefinitionSource::Dylib { install_name, weak } => {
                let _ = write!(
                    s,
                    "\"definition\":{{\"kind\":\"dylib\",\"install_name\":{},\"weak\":{}}}",
                    crate::map::escape_json(install_name),
                    weak,
                );
            }
            DefinitionSource::DynamicLookup | DefinitionSource::Unresolved => {
                let _ = write!(
                    s,
                    "\"definition\":{{\"kind\":\"{}\"}}",
                    self.definition.kind()
                );
            }
        }
        s.push_str(",\"sites\":[");
        for (i, site) in self.sites.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let _ = write!(
                s,
                "{{\"file\":{},\"segment\":{},\"section\":{},\"offset\":{}}}",
                crate::map::escape_json(&site.file),
                crate::map::escape_json(&site.section.0),
                crate::map::escape_json(&site.section.1),
                site.offset,
            );
        }
        s.push_str("]}");
        s
    }
}

/// Why one archive member rode the pull (M57): the decision that
/// admitted it, and the symbol surface it brought — the pass already
/// computed both (the ranlib-index scan and the member's own symtab
/// walk); the record costs one entry per pulled member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadExplanation {
    /// The archive the member rode in on.
    pub archive: String,
    /// The member's own name (`greet.o`).
    pub member: String,
    /// The decision that admitted the member.
    pub decision: LoadDecision,
    /// The member's defined external symbols (table order) — the names
    /// the pull added to the resolution's defined set.
    pub definitions: Vec<String>,
    /// The member's own undefined externals (table order) — the names
    /// that continued the fixpoint into the next round.
    pub opened: Vec<String>,
}

/// The pull's decision per member. The eager families outrank the lazy
/// fixpoint (an `-all_load`/`-force_load` or `-ObjC` member is admitted
/// before the reference rounds run) — the first puller names itself,
/// the pull order's own precedence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadDecision {
    /// The eager pull (`-all_load`, or `-force_load <archive>`): every
    /// member of the named archive rides regardless of liveness.
    AllLoad,
    /// The `-ObjC` metadata pull: the ranlib index names a class,
    /// metaclass or category the runtime registers by section address.
    ObjcMetadata,
    /// The S7 lazy fixpoint: `seed` names the still-unresolved
    /// reference whose index entry reached this member.
    Reference {
        /// The triggering (unresolved, undefined) reference.
        seed: String,
    },
}

/// One input dylib's carriage (M57, the `-dead_strip_dylibs` half of
/// the load story): without the knob every input dylib rides because
/// the command line names it — nothing to explain — and the rows ride
/// only under the knob, where the decision is real.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DylibExplanation {
    /// The dylib's install name.
    pub install_name: String,
    /// True when the dylib stays in the header — a referenced name
    /// binds against it, a re-export obligation rides it, or a
    /// dynamic-lookup reference could reach it. False when nothing
    /// binds: the `LC_LOAD_DYLIB` command drops (the M42 decision).
    pub kept: bool,
}

/// The `-why_load` answer (M57): every archive member the pull rode in
/// pull order, and (under `-dead_strip_dylibs`) every input dylib's
/// carriage. The pipeline builds it from data the passes already had —
/// the report and the bytes cannot disagree (the M11 map's contract).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LoadReport {
    /// The pulled members, in pull order (the eager archives, the
    /// `-ObjC` pass, then the lazy fixpoint rounds).
    pub members: Vec<LoadExplanation>,
    /// The dylib carriage rows (empty unless `-dead_strip_dylibs` ran).
    pub dylibs: Vec<DylibExplanation>,
}

impl LoadReport {
    /// Renders the answer as deterministic text: one block per pulled
    /// member (the decision line, the member's definitions and opens),
    /// then the dylib carriage rows — a build system can diff two
    /// reports line by line.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(256 + self.members.len() * 128);
        for m in &self.members {
            let _ = writeln!(s, "{}({}):", m.archive, m.member);
            match &m.decision {
                LoadDecision::AllLoad => {
                    let _ = writeln!(s, "  pulled by -all_load (the eager pull)");
                }
                LoadDecision::ObjcMetadata => {
                    let _ = writeln!(s, "  pulled by -ObjC (the metadata family)");
                }
                LoadDecision::Reference { seed } => {
                    let _ = writeln!(s, "  pulled for {seed} (the lazy fixpoint)");
                }
            }
            let _ = writeln!(s, "  defines: {}", m.definitions.join(" "));
            let _ = writeln!(s, "  opens: {}", m.opened.join(" "));
        }
        for d in &self.dylibs {
            let _ = writeln!(
                s,
                "{d_install}: {kept}",
                d_install = d.install_name,
                kept = if d.kept {
                    "kept (a referenced name binds against it)"
                } else {
                    "dropped (nothing binds against it)"
                },
            );
        }
        s
    }

    /// Renders the answer as deterministic, compact JSON (M57): fixed
    /// key order, one line, the report-JSON escape rules.
    #[must_use]
    pub fn render_json(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(128 + self.members.len() * 256);
        s.push_str("{\"members\":[");
        for (i, m) in self.members.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let _ = write!(
                s,
                "{{\"archive\":{},\"member\":{},\"decision\":{},\"definitions\":[",
                crate::map::escape_json(&m.archive),
                crate::map::escape_json(&m.member),
                match &m.decision {
                    LoadDecision::AllLoad => "{\"kind\":\"all_load\"}".to_string(),
                    LoadDecision::ObjcMetadata => "{\"kind\":\"objc_metadata\"}".to_string(),
                    LoadDecision::Reference { seed } => format!(
                        "{{\"kind\":\"reference\",\"seed\":{}}}",
                        crate::map::escape_json(seed)
                    ),
                },
            );
            for (j, name) in m.definitions.iter().enumerate() {
                if j > 0 {
                    s.push(',');
                }
                let _ = write!(s, "{}", crate::map::escape_json(name));
            }
            s.push_str("],\"opened\":[");
            for (j, name) in m.opened.iter().enumerate() {
                if j > 0 {
                    s.push(',');
                }
                let _ = write!(s, "{}", crate::map::escape_json(name));
            }
            s.push_str("]}");
        }
        s.push_str("],\"dylibs\":[");
        for (i, d) in self.dylibs.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            let _ = write!(
                s,
                "{{\"install_name\":{},\"kept\":{}}}",
                crate::map::escape_json(&d.install_name),
                d.kept,
            );
        }
        s.push_str("]}");
        s
    }
}
