//! The driver-side pipeline: Pass 0 (inputs) → Pass 1 (parse & intern) →
//! Pass 2 (resolve) → Pass 3 (layout). The returned [`Layout`] is the plan
//! Pass 4/5 (`pgr-emit`) turn into bytes.
//!
//! M4 (architecture doc §10.3 row M4): Pass 1 parses in parallel —
//! **LPT-scheduled** (longest input first, perf doc §4.1) on the shared
//! compute pool ([`crate::pool`]) — with giant objects split across threads
//! (symbol decode runs in deterministic index chunks). [`Parallelism::Serial`]
//! forces the M1–M3 single-threaded shape; both paths produce identical
//! layouts (determinism policy §4.3) and the equality is gated in tests.
//!
//! M5 adds **archive liveness** (S7, perf doc §4.2): static archives arrive
//! with their ranlib table pre-parsed and members are pulled lazily — the
//! fixpoint walks the unresolved-name set against the index in archive
//! command order, parsing only members that resolve something (`-all_load`
//! and `-force_load` short-circuit to eager). The pull order is a pure
//! function of the inputs, so `FileIds` — and every later pass — stay
//! schedule- and environment-independent.

use crate::LinkError;
use crate::ids::{FileId, StringId};
use crate::interner::Interner;
use crate::layout::{Layout, LinkConfig, layout};
use crate::object::InputObject;
use crate::observe::{LinkNote, LinkObserver, Phase, PhaseDetail, PhaseEvent, TaskEvent};
use crate::pool;
use crate::provenance::{LoadDecision, LoadExplanation};
use crate::resolve::Resolution;
use rayon::prelude::*;
use std::collections::HashSet;
use std::time::{Duration, Instant};

/// Pass 1 scheduling policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Parallelism {
    /// Use the shared compute pool: LPT-ordered parse, giant objects split
    /// across threads, parallel interner sort (the M4 default).
    #[default]
    Auto,
    /// Force the M1–M3 single-threaded pass bodies (reference path for the
    /// determinism gates and benches).
    Serial,
}

impl Parallelism {
    /// True when the parallel pass bodies should run.
    #[must_use]
    pub const fn is_parallel(self) -> bool {
        matches!(self, Self::Auto)
    }
}

/// One link input: a file name and its bytes (Pass 0 mapped them).
#[derive(Debug, Clone)]
pub struct LinkInput {
    /// File name (diagnostics only).
    pub name: String,
    /// Raw bytes of a relocatable arm64 object.
    pub bytes: Vec<u8>,
}

/// One archive member descriptor (data span + name for diagnostics).
#[derive(Debug, Clone)]
pub struct LinkArchiveMember {
    /// Member name (`greet.o`), diagnostics only.
    pub name: String,
    /// File offset of the member's data inside [`LinkArchive::bytes`].
    pub offset: u64,
    /// Data size in bytes.
    pub size: u64,
}

/// A static archive input (M5/S7): the raw bytes plus the pre-parsed ranlib
/// table. Members are **not** parsed here — the pull fixpoint decides which
/// members the link needs, which is the S7 decision (lazy beats eager on
/// archive-heavy corpora; see `docs/BENCHMARKS.md`).
#[derive(Debug, Clone)]
pub struct LinkArchive {
    /// Archive name (diagnostics; `libfoo.a`).
    pub name: String,
    /// Raw archive bytes (members slice into it).
    pub bytes: Vec<u8>,
    /// Ranlib entries in stored order: `(symbol name, member index)`.
    pub index: Vec<(Vec<u8>, u32)>,
    /// Content members in file order.
    pub members: Vec<LinkArchiveMember>,
    /// `-all_load` / `-force_load`: pull every member regardless of liveness.
    pub all_load: bool,
}

/// The full Pass 1–3 product: the emit plan plus the parsed input arena
/// (Pass 4 needs the input bytes for the section copies) and the Pass-2
/// resolution (the M56 provenance query's input — the `-why_export`
/// seam reads the winners and the reverse index over the same arena).
#[derive(Debug)]
pub struct LinkResult {
    /// The layout plan (Pass 3).
    pub layout: Layout,
    /// Parsed input objects (Pass 1 arenas; Pass 4 copies from these).
    pub objects: Vec<InputObject>,
    /// The interner (name diagnostics for driver-side checks).
    pub interner: Interner,
    /// The Pass-2 winners ([`crate::resolve::Resolution`]): the
    /// provenance query's input — [`crate::provenance::explain_export`]
    /// reads the definition it installed against the same arena.
    pub resolution: Resolution,
    /// The M57 load-provenance record: every archive member the S7
    /// pull rode (the decision that admitted it) and, under
    /// `-dead_strip_dylibs`, every input dylib's carriage. The pull
    /// records it from data it already had; the report and the bytes
    /// cannot disagree.
    pub loads: crate::provenance::LoadReport,
    /// The Pass-2 snapshot ([`crate::resolve::ResolutionSnapshot`])
    /// captured when [`LinkConfig::record_resolution`] is set — the
    /// record-side half of the M9 resolve wiring (the link record's v5
    /// section). `None` on every clean link.
    pub resolve_snapshot: Option<crate::resolve::ResolutionSnapshot>,
    /// The M92 liveness record: the M5 mark phase's first-marker table
    /// ([`crate::deadstrip::LivenessIndex`]), the `-why_live` query's
    /// input — the mark recorded, from data it already had, the first
    /// way each atom went live (the root that named it, or the
    /// reference that reached it). `Some` exactly when the strip ran;
    /// `None` otherwise (a link without `-dead_strip` has no strip to
    /// explain). The record never feeds a pass: the layout is planned
    /// before the extraction, the plan and the record cannot disagree.
    pub liveness: Option<crate::deadstrip::LivenessIndex>,
}

/// Runs Passes 1–3 over the inputs, producing the emit plan (M4 default:
/// parallel Pass 1 — see [`link_with`] for the serial reference path).
///
/// # Errors
/// [`LinkError`] on malformed inputs, unresolvable/duplicate symbols, or
/// layout contract violations.
pub fn link(
    inputs: &[LinkInput],
    archives: &[LinkArchive],
    cfg: &LinkConfig,
) -> Result<LinkResult, LinkError> {
    link_with(inputs, archives, cfg, Parallelism::Auto)
}

/// Runs Passes 1–3 with an explicit scheduling policy.
///
/// # Errors
/// [`LinkError`] on malformed inputs, unresolvable/duplicate symbols, or
/// layout contract violations.
pub fn link_with(
    inputs: &[LinkInput],
    archives: &[LinkArchive],
    cfg: &LinkConfig,
    parallel: Parallelism,
) -> Result<LinkResult, LinkError> {
    link_cached(inputs, archives, cfg, parallel, None)
}

/// Runs Passes 1–3 through the M6 Stage A POI cache: unchanged inputs skip
/// Pass 1's Mach-O walk entirely (architecture doc §7.1). A cache hit must
/// produce byte-identical results to a fresh parse — the equality is gated
/// in [`crate::cache`] and the driver's M6 tests.
///
/// # Errors
/// [`LinkError`] on malformed inputs, unresolvable/duplicate symbols, or
/// layout contract violations.
pub fn link_cached(
    inputs: &[LinkInput],
    archives: &[LinkArchive],
    cfg: &LinkConfig,
    parallel: Parallelism,
    cache: Option<&crate::cache::PoiCache>,
) -> Result<LinkResult, LinkError> {
    link_cached_inner(inputs, archives, cfg, parallel, cache, None)
}

/// Runs Passes 1–3 under an observer (M54): the same pipeline
/// [`link_cached`] runs — an observed link plans the identical layout
/// (the parity gate is the seam's own contract, `tests/m54_observer.rs`)
/// — with each phase's completion and the ladder's silent-correct rungs
/// reported to `observer`. The zero-config consumer installs
/// [`crate::observe::TracingObserver`] (the events ride the house tracing seam, inert
/// until a subscriber joins).
///
/// # Errors
/// [`LinkError`] on malformed inputs, unresolvable/duplicate symbols, or
/// layout contract violations.
pub fn link_observed(
    inputs: &[LinkInput],
    archives: &[LinkArchive],
    cfg: &LinkConfig,
    parallel: Parallelism,
    cache: Option<&crate::cache::PoiCache>,
    observer: &mut dyn LinkObserver,
) -> Result<LinkResult, LinkError> {
    link_cached_inner(inputs, archives, cfg, parallel, cache, Some(observer))
}

/// The Passes 1–3 body both link entries share; `observer` carries the
/// M54 seam (`None` = silence, the historical shape).
fn link_cached_inner(
    inputs: &[LinkInput],
    archives: &[LinkArchive],
    cfg: &LinkConfig,
    parallel: Parallelism,
    cache: Option<&crate::cache::PoiCache>,
    mut observer: Option<&mut dyn LinkObserver>,
) -> Result<LinkResult, LinkError> {
    // ---- Pass 1: parse & collect names for the interner --------------------
    // M11: an order file ranks symbols — the atom split feeds it the same
    // way dead-strip does (and rides the same cache-key flag).
    let split_symbols = split_symbols_for(cfg);
    let parse_started = Instant::now();
    let objects = parse_inputs(inputs, parallel, split_symbols, cache, &mut observer)?;
    emit_phase(
        &mut observer,
        Phase::Parse,
        PhaseDetail::Objects {
            inputs: objects.len(),
        },
        parse_started.elapsed(),
    );
    link_from_objects_observed(objects, archives, cfg, parallel, cache, observer)
}

/// The Pass-1 symbol-split decision (M11): an order file ranks symbols —
/// the atom split feeds it the same way dead-strip does (and rides the
/// same cache-key flag). One rule, both lanes: the driver's cached link
/// and the resident session's prepare must decide identically, or a warm
/// ordered link plans a different atom shape than the cold one (the M81
/// parity gate is the rule's own contract).
#[must_use]
pub fn split_symbols_for(cfg: &LinkConfig) -> bool {
    cfg.dead_strip || cfg.symbol_order.is_some()
}

/// Runs Passes 1b–3 over **already-parsed** direct inputs (M8): the resident
/// server skips the Mach-O parse for unchanged files (its session holds the
/// Pass 1 product) and calls this instead of [`link_cached`]. The archive
/// pull fixpoint, interning, resolution, liveness/ICF and layout run exactly
/// as in the one-shot path — a pre-parsed link must produce the identical
/// layout (gated in `tests/m8_foundations.rs`), and through it, identical
/// bytes.
///
/// `objects` must be parsed, atomized ([`InputObject::compute_atoms`]) and
/// carry their command-line [`FileId`]s.
///
/// # Errors
/// [`LinkError`] on malformed archive members, unresolvable/duplicate
/// symbols, or layout contract violations.
pub fn link_from_objects(
    objects: Vec<InputObject>,
    archives: &[LinkArchive],
    cfg: &LinkConfig,
    parallel: Parallelism,
    cache: Option<&crate::cache::PoiCache>,
) -> Result<LinkResult, LinkError> {
    link_from_objects_observed(objects, archives, cfg, parallel, cache, None)
}

/// Runs Passes 1b–3 under an observer over **already-parsed** direct
/// inputs (M54): the [`link_from_objects`] contract — a pre-parsed link
/// produces the identical layout (the M8 gate) — with the observation
/// seam of [`link_observed`]. The resident server's session can subscribe
/// to its warm relinks without re-parsing anything.
///
/// `objects` must be parsed, atomized ([`InputObject::compute_atoms`]) and
/// carry their command-line [`FileId`]s.
///
/// # Errors
/// [`LinkError`] on malformed archive members, unresolvable/duplicate
/// symbols, or layout contract violations.
pub fn link_from_objects_observed(
    objects: Vec<InputObject>,
    archives: &[LinkArchive],
    cfg: &LinkConfig,
    parallel: Parallelism,
    cache: Option<&crate::cache::PoiCache>,
    mut observer: Option<&mut dyn LinkObserver>,
) -> Result<LinkResult, LinkError> {
    let (objects, interner, export_ids, loader_ids, mut loads) =
        pull_and_intern(objects, archives, cfg, parallel, cache, true, &mut observer)?;

    // ---- M39: the make-undefined marks ---------------------------------------
    // The names resolve against the finished interner batch (object
    // symbols, dylib exports, aliases): a name nothing interned was
    // never defined or referenced by any input — the vacuous decision
    // refuses with the fix. The definition check (a mark must land on a
    // real definition) runs in `Resolution::install_make_undefined`,
    // on both resolve paths.
    let make_undefined_ids = make_undefined_ids(&cfg.make_undefined, &interner)?;

    // ---- Pass 2: resolution --------------------------------------------------
    // M9 GA rung — the resolve's record-side wiring: a relink whose record
    // vouches a snapshot plans Pass 2 through the recorded decisions
    // (`resolve_reuse`; the replay enforces the undefined policy itself)
    // and falls back to the full install whenever the shape guard or the
    // replay refuses. The fallback is the ladder's bottom rung — always
    // available, always correct, and invisible to the layout (the equality
    // contract is gated in `tests/m9_resolve_reuse.rs`).
    let loader_export_names: Vec<Vec<u8>> = cfg
        .bundle_loader
        .as_ref()
        .map_or_else(Vec::new, |l| l.exports().to_vec());
    let resolve_started = Instant::now();
    let reused = cfg.resolve_reuse.as_ref().and_then(|seed| {
        match crate::resolve_reuse::plan_reuse(
            &seed.snapshot,
            &seed.digests,
            &interner,
            &objects,
            &cfg.dylibs,
            &loader_export_names,
        ) {
            Ok(plan) => {
                // M113: the reference-trace face rides the replay too —
                // the replay's reference re-walk reports the same visits
                // the full path does (the trace is the run's own Pass-2
                // record, the M107/M108 config pattern).
                let replay = crate::resolve_reuse::install_reused(
                    &plan,
                    &seed.snapshot,
                    &interner,
                    &objects,
                    &cfg.dylibs,
                    &loader_export_names,
                    &make_undefined_ids,
                    cfg.undefined_policy,
                    cfg.no_weak_imports,
                    cfg.module_policy,
                    cfg.flat_namespace,
                    cfg.multiply_defined,
                    &mut observer,
                );
                match replay {
                    Ok(res) => Some(res),
                    // The shape guard passed but the replay refused an
                    // invariant — a distinct cause from a shape move, and
                    // it used to vanish into the fallback. The ladder's
                    // bottom rung stays silent-correct, not silent-blind:
                    // the refusal names itself on the tracing seam (and
                    // on the M54 observer, the typed face of the same
                    // convention).
                    Err(e) => {
                        tracing::debug!(
                            error = %e,
                            "the resolve-reuse install refused; falling back to the full resolve"
                        );
                        emit_note(
                            &mut observer,
                            LinkNote::ResolveReuseFallback {
                                reason: e.to_string(),
                            },
                        );
                        None
                    }
                }
            }
            Err(fallback) => {
                tracing::debug!(
                    fallback = %fallback,
                    "the resolve-reuse plan refused; falling back to the full resolve"
                );
                emit_note(
                    &mut observer,
                    LinkNote::ResolveReuseFallback {
                        reason: fallback.to_string(),
                    },
                );
                None
            }
        }
    });
    let replayed = reused.is_some();
    let mut res = if let Some(reused) = reused {
        reused
    } else {
        let mut full = Resolution::default();
        full.install_make_undefined(&make_undefined_ids, &objects, &interner)?;
        full.install(&objects, &interner, cfg.multiply_defined, &mut observer)?;
        full.install_dylibs(&cfg.dylibs, &export_ids);
        full.install_loader_exports(&loader_ids);
        full.require_all_resolved(
            &interner,
            &objects,
            cfg.undefined_policy,
            cfg.no_weak_imports,
            cfg.module_policy,
            cfg.flat_namespace,
        )?;
        full
    };
    emit_phase(
        &mut observer,
        Phase::Resolve,
        PhaseDetail::Winners { reused: replayed },
        resolve_started.elapsed(),
    );
    // M108: the multiply-defined resolution policy (`-multiply_defined
    // <policy>`) — the collision's advisory product rides both resolve
    // paths (the full install and the reuse replay — the policy is
    // config, not a lane product, the M107 pattern): the decision
    // landed at the install site, this walk derives the record faces'
    // entries from the resolved state (the replay's copied winners and
    // the fresh parse reach the same entries the cold walk derives).
    res.apply_multiply_defined_policy(cfg.multiply_defined, &interner, &objects)?;
    // M107: the commons resolution policy (`-commons <policy>`) — the
    // tentative's fate is the policy's decision. The walk rides both
    // resolve paths (the full install and the reuse replay — the policy
    // is config, not a lane product): the default face is a no-op (the
    // house rank order — an in-image definition, a common included,
    // beats the two-level export), the non-default faces replace or
    // un-define the tentative and let the exporting dylib serve the
    // bind, so the M42 drop's use-decision below reads the post-policy
    // winners.
    res.apply_commons_policy(cfg.commons, cfg.undefined_policy, &interner)?;
    // M42: the unused-dylib drop (`-dead_strip_dylibs`) — the Pass-2
    // decision the kept command list reads. The compaction rides both
    // resolve paths (the full install and the reuse replay): the
    // resolution compacts its two-level map onto the kept dylibs and
    // returns them, and the config's dylib list — the header assembly's
    // `LC_LOAD_DYLIB` commands and the trie's REEXPORT loop — becomes
    // the kept list. Everything downstream (the record snapshot, the
    // dead-strip roots, the fixup planner's ordinals) reads the
    // compacted state. The default path never clones the config.
    let cfg_owned;
    let cfg: &LinkConfig = if cfg.dead_strip_dylibs {
        let kept = res.dead_strip_dylibs();
        // M57: the load story's dylib half — one carriage row per input
        // dylib (the kept list is the compacted subset; the dropped ride
        // named). Without the knob the rows stay empty: every dylib
        // rides because the command line names it.
        let kept_names: std::collections::HashSet<&str> =
            kept.iter().map(|d| d.install_name.as_str()).collect();
        loads.dylibs = cfg
            .dylibs
            .iter()
            .map(|d| crate::provenance::DylibExplanation {
                install_name: d.install_name.clone(),
                kept: kept_names.contains(d.install_name.as_str()),
            })
            .collect();
        cfg_owned = {
            let mut c = cfg.clone();
            c.dylibs = kept;
            c
        };
        &cfg_owned
    } else {
        cfg
    };
    // M116: the common-symbol advisory (`-warn_commons`) — the walk
    // rides both resolve paths (the full install and the reuse replay —
    // the decision is config, not a lane product, the M107/M108
    // pattern): it derives, from the finished resolution, where every
    // input common symbol landed (a local definition or a linked
    // dylib's export) and records the advisory product the driver's
    // warning face tallies. The default (`false`) records nothing — the
    // face is a measurement, never a layout product (the M109 pattern).
    // The M42 drop above ran first, so a dropped provider is never
    // named; the relocatable path refuses the knob (the walk never runs
    // there — the object's symtab is the input's, verbatim).
    res.apply_warn_commons(cfg.warn_commons, &interner, &objects);
    // M121: the duplicate-symbol advisory rides the same post-resolve walk
    // (the M107/M116 config pattern) — the advisory never changes the
    // resolution policy itself; the walk derives the duplicate-strong
    // collisions the `multiply_defined` policy prices, the M81 replay
    // riding the same way. The relocatable path refuses the knob before
    // the resolve runs (the object's symtab is the input's, verbatim).
    res.apply_warn_duplicate(cfg.warn_duplicate, &interner, &objects);
    // M123: the weak-reference-mismatches advisory rides the same
    // post-resolve walk (the M107/M116/M121 config pattern) — the walk
    // derives the record from the resolved `references` map, the policy
    // decides the exit. Under the default `error` a mix refuses the link
    // (the M108 refusal shape); the advisory `weak` / `non-weak` faces
    // leave the record for the driver to print (the bytes never move —
    // the M109/M116 pattern). The relocatable path refuses the knob
    // before the resolve runs (the object's symtab is the input's).
    res.apply_weak_reference_mismatches(cfg.weak_reference_mismatches, &interner, &objects);
    if matches!(
        cfg.weak_reference_mismatches,
        crate::resolve::WeakReferenceMismatchesPolicy::Error
    ) {
        if let Some(entry) = res.weak_reference_mismatches_open().next() {
            return Err(LinkError::Layout {
                message: format!(
                    "-weak_reference_mismatches error: a symbol is referenced both \
                     weakly and strongly — {entry} — drop the weak reference or pass \
                     -weak_reference_mismatches weak|non-weak to record the mismatch \
                     and exit 0"
                ),
            });
        }
    }
    // The record side: capture the finished Pass-2 state when the caller
    // asked for it (the `-incremental` record), so the v5 record section
    // carries it to the next relink.
    let resolve_snapshot = cfg.record_resolution.then(|| {
        crate::resolve::ResolutionSnapshot::capture(
            &objects,
            &interner,
            &res,
            &cfg.dylibs,
            &loader_export_names,
        )
    });

    // ---- M5/D12 liveness, then M6 ICF over the live text atoms --------------
    let live_started = Instant::now();
    let mut live = crate::deadstrip::compute(&objects, &res, &interner, cfg);
    // M92: the mark's why-record leaves the live set before the passes
    // consume it (`std::mem::take` — the layout plans from the same
    // grids it always did); the query reads it off the result.
    let liveness = live.take_liveness();
    emit_phase(
        &mut observer,
        Phase::Liveness,
        PhaseDetail::Live {
            active: live.is_active(),
        },
        live_started.elapsed(),
    );
    let fold_started = Instant::now();
    let fold = crate::icf::fold(&objects, &res, cfg, &live)?;
    emit_phase(
        &mut observer,
        Phase::Fold,
        PhaseDetail::Folded {
            folded: fold.folded_count,
        },
        fold_started.elapsed(),
    );

    // ---- Pass 3: layout -------------------------------------------------------
    let layout_started = Instant::now();
    let layout = layout(&objects, &res, &interner, cfg, &live, &fold)?;
    emit_phase(
        &mut observer,
        Phase::Layout,
        PhaseDetail::Planned {
            segments: layout.segments.len(),
            sections: layout.sections.len(),
        },
        layout_started.elapsed(),
    );
    Ok(LinkResult {
        layout,
        objects,
        interner,
        resolution: res,
        loads,
        resolve_snapshot,
        liveness,
    })
}

/// Resolves the M39 make-undefined names against the finished interner
/// batch: a name nothing interned was never defined or referenced by
/// any input, so the decision is vacuous — the refusal names the
/// misspelling (the `-alias` convention; the definition check itself
/// runs in [`Resolution::install_make_undefined`], where the parse's
/// symbol tables are in hand).
fn make_undefined_ids(
    table: &crate::make_undefined::MakeUndefined,
    interner: &Interner,
) -> Result<Vec<StringId>, LinkError> {
    table
        .iter()
        .map(|entry| {
            interner
                .lookup(entry.name().as_bytes())
                .ok_or_else(|| LinkError::Symbol {
                    name: String::new(),
                    message: format!(
                        "-U {} marks a defined symbol undefined, but no input defines or \
                         references it — nothing to strip; check the spelling (C symbols \
                         carry the leading underscore) or drop the -U decision",
                        entry.name()
                    ),
                })
        })
        .collect()
}

/// The Pass 1–2 front half both link shapes share: the S7 archive pull
/// fixpoint, the interner batch (object symbols, then dylib exports; the
/// executable-header symbol appended only on the image path), the
/// `InputObject::finish` id patch and — for the caller's convenience —
/// the dylib export ids. Pass 3 onward is where `-r` and the image
/// pipeline diverge.
fn pull_and_intern(
    mut objects: Vec<InputObject>,
    archives: &[LinkArchive],
    cfg: &LinkConfig,
    parallel: Parallelism,
    cache: Option<&crate::cache::PoiCache>,
    intern_header_symbol: bool,
    observer: &mut Option<&mut dyn LinkObserver>,
) -> Result<
    (
        Vec<InputObject>,
        Interner,
        Vec<StringId>,
        Vec<StringId>,
        crate::provenance::LoadReport,
    ),
    LinkError,
> {
    // ---- S7 archive liveness (M5): pull only referenced members ------------
    let pull_started = Instant::now();
    let (pulled, loads) = pull_archive_members(&objects, archives, cfg, cache)?;
    let pulled_count = pulled.len();
    for obj in pulled {
        objects.push(obj);
    }
    emit_phase(
        observer,
        Phase::ArchivePull,
        PhaseDetail::Members {
            pulled: pulled_count,
        },
        pull_started.elapsed(),
    );

    let mut names: Vec<Vec<u8>> = Vec::new();
    for obj in &mut objects {
        names.append(&mut obj.take_symbol_names());
    }
    // Dylib export names join the interner batch *after* the object symbol
    // stream, so the object id slices stay stable (M2 two-level namespace).
    let dylib_export_count: usize = cfg.dylibs.iter().map(|d| d.exports.len()).sum();
    let mut export_names: Vec<Vec<u8>> = Vec::with_capacity(dylib_export_count);
    for d in &cfg.dylibs {
        export_names.extend(d.exports.iter().cloned());
    }
    names.extend(export_names.iter().cloned());
    // M25: the loader export names join the batch after the dylib
    // exports (the image path only — the `-r` object surface opens its
    // undefineds by design and refuses the knob), so Pass 2 can
    // install the loader surface by id.
    let loader_export_count = if intern_header_symbol {
        cfg.bundle_loader.as_ref().map_or(0, |l| l.exports().len())
    } else {
        0
    };
    if intern_header_symbol {
        if let Some(loader) = &cfg.bundle_loader {
            for e in loader.exports() {
                names.push(e.clone());
            }
        }
    }
    // M24: the alias names join the batch after the dylib exports (the
    // image path only — the `-r` object surface carries no alias rows),
    // so the layout's name lookups find them.
    if intern_header_symbol {
        for a in &cfg.aliases {
            names.push(a.alias().as_bytes().to_vec());
        }
    }
    // `__mh_execute_header` is always interned so the layout pass can emit
    // the executable's header symbol (ld64/lld convention). The `-r` path
    // never emits one — the object emit consumes the batch without it.
    if intern_header_symbol {
        names.push(b"__mh_execute_header".to_vec());
    }

    let intern_started = Instant::now();
    let (interner, ids) = Interner::build_with(&names, parallel.is_parallel());
    let mut cursor = 0usize;
    for obj in &mut objects {
        let take = obj.symbols.len();
        if cursor + take > ids.len() {
            return Err(LinkError::Internal {
                message: "interner table shorter than the symbol stream".into(),
            });
        }
        obj.finish(&ids[cursor..cursor + take])?;
        cursor += take;
    }
    emit_phase(
        observer,
        Phase::Intern,
        PhaseDetail::Names {
            interned: names.len(),
        },
        intern_started.elapsed(),
    );
    let export_ids: Vec<StringId> = ids[cursor..cursor + dylib_export_count].to_vec();
    cursor += dylib_export_count;
    let loader_ids: Vec<StringId> = ids[cursor..cursor + loader_export_count].to_vec();
    Ok((objects, interner, export_ids, loader_ids, loads))
}

/// The Pass 1–2 product a `-r` output consumes (M10 rung 1): the parsed
/// objects, the interner and the resolution — winners for the defined
/// externs, references for the rest. Undefined externals stay open (the
/// object is itself a link *input*; the next link resolves them), so the
/// undefined policy and the dylib install never run on this path.
#[derive(Debug)]
pub struct RelocLink {
    /// Parsed input objects (Pass 1 arenas; the emit copies section bytes
    /// and re-encodes relocation entries from these).
    pub objects: Vec<InputObject>,
    /// The interner (name bytes for the output symbol table).
    pub interner: Interner,
    /// The Pass-2 winners (`Resolution::def` per interned name).
    pub resolution: Resolution,
    /// The M57 load-provenance record (the pull's members; the dylib
    /// rows ride empty — the relocatable output refuses
    /// `-dead_strip_dylibs`, every dylib rides because the command line
    /// names it).
    pub loads: crate::provenance::LoadReport,
}

/// Runs Passes 1–2 for a `-r` relocatable output (M10 rung 1): the same
/// parse (Pass 1, LPT-scheduled) and resolution (Pass 2) as [`link_cached`],
/// stopping before the segment-shaped Pass 3 — a relocatable object has no
/// pages, no `__PAGEZERO`, no entry point, no fixups and no signature.
/// Duplicate strong definitions still refuse; undefined externals do not.
/// The object bytes are assembled by `pgr-emit`'s `build_object_image`.
///
/// # Errors
/// [`LinkError`] on malformed inputs or unresolvable duplicate symbols.
pub fn link_reloc(
    inputs: &[LinkInput],
    archives: &[LinkArchive],
    cfg: &LinkConfig,
    parallel: Parallelism,
) -> Result<RelocLink, LinkError> {
    link_reloc_inner(inputs, archives, cfg, parallel, None)
}

/// Runs the `-r` relocatable Passes 1–2 under an observer (M54): the
/// [`link_reloc`] contract — the same parse and resolution as
/// [`link_cached`], stopping before the segment-shaped Pass 3 — with the
/// observation seam of [`link_observed`]. The object shape reports its
/// own run (`Parse → ArchivePull → Intern → Resolve → Reloc`).
///
/// # Errors
/// [`LinkError`] on malformed inputs or unresolvable duplicate symbols.
pub fn link_reloc_observed(
    inputs: &[LinkInput],
    archives: &[LinkArchive],
    cfg: &LinkConfig,
    parallel: Parallelism,
    observer: &mut dyn LinkObserver,
) -> Result<RelocLink, LinkError> {
    link_reloc_inner(inputs, archives, cfg, parallel, Some(observer))
}

/// The relocatable front half both `-r` entries share; `observer` carries
/// the M54 seam (`None` = silence, the historical shape).
fn link_reloc_inner(
    inputs: &[LinkInput],
    archives: &[LinkArchive],
    cfg: &LinkConfig,
    parallel: Parallelism,
    mut observer: Option<&mut dyn LinkObserver>,
) -> Result<RelocLink, LinkError> {
    let span = tracing::info_span!("link_reloc", inputs = inputs.len());
    let _entered = span.enter();
    let reloc_started = Instant::now();
    if cfg.bundle_loader.is_some() {
        return Err(LinkError::Layout {
            message: "-bundle_loader binds a bundle against its host process, but the \
                      relocatable output opens its undefineds by design — drop \
                      -bundle_loader or link a bundle"
                .into(),
        });
    }
    // M42: the unused-dylib drop is a segmented-output decision — the
    // relocatable output carries no load commands (its symbol table is
    // the input's, verbatim), so there is nothing to strip. The
    // re-check backs the driver surface's earlier refusal: no library
    // caller can plan the shape either.
    if cfg.dead_strip_dylibs {
        return Err(LinkError::Layout {
            message: "-dead_strip_dylibs drops the load commands of unused dylibs, but the \
                      relocatable output opens its undefineds by design and carries no load \
                      commands — drop -dead_strip_dylibs or link a segmented output"
                .into(),
        });
    }
    // M107: the non-default commons policies are a segmented-output
    // decision — the relocatable output's symtab is the input's,
    // verbatim (there is no tentative fate to decide). The re-check
    // backs the driver surface's earlier refusal: no library caller can
    // plan the shape either.
    if cfg.commons != crate::resolve::CommonsPolicy::UseDylibs {
        return Err(LinkError::Layout {
            message: format!(
                "-commons {} decides a tentative definition's fate against the linked \
                 dylibs, but the relocatable output opens its undefineds by design — \
                 nothing to decide: drop -commons or link a segmented output",
                cfg.commons.flag_word()
            ),
        });
    }
    // M108: the non-default multiply-defined policies are a
    // segmented-output decision — the relocatable output's symtab is the
    // input's, verbatim (an object carries its inputs' symbol tables
    // untouched; there is no winner to decide about). The re-check backs
    // the driver surface's earlier refusal: no library caller can plan
    // the shape either (the M104/M105/M107 pattern).
    if cfg.multiply_defined != crate::resolve::MultiplyDefinedPolicy::Error {
        return Err(LinkError::Layout {
            message: format!(
                "-multiply_defined {} decides which definition wins a duplicated name, \
                 but the relocatable output's symtab is the input's, verbatim — nothing \
                 to decide: drop -multiply_defined or link an image (an executable, dylib \
                 or bundle)",
                cfg.multiply_defined.flag_word()
            ),
        });
    }
    // M109: the warnings-as-errors exit decision is a segmented-output
    // decision — the relocatable output's shape is the input's, verbatim,
    // and every advisory face that would warn beside `-r` is already
    // refused there (the M103/M108 `-r` refusals: an object has no
    // load-time bind to warn about, no winner to decide about), so there
    // is nothing left to elevate. The re-check backs the driver
    // surface's earlier refusal: no library caller can plan the shape
    // either.
    if cfg.fatal_warnings {
        return Err(LinkError::Layout {
            message: "-fatal_warnings elevates the advisory faces' warnings to a failed \
                      link, but the relocatable output's shape is the input's, verbatim \
                      and every advisory face is already refused beside -r — nothing to \
                      elevate: drop -fatal_warnings or link an image (an executable, \
                      dylib or bundle)"
                .into(),
        });
    }
    // M106: the needed-dylib mark is a segmented-output decision — the
    // mark keeps a dylib's load command alive under the drop, and the
    // relocatable output carries no load commands (its symtab is the
    // input's, verbatim), so there is nothing for the mark to keep. The
    // re-check backs the driver surface's earlier refusal: no library
    // caller can plan the shape either.
    if cfg.dylibs.iter().any(|d| d.needed) {
        return Err(LinkError::Layout {
            message: "-needed_library/-needed_framework/-needed-l marks a dylib to really \
                      ride the load commands even when nothing binds against it, but the \
                      relocatable output opens its undefineds by design and carries no \
                      load commands — drop the needed marks or link a segmented output"
                .into(),
        });
    }
    // M110: the hidden-dylib mark is a segmented-output decision — the
    // mark drops a load command the object cannot carry (its load
    // command list is the input's, verbatim: there is no header to
    // drop the command from, and no two-level ordinal space to keep
    // the dylib out of). The re-check backs the driver surface's
    // earlier refusal: no library caller can plan the shape either.
    // M111: the read-only-relocations policy is a final-image decision —
    // the relocatable output's sections are the input's, verbatim, and
    // its relocation sites ride untouched (there is no segment mapping
    // for the policy to price). The re-check backs the driver surface's
    // earlier refusal: no library caller can plan the shape either.
    if cfg.read_only_relocs != crate::resolve::ReadOnlyRelocsPolicy::Error {
        return Err(LinkError::Layout {
            message: format!(
                "-read_only_relocs {} decides what a write into a read-only segment \
                 becomes, but the relocatable output's sections are the input's, \
                 verbatim — nothing to decide: drop -read_only_relocs or link an image \
                 (an executable, dylib or bundle)",
                cfg.read_only_relocs.flag_word()
            ),
        });
    }
    // M123: the weak-reference-mismatches policy is a final-image
    // decision — the relocatable output's references ride untouched (no
    // resolve walk prices them), so the advisory faces have no record to
    // derive and the default `error` is a no-op there (the M103/M111
    // pattern — the non-default faces are the refused ones). The
    // re-check backs the driver surface's earlier refusal.
    if cfg.weak_reference_mismatches != crate::resolve::WeakReferenceMismatchesPolicy::Error {
        return Err(LinkError::Layout {
            message: format!(
                "-weak_reference_mismatches {} records the weak/strong reference \
                 mismatch, but the relocatable output's references ride untouched — \
                 nothing to record: drop -weak_reference_mismatches or link an image \
                 (an executable, dylib or bundle)",
                cfg.weak_reference_mismatches.flag_word()
            ),
        });
    }
    if cfg.dylibs.iter().any(|d| d.hidden) {
        return Err(LinkError::Layout {
            message: "-hidden_library/-hidden_framework/-hidden-l marks a dylib to ride \
                      without its load command, but the relocatable output opens its \
                      undefineds by design and carries no load commands to drop — link \
                      a segmented output (an executable, dylib or bundle) or drop the \
                      hidden marks"
                .into(),
        });
    }
    // M112: the link-statistics report is a final-image decision — the
    // relocatable output has no full-emit layout or fixup planning to
    // report in the same way (its sections are the input's, verbatim;
    // the object walk plans no segments, no fixup slots and emits no
    // image the report's counts name). The re-check backs the driver
    // surface's earlier refusal: no library caller can plan the shape
    // either (the M104/M105 pattern).
    if cfg.print_statistics {
        return Err(LinkError::Layout {
            message: "-print_statistics reports the link's statistics, but the relocatable \
                      output has no full-emit layout or fixup planning to report in the \
                      same way — drop -print_statistics or link an image (an executable, \
                      dylib or bundle)"
                .into(),
        });
    }
    // M113: the reference trace is a resolve-shaping decision — the
    // relocatable output's symtab is the input's, verbatim (its symbol
    // table rides the inputs untouched; there is no Pass-2 trace to
    // report). The re-check backs the driver surface's earlier refusal:
    // no library caller can plan the shape either (the
    // M104/M105/M112 pattern).
    if cfg.trace_refs {
        return Err(LinkError::Layout {
            message: "-t traces the symbols Pass 2's resolve references, but the \
                      relocatable output's symtab is the input's, verbatim — nothing to \
                      trace: drop -t or link an image (an executable, dylib or bundle)"
                .into(),
        });
    }
    // M116: the common-symbol advisory is a resolve-record decision —
    // the relocatable output's symtab is the input's, verbatim (its
    // symbol table rides the inputs untouched; there is no resolution
    // landing to advise about). The re-check backs the driver surface's
    // earlier refusal: no library caller can plan the shape either (the
    // M104/M105/M112 pattern).
    if cfg.warn_commons {
        return Err(LinkError::Layout {
            message: "-warn_commons advises where every tentative definition resolved, \
                      but the relocatable output's symtab is the input's, verbatim — \
                      nothing to advise about: drop -warn_commons or link an image (an \
                      executable, dylib or bundle)"
                .into(),
        });
    }
    // M117: the init/term section suppression is a final-image decision
    // — the relocatable output's sections are the input's, verbatim
    // (its sections ride the inputs untouched; there is no init
    // classification to apply). The re-check backs the driver surface's
    // earlier refusal: no library caller can plan the shape either (the
    // M104/M105/M115 pattern).
    if cfg.no_inits {
        return Err(LinkError::Layout {
            message: "-no_inits drops the output's init/term sections (the \
                      __mod_init_func, __mod_term_func and __init_offsets shapes), but \
                      the relocatable output's sections are the input's, verbatim — \
                      nothing to drop: drop -no_inits or link an image (an executable, \
                      dylib or bundle)"
                .into(),
        });
    }
    // M118: the dtrace DOF processing is a final-image decision — the
    // relocatable output's sections are the input's, verbatim (its
    // sections ride the inputs untouched; there is no DOF header to
    // validate at emit). The re-check backs the driver surface's earlier
    // refusal: no library caller can plan the shape either (the
    // M104/M105/M117 pattern).
    if cfg.dtrace {
        return Err(LinkError::Layout {
            message: "-dtrace validates the output's __dtrace_dof (DOF) section \
                      headers and links them into the image, but the relocatable \
                      output's sections are the input's, verbatim — nothing to validate \
                      or assemble: drop -dtrace or link an image (an executable, dylib \
                      or bundle)"
                .into(),
        });
    }
    // M119: the dylib module contract is a final-image decision — the
    // relocatable output's symtab is the input's, verbatim (its sections
    // and tables ride the inputs untouched; there is no LC_DYSYMTAB
    // module table to shape, no single-module escalation to apply). The
    // re-check backs the driver surface's earlier refusal: no library
    // caller can plan the shape either (the M104/M105/M117 pattern).
    if cfg.module_policy.is_single() {
        return Err(LinkError::Layout {
            message: "-single_module shapes the output's LC_DYSYMTAB module table \
                      and escalates unresolved strong references, but the relocatable \
                      output's symtab is the input's, verbatim — nothing to shape or \
                      escalate: drop -single_module or link an image (an executable, \
                      dylib or bundle)"
                .into(),
        });
    }
    // M120: `-executable` forces an `MH_EXECUTE` output — `link_reloc` is
    // the `-r` path whose `MH_OBJECT` is the input's filetype verbatim. The
    // re-check backs the driver surface's earlier refusal: no library
    // caller can plan the shape either (the M104/M105/M117 pattern).
    if cfg.executable {
        return Err(LinkError::Layout {
            message: "-executable forces an MH_EXECUTE output, but link_reloc is the \
                      -r path whose MH_OBJECT preserves the input's filetype verbatim — \
                      drop -executable or drop -r (link an image)"
                .into(),
        });
    }
    // M121: the duplicate-symbol advisory reads the resolution the object
    // path never produces — the relocatable output's symtab is the input's,
    // verbatim (there is no resolution landing to tally). The re-check
    // backs the driver surface's earlier refusal: no library caller can
    // plan the shape either (the M104/M105/M116 pattern).
    if cfg.warn_duplicate {
        return Err(LinkError::Layout {
            message: "-warn_duplicate tallies the duplicate strong definitions found \
                      during resolve, but the relocatable output's symtab is the \
                      input's, verbatim — nothing to tally: drop -warn_duplicate or \
                      link an image (an executable, dylib or bundle)"
                .into(),
        });
    }
    // M28: the section-alignment floors are a packing-engine decision —
    // the relocatable output plans no segments and carries its input
    // sections verbatim, so a named floor has nothing to land on. The
    // re-check backs the driver surface's earlier refusal: no library
    // caller can plan the shape either.
    if !cfg.sect_aligns.is_empty() {
        return Err(LinkError::Layout {
            message: "-sectalign names a packing-engine alignment floor, but the \
                      relocatable output plans no segments and carries its input \
                      sections verbatim — drop -sectalign or link a segmented output"
                .into(),
        });
    }
    // M29: the header-region floor is a packing decision — the
    // relocatable output plans no segments and carries its input
    // sections verbatim, so a named floor has nothing to land on. The
    // re-check backs the driver surface's earlier refusal: no library
    // caller can plan the shape either.
    if cfg.header_pad.is_some() {
        return Err(LinkError::Layout {
            message: "-headerpad reserves the header region the load commands occupy, \
                      but the relocatable output plans no segments and carries its \
                      input sections verbatim — drop -headerpad or link a segmented \
                      output"
                .into(),
        });
    }
    // M38: the install-name auto-floor is the same packing decision —
    // the reserved region has no load commands to grow here. The
    // re-check backs the driver surface's earlier refusal (the M38
    // gate matrix links the relocatable output to prove it).
    if cfg.header_pad_max_install_names {
        return Err(LinkError::Layout {
            message: "-headerpad_max_install_names grows the header region the load \
                      commands occupy, but the relocatable output plans no segments \
                      and carries its input sections verbatim — drop \
                      -headerpad_max_install_names or link a segmented output"
                .into(),
        });
    }
    // M27/M51/M102: the header flag words (`MH_PIE`,
    // `MH_ALLOW_STACK_EXECUTION`, `MH_BINDATLOAD`) are executable-only
    // decisions — the relocatable output carries no loader semantics and
    // plans no header word, so a named knob has no bit to land on. The
    // re-checks back the driver surface's earlier refusals (the M27 and
    // M51 knobs never re-checked here — the relocatable path left them
    // silently inert for a library caller; the M102 decision completes
    // the trio and heals the two holes with it): no library caller can
    // plan the shape either.
    if cfg.no_pie {
        return Err(LinkError::Layout {
            message: "-no_pie clears the executable's MH_PIE flag, but the relocatable \
                      output carries no loader semantics and plans no header word — drop \
                      -no_pie or link an executable"
                .into(),
        });
    }
    // M122: the PIE positive-form twin — the relocatable output carries
    // no header word and no loader semantics, so a named `-pie` has no
    // bit to set (the M27 refusal shape, mirrored exactly).
    if cfg.pie {
        return Err(LinkError::Layout {
            message: "-pie sets the executable's MH_PIE flag, but the relocatable \
                      output carries no loader semantics and plans no header word — drop \
                      -pie or link an executable"
                .into(),
        });
    }
    if cfg.allow_stack_execute {
        return Err(LinkError::Layout {
            message: "-allow_stack_execute sets the executable's MH_ALLOW_STACK_EXECUTION \
                      flag, but the relocatable output carries no loader semantics and \
                      plans no header word — drop -allow_stack_execute or link an \
                      executable"
                .into(),
        });
    }
    if cfg.bind_at_load {
        return Err(LinkError::Layout {
            message: "-bind_at_load sets the executable's MH_BINDATLOAD flag, but the \
                      relocatable output carries no loader semantics and plans no header \
                      word — drop -bind_at_load or link an executable"
                .into(),
        });
    }
    // M104: the symtab-shaping decision's drop face (`-x`) is a final
    // image decision — the relocatable output's symtab is the input's,
    // verbatim (its tables ride the inputs untouched; there is no
    // locals subrange to shape). The keep face is the default's mirror
    // and never refuses. The re-check backs the driver surface's
    // earlier refusal: no library caller can plan the shape either.
    if !cfg.keep_local_symbols {
        return Err(LinkError::Layout {
            message: "-x drops the output's plain local symbols (the symtab's \
                      N_SECT & ~N_EXT rows), but the relocatable output's symtab is \
                      the input's, verbatim — nothing to shape: drop -x or link an \
                      image (an executable, dylib or bundle)"
                .into(),
        });
    }
    // M105: the debug-section suppression's `-S` face is a final image
    // decision — the relocatable output's sections are the input's,
    // verbatim (its sections ride the inputs untouched; there is no
    // debug classification to apply). The re-check backs the driver
    // surface's earlier refusal: no library caller can plan the shape
    // either.
    if cfg.strip_debug {
        return Err(LinkError::Layout {
            message: "-S drops the output's debug sections (the __DWARF segments, \
                      the __debug_* and S_ATTR_DEBUG shapes), but the relocatable \
                      output's sections are the input's, verbatim — nothing to \
                      strip: drop -S or link an image (an executable, dylib or \
                      bundle)"
                .into(),
        });
    }
    // M103: the non-escalating undefined policies are a load-time-bind
    // exit decision — the relocatable output's undefineds stay open in
    // its symbol table by design (an object carries no load-time bind to
    // warn or suppress). The re-check backs the driver surface's earlier
    // refusal: no library caller can plan the shape either.
    if matches!(
        cfg.undefined_policy,
        crate::resolve::UndefinedPolicy::Warning | crate::resolve::UndefinedPolicy::Suppress
    ) {
        return Err(LinkError::Layout {
            message: "-undefined warning|suppress names the load-time bind's exit policy, \
                      but the relocatable output's undefineds stay open by design — an \
                      object has no load-time bind to warn or suppress: drop -undefined \
                      or link an image (an executable, dylib or bundle)"
                .into(),
        });
    }
    // M39: the make-undefined marks are a Pass-2 decision — the
    // relocatable output opens its undefineds by design and carries its
    // input symbol table verbatim, so a mark has nothing to strip. The
    // re-check backs the driver surface's earlier refusal: no library
    // caller can plan the shape either.
    if !cfg.make_undefined.is_empty() {
        return Err(LinkError::Layout {
            message: "-U marks a defined symbol undefined, but the relocatable output \
                      opens its undefineds by design and carries its input symbol table \
                      verbatim — nothing to strip: drop -U or link an image (an \
                      executable, dylib or bundle)"
                .into(),
        });
    }
    // M40: the export-trie suppression is a header-assembly decision —
    // the relocatable output carries no __LINKEDIT commands at all, so
    // a named suppression has no command to drop. The re-check backs
    // the driver surface's earlier refusal: no library caller can plan
    // the shape either.
    if !cfg.exported_symbols {
        return Err(LinkError::Layout {
            message: "-no_exported_symbols drops the output's LC_DYLD_EXPORTS_TRIE, but \
                      the relocatable output carries no __LINKEDIT commands at all — \
                      drop -no_exported_symbols or link an executable"
                .into(),
        });
    }
    // M46: the export-dynamic roots are an executable decision — the
    // relocatable output strips nothing (its symbol table is the
    // input's, verbatim), so a named knob has nothing to widen. The
    // re-check backs the driver surface's earlier refusal: no library
    // caller can plan the shape either.
    if cfg.export_dynamic {
        return Err(LinkError::Layout {
            message: "-export_dynamic preserves global symbols during dead stripping, but \
                      the relocatable output strips nothing — the object's symbol table \
                      is the input's, verbatim: drop -export_dynamic or link an \
                      executable"
                .into(),
        });
    }
    // M48: the dylib initializer is a dylib decision — the relocatable
    // output carries no load commands at all, so a named `-init` has no
    // command to land on. The re-check backs the driver surface's
    // earlier refusal: no library caller can plan the shape either.
    if cfg.init_symbol.is_some() {
        return Err(LinkError::Layout {
            message: "-init names a load-time initializer dyld calls when the image loads, \
                      but the relocatable output carries no load commands — drop -init \
                      or link a dylib"
                .into(),
        });
    }
    // M98: the dylib terminator is a dylib decision — the relocatable
    // output carries no load commands at all, so a named `-term` has no
    // command to land on (the same shape the M48 re-check rides, one
    // field over). The re-check backs the driver surface's earlier
    // refusal: no library caller can plan the shape either.
    if cfg.term_symbol.is_some() {
        return Err(LinkError::Layout {
            message: "-term names a load-time terminator dyld calls when the image unloads, \
                      but the relocatable output carries no load commands — drop -term \
                      or link a dylib"
                .into(),
        });
    }
    // M99/M114: the named output UUID's and the random source's
    // relocatable refusals — the object carries no `LC_UUID` command at
    // all (the M32 shape), so a named value and a random draw have no
    // field to land on. The re-check backs the driver surface's earlier
    // refusals: no library caller can plan the shape either. (The
    // `-no_uuid` pair refusal is the layout's — the relocatable output
    // never reaches a uuid field to patch.)
    if cfg.named_uuid.is_some() {
        return Err(LinkError::Layout {
            message: "-uuid names the output's LC_UUID identity, but the relocatable \
                      output carries no LC_UUID command at all — drop -uuid or link an \
                      executable/dylib/bundle"
                .into(),
        });
    }
    if cfg.uuid_source == crate::layout::UuidSource::Random {
        return Err(LinkError::Layout {
            message: "-random_uuid generates the output's LC_UUID identity, but the \
                      relocatable output carries no LC_UUID command at all — drop \
                      -random_uuid or link an executable/dylib/bundle"
                .into(),
        });
    }
    // M115: the category-merge disable's relocatable refusal — the
    // object's sections are the input's, verbatim (the re-check backs
    // the driver surface so no library caller plans the shape either).
    if !cfg.objc_category_merging {
        return Err(LinkError::Layout {
            message: "-no_objc_category_merging keeps every category's registration \
                      verbatim, but the relocatable output's sections are the input's, \
                      verbatim already — drop -no_objc_category_merging or link an \
                      image (an executable, dylib or bundle)"
                .into(),
        });
    }
    let parse_started = Instant::now();
    let objects = parse_inputs(inputs, parallel, cfg.dead_strip, None, &mut observer)?;
    emit_phase(
        &mut observer,
        Phase::Parse,
        PhaseDetail::Objects {
            inputs: objects.len(),
        },
        parse_started.elapsed(),
    );
    let (objects, interner, _export_ids, _loader_ids, loads) =
        pull_and_intern(objects, archives, cfg, parallel, None, false, &mut observer)?;
    let resolve_started = Instant::now();
    let mut res = Resolution::default();
    // M113: the relocatable walk never carries the trace face — the knob
    // is refused above (the object's symtab is the input's, verbatim);
    // the slot rides `None` by construction here.
    res.install(&objects, &interner, cfg.multiply_defined, &mut None)?;
    // M108: the default policy's walk product (the non-default faces the
    // re-check above refused) — the record faces derive nothing under
    // `error`; the call keeps the relocatable path's contract symmetric
    // with the image path's (the install site's escalation is the
    // product, the walk is the record faces' advisory).
    res.apply_multiply_defined_policy(cfg.multiply_defined, &interner, &objects)?;
    // M121: the advisory walk keeps the relocatable path's contract
    // symmetric with the image path's — the re-check above refused the
    // knob (the object's symtab is the input's, verbatim), so under the
    // default the call records nothing; the symmetry holds for any caller
    // the re-check admits.
    res.apply_warn_duplicate(cfg.warn_duplicate, &interner, &objects);
    // M123: the advisory walk keeps the relocatable path's contract
    // symmetric with the image path's — the re-check above refused the
    // non-default faces (the object's symtab is the input's, verbatim),
    // so under the default the call records the same mismatches the
    // image path would; the symmetry holds for any caller the re-check
    // admits.
    res.apply_weak_reference_mismatches(cfg.weak_reference_mismatches, &interner, &objects);
    emit_phase(
        &mut observer,
        Phase::Resolve,
        PhaseDetail::Winners { reused: false },
        resolve_started.elapsed(),
    );
    emit_phase(
        &mut observer,
        Phase::Reloc,
        PhaseDetail::Reloc {
            inputs: inputs.len(),
        },
        reloc_started.elapsed(),
    );
    tracing::debug!(
        objects = objects.len(),
        "the relocatable front half finished (undefineds stay open)"
    );
    Ok(RelocLink {
        objects,
        interner,
        resolution: res,
        loads,
    })
}

/// Emits one phase completion through the observer slot (`None` = the
/// historical silence — the seam costs nothing when nobody subscribes).
fn emit_phase(
    observer: &mut Option<&mut dyn LinkObserver>,
    phase: Phase,
    detail: PhaseDetail,
    elapsed: Duration,
) {
    if let Some(obs) = observer.as_deref_mut() {
        obs.on_phase(PhaseEvent {
            phase,
            detail,
            elapsed,
        });
    }
}

/// Emits one pipeline note through the observer slot (the ladder's
/// silent-correct rungs, made visible).
fn emit_note(observer: &mut Option<&mut dyn LinkObserver>, note: LinkNote) {
    if let Some(obs) = observer.as_deref_mut() {
        obs.on_note(note);
    }
}

/// Emits one intra-phase task through the observer slot (the M63 task
/// seam — the parse pool's per-input work, reported by the thread that
/// ran it; `None` = the historical silence, the seam costs nothing when
/// nobody subscribes).
fn emit_task(observer: &mut Option<&mut dyn LinkObserver>, task: TaskEvent) {
    if let Some(obs) = observer.as_deref_mut() {
        obs.on_task(task);
    }
}

/// Pass 1 over the input files. `Auto` schedules **LPT** (longest input
/// first — perf doc §4.1) on the shared pool; the results land at their
/// command-line indices either way, and errors surface in command-line
/// order, so the schedule never changes the outcome.
///
/// M63: each input's parse rides the task seam — one [`TaskEvent`] per
/// input when an observer subscribes (a cache hit is still a completed
/// task: the load is the work the consumer waited on). The pool threads
/// cannot borrow the caller's observer slot, so the parallel path reports
/// through a channel (opened only when a subscriber rides) and the caller
/// forwards the records once the pool returns; each record carries its own
/// arrival clock and thread, so the timeline's lane registry and µs bounds
/// stay the worker's own (a drain-time re-stamp would end every worker's
/// span at the drain).
fn parse_inputs(
    inputs: &[LinkInput],
    parallel: Parallelism,
    split_symbols: bool,
    cache: Option<&crate::cache::PoiCache>,
    observer: &mut Option<&mut dyn LinkObserver>,
) -> Result<Vec<InputObject>, LinkError> {
    // M6 Stage A: the cache key is per-input content + the parse flag.
    let keys: Vec<[u8; 32]> = inputs
        .iter()
        .map(|i| crate::cache::PoiCache::content_key(&i.bytes, split_symbols))
        .collect();
    let mut objects: Vec<Option<InputObject>> = (0..inputs.len()).map(|_| None).collect();
    if parallel.is_parallel() && inputs.len() > 1 {
        // LPT: biggest file first so the pool tail is filled by small files.
        let mut order: Vec<usize> = (0..inputs.len()).collect();
        order.sort_by(|&a, &b| {
            inputs[b]
                .bytes
                .len()
                .cmp(&inputs[a].bytes.len())
                .then(a.cmp(&b))
        });
        let mut task_tx: Option<std::sync::mpsc::Sender<TaskEvent>> = None;
        let mut task_rx: Option<std::sync::mpsc::Receiver<TaskEvent>> = None;
        if observer.is_some() {
            let (tx, rx) = std::sync::mpsc::channel();
            task_tx = Some(tx);
            task_rx = Some(rx);
        }
        let parsed: Vec<Result<InputObject, LinkError>> = pool::compute_pool().install(|| {
            order
                .par_iter()
                .map(|&i| {
                    let started = Instant::now();
                    let obj = if let Some(cache) = cache
                        && let Some(hit) = cache.load(
                            &keys[i],
                            FileId(i as u32),
                            &inputs[i].name,
                            inputs[i].bytes.clone(),
                            split_symbols,
                        ) {
                        hit
                    } else {
                        let parsed = InputObject::parse(
                            FileId(i as u32),
                            &inputs[i].name,
                            inputs[i].bytes.clone(),
                        )?;
                        if let Some(cache) = cache {
                            cache.store(&keys[i], &parsed, split_symbols);
                        }
                        parsed
                    };
                    if let Some(tx) = task_tx.as_ref() {
                        let _ = tx.send(TaskEvent {
                            phase: Phase::Parse,
                            label: inputs[i].name.clone(),
                            elapsed: started.elapsed(),
                            at: Instant::now(),
                            thread: std::thread::current().id(),
                        });
                    }
                    Ok(obj)
                })
                .collect()
        });
        if let Some(rx) = task_rx {
            drop(task_tx);
            for task in rx {
                emit_task(observer, task);
            }
        }
        for (slot, obj) in order.iter().zip(parsed) {
            objects[*slot] = Some(obj?);
        }
    } else {
        for (i, input) in inputs.iter().enumerate() {
            let started = Instant::now();
            let obj = if let Some(cache) = cache
                && let Some(hit) = cache.load(
                    &keys[i],
                    FileId(i as u32),
                    &input.name,
                    input.bytes.clone(),
                    split_symbols,
                ) {
                hit
            } else {
                let parsed =
                    InputObject::parse(FileId(i as u32), &input.name, input.bytes.clone())?;
                if let Some(cache) = cache {
                    cache.store(&keys[i], &parsed, split_symbols);
                }
                parsed
            };
            emit_task(
                observer,
                TaskEvent {
                    phase: Phase::Parse,
                    label: input.name.clone(),
                    elapsed: started.elapsed(),
                    at: Instant::now(),
                    thread: std::thread::current().id(),
                },
            );
            objects[i] = Some(obj);
        }
    }
    // M5/D1+D4: fill the atom tables (cstring sections always split for
    // the merge; symbol-boundary splitting only feeds dead-strip).
    for obj in objects.iter_mut().flatten() {
        obj.compute_atoms(split_symbols);
    }
    Ok(objects.into_iter().map(Option::unwrap).collect())
}

/// The S7 archive pull fixpoint (M5). Seeds the unresolved-name set from the
/// direct objects (weak references do not pull — ld64 semantics), then walks
/// the archive indexes in command-line order until nothing new pulls. Only
/// pulled members are parsed, so an archive-heavy link pays for the members
/// it uses, not the members it ships (`-all_load`/`-force_load` parse all).
///
/// Determinism: archives are scanned in command order, members in index
/// order; `FileIds` continue after the direct inputs in pull order.
fn pull_archive_members(
    direct: &[InputObject],
    archives: &[LinkArchive],
    cfg: &LinkConfig,
    cache: Option<&crate::cache::PoiCache>,
) -> Result<(Vec<InputObject>, crate::provenance::LoadReport), LinkError> {
    let mut loads = crate::provenance::LoadReport::default();
    if archives.is_empty() {
        return Ok((Vec::new(), loads));
    }
    let mut defined: HashSet<Vec<u8>> = HashSet::new();
    let mut undefined: HashSet<Vec<u8>> = HashSet::new();
    for obj in direct {
        let names = obj.peek_symbol_names();
        for (i, sym) in obj.symbols.iter().enumerate() {
            if sym.stab || !sym.external {
                continue;
            }
            let Some(name) = names.get(i) else {
                continue;
            };
            if sym.is_defined() || sym.is_common() {
                defined.insert(name.clone());
            } else if sym.is_undefined() && !sym.weak_ref {
                undefined.insert(name.clone());
            }
        }
    }
    // `-u` names are liveness roots: a member defining one is pulled.
    for sym in &cfg.load_symbols {
        undefined.insert(sym.clone());
    }

    let mut pulled: Vec<InputObject> = Vec::new();
    let mut pulled_set: HashSet<(usize, u64)> = HashSet::new();
    let base_file = direct.len() as u32;

    // Eager path: `-all_load` / `-force_load` archives contribute every
    // member in file order.
    for (ai, arch) in archives.iter().enumerate() {
        if !arch.all_load {
            continue;
        }
        for member in &arch.members {
            if !pulled_set.insert((ai, member.offset)) {
                continue;
            }
            let obj = parse_member(
                arch,
                member,
                base_file + pulled.len() as u32,
                cfg.dead_strip,
                cache,
            )?;
            record_names(&obj, &mut defined, &mut undefined);
            loads
                .members
                .push(member_row(arch, member, &obj, LoadDecision::AllLoad));
            pulled.push(obj);
        }
    }

    // M43 eager path: the `-ObjC` pull (ld64's man-page rule — members
    // implementing an Objective-C class or category ride without a
    // reference, because the ObjC runtime registers the metadata by
    // section address at load time and no static reference exists to
    // seed the fixpoint). The scan rides the ranlib index every link
    // already parsed — a member whose index entry names a class,
    // metaclass or category metadata symbol joins the pull — and the
    // members ride in member file order, the same determinism the
    // `-all_load` path keeps. The pulled members' own names feed the
    // fixpoint below (a category pulls its class's provider, a member
    // pulls its own providers). Archives under `-all_load`/`-force_load`
    // skip the pass: the eager pass above already carries every member.
    if cfg.objc {
        let span = tracing::info_span!("objc_pull", archives = archives.len());
        let _entered = span.enter();
        for (ai, arch) in archives.iter().enumerate() {
            if arch.all_load {
                continue;
            }
            let metadata_members: Vec<u32> = {
                let mut members: Vec<u32> = arch
                    .index
                    .iter()
                    .filter(|(name, _)| crate::objc::defines_objc_metadata(name))
                    .map(|(_, member)| *member)
                    .collect();
                members.sort_unstable();
                members.dedup();
                members
            };
            for member_index in &metadata_members {
                let Some(member) = arch.members.get(*member_index as usize) else {
                    return Err(LinkError::Internal {
                        message: format!(
                            "archive {}: index entry points at member {} of {}",
                            arch.name,
                            member_index,
                            arch.members.len()
                        ),
                    });
                };
                if !pulled_set.insert((ai, member.offset)) {
                    continue;
                }
                let obj = parse_member(
                    arch,
                    member,
                    base_file + pulled.len() as u32,
                    cfg.dead_strip,
                    cache,
                )?;
                record_names(&obj, &mut defined, &mut undefined);
                loads
                    .members
                    .push(member_row(arch, member, &obj, LoadDecision::ObjcMetadata));
                pulled.push(obj);
            }
            tracing::debug!(
                archive = %arch.name,
                pulled = metadata_members.len(),
                "the -ObjC pull named the metadata members"
            );
        }
    }

    // Lazy fixpoint: scan indexes in archive command order; a member is
    // pulled when it defines a still-unresolved name.
    loop {
        let mut changed = false;
        for (ai, arch) in archives.iter().enumerate() {
            for (name, member_index) in &arch.index {
                if !undefined.contains(name) || defined.contains(name) {
                    continue;
                }
                let Some(member) = arch.members.get(*member_index as usize) else {
                    return Err(LinkError::Internal {
                        message: format!(
                            "archive {}: index entry points at member {} of {}",
                            arch.name,
                            member_index,
                            arch.members.len()
                        ),
                    });
                };
                if !pulled_set.insert((ai, member.offset)) {
                    continue;
                }
                let obj = parse_member(
                    arch,
                    member,
                    base_file + pulled.len() as u32,
                    cfg.dead_strip,
                    cache,
                )?;
                record_names(&obj, &mut defined, &mut undefined);
                loads.members.push(member_row(
                    arch,
                    member,
                    &obj,
                    LoadDecision::Reference {
                        seed: String::from_utf8_lossy(name).into_owned(),
                    },
                ));
                pulled.push(obj);
                changed = true;
            }
        }
        if !changed {
            return Ok((pulled, loads));
        }
    }
}

/// The M57 load-provenance row for one pulled member: the decision that
/// admitted it plus the symbol surface its own symtab already carried —
/// the pass computed both on its way to `record_names`; the record
/// re-derives nothing.
fn member_row(
    arch: &LinkArchive,
    member: &LinkArchiveMember,
    obj: &InputObject,
    decision: LoadDecision,
) -> LoadExplanation {
    let names = obj.peek_symbol_names();
    let mut definitions = Vec::new();
    let mut opened = Vec::new();
    for (i, sym) in obj.symbols.iter().enumerate() {
        if sym.stab || !sym.external {
            continue;
        }
        let Some(name) = names.get(i) else {
            continue;
        };
        let name = String::from_utf8_lossy(name).into_owned();
        if sym.is_defined() || sym.is_common() {
            definitions.push(name);
        } else if sym.is_undefined() {
            opened.push(name);
        }
    }
    LoadExplanation {
        archive: arch.name.clone(),
        member: member.name.clone(),
        decision,
        definitions,
        opened,
    }
}

/// Parses one archive member as an [`InputObject`] (ranked below direct
/// inputs — see [`crate::resolve::Rank::ArchiveStrong`]).
fn parse_member(
    arch: &LinkArchive,
    member: &LinkArchiveMember,
    file: u32,
    split_symbols: bool,
    cache: Option<&crate::cache::PoiCache>,
) -> Result<InputObject, LinkError> {
    let start = member.offset as usize;
    let end = start
        .checked_add(member.size as usize)
        .ok_or_else(|| LinkError::Internal {
            message: format!("archive {} member {} overflows", arch.name, member.name),
        })?;
    let bytes = arch
        .bytes
        .get(start..end)
        .ok_or_else(|| LinkError::Internal {
            message: format!(
                "archive {} member {} span {}..{} is out of bounds",
                arch.name, member.name, start, end
            ),
        })?
        .to_vec();
    let name = format!("{}({})", arch.name, member.name);
    if let Some(cache) = cache {
        let key = crate::cache::PoiCache::content_key(&bytes, split_symbols);
        if let Some(mut hit) = cache.load(&key, FileId(file), &name, bytes.clone(), split_symbols) {
            hit.from_archive = true;
            hit.archive_name.clone_from(&arch.name);
            return Ok(hit);
        }
    }
    let mut obj = InputObject::parse(FileId(file), &name, bytes)?;
    obj.from_archive = true;
    obj.archive_name.clone_from(&arch.name);
    obj.compute_atoms(split_symbols);
    if let Some(cache) = cache {
        let key = crate::cache::PoiCache::content_key(&obj.bytes, split_symbols);
        cache.store(&key, &obj, split_symbols);
    }
    Ok(obj)
}

/// Feeds one parsed member's defined/undefined names into the fixpoint sets.
fn record_names(
    obj: &InputObject,
    defined: &mut HashSet<Vec<u8>>,
    undefined: &mut HashSet<Vec<u8>>,
) {
    let names = obj.peek_symbol_names();
    for (i, sym) in obj.symbols.iter().enumerate() {
        if sym.stab || !sym.external {
            continue;
        }
        let Some(name) = names.get(i) else {
            continue;
        };
        if sym.is_defined() || sym.is_common() {
            defined.insert(name.clone());
            undefined.remove(name);
        } else if sym.is_undefined() && !sym.weak_ref {
            undefined.insert(name.clone());
        }
    }
}

/// The `-u` gate (M5 semantics, shared by the driver's one-shot path and the
/// M8 resident server): every named symbol must resolve to an **in-image**
/// definition. Archive members pulled for the name count (the name also
/// seeds the pull fixpoint, so a member defining it is present).
///
/// # Errors
/// [`LinkError::Symbol`] naming the first missing symbol.
pub fn check_load_symbols(result: &LinkResult, names: &[Vec<u8>]) -> Result<(), LinkError> {
    for sym in names {
        let defined = result.layout.symbols.iter().any(|s| {
            s.external
                && s.n_type & pgr_format::consts::N_TYPE != pgr_format::consts::N_UNDF
                && result.interner.bytes(s.name) == sym.as_slice()
        });
        if !defined {
            return Err(LinkError::Symbol {
                name: String::from_utf8_lossy(sym).into_owned(),
                message: format!(
                    "-u {}: symbol is not defined by any input (direct objects or pulled \
                     archive members)",
                    String::from_utf8_lossy(sym)
                ),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{LinkArchive, LinkArchiveMember, LinkConfig, LinkInput, link};
    use crate::LinkError;
    use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

    /// hello.o: _main calls _greet (BL), references _msg (ADRP+ADD).
    fn hello_main() -> ObjectBuilder {
        // adrp x0, _msg@page
        let mut text: Vec<u8> = 0x9000_0000u32.to_le_bytes().to_vec();
        text.extend_from_slice(&0x9100_0000u32.to_le_bytes()); // add x0, x0, #msg@pageoff
        text.extend_from_slice(&0x9400_0000u32.to_le_bytes()); // bl _greet
        text.extend_from_slice(&0x5280_0000u32.to_le_bytes()); // mov w0, #0
        text.extend_from_slice(&0xD65F_03C0u32.to_le_bytes()); // ret
        let mut b = ObjectBuilder::new("hello.o");
        let sect = b.add_section(ObjectSection::text(
            "__text",
            text,
            vec![
                ObjectReloc::addend(0).at(0),
                ObjectReloc::page21(1).at(0),
                ObjectReloc::addend(0).at(4),
                ObjectReloc::pageoff12(1).at(4),
                ObjectReloc::branch26(2).at(8),
            ],
        ));
        b.add_section(ObjectSection::cstring("hello, peregrine\n"));
        b.add_symbol(ObjectSymbol::Defined {
            name: "_main".into(),
            section_index: sect,
            value: 0,
            weak: false,
        });
        b.add_symbol(ObjectSymbol::Defined {
            name: "_msg".into(),
            section_index: 1,
            value: 0,
            weak: false,
        });
        b.add_symbol(ObjectSymbol::Undefined {
            name: "_greet".into(),
            weak_ref: false,
        });
        b
    }

    /// greet.o: _greet body + __data pointer to _main (chained rebase).
    fn greet() -> ObjectBuilder {
        let mut b = ObjectBuilder::new("greet.o");
        let text = b.add_section(ObjectSection::text(
            "__text",
            vec![
                0x91, 0x00, 0x00, 0x00, // add x0, x0, #0 (placeholder imm12)
                0xC0, 0x03, 0x5F, 0xD6, // ret
            ],
            vec![],
        ));
        let data = b.add_section(ObjectSection::data(
            "__data",
            vec![0u8; 8],
            vec![ObjectReloc::unsigned(0).at(0)],
        ));
        let _ = data;
        b.add_symbol(ObjectSymbol::Defined {
            name: "_greet".into(),
            section_index: text,
            value: 0,
            weak: false,
        });
        b.add_symbol(ObjectSymbol::Defined {
            name: "_main_ptr".into(),
            section_index: 1,
            value: 0,
            weak: false,
        });
        b
    }

    #[test]
    fn hello_world_layout_converges() {
        let main = hello_main().build().unwrap();
        let greet = greet().build().unwrap();
        let cfg = LinkConfig {
            ident: "hello".into(),
            ..LinkConfig::default()
        };
        let layout = link(
            &[
                LinkInput {
                    name: "hello.o".into(),
                    bytes: main,
                },
                LinkInput {
                    name: "greet.o".into(),
                    bytes: greet,
                },
            ],
            &[],
            &cfg,
        );
        let layout = match layout {
            Ok(l) => l.layout,
            Err(e) => panic!("link failed: {e:?}"),
        };

        // Segments: five, canonical order, constant delta.
        assert_eq!(layout.segments.len(), 5);
        let names: Vec<&str> = layout.segments.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "__PAGEZERO",
                "__TEXT",
                "__DATA_CONST",
                "__DATA",
                "__LINKEDIT"
            ]
        );
        for seg in &layout.segments[1..] {
            assert_eq!(seg.vmaddr - seg.fileoff, 0x1_0000_0000, "{}", seg.name);
            assert_eq!(seg.fileoff % 0x4000, 0, "{} fileoff", seg.name);
            assert_eq!(seg.vmaddr % 0x4000, 0, "{} vmaddr", seg.name);
        }
        // Entry at _main (first piece of __text): entryoff == the __text
        // file offset (right after the header page region).
        let text_file_off = layout
            .sections
            .iter()
            .find(|s| s.name == "__text")
            .map_or(u64::MAX, |s| s.file_off);
        assert_eq!(layout.entryoff, text_file_off);
        // One fixup slot: greet.o's __data pointer to _main.
        assert_eq!(layout.fixups.slot_count, 1);
        // __chain_starts mirror: one head.
        assert_eq!(layout.fixups.chain_starts.len(), 12);
        // File size: signature last.
        assert_eq!(
            layout.linkedit.sig_off + layout.linkedit.sig_size,
            layout.file_size
        );
    }

    /// hello.o alone: _greet is never defined.
    fn hello_main_only() -> ObjectBuilder {
        let text: Vec<u8> = [
            0x9000_0000u32, // adrp x0, _msg@page
            0x9100_0000u32, // add x0, x0, #msg@pageoff
            0x9400_0000u32, // bl _greet
            0x5280_0000u32, // mov w0, #0
            0xD65F_03C0u32, // ret
        ]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
        let mut b = ObjectBuilder::new("hello.o");
        let sect = b.add_section(ObjectSection::text(
            "__text",
            text,
            vec![ObjectReloc::branch26(1).at(8)],
        ));
        b.add_symbol(ObjectSymbol::Defined {
            name: "_main".into(),
            section_index: sect,
            value: 0,
            weak: false,
        });
        b.add_symbol(ObjectSymbol::Undefined {
            name: "_greet".into(),
            weak_ref: false,
        });
        b
    }

    #[test]
    fn undefined_symbol_errors() {
        let main = hello_main_only().build().unwrap();
        let cfg = LinkConfig::default();
        let err = link(
            &[LinkInput {
                name: "hello.o".into(),
                bytes: main,
            }],
            &[],
            &cfg,
        )
        .unwrap_err();
        assert!(matches!(err, LinkError::Symbol { .. }));
        assert!(err.to_string().contains("_greet"), "{err}");
    }

    #[test]
    fn missing_entry_errors() {
        let bytes = greet().build().unwrap();
        let cfg = LinkConfig::default();
        let err = link(
            &[LinkInput {
                name: "greet.o".into(),
                bytes,
            }],
            &[],
            &cfg,
        )
        .unwrap_err();
        assert!(err.to_string().contains("_main"), "{err}");
    }

    /// S7: a member is pulled when it defines an unresolved name — the
    /// hello/greet pair through an archive instead of direct inputs.
    #[test]
    fn archive_member_is_pulled_for_an_unresolved_name() {
        let main = hello_main_only().build().unwrap();
        let greet = greet().build().unwrap();
        let unused = {
            let mut b = ObjectBuilder::new("unused.o");
            let t = b.add_section(ObjectSection::text(
                "__text",
                vec![0xC0, 0x03, 0x5F, 0xD6],
                Vec::new(),
            ));
            b.add_symbol(ObjectSymbol::Defined {
                name: "_unused".into(),
                section_index: t,
                value: 0,
                weak: false,
            });
            b.build().unwrap()
        };
        let mut archive = pgr_fixtures::ArchiveBuilder::new("libutil.a");
        archive.add_member("greet.o", greet);
        archive.add_member("unused.o", unused);
        let bytes = archive.build();
        let parsed = pgr_format::parse_archive(&bytes).unwrap();
        let arch = LinkArchive {
            name: "libutil.a".into(),
            bytes,
            index: parsed
                .index
                .iter()
                .map(|e| (e.name.clone().into_bytes(), e.member))
                .collect(),
            members: parsed
                .members
                .iter()
                .map(|m| LinkArchiveMember {
                    name: m.name.clone(),
                    offset: m.offset,
                    size: m.size,
                })
                .collect(),
            all_load: false,
        };
        let cfg = LinkConfig {
            ident: "hello".into(),
            ..LinkConfig::default()
        };
        let result = link(
            &[LinkInput {
                name: "hello.o".into(),
                bytes: main,
            }],
            &[arch],
            &cfg,
        )
        .unwrap();
        // greet.o pulled, unused.o not: exactly 2 objects in the arena.
        assert_eq!(
            result.objects.len(),
            2,
            "{:?}",
            result
                .objects
                .iter()
                .map(|o| (&o.name, o.from_archive))
                .collect::<Vec<_>>()
        );
        assert!(result.objects[1].from_archive);
    }
}
