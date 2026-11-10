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
use crate::pool;
use crate::resolve::Resolution;
use rayon::prelude::*;
use std::collections::HashSet;

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
/// (Pass 4 needs the input bytes for the section copies).
#[derive(Debug)]
pub struct LinkResult {
    /// The layout plan (Pass 3).
    pub layout: Layout,
    /// Parsed input objects (Pass 1 arenas; Pass 4 copies from these).
    pub objects: Vec<InputObject>,
    /// The interner (name diagnostics for driver-side checks).
    pub interner: Interner,
    /// The Pass-2 snapshot ([`crate::resolve::ResolutionSnapshot`])
    /// captured when [`LinkConfig::record_resolution`] is set — the
    /// record-side half of the M9 resolve wiring (the link record's v5
    /// section). `None` on every clean link.
    pub resolve_snapshot: Option<crate::resolve::ResolutionSnapshot>,
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
    // ---- Pass 1: parse & collect names for the interner --------------------
    // M11: an order file ranks symbols — the atom split feeds it the same
    // way dead-strip does (and rides the same cache-key flag).
    let split_symbols = cfg.dead_strip || cfg.symbol_order.is_some();
    let objects = parse_inputs(inputs, parallel, split_symbols, cache)?;
    link_from_objects(objects, archives, cfg, parallel, cache)
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
    let (objects, interner, export_ids) =
        pull_and_intern(objects, archives, cfg, parallel, cache, true)?;

    // ---- Pass 2: resolution --------------------------------------------------
    // M9 GA rung — the resolve's record-side wiring: a relink whose record
    // vouches a snapshot plans Pass 2 through the recorded decisions
    // (`resolve_reuse`; the replay enforces the undefined policy itself)
    // and falls back to the full install whenever the shape guard or the
    // replay refuses. The fallback is the ladder's bottom rung — always
    // available, always correct, and invisible to the layout (the equality
    // contract is gated in `tests/m9_resolve_reuse.rs`).
    let reused = cfg.resolve_reuse.as_ref().and_then(|seed| {
        match crate::resolve_reuse::plan_reuse(
            &seed.snapshot,
            &seed.digests,
            &interner,
            &objects,
            &cfg.dylibs,
        ) {
            Ok(plan) => {
                match crate::resolve_reuse::install_reused(
                    &plan,
                    &seed.snapshot,
                    &interner,
                    &objects,
                    &cfg.dylibs,
                    cfg.undefined_policy,
                ) {
                    Ok(res) => Some(res),
                    // The shape guard passed but the replay refused an
                    // invariant — a distinct cause from a shape move, and
                    // it used to vanish into the fallback. The ladder's
                    // bottom rung stays silent-correct, not silent-blind:
                    // the refusal names itself on the tracing seam.
                    Err(e) => {
                        tracing::debug!(
                            error = %e,
                            "the resolve-reuse install refused; falling back to the full resolve"
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
                None
            }
        }
    });
    let res = if let Some(reused) = reused {
        reused
    } else {
        let mut full = Resolution::default();
        full.install(&objects)?;
        full.install_dylibs(&cfg.dylibs, &export_ids);
        full.require_all_resolved(&interner, &objects, cfg.undefined_policy)?;
        full
    };
    // The record side: capture the finished Pass-2 state when the caller
    // asked for it (the `-incremental` record), so the v5 record section
    // carries it to the next relink.
    let resolve_snapshot = cfg.record_resolution.then(|| {
        crate::resolve::ResolutionSnapshot::capture(&objects, &interner, &res, &cfg.dylibs)
    });

    // ---- M5/D12 liveness, then M6 ICF over the live text atoms --------------
    let live = crate::deadstrip::compute(&objects, &res, &interner, cfg);
    let fold = crate::icf::fold(&objects, &res, &interner, cfg, &live)?;

    // ---- Pass 3: layout -------------------------------------------------------
    let layout = layout(&objects, &res, &interner, cfg, &live, &fold)?;
    Ok(LinkResult {
        layout,
        objects,
        interner,
        resolve_snapshot,
    })
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
) -> Result<(Vec<InputObject>, Interner, Vec<StringId>), LinkError> {
    // ---- S7 archive liveness (M5): pull only referenced members ------------
    let pulled = pull_archive_members(&objects, archives, cfg, cache)?;
    for obj in pulled {
        objects.push(obj);
    }

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
    // `__mh_execute_header` is always interned so the layout pass can emit
    // the executable's header symbol (ld64/lld convention). The `-r` path
    // never emits one — the object emit consumes the batch without it.
    if intern_header_symbol {
        names.push(b"__mh_execute_header".to_vec());
    }

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
    let export_ids: Vec<StringId> = ids[cursor..cursor + dylib_export_count].to_vec();
    Ok((objects, interner, export_ids))
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
    let span = tracing::info_span!("link_reloc", inputs = inputs.len());
    let _entered = span.enter();
    let objects = parse_inputs(inputs, parallel, cfg.dead_strip, None)?;
    let (objects, interner, _export_ids) =
        pull_and_intern(objects, archives, cfg, parallel, None, false)?;
    let mut res = Resolution::default();
    res.install(&objects)?;
    tracing::debug!(
        objects = objects.len(),
        "the relocatable front half finished (undefineds stay open)"
    );
    Ok(RelocLink {
        objects,
        interner,
        resolution: res,
    })
}

/// Pass 1 over the input files. `Auto` schedules **LPT** (longest input
/// first — perf doc §4.1) on the shared pool; the results land at their
/// command-line indices either way, and errors surface in command-line
/// order, so the schedule never changes the outcome.
fn parse_inputs(
    inputs: &[LinkInput],
    parallel: Parallelism,
    split_symbols: bool,
    cache: Option<&crate::cache::PoiCache>,
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
        let parsed: Vec<Result<InputObject, LinkError>> = pool::compute_pool().install(|| {
            order
                .par_iter()
                .map(|&i| {
                    if let Some(cache) = cache
                        && let Some(hit) = cache.load(
                            &keys[i],
                            FileId(i as u32),
                            &inputs[i].name,
                            inputs[i].bytes.clone(),
                            split_symbols,
                        )
                    {
                        return Ok(hit);
                    }
                    let obj = InputObject::parse(
                        FileId(i as u32),
                        &inputs[i].name,
                        inputs[i].bytes.clone(),
                    )?;
                    if let Some(cache) = cache {
                        cache.store(&keys[i], &obj, split_symbols);
                    }
                    Ok(obj)
                })
                .collect()
        });
        for (slot, obj) in order.iter().zip(parsed) {
            objects[*slot] = Some(obj?);
        }
    } else {
        for (i, input) in inputs.iter().enumerate() {
            if let Some(cache) = cache
                && let Some(hit) = cache.load(
                    &keys[i],
                    FileId(i as u32),
                    &input.name,
                    input.bytes.clone(),
                    split_symbols,
                )
            {
                objects[i] = Some(hit);
                continue;
            }
            let obj = InputObject::parse(FileId(i as u32), &input.name, input.bytes.clone())?;
            if let Some(cache) = cache {
                cache.store(&keys[i], &obj, split_symbols);
            }
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
) -> Result<Vec<InputObject>, LinkError> {
    if archives.is_empty() {
        return Ok(Vec::new());
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
            pulled.push(obj);
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
                pulled.push(obj);
                changed = true;
            }
        }
        if !changed {
            return Ok(pulled);
        }
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
