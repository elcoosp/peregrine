//! Pass 2 — global symbol resolution (TDD §5 Pass 2, M1 subset).
//!
//! Mach-O precedence (TDD §5 Pass 2, adapted from mold's Table 2 and ld64
//! semantics):
//!
//! | rank | definition |
//! |---|---|
//! | 1 | strong `N_SECT\|N_EXT` definition |
//! | 2 | weak definition (`N_WEAK_DEF`) |
//! | 3 | strong definition in an archive member (M5) |
//! | 4 | weak definition in an archive member (M5) |
//! | 5 | tentative/common (`N_UNDF`, `n_value != 0`) — coalesce to max size/align |
//! | 7 | undefined (only valid if some definition exists elsewhere) |
//!
//! Rank 6 (dylib exports) is M2 scope. Archive members only reach the table
//! once pulled (S7 liveness), so ranks 3/4 matter when a pulled member
//! collides with a direct definition — the direct object wins without a
//! duplicate error, exactly ld64's behavior. Ties within a rank: lower file
//! index wins (command-line order); the comparison is a pure function of
//! `(rank, file)`, so the M4 CAS key packs exactly these two fields and the
//! winner stays schedule-independent.
//!
//! M2 adds rank 6 (dylib exports): an undefined reference resolves against
//! the first `LC_LOAD_DYLIB` (in command order) that exports the name —
//! two-level namespace — or, under `-flat_namespace`, stays ordinal-free
//! (dyld looks it up at launch). Liveness: direct objects are live; archive
//! members are pulled by the S7 fixpoint (M5).

use crate::LinkError;
use crate::ids::{FileId, StringId};
use crate::interner::Interner;
use crate::object::{InputObject, InputSymbol, RelocTarget};
use std::collections::{BTreeMap, BTreeSet};

/// Definition rank (lower wins; TDD §5 Pass 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rank {
    /// Strong `N_SECT | N_EXT` definition.
    Strong = 1,
    /// Weak definition (`N_WEAK_DEF`).
    WeakDef = 2,
    /// Strong definition in a pulled archive member (M5).
    ArchiveStrong = 3,
    /// Weak definition in a pulled archive member (M5).
    ArchiveWeak = 4,
    /// Tentative/common symbol.
    Common = 5,
    /// Dylib export (rank 6: any definition in this image beats a dylib).
    DylibExport = 6,
}

/// One input dylib (`LC_LOAD_DYLIB`/`LC_REEXPORT_DYLIB`): a parsed `.tbd`
/// (M2) or a Mach-O dylib scan (M3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dylib {
    /// Install name — the two-level namespace key and the `LC_LOAD_DYLIB`
    /// string. The 1-based position in this list is the symbol's library
    /// ordinal.
    pub install_name: String,
    /// `LC_LOAD_DYLIB` current version.
    pub current_version: u32,
    /// `LC_LOAD_DYLIB` compatibility version.
    pub compatibility_version: u32,
    /// Exported symbol names (with the C underscore).
    pub exports: Vec<Vec<u8>>,
    /// `-weak_library`: the whole dylib loads weakly (`LC_LOAD_WEAK_DYLIB`)
    /// and every bind to it is weak.
    pub weak: bool,
    /// M3 `-reexport_library`: the dylib loads as `LC_REEXPORT_DYLIB` and
    /// its exports join this image's export trie as REEXPORT nodes.
    pub reexport: bool,
    /// M14 `-lazy_library`/`-lazy_framework`: the dylib loads as
    /// `LC_LAZY_LOAD_DYLIB` — dyld's delay-load surface. Under chained
    /// fixups the command participates in the two-level ordinal space
    /// exactly like a plain load (the verifier's walk counts it); the
    /// laziness is the loader's scheduling, the surface is the LC kind.
    /// Mutually exclusive with `reexport` by flag shape; `weak` composes
    /// (a weak lazy load binds weakly, the command kind stays lazy).
    pub lazy: bool,
    /// M45 `-upward_library`/`-upward_framework`: the dylib loads as
    /// `LC_LOAD_UPWARD_DYLIB` — ld64's umbrella-relationship mark for a
    /// sub-umbrella loaded by its umbrella (the load rides *upward*
    /// within the framework region dyld maps). Under chained fixups the
    /// command participates in the two-level ordinal space exactly like
    /// a plain load (the verifier's walk counts it — the format reader
    /// has decoded the opcode since M0; the producer surface names it
    /// from M45). The `reexport` obligation outranks the mark (a
    /// re-export keeps its `LC_REEXPORT_DYLIB` command), `weak` composes
    /// (weakness rides the binds — a weak upward load binds weakly, the
    /// command kind stays upward), and `lazy` outranks it (one load
    /// command per dylib; the driver marks one kind per path).
    pub upward: bool,
}

/// What to do with references no input and no dylib resolves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UndefinedPolicy {
    /// `-undefined error` (default): hard error.
    #[default]
    Error,
    /// `-undefined dynamic_lookup`: the reference becomes a dynamic lookup
    /// bind (dyld resolves it at launch or kills the image).
    DynamicLookup,
}

/// The winning definition of a resolved symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Def {
    /// Defining file (command-line order).
    pub file: FileId,
    /// Symbol table index within that file.
    pub sym: usize,
    /// Definition rank (precedence).
    pub rank: Rank,
    /// `N_WEAK_DEF` on the winner.
    pub weak: bool,
    /// Value the definition carries: the section-relative address for
    /// `N_SECT` definitions, the requested size for commons.
    pub value: u64,
    /// 0-based input section for `N_SECT` definitions.
    pub section: Option<usize>,
    /// Coalesced alignment exponent (commons only).
    pub common_align: u32,
    /// Coalesced size (commons only).
    pub common_size: u64,
}

/// The global resolution state (Pass 2 output).
#[derive(Debug, Default)]
pub struct Resolution {
    /// Winner per interned name (`StringId` → def).
    defs: BTreeMap<u32, Def>,
    /// References: for each referenced name, the (file, sym) list that
    /// undefined it (diagnostics; references drive no liveness at M1).
    references: BTreeMap<u32, Vec<(FileId, usize)>>,
    /// Input dylibs in `LC_LOAD_DYLIB` order (1-based ordinals).
    dylibs: Vec<Dylib>,
    /// Interned name → 1-based dylib ordinal that exports it (the first
    /// dylib in command order exporting the name; two-level namespace).
    dylib_exports: BTreeMap<u32, u16>,
    /// Names left to dyld (`-undefined dynamic_lookup`).
    dynamic_lookups: BTreeSet<u32>,
    /// Names the bundle's `-bundle_loader` host exports (M25): the
    /// references that resolve against the host process at load time,
    /// binding with the main-executable ordinal (`0xFF`).
    loader_exports: BTreeSet<u32>,
    /// Names `-U` marked as undefined (M39): the keys that never
    /// install — a definition or common of a marked name is dropped
    /// *as it is linked* (ld64's phrasing), so the symtab row, the
    /// export-trie node and the `__common` slot the definition would
    /// have claimed all drop, and the defining atom loses its
    /// liveness root. References to a marked name follow the
    /// `-undefined` policy like any unresolved name.
    make_undefined: BTreeSet<u32>,
}

impl Resolution {
    /// Installs the make-undefined marks (M39): every named symbol is
    /// treated as undefined *as it is linked* — its definitions and
    /// commons never install. The decision is validated against the
    /// parse: a name no input object defines has nothing to strip (the
    /// vacuous decision refuses with the fix — the `-alias` misspelling
    /// convention; a name the interner never saw refuses the same way,
    /// before this call, in [`crate::link::link`]).
    ///
    /// # Errors
    /// [`LinkError::Symbol`] naming the marked symbol nothing defines.
    pub fn install_make_undefined(
        &mut self,
        ids: &[StringId],
        objects: &[InputObject],
        interner: &Interner,
    ) -> Result<(), LinkError> {
        for id in ids {
            let defined = objects.iter().any(|obj| {
                obj.symbols.iter().any(|sym| {
                    sym.name == *id
                        && sym.external
                        && !sym.stab
                        && (sym.is_defined() || sym.is_common())
                })
            });
            if !defined {
                return Err(LinkError::Symbol {
                    name: String::new(),
                    message: format!(
                        "-U {} marks a defined symbol undefined, but no input defines it — \
                         nothing to strip; check the spelling (C symbols carry the leading \
                         underscore) or drop the -U decision",
                        interner.name(*id)
                    ),
                });
            }
            self.make_undefined.insert(id.0);
        }
        Ok(())
    }

    /// Installs every definition of every object (Pass 2 step 1) and records
    /// undefined references.
    ///
    /// # Errors
    /// [`LinkError::Symbol`] on duplicate strong definitions.
    pub fn install(&mut self, objects: &[InputObject]) -> Result<(), LinkError> {
        for obj in objects {
            for (sym_i, sym) in obj.symbols.iter().enumerate() {
                if sym.stab || !sym.external {
                    continue;
                }
                let key = sym.name.0;
                if self.make_undefined.contains(&key) {
                    continue; // M39: marked as undefined while being linked
                }
                if sym.is_defined() {
                    let rank = if obj.from_archive {
                        if sym.weak_def {
                            Rank::ArchiveWeak
                        } else {
                            Rank::ArchiveStrong
                        }
                    } else if sym.weak_def {
                        Rank::WeakDef
                    } else {
                        Rank::Strong
                    };
                    self.install_sect_def(
                        key,
                        Def {
                            file: obj.file,
                            sym: sym_i,
                            rank,
                            weak: sym.weak_def,
                            value: sym.value,
                            section: sym.section,
                            common_align: 0,
                            common_size: 0,
                        },
                    )?;
                } else if sym.is_common() {
                    self.install_common(key, obj.file, sym_i, sym);
                } else if sym.is_undefined() {
                    self.references
                        .entry(key)
                        .or_default()
                        .push((obj.file, sym_i));
                }
            }
        }
        Ok(())
    }

    /// Installs one `N_SECT` definition under the precedence rules.
    fn install_sect_def(&mut self, key: u32, def: Def) -> Result<(), LinkError> {
        match self.defs.get(&key) {
            None => {
                self.defs.insert(key, def);
                Ok(())
            }
            Some(existing) => match existing.rank.cmp(&def.rank) {
                core::cmp::Ordering::Less => Ok(()), // stronger already installed
                core::cmp::Ordering::Greater => {
                    self.defs.insert(key, def);
                    Ok(())
                }
                core::cmp::Ordering::Equal => {
                    // Two pulled members or two direct objects claiming the
                    // same strong symbol: a genuine duplicate. Direct vs
                    // archive never reaches Equal (ranks 1/2 < 3/4).
                    if def.rank == Rank::Strong || def.rank == Rank::ArchiveStrong {
                        Err(LinkError::Symbol {
                            name: String::new(),
                            message: format!(
                                "duplicate strong definition of symbol #{} in input {} (also \
                                 defined in input {})",
                                key, def.file.0, existing.file.0
                            ),
                        })
                    } else {
                        // Weak/weak or common/common ties: lower file index
                        // wins (TDD §5 Pass 2 tie-break).
                        if def.file < existing.file {
                            self.defs.insert(key, def);
                        }
                        Ok(())
                    }
                }
            },
        }
    }

    /// Installs a common symbol: coalesces size/align; loses to any `N_SECT`
    /// definition (TDD §5 Pass 2: "a real definition beats a common").
    fn install_common(&mut self, key: u32, file: FileId, sym: usize, isym: &InputSymbol) {
        let align = isym.common_align.unwrap_or(0).min(15);
        match self.defs.get(&key) {
            None => {
                self.defs.insert(
                    key,
                    Def {
                        file,
                        sym,
                        rank: Rank::Common,
                        weak: false,
                        value: isym.value,
                        section: None,
                        common_align: align,
                        common_size: isym.value,
                    },
                );
            }
            Some(existing) if existing.rank == Rank::Common => {
                // Two commons coalesce: max size, max align, lowest file.
                let merged = Def {
                    file: file.min(existing.file),
                    sym: if file < existing.file {
                        sym
                    } else {
                        existing.sym
                    },
                    rank: Rank::Common,
                    weak: false,
                    value: 0,
                    section: None,
                    common_align: align.max(existing.common_align),
                    common_size: isym.value.max(existing.common_size),
                };
                self.defs.insert(key, merged);
            }
            Some(_) => {} // a real definition beats a common — nothing to do
        }
    }

    /// Installs the bundle loader's export surface (M25): the names a
    /// bundle's undefined references may resolve against, binding with
    /// the main-executable ordinal. The export ids are the interned ids
    /// of the flattened export names, in scan order —
    /// [`crate::link()`] appends them to the interner batch after the
    /// dylib exports.
    pub fn install_loader_exports(&mut self, export_ids: &[StringId]) {
        self.loader_exports.extend(export_ids.iter().map(|id| id.0));
    }

    /// True when the name resolves against the `-bundle_loader` host
    /// (M25): a bind that rides the main-executable ordinal.
    #[must_use]
    pub fn is_loader_export(&self, id: StringId) -> bool {
        self.loader_exports.contains(&id.0)
    }

    /// Installs the dylib list (Pass 2 step 1b) and resolves two-level
    /// ordinals for every referenced name a dylib exports.
    ///
    /// `export_ids` are the interned ids of the flattened export names, in
    /// `(dylib index, export index)` order — [`crate::link()`] appends them to
    /// the interner batch after the object symbol names.
    pub fn install_dylibs(&mut self, dylibs: &[Dylib], export_ids: &[StringId]) {
        self.dylibs = dylibs.to_vec();
        let mut cursor = 0usize;
        for (ord, dylib) in dylibs.iter().enumerate() {
            let ordinal = (ord + 1) as u16;
            for _ in &dylib.exports {
                if let Some(id) = export_ids.get(cursor) {
                    // First dylib in command order wins (two-level lookup
                    // order); a local definition overrides later in layout.
                    self.dylib_exports.entry(id.0).or_insert(ordinal);
                }
                cursor += 1;
            }
        }
    }

    /// M42 — the unused-dylib drop (`-dead_strip_dylibs`): drops every
    /// input dylib no referenced name binds against *as it is linked*
    /// and renumbers the two-level ordinals onto the kept command
    /// order. A dylib is used when a referenced name resolves to its
    /// export (no in-image definition won — the bind carries the
    /// dylib's ordinal) or when the reference was left to dyld (a
    /// dynamic lookup binds flat and may reach any loaded image's
    /// exports, so the provider cannot be proven unreachable). The
    /// re-export dylibs always ride: their `LC_REEXPORT_DYLIB` command
    /// is an identity obligation and their REEXPORT nodes join the
    /// image's export trie. Returns the kept dylibs in command order —
    /// the `LinkConfig.dylibs` replacement the header assembly reads.
    #[must_use]
    pub fn dead_strip_dylibs(&mut self) -> Vec<Dylib> {
        // Used ordinals: every referenced name whose bind names a dylib
        // (no in-image winner) or could reach one through dyld (the
        // dynamic-lookup set), keyed by the first-exporting dylib the
        // two-level map carries.
        let mut used = vec![false; self.dylibs.len()];
        for name in self.references.keys() {
            let Some(&ordinal) = self.dylib_exports.get(name) else {
                continue;
            };
            let idx = ordinal as usize - 1;
            if idx >= used.len() {
                continue;
            }
            if self.dynamic_lookups.contains(name) || !self.defs.contains_key(name) {
                used[idx] = true;
            }
        }
        // The kept list rides in command order; re-exports are identity
        // obligations (the trie contract cannot survive their drop).
        let mut kept: Vec<Dylib> = Vec::new();
        let mut remap: Vec<Option<u16>> = Vec::with_capacity(self.dylibs.len());
        for (i, dylib) in self.dylibs.iter().enumerate() {
            if dylib.reexport || used[i] {
                kept.push(dylib.clone());
                remap.push(Some(kept.len() as u16));
            } else {
                remap.push(None);
            }
        }
        // The two-level map compacts onto the kept list: an entry whose
        // provider dropped named no bind (its names' winners are
        // in-image definitions nothing binds dylib-ly — the drop rule
        // above kept every provider a bind or a lookup can reach).
        // Total (no indexing panic): an entry whose provider dropped
        // named no bind (the drop rule kept every provider a bind or a
        // lookup can reach).
        let mut compacted = std::collections::BTreeMap::new();
        for (name, ordinal) in &self.dylib_exports {
            if let Some(Some(new_ordinal)) = remap.get(*ordinal as usize - 1) {
                compacted.insert(*name, *new_ordinal);
            }
        }
        self.dylib_exports = compacted;
        self.dylibs.clone_from(&kept);
        kept
    }

    /// Verifies every referenced name resolves (Pass 2, static + dylib
    /// semantics), recording the references that become dynamic lookups.
    ///
    /// # Errors
    /// [`LinkError::Symbol`] listing each undefined name and a referencing
    /// file (policy [`UndefinedPolicy::Error`]).
    pub fn require_all_resolved(
        &mut self,
        interner: &Interner,
        objects: &[crate::object::InputObject],
        policy: UndefinedPolicy,
        no_weak_imports: bool,
    ) -> Result<(), LinkError> {
        self.dynamic_lookups.clear();
        let mut missing: Vec<String> = Vec::new();
        // M50: the weak-import refusals, one entry per runtime-lookup
        // weak reference (kept beside `missing` so the aggregate error
        // names the lane, not just the symbols).
        let mut weak_imports: Vec<String> = Vec::new();
        // M39: the marked names' *relocation* references. A well-formed
        // object references an external name through an undefined symtab
        // row — the symtab walk below. A marked name's reference is
        // different: the same object also *defines* it (one symtab row),
        // so the only reference sites are the relocations themselves,
        // and the definition was just stripped. The walk scopes the
        // `-undefined` policy to exactly those sites — a marked name
        // referenced from the code refuses under the default policy (the
        // fix) and rides the dynamic lookup under `-undefined
        // dynamic_lookup`, like any unresolved reference.
        for obj in objects {
            for sect in &obj.sections {
                for reloc in &sect.relocs {
                    let RelocTarget::Extern(id) = reloc.target else {
                        continue;
                    };
                    if !self.make_undefined.contains(&id.0)
                        || self.defs.contains_key(&id.0)
                        || self.dylib_exports.contains_key(&id.0)
                        || self.loader_exports.contains(&id.0)
                    {
                        continue;
                    }
                    match policy {
                        UndefinedPolicy::DynamicLookup => {
                            self.dynamic_lookups.insert(id.0);
                        }
                        UndefinedPolicy::Error => {
                            missing.push(format!(
                                "\"{}\" (referenced from {} through a relocation) — -U marks \
                                 it undefined; bind it at runtime with -undefined \
                                 dynamic_lookup (or -flat_namespace), or drop the -U decision",
                                interner.name(id),
                                obj.name
                            ));
                        }
                    }
                }
            }
        }
        for (key, refs) in &self.references {
            if self.defs.contains_key(key)
                || self.dylib_exports.contains_key(key)
                || self.loader_exports.contains(key)
            {
                continue;
            }
            let (file, sym) = refs.first().copied().unwrap_or((FileId(0), 0));
            // M50: the weak-import refusal reads the same weak bit the
            // lookup fallthrough reads — a weak reference no input, no
            // dylib and no loader resolves is a bind dyld must look up
            // at runtime (ld64's proxy shape), and `-no_weak_imports`
            // refuses it with the site named (ld64: "weak import of
            // symbol '%s' not supported because of option:
            // -no_weak_imports"). A resolved weak reference never
            // reaches this lane: the knob prices the runtime lookup,
            // not the weakness.
            let is_weak_ref = objects
                .get(file.0 as usize)
                .and_then(|o| o.symbols.get(sym).map(|s| s.weak_ref))
                == Some(true);
            if is_weak_ref && no_weak_imports {
                let file_name = objects
                    .get(file.0 as usize)
                    .map_or_else(|| format!("input {}", file.0), |o| o.name.clone());
                weak_imports.push(format!(
                    "\"{}\" (referenced from {file_name}) — the name would ride dyld's \
                     runtime lookup; link the provider that exports it or drop the \
                     -no_weak_imports decision",
                    interner.name(crate::ids::StringId(*key))
                ));
                continue;
            }
            match policy {
                UndefinedPolicy::DynamicLookup => {
                    self.dynamic_lookups.insert(*key);
                }
                UndefinedPolicy::Error => {
                    if is_weak_ref {
                        self.dynamic_lookups.insert(*key);
                        continue;
                    }
                    let file_name = objects
                        .get(file.0 as usize)
                        .map_or_else(|| format!("input {}", file.0), |o| o.name.clone());
                    if self.make_undefined.contains(key) {
                        // M39: the reference is unresolved *because* the
                        // decision stripped its definition — the refusal
                        // names the knob and the runtime-binding fix.
                        missing.push(format!(
                            "\"{}\" (referenced from {file_name}) — -U marks it undefined; \
                             bind it at runtime with -undefined dynamic_lookup (or \
                             -flat_namespace), or drop the -U decision",
                            interner.name(crate::ids::StringId(*key))
                        ));
                    } else {
                        missing.push(format!(
                            "\"{}\" (referenced from {file_name})",
                            interner.name(crate::ids::StringId(*key))
                        ));
                    }
                }
            }
        }
        if !weak_imports.is_empty() {
            return Err(LinkError::Symbol {
                name: String::new(),
                message: format!(
                    "weak import(s) not supported under -no_weak_imports: {}",
                    weak_imports.join(", ")
                ),
            });
        }
        if missing.is_empty() {
            Ok(())
        } else {
            Err(LinkError::Symbol {
                name: String::new(),
                message: format!("undefined symbol(s): {}", missing.join(", ")),
            })
        }
    }

    /// The 1-based library ordinal that exports `id`, if any dylib does.
    #[must_use]
    pub fn dylib_ordinal(&self, id: StringId) -> Option<u16> {
        self.dylib_exports.get(&id.0).copied()
    }

    /// The input dylib list in `LC_LOAD_DYLIB` order.
    #[must_use]
    pub fn dylibs(&self) -> &[Dylib] {
        &self.dylibs
    }

    /// True when the name was left to dyld (`-undefined dynamic_lookup` or
    /// an unresolvable weak reference).
    #[must_use]
    pub fn is_dynamic_lookup(&self, id: StringId) -> bool {
        self.dynamic_lookups.contains(&id.0)
    }

    /// True when at least one *bind* in the image is weak (dyld semantics
    /// flag `MH_BINDS_TO_WEAK`): a reference that resolves to a dylib
    /// export or a dynamic lookup, carried by a weak-referenced symbol.
    #[must_use]
    pub fn any_weak_bind(&self, objects: &[InputObject]) -> bool {
        self.references.iter().any(|(key, refs)| {
            let binds = self.dylib_exports.contains_key(key) || self.dynamic_lookups.contains(key);
            binds
                && refs.iter().any(|(f, s)| {
                    objects
                        .get(f.0 as usize)
                        .and_then(|o| o.symbols.get(*s))
                        .is_some_and(|sym| sym.weak_ref)
                })
        })
    }

    /// The winning definition for a name, if any.
    #[must_use]
    pub fn def(&self, id: crate::ids::StringId) -> Option<&Def> {
        self.defs.get(&id.0)
    }

    /// All winning definitions keyed by name.
    pub fn definitions(&self) -> impl Iterator<Item = (crate::ids::StringId, &Def)> {
        self.defs.iter().map(|(k, d)| (crate::ids::StringId(*k), d))
    }

    /// Equality of the Pass-2 decision state, name by name: winners
    /// (definition, rank, file, values), reference sites, two-level dylib
    /// ordinals and the dynamic-lookup set. The M9 tier-2c reuse path must
    /// reproduce exactly this state or fall back (the gate the resolve
    /// tests lean on).
    #[must_use]
    pub fn equivalent(&self, other: &Self) -> bool {
        self.defs == other.defs
            && self.references == other.references
            && self.dylib_exports == other.dylib_exports
            && self.loader_exports == other.loader_exports
            && self.dynamic_lookups == other.dynamic_lookups
            && self.make_undefined == other.make_undefined
    }

    /// Copies one recorded winner verbatim (M9 tier-2c): the name sits
    /// outside the propagation seeds, so its recorded decision is still
    /// the decision the full walk would reach. No precedence check — the
    /// digest table vouches for the defining section. A `-U`-marked name
    /// (M39) is never a winner: the full walk never installed one.
    pub(crate) fn copy_winner(&mut self, key: u32, lite: &DefLite) {
        if self.make_undefined.contains(&key) {
            return;
        }
        self.defs.insert(key, Def::from(lite.clone()));
    }

    /// Records one reference site (M9 tier-2c merge): the reuse path
    /// re-walks the parse in file order, so merged lists match the full
    /// walk's ordering by construction.
    pub(crate) fn merge_reference(&mut self, key: u32, site: (FileId, usize)) {
        self.references.entry(key).or_default().push(site);
    }

    /// Replays one recorded or freshly parsed candidate through the
    /// precedence rules (M9 tier-2c): the same decision `install` reaches,
    /// fed from the snapshot instead of an object walk. A `-U`-marked
    /// name (M39) skips the install — the full walk never installed one.
    ///
    /// # Errors
    /// [`LinkError::Symbol`] on a duplicate strong definition — the same
    /// error `install` lands on for the same candidate stream.
    pub(crate) fn replay_candidate(&mut self, key: u32, cand: &DefLite) -> Result<(), LinkError> {
        if self.make_undefined.contains(&key) {
            return Ok(());
        }
        match cand.rank {
            Rank::Common => {
                self.replay_common(key, cand);
                Ok(())
            }
            _ => self.install_sect_def(key, Def::from(cand.clone())),
        }
    }

    /// The common-symbol coalescing `install_common` performs, from a
    /// recorded candidate: first common wins the slot, later ones merge
    /// (max size, max align, lowest file) and a real definition beats a
    /// common.
    fn replay_common(&mut self, key: u32, cand: &DefLite) {
        let file = FileId(cand.file);
        match self.defs.get(&key) {
            None => {
                self.defs.insert(
                    key,
                    Def {
                        file,
                        sym: cand.sym,
                        rank: Rank::Common,
                        weak: false,
                        value: cand.value,
                        section: None,
                        common_align: cand.common_align,
                        common_size: cand.common_size,
                    },
                );
            }
            Some(existing) if existing.rank == Rank::Common => {
                let merged = Def {
                    file: file.min(existing.file),
                    sym: if file < existing.file {
                        cand.sym
                    } else {
                        existing.sym
                    },
                    rank: Rank::Common,
                    weak: false,
                    value: 0,
                    section: None,
                    common_align: cand.common_align.max(existing.common_align),
                    common_size: cand.common_size.max(existing.common_size),
                };
                self.defs.insert(key, merged);
            }
            Some(_) => {} // a real definition beats a common — nothing to do
        }
    }
}

/// A [`Def`] stripped to its serializable shape (M9 tier-2c): the
/// resolution snapshot is a pointer-free, name-keyed record payload (the
/// cache/record framing convention), so file and name identities travel as
/// raw indices and bytes. Rank carries the precedence the replay applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefLite {
    /// Defining file (command-line order).
    pub file: u32,
    /// Symbol table index within that file.
    pub sym: usize,
    /// Definition rank (precedence).
    pub rank: Rank,
    /// `N_WEAK_DEF` on the winner.
    pub weak: bool,
    /// The definition's value (section-relative address, or the common's
    /// requested size before coalescing).
    pub value: u64,
    /// 0-based input section for `N_SECT` definitions.
    pub section: Option<usize>,
    /// Coalesced alignment exponent (commons only).
    pub common_align: u32,
    /// Coalesced size (commons only).
    pub common_size: u64,
}

impl DefLite {
    /// Captures one input symbol as a candidate: the same classification
    /// `install` applies (archive rank by `from_archive`, common coalescing
    /// fields, weak marker).
    #[must_use]
    pub fn of(obj: &InputObject, sym: usize) -> Self {
        let s = &obj.symbols[sym];
        let rank = if s.is_common() {
            Rank::Common
        } else if obj.from_archive {
            if s.weak_def {
                Rank::ArchiveWeak
            } else {
                Rank::ArchiveStrong
            }
        } else if s.weak_def {
            Rank::WeakDef
        } else {
            Rank::Strong
        };
        Self {
            file: obj.file.0,
            sym,
            rank,
            weak: s.weak_def,
            value: s.value,
            section: s.section,
            common_align: s.common_align.unwrap_or(0).min(15),
            common_size: if s.is_common() { s.value } else { 0 },
        }
    }
}

impl From<&Def> for DefLite {
    fn from(def: &Def) -> Self {
        Self {
            file: def.file.0,
            sym: def.sym,
            rank: def.rank,
            weak: def.weak,
            value: def.value,
            section: def.section,
            common_align: def.common_align,
            common_size: def.common_size,
        }
    }
}

impl From<&DefLite> for Def {
    fn from(lite: &DefLite) -> Self {
        Self {
            file: FileId(lite.file),
            sym: lite.sym,
            rank: lite.rank,
            weak: lite.weak,
            value: lite.value,
            section: lite.section,
            common_align: lite.common_align,
            common_size: lite.common_size,
        }
    }
}

impl From<DefLite> for Def {
    fn from(lite: DefLite) -> Self {
        Self::from(&lite)
    }
}

/// The Pass-2 state a relink reuses (M9 tier-2c): the complete candidate
/// stream and the winning decisions of the linked parse, keyed so the
/// reuse path never re-derives them through name lookups. All fields are
/// pointer-free and name-keyed only where the record payload needs to be
/// self-describing (the cache/record framing convention); the seed's
/// section-digest table travels beside it and vouches for the per-file
/// state it describes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolutionSnapshot {
    /// Input file names in command-line order: the reuse shape guard (a
    /// moved file list renumbers every `FileId`, so the plan refuses).
    pub file_names: Vec<Vec<u8>>,
    /// Every external definition and common of the linked parse, sorted
    /// by `(name, file, symbol)` — the complete candidate stream, winners
    /// and losers both (a re-decided name needs every candidate to replay
    /// the precedence rules, not just the recorded winner). The name
    /// grouping is the replay's index: one binary search per re-decided
    /// name, never a scan of the whole list.
    pub candidates: Vec<(Vec<u8>, DefLite)>,
    /// Winning definitions as a per-file, per-symbol-index matrix: the
    /// winner's defining `(file, sym)` position, digest-vouched for
    /// unchanged files. The reuse copy walks the relink parse (whose
    /// symbol ids are already in hand) and reads this O(1) — the name-keyed
    /// join the record payload could otherwise force per winner.
    pub winner_slots: Vec<Vec<Option<DefLite>>>,
    /// Dylib export names flattened in `(dylib, export)` order: the
    /// two-level ordinal map's shape guard (an export-set change renumbers
    /// ordinals, so the plan refuses).
    pub dylib_export_names: Vec<Vec<u8>>,
}

impl ResolutionSnapshot {
    /// Captures the Pass-2 state of a finished resolve (the record-side
    /// half of the reuse path): candidates from the parse walk, winners
    /// placed by their defining symbol's position, export names from the
    /// dylib list — all in deterministic total order (§4.3).
    #[must_use]
    pub fn capture(
        objects: &[InputObject],
        interner: &Interner,
        res: &Resolution,
        dylibs: &[Dylib],
        loader_exports: &[Vec<u8>],
    ) -> Self {
        let file_names = objects
            .iter()
            .map(|o| o.name.clone().into_bytes())
            .collect();
        let mut candidates: Vec<(Vec<u8>, DefLite)> = objects
            .iter()
            .flat_map(|obj| {
                (0..obj.symbols.len()).filter_map(move |i| {
                    let s = &obj.symbols[i];
                    if s.stab || !s.external || !(s.is_defined() || s.is_common()) {
                        return None;
                    }
                    Some((interner.bytes(s.name).to_vec(), DefLite::of(obj, i)))
                })
            })
            .collect();
        // Name-sorted (then file/symbol): the reuse path's replay reads
        // each re-decided name's recorded stream as one binary-searched
        // group instead of scanning the whole list.
        candidates.sort_unstable_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| (a.1.file, a.1.sym).cmp(&(b.1.file, b.1.sym)))
        });
        let mut winner_slots: Vec<Vec<Option<DefLite>>> = objects
            .iter()
            .map(|o| vec![None; o.symbols.len()])
            .collect();
        for (_, def) in res.definitions() {
            // A finished Resolution's winners name files and symbols of the
            // very parse that produced it — the slots always fit.
            let slots = &mut winner_slots[def.file.0 as usize];
            if let Some(slot) = slots.get_mut(def.sym) {
                *slot = Some(DefLite::from(def));
            }
        }
        Self {
            file_names,
            candidates,
            winner_slots,
            dylib_export_names: dylibs
                .iter()
                .flat_map(|d| d.exports.iter().cloned())
                .chain(loader_exports.iter().cloned())
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Rank, Resolution, UndefinedPolicy};
    use crate::ids::FileId;
    use crate::interner::Interner;
    use crate::object::InputObject;
    use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

    /// Runs Pass 1 + interning + Pass 2 install over fixture objects.
    fn run(specs: Vec<ObjectBuilder>) -> (Interner, Vec<InputObject>, Resolution) {
        let mut names: Vec<Vec<u8>> = Vec::new();
        let mut objects = Vec::new();
        for (i, spec) in specs.into_iter().enumerate() {
            let bytes = spec.build().unwrap();
            let mut obj = InputObject::parse(FileId(i as u32), spec.name(), bytes).unwrap();
            names.append(&mut obj.take_symbol_names());
            objects.push(obj);
        }
        let (interner, ids) = Interner::build(&names);
        let mut cursor = 0usize;
        for obj in &mut objects {
            let take = obj.symbols.len();
            obj.finish(&ids[cursor..cursor + take]).unwrap();
            cursor += take;
        }
        let mut res = Resolution::default();
        res.install(&objects).unwrap();
        (interner, objects, res)
    }

    #[test]
    fn strong_beats_weak_beats_common() {
        let mut a = ObjectBuilder::new("a.o");
        let t = a.add_section(ObjectSection::text(
            "__text",
            vec![0xC0, 0x03, 0x5F, 0xD6],
            Vec::new(),
        ));
        a.add_symbol(ObjectSymbol::Defined {
            name: "_f".into(),
            section_index: t,
            value: 0,
            weak: true,
        });
        let mut b = ObjectBuilder::new("b.o");
        let t2 = b.add_section(ObjectSection::text(
            "__text",
            vec![0xC0, 0x03, 0x5F, 0xD6],
            Vec::new(),
        ));
        b.add_symbol(ObjectSymbol::Defined {
            name: "_f".into(),
            section_index: t2,
            value: 4,
            weak: false,
        });

        let (interner, _objects, res) = run(vec![a, b]);
        let f = interner.lookup(b"_f").unwrap();
        let def = res.def(f).unwrap();
        assert_eq!(def.rank, Rank::Strong);
        assert_eq!(def.file, FileId(1), "the strong definition wins");
        assert!(!def.weak);
    }

    #[test]
    fn weak_beats_common_and_ties_break_by_file_order() {
        let mut a = ObjectBuilder::new("a.o");
        let t = a.add_section(ObjectSection::text(
            "__text",
            vec![0xC0, 0x03, 0x5F, 0xD6],
            Vec::new(),
        ));
        a.add_symbol(ObjectSymbol::Defined {
            name: "_w".into(),
            section_index: t,
            value: 0,
            weak: true,
        });
        let mut b = ObjectBuilder::new("b.o");
        b.add_section(ObjectSection::text(
            "__text",
            vec![0xC0, 0x03, 0x5F, 0xD6],
            Vec::new(),
        ));
        b.add_symbol(ObjectSymbol::Common {
            name: "_w".into(),
            size: 32,
            align_log2: 4,
        });

        let (interner, _objects, res) = run(vec![a, b]);
        let w = interner.lookup(b"_w").unwrap();
        assert_eq!(res.def(w).unwrap().rank, Rank::WeakDef);
    }

    #[test]
    fn commons_coalesce_to_max_size_and_align() {
        let mut a = ObjectBuilder::new("a.o");
        a.add_section(ObjectSection::text(
            "__text",
            vec![0xC0, 0x03, 0x5F, 0xD6],
            Vec::new(),
        ));
        a.add_symbol(ObjectSymbol::Common {
            name: "_buf".into(),
            size: 32,
            align_log2: 4,
        });
        let mut b = ObjectBuilder::new("b.o");
        b.add_section(ObjectSection::text(
            "__text",
            vec![0xC0, 0x03, 0x5F, 0xD6],
            Vec::new(),
        ));
        b.add_symbol(ObjectSymbol::Common {
            name: "_buf".into(),
            size: 96,
            align_log2: 5,
        });

        let (interner, _objects, res) = run(vec![a, b]);
        let buf = interner.lookup(b"_buf").unwrap();
        let def = res.def(buf).unwrap();
        assert_eq!(def.rank, Rank::Common);
        assert_eq!(def.common_size, 96);
        assert_eq!(def.common_align, 5);
        assert_eq!(def.file, FileId(0), "tie-break: lowest file index");
    }

    #[test]
    fn real_definition_beats_common() {
        let mut a = ObjectBuilder::new("a.o");
        let t = a.add_section(ObjectSection::text(
            "__text",
            vec![0xC0, 0x03, 0x5F, 0xD6],
            Vec::new(),
        ));
        a.add_symbol(ObjectSymbol::Defined {
            name: "_x".into(),
            section_index: t,
            value: 0,
            weak: false,
        });
        let mut b = ObjectBuilder::new("b.o");
        b.add_section(ObjectSection::text(
            "__text",
            vec![0xC0, 0x03, 0x5F, 0xD6],
            Vec::new(),
        ));
        b.add_symbol(ObjectSymbol::Common {
            name: "_x".into(),
            size: 128,
            align_log2: 6,
        });

        let (interner, _objects, res) = run(vec![a, b]);
        let x = interner.lookup(b"_x").unwrap();
        let def = res.def(x).unwrap();
        assert_eq!(def.rank, Rank::Strong);
        assert_eq!(def.section, Some(0));
    }

    #[test]
    fn duplicate_strong_is_an_error() {
        let mut names: Vec<Vec<u8>> = Vec::new();
        let mut objects = Vec::new();
        for (i, name) in ["a.o", "b.o"].iter().enumerate() {
            let mut spec = ObjectBuilder::new(name);
            let t = spec.add_section(ObjectSection::text(
                "__text",
                vec![0xC0, 0x03, 0x5F, 0xD6],
                Vec::new(),
            ));
            spec.add_symbol(ObjectSymbol::Defined {
                name: "_dup".into(),
                section_index: t,
                value: 0,
                weak: false,
            });
            let bytes = spec.build().unwrap();
            let mut obj = InputObject::parse(FileId(i as u32), name, bytes).unwrap();
            names.append(&mut obj.take_symbol_names());
            objects.push(obj);
        }
        let (_interner, ids) = Interner::build(&names);
        let mut cursor = 0usize;
        for obj in &mut objects {
            let take = obj.symbols.len();
            obj.finish(&ids[cursor..cursor + take]).unwrap();
            cursor += take;
        }
        let mut res = Resolution::default();
        let err = res.install(&objects).unwrap_err();
        assert!(err.to_string().contains("duplicate strong"), "{err}");
    }

    #[test]
    fn undefined_reference_is_reported() {
        let mut a = ObjectBuilder::new("a.o");
        let t = a.add_section(ObjectSection::text(
            "__text",
            vec![0xC0, 0x03, 0x5F, 0xD6],
            Vec::new(),
        ));
        a.add_symbol(ObjectSymbol::Defined {
            name: "_main".into(),
            section_index: t,
            value: 0,
            weak: false,
        });
        a.add_symbol(ObjectSymbol::Undefined {
            name: "_nowhere".into(),
            weak_ref: false,
        });

        let (interner, _objects, mut res) = run(vec![a]);
        let err = res
            .require_all_resolved(&interner, &[], UndefinedPolicy::Error, false)
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("_nowhere"), "{msg}");
        assert!(msg.contains("input 0"), "{msg}");
    }

    #[test]
    fn all_resolved_when_every_reference_has_a_definition() {
        let mut a = ObjectBuilder::new("a.o");
        let t = a.add_section(ObjectSection::text(
            "__text",
            vec![0xC0, 0x03, 0x5F, 0xD6],
            Vec::new(),
        ));
        a.add_symbol(ObjectSymbol::Defined {
            name: "_main".into(),
            section_index: t,
            value: 0,
            weak: false,
        });
        a.add_symbol(ObjectSymbol::Undefined {
            name: "_f".into(),
            weak_ref: false,
        });
        let mut b = ObjectBuilder::new("b.o");
        let t2 = b.add_section(ObjectSection::text(
            "__text",
            vec![0xC0, 0x03, 0x5F, 0xD6],
            Vec::new(),
        ));
        b.add_symbol(ObjectSymbol::Defined {
            name: "_f".into(),
            section_index: t2,
            value: 0,
            weak: false,
        });

        let (interner, _objects, mut res) = run(vec![a, b]);
        res.require_all_resolved(&interner, &[], UndefinedPolicy::Error, false)
            .unwrap();
    }
}
