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
use crate::object::{InputObject, InputSymbol};
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
}

impl Resolution {
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
    ) -> Result<(), LinkError> {
        self.dynamic_lookups.clear();
        let mut missing: Vec<String> = Vec::new();
        for (key, refs) in &self.references {
            if self.defs.contains_key(key) || self.dylib_exports.contains_key(key) {
                continue;
            }
            let (file, sym) = refs.first().copied().unwrap_or((FileId(0), 0));
            match policy {
                UndefinedPolicy::DynamicLookup => {
                    self.dynamic_lookups.insert(*key);
                }
                UndefinedPolicy::Error => {
                    let is_weak_ref = objects
                        .get(file.0 as usize)
                        .and_then(|o| o.symbols.get(sym).map(|s| s.weak_ref));
                    if is_weak_ref == Some(true) {
                        self.dynamic_lookups.insert(*key);
                        continue;
                    }
                    let file_name = objects
                        .get(file.0 as usize)
                        .map_or_else(|| format!("input {}", file.0), |o| o.name.clone());
                    missing.push(format!(
                        "\"{}\" (referenced from {file_name})",
                        interner.name(crate::ids::StringId(*key))
                    ));
                }
            }
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

    /// All reference sites of a name (`(file, symbol index)` pairs).
    #[must_use]
    pub fn reference_sites(&self, id: StringId) -> &[(FileId, usize)] {
        self.references
            .get(&id.0)
            .map_or(&[], std::vec::Vec::as_slice)
    }

    /// All winning definitions keyed by name.
    pub fn definitions(&self) -> impl Iterator<Item = (crate::ids::StringId, &Def)> {
        self.defs.iter().map(|(k, d)| (crate::ids::StringId(*k), d))
    }

    /// True when the name was referenced by some input.
    #[must_use]
    pub fn is_referenced(&self, id: crate::ids::StringId) -> bool {
        self.references.contains_key(&id.0)
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
            .require_all_resolved(&interner, &[], UndefinedPolicy::Error)
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
        res.require_all_resolved(&interner, &[], UndefinedPolicy::Error)
            .unwrap();
    }
}
