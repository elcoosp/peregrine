//! Pass 2 — global symbol resolution (TDD §5 Pass 2, M1 subset).
//!
//! Mach-O precedence (TDD §5 Pass 2, adapted from mold's Table 2 and ld64
//! semantics):
//!
//! | rank | definition |
//! |---|---|
//! | 1 | strong `N_SECT\|N_EXT` definition |
//! | 2 | weak definition (`N_WEAK_DEF`) |
//! | 5 | tentative/common (`N_UNDF`, `n_value != 0`) — coalesce to max size/align |
//! | 7 | undefined (only valid if some definition exists elsewhere) |
//!
//! Ranks 3/4 (archive members) and 6 (dylib exports) are M2/M5 scope — M1
//! links direct `.o` inputs only. Ties within a rank: lower file index wins
//! (command-line order); the comparison is a pure function of
//! `(rank, file)`, so the M4 CAS key packs exactly these two fields and the
//! winner stays schedule-independent.
//!
//! M1 liveness: every command-line object is live (no archives yet).

use crate::LinkError;
use crate::ids::FileId;
use crate::interner::Interner;
use crate::object::{InputObject, InputSymbol};
use std::collections::BTreeMap;

/// Definition rank (lower wins; TDD §5 Pass 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Rank {
    /// Strong `N_SECT | N_EXT` definition.
    Strong = 1,
    /// Weak definition (`N_WEAK_DEF`).
    WeakDef = 2,
    /// Tentative/common symbol.
    Common = 5,
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
                    self.install_sect_def(
                        key,
                        Def {
                            file: obj.file,
                            sym: sym_i,
                            rank: if sym.weak_def {
                                Rank::WeakDef
                            } else {
                                Rank::Strong
                            },
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
                    if def.rank == Rank::Strong {
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

    /// Verifies every referenced name resolves (Pass 2, static semantics).
    ///
    /// # Errors
    /// [`LinkError::Symbol`] listing each undefined name and a referencing
    /// file.
    pub fn require_all_resolved(
        &self,
        interner: &Interner,
        objects: &[crate::object::InputObject],
    ) -> Result<(), LinkError> {
        let mut missing: Vec<String> = Vec::new();
        for (key, refs) in &self.references {
            if !self.defs.contains_key(key) {
                let (file, _sym) = refs.first().copied().unwrap_or((FileId(0), 0));
                let file_name = objects
                    .get(file.0 as usize)
                    .map(|o| o.name.clone())
                    .unwrap_or_else(|| format!("input {}", file.0));
                missing.push(format!(
                    "\"{}\" (referenced from {file_name})",
                    interner.name(crate::ids::StringId(*key))
                ));
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

    /// The winning definition for a name, if any.
    #[must_use]
    pub fn def(&self, id: crate::ids::StringId) -> Option<&Def> {
        self.defs.get(&id.0)
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
    use super::{Rank, Resolution};
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

        let (interner, _objects, res) = run(vec![a]);
        let err = res.require_all_resolved(&interner, &[]).unwrap_err();
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

        let (interner, _objects, res) = run(vec![a, b]);
        res.require_all_resolved(&interner, &[]).unwrap();
    }
}
