//! ICF — identical code folding (M6 — architecture doc §10.3 row M6:
//! "ICF (parallel color refinement)"; perf gate: "ICF ≤ 25% added wall on
//! the large corpus", determinism gate: "ICF preserves determinism").
//!
//! Text atoms with identical bytes *and* identical relocation behavior are
//! folded: one canonical copy is placed, every other instance leaves the
//! layout, and every reference (symtab, GOT, relocations, trie) resolves to
//! the canonical copy's address — ld64's `-icf` semantics with the aliases
//! visible in the symbol table.
//!
//! Algorithm (mold §4.6 shape): Hopcroft-style **color refinement** over
//! per-atom signatures. Round 0 hashes `(content, ordered relocation
//! fingerprints)`; each round re-hashes `(own class, ordered (offset, kind,
//! target class))` until the partition stabilizes — identical bytes that
//! call different targets end up in different classes without any
//! address knowledge. The byte-heavy hashing runs on the shared compute
//! pool ([`crate::pool`]); the refinement itself is serial and
//! deterministic: class ids are assigned in candidate order and every
//! target key is a pure function of the inputs (TDD §4.3), so the fold map
//! never reads hash iteration order.
//!
//! Exclusions (conservative, ld64-aligned):
//!
//! * `-icf=safe` never folds an atom whose *address is taken* — any
//!   non-`Branch26` reference (data pointer, GOT load, subtractor operand)
//!   names it;
//! * both modes exclude atoms targeted by same-file **section-relative**
//!   relocations (those references cannot be redirected to another file);
//! * weak definitions never fold (aliasing changes override semantics);
//! * dead atoms are invisible to ICF (it runs after the D12 mark-sweep).

use crate::LinkError;
use crate::interner::Interner;
use crate::layout::LinkConfig;
use crate::object::{InputObject, RelocKind, RelocTarget};
use crate::resolve::Resolution;
use pgr_format::consts::S_ATTR_PURE_INSTRUCTIONS;

/// `-icf` level (ld64's `-icf=none|safe|all` surface; default `None`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IcfMode {
    /// `-no_icf` (ld64 default): fold nothing.
    #[default]
    None,
    /// `-icf=safe`: fold only atoms whose address is never taken — calls
    /// (`Branch26`) are the only legal reference shape.
    Safe,
    /// `-icf=all`: fold regardless of address-taken references (unsafe for
    /// C++ virtual tables etc., exactly like ld64's `-icf=all`); atoms
    /// targeted by same-file section-relative relocations still never fold
    /// (their references cannot be redirected).
    All,
}

impl IcfMode {
    /// True when folding runs at all.
    #[must_use]
    pub const fn is_active(self) -> bool {
        !matches!(self, Self::None)
    }

    /// True when address-taken atoms may fold (`-icf=all`).
    #[must_use]
    pub const fn allows_address_taken(self) -> bool {
        matches!(self, Self::All)
    }
}

/// The fold plan: folded atom `(file, section, start)` → canonical atom's
/// `(file, section, start)`. The layout consults it when placing pieces and
/// when resolving def/symbol addresses; nothing else changes.
#[derive(Debug, Default, Clone)]
pub struct FoldPlan {
    folded: std::collections::HashMap<(u32, usize, u64), (u32, usize, u64)>,
    /// Number of folded atoms (diagnostics / bench counters).
    pub folded_count: usize,
    /// Bytes removed from the output (diagnostics / bench counters).
    pub folded_bytes: u64,
}

impl FoldPlan {
    /// The canonical location of `(file, sect, atom_start)` when it folds.
    #[must_use]
    pub fn canonical_of(
        &self,
        file: u32,
        sect: usize,
        atom_start: u64,
    ) -> Option<(u32, usize, u64)> {
        self.folded.get(&(file, sect, atom_start)).copied()
    }

    /// True when the atom folds away (its bytes are not placed).
    #[must_use]
    pub fn is_folded(&self, file: u32, sect: usize, atom_start: u64) -> bool {
        self.folded.contains_key(&(file, sect, atom_start))
    }

    /// True when no atom folds (the layout keeps the fast path).
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.folded_count == 0
    }
}

/// One ICF candidate: a live, pure-code atom.
#[derive(Debug, Clone, Copy)]
struct Cand {
    file: u32,
    sect: usize,
    start: u64,
    end: u64,
}

/// Computes the fold plan (M6). Runs after Pass 2 and the dead-strip
/// mark-sweep; the layout consumes the returned plan.
///
/// # Errors
/// [`LinkError::Internal`] on resolution-state inconsistencies.
pub fn fold(
    objects: &[InputObject],
    res: &Resolution,
    interner: &Interner,
    cfg: &LinkConfig,
    live: &crate::deadstrip::LiveSet,
) -> Result<FoldPlan, LinkError> {
    if !cfg.icf.is_active() {
        return Ok(FoldPlan::default());
    }
    refine(objects, res, interner, cfg, live)
}

/// FNV-1a 64: a deterministic hasher (the std hasher is randomly seeded,
/// which would break the determinism policy).
fn fnv64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn fnv64_mix(h: u64, v: u64) -> u64 {
    (h ^ v).wrapping_mul(0x0000_0100_0000_01b3)
}

/// The containing atom's start for `off` (dead-strip's containment rule).
fn containing_atom(obj: &InputObject, sect: usize, off: u64) -> Option<u64> {
    let ranges = obj.atoms_of(sect);
    if ranges.is_empty() {
        return None;
    }
    let idx = ranges.partition_point(|r| r.start <= off).saturating_sub(1);
    ranges.get(idx).map(|r| r.start)
}

/// The relocation addend the resolution paths would use (mirrors
/// `deadstrip::compute`'s rule).
fn addend_of(obj: &InputObject, sect: usize, r: &crate::object::DecodedReloc) -> i64 {
    match r.kind {
        RelocKind::Page21 { addend } | RelocKind::PageOff12 { addend } => addend,
        RelocKind::Unsigned | RelocKind::Subtractor { .. } => {
            let at = obj.sections[sect].data.start as usize + r.offset as usize;
            obj.bytes
                .get(at..at + 8)
                .and_then(|b| <[u8; 8]>::try_from(b).ok())
                .map(u64::from_le_bytes)
                .map(|v| v as i64)
                .unwrap_or(0)
        }
        _ => 0,
    }
}

/// Collects the candidate atoms: live, pure-code, not weak-defined.
fn candidates(objects: &[InputObject], live: &crate::deadstrip::LiveSet) -> Vec<Cand> {
    let mut out = Vec::new();
    for obj in objects {
        for (si, sect) in obj.sections.iter().enumerate() {
            if sect.flags & S_ATTR_PURE_INSTRUCTIONS == 0 {
                continue;
            }
            for range in obj.atoms_of(si) {
                if range.end <= range.start {
                    continue;
                }
                if live.is_active() && live.is_atom_dead(obj.file.0, si, range.start) {
                    continue;
                }
                // Weak definitions never fold.
                let weak_here = obj.symbols.iter().any(|s| {
                    s.weak_def
                        && s.section == Some(si)
                        && s.value >= range.start
                        && s.value < range.end
                });
                if weak_here {
                    continue;
                }
                out.push(Cand {
                    file: obj.file.0,
                    sect: si,
                    start: range.start,
                    end: range.end,
                });
            }
        }
    }
    out
}

/// The atoms whose address is taken: targets of section-relative relocs
/// (both modes — unredirectable) and, under `-icf=safe`, of any
/// non-`Branch26` reference.
fn address_taken(
    objects: &[InputObject],
    res: &Resolution,
    mode: IcfMode,
) -> std::collections::HashSet<(u32, usize, u64)> {
    let mut taken = std::collections::HashSet::new();
    for obj in objects {
        for (si, sect) in obj.sections.iter().enumerate() {
            for r in &sect.relocs {
                match r.target {
                    RelocTarget::Section(tsi) => {
                        let addend = addend_of(obj, si, r);
                        // Negative addends never name a valid atom.
                        if let Some(off) = u64::try_from(addend).ok()
                            && let Some(start) = containing_atom(obj, tsi, off)
                        {
                            taken.insert((obj.file.0, tsi, start));
                        }
                    }
                    RelocTarget::Extern(id) => {
                        if matches!(r.kind, RelocKind::Branch26) {
                            continue;
                        }
                        if mode.allows_address_taken() {
                            continue;
                        }
                        if let Some(d) = res.def(id)
                            && let Some(ts) = d.section
                            && let Some(tobj) = objects.get(d.file.0 as usize)
                            && let Some(start) = containing_atom(tobj, ts, d.value)
                        {
                            taken.insert((d.file.0, ts, start));
                        }
                    }
                }
            }
        }
    }
    taken
}

/// The refinement target key: externs compare by interned name (the
/// interner dedups globally), local sections by their containing atom.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum TargetKey {
    Extern(u32),
    Section(u32, usize, u64),
}

/// One relocation fingerprint: `(offset, kind, target key)` — compared as
/// an ordered list between candidate atoms.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RelocFp {
    offset: u32,
    kind: u8,
    target: TargetKey,
}

/// The kind discriminant (stability across the link, not a wire format).
fn kind_fp(kind: &RelocKind) -> u8 {
    match kind {
        RelocKind::Branch26 => 0,
        RelocKind::GotLoadPage21 { .. } | RelocKind::GotLoadPageOff12 { .. } => 1,
        RelocKind::PointerToGot => 2,
        RelocKind::Page21 { .. } => 3,
        RelocKind::PageOff12 { .. } => 4,
        RelocKind::Unsigned => 5,
        RelocKind::Subtractor { .. } => 6,
    }
}

/// Color refinement over the candidates; returns the fold plan.
fn refine(
    objects: &[InputObject],
    res: &Resolution,
    interner: &Interner,
    cfg: &LinkConfig,
    live: &crate::deadstrip::LiveSet,
) -> Result<FoldPlan, LinkError> {
    use rayon::prelude::*;
    let cands = candidates(objects, live);
    if cands.len() < 2 {
        return Ok(FoldPlan::default());
    }
    let taken = address_taken(objects, res, cfg.icf);
    let kept: Vec<&Cand> = cands
        .iter()
        .filter(|c| !taken.contains(&(c.file, c.sect, c.start)))
        .collect();
    if kept.len() < 2 {
        return Ok(FoldPlan::default());
    }

    // Candidate identity: (file, sect, atom start) → index into `kept`.
    let mut index_of: std::collections::HashMap<(u32, usize, u64), usize> =
        std::collections::HashMap::with_capacity(kept.len());
    for (i, c) in kept.iter().enumerate() {
        index_of.insert((c.file, c.sect, c.start), i);
    }

    // ---- round 0: content + ordered relocation fingerprints ----------------
    // Byte hashing runs on the pool (the expensive half of ICF).
    let base_sigs: Vec<u64> = kept
        .par_iter()
        .map(|&c| {
            let obj = &objects[c.file as usize];
            let sect = &obj.sections[c.sect];
            let lo = sect.data.start as usize + c.start as usize;
            let hi = sect.data.start as usize + c.end as usize;
            let content = obj.bytes.get(lo..hi).unwrap_or(&[]);
            let mut h = fnv64(content);
            h = fnv64_mix(h, c.end - c.start);
            h = fnv64_mix(h, u64::from(sect.flags));
            // Ordered fingerprint list: relocs whose offset falls inside
            // the atom, re-based to atom-relative offsets.
            let mut fps: Vec<RelocFp> = Vec::new();
            for r in &sect.relocs {
                if r.offset < c.start as u32 || r.offset >= c.end as u32 {
                    continue;
                }
                let target = match r.target {
                    RelocTarget::Extern(id) => TargetKey::Extern(id.0),
                    RelocTarget::Section(tsi) => {
                        let addend = addend_of(obj, c.sect, r);
                        let off = u64::try_from(addend).unwrap_or(u64::MAX);
                        match containing_atom(obj, tsi, off) {
                            Some(start) => TargetKey::Section(c.file, tsi, start),
                            None => TargetKey::Section(c.file, tsi, u64::MAX),
                        }
                    }
                };
                fps.push(RelocFp {
                    offset: r.offset - c.start as u32,
                    kind: kind_fp(&r.kind),
                    target,
                });
            }
            // `relocs` arrive in table order — already sorted by offset
            // within one section; sort anyway to keep the invariant local.
            fps.sort_by_key(|fp| fp.offset);
            for fp in &fps {
                h = fnv64_mix(h, u64::from(fp.offset));
                h = fnv64_mix(h, u64::from(fp.kind));
                h = match &fp.target {
                    TargetKey::Extern(id) => fnv64_mix(h, 0x8000_0000 ^ u64::from(*id)),
                    TargetKey::Section(f, s, st) => fnv64_mix(
                        h,
                        0x4000_0000
                            ^ fnv64(&[*f as u8, 0, 0, 0])
                                .wrapping_add((*s as u64) << 8)
                                .wrapping_add(*st),
                    ),
                };
            }
            h
        })
        .collect();

    // ---- class assignment (deterministic: first occurrence wins) -----------
    let mut class: Vec<u64> = Vec::with_capacity(kept.len());
    let mut class_of_sig: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();
    for sig in &base_sigs {
        let next = class_of_sig.len() as u64;
        let id = *class_of_sig.entry(*sig).or_insert(next);
        class.push(id);
    }

    // ---- refinement rounds ---------------------------------------------------
    for _ in 0..12 {
        let before = class_of_sig.len();
        // Per-candidate new signature: (own class, ordered (offset, kind,
        // target class)). Target class: externs keep their name identity;
        // section targets use the containing atom's *class* when it is a
        // candidate (transitive equivalence), a stable raw key otherwise.
        let sigs: Vec<u64> = kept
            .par_iter()
            .enumerate()
            .map(|(i, &c)| {
                let obj = &objects[c.file as usize];
                let sect = &obj.sections[c.sect];
                let mut fps: Vec<(u32, u8, u64)> = Vec::new();
                for r in &sect.relocs {
                    if r.offset < c.start as u32 || r.offset >= c.end as u32 {
                        continue;
                    }
                    let tclass = match r.target {
                        RelocTarget::Extern(id) => 0x8000_0000 ^ u64::from(id.0),
                        RelocTarget::Section(tsi) => {
                            let addend = addend_of(obj, c.sect, r);
                            let off = u64::try_from(addend).unwrap_or(u64::MAX);
                            let start = containing_atom(obj, tsi, off).unwrap_or(u64::MAX);
                            match index_of.get(&(c.file, tsi, start)) {
                                Some(&ti) => 0x4000_0000 | class[ti],
                                None => {
                                    0x4000_0000
                                        | fnv64(&c.file.to_le_bytes())
                                            .wrapping_add((tsi as u64) << 8)
                                            .wrapping_add(start)
                                }
                            }
                        }
                    };
                    fps.push((r.offset - c.start as u32, kind_fp(&r.kind), tclass));
                }
                fps.sort_by_key(|fp| fp.0);
                let mut h = fnv64(&class[i].to_le_bytes());
                for (off, kind, tc) in fps {
                    h = fnv64_mix(h, u64::from(off));
                    h = fnv64_mix(h, u64::from(kind));
                    h = fnv64_mix(h, tc);
                }
                h
            })
            .collect();
        let mut class_of_sig: std::collections::HashMap<u64, u64> =
            std::collections::HashMap::with_capacity(kept.len());
        let mut new_class: Vec<u64> = Vec::with_capacity(kept.len());
        for sig in &sigs {
            let next = class_of_sig.len() as u64;
            let id = *class_of_sig.entry(*sig).or_insert(next);
            new_class.push(id);
        }
        let converged = class_of_sig.len() == before;
        class = new_class;
        if converged {
            break;
        }
    }

    // ---- fold: canonical = first candidate of each class ---------------------
    let mut plan = FoldPlan::default();
    let mut canon_of_class: std::collections::HashMap<u64, usize> =
        std::collections::HashMap::new();
    for (i, &c) in kept.iter().enumerate() {
        let canonical = *canon_of_class.entry(class[i]).or_insert(i);
        if canonical == i {
            continue;
        }
        let k = &kept[canonical];
        plan.folded
            .insert((c.file, c.sect, c.start), (k.file, k.sect, k.start));
        plan.folded_count += 1;
        plan.folded_bytes += c.end - c.start;
    }
    let _ = interner;
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::{FoldPlan, IcfMode, fold};
    use crate::deadstrip;
    use crate::layout::LinkConfig;
    use crate::link::{LinkInput, link_with};
    use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

    /// One object defining `sym`: an 8-byte two-instruction body + `ret`,
    /// split into atoms (`MH_SUBSECTIONS_VIA_SYMBOLS`).
    fn identical_fn(sym: &str) -> Vec<u8> {
        let mut b = ObjectBuilder::new(&format!("{sym}.o")).set_subsections_via_symbols(true);
        let text = b.add_section(ObjectSection::text(
            "__text",
            vec![
                0x20, 0x00, 0x00, 0x8B, // add x0, x1, x0
                0x00, 0x00, 0x00, 0x8B, // add x0, x0, x0 (distinct bytes)
                0xC0, 0x03, 0x5F, 0xD6, // ret
            ],
            vec![],
        ));
        b.add_symbol(ObjectSymbol::Defined {
            name: sym.into(),
            section_index: text,
            value: 0,
            weak: false,
        });
        b.build().unwrap()
    }

    fn cfg_with(icf: IcfMode) -> LinkConfig {
        LinkConfig {
            ident: "icf-test".into(),
            icf,
            entry_symbol: "_f0".into(),
            ..LinkConfig::default()
        }
    }

    #[test]
    fn icf_mode_defaults_to_none() {
        assert_eq!(IcfMode::default(), IcfMode::None);
        assert!(!IcfMode::None.is_active());
        assert!(IcfMode::Safe.is_active());
        assert!(IcfMode::All.is_active());
        assert!(!IcfMode::Safe.allows_address_taken());
        assert!(IcfMode::All.allows_address_taken());
    }

    /// Identical live atoms fold: `__text` shrinks from 36 to 12 bytes and
    /// every alias keeps its name at the canonical address.
    #[test]
    fn m6_identical_functions_fold() {
        let inputs: Vec<LinkInput> = ["_f0", "_f1", "_f2"]
            .iter()
            .map(|n| LinkInput {
                name: format!("{n}.o"),
                bytes: identical_fn(n),
            })
            .collect();
        let cfg = cfg_with(IcfMode::Safe);
        let result = link_with(&inputs, &[], &cfg, crate::Parallelism::Serial).unwrap();
        assert_eq!(result.objects.len(), 3);
        let text = result
            .layout
            .sections
            .iter()
            .find(|s| s.name == "__text")
            .unwrap();
        assert_eq!(text.size, 12, "three 12-byte bodies fold to one");
        let values: Vec<u64> = result
            .layout
            .symbols
            .iter()
            .filter(|s| s.external)
            .map(|s| s.value)
            .collect();
        assert_eq!(
            values.len(),
            4,
            "three aliases + __mh_execute_header: {values:?}"
        );
        let aliases = &values[..3];
        assert!(
            aliases.windows(2).all(|w| w[0] == w[1]),
            "all aliases share the canonical address: {values:?}"
        );
        assert_ne!(aliases[0], values[3], "the header symbol is separate");
    }

    /// Different targets keep functions apart even with identical bytes.
    #[test]
    fn m6_identical_bytes_with_different_targets_do_not_fold() {
        let mk = |name: &str, call: &str, define: &str| {
            let mut b = ObjectBuilder::new(name).set_subsections_via_symbols(true);
            let text = b.add_section(ObjectSection::text(
                "__text",
                vec![
                    0x94, 0x00, 0x00, 0x00, // bl <target>
                    0xC0, 0x03, 0x5F, 0xD6, // ret
                ],
                vec![ObjectReloc::branch26(0).at(0)],
            ));
            b.add_symbol(ObjectSymbol::Defined {
                name: define.into(),
                section_index: text,
                value: 0,
                weak: false,
            });
            b.add_symbol(ObjectSymbol::Undefined {
                name: call.into(),
                weak_ref: false,
            });
            b.build().unwrap()
        };
        let callees = {
            let mut b = ObjectBuilder::new("callees.o").set_subsections_via_symbols(true);
            let t = b.add_section(ObjectSection::text(
                "__text",
                vec![0xC0, 0x03, 0x5F, 0xD6, 0xC0, 0x03, 0x5F, 0xD6],
                vec![],
            ));
            b.add_symbol(ObjectSymbol::Defined {
                name: "_callee_a".into(),
                section_index: t,
                value: 0,
                weak: false,
            });
            b.add_symbol(ObjectSymbol::Defined {
                name: "_callee_b".into(),
                section_index: t,
                value: 4,
                weak: false,
            });
            b.build().unwrap()
        };
        let inputs = vec![
            LinkInput {
                name: "a.o".into(),
                bytes: mk("a.o", "_callee_a", "_caller_a"),
            },
            LinkInput {
                name: "b.o".into(),
                bytes: mk("b.o", "_callee_b", "_caller_b"),
            },
            LinkInput {
                name: "callees.o".into(),
                bytes: callees,
            },
        ];
        let cfg = LinkConfig {
            entry_symbol: "_caller_a".into(),
            ..cfg_with(IcfMode::Safe)
        };
        let layout = link_with(&inputs, &[], &cfg, crate::Parallelism::Serial)
            .unwrap()
            .layout;
        let text = layout.sections.iter().find(|s| s.name == "__text").unwrap();
        assert_eq!(text.size, 24, "no fold across distinct branch targets");
        let branches = text
            .pieces
            .iter()
            .flat_map(|p| p.patches.iter())
            .filter(|op| matches!(op, crate::PatchOp::Branch26 { .. }))
            .count();
        assert_eq!(branches, 2, "both callers keep their own branch");
    }

    /// `-icf=safe` keeps address-taken functions; `-icf=all` folds them.
    #[test]
    fn m6_safe_mode_respects_address_taken() {
        let mk = |name: &str, ptr: bool| {
            let mut b = ObjectBuilder::new(name).set_subsections_via_symbols(true);
            let text = b.add_section(ObjectSection::text(
                "__text",
                vec![0xC0, 0x03, 0x5F, 0xD6], // ret
                vec![],
            ));
            let fn_sym = b.add_symbol(ObjectSymbol::Defined {
                name: if ptr { "_fn1" } else { "_fn0" }.into(),
                section_index: text,
                value: 0,
                weak: false,
            });
            if ptr {
                let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
                b.add_symbol(ObjectSymbol::Defined {
                    name: "_fn_ptr".into(),
                    section_index: data,
                    value: 0,
                    weak: false,
                });
                b.section_mut(data).relocs = vec![ObjectReloc::unsigned(fn_sym as u32).at(0)];
            }
            b.build().unwrap()
        };
        let inputs = vec![
            LinkInput {
                name: "f0.o".into(),
                bytes: mk("f0.o", false),
            },
            LinkInput {
                name: "f1.o".into(),
                bytes: mk("f1.o", true),
            },
        ];
        let base = LinkConfig {
            ident: "icf-ptr".into(),
            entry_symbol: "_fn0".into(),
            ..cfg_with(IcfMode::Safe)
        };
        let safe = link_with(&inputs, &[], &base, crate::Parallelism::Serial)
            .unwrap()
            .layout;
        let text = safe.sections.iter().find(|s| s.name == "__text").unwrap();
        assert_eq!(text.size, 8, "address-taken function stays in safe mode");
        let all = link_with(
            &inputs,
            &[],
            &LinkConfig {
                icf: IcfMode::All,
                ..base
            },
            crate::Parallelism::Serial,
        )
        .unwrap()
        .layout;
        let text = all.sections.iter().find(|s| s.name == "__text").unwrap();
        assert_eq!(text.size, 4, "-icf=all folds it anyway");
    }

    /// ICF composes with dead-strip: dylib exports root the atoms; the
    /// identical copies fold.
    #[test]
    fn m6_icf_composes_with_dead_strip() {
        let inputs: Vec<LinkInput> = ["_f0", "_f1", "_f2"]
            .iter()
            .map(|n| LinkInput {
                name: format!("{n}.o"),
                bytes: identical_fn(n),
            })
            .collect();
        let cfg = LinkConfig {
            filetype: crate::layout::OutputType::Dylib,
            install_name: Some("@rpath/libf.dylib".into()),
            dead_strip: true,
            ..cfg_with(IcfMode::Safe)
        };
        let layout = link_with(&inputs, &[], &cfg, crate::Parallelism::Serial)
            .unwrap()
            .layout;
        let text = layout.sections.iter().find(|s| s.name == "__text").unwrap();
        assert_eq!(text.size, 12, "exports root all three; ICF folds two");
    }

    /// Determinism (TDD §4.3): the fold plan is identical across the serial
    /// and parallel pipelines and across repeated runs.
    #[test]
    fn m6_icf_is_schedule_and_repeat_stable() {
        let inputs: Vec<LinkInput> = ["_f0", "_f1", "_f2"]
            .iter()
            .map(|n| LinkInput {
                name: format!("{n}.o"),
                bytes: identical_fn(n),
            })
            .collect();
        let cfg = cfg_with(IcfMode::Safe);
        let a = link_with(&inputs, &[], &cfg.clone(), crate::Parallelism::Serial)
            .unwrap()
            .layout;
        let b = link_with(&inputs, &[], &cfg, crate::Parallelism::Auto)
            .unwrap()
            .layout;
        assert_eq!(a.file_size, b.file_size);
        for (s1, s2) in a.sections.iter().zip(b.sections.iter()) {
            assert_eq!(s1.size, s2.size, "{}", s1.name);
            for (p1, p2) in s1.pieces.iter().zip(s2.pieces.iter()) {
                assert_eq!(p1.in_range, p2.in_range, "{}", s1.name);
            }
        }
        let _: FoldPlan = FoldPlan::default();
        let _ = deadstrip::LiveSet::default();
        let _ = fold;
    }
}
