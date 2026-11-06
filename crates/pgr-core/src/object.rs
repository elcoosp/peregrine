//! Pass 1 — parse & intern (TDD §5 Pass 1, minimal M1 shape).
//!
//! Per input file, materializes the per-file arena the later passes consume:
//! input sections (with decoded relocations) and the typed symbol table.
//! Relocations are *located here* and applied in Pass 4 (emit); pair
//! decoding (`ADDEND`→page relocs, `SUBTRACTOR`→`UNSIGNED`) happens once,
//! here, exactly like the spec demands.
//!
//! Input lifetime: the caller holds the object bytes for the whole link (the
//! M4 `InputArena`); all cross-references are byte ranges, never pointers.

use crate::LinkError;
use crate::ids::{FileId, StringId};
use pgr_format::consts::{
    ARM64_RELOC_ADDEND, ARM64_RELOC_BRANCH26, ARM64_RELOC_GOT_LOAD_PAGE21,
    ARM64_RELOC_GOT_LOAD_PAGEOFF12, ARM64_RELOC_PAGE21, ARM64_RELOC_PAGEOFF12,
    ARM64_RELOC_POINTER_TO_GOT, ARM64_RELOC_SUBTRACTOR, ARM64_RELOC_UNSIGNED, N_EXT, N_STAB,
    N_TYPE, N_UNDF, N_WEAK_DEF, N_WEAK_REF, S_ZEROFILL, SECTION_TYPE_MASK,
};
use rayon::prelude::*;

/// Inputs at or above this size split their Pass 1 work across the pool
/// (giant-object threshold, perf doc §4.1: default 64 MiB, "tunable").
pub const GIANT_OBJECT_BYTES: u64 = 64 << 20;
/// Symbol tables at or above this count split the same way (a small file can
/// still carry a huge symtab after section stripping).
pub const GIANT_SYMS: usize = 1 << 20;
use pgr_format::header::MachHeader64;
use pgr_format::load_command::{LoadCommandIter, LoadCommandKind};
use pgr_format::reloc::RelocationInfo;
use pgr_format::segment::{Section64, SegmentCommand64};

/// Decodes a symbol-table range on the pool (exposed `doc(hidden)` for the
/// giant-object mechanism tests and benches; production code goes through
/// [`InputObject::parse`]).
///
/// # Errors
/// [`LinkError::Parse`] on malformed symbol table entries.
#[doc(hidden)]
pub fn decode_symbol_range_for_test<F: Fn(String) -> LinkError + Sync>(
    bytes: &[u8],
    st: &pgr_format::SymtabCommand,
    strtab: &[u8],
    sections: &[InputSection],
    range: core::ops::Range<usize>,
    fail: &F,
) -> Result<(Vec<InputSymbol>, Vec<Vec<u8>>), LinkError> {
    InputObject::decode_symbols(bytes, st, strtab, sections, range, fail)
}

/// The decoded relocation kinds the emit path can apply (TDD §3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocKind {
    /// 8-byte absolute pointer slot → chained fixup (rebase or bind).
    Unsigned,
    /// `B`/`BL` 26-bit branch immediate.
    Branch26,
    /// ADRP page immediate, with its paired `ADDEND`.
    Page21 {
        /// Addend carried by the paired `ADDEND` entry.
        addend: i64,
    },
    /// ADD/LDR/STR 12-bit page-offset immediate, with its paired `ADDEND`.
    PageOff12 {
        /// Addend carried by the paired `ADDEND` entry.
        addend: i64,
    },
    /// ADRP against the symbol's synthetic GOT slot, with its paired
    /// `ADDEND` (M2: the slot is synthesized in `__DATA_CONST,__got`).
    GotLoadPage21 {
        /// Addend carried by the paired `ADDEND` entry.
        addend: i64,
    },
    /// LDR against the symbol's synthetic GOT slot, with its paired
    /// `ADDEND` (M2).
    GotLoadPageOff12 {
        /// Addend carried by the paired `ADDEND` entry.
        addend: i64,
    },
    /// A pointer whose value is the symbol's GOT slot address (M2: the
    /// slot becomes a chained rebase targeting the GOT slot's vaddr).
    PointerToGot,
    /// Paired subtraction: this relocation's `target` is the *subtrahend*;
    /// the preceding `SUBTRACTOR` named the minuend.
    Subtractor {
        /// The minuend target from the paired `SUBTRACTOR` entry.
        minuend: RelocTarget,
    },
}

/// What a relocation refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocTarget {
    /// An external symbol (interned name).
    Extern(StringId),
    /// A section of the same input file (0-based local ordinal).
    Section(usize),
}

/// A decoded, pair-resolved relocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedReloc {
    /// Section-relative offset of the relocated item.
    pub offset: u32,
    /// Decoded kind (pairs already merged).
    pub kind: RelocKind,
    /// What the relocation names.
    pub target: RelocTarget,
    /// True when PC-relative.
    pub pcrel: bool,
    /// `r_length` exponent.
    pub length_log2: u32,
}

/// One input section of a relocatable object.
#[derive(Debug, Clone)]
pub struct InputSection {
    /// Section name (`__text`...).
    pub name: String,
    /// Owning segment name (`__TEXT`...).
    pub segment: String,
    /// `S_*` type/attribute flags.
    pub flags: u32,
    /// Alignment exponent.
    pub align_log2: u32,
    /// Section `addr`: the base symbol `n_value`s are relative to. Nonzero
    /// under the LLVM single-segment convention where the address is the
    /// section's offset into the object's section-data blob.
    pub addr: u64,
    /// Byte range within the object (empty for zero-fill sections).
    pub data: core::ops::Range<u64>,
    /// Virtual size (== byte length except zero-fill).
    pub size: u64,
    /// True for `S_ZEROFILL` (no file bytes).
    pub zerofill: bool,
    /// Raw `relocation_info` table (pairs decoded after symbol parsing).
    raw_relocs: Vec<RelocationInfo>,
    /// Decoded relocation table (populated by [`InputObject::finish`]).
    pub relocs: Vec<DecodedReloc>,
}

impl InputSection {
    /// The input bytes backing this section.
    #[must_use]
    pub fn bytes<'a>(&self, file: &'a [u8]) -> &'a [u8] {
        if self.zerofill {
            &[]
        } else {
            file.get(self.data.start as usize..self.data.end as usize)
                .unwrap_or(&[])
        }
    }
}

/// One symbol table entry of a relocatable object, typed once (Pass 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputSymbol {
    /// Interned name (patched by [`InputObject::finish`] after interning).
    pub name: StringId,
    /// True when `N_EXT`.
    pub external: bool,
    /// True for stabs (skipped everywhere).
    pub stab: bool,
    /// 0-based defining section (`N_SECT`), `None` otherwise.
    pub section: Option<usize>,
    /// `n_value`: address / common size.
    pub value: u64,
    /// `N_WEAK_DEF`.
    pub weak_def: bool,
    /// `N_WEAK_REF`.
    pub weak_ref: bool,
    /// Common-symbol alignment exponent (`GET_COMM_ALIGN`) when tentative.
    pub common_align: Option<u32>,
    /// `N_ALT_ENTRY` (n_desc): merges into the preceding atom (M5/D1).
    pub alt_entry: bool,
}

impl InputSymbol {
    /// True when this is an external definition (`N_SECT | N_EXT`).
    #[must_use]
    pub const fn is_defined(&self) -> bool {
        self.external && self.section.is_some()
    }

    /// True when this is a tentative/common symbol.
    #[must_use]
    pub const fn is_common(&self) -> bool {
        self.external && self.section.is_none() && !self.stab && self.value != 0
    }

    /// True when this is a plain undefined external.
    #[must_use]
    pub const fn is_undefined(&self) -> bool {
        self.external && self.section.is_none() && !self.stab && self.value == 0
    }
}

/// A parsed relocatable object (Pass 1 arena).
#[derive(Debug, Clone)]
pub struct InputObject {
    /// Command-line identity.
    pub file: FileId,
    /// File name (diagnostics only).
    pub name: String,
    /// The raw object bytes (caller-owned for the whole link).
    pub bytes: Vec<u8>,
    /// Input sections in file order (the file's `n_sect` numbering).
    pub sections: Vec<InputSection>,
    /// Symbol table in file order.
    pub symbols: Vec<InputSymbol>,
    /// Symbol names in table order (drained into the global interner).
    symbol_names: Vec<Vec<u8>>,
    /// M5: true when this object is an archive member (its definitions rank
    /// as [`crate::resolve::Rank::ArchiveStrong`]/[`crate::resolve::Rank::ArchiveWeak`]
    /// and lose to direct command-line objects).
    pub from_archive: bool,
    /// The archive this member came from (diagnostics only; empty for
    /// direct inputs).
    pub archive_name: String,
    /// `MH_SUBSECTIONS_VIA_SYMBOLS` (D1): sections split at symbol
    /// boundaries.
    pub subsections_via_symbols: bool,
    /// D1 atom table: per input section, the atom ranges (section-relative,
    /// sorted). Empty when [`Self::compute_atoms`] was not run or the header
    /// flag is absent.
    pub atoms: Vec<Vec<core::ops::Range<u64>>>,
}

impl InputObject {
    /// Parses one relocatable object.
    ///
    /// # Errors
    /// [`LinkError::Parse`] on malformed Mach-O; [`LinkError::Unsupported`]
    /// on input constructs M1 does not link (scattered relocs, unknown arm64
    /// relocation types, GOT-based references).
    pub fn parse(file: FileId, name: &str, bytes: Vec<u8>) -> Result<Self, LinkError> {
        let fail = |msg: String| LinkError::Parse {
            file: name.to_string(),
            message: msg,
        };
        let unsupported = |msg: String| LinkError::Unsupported {
            file: name.to_string(),
            message: msg,
        };

        let header = MachHeader64::parse(&bytes)
            .map_err(|e| fail(format!("not a valid Mach-O image: {e}")))?;
        if header.filetype != pgr_format::consts::MH_OBJECT {
            return Err(unsupported(format!(
                "file type {} is not MH_OBJECT (M1 links direct .o inputs only)",
                header.filetype
            )));
        }

        // ---- sweep 1: sections + symtab command ----------------------------
        let mut sections: Vec<InputSection> = Vec::new();
        let mut symtab = None;
        let mut it =
            LoadCommandIter::new(&bytes, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
                .map_err(|e| fail(format!("load command walk failed: {e}")))?;
        while let Some(cmd) = it
            .next_command()
            .map_err(|e| fail(format!("load command walk failed: {e}")))?
        {
            match cmd.kind {
                LoadCommandKind::Segment64 => {
                    let seg = SegmentCommand64::parse(cmd.bytes, 0)
                        .map_err(|e| fail(format!("segment command: {e}")))?;
                    let sects = seg
                        .sections(cmd.bytes, SegmentCommand64::SIZE)
                        .map_err(|e| fail(format!("section table: {e}")))?;
                    for s in sects {
                        sections.push(convert_section(s, &bytes, &fail)?);
                    }
                }
                LoadCommandKind::Symtab if symtab.is_none() => {
                    symtab = Some(
                        pgr_format::SymtabCommand::parse(cmd.bytes, 0)
                            .map_err(|e| fail(format!("LC_SYMTAB: {e}")))?,
                    );
                }
                _ => {}
            }
        }

        // ---- sweep 2: symbol table -----------------------------------------
        let st = symtab.ok_or_else(|| fail("relocatable object has no LC_SYMTAB".into()))?;
        let strtab = bytes
            .get(st.stroff as usize..st.stroff as usize + st.strsize as usize)
            .ok_or_else(|| fail("string table out of bounds".into()))?;
        // Giant objects (perf doc §4.1): decode the symbol table in
        // deterministic index chunks on the compute pool. The chunk boundaries
        // are a pure function of `nsyms`, so the concatenated result — and
        // every later pass — is schedule-independent.
        let (symbols, names) = if Self::is_giant(&bytes, st.nsyms as usize) {
            Self::decode_symbols_chunked(&bytes, &st, strtab, &sections, &fail)?
        } else {
            Self::decode_symbols(&bytes, &st, strtab, &sections, 0..st.nsyms as usize, &fail)?
        };

        let obj = Self {
            file,
            name: name.to_string(),
            bytes,
            sections,
            symbols,
            symbol_names: names,
            from_archive: false,
            archive_name: String::new(),
            subsections_via_symbols: header.flags & pgr_format::consts::MH_SUBSECTIONS_VIA_SYMBOLS
                != 0,
            atoms: Vec::new(),
        };
        Ok(obj)
    }

    /// D1 atomization (M5): fills the atom table for every section —
    /// `S_CSTRING_LITERALS` sections split at their NUL terminators (D4),
    /// `MH_SUBSECTIONS_VIA_SYMBOLS` sections at symbol boundaries (D1,
    /// `N_ALT_ENTRY` merges into the preceding atom; only when the link
    /// dead-strips — merging needs only the string split), everything else
    /// stays one whole-section atom. A pure function of the parsed input.
    pub fn compute_atoms(&mut self, split_symbols: bool) {
        self.atoms = Vec::with_capacity(self.sections.len());
        for sect in self.sections.iter() {
            if sect.zerofill || sect.size == 0 {
                self.atoms.push(Vec::new());
                continue;
            }
            if sect.flags & pgr_format::consts::SECTION_TYPE_MASK
                == pgr_format::consts::S_CSTRING_LITERALS
            {
                // D4: one atom per NUL-terminated literal (an unterminated
                // tail forms one string — malformed input stays linkable).
                let data = &self.bytes[sect.data.start as usize..sect.data.end as usize];
                let mut ranges: Vec<core::ops::Range<u64>> = Vec::new();
                let mut i = 0u64;
                while i < sect.size {
                    let end = data[i as usize..]
                        .iter()
                        .position(|&b| b == 0)
                        .map_or(sect.size, |p| i + p as u64 + 1);
                    if end > i {
                        ranges.push(i..end);
                    }
                    i = end;
                }
                self.atoms.push(ranges);
                continue;
            }
            if !self.subsections_via_symbols || !split_symbols {
                self.atoms.push(core::iter::once(0..sect.size).collect());
                continue;
            }
            let mut starts: Vec<u64> = vec![0];
            for sym in &self.symbols {
                if sym.alt_entry || sym.stab {
                    continue;
                }
                if sym.section == Some(self.atoms.len()) && sym.value > 0 && sym.value < sect.size {
                    starts.push(sym.value);
                }
            }
            starts.sort_unstable();
            starts.dedup();
            let mut ranges: Vec<core::ops::Range<u64>> = Vec::with_capacity(starts.len());
            for (i, &s) in starts.iter().enumerate() {
                let end = starts.get(i + 1).copied().unwrap_or(sect.size);
                if end > s {
                    ranges.push(s..end);
                }
            }
            if ranges.is_empty() {
                ranges.push(0..sect.size);
            }
            self.atoms.push(ranges);
        }
    }

    /// The atom ranges of one section (borrowed — the table is always
    /// materialized by [`Self::compute_atoms`]).
    #[must_use]
    pub fn atoms_of(&self, sect: usize) -> &[core::ops::Range<u64>] {
        self.atoms.get(sect).map_or(&[][..], Vec::as_slice)
    }

    /// True when this object's symbol table is big enough to split across
    /// the pool (giant-object splitting, perf doc §4.1: whole-module Rust
    /// and Swift objects otherwise serialize Pass 1).
    fn is_giant(bytes: &[u8], nsyms: usize) -> bool {
        bytes.len() as u64 >= GIANT_OBJECT_BYTES || nsyms >= GIANT_SYMS
    }

    /// Decodes symbols `[lo, hi)` of the table (a pure function of the
    /// inputs — the chunked path concatenates these ranges in order).
    fn decode_symbols<F: Fn(String) -> LinkError + Sync>(
        bytes: &[u8],
        st: &pgr_format::SymtabCommand,
        strtab: &[u8],
        sections: &[InputSection],
        range: core::ops::Range<usize>,
        fail: &F,
    ) -> Result<(Vec<InputSymbol>, Vec<Vec<u8>>), LinkError> {
        let mut symbols = Vec::with_capacity(range.len());
        let mut names: Vec<Vec<u8>> = Vec::with_capacity(range.len());
        for i in range {
            let off = st.symoff as usize + i * 16;
            let raw: pgr_format::symtab::Nlist64 =
                pgr_format::cursor::pod_read_unaligned_at(bytes, off)
                    .map_err(|e| fail(format!("symbol {i}: {e}")))?;
            let name_bytes: &[u8] = if (raw.n_strx as usize) < strtab.len() {
                let rest = &strtab[raw.n_strx as usize..];
                let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
                &rest[..end]
            } else {
                b""
            };
            names.push(name_bytes.to_vec());

            let stab = raw.n_type & N_STAB != 0;
            let external = raw.n_type & N_EXT != 0;
            let ntype = raw.n_type & N_TYPE;
            let (section, common_align) = if !stab && external && ntype == N_UNDF {
                if raw.n_value != 0 {
                    (None, Some(pgr_format::consts::get_comm_align(raw.n_desc)))
                } else {
                    (None, None)
                }
            } else if !stab && ntype == pgr_format::consts::N_SECT && raw.n_sect > 0 {
                if raw.n_sect as usize > sections.len() {
                    return Err(fail(format!(
                        "symbol {i}: defining section {} out of range (file has {})",
                        raw.n_sect,
                        sections.len()
                    )));
                }
                (Some(raw.n_sect as usize - 1), None)
            } else {
                (None, None)
            };
            // Normalize the value to *section-relative*: the LLVM
            // single-segment convention carries blob-relative `n_value`s and
            // nonzero section addresses; the legacy per-section convention
            // has addr == 0. One subtraction covers both.
            let value = match section {
                Some(idx) => {
                    let base = sections[idx].addr;
                    if raw.n_value < base {
                        return Err(fail(format!(
                            "symbol {i}: n_value {:#x} below section base {:#x}",
                            raw.n_value, base
                        )));
                    }
                    raw.n_value - base
                }
                None => raw.n_value,
            };
            symbols.push(InputSymbol {
                name: StringId(0), // patched by `finish` after interning
                external,
                stab,
                section,
                value,
                weak_def: raw.n_desc & N_WEAK_DEF != 0,
                weak_ref: raw.n_desc & N_WEAK_REF != 0,
                common_align,
                alt_entry: raw.n_desc & pgr_format::consts::N_ALT_ENTRY != 0,
            });
        }
        Ok((symbols, names))
    }

    /// Chunked symbol decode for giant objects: fixed index ranges decoded
    /// in parallel, concatenated in ascending index order (deterministic).
    fn decode_symbols_chunked<F: Fn(String) -> LinkError + Sync>(
        bytes: &[u8],
        st: &pgr_format::SymtabCommand,
        strtab: &[u8],
        sections: &[InputSection],
        fail: &F,
    ) -> Result<(Vec<InputSymbol>, Vec<Vec<u8>>), LinkError> {
        let nsyms = st.nsyms as usize;
        let workers = crate::pool::worker_count();
        let chunk_count = (workers * 4).clamp(2, 256);
        let chunk_len = nsyms.div_ceil(chunk_count).max(1);
        let bounds: Vec<usize> = (0..=nsyms).step_by(chunk_len).collect();
        let ranges: Vec<core::ops::Range<usize>> = bounds
            .windows(2)
            .map(|w| w[0]..w[1])
            .filter(|r| !r.is_empty())
            .collect();
        type DecodedPart = Result<(Vec<InputSymbol>, Vec<Vec<u8>>), LinkError>;
        let parts: Vec<DecodedPart> = crate::pool::compute_pool().install(|| {
            ranges
                .par_iter()
                .map(|r| Self::decode_symbols(bytes, st, strtab, sections, r.clone(), fail))
                .collect()
        });
        let mut symbols = Vec::with_capacity(nsyms);
        let mut names = Vec::with_capacity(nsyms);
        for part in parts {
            let (mut s, mut n) = part?;
            symbols.append(&mut s);
            names.append(&mut n);
        }
        Ok((symbols, names))
    }

    /// Symbol names in table order, handed to the global interner build.
    ///
    /// Drained by [`crate::link`]; [`InputObject::finish`] patches the ids.
    #[doc(hidden)]
    pub fn take_symbol_names(&mut self) -> Vec<Vec<u8>> {
        core::mem::take(&mut self.symbol_names)
    }

    /// Borrows the raw symbol names (pre-intern). The S7 pull fixpoint reads
    /// them without draining ([`InputObject::take_symbol_names`] hands the
    /// batch to the interner later).
    #[doc(hidden)]
    #[must_use]
    pub fn peek_symbol_names(&self) -> &[Vec<u8>] {
        &self.symbol_names
    }

    /// Patches interned ids and decodes relocation pairs (Pass 1 phase C).
    ///
    /// `name_ids[i]` is the [`StringId`] for table position `i`.
    ///
    /// # Errors
    /// [`LinkError::Parse`] on malformed relocation tables;
    /// [`LinkError::Unsupported`] on relocation constructs M1 rejects.
    pub fn finish(&mut self, name_ids: &[StringId]) -> Result<(), LinkError> {
        let fail = |msg: String| LinkError::Parse {
            file: self.name.clone(),
            message: msg,
        };
        let unsupported = |msg: String| LinkError::Unsupported {
            file: self.name.clone(),
            message: msg,
        };
        for (i, s) in self.symbols.iter_mut().enumerate() {
            s.name = *name_ids
                .get(i)
                .ok_or_else(|| fail(format!("symbol {i}: missing interner entry")))?;
        }

        // Pair rules (arm64, TDD §3.5): ADDEND precedes its PAGE21/PAGEOFF12;
        // SUBTRACTOR precedes the UNSIGNED that carries the subtrahend.
        for si in 0..self.sections.len() {
            let mut decoded: Vec<DecodedReloc> = Vec::new();
            let table = core::mem::take(&mut self.sections[si].raw_relocs);
            let mut i = 0usize;
            while i < table.len() {
                let r = table[i];
                if r.is_scattered() {
                    return Err(unsupported(
                        "scattered relocation (not generated by modern clang)".into(),
                    ));
                }
                match r.rtype() {
                    ARM64_RELOC_ADDEND => {
                        // r_symbolnum carries the addend value here, not a
                        // symbol/section reference.
                        let addend = r.symbolnum() as i32 as i64;
                        let Some(r2) = table.get(i + 1) else {
                            return Err(fail(
                                "ADDEND relocation is not followed by its target".into(),
                            ));
                        };
                        let kind = match r2.rtype() {
                            ARM64_RELOC_PAGE21 => RelocKind::Page21 { addend },
                            ARM64_RELOC_PAGEOFF12 => RelocKind::PageOff12 { addend },
                            ARM64_RELOC_GOT_LOAD_PAGE21 => RelocKind::GotLoadPage21 { addend },
                            ARM64_RELOC_GOT_LOAD_PAGEOFF12 => {
                                RelocKind::GotLoadPageOff12 { addend }
                            }
                            other => {
                                return Err(fail(format!(
                                    "ADDEND pair target is relocation type {other}, not a                                      PAGE/GOT-load reference"
                                )));
                            }
                        };
                        let t2 = self.reloc_target(r2, &fail)?;
                        decoded.push(DecodedReloc {
                            offset: r.r_address,
                            kind,
                            target: t2,
                            pcrel: r2.pcrel(),
                            length_log2: r2.length_log2(),
                        });
                        i += 2;
                    }
                    ARM64_RELOC_SUBTRACTOR => {
                        let minuend = self.reloc_target(&r, &fail)?;
                        let Some(r2) = table.get(i + 1) else {
                            return Err(fail(
                                "SUBTRACTOR relocation is not followed by its UNSIGNED".into(),
                            ));
                        };
                        if r2.rtype() != ARM64_RELOC_UNSIGNED {
                            return Err(fail(
                                "SUBTRACTOR pair target is not an UNSIGNED relocation".into(),
                            ));
                        }
                        if r2.length_log2() != 3 {
                            return Err(fail(
                                "SUBTRACTOR pair must relocate an 8-byte pointer".into(),
                            ));
                        }
                        let subtrahend = self.reloc_target(r2, &fail)?;
                        decoded.push(DecodedReloc {
                            offset: r.r_address,
                            kind: RelocKind::Subtractor { minuend },
                            target: subtrahend,
                            pcrel: false,
                            length_log2: r2.length_log2(),
                        });
                        i += 2;
                    }
                    ARM64_RELOC_UNSIGNED => {
                        if r.pcrel() {
                            return Err(unsupported(
                                "PC-relative UNSIGNED is not a standalone arm64 construct".into(),
                            ));
                        }
                        if r.length_log2() != 3 {
                            return Err(unsupported(format!(
                                "UNSIGNED relocation of {} byte(s) (only 8-byte pointers chain)",
                                r.length()
                            )));
                        }
                        let target = self.reloc_target(&r, &fail)?;
                        decoded.push(DecodedReloc {
                            offset: r.r_address,
                            kind: RelocKind::Unsigned,
                            target,
                            pcrel: false,
                            length_log2: r.length_log2(),
                        });
                        i += 1;
                    }
                    ARM64_RELOC_BRANCH26 => {
                        let target = self.reloc_target(&r, &fail)?;
                        decoded.push(DecodedReloc {
                            offset: r.r_address,
                            kind: RelocKind::Branch26,
                            target,
                            pcrel: true,
                            length_log2: r.length_log2(),
                        });
                        i += 1;
                    }
                    ARM64_RELOC_PAGE21 | ARM64_RELOC_PAGEOFF12 => {
                        return Err(fail(
                            "unpaired PAGE21/PAGEOFF12 (arm64 page relocs carry their addend \
                             in a preceding ADDEND pair member)"
                                .into(),
                        ));
                    }
                    ARM64_RELOC_GOT_LOAD_PAGE21 | ARM64_RELOC_GOT_LOAD_PAGEOFF12 => {
                        // Standalone GOT-load (no ADDEND pair): the addend
                        // is zero; clang emits the paired form, this shape
                        // appears in hand-built objects.
                        let target = self.reloc_target(&r, &fail)?;
                        let kind = if r.rtype() == ARM64_RELOC_GOT_LOAD_PAGE21 {
                            RelocKind::GotLoadPage21 { addend: 0 }
                        } else {
                            RelocKind::GotLoadPageOff12 { addend: 0 }
                        };
                        decoded.push(DecodedReloc {
                            offset: r.r_address,
                            kind,
                            target,
                            pcrel: r.pcrel(),
                            length_log2: r.length_log2(),
                        });
                        i += 1;
                    }
                    ARM64_RELOC_POINTER_TO_GOT => {
                        if r.pcrel() {
                            return Err(fail("POINTER_TO_GOT is not PC-relative".into()));
                        }
                        let target = self.reloc_target(&r, &fail)?;
                        decoded.push(DecodedReloc {
                            offset: r.r_address,
                            kind: RelocKind::PointerToGot,
                            target,
                            pcrel: false,
                            length_log2: r.length_log2(),
                        });
                        i += 1;
                    }
                    other => {
                        return Err(unsupported(format!(
                            "relocation type {other} is not an arm64 construct Peregrine \
                             links"
                        )));
                    }
                }
            }
            decoded.sort_by_key(|d| d.offset);
            self.sections[si].relocs = decoded;
        }
        Ok(())
    }

    /// Resolves one relocation's target to an interned name or local section.
    fn reloc_target(
        &self,
        r: &RelocationInfo,
        fail: &dyn Fn(String) -> LinkError,
    ) -> Result<RelocTarget, LinkError> {
        if r.is_extern() {
            let idx = r.symbolnum() as usize;
            let sym = self
                .symbols
                .get(idx)
                .ok_or_else(|| fail(format!("relocation references symbol index {idx}")))?;
            Ok(RelocTarget::Extern(sym.name))
        } else {
            let ord = r.symbolnum() as usize;
            if ord == 0 || ord > self.sections.len() {
                return Err(fail(format!(
                    "relocation section ordinal {ord} out of range (1..={})",
                    self.sections.len()
                )));
            }
            Ok(RelocTarget::Section(ord - 1))
        }
    }
}

// `symbol_names` is private with accessors so the transient Vec never leaks
// into user copies of the struct.

/// Reads a `Section64` into the arena form (raw relocs kept for pairing).
fn name16(field: &[u8; 16]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

fn convert_section(
    s: &Section64,
    file_bytes: &[u8],
    fail: &dyn Fn(String) -> LinkError,
) -> Result<InputSection, LinkError> {
    let zerofill = s.flags & SECTION_TYPE_MASK == S_ZEROFILL;
    let size = s.size;
    let name = name16(&s.sectname);
    let segment = name16(&s.segname);

    let mut data = 0u64..0u64;
    if !zerofill && size > 0 {
        let start = s.offset as u64;
        let end = start
            .checked_add(size)
            .ok_or_else(|| fail(format!("section {name}: size overflow")))?;
        if end > file_bytes.len() as u64 {
            return Err(fail(format!(
                "section {name}: file range [{start:#x}, {end:#x}) exceeds the file"
            )));
        }
        data = start..end;
    }
    let mut raw_relocs = Vec::with_capacity(s.nreloc as usize);
    for i in 0..s.nreloc as usize {
        let off = s.reloff as usize + i * 8;
        let r = RelocationInfo::parse(file_bytes, off)
            .map_err(|e| fail(format!("section {name}: relocation {i}: {e}")))?;
        raw_relocs.push(r);
    }
    Ok(InputSection {
        name,
        segment,
        flags: s.flags,
        align_log2: s.align.min(14),
        addr: s.addr,
        data,
        size,
        zerofill,
        raw_relocs,
        relocs: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::InputObject;
    use crate::ids::FileId;
    use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

    /// Giant-object splitting (perf doc §4.1): the chunked symbol decoder
    /// must produce exactly the serial decode for any chunk boundaries —
    /// exercised here against the real fixture builder with a table large
    /// enough to split several ways (`GIANT_SYMS` would gate at 2²⁰; the
    /// chunked path is driven directly so the mechanism is testable at
    /// CI-friendly sizes).
    #[test]
    fn chunked_symbol_decode_equals_the_serial_decode() {
        let nsyms = 5_000usize;
        let mut b = ObjectBuilder::new("giant.o");
        let text = b.add_section(ObjectSection::text("__text", vec![0u8; 64], Vec::new()));
        for i in 0..nsyms {
            b.add_symbol(ObjectSymbol::Defined {
                name: format!("_giant_fn_{i:06}"),
                section_index: text,
                value: (i % 16) as u64,
                weak: false,
            });
        }
        let bytes = b.build().unwrap();
        let obj = InputObject::parse(FileId(0), "giant.o", bytes.clone()).unwrap();

        // Re-derive the symtab command + strtab from the parsed layout the
        // same way parse() does, then decode ranges and compare.
        let header = pgr_format::header::MachHeader64::parse(&bytes).unwrap();
        let mut it = pgr_format::load_command::LoadCommandIter::new(
            &bytes,
            pgr_format::header::MachHeader64::SIZE,
            header.ncmds,
            header.sizeofcmds,
        )
        .unwrap();
        let mut st = None;
        while let Some(cmd) = it.next_command().unwrap() {
            if let pgr_format::load_command::LoadCommandKind::Symtab = cmd.kind {
                st = Some(pgr_format::SymtabCommand::parse(cmd.bytes, 0).unwrap());
            }
        }
        let st = st.unwrap();
        let strtab = &bytes[st.stroff as usize..st.stroff as usize + st.strsize as usize];
        let fail = |msg: String| crate::LinkError::Parse {
            file: "giant.o".into(),
            message: msg,
        };

        // Serial reference over the whole table.
        let (all_syms, all_names) = super::decode_symbol_range_for_test(
            &bytes,
            &st,
            strtab,
            &obj.sections,
            0..nsyms,
            &fail,
        )
        .unwrap();
        assert_eq!(all_syms.len(), nsyms);
        assert_eq!(all_names.len(), nsyms);

        // Chunked: overlapping-free ranges decoded separately, concatenated
        // in ascending order — must equal the serial decode exactly.
        let mut chunk_syms = Vec::new();
        let mut chunk_names = Vec::new();
        let mut lo = 0usize;
        for hi in [777usize, 1501, 4321, nsyms] {
            let (mut s, mut n) = super::decode_symbol_range_for_test(
                &bytes,
                &st,
                strtab,
                &obj.sections,
                lo..hi,
                &fail,
            )
            .unwrap();
            chunk_syms.append(&mut s);
            chunk_names.append(&mut n);
            lo = hi;
        }
        assert_eq!(chunk_syms.len(), all_syms.len());
        for (a, b) in chunk_syms.iter().zip(&all_syms) {
            assert_eq!(
                (a.section, a.value, a.external, a.weak_def, a.weak_ref),
                (b.section, b.value, b.external, b.weak_def, b.weak_ref)
            );
        }
        assert_eq!(chunk_names, all_names);
        // The gate constants stay tuned for the P0 rig (64 MiB / 2²⁰ syms);
        // const asserts keep the tuning contract visible without tripping
        // the assertions-on-constants lint.
        const {
            assert!(super::GIANT_OBJECT_BYTES >= 1 << 25);
            assert!(super::GIANT_SYMS >= 1 << 19);
        }
    }
}
