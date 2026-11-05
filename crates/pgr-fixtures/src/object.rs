//! Deterministic arm64 relocatable-object (`MH_OBJECT`, ".o") builder.
//!
//! The M1 pipeline consumes direct `.o` inputs only (TDD §12 "M1 — Static
//! hello-world"); this builder produces them deterministically, so every
//! downstream test links against byte-identical inputs and no Apple toolchain
//! is required on Linux. The emitted objects follow the exact rules clang
//! does for `-c` output:
//!
//! * one `LC_SEGMENT_64` carrying *all* sections (the LLVM/MC relocatable
//!   convention: anonymous segment name, blob-relative section addresses,
//!   1-based section ordinals counted across the whole file),
//! * `LC_SYMTAB` with locals first, then extern defs, then undefineds,
//! * relocation tables per section, `r_address` section-relative,
//! * `ARM64_RELOC_ADDEND` pairs precede their `PAGE21`/`PAGEOFF12` target,
//! * `ARM64_RELOC_SUBTRACTOR` pairs precede the `UNSIGNED` that carries the
//!   subtrahend (classic paired-subtraction encoding),
//! * tentative/common symbols are `N_UNDF | N_EXT` with `n_value` = size and
//!   the alignment exponent in `n_desc` (`GET_COMM_ALIGN`).
//!
//! Instruction encodings are real arm64 (ADRP/ADD/B/BL/RET/NOP/MOV), so the
//! relocation applier under test patches words that decode exactly like
//! clang's output.

use crate::pad_name;
use pgr_format::consts::{
    ARM64_RELOC_ADDEND, ARM64_RELOC_BRANCH26, ARM64_RELOC_GOT_LOAD_PAGE21,
    ARM64_RELOC_GOT_LOAD_PAGEOFF12, ARM64_RELOC_PAGE21, ARM64_RELOC_PAGEOFF12,
    ARM64_RELOC_POINTER_TO_GOT, ARM64_RELOC_SUBTRACTOR, ARM64_RELOC_UNSIGNED,
    CPU_SUBTYPE_ARM64_ALL, CPU_TYPE_ARM64, LC_BUILD_VERSION, MH_OBJECT, N_EXT, N_SECT, N_UNDF,
    N_WEAK_DEF, N_WEAK_REF, PLATFORM_MACOS, RELOC_LENGTH_4, RELOC_LENGTH_8,
    S_ATTR_PURE_INSTRUCTIONS, S_CSTRING_LITERALS, S_REGULAR, S_ZEROFILL, SECTION_TYPE_MASK,
    TOOL_CLANG, VM_PROT_READ, VM_PROT_WRITE,
};
use pgr_format::cursor::pod_read_unaligned_at;
use pgr_format::reloc::RelocationInfo;
use pgr_format::segment::Section64;
use pgr_format::symtab::Nlist64;

/// A relocation to attach to a section, section-relative.
///
/// Mirrors the fields the applier reads ([`pgr_format::reloc::RelocationInfo`]
/// bit layout) so the fixture table and the parser agree by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectReloc {
    /// Offset of the relocated item within its section.
    pub offset: u32,
    /// `r_symbolnum`: symbol index (`extern`) or 1-based section ordinal.
    pub symbolnum: u32,
    /// PC-relative item.
    pub pcrel: bool,
    /// `r_length` exponent (0=1, 1=2, 2=4, 3=8).
    pub length_log2: u32,
    /// `r_extern`: `symbolnum` names a symbol-table entry.
    pub extern_: bool,
    /// The `ARM64_RELOC_*` type.
    pub rtype: u32,
}

impl ObjectReloc {
    /// 8-byte absolute pointer (`ARM64_RELOC_UNSIGNED`, external).
    #[must_use]
    pub const fn unsigned(sym: u32) -> Self {
        Self {
            offset: 0,
            symbolnum: sym,
            pcrel: false,
            length_log2: RELOC_LENGTH_8,
            extern_: true,
            rtype: ARM64_RELOC_UNSIGNED,
        }
    }

    /// `B`/`BL` immediate (`ARM64_RELOC_BRANCH26`, external).
    #[must_use]
    pub const fn branch26(sym: u32) -> Self {
        Self {
            offset: 0,
            symbolnum: sym,
            pcrel: true,
            length_log2: RELOC_LENGTH_4,
            extern_: true,
            rtype: ARM64_RELOC_BRANCH26,
        }
    }

    /// ADRP page immediate (`ARM64_RELOC_PAGE21`, external).
    #[must_use]
    pub const fn page21(sym: u32) -> Self {
        Self {
            offset: 0,
            symbolnum: sym,
            pcrel: true,
            length_log2: RELOC_LENGTH_4,
            extern_: true,
            rtype: ARM64_RELOC_PAGE21,
        }
    }

    /// ADD/LDR 12-bit page-offset immediate (`ARM64_RELOC_PAGEOFF12`).
    #[must_use]
    pub const fn pageoff12(sym: u32) -> Self {
        Self {
            offset: 0,
            symbolnum: sym,
            pcrel: false,
            length_log2: RELOC_LENGTH_4,
            extern_: true,
            rtype: ARM64_RELOC_PAGEOFF12,
        }
    }

    /// Paired `ARM64_RELOC_ADDEND` (carries the addend for page relocs).
    #[must_use]
    pub const fn addend(value: i64) -> Self {
        Self {
            offset: 0,
            // r_symbolnum is the addend for ADDEND entries (never external).
            symbolnum: value as i32 as u32,
            pcrel: false,
            length_log2: RELOC_LENGTH_4,
            extern_: false,
            rtype: ARM64_RELOC_ADDEND,
        }
    }

    /// Paired `ARM64_RELOC_SUBTRACTOR` (minuend; precedes an `UNSIGNED`).
    #[must_use]
    pub const fn subtractor(sym: u32) -> Self {
        Self {
            offset: 0,
            symbolnum: sym,
            pcrel: false,
            length_log2: RELOC_LENGTH_8,
            extern_: true,
            rtype: ARM64_RELOC_SUBTRACTOR,
        }
    }

    /// ADRP against the symbol's GOT slot (`ARM64_RELOC_GOT_LOAD_PAGE21`).
    #[must_use]
    pub const fn got_page21(sym: u32) -> Self {
        Self {
            offset: 0,
            symbolnum: sym,
            pcrel: true,
            length_log2: RELOC_LENGTH_4,
            extern_: true,
            rtype: ARM64_RELOC_GOT_LOAD_PAGE21,
        }
    }

    /// LDR against the symbol's GOT slot (`ARM64_RELOC_GOT_LOAD_PAGEOFF12`).
    #[must_use]
    pub const fn got_pageoff12(sym: u32) -> Self {
        Self {
            offset: 0,
            symbolnum: sym,
            pcrel: false,
            length_log2: RELOC_LENGTH_4,
            extern_: true,
            rtype: ARM64_RELOC_GOT_LOAD_PAGEOFF12,
        }
    }

    /// A data pointer whose value is the symbol's GOT slot address
    /// (`ARM64_RELOC_POINTER_TO_GOT`).
    #[must_use]
    pub const fn pointer_to_got(sym: u32) -> Self {
        Self {
            offset: 0,
            symbolnum: sym,
            pcrel: false,
            length_log2: RELOC_LENGTH_8,
            extern_: true,
            rtype: ARM64_RELOC_POINTER_TO_GOT,
        }
    }

    /// Positions the relocation at `offset` within its section.
    #[must_use]
    pub const fn at(mut self, offset: u32) -> Self {
        self.offset = offset;
        self
    }
}

/// A section of the relocatable object.
#[derive(Debug, Clone)]
pub struct ObjectSection {
    /// Section name without padding (`__text`, `__data`, ...).
    pub name: String,
    /// Owning segment name (`__TEXT`, `__DATA`, ...).
    pub segment: String,
    /// Alignment exponent (`2^align`).
    pub align_log2: u32,
    /// `S_*` flags (type and attributes).
    pub flags: u32,
    /// Section content (ignored for zero-fill sections).
    pub data: Vec<u8>,
    /// Relocation entries (section-relative addresses).
    pub relocs: Vec<ObjectReloc>,
}

impl ObjectSection {
    /// A code section (`__TEXT,__text`).
    #[must_use]
    pub fn text(name: &str, data: Vec<u8>, relocs: Vec<ObjectReloc>) -> Self {
        Self {
            name: name.into(),
            segment: "__TEXT".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data,
            relocs,
        }
    }

    /// A C-string section (`__TEXT,__cstring`).
    #[must_use]
    pub fn cstring(data: &str) -> Self {
        Self {
            name: "__cstring".into(),
            segment: "__TEXT".into(),
            align_log2: 0,
            flags: S_CSTRING_LITERALS,
            data: format!("{data}\0").into_bytes(),
            relocs: Vec::new(),
        }
    }

    /// A regular data section (`__DATA,<name>`).
    #[must_use]
    pub fn data(name: &str, data: Vec<u8>, relocs: Vec<ObjectReloc>) -> Self {
        Self {
            name: name.into(),
            segment: "__DATA".into(),
            align_log2: 3,
            flags: S_REGULAR,
            data,
            relocs,
        }
    }

    /// A read-only data section (`__TEXT,__const`).
    #[must_use]
    pub fn rodata(name: &str, data: Vec<u8>, relocs: Vec<ObjectReloc>) -> Self {
        Self {
            name: name.into(),
            segment: "__TEXT".into(),
            align_log2: 3,
            flags: S_REGULAR,
            data,
            relocs,
        }
    }

    /// A zero-fill section (`S_ZEROFILL`; occupies VM, no file bytes).
    #[must_use]
    pub fn zerofill(name: &str, size: usize, align_log2: u32) -> Self {
        Self {
            name: name.into(),
            segment: "__DATA".into(),
            align_log2,
            flags: S_ZEROFILL,
            data: Vec::new(),
            relocs: Vec::new(),
        }
        .with_size(size)
    }

    /// Forces a section size (used by [`ObjectSection::zerofill`]).
    fn with_size(mut self, size: usize) -> Self {
        self.data = vec![0u8; size];
        self
    }
}

/// A symbol of the relocatable object, in declaration order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectSymbol {
    /// Local symbol (`!N_EXT`): name-only entry.
    Local(
        /// Symbol name as written in source.
        String,
    ),
    /// External definition (`N_SECT | N_EXT`).
    Defined {
        /// Symbol name.
        name: String,
        /// 0-based index into the builder's section list.
        section_index: usize,
        /// Section-relative address.
        value: u64,
        /// `N_WEAK_DEF` semantics.
        weak: bool,
    },
    /// Undefined external reference.
    Undefined {
        /// Symbol name.
        name: String,
        /// `N_WEAK_REF` semantics.
        weak_ref: bool,
    },
    /// Tentative/common symbol (`N_UNDF | N_EXT` with `n_value != 0`).
    Common {
        /// Symbol name.
        name: String,
        /// Requested size in bytes.
        size: u64,
        /// Alignment exponent carried in `n_desc` (`GET_COMM_ALIGN`).
        align_log2: u32,
    },
}

/// Deterministic arm64 relocatable-object builder.
///
/// Assembles an `MH_OBJECT` image the way clang does: a single
/// `LC_SEGMENT_64` carrying every section (the LLVM/MC relocatable
/// convention — anonymous segment name, section addresses are offsets into
/// the one section-data blob, symbol `n_value`s are blob-relative), the
/// `LC_SYMTAB` grouped locals → extern defs → undefineds / commons, and
/// per-section relocation tables. No clocks, no entropy: the same spec
/// builds byte-identical objects.
#[derive(Debug, Clone)]
pub struct ObjectBuilder {
    /// Source file name (kept only for actionable failure messages).
    name: String,
    sections: Vec<ObjectSection>,
    symbols: Vec<ObjectSymbol>,
    build_version: bool,
}

impl ObjectBuilder {
    /// Starts an empty object named `name`.
    #[must_use]
    pub fn new(name: &str) -> Self {
        Self {
            name: name.into(),
            sections: Vec::new(),
            symbols: Vec::new(),
            build_version: true,
        }
    }

    /// Appends a section and returns the 0-based section index.
    pub fn add_section(&mut self, section: ObjectSection) -> usize {
        self.sections.push(section);
        self.sections.len() - 1
    }

    /// Mutable access to a section (relocations are attached after the fact).
    pub fn section_mut(&mut self, index: usize) -> &mut ObjectSection {
        &mut self.sections[index]
    }

    /// Appends a symbol and returns the declaration index (resolve it to a
    /// relocation-referenced index with [`ObjectBuilder::sym_index`]).
    pub fn add_symbol(&mut self, symbol: ObjectSymbol) -> usize {
        self.symbols.push(symbol);
        self.symbols.len() - 1
    }

    /// Controls whether `LC_BUILD_VERSION` is emitted (clang emits it).
    #[must_use]
    pub const fn set_build_version(mut self, on: bool) -> Self {
        self.build_version = on;
        self
    }

    /// The builder's object name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Assembles the relocatable object.
    ///
    /// Layout (the relocatable convention — no segments/pages, no fixups):
    /// header | load commands | one section-data blob | relocation tables |
    /// symtab | strtab. Section addresses and symbol `n_value`s are
    /// offsets into the blob; zero-fill sections advance the blob address
    /// but commit no file bytes.
    pub fn build(&self) -> Result<Vec<u8>, String> {
        if self.sections.len() > u8::MAX as usize {
            return Err(format!("{}: too many sections", self.name));
        }
        if self.symbols.len() >= u16::MAX as usize {
            return Err(format!("{}: too many symbols", self.name));
        }

        // ---- load command sizing ----------------------------------------
        let mut ncmds = 2u32; // LC_SEGMENT_64 + LC_SYMTAB
        let mut sizeofcmds = 72 + 80 * self.sections.len() + 24;
        if self.build_version {
            sizeofcmds += 32;
            ncmds += 1;
        }
        let header_len = 32 + sizeofcmds;

        // ---- placement: one blob of section data --------------------------
        // LLVM convention: section `addr` values are offsets into the blob,
        // symbol `n_value`s are blob-relative, and the blob starts right
        // after the load commands. Zero-fill sections advance the blob
        // cursor but commit no bytes.
        let mut placed: Vec<(u64, u64)> = Vec::new(); // (blob addr, size)
        let mut blob = 0u64;
        for sec in &self.sections {
            blob = align_up(blob, 1u64 << sec.align_log2.min(14));
            let size = sec.data.len() as u64;
            placed.push((blob, size));
            blob += size;
        }
        let blob_span = blob;
        let mut rel_offs: Vec<u64> = Vec::with_capacity(self.sections.len());
        for sec in &self.sections {
            if sec.relocs.is_empty() {
                rel_offs.push(0);
                continue;
            }
            blob = align_up(blob, 4);
            rel_offs.push(header_len as u64 + blob);
            blob += sec.relocs.len() as u64 * 8;
        }
        let symoff = align_up(header_len as u64 + blob, 8);

        // ---- symbol table (grouped: locals, defs, undefs/commons) --------
        let mut strtab: Vec<u8> = vec![0];
        let mut entries: Vec<(u32, u8, u8, u16, u64)> = Vec::new();
        let push_sym = |strtab: &mut Vec<u8>,
                        entries: &mut Vec<(u32, u8, u8, u16, u64)>,
                        name: &str,
                        n_type: u8,
                        n_sect: u8,
                        n_desc: u16,
                        value: u64| {
            let strx = strtab.len() as u32;
            strtab.extend_from_slice(name.as_bytes());
            strtab.push(0);
            entries.push((strx, n_type, n_sect, n_desc, value));
        };
        for sym in &self.symbols {
            if let ObjectSymbol::Local(name) = sym {
                push_sym(&mut strtab, &mut entries, name, 0, 0, 0, 0);
            }
        }
        for sym in &self.symbols {
            if let ObjectSymbol::Defined {
                name,
                section_index,
                value,
                weak,
            } = sym
            {
                let n_desc = if *weak { N_WEAK_DEF } else { 0 };
                let blob_addr = placed.get(*section_index).map_or(0, |(addr, _)| *addr);
                push_sym(
                    &mut strtab,
                    &mut entries,
                    name,
                    N_EXT | N_SECT,
                    (*section_index + 1) as u8,
                    n_desc,
                    blob_addr + *value,
                );
            }
        }
        for sym in &self.symbols {
            match sym {
                ObjectSymbol::Undefined { name, weak_ref } => {
                    let n_desc = if *weak_ref { N_WEAK_REF } else { 0 };
                    push_sym(
                        &mut strtab,
                        &mut entries,
                        name,
                        N_EXT | N_UNDF,
                        0,
                        n_desc,
                        0,
                    );
                }
                ObjectSymbol::Common {
                    name,
                    size,
                    align_log2,
                } => {
                    let n_desc = ((*align_log2 as u16) & 0x0f) << 8;
                    push_sym(
                        &mut strtab,
                        &mut entries,
                        name,
                        N_EXT | N_UNDF,
                        0,
                        n_desc,
                        *size,
                    );
                }
                _ => {}
            }
        }
        let nsyms = entries.len() as u32;
        let stroff = symoff + nsyms as u64 * 16;
        let file_len = stroff + strtab.len() as u64;

        // ---- assemble ------------------------------------------------------
        let mut buf = vec![0u8; file_len as usize];
        buf[0..4].copy_from_slice(&pgr_format::consts::MH_MAGIC_64.to_le_bytes());
        buf[4..8].copy_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
        buf[8..12].copy_from_slice(&CPU_SUBTYPE_ARM64_ALL.to_le_bytes());
        buf[12..16].copy_from_slice(&MH_OBJECT.to_le_bytes());
        buf[16..20].copy_from_slice(&ncmds.to_le_bytes());
        buf[20..24].copy_from_slice(&(sizeofcmds as u32).to_le_bytes());

        let mut lc = 32usize;
        let w32 = |buf: &mut [u8], at: usize, v: u32| {
            buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
        };
        let w64 = |buf: &mut [u8], at: usize, v: u64| {
            buf[at..at + 8].copy_from_slice(&v.to_le_bytes());
        };

        // Single anonymous segment carrying every section (LLVM/MC
        // convention). `filesize` is 0 for relocatable objects; prots and
        // flags are advisory (consumers ignore them for MH_OBJECT).
        w32(&mut buf, lc, pgr_format::consts::LC_SEGMENT_64);
        w32(&mut buf, lc + 4, 72 + 80 * self.sections.len() as u32);
        // segname stays zeroed (anonymous).
        w64(&mut buf, lc + 24, 0); // vmaddr: 0 in relocatable objects
        w64(&mut buf, lc + 32, blob_span);
        w64(&mut buf, lc + 40, header_len as u64); // fileoff: blob start
        w64(&mut buf, lc + 48, 0); // filesize: 0 (relocatable)
        w32(&mut buf, lc + 56, VM_PROT_READ | VM_PROT_WRITE);
        w32(&mut buf, lc + 60, VM_PROT_READ);
        w32(&mut buf, lc + 64, self.sections.len() as u32);
        w32(&mut buf, lc + 68, 0); // flags
        lc += 72;
        for (i, sec) in self.sections.iter().enumerate() {
            let (addr, size) = placed[i];
            let zerofill = sec.flags & SECTION_TYPE_MASK == S_ZEROFILL;
            let mut sect = [0u8; 80];
            sect[0..16].copy_from_slice(&pad_name(sec.name.as_bytes()));
            sect[16..32].copy_from_slice(&pad_name(sec.segment.as_bytes()));
            w64(&mut sect, 32, addr); // blob-relative address
            w64(&mut sect, 40, size);
            w32(
                &mut sect,
                48,
                if zerofill {
                    0
                } else {
                    (header_len as u64 + addr) as u32
                },
            );
            w32(&mut sect, 52, sec.align_log2);
            w32(&mut sect, 56, rel_offs[i] as u32);
            w32(&mut sect, 60, sec.relocs.len() as u32);
            w32(&mut sect, 64, sec.flags);
            buf[lc..lc + 80].copy_from_slice(&sect);
            lc += 80;
        }
        if self.build_version {
            w32(&mut buf, lc, LC_BUILD_VERSION);
            w32(&mut buf, lc + 4, 32);
            w32(&mut buf, lc + 8, PLATFORM_MACOS);
            w32(&mut buf, lc + 12, 0x000c_0000); // minos 12.0.0
            w32(&mut buf, lc + 16, 0x000e_0400); // sdk 14.4.0
            w32(&mut buf, lc + 20, 1);
            w32(&mut buf, lc + 24, TOOL_CLANG);
            w32(&mut buf, lc + 28, 0x000f_0200);
            lc += 32;
        }
        w32(&mut buf, lc, pgr_format::consts::LC_SYMTAB);
        w32(&mut buf, lc + 4, 24);
        w32(&mut buf, lc + 8, symoff as u32);
        w32(&mut buf, lc + 12, nsyms);
        w32(&mut buf, lc + 16, stroff as u32);
        w32(&mut buf, lc + 20, strtab.len() as u32);
        lc += 24;
        debug_assert_eq!(lc, header_len, "load command assembly must match sizing");

        // ---- section data --------------------------------------------------
        for (i, sec) in self.sections.iter().enumerate() {
            let (addr, size) = placed[i];
            let zerofill = sec.flags & SECTION_TYPE_MASK == S_ZEROFILL;
            if !zerofill && size > 0 {
                let at = header_len + addr as usize;
                buf[at..at + size as usize].copy_from_slice(&sec.data);
            }
        }

        // ---- relocation tables ----------------------------------------------
        for (i, sec) in self.sections.iter().enumerate() {
            if sec.relocs.is_empty() {
                continue;
            }
            let mut at = rel_offs[i] as usize;
            for r in &sec.relocs {
                let mut info = r.symbolnum & 0x00ff_ffff;
                if r.pcrel {
                    info |= 1 << 24;
                }
                info |= (r.length_log2 & 0x3) << 25;
                if r.extern_ {
                    info |= 1 << 27;
                }
                info |= (r.rtype & 0xf) << 28;
                buf[at..at + 4].copy_from_slice(&r.offset.to_le_bytes());
                buf[at + 4..at + 8].copy_from_slice(&info.to_le_bytes());
                at += 8;
            }
        }

        // ---- symbol table + strtab -------------------------------------------
        for (i, (strx, ty, sect, desc, value)) in entries.iter().enumerate() {
            let at = symoff as usize + i * 16;
            buf[at..at + 4].copy_from_slice(&strx.to_le_bytes());
            buf[at + 4] = *ty;
            buf[at + 5] = *sect;
            buf[at + 6..at + 8].copy_from_slice(&desc.to_le_bytes());
            buf[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
        }
        let st = stroff as usize;
        buf[st..st + strtab.len()].copy_from_slice(&strtab);

        Ok(buf)
    }

    /// The relocation-referenced symbol index (`r_symbolnum`) for the symbol
    /// declared at `builder_index`.
    ///
    /// The symtab groups locals → defs → undefineds/commons, so declaration
    /// order differs from table order; this recomputes the mapping.
    #[must_use]
    pub fn sym_index(&self, builder_index: usize) -> u32 {
        let mut locals = 0usize;
        let mut defs = 0usize;
        for (i, sym) in self.symbols.iter().enumerate() {
            match sym {
                ObjectSymbol::Local(_) => {
                    if i == builder_index {
                        return locals as u32;
                    }
                    locals += 1;
                }
                ObjectSymbol::Defined { .. } => {
                    if i == builder_index {
                        return (locals + defs) as u32;
                    }
                    defs += 1;
                }
                _ => {}
            }
        }
        let prior_undef = self.symbols[..builder_index]
            .iter()
            .filter(|s| {
                matches!(
                    s,
                    ObjectSymbol::Undefined { .. } | ObjectSymbol::Common { .. }
                )
            })
            .count();
        (locals + defs + prior_undef) as u32
    }
}

/// Alignment helper (shared with the image builder).
fn align_up(v: u64, a: u64) -> u64 {
    v.div_ceil(a) * a
}

/// Reads a single `nlist_64` entry from an object's `LC_SYMTAB`.
///
/// # Errors
/// Returns the format error when the symtab is out of bounds or absent.
pub fn read_sym(bytes: &[u8], index: usize) -> Result<Nlist64, pgr_format::FormatError> {
    let header = pgr_format::MachHeader64::parse(bytes)?;
    let mut it = pgr_format::LoadCommandIter::new(
        bytes,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )?;
    while let Some(cmd) = it.next_command()? {
        if cmd.kind == pgr_format::LoadCommandKind::Symtab {
            let st = pgr_format::SymtabCommand::parse(cmd.bytes, 0)?;
            return pod_read_unaligned_at::<Nlist64>(bytes, st.symoff as usize + index * 16);
        }
    }
    Err(pgr_format::FormatError::Invalid {
        offset: 0,
        what: "object has no LC_SYMTAB",
        value: 0,
    })
}

/// Reads a section record by its 0-based ordinal across the file, plus the
/// owning segment's file offset (section data lives at
/// `seg.fileoff + sect.offset` under the one-section-per-segment convention).
///
/// # Errors
/// Returns a string error when the object is malformed.
pub fn read_section(bytes: &[u8], ordinal: usize) -> Result<(Section64, u64), String> {
    let header = pgr_format::MachHeader64::parse(bytes).map_err(|e| e.to_string())?;
    let mut it = pgr_format::LoadCommandIter::new(
        bytes,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .map_err(|e| e.to_string())?;
    let mut seen = 0usize;
    while let Some(cmd) = it.next_command().map_err(|e| e.to_string())? {
        if cmd.kind == pgr_format::LoadCommandKind::Segment64 {
            let seg =
                pgr_format::SegmentCommand64::parse(cmd.bytes, 0).map_err(|e| e.to_string())?;
            let sects = seg
                .sections(cmd.bytes, pgr_format::SegmentCommand64::SIZE)
                .map_err(|e| e.to_string())?;
            for s in sects {
                if seen == ordinal {
                    return Ok((*s, seg.fileoff));
                }
                seen += 1;
            }
        }
    }
    Err(format!("section ordinal {ordinal} out of range"))
}

/// Parses the relocation table of the section with the given 0-based ordinal.
///
/// # Errors
/// Returns a string error when the table is out of bounds.
pub fn read_relocs(bytes: &[u8], ordinal: usize) -> Result<Vec<RelocationInfo>, String> {
    let (sect, _) = read_section(bytes, ordinal)?;
    let mut out = Vec::with_capacity(sect.nreloc as usize);
    for i in 0..sect.nreloc as usize {
        let r = RelocationInfo::parse(bytes, sect.reloff as usize + i * 8)
            .map_err(|e| e.to_string())?;
        out.push(r);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{
        ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol, read_relocs, read_section,
        read_sym,
    };
    use pgr_format::consts::{
        ARM64_RELOC_BRANCH26, ARM64_RELOC_PAGE21, ARM64_RELOC_UNSIGNED, N_EXT, N_SECT, N_TYPE,
        N_UNDF, N_WEAK_DEF, N_WEAK_REF, S_ZEROFILL, get_comm_align, get_library_ordinal,
    };
    use pgr_format::summarize;

    /// A minimal valid object: one code section, one def.
    fn minimal() -> ObjectBuilder {
        let mut b = ObjectBuilder::new("minimal.o");
        b.add_section(ObjectSection::text(
            "__text",
            vec![0xC0, 0x03, 0x5F, 0xD6], // ret
            Vec::new(),
        ));
        b.add_symbol(ObjectSymbol::Defined {
            name: "_main".into(),
            section_index: 0,
            value: 0,
            weak: false,
        });
        b
    }

    #[test]
    fn minimal_object_parses() {
        let bytes = minimal().build().unwrap();
        let s = summarize(&bytes).unwrap();
        assert_eq!(s.segments, 1);
        assert_eq!(s.sections, 1);
        assert_eq!(s.symbols, 1);
        assert_eq!(s.external_symbols, 1);
        assert!(!s.has_chained_fixups);
    }

    #[test]
    fn symbols_are_grouped_locals_defs_undefs() {
        let mut b = ObjectBuilder::new("grouped.o");
        let text = b.add_section(ObjectSection::text(
            "__text",
            vec![0xC0, 0x03, 0x5F, 0xD6],
            Vec::new(),
        ));
        b.add_symbol(ObjectSymbol::Local("_l1".into()));
        b.add_symbol(ObjectSymbol::Defined {
            name: "_main".into(),
            section_index: text,
            value: 0,
            weak: false,
        });
        b.add_symbol(ObjectSymbol::Defined {
            name: "_helper".into(),
            section_index: text,
            value: 0,
            weak: false,
        });
        b.add_symbol(ObjectSymbol::Undefined {
            name: "_undef1".into(),
            weak_ref: false,
        });
        b.add_symbol(ObjectSymbol::Common {
            name: "_common1".into(),
            size: 32,
            align_log2: 4,
        });
        let bytes = b.build().unwrap();
        // Order: _l1, _main, _helper, _undef1, _common1
        let s0 = read_sym(&bytes, 0).unwrap();
        let s3 = read_sym(&bytes, 3).unwrap();
        let s4 = read_sym(&bytes, 4).unwrap();
        assert_eq!(s0.n_type & N_EXT, 0, "local is not external");
        assert_eq!(s3.n_type & N_TYPE, N_UNDF);
        assert_eq!(s3.n_value, 0, "undefined n_value is 0");
        assert_eq!(s4.n_type & N_TYPE, N_UNDF);
        assert_eq!(s4.n_value, 32, "common size lives in n_value");
        assert_eq!(get_comm_align(s4.n_desc), 4);
        assert_eq!(get_library_ordinal(s4.n_desc), 4);
        let _ = N_SECT;
    }

    #[test]
    fn reloc_table_roundtrips() {
        let mut b = ObjectBuilder::new("relocs.o");
        let text = b.add_section(ObjectSection::text(
            "__text",
            vec![0; 16],
            vec![
                ObjectReloc::addend(0x1234).at(0),
                ObjectReloc::page21(0).at(0),
                ObjectReloc::branch26(1).at(4),
            ],
        ));
        b.add_symbol(ObjectSymbol::Defined {
            name: "_main".into(),
            section_index: text,
            value: 0,
            weak: false,
        });
        b.add_symbol(ObjectSymbol::Undefined {
            name: "_ext".into(),
            weak_ref: false,
        });
        let bytes = b.build().unwrap();
        let relocs = read_relocs(&bytes, 0).unwrap();
        assert_eq!(relocs.len(), 3);
        // ADDEND pair member: addend carried in r_symbolnum, not external.
        assert_eq!(relocs[0].symbolnum() as i32, 0x1234);
        assert!(!relocs[0].is_extern());
        // PAGE21 references the external symbol 0.
        assert_eq!(relocs[1].rtype(), ARM64_RELOC_PAGE21);
        assert!(relocs[1].pcrel());
        assert!(relocs[1].is_extern());
        // BRANCH26 references the undefined symbol 1.
        assert_eq!(relocs[2].rtype(), ARM64_RELOC_BRANCH26);
        assert_eq!(relocs[2].symbolnum(), 1);
    }

    #[test]
    fn zerofill_sections_carry_no_bytes() {
        let mut b = ObjectBuilder::new("bss.o");
        b.add_section(ObjectSection::zerofill("__bss", 64, 4));
        b.add_symbol(ObjectSymbol::Defined {
            name: "_zeroed".into(),
            section_index: 0,
            value: 0,
            weak: false,
        });
        let bytes = b.build().unwrap();
        let (sect, _seg_fileoff) = read_section(&bytes, 0).unwrap();
        assert_eq!(sect.size, 64);
        assert_eq!(
            sect.flags & pgr_format::consts::SECTION_TYPE_MASK,
            S_ZEROFILL
        );
        assert_eq!(sect.offset, 0, "zerofill section carries no file offset");
    }

    #[test]
    fn builds_are_deterministic() {
        let a = minimal().build().unwrap();
        let b2 = minimal().build().unwrap();
        assert_eq!(a, b2);
    }

    #[test]
    fn section_ordinals_count_across_segments() {
        let mut b = ObjectBuilder::new("multi.o");
        let text = b.add_section(ObjectSection::text(
            "__text",
            vec![0xC0, 0x03, 0x5F, 0xD6],
            Vec::new(),
        ));
        let data = b.add_section(ObjectSection::data("__data", vec![1, 2, 3, 4], Vec::new()));
        let cstr = b.add_section(ObjectSection::cstring("hello"));
        assert_ne!(text, data);
        assert_ne!(data, cstr);
        let bytes = b.build().unwrap();
        let (s1, _) = read_section(&bytes, 1).unwrap();
        assert_eq!(s1.name().unwrap(), "__data");
        let (s2, _) = read_section(&bytes, 2).unwrap();
        assert_eq!(s2.name().unwrap(), "__cstring");
        b.add_symbol(ObjectSymbol::Defined {
            name: "_main".into(),
            section_index: text,
            value: 0,
            weak: false,
        });
        let bytes = b.build().unwrap();
        let sym = read_sym(&bytes, 0).unwrap();
        assert_eq!(sym.n_sect, 1, "external def records its 1-based section");
    }

    #[test]
    fn weak_defs_and_weak_refs_record_desc_bits() {
        let mut b = ObjectBuilder::new("weak.o");
        let text = b.add_section(ObjectSection::text(
            "__text",
            vec![0xC0, 0x03, 0x5F, 0xD6],
            Vec::new(),
        ));
        b.add_symbol(ObjectSymbol::Defined {
            name: "_weakfn".into(),
            section_index: text,
            value: 0,
            weak: true,
        });
        b.add_symbol(ObjectSymbol::Undefined {
            name: "_weakref".into(),
            weak_ref: true,
        });
        let bytes = b.build().unwrap();
        let s0 = read_sym(&bytes, 0).unwrap();
        assert_eq!(s0.n_desc & N_WEAK_DEF, N_WEAK_DEF);
        let s1 = read_sym(&bytes, 1).unwrap();
        assert_eq!(s1.n_desc & N_WEAK_REF, N_WEAK_REF);
    }

    #[test]
    fn unsigned_pointer_reloc_roundtrip() {
        let mut b = ObjectBuilder::new("ptr.o");
        let text = b.add_section(ObjectSection::text(
            "__text",
            vec![0xC0, 0x03, 0x5F, 0xD6],
            Vec::new(),
        ));
        let data = b.add_section(ObjectSection::data("__data", vec![0; 8], Vec::new()));
        b.section_mut(data)
            .relocs
            .push(ObjectReloc::unsigned(0).at(0));
        b.add_symbol(ObjectSymbol::Defined {
            name: "_main".into(),
            section_index: text,
            value: 0,
            weak: false,
        });
        let bytes = b.build().unwrap();
        let relocs = read_relocs(&bytes, 1).unwrap();
        assert_eq!(relocs.len(), 1);
        assert_eq!(relocs[0].rtype(), ARM64_RELOC_UNSIGNED);
        assert_eq!(relocs[0].length_log2(), 3);
        assert_eq!(relocs[0].r_address, 0);
    }

    #[test]
    fn sym_index_follows_table_grouping() {
        let mut b = ObjectBuilder::new("idx.o");
        let text = b.add_section(ObjectSection::text(
            "__text",
            vec![0xC0, 0x03, 0x5F, 0xD6],
            Vec::new(),
        ));
        let l0 = b.add_symbol(ObjectSymbol::Local("_l1".into()));
        let d0 = b.add_symbol(ObjectSymbol::Defined {
            name: "_d1".into(),
            section_index: text,
            value: 0,
            weak: false,
        });
        let u0 = b.add_symbol(ObjectSymbol::Undefined {
            name: "_u1".into(),
            weak_ref: false,
        });
        let c0 = b.add_symbol(ObjectSymbol::Common {
            name: "_c1".into(),
            size: 8,
            align_log2: 3,
        });
        assert_eq!(b.sym_index(l0), 0);
        assert_eq!(b.sym_index(d0), 1);
        assert_eq!(b.sym_index(u0), 2);
        assert_eq!(b.sym_index(c0), 3);
    }
}
