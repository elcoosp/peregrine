//! The relocatable object emit (M10 rung 1, roadmap §10.4 row M10):
//! `pgr -r` assembles the Pass 1–2 product (`pgr_core::RelocLink`) into an
//! `MH_OBJECT` the pipeline itself consumes as an input.
//!
//! Byte rules (the relocatable convention — the mirror image of
//! `pgr-fixtures`' builder, which is the *parse* side's reference):
//!
//! * header | `LC_SEGMENT_64` (one anonymous segment carrying every
//!   merged section) | `LC_BUILD_VERSION` | `LC_SYMTAB` | `LC_DYSYMTAB`,
//!   then one section-data blob, then the per-section relocation tables,
//!   then the symbol table and string table;
//! * sections merge by `(segment, name)` in first-seen order
//!   (determinism §4.3: file order, table order — no hash iteration),
//!   each contribution re-aligned inside its section; section `addr`s
//!   are blob-relative and symbol `n_value`s map through
//!   `out_base + (n_value − in_section.addr)`;
//! * the symbol table groups locals, winner-backed globals and open
//!   undefineds (the `LC_DYSYMTAB` subranges follow the same order);
//!   commons keep the tentative shape (`N_UNDF|N_EXT`, size in
//!   `n_value`, alignment in the `n_desc` high nibble);
//! * relocation entries are **preserved, not applied**: every decoded
//!   entry re-encodes against the output symbol table (`r_extern`
//!   entries name the winner's output index; section-relative entries
//!   name the merged section's 1-based ordinal), `ADDEND`/`SUBTRACTOR`
//!   pairs re-emit their leader first (the decode order
//!   `InputObject::finish` consumes), and the site bytes ride verbatim;
//! * no `LC_MAIN`, no `LC_LOAD_DYLINKER`, no fixup payload, no code
//!   signature — a relocatable object is neither loaded nor signed, and
//!   undefined externals stay open by design (the next link resolves
//!   them).
//!
//! Tracing spans ride the two seams (`object_layout`, `reloc_encode`) —
//! inert until a subscriber installs, the workspace convention. A
//! relocation the output symbol table cannot represent (a malformed
//! input whose `r_extern` entry names a local) refuses with the
//! miette-rendered [`ObjectRelocRefusal`] — help text, not just a
//! verdict.

use crate::EmitError;
use pgr_core::{DecodedReloc, LinkConfig, RelocKind, RelocLink, RelocTarget};
use pgr_format::consts::{
    ARM64_RELOC_ADDEND, ARM64_RELOC_BRANCH26, ARM64_RELOC_GOT_LOAD_PAGE21,
    ARM64_RELOC_GOT_LOAD_PAGEOFF12, ARM64_RELOC_PAGE21, ARM64_RELOC_PAGEOFF12,
    ARM64_RELOC_POINTER_TO_GOT, ARM64_RELOC_SUBTRACTOR, ARM64_RELOC_UNSIGNED,
    CPU_SUBTYPE_ARM64_ALL, CPU_TYPE_ARM64, LC_BUILD_VERSION, LC_DYSYMTAB, LC_SEGMENT_64, LC_SYMTAB,
    MH_MAGIC_64, MH_OBJECT, N_ALT_ENTRY, N_EXT, N_SECT, N_WEAK_DEF, N_WEAK_REF, S_ZEROFILL,
    SECTION_TYPE_MASK, VM_PROT_READ, VM_PROT_WRITE,
};
use pgr_format::reloc::RelocationInfo;
use std::collections::{BTreeMap, HashMap};

/// A relocation the `-r` output cannot represent: the entry's target has
/// no voice in the output symbol table (a malformed input whose
/// `r_extern` entry names a local symbol), or names an input section the
/// parse never carried. Never a silent drop — the emit refuses and the
/// driver surfaces the help text.
#[derive(Debug, Clone, thiserror::Error, miette::Diagnostic)]
#[error("cannot encode the relocation at {section}+{offset:#x}: {reason}")]
#[diagnostic(help("{help}"))]
pub struct ObjectRelocRefusal {
    /// The merged output section the entry rides in (`__TEXT,__text`).
    pub section: String,
    /// The entry's section-relative address.
    pub offset: u32,
    /// What cannot be represented.
    pub reason: String,
    /// The fix, not just the verdict.
    pub help: String,
}

impl ObjectRelocRefusal {
    /// The miette-rendered refusal (issue + help text), the shape the
    /// driver surfaces and tests assert on.
    #[must_use]
    pub fn render(&self) -> String {
        let report = miette::Report::new(self.clone());
        format!("{report:?}")
    }
}

/// One merged output section: every input section sharing the
/// `(segment, name)` key, in first-seen order.
struct OutputSection {
    segment: String,
    name: String,
    flags: u32,
    align_log2: u32,
    zerofill: bool,
    /// Blob-relative address.
    addr: u64,
    /// Total span (zero-fill sections advance the blob address but
    /// commit no file bytes).
    size: u64,
    /// `(file index, input section index, base within this section,
    /// byte size)` in placement order.
    contributions: Vec<(u32, usize, u64, u64)>,
    /// Encoded relocation entries (section-relative addresses).
    relocs: Vec<RelocationInfo>,
}

impl OutputSection {
    /// The `__TEXT,__text`-shaped label refusals and spans carry.
    fn label(&self) -> String {
        format!("{},{}", self.segment, self.name)
    }
}

/// The placement maps both symbol-value mapping and relocation
/// re-ordinaling share: per `(file, input section)` the merged section's
/// blob address, the contribution's base inside it, the input section's
/// own blob-relative `addr` (the value mapping's subtrahend) and the
/// merged section's 1-based ordinal.
struct Placement {
    by_input: HashMap<(u32, usize), PlacementEntry>,
}

struct PlacementEntry {
    /// Merged section's blob-relative address.
    out_addr: u64,
    /// Contribution's base within the merged section.
    base: u64,
    /// Merged section's 1-based ordinal (`n_sect` / `!r_extern` targets).
    ordinal: u8,
}

impl Placement {
    /// Maps a section-relative symbol value (the parse normalizes
    /// `n_value`s to their section's base — object.rs) to its
    /// output-blob value.
    fn map_value(&self, file: u32, in_si: usize, value: u64) -> Result<u64, EmitError> {
        let p = self
            .by_input
            .get(&(file, in_si))
            .ok_or(EmitError::Internal {
                message: format!("{file}:{in_si}: symbol value has no merged section (internal)"),
            })?;
        Ok(p.out_addr + p.base + value)
    }
}

/// The symbol table mid-assembly: entries in output order (locals,
/// winner-backed globals, open undefineds) plus the name → index map the
/// relocation encoder re-points `r_extern` entries through.
struct SymbolTable {
    entries: Vec<OutSymbol>,
    strtab: Vec<u8>,
    /// name → output index (lookup-only; locals stay out — an `r_extern`
    /// entry naming one is the malformed shape [`ObjectRelocRefusal`]
    /// refuses).
    by_name: BTreeMap<Vec<u8>, u32>,
    nlocals: usize,
    ndefs: usize,
}

/// One symbol table entry.
struct OutSymbol {
    name: Vec<u8>,
    n_type: u8,
    n_sect: u8,
    n_desc: u16,
    n_value: u64,
}

/// Assembles the `-r` relocatable object: merged sections, the grouped
/// symbol table and the re-pointed relocation entries (the module doc
/// carries the full byte contract).
///
/// # Errors
/// [`EmitError::RelocRefusal`] when a relocation cannot be represented in
/// the output symbol table; [`EmitError::Internal`] on assembly
/// invariants (a bug, not input shape).
pub fn build_object_image(link: &RelocLink, cfg: &LinkConfig) -> Result<Vec<u8>, EmitError> {
    let span = tracing::info_span!(
        "object_emit",
        inputs = link.objects.len(),
        platform = cfg.platform
    );
    let _entered = span.enter();

    let (sections, placement) = layout_sections(link);
    let symbols = build_symbols(link, &sections, &placement)?;
    let tables = encode_relocs(link, &sections, &symbols, &placement)?;
    let mut sections = sections;
    for (out, relocs) in sections.iter_mut().zip(tables) {
        out.relocs = relocs;
    }
    tracing::debug!(
        sections = sections.len(),
        symbols = symbols.entries.len(),
        "the object layout settled"
    );
    assemble(link, &sections, &symbols, cfg)
}

/// Merges the input sections by `(segment, name)` in first-seen order
/// (file order, table order — no hash iteration) and places every
/// contribution: section `addr`s are blob-relative, each contribution is
/// re-aligned inside its section, zero-fill sections advance the blob
/// address but commit no file bytes. Returns the merged sections (sizes
/// and addresses settled, relocation tables still empty) and the
/// placement maps.
fn layout_sections(link: &RelocLink) -> (Vec<OutputSection>, Placement) {
    let _span = tracing::info_span!("object_layout").entered();
    let mut sections: Vec<OutputSection> = Vec::new();
    // Lookup-only index (never iterated — the Vec carries the order).
    let mut index: HashMap<(&str, &str), usize> = HashMap::new();
    for obj in &link.objects {
        for (si, sect) in obj.sections.iter().enumerate() {
            let zerofill = sect.flags & SECTION_TYPE_MASK == S_ZEROFILL;
            let key = (sect.segment.as_str(), sect.name.as_str());
            if let Some(&out) = index.get(&key) {
                let s = &mut sections[out];
                s.align_log2 = s.align_log2.max(sect.align_log2);
                s.zerofill |= zerofill;
                s.contributions.push((obj.file.0, si, 0, 0));
            } else {
                index.insert(key, sections.len());
                sections.push(OutputSection {
                    segment: sect.segment.clone(),
                    name: sect.name.clone(),
                    flags: sect.flags,
                    align_log2: sect.align_log2,
                    zerofill,
                    addr: 0,
                    size: 0,
                    contributions: vec![(obj.file.0, si, 0, 0)],
                    relocs: Vec::new(),
                });
            }
        }
    }
    let mut blob = 0u64;
    let mut by_input: HashMap<(u32, usize), PlacementEntry> = HashMap::new();
    for (i, s) in sections.iter_mut().enumerate() {
        blob = align_up(blob, 1u64 << s.align_log2.min(14));
        s.addr = blob;
        let mut inner = 0u64;
        for c in &mut s.contributions {
            let input = &link.objects[c.0 as usize].sections[c.1];
            inner = align_up(inner, 1u64 << input.align_log2.min(14));
            c.2 = inner;
            c.3 = input.size;
            by_input.insert(
                (c.0, c.1),
                PlacementEntry {
                    out_addr: s.addr,
                    base: inner,
                    ordinal: (i + 1) as u8,
                },
            );
            inner += input.size;
        }
        s.size = inner;
        blob = s.addr + s.size;
    }
    (sections, Placement { by_input })
}

/// Builds the grouped symbol table: locals (file order, table order),
/// winner-backed globals (the defining object's visit emits each name
/// exactly once), coalesced commons (the tentative shape) and open
/// undefineds (first reference wins the slot).
fn build_symbols(
    link: &RelocLink,
    _sections: &[OutputSection],
    placement: &Placement,
) -> Result<SymbolTable, EmitError> {
    let mut table = SymbolTable {
        entries: Vec::new(),
        strtab: vec![0],
        by_name: BTreeMap::new(),
        nlocals: 0,
        ndefs: 0,
    };
    // -- locals -------------------------------------------------------------
    // `N_SECT` locals re-map through the placement; the section-less
    // local shape (`n_type 0` — the fixtures' bare-local convention)
    // rides verbatim so the symbol survives the round trip unchanged.
    for obj in &link.objects {
        for s in &obj.symbols {
            if s.stab || s.external {
                continue;
            }
            let mut n_desc = 0u16;
            if s.alt_entry {
                n_desc |= N_ALT_ENTRY;
            }
            match s.section {
                Some(in_si) => {
                    let value = placement.map_value(obj.file.0, in_si, s.value)?;
                    let p = &placement.by_input[&(obj.file.0, in_si)];
                    table.entries.push(OutSymbol {
                        name: link.interner.bytes(s.name).to_vec(),
                        n_type: N_SECT,
                        n_sect: p.ordinal,
                        n_desc,
                        n_value: value,
                    });
                }
                None => table.entries.push(OutSymbol {
                    name: link.interner.bytes(s.name).to_vec(),
                    n_type: 0,
                    n_sect: 0,
                    n_desc,
                    n_value: s.value,
                }),
            }
        }
    }
    table.nlocals = table.entries.len();
    // -- globals (winner-backed) ---------------------------------------------
    for obj in &link.objects {
        for (i, s) in obj.symbols.iter().enumerate() {
            if s.stab || !s.is_defined() {
                continue;
            }
            let Some(def) = link.resolution.def(s.name) else {
                continue;
            };
            if def.file != obj.file || def.sym != i {
                continue; // a losing candidate — the winner's visit emits
            }
            let Some(def_sect) = def.section else {
                continue; // commons surface in the tentative pass below
            };
            let value = placement.map_value(def.file.0, def_sect, def.value)?;
            let p = &placement.by_input[&(def.file.0, def_sect)];
            let mut n_desc = 0u16;
            if s.weak_def {
                n_desc |= N_WEAK_DEF;
            }
            if s.alt_entry {
                n_desc |= N_ALT_ENTRY;
            }
            let name = link.interner.bytes(s.name).to_vec();
            table
                .by_name
                .insert(name.clone(), table.entries.len() as u32);
            table.entries.push(OutSymbol {
                name,
                n_type: N_SECT | N_EXT,
                n_sect: p.ordinal,
                n_desc,
                n_value: value,
            });
        }
    }
    table.ndefs = table.entries.len() - table.nlocals;
    // -- commons (coalesced, the tentative shape) -----------------------------
    for obj in &link.objects {
        for (i, s) in obj.symbols.iter().enumerate() {
            if s.stab || !s.is_common() {
                continue;
            }
            let Some(def) = link.resolution.def(s.name) else {
                continue;
            };
            if def.file != obj.file || def.sym != i {
                continue;
            }
            let name = link.interner.bytes(s.name).to_vec();
            table
                .by_name
                .insert(name.clone(), table.entries.len() as u32);
            table.entries.push(OutSymbol {
                name,
                n_type: N_EXT, // N_UNDF | N_EXT: tentative
                n_sect: 0,
                n_desc: (u16::from(def.common_align as u8) & 0x0F) << 8,
                n_value: def.common_size,
            });
        }
    }
    // -- open undefineds -------------------------------------------------------
    for obj in &link.objects {
        for s in &obj.symbols {
            if s.stab || !s.is_undefined() {
                continue;
            }
            let name = link.interner.bytes(s.name).to_vec();
            if table.by_name.contains_key(&name) {
                continue; // resolved (global or common) — one voice each
            }
            let mut n_desc = 0u16;
            if s.weak_ref {
                n_desc |= N_WEAK_REF;
            }
            table
                .by_name
                .insert(name.clone(), table.entries.len() as u32);
            table.entries.push(OutSymbol {
                name,
                n_type: N_EXT,
                n_sect: 0,
                n_desc,
                n_value: 0,
            });
        }
    }
    // Freeze the string table (leading NUL; entry offsets are positional).
    let mut strtab = vec![0u8];
    for sym in &table.entries {
        strtab.extend_from_slice(&sym.name);
        strtab.push(0);
    }
    table.strtab = strtab;
    Ok(table)
}

/// Re-encodes every decoded relocation against the output symbol table:
/// `r_extern` entries name the winner's (or open undefined's) output
/// index, section-relative entries name the merged section's 1-based
/// ordinal, pairs re-emit their leader first, site bytes ride verbatim.
/// Returns one entry vector per merged section.
fn encode_relocs(
    link: &RelocLink,
    sections: &[OutputSection],
    symbols: &SymbolTable,
    placement: &Placement,
) -> Result<Vec<Vec<RelocationInfo>>, EmitError> {
    let span = tracing::info_span!("reloc_encode");
    let _entered = span.enter();
    let mut tables: Vec<Vec<RelocationInfo>> = sections.iter().map(|_| Vec::new()).collect();
    let mut entries = 0usize;
    for (out_i, out) in sections.iter().enumerate() {
        for (file, si, base, _size) in &out.contributions {
            let obj = &link.objects[*file as usize];
            for r in &obj.sections[*si].relocs {
                let addr = base + u64::from(r.offset);
                if addr > u64::from(u32::MAX) {
                    return Err(EmitError::Internal {
                        message: format!(
                            "relocation address {addr:#x} exceeds the section-relative u32 space"
                        ),
                    });
                }
                encode_one(
                    link,
                    symbols,
                    placement,
                    *file,
                    &out.label(),
                    addr as u32,
                    r,
                    &mut tables[out_i],
                )?;
                entries += 1;
            }
        }
    }
    tracing::debug!(entries, "the relocation tables re-encoded");
    Ok(tables)
}

/// Packs one `relocation_info` word:
/// `r_symbolnum:24 | r_pcrel:1 | r_length:2 | r_extern:1 | r_type:4`.
fn entry(
    addr: u32,
    symbolnum: u32,
    pcrel: bool,
    length_log2: u32,
    ext: bool,
    rtype: u32,
) -> RelocationInfo {
    let mut info = symbolnum & 0x00FF_FFFF;
    if pcrel {
        info |= 1 << 24;
    }
    info |= (length_log2 & 0x3) << 25;
    if ext {
        info |= 1 << 27;
    }
    info |= (rtype & 0xF) << 28;
    RelocationInfo {
        r_address: addr & !0x8000_0000,
        r_info: info,
    }
}

/// Encodes one decoded relocation (plus its pair leader when the kind
/// carries one) at the merged section-relative `addr`. `file` is the
/// owning input's index — section-relative targets re-ordinal through
/// its placement entries.
fn encode_one(
    link: &RelocLink,
    symbols: &SymbolTable,
    placement: &Placement,
    file: u32,
    label: &str,
    addr: u32,
    r: &DecodedReloc,
    out: &mut Vec<RelocationInfo>,
) -> Result<(), EmitError> {
    let refuse = |reason: String| -> EmitError {
        EmitError::RelocRefusal {
            refusal: ObjectRelocRefusal {
                section: label.to_string(),
                offset: addr,
                reason,
                help: "the input object is malformed: r_extern entries must name external \
                       symbols and section ordinals must stay inside the section table — \
                       rebuild the object (docs/COMPAT.md, -r)"
                    .into(),
            },
        }
    };
    let extern_index = |t: &RelocTarget| -> Result<u32, EmitError> {
        match t {
            RelocTarget::Extern(id) => {
                let name = link.interner.bytes(*id).to_vec();
                symbols.by_name.get(&name).copied().ok_or_else(|| {
                    refuse(format!(
                        "the entry names {:?}, which no output symbol table entry represents",
                        String::from_utf8_lossy(&name)
                    ))
                })
            }
            RelocTarget::Section(idx) => {
                let p = placement.by_input.get(&(file, *idx)).ok_or_else(|| {
                    refuse(format!(
                        "the entry names input section {idx}, which has no merged section"
                    ))
                })?;
                Ok(u32::from(p.ordinal))
            }
        }
    };
    match &r.kind {
        RelocKind::Unsigned => {
            let idx = extern_index(&r.target)?;
            out.push(entry(
                addr,
                idx,
                r.pcrel,
                r.length_log2,
                idx_extern(&r.target),
                ARM64_RELOC_UNSIGNED,
            ));
        }
        RelocKind::Branch26 => {
            let idx = extern_index(&r.target)?;
            out.push(entry(
                addr,
                idx,
                r.pcrel,
                r.length_log2,
                idx_extern(&r.target),
                ARM64_RELOC_BRANCH26,
            ));
        }
        RelocKind::Page21 { addend }
        | RelocKind::PageOff12 { addend }
        | RelocKind::GotLoadPage21 { addend }
        | RelocKind::GotLoadPageOff12 { addend } => {
            // The ADDEND leader precedes its target (the decode order
            // `InputObject::finish` consumes): r_symbolnum carries the
            // addend, never a symbol reference.
            out.push(entry(
                addr,
                (*addend as i32) as u32 & 0x00FF_FFFF,
                false,
                r.length_log2,
                false,
                ARM64_RELOC_ADDEND,
            ));
            let idx = extern_index(&r.target)?;
            let rtype = match &r.kind {
                RelocKind::Page21 { .. } => ARM64_RELOC_PAGE21,
                RelocKind::PageOff12 { .. } => ARM64_RELOC_PAGEOFF12,
                RelocKind::GotLoadPage21 { .. } => ARM64_RELOC_GOT_LOAD_PAGE21,
                _ => ARM64_RELOC_GOT_LOAD_PAGEOFF12,
            };
            out.push(entry(
                addr,
                idx,
                r.pcrel,
                r.length_log2,
                idx_extern(&r.target),
                rtype,
            ));
        }
        RelocKind::PointerToGot => {
            let idx = extern_index(&r.target)?;
            out.push(entry(
                addr,
                idx,
                r.pcrel,
                r.length_log2,
                idx_extern(&r.target),
                ARM64_RELOC_POINTER_TO_GOT,
            ));
        }
        RelocKind::Subtractor { minuend } => {
            // The SUBTRACTOR leader names the minuend; the UNSIGNED that
            // follows carries the subtrahend (this decoded entry).
            let minuend_idx = extern_index(minuend)?;
            out.push(entry(
                addr,
                minuend_idx,
                false,
                r.length_log2,
                idx_extern(minuend),
                ARM64_RELOC_SUBTRACTOR,
            ));
            let idx = extern_index(&r.target)?;
            out.push(entry(
                addr,
                idx,
                r.pcrel,
                r.length_log2,
                idx_extern(&r.target),
                ARM64_RELOC_UNSIGNED,
            ));
        }
    }
    Ok(())
}

/// True when the target names a symbol-table entry (`r_extern=1`);
/// section targets ride `!r_extern` with the merged 1-based ordinal.
fn idx_extern(t: &RelocTarget) -> bool {
    matches!(t, RelocTarget::Extern(_))
}

/// Assembles the file: header, load commands, section-data blob,
/// relocation tables, symbol table, string table (the module doc's byte
/// rules; offsets mirror `pgr-fixtures`' builder).
fn assemble(
    link: &RelocLink,
    sections: &[OutputSection],
    symbols: &SymbolTable,
    cfg: &LinkConfig,
) -> Result<Vec<u8>, EmitError> {
    let nsects = sections.len();
    let sizeofcmds = (72 + 80 * nsects) + 32 + 24 + 80;
    let header_len = (32 + sizeofcmds) as u64;
    let blob_span = sections.last().map_or(0, |s| s.addr + s.size);

    // Relocation tables follow the blob (4-aligned each).
    let mut rel_offs: Vec<u64> = vec![0; nsects];
    let mut cursor = blob_span;
    for (i, s) in sections.iter().enumerate() {
        if s.relocs.is_empty() {
            continue;
        }
        cursor = align_up(cursor, 4);
        rel_offs[i] = header_len + cursor;
        cursor += s.relocs.len() as u64 * 8;
    }
    let symoff = align_up(header_len + cursor, 8);
    let nsyms = symbols.entries.len() as u32;
    let stroff = symoff + u64::from(nsyms) * 16;
    let file_len = stroff + symbols.strtab.len() as u64;

    let mut buf = vec![0u8; file_len as usize];
    let w32 = |buf: &mut [u8], at: usize, v: u32| buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
    let w64 = |buf: &mut [u8], at: usize, v: u64| buf[at..at + 8].copy_from_slice(&v.to_le_bytes());

    w32(&mut buf, 0, MH_MAGIC_64);
    w32(&mut buf, 4, CPU_TYPE_ARM64);
    w32(&mut buf, 8, CPU_SUBTYPE_ARM64_ALL);
    w32(&mut buf, 12, MH_OBJECT);
    w32(&mut buf, 16, 4);
    w32(&mut buf, 20, sizeofcmds as u32);
    w32(&mut buf, 24, 0); // flags

    // LC_SEGMENT_64: one anonymous segment carrying every section; the
    // relocatable convention zeroes `filesize` (consumers ignore it).
    let mut lc = 32usize;
    w32(&mut buf, lc, LC_SEGMENT_64);
    w32(&mut buf, lc + 4, (72 + 80 * nsects) as u32);
    w64(&mut buf, lc + 24, 0); // vmaddr
    w64(&mut buf, lc + 32, blob_span); // vmsize
    w64(&mut buf, lc + 40, header_len); // fileoff: the blob starts here
    w64(&mut buf, lc + 48, 0); // filesize: 0 (relocatable)
    w32(&mut buf, lc + 56, VM_PROT_READ | VM_PROT_WRITE);
    w32(&mut buf, lc + 60, VM_PROT_READ);
    w32(&mut buf, lc + 64, nsects as u32);
    w32(&mut buf, lc + 68, 0);
    lc += 72;
    for (i, s) in sections.iter().enumerate() {
        let mut sect = [0u8; 80];
        sect[0..16].copy_from_slice(&pad16(s.name.as_bytes()));
        sect[16..32].copy_from_slice(&pad16(s.segment.as_bytes()));
        w64(&mut sect, 32, s.addr);
        w64(&mut sect, 40, s.size);
        w32(
            &mut sect,
            48,
            if s.zerofill {
                0
            } else {
                (header_len + s.addr) as u32
            },
        );
        w32(&mut sect, 52, s.align_log2);
        w32(&mut sect, 56, rel_offs[i] as u32);
        w32(&mut sect, 60, s.relocs.len() as u32);
        w32(&mut sect, 64, s.flags);
        buf[lc..lc + 80].copy_from_slice(&sect);
        lc += 80;
    }
    // LC_BUILD_VERSION: the link's own platform triple, no tool entries
    // (ld64's -r output carries none — the tools are the compiler's).
    w32(&mut buf, lc, LC_BUILD_VERSION);
    w32(&mut buf, lc + 4, 32);
    w32(&mut buf, lc + 8, cfg.platform);
    w32(&mut buf, lc + 12, cfg.minos);
    w32(&mut buf, lc + 16, cfg.sdk);
    w32(&mut buf, lc + 20, 0); // ntools
    lc += 32;
    // LC_SYMTAB.
    w32(&mut buf, lc, LC_SYMTAB);
    w32(&mut buf, lc + 4, 24);
    w32(&mut buf, lc + 8, symoff as u32);
    w32(&mut buf, lc + 12, nsyms);
    w32(&mut buf, lc + 16, stroff as u32);
    w32(&mut buf, lc + 20, symbols.strtab.len() as u32);
    lc += 24;
    // LC_DYSYMTAB: the grouped subranges; no toc/module/indirect tables.
    w32(&mut buf, lc, LC_DYSYMTAB);
    w32(&mut buf, lc + 4, 80);
    w32(&mut buf, lc + 8, 0); // ilocalsym
    w32(&mut buf, lc + 12, symbols.nlocals as u32);
    w32(&mut buf, lc + 16, symbols.nlocals as u32); // iextdefsym
    w32(&mut buf, lc + 20, symbols.ndefs as u32);
    w32(
        &mut buf,
        lc + 24,
        (symbols.nlocals + symbols.ndefs) as u32, // iundefsym
    );
    w32(
        &mut buf,
        lc + 28,
        (symbols.entries.len() - symbols.nlocals - symbols.ndefs) as u32,
    );
    lc += 80;
    debug_assert_eq!(
        lc,
        32 + sizeofcmds,
        "load command sizing must match assembly"
    );

    // Section data (zero-fill sections commit nothing).
    for s in sections {
        if s.zerofill {
            continue;
        }
        for (file, si, base, size) in &s.contributions {
            let obj = &link.objects[*file as usize];
            let bytes = obj.sections[*si].bytes(&obj.bytes);
            let at = (header_len + s.addr + base) as usize;
            buf.get_mut(at..at + *size as usize)
                .ok_or(EmitError::Internal {
                    message: format!("section {} contribution leaves the blob", s.label()),
                })?
                .copy_from_slice(bytes);
        }
    }
    // Relocation tables.
    for (i, s) in sections.iter().enumerate() {
        if s.relocs.is_empty() {
            continue;
        }
        let mut at = rel_offs[i] as usize;
        for r in &s.relocs {
            buf[at..at + 4].copy_from_slice(&r.r_address.to_le_bytes());
            buf[at + 4..at + 8].copy_from_slice(&r.r_info.to_le_bytes());
            at += 8;
        }
    }
    // Symbol table (strtab offsets are positional: 1 + Σ prior name lens)
    // + string table.
    let mut strx = 1u32;
    let mut at = symoff as usize;
    for sym in &symbols.entries {
        buf[at..at + 4].copy_from_slice(&strx.to_le_bytes());
        buf[at + 4] = sym.n_type;
        buf[at + 5] = sym.n_sect;
        buf[at + 6..at + 8].copy_from_slice(&sym.n_desc.to_le_bytes());
        buf[at + 8..at + 16].copy_from_slice(&sym.n_value.to_le_bytes());
        at += 16;
        strx += sym.name.len() as u32 + 1;
    }
    buf[stroff as usize..].copy_from_slice(&symbols.strtab);
    Ok(buf)
}

fn pad16(name: &[u8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let take = name.len().min(16);
    out[..take].copy_from_slice(&name[..take]);
    out
}

fn align_up(v: u64, align: u64) -> u64 {
    debug_assert!(align.is_power_of_two());
    (v + align - 1) & !(align - 1)
}
