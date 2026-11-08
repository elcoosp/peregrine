//! Peregrine format layer: zero-copy Mach-O primitives for arm64-apple-darwin.
//!
//! Scope (M0, TDD §12 "M0 Verifier first"): raw `#[repr(C)]` structures, the
//! constant set, a bounds-checked cursor, and codecs for the structures the
//! verifier must reason about — load commands, symbol tables, relocations,
//! chained fixups and code-signature blobs. Everything parses with typed
//! errors and never panics on malformed input.
//!
//! Design invariants carried from the TDD / perf doc:
//!
//! * little-endian only (arm64 Mach-O); big-endian slices are rejected
//!   explicitly ([`MachHeader64::parse`]),
//! * no allocation in the hot path beyond counting structures
//!   ([`summarize`] walks with a cursor and per-file spans),
//! * constants are mirrored (not imported) and cross-checked against
//!   `object::macho` in `tests/constants_crosscheck.rs`.

pub mod archive;
pub mod commands;
pub mod consts;
pub mod cursor;
pub mod dyld_info;
pub mod error;
pub mod fixups;
pub mod header;
pub mod load_command;
pub mod reloc;
pub mod segment;
pub mod signature;
pub mod symtab;
pub mod tbd;
pub mod trie;

pub use dyld_info::{BindEntry, BindOrdinal, DyldInfoCommand, RebaseEntry};

pub use archive::{Archive, ArchiveIndexEntry, ArchiveMember, is_archive, parse_archive};
pub use commands::{
    BuildToolVersion, BuildVersionCommand, DataInCodeEntry, DylibCommand, DylinkerCommand,
    EntryPointCommand, LinkeditDataCommand, SourceVersionCommand, UuidCommand,
};
pub use error::FormatError;
pub use header::MachHeader64;
pub use load_command::{LoadCommandIter, LoadCommandKind, ParsedCommand};
pub use reloc::RelocationInfo;
pub use segment::{Section64, SegmentCommand64};
pub use signature::{CodeDirectory, SuperBlob};
pub use symtab::{DysymtabCommand, Nlist64, SymtabCommand};
pub use tbd::{Tbd, TbdSymbol, parse_tbd};
pub use trie::{TrieExport, exports as exports_trie};

use consts::LC_DYLD_CHAINED_FIXUPS;
use cursor::Cursor;

/// Summary produced by the structural parser: counts of every table Pass 1
/// will materialize. This is the M0 benchmark unit — GB/s over
/// [`summarize`] is the recorded baseline for the parse pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ObjectSummary {
    /// Total input size in bytes.
    pub file_size: u64,
    /// Number of load commands walked.
    pub load_commands: u32,
    /// Number of `LC_SEGMENT_64` commands.
    pub segments: u32,
    /// Number of sections across all segments.
    pub sections: u32,
    /// Number of `nlist_64` entries.
    pub symbols: u32,
    /// Number of external (non-stab) symbols.
    pub external_symbols: u32,
    /// Number of relocation entries.
    pub relocations: u32,
    /// Number of indirect-symbol-table entries declared.
    pub indirect_symbols: u32,
    /// True when an `LC_DYLD_CHAINED_FIXUPS` payload is present.
    pub has_chained_fixups: bool,
    /// Number of fixup slots visited while walking the chains.
    pub fixup_slots: u64,
}

/// One segment's span, kept while summarizing so the fixup chain walk can
/// translate payload-relative pages to file offsets.
#[derive(Debug, Clone, Copy)]
struct SegmentSpan {
    fileoff: u64,
}

/// Walks one chain page, counting slots and validating the stride invariants
/// (8-byte slots, no page crossing, termination). Returns slots visited.
fn walk_chain_page(
    bytes: &[u8],
    page_base: u64,
    page_size: u64,
    start_off: u16,
) -> Result<u64, FormatError> {
    if start_off % 8 != 0 {
        return Err(FormatError::Invalid {
            offset: usize::try_from(page_base).unwrap_or(usize::MAX),
            what: "chain start offset not 8-byte aligned",
            value: u64::from(start_off),
        });
    }
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let mut slot_off = u64::from(start_off);
    let mut visited = 0u64;
    loop {
        let slot_file = page_base + slot_off;
        let slot_end = slot_file.saturating_add(8);
        if slot_end > len {
            return Err(FormatError::Overrun {
                offset: usize::try_from(slot_file).unwrap_or(usize::MAX),
                overrun: usize::try_from(slot_end - len).unwrap_or(usize::MAX),
            });
        }
        let mut c = Cursor::new(bytes);
        c.seek(usize::try_from(slot_file).unwrap_or(usize::MAX))?;
        let word = fixups::ChainWord64::new(c.read_u64()?);
        visited += 1;
        let strides = u64::from(word.next());
        if strides == 0 {
            return Ok(visited);
        }
        let advance = strides * 4;
        if slot_off % 8 != 0 || slot_off + advance + 8 > page_size {
            return Err(FormatError::Invalid {
                offset: usize::try_from(slot_file).unwrap_or(usize::MAX),
                what: "chain stride leaves the page or misaligns the next slot",
                value: strides,
            });
        }
        slot_off += advance;
    }
}

/// Walks an `LC_DYLD_CHAINED_FIXUPS` payload, counting fixup slots.
fn walk_fixup_payload(
    bytes: &[u8],
    segments: &[SegmentSpan],
    payload: &[u8],
) -> Result<u64, FormatError> {
    let hdr = fixups::parse_header(payload)?;
    let starts = fixups::parse_starts_in_image(payload, hdr.starts_offset as usize)?;
    let mut total = 0u64;
    for (seg_index, &off) in starts.seg_info_offset.iter().enumerate() {
        if off == 0 {
            continue;
        }
        let record_offset = hdr.starts_offset as usize + off as usize;
        let seg = fixups::parse_starts_in_segment(payload, record_offset)?;
        let Some(&span) = segments.get(seg_index) else {
            return Err(FormatError::Invalid {
                offset: record_offset,
                what: "fixup starts reference a segment index beyond the header's segments",
                value: seg_index as u64,
            });
        };
        for page in 0..seg.page_count {
            for start_off in fixups::page_chain_starts(payload, record_offset, &seg, page)? {
                let page_base = span
                    .fileoff
                    .checked_add(u64::from(page) * u64::from(seg.page_size))
                    .ok_or(FormatError::Invalid {
                        offset: record_offset,
                        what: "fixup page base overflow",
                        value: u64::from(page),
                    })?;
                total += walk_chain_page(bytes, page_base, u64::from(seg.page_size), start_off)?;
            }
        }
    }
    Ok(total)
}

/// Parses an image structurally, counting every table the linking pipeline
/// will later materialize.
///
/// # Errors
/// [`FormatError`] when the input structure is malformed or truncated.
///
/// This is the M0 parser-throughput benchmark unit: it walks the header,
/// every load command, all sections, the full symbol table, all relocation
/// entries and — when present — the complete chained-fixup chain structure.
/// Malformed input yields [`FormatError`], never a panic.
pub fn summarize(bytes: &[u8]) -> Result<ObjectSummary, FormatError> {
    let header = MachHeader64::parse(bytes)?;
    let mut s = ObjectSummary {
        file_size: bytes.len() as u64,
        load_commands: header.ncmds,
        ..ObjectSummary::default()
    };
    let mut segments: Vec<SegmentSpan> = Vec::new();
    let mut fixups_lc: Option<LinkeditDataCommand> = None;

    let mut it = LoadCommandIter::new(bytes, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)?;
    while let Some(cmd) = it.next_command()? {
        match cmd.kind {
            LoadCommandKind::Segment64 => {
                let seg = SegmentCommand64::parse(cmd.bytes, 0)?;
                let sects = seg.sections(cmd.bytes, SegmentCommand64::SIZE)?;
                s.segments += 1;
                s.sections += seg.nsects;
                segments.push(SegmentSpan {
                    fileoff: seg.fileoff,
                });
                for sect in sects {
                    s.relocations += sect.nreloc;
                    for i in 0..sect.nreloc {
                        let off = sect.reloff as usize + i as usize * 8;
                        let r = RelocationInfo::parse(bytes, off)?;
                        if r.is_scattered() {
                            return Err(FormatError::Invalid {
                                offset: off,
                                what: "scattered relocation (not generated on arm64)",
                                value: u64::from(r.r_address),
                            });
                        }
                        // Touch the decoded fields: this is the per-reloc work
                        // Pass 4's apply loop does when scanning relocations.
                        let _ = (r.rtype(), r.symbolnum(), r.length_log2());
                    }
                }
            }
            LoadCommandKind::Symtab => {
                let st = SymtabCommand::parse(cmd.bytes, 0)?;
                s.symbols = st.nsyms;
                for i in 0..st.nsyms {
                    let off = st.symoff as usize + i as usize * 16;
                    let sym = pod_read_nlist(bytes, off)?;
                    if sym.is_external() && !sym.is_stab() {
                        s.external_symbols += 1;
                    }
                    // Touch value + desc: the two fields resolution reads.
                    let _ = (sym.n_value, sym.library_ordinal());
                }
            }
            LoadCommandKind::Dysymtab => {
                let dys = DysymtabCommand::parse(cmd.bytes, 0)?;
                s.indirect_symbols = dys.nindirectsyms;
                let _ = dys.indirect_symbols(bytes)?.len();
            }
            LoadCommandKind::LinkeditData(LC_DYLD_CHAINED_FIXUPS) => {
                fixups_lc = Some(LinkeditDataCommand::parse(cmd.bytes)?);
            }
            _ => {}
        }
    }

    if let Some(lc) = fixups_lc {
        s.has_chained_fixups = true;
        let payload = lc.data(bytes)?;
        s.fixup_slots = walk_fixup_payload(bytes, &segments, payload)?;
    }
    Ok(s)
}

/// Reads one `nlist_64` at `offset` (thin wrapper so the hot loop stays
/// allocation-free and branch-free beyond the bounds check).
#[inline]
fn pod_read_nlist(bytes: &[u8], offset: usize) -> Result<Nlist64, FormatError> {
    cursor::pod_read_unaligned_at::<Nlist64>(bytes, offset)
}

#[cfg(test)]
mod tests {
    use super::summarize;

    #[test]
    fn empty_and_tiny_inputs_error_not_panic() {
        assert!(summarize(&[]).is_err());
        assert!(summarize(&[0u8; 8]).is_err());
        assert!(summarize(&[0xffu8; 32]).is_err());
    }
}
