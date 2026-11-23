//! M132: the exit-time terminator-surface contract — the read-side backstop
//! the producer's `__mod_term_func` emit-side stride assumes. The
//! `S_MOD_TERM_FUNC_POINTERS` section dyld's exit walk consumes
//! (`MachOAnalyzer::forEachTerminator`, the mirror of the initializer walk
//! the `init_offsets` family gates) must ride a whole 8-byte pointer
//! stride: every entry is a fixup word the walk reads as a whole slot, so
//! a section whose size is not a multiple of 8 is the malformed shape
//! dyld's walk would misread (the same stride contract the M94 pointer
//! form carries, one section type over — `S_MOD_TERM_FUNC_POINTERS` 0xa
//! beside `S_MOD_INIT_FUNC_POINTERS` 0x9). The producer emits the section
//! (`pgr_core::layout` sizes `__mod_term_func` beside `__mod_init_func`,
//! and `dead_strip` keeps it whole under `-no_dead_strip_inits`); the
//! family is the read-side backstop regardless of how the section was
//! produced (the M115/M131 read-side-backstop shape — a malformed pool
//! the producer never wrote still reports).
//!
//! The slots are fixup words (chained rebase encodings under
//! `LC_DYLD_CHAINED_FIXUPS`, opcode-driven rebases under the legacy
//! streams), so the raw bytes stay unread — the *stride* is the shape
//! this gate can honestly check (the M94 pointer-form precedent).
//! Terminators are pointer-form only (Mach-O carries no
//! `S_TERM_FUNC_OFFSETS`), so the family carries no offsets-form target
//! walk and no chained-fixups floor rule (the M94 offsets-form concerns
//! stay the initializer family's own).

use crate::structural::ParsedImage;
use crate::{Code, Issue, Report};
use pgr_format::consts::{S_MOD_TERM_FUNC_POINTERS, SECTION_TYPE_MASK};

/// One terminator surface the image carries.
struct TermSection {
    /// Segment name (sanity context for the message).
    seg: String,
    /// Section name.
    name: String,
    /// File offset of the section's bytes (the issue anchor).
    offset: u64,
    /// Section size in bytes.
    size: u64,
}

/// Validates the image's exit-time terminator surface. Runs on every
/// image kind dyld loads (the registry's `ModTermCheck` self-gates off
/// `MH_OBJECT` — an `-r` output preserves input sections verbatim and
/// carries no dyld walk; the `Symbols` family's object contract owns the
/// relocatable shape).
pub(crate) fn check_mod_term(bytes: &[u8], img: &ParsedImage<'_>, report: &mut Report) {
    for cmd in &img.commands {
        if cmd.kind != pgr_format::load_command::LoadCommandKind::Segment64 {
            continue;
        }
        let Ok(seg) = pgr_format::SegmentCommand64::parse(cmd.bytes, 0) else {
            continue; // the segment/section shape gates ride `segments`
        };
        let Ok(sects) = seg.sections(bytes, cmd.offset + pgr_format::SegmentCommand64::SIZE) else {
            continue;
        };
        for s in sects {
            if s.flags & SECTION_TYPE_MASK != S_MOD_TERM_FUNC_POINTERS {
                continue;
            }
            let sect = TermSection {
                seg: cstr(&s.segname),
                name: cstr(&s.sectname),
                offset: u64::from(s.offset),
                size: s.size,
            };
            // The walk reads whole 8-byte pointer slots; a section off its
            // stride makes the walk read a truncated entry the shape never
            // carried (the M94 pointer-form stride gate, one section type
            // over). The slots themselves are fixup words — chained rebase
            // encodings or legacy opcode-driven rebases — so the raw bytes
            // stay unread and the stride is the shape this gate honestly
            // checks.
            if sect.size % 8 != 0 {
                report.issues.push(Issue::error(
                    Code::ModTerm,
                    format!(
                        "terminator-pointer section {},{} (`__mod_term_func`, \
                         S_MOD_TERM_FUNC_POINTERS): size {:#x} is not a multiple of the \
                         8-byte pointer stride — dyld's exit walk reads whole slots; relink \
                         the image (the producer refuses the same shape)",
                        sect.seg, sect.name, sect.size
                    ),
                    Some(sect.offset),
                ));
            }
        }
    }
}

/// One NUL-terminated 16-byte section-name field, as a string.
fn cstr(field: &[u8; 16]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}
