//! The initializer-surface contract (M94): the sections dyld's
//! load-time initializer walk consumes must name targets the image
//! actually maps. Two forms ride the same walk
//! (`MachOAnalyzer::forEachInitializer`): the classic
//! `S_MOD_INIT_FUNC_POINTERS` pointer sections (8-byte slots whose file
//! bytes are fixup words — chained rebase encodings under
//! `LC_DYLD_CHAINED_FIXUPS`, opcode-driven rebases under the legacy
//! streams — so the raw bytes stay unread and the *stride* is the shape
//! this gate can honestly check) and the `S_INIT_FUNC_OFFSETS`
//! u32-offset section the M16 transform emits
//! (`__TEXT,__init_offsets`): each entry is the initializer's distance
//! from the load address, and dyld's own load-time check —
//! *"initializer does not point within executable segment"* — is the
//! contract replayed here read-side, entry by entry, against the
//! segments the image maps.
//!
//! The floor rule rides the same family: below the platform's
//! chained-fixups floor ([`pgr_format::consts::chained_fixups_floor`],
//! the one table the layout's refusal, the M10 verifier gate and the
//! encoding query read) no dyld consumes `S_INIT_FUNC_OFFSETS`, so the
//! section would silently lose every initializer — the producer refuses
//! the same premise at link time (`pgr_core::init_offsets`); the gate is
//! the read-side backstop for shapes built independently of it.
//!
//! An `MH_OBJECT` carries no dyld walk at all (the `-r` output preserves
//! input sections verbatim), so the family self-gates to the kinds dyld
//! loads — the [`crate::checks::Check::Symbols`] object contract owns
//! the relocatable shape.

use crate::structural::ParsedImage;
use crate::{Code, Issue, Report};
use pgr_format::consts::{
    S_INIT_FUNC_OFFSETS, S_MOD_INIT_FUNC_POINTERS, SECTION_TYPE_MASK, VM_PROT_EXECUTE,
};

/// One initializer surface the image carries.
struct InitSection {
    /// Segment name (sanity context for the message).
    seg: String,
    /// Section name.
    name: String,
    /// File offset of the section's bytes (the issue anchor).
    offset: u64,
    /// Section size in bytes.
    size: u64,
}

/// The offsets-form entries, read total: the stride finding has already
/// fired for a mis-shaped section, so a truncated tail rides the bounds
/// check the `segments` family owns rather than a second verdict here.
fn read_entries(bytes: &[u8], sect: &InitSection) -> Vec<u32> {
    let off = usize::try_from(sect.offset).unwrap_or(usize::MAX);
    let len = usize::try_from(sect.size).unwrap_or(usize::MAX);
    let Some(win) = bytes.get(off..off.saturating_add(len)) else {
        return Vec::new();
    };
    win.chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

/// Validates the image's initializer surface. Runs on every image kind
/// dyld loads (an `MH_OBJECT` never reaches the walk).
pub(crate) fn check_init_offsets(bytes: &[u8], img: &ParsedImage<'_>, report: &mut Report) {
    let mut offsets_sections: Vec<InitSection> = Vec::new();
    let mut pointer_sections: Vec<InitSection> = Vec::new();
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
            let section = InitSection {
                seg: cstr(&s.segname),
                name: cstr(&s.sectname),
                offset: u64::from(s.offset),
                size: s.size,
            };
            match s.flags & SECTION_TYPE_MASK {
                S_INIT_FUNC_OFFSETS => offsets_sections.push(section),
                S_MOD_INIT_FUNC_POINTERS => pointer_sections.push(section),
                _ => {}
            }
        }
    }
    let err = |what: String, at: Option<u64>| Issue::error(Code::InitOffsets, what, at);

    // The floor: below the platform's chained-fixups floor no dyld
    // consumes the offsets form, so every initializer would silently
    // never run (the producer refuses the same premise; this is the
    // read-side backstop for shapes built independently of it).
    if !offsets_sections.is_empty()
        && let Some(bv) = &img.build_version
        && bv.minos < pgr_format::consts::chained_fixups_floor(bv.platform)
    {
        let floor = pgr_format::consts::chained_fixups_floor(bv.platform);
        report.issues.push(err(
            format!(
                "deployment target {} is below the chained-fixups floor {} for platform {} \
                 while the image carries an S_INIT_FUNC_OFFSETS section — that dyld cannot \
                 consume __init_offsets and every initializer would silently never run; \
                 raise the -platform_version deployment target or relink with \
                 -no_init_offsets (the classic pointer form encodes the same initializers)",
                crate::misc::fmt_packed_version(bv.minos),
                crate::misc::fmt_packed_version(floor),
                bv.platform,
            ),
            Some(offsets_sections[0].offset),
        ));
    }

    // The strides: the walks read whole u32 offsets / whole 8-byte
    // pointer slots; a section off its stride makes the walk read a
    // truncated entry the shape never carried.
    for s in &offsets_sections {
        if s.size % 4 != 0 {
            report.issues.push(err(
                format!(
                    "initializer-offset section {},{}: size {:#x} is not a multiple of the \
                     4-byte u32 stride — the initializer walk reads whole offsets; relink \
                     the image (the producer refuses the same shape)",
                    s.seg, s.name, s.size
                ),
                Some(s.offset),
            ));
        }
    }
    for s in &pointer_sections {
        if s.size % 8 != 0 {
            report.issues.push(err(
                format!(
                    "initializer-pointer section {},{}: size {:#x} is not a multiple of the \
                     8-byte pointer stride — the initializer walk reads whole slots; relink \
                     the image (the producer refuses the same shape)",
                    s.seg, s.name, s.size
                ),
                Some(s.offset),
            ));
        }
    }

    // The offsets form's targets: entry = distance from the load address
    // (the __TEXT vmaddr, where the mach header maps), and dyld's own
    // load-time check — "initializer does not point within executable
    // segment" — is the contract replayed here entry by entry.
    let text_vmaddr = img
        .segments
        .iter()
        .find(|s| s.name() == Ok("__TEXT"))
        .map_or(0, |s| s.vmaddr);
    for s in &offsets_sections {
        for (i, entry) in read_entries(bytes, s).iter().enumerate() {
            let target = text_vmaddr.wrapping_add(u64::from(*entry));
            let seg = img.segments.iter().find(|seg| {
                seg.vmsize > 0 && target >= seg.vmaddr && target < seg.vmaddr + seg.vmsize
            });
            match seg {
                None => {
                    report.issues.push(err(
                        format!(
                            "initializer-offset section {},{}: entry {} ({entry:#x} from the \
                             load address) names {target:#x} and no segment maps it — dyld's \
                             initializer walk refuses the image at load; relink the image so \
                             the entry names a function the image maps",
                            s.seg, s.name, i,
                        ),
                        Some(s.offset),
                    ));
                }
                Some(seg) if seg.initprot & VM_PROT_EXECUTE == 0 => {
                    report.issues.push(err(
                        format!(
                            "initializer-offset section {},{}: entry {} ({entry:#x} from the \
                             load address) names {target:#x} inside segment {} — dyld's \
                             initializer walk refuses an initializer that does not point \
                             within an executable segment; relink the image so the entry \
                             names a function in __TEXT",
                            s.seg,
                            s.name,
                            i,
                            seg.name().unwrap_or("?"),
                        ),
                        Some(s.offset),
                    ));
                }
                Some(_) => {}
            }
        }
    }
}

/// One NUL-terminated 16-byte section-name field, as a string.
fn cstr(field: &[u8; 16]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}
