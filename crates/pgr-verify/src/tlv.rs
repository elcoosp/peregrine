//! The thread-local surface contract (M37): the `MH_HAS_TLV_DESCRIPTORS`
//! header marker and the `S_THREAD_LOCAL_*` sections ride together — the
//! marker is what dyld's load-time TLV allocation keys on, so an image
//! that declares it without carrying a thread-local section asks dyld to
//! allocate for nothing, and an image that carries the sections without
//! the marker never gets its thread-local variables allocated. The
//! `__thread_vars` descriptors are 16-byte thunk/initializer pairs (the
//! stride the descriptor walk reads), and descriptors without
//! thread-local data have initializer fields with nothing to point at.
//!
//! The sections' absence is the default (a TLV-free image sets no flag —
//! never a finding); the flag/section parity is the contract.

use crate::structural::ParsedImage;
use crate::{Code, Issue, Report};
use pgr_format::consts::{
    MH_HAS_TLV_DESCRIPTORS, S_THREAD_LOCAL_REGULAR, S_THREAD_LOCAL_VARIABLES,
    S_THREAD_LOCAL_ZEROFILL, SECTION_TYPE_MASK,
};

/// The TLV descriptor's byte width (8-byte thunk, 8-byte initializer).
const DESCRIPTOR_SIZE: u64 = 16;

/// One NUL-terminated 16-byte section-name field, as a string.
fn cstr(field: &[u8; 16]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

/// One thread-local section the image carries.
struct TlvSection {
    /// Segment name (sanity context for the message).
    seg: String,
    /// Section name.
    name: String,
    /// File offset of the section's bytes.
    offset: u64,
    /// Section size in bytes.
    size: u64,
}

/// Validates the image's thread-local surface. Runs on every image kind
/// dyld loads (an `MH_OBJECT` carries no TLV marker — the `-r` output's
/// flag word is zero by contract).
pub(crate) fn check_tlv(bytes: &[u8], img: &ParsedImage<'_>, report: &mut Report) {
    let mut descriptors: Vec<TlvSection> = Vec::new();
    let mut data: Vec<TlvSection> = Vec::new();
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
            let seg = cstr(&s.segname);
            let name = cstr(&s.sectname);
            let section = TlvSection {
                seg,
                name,
                offset: u64::from(s.offset),
                size: s.size,
            };
            match s.flags & SECTION_TYPE_MASK {
                S_THREAD_LOCAL_VARIABLES => descriptors.push(section),
                S_THREAD_LOCAL_REGULAR | S_THREAD_LOCAL_ZEROFILL => data.push(section),
                _ => {}
            }
        }
    }
    let flagged = img.header.flags & MH_HAS_TLV_DESCRIPTORS != 0;
    let err = |what: String, at: Option<u64>| Issue::error(Code::Tlv, what, at);

    // The marker/section parity: dyld's load-time TLV allocation keys on
    // the flag alone, so both directions lie to the loader.
    if flagged && descriptors.is_empty() && data.is_empty() {
        report.issues.push(err(
            "the image declares MH_HAS_TLV_DESCRIPTORS but carries no thread-local section — \
             the marker asks dyld to run its TLV allocation for nothing; drop the flag or link \
             the thread-local surface"
                .into(),
            None,
        ));
    }
    if !flagged && (!descriptors.is_empty() || !data.is_empty()) {
        report.issues.push(err(
            "the image carries thread-local sections but does not declare \
             MH_HAS_TLV_DESCRIPTORS — dyld's load-time TLV allocation never engages and the \
             variables stay unallocated; set the flag"
                .into(),
            descriptors.first().or(data.first()).map(|s| s.offset),
        ));
    }

    // The descriptor stride: the 16-byte thunk/initializer pair the
    // descriptor walk reads.
    for d in &descriptors {
        if d.size % DESCRIPTOR_SIZE != 0 {
            report.issues.push(err(
                format!(
                    "descriptor section {},{}: size {:#x} is not a multiple of the 16-byte \
                     descriptor stride — the descriptor walk reads whole thunk/initializer \
                     pairs; relink the image (the producer refuses the same shape)",
                    d.seg, d.name, d.size
                ),
                Some(d.offset),
            ));
        }
    }

    // The descriptors' initializers need thread-local data to point at.
    if !descriptors.is_empty() && data.is_empty() {
        report.issues.push(err(
            "the image carries __thread_vars descriptors with no thread-local data section — \
             the descriptors' initializer field has nothing to point at; link the \
             __thread_data/__thread_bss sections the variables allocate from"
                .into(),
            Some(descriptors[0].offset),
        ));
    }
}
