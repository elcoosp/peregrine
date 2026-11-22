//! M131: the mergeable literal-pool contract — the read-side backstop the
//! producer's D4 dedup emit-side gate mirrors. The three fixed-width
//! literal section types (`S_4BYTE_LITERALS`, `S_8BYTE_LITERALS`,
//! `S_16BYTE_LITERALS`) the producer's D4 dedup emits (one canonical copy
//! per unique value, M131) must ride a whole atom-width stride (the size a
//! whole multiple of 4/8/16 — dyld's literal-pool consumer walks the
//! section at that stride) and an alignment at or above the width's own
//! power of two (4→2, 8→3, 16→4 — the dedup's width atoms assume the
//! section's natural alignment). A section whose stride or alignment
//! leaves the contract is the malformed shape the producer's emit-side
//! gate should have caught; the verifier reports it read-side regardless
//! of how the section was produced (the M115/M118/M129 read-side-backstop
//! shape). The dedup correctness itself (one canonical copy per unique
//! value) is pinned byte-identity by the `m131_literal_merge` gate, the
//! M5 cstring precedent (cstrings carry no verify family — the variable
//! NUL-terminated stride needs no whole-multiple gate).

use crate::structural::ParsedImage;
use crate::{Code, Issue, Report};
use pgr_format::consts::literal_atom_width;

/// Walks every segment's sections for the three fixed-width literal types
/// and reports a stride or alignment contract violation. The check is
/// total (never panics on malformed input — a truncated command or section
/// header reports nothing and returns) and self-gates on the image
/// carrying fixed-width literal sections at all.
pub(crate) fn check_literals(_bytes: &[u8], parsed: &ParsedImage<'_>, report: &mut Report) {
    for cmd in &parsed.commands {
        if !matches!(cmd.kind, pgr_format::LoadCommandKind::Segment64) {
            continue;
        }
        if cmd.bytes.len() < 72 {
            continue;
        }
        let nsects = u32::from_le_bytes(cmd.bytes[64..68].try_into().unwrap_or([0; 4]));
        for i in 0..nsects as usize {
            let base = 72 + i * 80;
            if base + 80 > cmd.bytes.len() {
                break;
            }
            let flags =
                u32::from_le_bytes(cmd.bytes[base + 64..base + 68].try_into().unwrap_or([0; 4]));
            // Cstrings are variable-width (split at the NUL) — no stride
            // gate. Only the three fixed-width literal types ride this
            // backstop.
            let Some(width) = literal_atom_width(flags) else {
                continue;
            };
            let size =
                u64::from_le_bytes(cmd.bytes[base + 40..base + 48].try_into().unwrap_or([0; 8]));
            // An empty literal section carries no atoms — nothing to stride
            // over and no content the consumer walks.
            if size == 0 {
                continue;
            }
            let align =
                u32::from_le_bytes(cmd.bytes[base + 52..base + 56].try_into().unwrap_or([0; 4]));
            let width_log2 = width.trailing_zeros();
            let seg_name = name(&cmd.bytes[base..base + 16]);
            let sect_name = name(&cmd.bytes[base + 16..base + 32]);
            if size % u64::from(width) != 0 {
                report.issues.push(Issue::error(
                    Code::Literal,
                    format!(
                        "the literal section {seg_name},{sect_name} (S_{width}BYTE_LITERALS) \
                         carries size {size} not a whole multiple of its atom width {width} — \
                         dyld's literal-pool consumer walks the section at the {width}-byte \
                         stride the D4 dedup's width atoms assume",
                    ),
                    None,
                ));
            }
            if align < width_log2 {
                report.issues.push(Issue::error(
                    Code::Literal,
                    format!(
                        "the literal section {seg_name},{sect_name} (S_{width}BYTE_LITERALS) \
                         carries align 2^{align} below its atom width's own power of two \
                         2^{width_log2} — the {width}-byte stride the D4 dedup's width atoms \
                         assume needs the section's natural alignment",
                    ),
                    None,
                ));
            }
        }
    }
}

/// Reads a null-padded 16-byte section/segment name field as a trimmed
/// string (the `section_64` name arrays are fixed-width and NUL-padded).
fn name(field: &[u8]) -> String {
    String::from_utf8_lossy(field)
        .trim_end_matches('\0')
        .to_string()
}
