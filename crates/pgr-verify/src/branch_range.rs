//! Branch-range checking (M6 — architecture doc §10.3 row M6 gate:
//! "thunk placement verified by a branch-range checker in `pgr-verify`").
//!
//! The pass decodes every arm64 `B`/`BL` in the image's executable sections
//! and validates that each computed target lands back inside executable
//! code, 4-byte aligned. After M6's veneer insertion (pgr-core `thunks`)
//! every direct branch either reaches its target directly or reaches a
//! veneer whose register branch (`br x16`) carries the long hop — so any
//! `B`/`BL` leaving the executable span is a mis-encode, and any
//! mis-aligned target a corrupt immediate.
//!
//! The decode is read-only and panic-free: malformed sections are skipped,
//! truncated tails ignored, and every finding is an [`Issue`].

use crate::Issue;
use crate::Report;
use crate::structural::{ParsedImage, section_table_offset};
use pgr_format::consts::S_ATTR_SOME_INSTRUCTIONS;

/// One decoded arm64 unconditional branch: `(is_bl, byte delta)`.
///
/// `B` is `000101 imm26`, `BL` is `100101 imm26`; the delta is the
/// sign-extended imm26 scaled by 4. Every other word returns `None`
/// (register branches, returns, ADRP/ADD — none are range-checked here).
#[must_use]
pub fn decode_branch(word: u32) -> Option<(bool, i64)> {
    let op = word >> 26;
    match op {
        0b00_0101 => Some((false, sign_extend_26(word) * 4)),
        0b10_0101 => Some((true, sign_extend_26(word) * 4)),
        _ => None,
    }
}

/// Sign-extends the 26-bit immediate field.
fn sign_extend_26(word: u32) -> i64 {
    let imm = (word & 0x03FF_FFFF) as i64;
    if imm & (1 << 25) != 0 {
        imm - (1 << 26)
    } else {
        imm
    }
}

/// Walks one executable section's words: every `B`/`BL` target must stay
/// inside `[lo, hi)` (the image's executable span) and 4-byte aligned.
/// `base` is the section's vm_addr; findings anchor at the word's file
/// offset when `file_off` is meaningful (`Some`), else section-relative.
pub(crate) fn check_branch_words(
    words: &[u8],
    base: u64,
    lo: u64,
    hi: u64,
    file_off: Option<u64>,
    report: &mut Report,
) {
    for (i, chunk) in words.chunks_exact(4).enumerate() {
        let word = u32::from_le_bytes(chunk.try_into().expect("chunks_exact(4)"));
        let Some((is_bl, delta)) = decode_branch(word) else {
            continue;
        };
        let pc = base + (i * 4) as u64;
        let target = (pc as i64) + delta;
        let anchor = file_off.map(|off| off + (i * 4) as u64);
        let what = if is_bl { "bl" } else { "b" };
        if target < 0 || (target as u64) < lo || (target as u64) >= hi {
            report.issues.push(Issue::error(
                crate::Code::BranchRange,
                format!(
                    "{what} at {pc:#x} targets {target:#x}, outside the executable span \
                     [{lo:#x}, {hi:#x})"
                ),
                anchor,
            ));
        } else if target % 4 != 0 {
            report.issues.push(Issue::error(
                crate::Code::BranchRange,
                format!("{what} at {pc:#x} targets {target:#x}, not 4-byte aligned"),
                anchor,
            ));
        }
    }
}

/// The M6 branch-range gate: every executable section of the image is
/// decoded; `B`/`BL` targets must land within the `__TEXT` segment's
/// virtual span (all executable sections live there, veneers included).
pub(crate) fn check_branch_range(bytes: &[u8], img: &ParsedImage<'_>, report: &mut Report) {
    // The executable span: `__TEXT` vmaddr .. vmaddr + vmsize. Every code
    // section (and every veneer) lives inside it by construction.
    let Some(text) = img
        .segments
        .iter()
        .find(|s| s.name().is_ok_and(|n| n == "__TEXT"))
    else {
        return;
    };
    let lo = text.vmaddr;
    let hi = text.vmaddr.saturating_add(text.vmsize);
    let table_at = section_table_offset(img, text);
    let Ok(sects) = text.sections(bytes, table_at) else {
        return;
    };
    for sect in sects {
        if sect.flags & S_ATTR_SOME_INSTRUCTIONS == 0 || sect.size == 0 {
            continue;
        }
        // Section bytes: file-backed code sections only (zero-fill code
        // sections do not exist in practice; skip gracefully).
        let Some(words) = bytes
            .get(sect.offset as usize..)
            .and_then(|rest| rest.get(..(sect.size as usize).min(rest.len())))
        else {
            report.issues.push(Issue::warning(
                crate::Code::BranchRange,
                format!(
                    "executable section {} bytes are not file-backed; skipped",
                    sect.name().unwrap_or("?")
                ),
                Some(u64::from(sect.offset)),
            ));
            continue;
        };
        check_branch_words(
            words,
            sect.addr,
            lo,
            hi,
            Some(u64::from(sect.offset)),
            report,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{check_branch_words, decode_branch};
    use crate::Report;

    fn word(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }

    #[test]
    fn decodes_b_and_bl_shapes() {
        // b .+8: 000101 imm26=2 → delta 8.
        assert_eq!(decode_branch(0x1400_0002), Some((false, 8)));
        // b .-4: imm26 = 0x3FF_FFFF (−1) → delta −4.
        assert_eq!(decode_branch(0x17FF_FFFF), Some((false, -4)));
        // bl .+4.
        assert_eq!(decode_branch(0x9400_0001), Some((true, 4)));
        // bl .−128 MiB exactly (imm26 = −0x200_0000/4 words).
        let neg = ((-0x0200_0000i64 / 4) as u32) & 0x03FF_FFFF;
        assert_eq!(decode_branch(0x9400_0000 | neg), Some((true, -0x0200_0000)));
        // Non-branches: adrp/ret/nop register-branch shapes.
        assert_eq!(decode_branch(0x9000_0010), None); // adrp x16
        assert_eq!(decode_branch(0xD65F_03C0), None); // ret
        assert_eq!(decode_branch(0xD61F_0200), None); // br x16
        assert_eq!(decode_branch(0xD61F_0220), None); // brj x17 / brk family
        assert_eq!(decode_branch(0x9100_0210), None); // add x16
    }

    #[test]
    fn in_range_branches_pass() {
        // base 0x100: b +8 (to 0x108), bl −4 (to 0xFC — inside [0, 0x1000)).
        let mut words = Vec::new();
        words.extend_from_slice(&word(0x1400_0002));
        words.extend_from_slice(&word(0x97FF_FFFF)); // bl −4
        let mut report = Report::default();
        check_branch_words(&words, 0x100, 0, 0x1000, None, &mut report);
        assert!(
            report.issues.is_empty(),
            "{:?}",
            report.issues.iter().map(|i| &i.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn out_of_range_target_is_an_error() {
        // base 0x100: b +0x800_0000-sized hop: imm26 max positive = +128 MiB.
        // Target 0x100 + 0x800_0000 = far beyond hi=0x1000 → error.
        let mut words = Vec::new();
        words.extend_from_slice(&word(0x1400_0000 | (0x0200_0000u32 >> 2))); // b +128 MiB
        let mut report = Report::default();
        check_branch_words(&words, 0x100, 0, 0x1000, None, &mut report);
        assert_eq!(report.issues.len(), 1);
        assert_eq!(report.issues[0].code, crate::Code::BranchRange);
        assert_eq!(report.issues[0].severity, crate::Severity::Error);
        assert!(
            report.issues[0]
                .message
                .contains("outside the executable span")
        );
    }

    #[test]
    fn backward_out_of_range_target_is_an_error() {
        // bl −4 from base 0 → target −4 (negative) → error.
        let mut words = Vec::new();
        words.extend_from_slice(&word(0x97FF_FFFF));
        let mut report = Report::default();
        check_branch_words(&words, 0, 0, 0x1000, None, &mut report);
        assert_eq!(report.issues.len(), 1);
        assert!(
            report.issues[0]
                .message
                .contains("outside the executable span")
        );
    }

    #[test]
    fn misaligned_target_is_an_error() {
        // b +6 (imm26 = 1.5 words is impossible — imm26 scales by 4, so a
        // mis-aligned *target* comes from a mis-aligned base/pc. Simulate by
        // an odd base: pc=1, b+4 → target 5 (misaligned).
        let mut words = Vec::new();
        words.extend_from_slice(&word(0x1400_0001)); // b +4
        let mut report = Report::default();
        check_branch_words(&words, 1, 0, 0x1000, None, &mut report);
        assert_eq!(report.issues.len(), 1);
        assert!(report.issues[0].message.contains("not 4-byte aligned"));
    }

    #[test]
    fn truncated_tail_is_tolerated() {
        let mut words = Vec::new();
        words.extend_from_slice(&word(0x1400_0002));
        words.extend_from_slice(&[0x00]); // 1 stray byte
        let mut report = Report::default();
        check_branch_words(&words, 0x100, 0, 0x1000, None, &mut report);
        assert!(report.issues.is_empty());
    }
}
