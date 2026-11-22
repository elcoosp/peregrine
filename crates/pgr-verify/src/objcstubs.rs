//! M6/D-R3 (M130): the `__objc_stubs` synthesis contract — the read-side
//! backstop the producer's stub-synthesis emit-side gate mirrors. The
//! `__TEXT,__objc_stubs` section ld64's `objc_msgSend` dispatch consumes
//! rides a well-formed shape: `S_SYMBOL_STUBS` type (the same type
//! `__stubs` carries — the name distinguishes the objc family) and a
//! whole `OBJC_STUB_SIZE_ARM64` stride (every stub is five arm64
//! words). The paired `__TEXT,__objc_methname` section carries
//! `S_CSTRING_LITERALS`.

use crate::{Code, Issue, Report};
use pgr_format::consts::{OBJC_STUB_SIZE_ARM64, SECTION_TYPE_MASK, S_CSTRING_LITERALS, S_SYMBOL_STUBS};

/// Walks every declared section (the raw load-command walk); an
/// `__objc_stubs` section off the stride or with the wrong type, or an
/// `__objc_methname` section with the wrong type, is the malformed
/// shape dyld's dispatch would misread.
pub(crate) fn check_objc_stubs(bytes: &[u8], report: &mut Report) {
    let Ok(hdr) = pgr_format::MachHeader64::parse(bytes) else {
        return;
    };
    let Ok(mut it) = pgr_format::LoadCommandIter::new(
        bytes,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    ) else {
        return;
    };
    while let Ok(Some(cmd)) = it.next_command() {
        if cmd.kind != pgr_format::LoadCommandKind::Segment64 || cmd.bytes.len() < 72 {
            continue;
        }
        let nsects = u32::from_le_bytes(cmd.bytes[64..68].try_into().unwrap_or([0; 4]));
        for i in 0..nsects as usize {
            let base = 72 + i * 80;
            if base + 80 > cmd.bytes.len() {
                return;
            }
            let entry = &cmd.bytes[base..base + 80];
            let name = String::from_utf8_lossy(&entry[..16]);
            let name = name.trim_end_matches('\0');
            let flags = u32::from_le_bytes(entry[64..68].try_into().unwrap_or([0; 4]));
            let size = u64::from_le_bytes(entry[40..48].try_into().unwrap_or([0; 8]));
            let anchor = u64::try_from(cmd.offset).unwrap_or(0);
            if name == "__objc_stubs" {
                if flags & SECTION_TYPE_MASK != S_SYMBOL_STUBS {
                    report.issues.push(Issue::error(
                        Code::ObjcStubs,
                        format!(
                            "`__objc_stubs` carries the wrong section type (0x{:x}, expected \
                             S_SYMBOL_STUBS 0x8) — the objc-msgSend stub family reuses the \
                             symbol-stubs type the `__stubs` family rides",
                            flags & SECTION_TYPE_MASK
                        ),
                        Some(anchor),
                    ));
                }
                if size % u64::from(OBJC_STUB_SIZE_ARM64) != 0 {
                    report.issues.push(Issue::error(
                        Code::ObjcStubs,
                        format!(
                            "`__objc_stubs` rides a broken stub stride (size {size} is not a \
                             multiple of OBJC_STUB_SIZE_ARM64 {OBJC_STUB_SIZE_ARM64}) — every \
                             stub is five arm64 words"
                        ),
                        Some(anchor),
                    ));
                }
            } else if name == "__objc_methname" {
                if flags & SECTION_TYPE_MASK != S_CSTRING_LITERALS {
                    report.issues.push(Issue::error(
                        Code::ObjcStubs,
                        format!(
                            "`__objc_methname` carries the wrong section type (0x{:x}, expected \
                             S_CSTRING_LITERALS 0x2) — the selector strings dedup like cstrings",
                            flags & SECTION_TYPE_MASK
                        ),
                        Some(anchor),
                    ));
                }
            }
        }
    }
}
