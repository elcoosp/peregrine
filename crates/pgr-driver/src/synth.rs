//! Synthetic inputs for driver flags that contribute bytes rather than
//! objects (M5).
//!
//! `-sectcreate <seg> <sect> <file>` contributes a section whose contents
//! are the file's bytes. Internally it is carried as a minimal relocatable
//! object (one `S_REGULAR` section, no symbols, no relocations) so the
//! normal Pass 1–3 pipeline places it: the bucketing pass routes
//! `(segment, name)` by name, and unknown names follow the canonical
//! first-seen order (TDD §8.4). The bytes are deterministic.

use pgr_format::consts::{
    CPU_SUBTYPE_ARM64_ALL, CPU_TYPE_ARM64, LC_SEGMENT_64, LC_SYMTAB, MH_MAGIC_64, MH_OBJECT,
};

/// Builds a minimal single-section `MH_OBJECT` carrying `data` as
/// `<seg>,<sect>` (the `-sectcreate` payload).
///
/// # Errors
/// A `String` diagnostic when the names do not fit the 16-byte Mach-O
/// fields (naming rules identical to `pgr-fixtures`' object builder).
pub fn section_object(seg: &str, sect: &str, data: &[u8]) -> Result<Vec<u8>, String> {
    let pad16 = |name: &str| -> Result<[u8; 16], String> {
        let bytes = name.as_bytes();
        if bytes.len() > 16 {
            return Err(format!("section/segment name {name:?} exceeds 16 bytes"));
        }
        let mut out = [0u8; 16];
        out[..bytes.len()].copy_from_slice(bytes);
        Ok(out)
    };
    let seg_name = pad16(seg)?;
    let sect_name = pad16(sect)?;

    // Layout: header (32) | LC_SEGMENT_64 (72 + 80) | LC_SYMTAB (24) | data
    // | strtab (1 byte, the standard leading NUL).
    // Explicit `u32` annotations: the sizes feed `to_le_bytes()` — inferring
    // them as `usize` (through `data.len()`) would emit 8-byte fields.
    let segment_cmd_size: u32 = 72 + 80;
    let symtab_cmd_size: u32 = 24;
    let data_off: u32 = 32 + segment_cmd_size + symtab_cmd_size;
    let strtab_off: usize = data_off as usize + data.len();

    let mut out = Vec::with_capacity(strtab_off + 1);
    // Mach header (LE).
    out.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
    out.extend_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
    out.extend_from_slice(&CPU_SUBTYPE_ARM64_ALL.to_le_bytes());
    out.extend_from_slice(&MH_OBJECT.to_le_bytes());
    out.extend_from_slice(&2u32.to_le_bytes()); // ncmds
    out.extend_from_slice(&(segment_cmd_size + symtab_cmd_size).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // flags
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved

    // LC_SEGMENT_64.
    out.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
    out.extend_from_slice(&segment_cmd_size.to_le_bytes());
    out.extend_from_slice(b"__PGR\0\0\0\0\0\0\0\0\0\0\0"); // segname (unused)
    out.extend_from_slice(&0u64.to_le_bytes()); // vmaddr
    out.extend_from_slice(&0u64.to_le_bytes()); // vmsize
    out.extend_from_slice(&(data_off as u64).to_le_bytes()); // fileoff
    out.extend_from_slice(&(data.len() as u64).to_le_bytes()); // filesize
    out.extend_from_slice(&0x07u32.to_le_bytes()); // maxprot RWX
    out.extend_from_slice(&0x07u32.to_le_bytes()); // initprot RWX
    out.extend_from_slice(&1u32.to_le_bytes()); // nsects
    out.extend_from_slice(&0u32.to_le_bytes()); // flags

    // The one section.
    out.extend_from_slice(&sect_name);
    out.extend_from_slice(&seg_name);
    out.extend_from_slice(&(data_off as u64).to_le_bytes()); // addr (blob-relative)
    out.extend_from_slice(&(data.len() as u64).to_le_bytes()); // size
    out.extend_from_slice(&data_off.to_le_bytes()); // offset
    out.extend_from_slice(&0u32.to_le_bytes()); // align (1-byte)
    out.extend_from_slice(&0u32.to_le_bytes()); // reloff
    out.extend_from_slice(&0u32.to_le_bytes()); // nreloc
    out.extend_from_slice(&0u32.to_le_bytes()); // flags (S_REGULAR)
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved1
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved2
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved3

    // LC_SYMTAB (empty).
    out.extend_from_slice(&LC_SYMTAB.to_le_bytes());
    out.extend_from_slice(&symtab_cmd_size.to_le_bytes());
    out.extend_from_slice(&(strtab_off as u32).to_le_bytes()); // symoff
    out.extend_from_slice(&0u32.to_le_bytes()); // nsyms
    out.extend_from_slice(&(strtab_off as u32).to_le_bytes()); // stroff
    out.extend_from_slice(&1u32.to_le_bytes()); // strsize
    out.extend_from_slice(data);
    out.push(0);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::section_object;

    #[test]
    fn section_object_parses_back() {
        let bytes = section_object("__DATA", "__plist", b"hello").unwrap();
        let header = pgr_format::MachHeader64::parse(&bytes).unwrap();
        assert_eq!(header.filetype, pgr_format::consts::MH_OBJECT);
        assert_eq!(header.ncmds, 2);
        let mut it = pgr_format::LoadCommandIter::new(
            &bytes,
            pgr_format::MachHeader64::SIZE,
            header.ncmds,
            header.sizeofcmds,
        )
        .unwrap();
        let mut seen = Vec::new();
        while let Some(cmd) = it.next_command().unwrap() {
            seen.push(cmd.kind);
        }
        assert_eq!(
            seen,
            vec![
                pgr_format::LoadCommandKind::Segment64,
                pgr_format::LoadCommandKind::Symtab
            ]
        );
        assert!(bytes.windows(5).any(|w| w == b"hello"));
    }

    #[test]
    fn oversized_names_error() {
        assert!(section_object("__WAY_TOO_LONG_SEGMENT_NAME_XYZ", "__ok", b"").is_err());
    }
}
