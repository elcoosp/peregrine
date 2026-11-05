//! Load-command region: iteration, classification and bounds enforcement.
//!
//! The iterator walks the `sizeofcmds` region after the header, validating
//! every `cmdsize` (minimum 8, 8-byte aligned for 64-bit images, within the
//! region) before handing the command's bytes to the caller. Malformed sizes
//! are errors, never panics — the fuzz targets exercise exactly this path.

use crate::consts::{
    LC_BUILD_VERSION, LC_CODE_SIGNATURE, LC_DATA_IN_CODE, LC_DYLD_CHAINED_FIXUPS,
    LC_DYLD_EXPORTS_TRIE, LC_DYSYMTAB, LC_FUNCTION_STARTS, LC_ID_DYLIB, LC_LOAD_DYLIB,
    LC_LOAD_DYLINKER, LC_MAIN, LC_RPATH, LC_SEGMENT_64, LC_SOURCE_VERSION, LC_SYMTAB, LC_UUID,
};
use crate::cursor::Cursor;
use crate::error::FormatError;

/// One classified load command and the raw bytes it occupies.
#[derive(Debug, Clone, Copy)]
pub struct ParsedCommand<'a> {
    /// Absolute file offset of the command.
    pub offset: usize,
    /// `cmdsize` in bytes (8-byte aligned, checked).
    pub cmdsize: usize,
    /// Classified opcode.
    pub kind: LoadCommandKind,
    /// The command's bytes, including the 8-byte header.
    pub bytes: &'a [u8],
}

impl ParsedCommand<'_> {
    /// Reads the 8-byte command header fields (`cmd`, `cmdsize`).
    #[must_use]
    pub fn hdr(&self) -> (u32, u32) {
        let mut c = Cursor::new(self.bytes);
        let cmd = c.read_u32().unwrap_or(0);
        let cmdsize = c.read_u32().unwrap_or(0);
        (cmd, cmdsize)
    }
}

/// The load commands Peregrine's M0 pipeline reasons about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadCommandKind {
    /// `LC_SEGMENT_64`.
    Segment64,
    /// `LC_SYMTAB`.
    Symtab,
    /// `LC_DYSYMTAB`.
    Dysymtab,
    /// `LC_LOAD_DYLIB` (and its weak/upward variants, same layout).
    LoadDylib,
    /// `LC_ID_DYLIB`.
    IdDylib,
    /// `LC_LOAD_DYLINKER`.
    LoadDylinker,
    /// `LC_MAIN`.
    Main,
    /// `LC_BUILD_VERSION` (and the legacy `LC_VERSION_MIN_*` family).
    BuildVersion,
    /// `LC_UUID`.
    Uuid,
    /// `LC_RPATH`.
    Rpath,
    /// `LC_SOURCE_VERSION`.
    SourceVersion,
    /// `linkedit_data_command` payloads: chained fixups, export trie,
    /// function starts, data-in-code, code signature, split info.
    LinkeditData(u32),
    /// Anything else (tolerated with a warning by the verifier).
    Unknown(u32),
}

impl LoadCommandKind {
    /// Classifies a raw opcode.
    #[must_use]
    pub const fn from_cmd(cmd: u32) -> Self {
        // Weak/upward dylibs share the dylib layout; classify them together.
        let weak_or_upward =
            cmd == crate::consts::LC_LOAD_WEAK_DYLIB || cmd == crate::consts::LC_LOAD_UPWARD_DYLIB;
        match cmd {
            LC_SEGMENT_64 => Self::Segment64,
            LC_SYMTAB => Self::Symtab,
            LC_DYSYMTAB => Self::Dysymtab,
            LC_LOAD_DYLIB => Self::LoadDylib,
            LC_ID_DYLIB => Self::IdDylib,
            LC_LOAD_DYLINKER => Self::LoadDylinker,
            LC_MAIN => Self::Main,
            LC_BUILD_VERSION
            | crate::consts::LC_VERSION_MIN_MACOSX
            | crate::consts::LC_VERSION_MIN_TVOS
            | crate::consts::LC_VERSION_MIN_WATCHOS => Self::BuildVersion,
            LC_UUID => Self::Uuid,
            LC_RPATH => Self::Rpath,
            LC_SOURCE_VERSION => Self::SourceVersion,
            LC_CODE_SIGNATURE
            | LC_DYLD_CHAINED_FIXUPS
            | LC_DYLD_EXPORTS_TRIE
            | LC_FUNCTION_STARTS
            | LC_DATA_IN_CODE
            | crate::consts::LC_SEGMENT_SPLIT_INFO
            | crate::consts::LC_DYLD_INFO
            | crate::consts::LC_DYLD_INFO_ONLY => Self::LinkeditData(cmd),
            _ if weak_or_upward => Self::LoadDylib,
            _ => Self::Unknown(cmd),
        }
    }
}

/// Iterates the load-command region of an image.
#[derive(Debug, Clone, Copy)]
pub struct LoadCommandIter<'a> {
    region: &'a [u8],
    base: usize,
    pos: usize,
    remaining: u32,
}

impl<'a> LoadCommandIter<'a> {
    /// Opens the load-command region starting at `offset` with `ncmds`
    /// commands of total size `sizeofcmds`; the whole region must lie
    /// within `bytes`.
    pub fn new(
        bytes: &'a [u8],
        offset: usize,
        ncmds: u32,
        sizeofcmds: u32,
    ) -> Result<Self, FormatError> {
        let end = offset
            .checked_add(sizeofcmds as usize)
            .ok_or(FormatError::Invalid {
                offset,
                what: "sizeofcmds overflow",
                value: sizeofcmds as u64,
            })?;
        if end > bytes.len() {
            return Err(FormatError::Overrun {
                offset,
                overrun: end - bytes.len(),
            });
        }
        Ok(Self {
            region: &bytes[offset..end],
            base: offset,
            pos: 0,
            remaining: ncmds,
        })
    }

    /// Advances to the next command, validating its size fields.
    pub fn next_command(&mut self) -> Result<Option<ParsedCommand<'a>>, FormatError> {
        if self.remaining == 0 {
            if self.pos != self.region.len() {
                return Err(FormatError::Invalid {
                    offset: self.pos,
                    what: "load-command bytes left after ncmds commands (ncmds/sizeofcmds mismatch)",
                    value: (self.region.len() - self.pos) as u64,
                });
            }
            return Ok(None);
        }
        let here = self.pos;
        let mut c = Cursor::new(self.region);
        c.seek(here)?;
        let cmd = c.read_u32()?;
        let cmdsize = c.read_u32()?;
        if cmdsize < 8 {
            return Err(FormatError::Invalid {
                offset: here,
                what: "cmdsize smaller than the 8-byte command header",
                value: cmdsize as u64,
            });
        }
        if cmdsize % 8 != 0 {
            return Err(FormatError::Invalid {
                offset: here,
                what: "cmdsize not 8-byte aligned (64-bit Mach-O contract)",
                value: cmdsize as u64,
            });
        }
        let end = here + cmdsize as usize;
        if end > self.region.len() {
            return Err(FormatError::Overrun {
                offset: here,
                overrun: end - self.region.len(),
            });
        }
        self.pos = end;
        self.remaining -= 1;
        Ok(Some(ParsedCommand {
            // Absolute file offset (the iterator's caller always reasons
            // about the image, not the load-command region).
            offset: self.base + here,
            cmdsize: cmdsize as usize,
            kind: LoadCommandKind::from_cmd(cmd),
            bytes: &self.region[here..end],
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::LoadCommandKind;
    use crate::consts::{
        LC_BUILD_VERSION, LC_CODE_SIGNATURE, LC_DYLD_CHAINED_FIXUPS, LC_MAIN, LC_SEGMENT_64,
        LC_SYMTAB, LC_UUID,
    };

    fn push32(v: &mut Vec<u8>, x: u32) {
        v.extend_from_slice(&x.to_le_bytes());
    }

    /// Builds a load-command region of `ncmds` well-formed commands.
    fn region(ncmds: u32, cmdsize: u32, cmd: u32) -> Vec<u8> {
        let mut v = Vec::new();
        for _ in 0..ncmds {
            push32(&mut v, cmd);
            push32(&mut v, cmdsize);
            v.resize(v.len() + cmdsize as usize - 8, 0);
        }
        v
    }

    #[test]
    fn walks_exact_region() {
        let r = region(3, 16, LC_SEGMENT_64);
        let mut it = super::LoadCommandIter::new(&r, 0, 3, r.len() as u32).unwrap();
        let mut seen = 0;
        while let Some(c) = it.next_command().unwrap() {
            assert_eq!(c.cmdsize, 16);
            assert_eq!(c.kind, LoadCommandKind::Segment64);
            seen += 1;
        }
        assert_eq!(seen, 3);
    }

    #[test]
    fn rejects_cmdsize_misalignment_and_short() {
        // cmdsize = 12 (not 8-aligned): must error, not panic.
        let r = region(1, 12, LC_SEGMENT_64);
        let mut it = super::LoadCommandIter::new(&r, 0, 1, r.len() as u32).unwrap();
        assert!(it.next_command().is_err());

        // cmdsize = 4 < 8: must error.
        let r2 = region(1, 8, LC_SEGMENT_64);
        let mut bytes = r2.clone();
        bytes[4..8].copy_from_slice(&4u32.to_le_bytes());
        let mut it2 = super::LoadCommandIter::new(&bytes, 0, 1, bytes.len() as u32).unwrap();
        assert!(it2.next_command().is_err());
    }

    #[test]
    fn rejects_region_overrun() {
        // sizeofcmds larger than the buffer: the constructor must reject it.
        let r = region(1, 32, LC_UUID);
        assert!(super::LoadCommandIter::new(&r, 0, 1, 64).is_err());
        // A single command whose cmdsize overruns a valid region: iteration
        // must reject it.
        let r2 = region(1, 32, LC_UUID);
        let mut bytes = r2;
        bytes[4..8].copy_from_slice(&64u32.to_le_bytes()); // cmdsize 64 > region 32
        let mut it = super::LoadCommandIter::new(&bytes, 0, 1, bytes.len() as u32).unwrap();
        assert!(it.next_command().is_err());
    }

    #[test]
    fn rejects_trailing_bytes_after_ncmds() {
        let r = region(1, 16, LC_SYMTAB);
        let mut padded = r.clone();
        padded.extend_from_slice(&[0u8; 8]);
        let mut it = super::LoadCommandIter::new(&padded, 0, 1, padded.len() as u32).unwrap();
        assert!(it.next_command().unwrap().is_some());
        assert!(it.next_command().is_err());
    }

    #[test]
    fn classifies_opcodes() {
        assert_eq!(
            LoadCommandKind::from_cmd(LC_BUILD_VERSION),
            LoadCommandKind::BuildVersion
        );
        assert_eq!(
            LoadCommandKind::from_cmd(LC_DYLD_CHAINED_FIXUPS),
            LoadCommandKind::LinkeditData(LC_DYLD_CHAINED_FIXUPS)
        );
        assert_eq!(
            LoadCommandKind::from_cmd(LC_CODE_SIGNATURE),
            LoadCommandKind::LinkeditData(LC_CODE_SIGNATURE)
        );
        assert_eq!(LoadCommandKind::from_cmd(LC_MAIN), LoadCommandKind::Main);
        assert_eq!(
            LoadCommandKind::from_cmd(0xdead_beef),
            LoadCommandKind::Unknown(0xdead_beef)
        );
    }
}
