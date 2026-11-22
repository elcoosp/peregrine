//! Symbol table structures: `LC_SYMTAB`, `LC_DYSYMTAB` and `nlist_64`.

use crate::consts::{
    N_EXT, N_SECT, N_STAB, N_TYPE, N_UNDF, N_WEAK_DEF, N_WEAK_REF, get_library_ordinal,
};
use crate::cursor::pod_read_unaligned_at;
use crate::error::FormatError;

/// The 24-byte `symtab_command`.
#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct SymtabCommand {
    /// `LC_SYMTAB`.
    pub cmd: u32,
    /// Command size, always 24.
    pub cmdsize: u32,
    /// File offset of the `nlist_64` array.
    pub symoff: u32,
    /// Number of symbol entries.
    pub nsyms: u32,
    /// File offset of the string table.
    pub stroff: u32,
    /// String table size in bytes.
    pub strsize: u32,
}

const _: () = assert!(core::mem::size_of::<SymtabCommand>() == 24);

/// The 80-byte `dysymtab_command`.
#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct DysymtabCommand {
    /// `LC_DYSYMTAB`.
    pub cmd: u32,
    /// Command size, always 80.
    pub cmdsize: u32,
    /// Index of first local symbol.
    pub ilocalsym: u32,
    /// Number of local symbols.
    pub nlocalsym: u32,
    /// Index of first external definition.
    pub iextdefsym: u32,
    /// Number of external definitions.
    pub nextdefsym: u32,
    /// Index of first undefined symbol.
    pub iundefsym: u32,
    /// Number of undefined symbols.
    pub nundefsym: u32,
    /// File offset of the table-of-contents (legacy, zero).
    pub tocoff: u32,
    /// Number of TOC entries (legacy, zero).
    pub ntoc: u32,
    /// File offset of the module table (legacy, zero).
    pub modtaboff: u32,
    /// Number of module table entries (legacy, zero).
    pub nmodtab: u32,
    /// File offset of external reference symbols (legacy, zero).
    pub extrefsymoff: u32,
    /// Number of external reference symbols (legacy, zero).
    pub nextrefsyms: u32,
    /// File offset of the indirect symbol table.
    pub indirectsymoff: u32,
    /// Number of indirect symbol entries.
    pub nindirectsyms: u32,
    /// File offset of external relocations (legacy, zero under fixups).
    pub extreloff: u32,
    /// Number of external relocations (legacy, zero under fixups).
    pub nextrel: u32,
    /// File offset of local relocations (legacy, zero under fixups).
    pub locreloff: u32,
    /// Number of local relocations (legacy, zero under fixups).
    pub nlocrel: u32,
}

const _: () = assert!(core::mem::size_of::<DysymtabCommand>() == 80);

/// The 56-byte `dylib_module_64` — one entry of the `LC_DYSYMTAB` module
/// table (`modtaboff`/`nmodtab`), Apple `<mach-o/loader.h>`'s 64-bit
/// dylib-module record. The module table is the legacy two-level-namespace
/// shape ld64's `-single_module`/`-multi_module` names: under
/// `-single_module` the dylib is one module (the whole image's locals and
/// extdefs ride one entry whose subranges mirror the `LC_DYSYMTAB`'s), and
/// the producer emits exactly one entry (M119). The field order matches the
/// Apple header verbatim (the 32-bit `dylib_module` is 52 bytes — the
/// 64-bit form widens the trailing `objc_module_info_addr` to `u64` and
/// swaps it after `objc_module_info_size`, the one order change the
/// 64-bit split carries).
#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct DylibModule64 {
    /// String-table offset of the module name (0 for a single-module
    /// dylib — the image has no per-module name).
    pub module_name: u32,
    /// Index of the module's first external definition (mirrors
    /// `LC_DYSYMTAB.iextdefsym` for a single-module dylib).
    pub iextdefsym: u32,
    /// Number of the module's external definitions (mirrors
    /// `LC_DYSYMTAB.nextdefsym`).
    pub nextdefsym: u32,
    /// Index of the module's first reference (legacy, zero under fixups).
    pub irefsym: u32,
    /// Number of the module's references (legacy, zero under fixups).
    pub nrefsym: u32,
    /// Index of the module's first local symbol (mirrors
    /// `LC_DYSYMTAB.ilocalsym`).
    pub ilocalsym: u32,
    /// Number of the module's local symbols (mirrors
    /// `LC_DYSYMTAB.nlocalsym`).
    pub nlocalsym: u32,
    /// Index of the module's first external relocation (legacy, zero).
    pub iextrel: u32,
    /// Number of the module's external relocations (legacy, zero).
    pub nextrel: u32,
    /// Packed index/count of the module's init/term entries (legacy, zero).
    pub iinit_iterm: u32,
    /// Packed count of the module's init/term entries (legacy, zero).
    pub ninit_nterm: u32,
    /// Byte size of the module's `ObjC` module info (legacy, zero).
    pub objc_module_info_size: u32,
    /// Address of the module's `ObjC` module info (legacy, zero).
    pub objc_module_info_addr: u64,
}

const _: () = assert!(core::mem::size_of::<DylibModule64>() == 56);

/// The 16-byte `nlist_64` entry (TDD §3.3).
#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct Nlist64 {
    /// String-table offset of the symbol name.
    pub n_strx: u32,
    /// Type bits: stab / external / `N_TYPE` value.
    pub n_type: u8,
    /// Defining section index (1-based within the file).
    pub n_sect: u8,
    /// Reference flags, library ordinal, weak bits.
    pub n_desc: u16,
    /// Symbol value (address, tentative size, or 0 for undefined).
    pub n_value: u64,
}

const _: () = assert!(core::mem::size_of::<Nlist64>() == 16);

impl SymtabCommand {
    /// Parses the command from its 24 bytes at `offset`.
    ///
    /// # Errors
    /// [`FormatError`] when the input structure is malformed or truncated.
    pub fn parse(bytes: &[u8], offset: usize) -> Result<Self, FormatError> {
        pod_read_unaligned_at::<Self>(bytes, offset)
    }
}

impl DysymtabCommand {
    /// Parses the command from its 80 bytes at `offset`.
    ///
    /// # Errors
    /// [`FormatError`] when the input structure is malformed or truncated.
    pub fn parse(bytes: &[u8], offset: usize) -> Result<Self, FormatError> {
        pod_read_unaligned_at::<Self>(bytes, offset)
    }

    /// Parses the `nindirectsyms` `u32` entries at `indirectsymoff`.
    ///
    /// # Errors
    /// [`FormatError`] when the input structure is malformed or truncated.
    pub fn indirect_symbols<'a>(&self, bytes: &'a [u8]) -> Result<&'a [u32], FormatError> {
        let total = self
            .nindirectsyms
            .checked_mul(4)
            .ok_or(FormatError::Invalid {
                offset: self.indirectsymoff as usize,
                what: "indirect symbol array size overflow",
                value: u64::from(self.nindirectsyms),
            })? as usize;
        let start = self.indirectsymoff as usize;
        let end = start.checked_add(total).ok_or(FormatError::Invalid {
            offset: start,
            what: "indirect symbol array end overflow",
            value: total as u64,
        })?;
        if end > bytes.len() {
            return Err(FormatError::Overrun {
                offset: start,
                overrun: end - bytes.len(),
            });
        }
        bytemuck::try_cast_slice(&bytes[start..end]).map_err(|e| match e {
            bytemuck::PodCastError::TargetAlignmentGreaterAndInputNotAligned => {
                FormatError::Unaligned {
                    offset: start,
                    align: core::mem::align_of::<u32>(),
                }
            }
            bytemuck::PodCastError::SizeMismatch => FormatError::Overrun {
                offset: start,
                overrun: 0,
            },
            _ => FormatError::Invalid {
                offset: start,
                what: "indirect symbol array cast failed",
                value: total as u64,
            },
        })
    }

    /// Parses the `nmodtab` [`DylibModule64`] entries at `modtaboff` (M119):
    /// the `LC_DYSYMTAB` module table ld64's `-single_module`/
    /// `-multi_module` names — one 56-byte entry under `-single_module`
    /// (the whole image as one module), zero entries under the default
    /// `-multi_module` (the legacy table peregrine never carried). The
    /// verifier's read-side backstop consults this on every output image
    /// regardless of how the table was produced.
    ///
    /// # Errors
    /// [`FormatError`] when the module table is truncated, misaligned, or
    /// its byte length is not a whole multiple of [`DylibModule64`]'s
    /// size.
    pub fn modules<'a>(&self, bytes: &'a [u8]) -> Result<&'a [DylibModule64], FormatError> {
        let total = self
            .nmodtab
            .checked_mul(core::mem::size_of::<DylibModule64>() as u32)
            .ok_or(FormatError::Invalid {
                offset: self.modtaboff as usize,
                what: "module table size overflow",
                value: u64::from(self.nmodtab),
            })? as usize;
        let start = self.modtaboff as usize;
        let end = start.checked_add(total).ok_or(FormatError::Invalid {
            offset: start,
            what: "module table end overflow",
            value: total as u64,
        })?;
        if end > bytes.len() {
            return Err(FormatError::Overrun {
                offset: start,
                overrun: end - bytes.len(),
            });
        }
        bytemuck::try_cast_slice(&bytes[start..end]).map_err(|e| match e {
            bytemuck::PodCastError::TargetAlignmentGreaterAndInputNotAligned => {
                FormatError::Unaligned {
                    offset: start,
                    align: core::mem::align_of::<DylibModule64>(),
                }
            }
            bytemuck::PodCastError::SizeMismatch => FormatError::Overrun {
                offset: start,
                overrun: 0,
            },
            _ => FormatError::Invalid {
                offset: start,
                what: "module table cast failed",
                value: total as u64,
            },
        })
    }
}

impl Nlist64 {
    /// True when the entry is a debug stabs entry.
    #[must_use]
    pub const fn is_stab(&self) -> bool {
        self.n_type & N_STAB != 0
    }

    /// True when the entry is external (`N_EXT`).
    #[must_use]
    pub const fn is_external(&self) -> bool {
        self.n_type & N_EXT != 0
    }

    /// True when the entry is defined in a section (`N_SECT | N_EXT`).
    #[must_use]
    pub const fn is_section_defined(&self) -> bool {
        self.n_type & N_TYPE == N_SECT
    }

    /// True when the entry is undefined (`N_UNDF`, excluding stabs).
    #[must_use]
    pub const fn is_undefined(&self) -> bool {
        !self.is_stab() && self.n_type & N_TYPE == N_UNDF
    }

    /// True when the entry is a tentative/common definition (`N_UNDF` with a
    /// nonzero size in `n_value` and an alignment exponent in `n_desc`).
    #[must_use]
    pub const fn is_tentative(&self) -> bool {
        self.is_undefined() && self.n_value != 0
    }

    /// The two-level namespace library ordinal carried in `n_desc`.
    #[must_use]
    pub const fn library_ordinal(&self) -> u16 {
        get_library_ordinal(self.n_desc)
    }

    /// True when the definition is weak (`N_WEAK_DEF`).
    #[must_use]
    pub const fn is_weak_def(&self) -> bool {
        self.n_desc & N_WEAK_DEF != 0
    }

    /// True when the reference is weak (`N_WEAK_REF`).
    #[must_use]
    pub const fn is_weak_ref(&self) -> bool {
        self.n_desc & N_WEAK_REF != 0
    }
}

#[cfg(test)]
mod tests {
    use super::{DysymtabCommand, Nlist64, SymtabCommand};
    use crate::consts::{
        BIND_SPECIAL_DYLIB_FLAT_LOOKUP, N_EXT, N_SECT, N_UNDF, REFERENCE_FLAG_UNDEFINED_NON_LAZY,
    };

    #[test]
    fn struct_sizes_match_the_format() {
        assert_eq!(core::mem::size_of::<SymtabCommand>(), 24);
        assert_eq!(core::mem::size_of::<DysymtabCommand>(), 80);
        assert_eq!(core::mem::size_of::<Nlist64>(), 16);
    }

    #[test]
    fn nlist_type_decoding() {
        let defined = Nlist64 {
            n_strx: 1,
            n_type: N_EXT | N_SECT,
            n_sect: 1,
            n_desc: 0,
            n_value: 0x1_0000_0000,
        };
        assert!(defined.is_external());
        assert!(defined.is_section_defined());
        assert!(!defined.is_undefined());
        assert!(!defined.is_stab());

        let undef = Nlist64 {
            n_strx: 2,
            n_type: N_EXT | N_UNDF,
            n_sect: 0,
            n_desc: (1 << 8) | REFERENCE_FLAG_UNDEFINED_NON_LAZY,
            n_value: 0,
        };
        assert!(undef.is_undefined());
        assert!(!undef.is_tentative());
        assert_eq!(undef.library_ordinal(), 1);

        let tentative = Nlist64 {
            n_strx: 3,
            n_type: N_EXT | N_UNDF,
            n_sect: 0,
            n_desc: 4 << 8, // common alignment exponent 4 in bits 8-11
            n_value: 64,
        };
        assert!(tentative.is_undefined());
        assert!(tentative.is_tentative());
        assert_eq!(crate::consts::get_comm_align(tentative.n_desc), 4);

        let flat = Nlist64 {
            n_desc: (BIND_SPECIAL_DYLIB_FLAT_LOOKUP << 8),
            n_value: 0,
            n_strx: 0,
            n_type: N_EXT | N_UNDF,
            n_sect: 0,
        };
        assert_eq!(flat.library_ordinal(), 0xfe);
    }

    #[test]
    fn weak_bits_decode() {
        let weak = Nlist64 {
            n_strx: 1,
            n_type: N_EXT | N_SECT,
            n_sect: 1,
            n_desc: crate::consts::N_WEAK_DEF,
            n_value: 8,
        };
        assert!(weak.is_weak_def());
        assert!(!weak.is_weak_ref());
    }

    #[test]
    fn indirect_symbols_bounds_checked() {
        let bytes = [0xffu8; 16];
        let mut dys = DysymtabCommand {
            cmd: crate::consts::LC_DYSYMTAB,
            cmdsize: 80,
            indirectsymoff: 0,
            nindirectsyms: 4,
            ilocalsym: 0,
            nlocalsym: 0,
            iextdefsym: 0,
            nextdefsym: 0,
            iundefsym: 0,
            nundefsym: 0,
            tocoff: 0,
            ntoc: 0,
            modtaboff: 0,
            nmodtab: 0,
            extrefsymoff: 0,
            nextrefsyms: 0,
            extreloff: 0,
            nextrel: 0,
            locreloff: 0,
            nlocrel: 0,
        };
        assert_eq!(dys.indirect_symbols(&bytes).unwrap().len(), 4);
        dys.nindirectsyms = 5;
        assert!(dys.indirect_symbols(&bytes).is_err());
    }

    #[test]
    fn symtab_parse_roundtrip() {
        let c = SymtabCommand {
            cmd: crate::consts::LC_SYMTAB,
            cmdsize: 24,
            symoff: 4096,
            nsyms: 12,
            stroff: 4096 + 192,
            strsize: 300,
        };
        let bytes = bytemuck::bytes_of(&c);
        let parsed = SymtabCommand::parse(bytes, 0).unwrap();
        assert_eq!(parsed.nsyms, 12);
        assert_eq!(parsed.strsize, 300);
    }
}
