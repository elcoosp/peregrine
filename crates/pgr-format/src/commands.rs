//! Small load-command structures (dylibs, entry point, build version, UUID,
//! linkedit-data payloads, data-in-code).
//!
//! Every parser here reads from the *whole image* bytes with the command's
//! absolute offset, because embedded strings are addressed relative to the
//! command start (`lc_str` offsets).

use crate::cursor::{Cursor, pod_read_unaligned_at};
use crate::error::FormatError;

/// The 24-byte `dylib_command` head (`LC_LOAD_DYLIB` / `LC_ID_DYLIB`).
#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct DylibCommand {
    /// Command opcode.
    pub cmd: u32,
    /// Command size (includes the install-name string, 8-byte padded).
    pub cmdsize: u32,
    /// Offset of the install-name string from the command start.
    pub name_offset: u32,
    /// Timestamp (legacy, zero).
    pub timestamp: u32,
    /// Current version number.
    pub current_version: u32,
    /// Compatibility version number.
    pub compatibility_version: u32,
}

const _: () = assert!(core::mem::size_of::<DylibCommand>() == 24);

impl DylibCommand {
    /// Parses the command head from `cmd_bytes` (the command's slice).
    pub fn parse(cmd_bytes: &[u8]) -> Result<Self, FormatError> {
        pod_read_unaligned_at::<Self>(cmd_bytes, 0)
    }

    /// The install name (NUL-terminated string at `name_offset`).
    pub fn name<'a>(&self, cmd_bytes: &'a [u8]) -> Result<&'a [u8], FormatError> {
        read_lc_str(self.name_offset, self.cmdsize as usize, cmd_bytes)
    }
}

/// The 12-byte `dylinker_command` head (`LC_LOAD_DYLINKER`).
#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct DylinkerCommand {
    /// Command opcode.
    pub cmd: u32,
    /// Command size.
    pub cmdsize: u32,
    /// Offset of the linker path string from the command start.
    pub name_offset: u32,
}

const _: () = assert!(core::mem::size_of::<DylinkerCommand>() == 12);

impl DylinkerCommand {
    /// Parses the command head from `cmd_bytes`.
    pub fn parse(cmd_bytes: &[u8]) -> Result<Self, FormatError> {
        pod_read_unaligned_at::<Self>(cmd_bytes, 0)
    }

    /// The linker path string.
    pub fn name<'a>(&self, cmd_bytes: &'a [u8]) -> Result<&'a [u8], FormatError> {
        read_lc_str(self.name_offset, self.cmdsize as usize, cmd_bytes)
    }
}

/// The 24-byte `entry_point_command` (`LC_MAIN`).
#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct EntryPointCommand {
    /// Command opcode.
    pub cmd: u32,
    /// Command size, always 24.
    pub cmdsize: u32,
    /// Entry point offset within `__TEXT`.
    pub entryoff: u64,
    /// Initial stack size (usually 0; dyld defaults to the main-thread stack).
    pub stacksize: u64,
}

const _: () = assert!(core::mem::size_of::<EntryPointCommand>() == 24);

impl EntryPointCommand {
    /// Parses the command from `cmd_bytes`.
    pub fn parse(cmd_bytes: &[u8]) -> Result<Self, FormatError> {
        pod_read_unaligned_at::<Self>(cmd_bytes, 0)
    }
}

/// The 24-byte `build_version_command` head (`LC_BUILD_VERSION`).
#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct BuildVersionCommand {
    /// Command opcode.
    pub cmd: u32,
    /// Command size (includes `ntools` 8-byte tool entries).
    pub cmdsize: u32,
    /// `PLATFORM_*` value.
    pub platform: u32,
    /// Minimum OS version packed `XX.YY.ZZ` as `(x<<16)|(y<<8)|z`.
    pub minos: u32,
    /// SDK version packed the same way.
    pub sdk: u32,
    /// Number of 8-byte `build_tool_version` entries following.
    pub ntools: u32,
}

const _: () = assert!(core::mem::size_of::<BuildVersionCommand>() == 24);

impl BuildVersionCommand {
    /// Parses the command head from `cmd_bytes`.
    pub fn parse(cmd_bytes: &[u8]) -> Result<Self, FormatError> {
        pod_read_unaligned_at::<Self>(cmd_bytes, 0)
    }
}

/// One 8-byte `build_tool_version` entry.
#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct BuildToolVersion {
    /// `TOOL_*` value.
    pub tool: u32,
    /// Tool version packed `XX.YY.ZZ`.
    pub version: u32,
}

const _: () = assert!(core::mem::size_of::<BuildToolVersion>() == 8);

/// The 24-byte `uuid_command` (`LC_UUID`).
#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct UuidCommand {
    /// Command opcode.
    pub cmd: u32,
    /// Command size, always 24.
    pub cmdsize: u32,
    /// The 16 UUID bytes.
    pub uuid: [u8; 16],
}

const _: () = assert!(core::mem::size_of::<UuidCommand>() == 24);

impl UuidCommand {
    /// Parses the command from `cmd_bytes`.
    pub fn parse(cmd_bytes: &[u8]) -> Result<Self, FormatError> {
        pod_read_unaligned_at::<Self>(cmd_bytes, 0)
    }
}

/// The 16-byte `linkedit_data_command` (chained fixups, export trie,
/// function starts, data-in-code, code signature).
#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct LinkeditDataCommand {
    /// Command opcode.
    pub cmd: u32,
    /// Command size, always 16.
    pub cmdsize: u32,
    /// File offset of the payload.
    pub dataoff: u32,
    /// Payload size in bytes.
    pub datasize: u32,
}

const _: () = assert!(core::mem::size_of::<LinkeditDataCommand>() == 16);

impl LinkeditDataCommand {
    /// Parses the command from `cmd_bytes`.
    pub fn parse(cmd_bytes: &[u8]) -> Result<Self, FormatError> {
        pod_read_unaligned_at::<Self>(cmd_bytes, 0)
    }

    /// The payload slice, bounds-checked against the image.
    pub fn data<'a>(&self, image: &'a [u8]) -> Result<&'a [u8], FormatError> {
        let start = self.dataoff as usize;
        let end = start
            .checked_add(self.datasize as usize)
            .ok_or(FormatError::Invalid {
                offset: start,
                what: "linkedit payload size overflow",
                value: self.datasize as u64,
            })?;
        if end > image.len() {
            return Err(FormatError::Overrun {
                offset: start,
                overrun: end - image.len(),
            });
        }
        Ok(&image[start..end])
    }
}

/// The 16-byte `source_version_command`.
#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct SourceVersionCommand {
    /// Command opcode.
    pub cmd: u32,
    /// Command size, always 16.
    pub cmdsize: u32,
    /// Source version packed `A24.B10.C10.D10.E10`.
    pub version: u64,
}

const _: () = assert!(core::mem::size_of::<SourceVersionCommand>() == 16);

/// The 8-byte `data_in_code_entry`.
#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct DataInCodeEntry {
    /// Offset from the start of `__TEXT`.
    pub offset: u32,
    /// Number of bytes this entry covers.
    pub length: u16,
    /// `DICE_KIND_*` value.
    pub kind: u16,
}

const _: () = assert!(core::mem::size_of::<DataInCodeEntry>() == 8);

/// Reads an `lc_str`-addressed NUL-terminated string from a command's bytes:
/// `offset` counts from the command start and the string must lie within
/// `cmdsize`.
fn read_lc_str(offset: u32, cmdsize: usize, cmd_bytes: &[u8]) -> Result<&[u8], FormatError> {
    let start = offset as usize;
    if start == 0 || start >= cmdsize || start > cmd_bytes.len() {
        return Err(FormatError::Invalid {
            offset: start,
            what: "lc_str offset outside its load command",
            value: offset as u64,
        });
    }
    let mut c = Cursor::new(&cmd_bytes[..cmdsize.min(cmd_bytes.len())]);
    c.seek(start)?;
    let s = c.read_cstr()?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::{
        BuildVersionCommand, DylibCommand, DylinkerCommand, EntryPointCommand, LinkeditDataCommand,
        UuidCommand,
    };

    fn dylib_bytes() -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&crate::consts::LC_LOAD_DYLIB.to_le_bytes());
        v.extend_from_slice(&56u32.to_le_bytes());
        v.extend_from_slice(&24u32.to_le_bytes()); // name_offset
        v.extend_from_slice(&0u32.to_le_bytes()); // timestamp
        v.extend_from_slice(&0x0001_0000u32.to_le_bytes()); // current_version
        v.extend_from_slice(&0u32.to_le_bytes()); // compat
        v.extend_from_slice(b"/usr/lib/libSystem.B.dylib\0");
        while v.len() < 56 {
            v.push(0);
        }
        v
    }

    #[test]
    fn dylib_name_reads_lc_str() {
        let bytes = dylib_bytes();
        let d = DylibCommand::parse(&bytes).unwrap();
        assert_eq!(d.name(&bytes).unwrap(), b"/usr/lib/libSystem.B.dylib");
        assert_eq!(d.cmdsize, 56);
    }

    #[test]
    fn lc_str_out_of_bounds_rejected() {
        let bytes = dylib_bytes();
        let mut d = DylibCommand::parse(&bytes).unwrap();
        // Last command byte, made non-NUL so no terminator exists before
        // the cmdsize boundary.
        let mut no_tail = bytes.clone();
        no_tail[55] = 0xff;
        d.name_offset = 55;
        assert!(d.name(&no_tail).is_err());
        d.name_offset = 60; // beyond cmdsize
        assert!(d.name(&bytes).is_err());
        d.name_offset = 0; // offset 0 is not a valid lc_str
        assert!(d.name(&bytes).is_err());
    }

    #[test]
    fn small_commands_roundtrip() {
        let ep = EntryPointCommand {
            cmd: crate::consts::LC_MAIN,
            cmdsize: 24,
            entryoff: 0x1000,
            stacksize: 0,
        };
        let parsed = EntryPointCommand::parse(bytemuck::bytes_of(&ep)).unwrap();
        assert_eq!(parsed.entryoff, 0x1000);

        let bv = BuildVersionCommand {
            cmd: crate::consts::LC_BUILD_VERSION,
            cmdsize: 32,
            platform: crate::consts::PLATFORM_MACOS,
            minos: 0x000c_0000,
            sdk: 0x000e_0000,
            ntools: 1,
        };
        let parsed = BuildVersionCommand::parse(bytemuck::bytes_of(&bv)).unwrap();
        assert_eq!(parsed.platform, crate::consts::PLATFORM_MACOS);

        let uuid = UuidCommand {
            cmd: crate::consts::LC_UUID,
            cmdsize: 24,
            uuid: [7; 16],
        };
        let parsed = UuidCommand::parse(bytemuck::bytes_of(&uuid)).unwrap();
        assert_eq!(parsed.uuid, [7; 16]);

        let dl = DylinkerCommand {
            cmd: crate::consts::LC_LOAD_DYLINKER,
            cmdsize: 32,
            name_offset: 12,
        };
        let mut bytes = bytemuck::bytes_of(&dl).to_vec();
        bytes.extend_from_slice(b"/usr/lib/dyld\0");
        while bytes.len() < 32 {
            bytes.push(0);
        }
        let parsed = DylinkerCommand::parse(&bytes).unwrap();
        assert_eq!(parsed.name(&bytes).unwrap(), b"/usr/lib/dyld");

        let le = LinkeditDataCommand {
            cmd: crate::consts::LC_FUNCTION_STARTS,
            cmdsize: 16,
            dataoff: 0,
            datasize: 4,
        };
        let parsed = LinkeditDataCommand::parse(bytemuck::bytes_of(&le)).unwrap();
        assert!(parsed.data(&[0u8; 4]).is_ok());
        assert!(parsed.data(&[0u8; 2]).is_err());
        assert!(parsed.data(&[]).is_err());
    }
}
