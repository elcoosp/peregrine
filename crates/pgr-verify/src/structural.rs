//! Structural checks: header, load commands, the 16 KiB segment contract,
//! the symbol tables (with the object relocation contract) and the output
//! contracts — the dylib/bundle shape (M3) and the `MH_OBJECT` one (M10
//! rung 1).

use crate::{Code, Issue, Report, issue_from};
use pgr_format::LinkeditDataCommand;
use pgr_format::consts::{
    ARM64_RELOC_ADDEND, ARM64_RELOC_GOT_LOAD_PAGE21, ARM64_RELOC_GOT_LOAD_PAGEOFF12,
    ARM64_RELOC_PAGE21, ARM64_RELOC_PAGEOFF12, ARM64_RELOC_SUBTRACTOR, ARM64_RELOC_UNSIGNED,
    CPU_SUBTYPE_ARM64_ALL, CPU_TYPE_ARM64, LC_CODE_SIGNATURE, LC_DYLD_CHAINED_FIXUPS, LC_DYLD_INFO,
    LC_DYLD_INFO_ONLY, MH_BUNDLE, MH_DYLIB, MH_DYLINKER, MH_EXECUTE, MH_FILESET, MH_KEXT_BUNDLE,
    MH_OBJECT, MH_PRELOAD, PAGE_SIZE_16K, PAGEZERO_SIZE_64, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL,
    S_ZEROFILL, VM_PROT_EXECUTE, VM_PROT_NONE, VM_PROT_WRITE,
};
use pgr_format::header::MachHeader64;
use pgr_format::load_command::{LoadCommandIter, LoadCommandKind, ParsedCommand};
use pgr_format::reloc::RelocationInfo;
use pgr_format::segment::SegmentCommand64;
use pgr_format::symtab::{DysymtabCommand, Nlist64, SymtabCommand};

/// Everything the checks need, collected once in load-command order.
///
/// The parse pre-pass product shared by every family: the raw header, the
/// classified load commands, the segment/symbol/fixup payload anchors and
/// the aggregate counters. Public since M12 so the [`crate::ImageCheck`]
/// seam can carry it in its public context type.
pub struct ParsedImage<'a> {
    /// Parsed header.
    pub header: MachHeader64,
    /// Load commands in header order.
    pub commands: Vec<ParsedCommand<'a>>,
    /// `LC_SEGMENT_64` commands in header order (`__PAGEZERO` included).
    pub segments: Vec<SegmentCommand64>,
    /// Total number of sections.
    pub nsections: u32,
    /// `LC_SYMTAB` payload.
    pub symtab: Option<SymtabCommand>,
    /// `LC_DYSYMTAB` payload.
    pub dysymtab: Option<DysymtabCommand>,
    /// `LC_DYLD_CHAINED_FIXUPS` payload command.
    pub fixups: Option<LinkeditDataCommand>,
    /// M6: the classic `LC_DYLD_INFO(_ONLY)` command (legacy fallback).
    pub dyld_info: Option<pgr_format::DyldInfoCommand>,
    /// `LC_CODE_SIGNATURE` payload command.
    pub code_signature: Option<LinkeditDataCommand>,
    /// `LC_MAIN` payload command.
    pub main: Option<pgr_format::EntryPointCommand>,
    /// `LC_BUILD_VERSION` payload command.
    pub build_version: Option<pgr_format::BuildVersionCommand>,
    /// Dependent dylib install names (`LC_LOAD_DYLIB`,
    /// `LC_LOAD_WEAK_DYLIB`, `LC_LAZY_LOAD_DYLIB` and
    /// `LC_REEXPORT_DYLIB`, in ordinal order — the lazy command rides
    /// the two-level ordinal space like a plain load, M14).
    pub dylibs: Vec<String>,
    /// The `LC_ID_DYLIB` payload (dylibs only), when present.
    pub id_dylib: Option<pgr_format::DylibCommand>,
    /// Install names of `LC_REEXPORT_DYLIB` commands (M3 re-exports).
    pub reexport_dylibs: Vec<String>,
    /// Number of chained-fixup slots counted during the pre-pass walk.
    pub fixup_slot_count: u64,
    /// Total virtual span of the image (LINKEDIT vmaddr + vmsize).
    pub total_vmsize: u64,
}

/// Loads and pre-validates the image: any failure here is fatal for all
/// downstream checks.
///
/// Public since M12: the [`crate::ImageCheck`] seam's context carries the
/// parsed image, so external tooling can parse once and drive selected
/// families through `crate::verify_with_checks`.
///
/// # Errors
/// A single error-severity [`Issue`] (header or load-command malformed)
/// anchored at the first bad offset — the same issue the whole-image
/// report carries when the parse cannot proceed.
pub fn parse_image(bytes: &[u8]) -> Result<ParsedImage<'_>, Issue> {
    let header = MachHeader64::parse(bytes).map_err(|e| issue_from(&e, Code::HeaderInvalid))?;
    let mut commands = Vec::new();
    let mut segments = Vec::new();
    let mut nsections = 0u32;
    let mut symtab = None;
    let mut dysymtab = None;
    let mut fixups = None;
    let mut dyld_info = None;
    let mut code_signature = None;
    let mut main = None;
    let mut build_version = None;
    let mut dylibs = Vec::new();
    let mut id_dylib = None;
    let mut reexport_dylibs = Vec::new();
    let mut fixup_slot_count = 0u64;

    let mut it = LoadCommandIter::new(bytes, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .map_err(|e| issue_from(&e, Code::LoadCommandMalformed))?;
    while let Some(cmd) = it
        .next_command()
        .map_err(|e| issue_from(&e, Code::LoadCommandMalformed))?
    {
        commands.push(cmd);
        match cmd.kind {
            LoadCommandKind::Segment64 => {
                let seg = SegmentCommand64::parse(cmd.bytes, 0)
                    .map_err(|e| issue_from(&e, Code::LoadCommandMalformed))?;
                // Hostile headers can carry nsects near u32::MAX: saturate
                // instead of overflowing the counter (M7 fuzzing find).
                nsections = nsections.saturating_add(seg.nsects);
                segments.push(seg);
            }
            LoadCommandKind::Symtab => {
                if symtab.is_none() {
                    symtab = SymtabCommand::parse(cmd.bytes, 0).ok();
                }
            }
            LoadCommandKind::Dysymtab => {
                if dysymtab.is_none() {
                    dysymtab = DysymtabCommand::parse(cmd.bytes, 0).ok();
                }
            }
            LoadCommandKind::LinkeditData(pgr_format::consts::LC_DYLD_CHAINED_FIXUPS) => {
                if let Ok(lc) = LinkeditDataCommand::parse(cmd.bytes) {
                    fixup_slot_count = count_fixup_slots(bytes, &lc, segments.len());
                    fixups = Some(lc);
                }
            }
            LoadCommandKind::LinkeditData(op) if crate::dyld_info::is_dyld_info_cmd(op) => {
                if dyld_info.is_none() {
                    dyld_info = crate::dyld_info::parse_command(cmd.bytes, cmd.offset);
                }
            }
            LoadCommandKind::LinkeditData(pgr_format::consts::LC_CODE_SIGNATURE) => {
                if let Ok(lc) = LinkeditDataCommand::parse(cmd.bytes) {
                    code_signature = Some(lc);
                }
            }
            LoadCommandKind::Main => {
                if main.is_none() {
                    main = pgr_format::EntryPointCommand::parse(cmd.bytes).ok();
                }
            }
            LoadCommandKind::BuildVersion => {
                if build_version.is_none() {
                    build_version = pgr_format::BuildVersionCommand::parse(cmd.bytes).ok();
                }
            }
            LoadCommandKind::LoadDylib => {
                if let Ok(d) = pgr_format::DylibCommand::parse(cmd.bytes) {
                    if let Ok(name) = d.name(cmd.bytes) {
                        dylibs.push(String::from_utf8_lossy(name).into_owned());
                    }
                }
            }
            LoadCommandKind::ReexportDylib => {
                if let Ok(d) = pgr_format::DylibCommand::parse(cmd.bytes) {
                    if let Ok(name) = d.name(cmd.bytes) {
                        // Re-exports share the load-dylib ordinal space.
                        dylibs.push(String::from_utf8_lossy(name).into_owned());
                        reexport_dylibs.push(String::from_utf8_lossy(name).into_owned());
                    }
                }
            }
            LoadCommandKind::IdDylib if id_dylib.is_none() => {
                id_dylib = pgr_format::DylibCommand::parse(cmd.bytes).ok();
            }
            _ => {}
        }
    }

    let total_vmsize = segments
        .last()
        .map_or(0, |s| s.vmaddr.saturating_add(s.vmsize));

    Ok(ParsedImage {
        header,
        commands,
        segments,
        nsections,
        symtab,
        dysymtab,
        fixups,
        dyld_info,
        code_signature,
        main,
        build_version,
        dylibs,
        id_dylib,
        reexport_dylibs,
        fixup_slot_count,
        total_vmsize,
    })
}

/// Counts fixup slots cheaply (pre-pass) without validating: full validation
/// happens in [`crate::dynamic`]. Returns 0 when anything is malformed.
/// The canonical executable segment order (dyld's load order).
const CANONICAL: [&str; 5] = [
    "__PAGEZERO",
    "__TEXT",
    "__DATA_CONST",
    "__DATA",
    "__LINKEDIT",
];

fn count_fixup_slots(bytes: &[u8], lc: &LinkeditDataCommand, nsegments: usize) -> u64 {
    let Ok(payload) = lc.data(bytes) else {
        return 0;
    };
    let Ok(hdr) = pgr_format::fixups::parse_header(payload) else {
        return 0;
    };
    let Ok(starts) = pgr_format::fixups::parse_starts_in_image(payload, hdr.starts_offset as usize)
    else {
        return 0;
    };
    if starts.seg_info_offset.len() > nsegments.max(1) {
        return 0;
    }
    let mut total = 0u64;
    for (i, &off) in starts.seg_info_offset.iter().enumerate() {
        if off == 0 || i >= nsegments {
            continue;
        }
        let Ok(seg) = pgr_format::fixups::parse_starts_in_segment(
            payload,
            hdr.starts_offset as usize + off as usize,
        ) else {
            continue;
        };
        for p in 0..seg.page_count {
            if let Ok(heads) = pgr_format::fixups::page_chain_starts(
                payload,
                hdr.starts_offset as usize + off as usize,
                &seg,
                p,
            ) {
                // The stride the segment's `next` fields count (8-byte
                // units for the arm64e family, 4-byte for the 64 pair);
                // an unknown format counts nothing (best effort).
                let Some(stride) = pgr_format::fixups::chain_stride(seg.pointer_format) else {
                    continue;
                };
                let arm64e = seg.pointer_format == pgr_format::consts::DYLD_CHAINED_PTR_ARM64E;
                let page_base = match bytes.get(seg.segment_offset as usize..) {
                    Some(_) => seg.segment_offset,
                    None => continue,
                };
                for h in heads {
                    if h == pgr_format::consts::DYLD_CHAINED_PTR_START_NONE {
                        continue;
                    }
                    // Walk the chain, counting slots (best effort).
                    let mut slot_off = u64::from(h);
                    let mut guard = 0;
                    while guard < 100_000 {
                        guard += 1;
                        let at = page_base
                            .saturating_add(u64::from(p).saturating_mul(u64::from(seg.page_size)))
                            .saturating_add(slot_off);
                        let Some(word_bytes) =
                            bytes.get(at as usize..at.saturating_add(8) as usize)
                        else {
                            break;
                        };
                        let raw = u64::from_le_bytes(word_bytes.try_into().unwrap_or([0; 8]));
                        total += 1;
                        let next = if arm64e {
                            u64::from(pgr_format::fixups::ChainWordArm64e::new(raw).next())
                        } else {
                            u64::from(pgr_format::fixups::ChainWord64::new(raw).next())
                        };
                        if next == 0 {
                            break;
                        }
                        slot_off += next * stride;
                    }
                }
            }
        }
    }
    total
}

/// Header-level checks.
pub(crate) fn check_header(img: &ParsedImage<'_>, report: &mut Report) {
    let h = img.header;
    if h.cputype != CPU_TYPE_ARM64 {
        report.issues.push(Issue::error(
            Code::HeaderInvalid,
            format!("cputype {:#x} is not CPU_TYPE_ARM64", h.cputype),
            Some(4),
        ));
    }
    if h.cpusubtype & 0x00ff_ffff != CPU_SUBTYPE_ARM64_ALL {
        report.issues.push(Issue::warning(
            Code::HeaderInvalid,
            format!("unexpected cpusubtype {:#x}", h.cpusubtype),
            Some(8),
        ));
    }
    if h.reserved != 0 {
        report.issues.push(Issue::error(
            Code::HeaderInvalid,
            "mach_header_64.reserved must be zero",
            Some(28),
        ));
    }
    if h.sizeofcmds == 0 && h.ncmds > 0 {
        report.issues.push(Issue::error(
            Code::HeaderInvalid,
            "ncmds > 0 but sizeofcmds == 0",
            Some(20),
        ));
    }
    if MachHeader64::SIZE + h.sizeofcmds as usize > PAGE_SIZE_16K as usize {
        report.issues.push(Issue::error(
            Code::HeaderInvalid,
            "header and load commands must fit the first 16 KiB page",
            Some(20),
        ));
    }
    let known = [
        MH_OBJECT,
        MH_EXECUTE,
        MH_DYLIB,
        MH_DYLINKER,
        MH_BUNDLE,
        MH_KEXT_BUNDLE,
        MH_PRELOAD,
        MH_FILESET,
    ];
    if !known.contains(&h.filetype) {
        report.issues.push(Issue::warning(
            Code::HeaderInvalid,
            format!("unusual filetype {:#x}", h.filetype),
            Some(12),
        ));
    }
}

/// Load-command region checks beyond what the iterator already rejects.
pub(crate) fn check_load_commands(img: &ParsedImage<'_>, report: &mut Report) {
    for cmd in &img.commands {
        if let LoadCommandKind::Unknown(op) = cmd.kind {
            // Unknown commands are tolerated (forward compatibility), but
            // LC_REQ_DYLD ones would make dyld reject the image.
            if op & pgr_format::consts::LC_REQ_DYLD != 0 {
                report.issues.push(Issue::error(
                    Code::LoadCommandMalformed,
                    format!("unknown load command {op:#x} carries LC_REQ_DYLD (dyld rejects it)"),
                    Some(cmd.offset as u64),
                ));
            } else {
                report.issues.push(Issue::warning(
                    Code::Suspicious,
                    format!("unknown load command {op:#x}"),
                    Some(cmd.offset as u64),
                ));
            }
        }
    }
    // Chained fixups and classic dyld info must not coexist.
    let has_classic = img.commands.iter().any(|c| {
        matches!(
            c.kind,
            LoadCommandKind::LinkeditData(pgr_format::consts::LC_DYLD_INFO_ONLY)
        )
    });
    if has_classic && img.fixups.is_some() {
        report.issues.push(Issue::error(
            Code::LoadCommandMalformed,
            "LC_DYLD_INFO_ONLY and LC_DYLD_CHAINED_FIXUPS must not coexist",
            None,
        ));
    }
    if let Some(st) = &img.symtab {
        if st.cmdsize != 24 {
            report.issues.push(Issue::error(
                Code::LoadCommandMalformed,
                "LC_SYMTAB cmdsize must be 24",
                None,
            ));
        }
    }
    check_umbrella_region(img, report);
    check_dyld_environment(img, report);
    check_load_dylinker(img, report);
}

/// The M22 dyld-environment contract: `LC_DYLD_ENVIRONMENT` is the
/// loader-configuration command dyld reads from the main executable —
/// each command carries one `DYLD_<var>=<value>` pair at the fixed
/// `lc_str` offset (the `dylinker_command` struct, the `LC_RPATH`
/// shape). The invariants the fixture knob can break are named: a
/// command off an executable is inert there (dyld reads it from the
/// main executable only — a warning), a variable dyld would ignore
/// (not `DYLD_`-prefixed), an empty variable (past the prefix), a pair
/// missing its `=`, a duplicate variable (dyld keeps its first
/// encounter — the loser would be a silently dropped decision), a
/// stray `lc_str` offset (the fixed part is 12 bytes), an undersized
/// command, and an unterminated pair.
fn check_dyld_environment(img: &ParsedImage<'_>, report: &mut Report) {
    const ENV_FIXED_PART: u32 = 12; // cmd + cmdsize + lc_str offset
    let is_object = img.header.filetype == MH_OBJECT;
    let is_exec = img.header.filetype == MH_EXECUTE;
    let mut seen: Vec<String> = Vec::new();
    for cmd in &img.commands {
        if cmd.kind != LoadCommandKind::DyldEnvironment {
            continue;
        }
        if is_object {
            report.issues.push(Issue::error(
                Code::LinkeditPayload,
                "LC_DYLD_ENVIRONMENT is a loader command — a relocatable object carries \
                 no loader to reach (dyld reads it from the main executable only)",
                Some(cmd.offset as u64),
            ));
            continue;
        }
        if !is_exec {
            report.issues.push(Issue::warning(
                Code::LinkeditPayload,
                "LC_DYLD_ENVIRONMENT rides a non-executable image — dyld reads the \
                 command from the main executable only, so it is inert here",
                Some(cmd.offset as u64),
            ));
        }
        if cmd.cmdsize < ENV_FIXED_PART as usize + 4 {
            report.issues.push(Issue::error(
                Code::LoadCommandMalformed,
                format!(
                    "LC_DYLD_ENVIRONMENT cmdsize {} is under the 12-byte fixed part plus \
                     one pair byte",
                    cmd.cmdsize
                ),
                Some(cmd.offset as u64),
            ));
            continue;
        }
        let raw = &cmd.bytes;
        let off = u32::from_le_bytes(
            raw[8..12]
                .try_into()
                .expect("the offset field rides byte 8"),
        );
        if off != ENV_FIXED_PART {
            report.issues.push(Issue::error(
                Code::LoadCommandMalformed,
                format!(
                    "LC_DYLD_ENVIRONMENT lc_str offset {off} must be 12 (the fixed part \
                     is cmd, cmdsize, offset)"
                ),
                Some(cmd.offset as u64),
            ));
            continue;
        }
        // The pair: a NUL-terminated C string inside the command, with
        // room for the terminator.
        let tail = &raw[ENV_FIXED_PART as usize..cmd.cmdsize];
        let Some(end) = tail.iter().position(|&b| b == 0) else {
            report.issues.push(Issue::error(
                Code::LoadCommandMalformed,
                "LC_DYLD_ENVIRONMENT pair is not NUL-terminated inside the command",
                Some(cmd.offset as u64),
            ));
            continue;
        };
        let pair = String::from_utf8_lossy(&tail[..end]).into_owned();
        let Some((var, _value)) = pair.split_once('=') else {
            report.issues.push(Issue::error(
                Code::LoadCommandMalformed,
                format!(
                    "LC_DYLD_ENVIRONMENT pair {pair:?} carries no = separator — the \
                     grammar is DYLD_<var>=<value>"
                ),
                Some(cmd.offset as u64),
            ));
            continue;
        };
        let Some(name) = var.strip_prefix("DYLD_") else {
            report.issues.push(Issue::error(
                Code::LoadCommandMalformed,
                format!(
                    "LC_DYLD_ENVIRONMENT variable {var:?} is not DYLD_-prefixed — dyld \
                     honors DYLD_* variables from this command only, so the pair would \
                     be silently dropped"
                ),
                Some(cmd.offset as u64),
            ));
            continue;
        };
        if name.is_empty() {
            report.issues.push(Issue::error(
                Code::LoadCommandMalformed,
                "LC_DYLD_ENVIRONMENT variable is empty past the DYLD_ prefix — name the \
                 variable the loader exports (e.g. DYLD_PRINT_LIBRARIES=1)",
                Some(cmd.offset as u64),
            ));
            continue;
        }
        if seen.iter().any(|s| s == var) {
            report.issues.push(Issue::error(
                Code::LoadCommandMalformed,
                format!(
                    "duplicate LC_DYLD_ENVIRONMENT variable {var:?}: dyld keeps its first \
                     encounter, so the loser is a silently dropped decision"
                ),
                Some(cmd.offset as u64),
            ));
            continue;
        }
        seen.push(var.to_string());
    }
}

/// The M26 loader-path contract: `LC_LOAD_DYLINKER` is the command the
/// kernel execs as the image's dynamic loader, so a configured
/// executable verifies strict exactly like the `/usr/lib/dyld` default.
/// The invariants the fixture knob can break are named: a command off
/// an executable (a relocatable object carries no loader — an error; a
/// dylib or a bundle is loaded by the kernel itself, so the command is
/// inert there — a warning), a second loader command on one image (the
/// kernel execs one loader — the loser would be a silently dropped
/// decision), an empty name (no loader), a relative path (the kernel
/// resolves the loader path from the process root at exec time — exec
/// would refuse before dyld ever runs), a stray `lc_str` offset (the
/// fixed part is 12 bytes), an undersized command, and an unterminated
/// name.
fn check_load_dylinker(img: &ParsedImage<'_>, report: &mut Report) {
    const LOADER_FIXED_PART: u32 = 12; // cmd + cmdsize + lc_str offset
    let is_object = img.header.filetype == MH_OBJECT;
    let is_exec = img.header.filetype == MH_EXECUTE;
    let mut seen = 0usize;
    for cmd in &img.commands {
        if cmd.kind != LoadCommandKind::LoadDylinker {
            continue;
        }
        if is_object {
            report.issues.push(Issue::error(
                Code::LinkeditPayload,
                "LC_LOAD_DYLINKER is a loader command — a relocatable object carries \
                 no loader to exec (the kernel reads it from the main executable only)",
                Some(cmd.offset as u64),
            ));
            continue;
        }
        if !is_exec {
            report.issues.push(Issue::warning(
                Code::LinkeditPayload,
                "LC_LOAD_DYLINKER rides a non-executable image — the kernel loads a \
                 dylib or a bundle itself, so the command is inert here",
                Some(cmd.offset as u64),
            ));
        }
        seen += 1;
        if seen > 1 {
            report.issues.push(Issue::error(
                Code::LoadCommandMalformed,
                format!(
                    "duplicate LC_LOAD_DYLINKER: the kernel execs one loader, so the \
                     second command is a silently dropped decision ({seen} commands seen)"
                ),
                Some(cmd.offset as u64),
            ));
        }
        if cmd.cmdsize < LOADER_FIXED_PART as usize + 2 {
            report.issues.push(Issue::error(
                Code::LoadCommandMalformed,
                format!(
                    "LC_LOAD_DYLINKER cmdsize {} is under the 12-byte fixed part plus \
                     a path and its terminator",
                    cmd.cmdsize
                ),
                Some(cmd.offset as u64),
            ));
            continue;
        }
        let raw = &cmd.bytes;
        let off = u32::from_le_bytes(
            raw[8..12]
                .try_into()
                .expect("the offset field rides byte 8"),
        );
        if off != LOADER_FIXED_PART {
            report.issues.push(Issue::error(
                Code::LoadCommandMalformed,
                format!(
                    "LC_LOAD_DYLINKER lc_str offset {off} must be 12 (the fixed part \
                     is cmd, cmdsize, offset)"
                ),
                Some(cmd.offset as u64),
            ));
            continue;
        }
        // The path: a NUL-terminated C string inside the command, with
        // room for the terminator.
        let tail = &raw[LOADER_FIXED_PART as usize..cmd.cmdsize];
        let Some(end) = tail.iter().position(|&b| b == 0) else {
            report.issues.push(Issue::error(
                Code::LoadCommandMalformed,
                "LC_LOAD_DYLINKER path is not NUL-terminated inside the command",
                Some(cmd.offset as u64),
            ));
            continue;
        };
        let path = String::from_utf8_lossy(&tail[..end]).into_owned();
        if path.is_empty() {
            report.issues.push(Issue::error(
                Code::LoadCommandMalformed,
                "LC_LOAD_DYLINKER names no loader — the command would exec nothing; \
                 name an absolute path (e.g. /usr/lib/dyld)",
                Some(cmd.offset as u64),
            ));
            continue;
        }
        if !path.starts_with('/') {
            report.issues.push(Issue::error(
                Code::LoadCommandMalformed,
                format!(
                    "LC_LOAD_DYLINKER path {path:?} is not absolute — the kernel \
                     resolves the loader path from the process root at exec time, so \
                     exec would refuse before dyld ever runs"
                ),
                Some(cmd.offset as u64),
            ));
        }
    }
}

/// The M20 umbrella-region contract, widened by M21 to the whole
/// identity-block sub-command family:
/// `LC_SUB_UMBRELLA`/`LC_SUB_LIBRARY`/`LC_SUB_CLIENT` are a dylib's
/// identity block, and each command carries one name at the fixed
/// `lc_str` offset. The invariants the fixture knob can break are
/// named: a sub command off a dylib (an executable's identity is
/// `LC_MAIN` + `LC_LOAD_DYLINKER`, a bundle dlopens without one), an
/// empty name (a typo, not a member or a client), a stray `lc_str`
/// offset (the fixed part is 12 bytes), an undersized command, and a
/// duplicate (the region names a member once — the same name under both
/// member kinds is still one member — and the client list names a
/// client once; the two namespaces are independent).
fn check_umbrella_region(img: &ParsedImage<'_>, report: &mut Report) {
    const SUB_FIXED_PART: u32 = 12; // cmd + cmdsize + lc_str offset
    let is_dylib = img.header.filetype == MH_DYLIB;
    let mut seen: Vec<String> = Vec::new();
    let mut seen_clients: Vec<String> = Vec::new();
    for cmd in &img.commands {
        let (opcode, name, is_client) = match cmd.kind {
            LoadCommandKind::SubUmbrella => (
                pgr_format::consts::LC_SUB_UMBRELLA,
                "LC_SUB_UMBRELLA",
                false,
            ),
            LoadCommandKind::SubLibrary => {
                (pgr_format::consts::LC_SUB_LIBRARY, "LC_SUB_LIBRARY", false)
            }
            LoadCommandKind::SubClient => {
                (pgr_format::consts::LC_SUB_CLIENT, "LC_SUB_CLIENT", true)
            }
            _ => continue,
        };
        if !is_dylib {
            report.issues.push(Issue::error(
                Code::LinkeditPayload,
                format!(
                    "{name} is only valid in dylibs (the sub commands ride LC_ID_DYLIB's \
                     identity block); this image carries filetype {:#x}",
                    img.header.filetype
                ),
                Some(cmd.offset as u64),
            ));
            continue;
        }
        if cmd.cmdsize < SUB_FIXED_PART as usize + 4 {
            report.issues.push(Issue::error(
                Code::LoadCommandMalformed,
                format!(
                    "{name} cmdsize {} is under the 12-byte fixed part plus one name byte",
                    cmd.cmdsize
                ),
                Some(cmd.offset as u64),
            ));
            continue;
        }
        let raw = &cmd.bytes;
        let off = u32::from_le_bytes(
            raw[8..12]
                .try_into()
                .expect("the offset field rides byte 8"),
        );
        if off != SUB_FIXED_PART {
            report.issues.push(Issue::error(
                Code::LoadCommandMalformed,
                format!(
                    "{name} lc_str offset {off} must be 12 (the fixed part is cmd, cmdsize, \
                     offset)",
                ),
                Some(cmd.offset as u64),
            ));
            continue;
        }
        // The name: a NUL-terminated C string inside the command, with
        // room for the terminator.
        let tail = &raw[SUB_FIXED_PART as usize..cmd.cmdsize];
        let Some(end) = tail.iter().position(|&b| b == 0) else {
            report.issues.push(Issue::error(
                Code::LoadCommandMalformed,
                format!("{name} member name is not NUL-terminated inside the command"),
                Some(cmd.offset as u64),
            ));
            continue;
        };
        let member = String::from_utf8_lossy(&tail[..end]).into_owned();
        if member.is_empty() {
            let (noun, example) = if is_client {
                ("client name", "-sub_client client.app")
            } else {
                ("member name", "-sub_umbrella MySub.framework")
            };
            report.issues.push(Issue::error(
                Code::LoadCommandMalformed,
                format!(
                    "{name} {noun} is empty — name the entry's install-name string \
                     (e.g. {example})"
                ),
                Some(cmd.offset as u64),
            ));
            continue;
        }
        let family = if is_client {
            &mut seen_clients
        } else {
            &mut seen
        };
        if family.iter().any(|s| s == &member) {
            let noun = if is_client {
                "sub_client"
            } else {
                "umbrella member"
            };
            report.issues.push(Issue::error(
                Code::LoadCommandMalformed,
                format!(
                    "duplicate {noun} {member:?}: the identity block names an entry once \
                     (opcode {opcode:#x})"
                ),
                Some(cmd.offset as u64),
            ));
            continue;
        }
        family.push(member);
    }
}

/// The M3 dylib/bundle contract: `LC_ID_DYLIB` presence per file type,
/// header flag sanity and install-name version ordering.
pub(crate) fn check_dylib_contract(img: &ParsedImage<'_>, report: &mut Report) {
    let n_id = img
        .commands
        .iter()
        .filter(|c| c.kind == LoadCommandKind::IdDylib)
        .count();
    match img.header.filetype {
        MH_DYLIB => {
            if n_id == 0 {
                report.issues.push(Issue::error(
                    Code::LoadCommandMalformed,
                    "dylibs require exactly one LC_ID_DYLIB (the install name)",
                    None,
                ));
            } else if n_id > 1 {
                report.issues.push(Issue::error(
                    Code::LoadCommandMalformed,
                    format!("dylib carries {n_id} LC_ID_DYLIB commands (exactly one allowed)"),
                    None,
                ));
            }
            if img.header.flags & pgr_format::consts::MH_PIE != 0 {
                report.issues.push(Issue::warning(
                    Code::HeaderInvalid,
                    "MH_PIE is only meaningful for executables",
                    Some(24),
                ));
            }
            if let Some(id) = &img.id_dylib {
                if id.current_version < id.compatibility_version {
                    report.issues.push(Issue::warning(
                        Code::LinkeditPayload,
                        format!(
                            "LC_ID_DYLIB current_version {:#x} < compatibility_version {:#x}",
                            id.current_version, id.compatibility_version
                        ),
                        None,
                    ));
                }
            }
            // Re-exported trie entries need LC_REEXPORT_DYLIB commands; the
            // pair check validates the names against the trie.
            if img.reexport_dylibs.is_empty()
                && img.header.flags & pgr_format::consts::MH_NO_REEXPORTED_DYLIBS == 0
            {
                // ld64 sets MH_NO_REEXPORTED_DYLIBS on dylibs without
                // re-exports; missing it is only a convention deviation.
                report.issues.push(Issue::warning(
                    Code::Suspicious,
                    "dylib without re-exports does not set MH_NO_REEXPORTED_DYLIBS",
                    Some(24),
                ));
            }
        }
        MH_BUNDLE => {
            if n_id > 0 {
                report.issues.push(Issue::error(
                    Code::LoadCommandMalformed,
                    "LC_ID_DYLIB is only valid in dylibs (bundles are dlopen-able objects)",
                    None,
                ));
            }
            if img.header.flags & pgr_format::consts::MH_PIE != 0 {
                report.issues.push(Issue::warning(
                    Code::HeaderInvalid,
                    "MH_PIE is only meaningful for executables",
                    Some(24),
                ));
            }
        }
        _ => {}
    }
}

/// The segment contract (TDD §3.6, §8; alignment diagram):
/// 16 KiB congruence, `vmaddr = fileoff + delta`, canonical ordering,
/// protections and file-coverage invariants.
pub(crate) fn check_segments(bytes: &[u8], img: &ParsedImage<'_>, report: &mut Report) {
    let exec = img.header.filetype == MH_EXECUTE;
    // Relocatable objects carry the LLVM single-segment convention: one
    // anonymous segment, blob-relative addresses, zero `filesize` — the
    // image-shaped invariants below do not apply (M10 rung 1; the object
    // contract lives in [`check_object_contract`]).
    let object = img.header.filetype == MH_OBJECT;
    let file_len = bytes.len() as u64;

    // Canonical ordering: __PAGEZERO (exec), __TEXT, __DATA_CONST, __DATA,
    // __LINKEDIT-last among named segments. ld64-compatible images may omit
    // empty segments, so the check is a canonical *subsequence* order (M1's
    // own output carries all five; the emit-side tests assert that).
    let names: Vec<&str> = img.segments.iter().filter_map(|s| s.name().ok()).collect();
    if exec {
        if names.first() != Some(&"__PAGEZERO") {
            report.issues.push(Issue::error(
                Code::SegmentLayout,
                "executables must start with __PAGEZERO",
                None,
            ));
        }
        // The present segments must appear in canonical relative order.
        let mut next = 0usize;
        let mut ordered = true;
        for name in &names {
            if let Some(pos) = CANONICAL.iter().position(|c| c == name) {
                if pos < next {
                    ordered = false;
                    break;
                }
                next = pos + 1;
            }
            // Non-canonical segment names are tolerated (unknown segments).
        }
        if !ordered {
            report.issues.push(Issue::error(
                Code::SegmentLayout,
                format!("executable segments {names:?} violate the canonical order {CANONICAL:?}"),
                None,
            ));
        }
    }
    if !object && !names.contains(&"__LINKEDIT") {
        report.issues.push(Issue::error(
            Code::SegmentLayout,
            "no __LINKEDIT segment",
            None,
        ));
    }

    // __PAGEZERO / __TEXT base contract (M15: the base is the image's
    // own `__PAGEZERO` vmsize — the invariant is verified, not the 4 GiB
    // constant every pre-M15 image carried; `-pagezero_size` names a
    // different base and the default stays bit-identical).
    let pagezero_vmsize = if exec {
        match img.segments.first() {
            Some(pz) if pz.name() == Ok("__PAGEZERO") => {
                if pz.vmaddr != 0 {
                    report.issues.push(Issue::error(
                        Code::ImageBase,
                        format!(
                            "__PAGEZERO.vmaddr must be 0 (the unmapped prefix), got {:#x}",
                            pz.vmaddr
                        ),
                        None,
                    ));
                }
                if pz.fileoff != 0 || pz.filesize != 0 {
                    report.issues.push(Issue::error(
                        Code::ImageBase,
                        "__PAGEZERO must not occupy file bytes",
                        None,
                    ));
                }
                if pz.vmsize == 0 || pz.vmsize % PAGE_SIZE_16K != 0 {
                    report.issues.push(Issue::error(
                        Code::ImageBase,
                        format!(
                            "__PAGEZERO vmsize {:#x} must be a non-zero multiple of the \
                             16 KiB arm64 page (the constant-delta base moves with it)",
                            pz.vmsize
                        ),
                        None,
                    ));
                }
                pz.vmsize
            }
            // The canonical-order gate already named the missing
            // segment; the delta check falls back to the historical
            // constant so the findings do not cascade.
            _ => PAGEZERO_SIZE_64,
        }
    } else {
        0
    };
    if exec {
        if let Some(text) = img.segments.iter().find(|s| s.name() == Ok("__TEXT")) {
            if text.vmaddr != pagezero_vmsize || text.fileoff != 0 {
                report.issues.push(Issue::error(
                    Code::ImageBase,
                    format!(
                        "__TEXT must start at the __PAGEZERO vmsize {:#x} with fileoff 0 \
                         (vmaddr {:#x}, fileoff {:#x})",
                        pagezero_vmsize, text.vmaddr, text.fileoff
                    ),
                    None,
                ));
            }
        }
    } else if let Some(text) = img.segments.iter().find(|s| s.name() == Ok("__TEXT")) {
        // M19: the constant-delta base is the image's own __TEXT delta —
        // the M3 zero default or a named `-image_base` (any 16 KiB
        // multiple; the per-segment contract below holds every segment
        // to it). The old constant check (`vmaddr == fileoff`) would
        // refuse exactly the shape the M19 knob exists to plan.
        let base = text.vmaddr.wrapping_sub(text.fileoff);
        if base % PAGE_SIZE_16K != 0 {
            report.issues.push(Issue::error(
                Code::ImageBase,
                format!(
                    "dylib __TEXT vmaddr {:#x} - fileoff {:#x} must differ by a \
                     multiple of the 16 KiB arm64 page (the constant-delta base \
                     moves with it)",
                    text.vmaddr, text.fileoff
                ),
                None,
            ));
        }
    }

    // Per-segment contract.
    let mut prev_end: Option<(u64, u64)> = None; // (fileoff_end, vmaddr_end)
    for seg in &img.segments {
        let name = seg.name().unwrap_or("<non-utf8>");
        if name == "__PAGEZERO" {
            // The protection half of the unmapped-prefix contract (M17):
            // `__PAGEZERO` is never mapped, so it carries no protections
            // — a fixture that names a pair there is refused, the same
            // way the base contract names a moved `__PAGEZERO`.
            if seg.maxprot != VM_PROT_NONE || seg.initprot != VM_PROT_NONE {
                report.issues.push(Issue::error(
                    Code::SegmentContract,
                    format!(
                        "__PAGEZERO must not carry protections (maxprot {:#x}, initprot \
                         {:#x}) — the unmapped prefix loads with none",
                        seg.maxprot, seg.initprot
                    ),
                    None,
                ));
            }
            continue;
        }
        // Congruence: vmaddr ≡ fileoff (mod 16 KiB). Mutated inputs can
        // carry vmaddr < fileoff, so the subtraction must be total.
        if seg.filesize > 0 && seg.vmaddr.wrapping_sub(seg.fileoff) % PAGE_SIZE_16K != 0 {
            report.issues.push(Issue::error(
                Code::SegmentContract,
                format!(
                    "segment {name}: vmaddr {:#x} and fileoff {:#x} differ by a non-multiple of 16 KiB",
                    seg.vmaddr, seg.fileoff
                ),
                None,
            ));
        }
        // Delta consistency: vmaddr - fileoff must equal the image delta
        // (base = the image's own __PAGEZERO vmsize for exec — M15
        // generalized from the 4 GiB constant; the image's own __TEXT
        // delta otherwise — M19: the M3 zero default or a named
        // `-image_base`). Objects carry the blob-relative convention
        // instead (vmaddr 0, fileoff = header end) — skipped, the
        // object contract checks the sections.
        let delta = if exec {
            pagezero_vmsize
        } else {
            img.segments
                .iter()
                .find(|s| s.name() == Ok("__TEXT"))
                .map_or(0, |s| s.vmaddr.wrapping_sub(s.fileoff))
        };
        if !object && seg.vmaddr.checked_sub(delta) != Some(seg.fileoff) {
            report.issues.push(Issue::error(
                Code::SegmentContract,
                format!(
                    "segment {name}: vmaddr {:#x} - fileoff {:#x} != {delta:#x} (constant-delta contract)",
                    seg.vmaddr, seg.fileoff
                ),
                None,
            ));
        }
        // File bounds.
        if seg.fileoff.saturating_add(seg.filesize) > file_len {
            report.issues.push(Issue::error(
                Code::SegmentContract,
                format!(
                    "segment {name}: file range [{:#x}, {:#x}) exceeds file size {:#x}",
                    seg.fileoff,
                    seg.fileoff.saturating_add(seg.filesize),
                    file_len
                ),
                Some(seg.fileoff),
            ));
        }
        if seg.vmsize < seg.filesize {
            report.issues.push(Issue::error(
                Code::SegmentContract,
                format!(
                    "segment {name}: vmsize {:#x} < filesize {:#x}",
                    seg.vmsize, seg.filesize
                ),
                None,
            ));
        }
        // Protections.
        if seg.initprot & !seg.maxprot != 0 {
            report.issues.push(Issue::error(
                Code::SegmentContract,
                format!("segment {name}: initprot has bits outside maxprot"),
                None,
            ));
        }
        // The W^X contract (M17): an initial mapping is never writable
        // and executable — arm64 macOS kills the process at exec time.
        // A writable+executable *ceiling* stays legal (maxprot is what
        // mprotect may raise to, not what the kernel maps).
        if seg.initprot & (VM_PROT_WRITE | VM_PROT_EXECUTE) == (VM_PROT_WRITE | VM_PROT_EXECUTE) {
            report.issues.push(Issue::error(
                Code::SegmentContract,
                format!(
                    "segment {name} maps writable and executable (initprot {:#x}) — \
                     arm64 macOS refuses a W+X mapping",
                    seg.initprot
                ),
                None,
            ));
        }
        if name == "__TEXT" && seg.initprot & VM_PROT_EXECUTE == 0 {
            report.issues.push(Issue::error(
                Code::SegmentContract,
                "__TEXT must be executable",
                None,
            ));
        }
        if name == "__DATA" || name == "__DATA_CONST" {
            if seg.initprot & VM_PROT_WRITE == 0 && name == "__DATA" {
                report.issues.push(Issue::warning(
                    Code::SegmentContract,
                    "__DATA is usually writable",
                    None,
                ));
            }
            if seg.initprot & VM_PROT_EXECUTE != 0 {
                report.issues.push(Issue::error(
                    Code::SegmentContract,
                    format!("segment {name} must not be executable"),
                    None,
                ));
            }
        }
        // Ordering / overlap (file layout must move forward).
        if let Some((pf, pv)) = prev_end {
            if seg.fileoff < pf {
                report.issues.push(Issue::error(
                    Code::SegmentLayout,
                    format!(
                        "segment {name} fileoff {:#x} overlaps the previous segment's end {:#x}",
                        seg.fileoff, pf
                    ),
                    Some(seg.fileoff),
                ));
            }
            if seg.vmaddr < pv {
                report.issues.push(Issue::error(
                    Code::SegmentLayout,
                    format!(
                        "segment {name} vmaddr {:#x} overlaps the previous segment's end {:#x}",
                        seg.vmaddr, pv
                    ),
                    Some(seg.vmaddr),
                ));
            }
        }
        prev_end = Some((
            seg.fileoff.saturating_add(seg.filesize),
            seg.vmaddr.saturating_add(seg.vmsize),
        ));

        // __LINKEDIT carries no sections.
        if name == "__LINKEDIT" && seg.nsects != 0 {
            report.issues.push(Issue::error(
                Code::SegmentLayout,
                "__LINKEDIT must not carry sections",
                None,
            ));
        }

        // Sections within the segment.
        let cmd_off = section_table_offset(img, seg);
        if let Ok(sects) = seg.sections(bytes, cmd_off) {
            for s in sects {
                let sname = s.name().unwrap_or("<non-utf8>");
                let zerofill = s.section_type() == S_ZEROFILL
                    || s.section_type() == S_GB_ZEROFILL
                    || s.section_type() == S_THREAD_LOCAL_ZEROFILL;
                if !zerofill {
                    if s.addr.saturating_add(s.size) > seg.vmaddr.saturating_add(seg.vmsize) {
                        report.issues.push(Issue::error(
                            Code::SectionBounds,
                            format!("section {sname}: vm range exceeds its segment"),
                            Some(s.addr),
                        ));
                    }
                    if u64::from(s.offset.saturating_add(s.size as u32)) > file_len
                        || (!object
                            && u64::from(s.offset) >= seg.fileoff.saturating_add(seg.filesize))
                    {
                        report.issues.push(Issue::error(
                            Code::SectionBounds,
                            format!("section {sname}: file range exceeds the segment or file"),
                            Some(u64::from(s.offset)),
                        ));
                    }
                }
                if s.align > 14 {
                    report.issues.push(Issue::error(
                        Code::SectionBounds,
                        format!("section {sname}: alignment exponent {} > 14", s.align),
                        Some(s.addr),
                    ));
                }
                if s.reserved3 != 0 {
                    report.issues.push(Issue::warning(
                        Code::Suspicious,
                        format!("section {sname}: reserved3 is set"),
                        Some(s.addr),
                    ));
                }
            }
        }
    }

    // __LINKEDIT covers through EOF.
    if let Some(le) = img.segments.iter().find(|s| s.name() == Ok("__LINKEDIT")) {
        if le.fileoff.saturating_add(le.filesize) != file_len {
            report.issues.push(Issue::error(
                Code::SegmentLayout,
                format!(
                    "__LINKEDIT must extend to EOF (ends {:#x}, file size {:#x})",
                    le.fileoff.saturating_add(le.filesize),
                    file_len
                ),
                Some(le.fileoff),
            ));
        }
    }
}

/// The relocatable-object contract (M10 rung 1, `-r`): `MH_OBJECT` is
/// neither loaded nor signed — fixup payloads, classic dyld-info streams
/// and signatures have no voice there — and every relocation entry must
/// name something the file actually carries: the section it rides in,
/// the symbol table entry (or 1-based section ordinal) it points at, and
/// the `ADDEND`/`SUBTRACTOR` pair shape the input decoder consumes.
pub(crate) fn check_object_contract(bytes: &[u8], img: &ParsedImage<'_>, report: &mut Report) {
    let file_len = bytes.len() as u64;
    for cmd in &img.commands {
        let banned = match cmd.kind {
            LoadCommandKind::LinkeditData(LC_DYLD_CHAINED_FIXUPS) => "LC_DYLD_CHAINED_FIXUPS",
            LoadCommandKind::LinkeditData(LC_DYLD_INFO_ONLY | LC_DYLD_INFO) => "LC_DYLD_INFO",
            LoadCommandKind::LinkeditData(LC_CODE_SIGNATURE) => "LC_CODE_SIGNATURE",
            _ => continue,
        };
        report.issues.push(Issue::error(
            Code::LoadCommandMalformed,
            format!("{banned} on an MH_OBJECT: relocatable objects are neither loaded nor signed"),
            Some(cmd.offset as u64),
        ));
    }
    let nsyms = img.symtab.map_or(0, |st| st.nsyms);
    let nsects = img.nsections as usize;
    for seg in &img.segments {
        let cmd_off = section_table_offset(img, seg);
        let Ok(sects) = seg.sections(bytes, cmd_off) else {
            continue;
        };
        for s in sects {
            let sname = s.name().unwrap_or("<non-utf8>");
            if s.nreloc == 0 {
                continue;
            }
            if u64::from(s.reloff.saturating_add(s.nreloc.saturating_mul(8))) > file_len {
                report.issues.push(Issue::error(
                    Code::SymbolTable,
                    format!("section {sname}: relocation table extends past EOF"),
                    Some(u64::from(s.reloff)),
                ));
                continue;
            }
            let mut i = 0u32;
            while i < s.nreloc {
                let at = s.reloff as usize + i as usize * 8;
                let Ok(r) = RelocationInfo::parse(bytes, at) else {
                    report.issues.push(Issue::error(
                        Code::SymbolTable,
                        format!("section {sname}: relocation entry {i} is truncated"),
                        Some(u64::from(s.reloff) + u64::from(i) * 8),
                    ));
                    break;
                };
                if r.is_scattered() {
                    report.issues.push(Issue::error(
                        Code::SymbolTable,
                        format!("section {sname}: relocation entry {i} is scattered (not generated by modern clang)"),
                        Some(at as u64),
                    ));
                    break;
                }
                let sym = r.symbolnum();
                if r.is_extern() {
                    if sym >= nsyms {
                        report.issues.push(Issue::error(
                            Code::SymbolTable,
                            format!(
                                "section {sname}: relocation entry {i} names symbol {sym} past the symbol table ({nsyms} entries)"
                            ),
                            Some(at as u64),
                        ));
                        break;
                    }
                } else if r.rtype() != ARM64_RELOC_ADDEND && (sym == 0 || sym as usize > nsects) {
                    report.issues.push(Issue::error(
                        Code::SymbolTable,
                        format!(
                            "section {sname}: relocation entry {i} names section ordinal {sym} past the section table ({nsects} sections)"
                        ),
                        Some(at as u64),
                    ));
                    break;
                }
                // Pair shape: a leader entry owns the next one.
                let paired = match r.rtype() {
                    ARM64_RELOC_ADDEND => Some("an ADDEND"),
                    ARM64_RELOC_SUBTRACTOR => Some("a SUBTRACTOR"),
                    _ => None,
                };
                if let Some(leader) = paired {
                    let Some(next) = s.nreloc.checked_sub(i + 1).filter(|rest| *rest > 0) else {
                        report.issues.push(Issue::error(
                            Code::SymbolTable,
                            format!(
                                "section {sname}: {leader} relocation is not followed by its target"
                            ),
                            Some(at as u64),
                        ));
                        break;
                    };
                    let _ = next;
                    let Ok(r2) = RelocationInfo::parse(bytes, at + 8) else {
                        report.issues.push(Issue::error(
                            Code::SymbolTable,
                            format!("section {sname}: {leader} relocation's target is truncated"),
                            Some((at + 8) as u64),
                        ));
                        break;
                    };
                    let ok = match r.rtype() {
                        ARM64_RELOC_ADDEND => matches!(
                            r2.rtype(),
                            ARM64_RELOC_PAGE21
                                | ARM64_RELOC_PAGEOFF12
                                | ARM64_RELOC_GOT_LOAD_PAGE21
                                | ARM64_RELOC_GOT_LOAD_PAGEOFF12
                        ),
                        _ => r2.rtype() == ARM64_RELOC_UNSIGNED && r2.length_log2() == 3,
                    };
                    if !ok {
                        report.issues.push(Issue::error(
                            Code::SymbolTable,
                            format!("section {sname}: {leader} relocation's pair target has the wrong type"),
                            Some((at + 8) as u64),
                        ));
                        break;
                    }
                    i += 2;
                    continue;
                }
                i += 1;
            }
        }
    }
}

/// Finds the byte offset of a segment's section table within the image by
/// re-scanning load commands (kept simple and allocation-light).
pub(crate) fn section_table_offset(img: &ParsedImage<'_>, seg: &SegmentCommand64) -> usize {
    for cmd in &img.commands {
        if cmd.kind == LoadCommandKind::Segment64 {
            if let Ok(candidate) = SegmentCommand64::parse(cmd.bytes, 0) {
                if candidate.vmaddr == seg.vmaddr && candidate.fileoff == seg.fileoff {
                    return cmd.offset + SegmentCommand64::SIZE;
                }
            }
        }
    }
    0
}

/// Symbol-table and indirect-symbol checks.
pub(crate) fn check_symbol_table(bytes: &[u8], img: &ParsedImage<'_>, report: &mut Report) {
    let file_len = bytes.len() as u64;
    let Some(st) = img.symtab else {
        if img.header.filetype != MH_OBJECT {
            report.issues.push(Issue::warning(
                Code::SymbolTable,
                "no LC_SYMTAB (stripped image?)",
                None,
            ));
        }
        return;
    };
    if u64::from(st.symoff) + u64::from(st.nsyms) * 16 > file_len {
        report.issues.push(Issue::error(
            Code::SymbolTable,
            "symbol table extends past EOF",
            Some(u64::from(st.symoff)),
        ));
        return;
    }
    if u64::from(st.stroff) + u64::from(st.strsize) > file_len {
        report.issues.push(Issue::error(
            Code::SymbolTable,
            "string table extends past EOF",
            Some(u64::from(st.stroff)),
        ));
        return;
    }
    // The last string-table byte should be NUL (ld64 contract).
    if st.strsize > 0 && bytes[st.stroff as usize + st.strsize as usize - 1] != 0 {
        report.issues.push(Issue::warning(
            Code::SymbolTable,
            "string table does not end with NUL",
            Some(u64::from(st.stroff) + u64::from(st.strsize)),
        ));
    }

    for i in 0..st.nsyms {
        let off = st.symoff as usize + i as usize * 16;
        let sym: Nlist64 = match pgr_format::cursor::pod_read_unaligned_at(bytes, off) {
            Ok(s) => s,
            Err(e) => {
                report.issues.push(issue_from(&e, Code::SymbolTable));
                return;
            }
        };
        if sym.is_stab() {
            continue;
        }
        if u64::from(sym.n_strx) >= u64::from(st.strsize) && st.strsize > 0 {
            report.issues.push(Issue::error(
                Code::SymbolTable,
                format!(
                    "symbol {i}: string offset {} beyond strtab {}",
                    sym.n_strx, st.strsize
                ),
                Some(off as u64),
            ));
        }
        if sym.is_undefined() {
            let ordinal = sym.library_ordinal();
            let special = matches!(ordinal, 0 | 0xfd | 0xfe | 0xff);
            if !special && ordinal as usize > img.dylibs.len() {
                report.issues.push(Issue::error(
                    Code::SymbolTable,
                    format!(
                        "symbol {i}: library ordinal {} exceeds the {} LC_LOAD_DYLIB commands",
                        ordinal,
                        img.dylibs.len()
                    ),
                    Some(off as u64),
                ));
            }
            if sym.is_external() && sym.n_value == 0 {
                // true undefined; fine
            } else if sym.is_tentative() {
                let align = pgr_format::consts::get_comm_align(sym.n_desc);
                if align > 15 {
                    report.issues.push(Issue::error(
                        Code::SymbolTable,
                        format!("symbol {i}: common alignment exponent {align} > 15"),
                        Some(off as u64),
                    ));
                }
            }
        } else if sym.is_section_defined()
            && (sym.n_sect == 0 || u32::from(sym.n_sect) > img.nsections)
        {
            report.issues.push(Issue::error(
                Code::SymbolTable,
                format!(
                    "symbol {i}: defining section {} outside 1..={}",
                    sym.n_sect, img.nsections
                ),
                Some(off as u64),
            ));
        }
    }

    // The M24 alias surface's image contract: the defined-external
    // subrange carries one row per name. ld64's `-alias` adds rows, and
    // a stray or hand-built duplicate silently shadows — dyld and the
    // debuggers read the first row, so the second is a different symbol
    // wearing the same name. Locals and undefined externals may repeat
    // (two files' static labels; duplicate references), only *defined*
    // externals wear the one-name contract.
    {
        let mut seen: std::collections::BTreeMap<&[u8], u32> = std::collections::BTreeMap::new();
        for i in 0..st.nsyms {
            let off = st.symoff as usize + i as usize * 16;
            let sym: Nlist64 = match pgr_format::cursor::pod_read_unaligned_at(bytes, off) {
                Ok(s) => s,
                Err(e) => {
                    report.issues.push(issue_from(&e, Code::SymbolTable));
                    return;
                }
            };
            if sym.is_stab() || !sym.is_external() || !sym.is_section_defined() {
                continue;
            }
            let str_at = st.stroff as usize + sym.n_strx as usize;
            let str_end = st.stroff as usize + st.strsize as usize;
            let Some(name) = bytes
                .get(str_at..str_end)
                .and_then(|tail| {
                    let end = tail.iter().position(|&b| b == 0)?;
                    Some(&tail[..end])
                })
                .filter(|n| !n.is_empty())
            else {
                continue; // the strtab bounds and NUL checks carry the findings
            };
            if let Some(first) = seen.get(name) {
                report.issues.push(Issue::error(
                    Code::SymbolTable,
                    format!(
                        "symbol {i}: duplicate defined-external name \"{}\" — \
                         one symtab row per name (first row at symbol {first}); \
                         the duplicate silently shadows",
                        String::from_utf8_lossy(name)
                    ),
                    Some(off as u64),
                ));
            } else {
                seen.insert(name, i);
            }
        }
    }

    if let Some(dys) = img.dysymtab {
        // Indirect symbol bounds.
        if dys.nindirectsyms > 0 {
            match dys.indirect_symbols(bytes) {
                Ok(entries) => {
                    for (i, &e) in entries.iter().enumerate() {
                        if e == pgr_format::consts::INDIRECT_SYMBOL_LOCAL
                            || e == pgr_format::consts::INDIRECT_SYMBOL_ABS
                        {
                            continue;
                        }
                        if e >= st.nsyms {
                            report.issues.push(Issue::error(
                                Code::SymbolTable,
                                format!("indirect symbol {i}: index {e} beyond nsyms {}", st.nsyms),
                                Some(u64::from(dys.indirectsymoff) + i as u64 * 4),
                            ));
                        }
                    }
                }
                Err(e) => {
                    report.issues.push(issue_from(&e, Code::SymbolTable));
                }
            }
        }
        // Sub-range sanity.
        let ranges = [
            (dys.ilocalsym, dys.nlocalsym),
            (dys.iextdefsym, dys.nextdefsym),
            (dys.iundefsym, dys.nundefsym),
        ];
        for (start, count) in ranges {
            if u64::from(start) + u64::from(count) > u64::from(st.nsyms) {
                report.issues.push(Issue::error(
                    Code::SymbolTable,
                    "dysymtab sub-range exceeds the symbol table",
                    None,
                ));
            }
        }
    }
}
