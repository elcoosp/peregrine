//! M10 rung 4, slice 2 — the arm64e producer rides the driver surface:
//! `-fixup_chains_format` names the chain word family the Pass-3 planner
//! encodes (the read side has accepted both families since slice 1).
//!
//! The gates: the flag parses in both ld64 spellings (attached and
//! separated), refuses unknown values with the vocabulary in the hint,
//! refuses the combinations that cannot carry the requested family (the
//! classic opcode path has no chain words, the resident session's reuse
//! gates and wire plan Offset64 shapes this slice, and `-r` objects carry
//! no fixups at all), and the end-to-end arm64e link verifies strict —
//! the verifier's dyld walk re-reads the produced words and finds them
//! well-formed — with byte-determinism and an unchanged Offset64 default.

use pgr_core::fixups::FixupPointerFormat;
use pgr_driver::opts::{parse, Options};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_format::consts::{
    DYLD_CHAINED_PTR_ARM64E, DYLD_CHAINED_PTR_64_OFFSET, LC_DYLD_CHAINED_FIXUPS,
};
use pgr_format::fixups::{parse_header, parse_starts_in_image, ChainWordArm64e, ChainWord64};
use pgr_format::{
    LoadCommandIter, LoadCommandKind, MachHeader64, SegmentCommand64,
};
use std::ffi::OsString;

fn args(list: &[&str]) -> Vec<OsString> {
    list.iter().map(OsString::from).collect()
}

fn scratch(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m10_arm64e").join(format!(
        "{tag}_{}_{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A libSystem-shaped `.tbd` (v4) exporting the printf surface.
fn libsystem_tbd() -> &'static str {
    "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: /usr/lib/libSystem.B.dylib\ncurrent-version: 1.2.3\ncompatibility-version: 1.0.0\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ _printf, _strlen ]\n...\n"
}

/// A self-contained `main.o` with one rebase slot (`__data`) and one
/// GOT bind (`_printf` via the tbd): both fixup kinds ride the link.
fn printf_main() -> Vec<u8> {
    let text: Vec<u8> = [
        0x9000_0000u32, // adrp x0, _printf@GOTPAGE
        0xF940_0000u32, // ldr x0, [x0, _printf@GOTPAGEOFF]
        0x9400_0000u32, // bl _printf
        0xD65F_03C0u32, // ret
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect();
    let mut b = ObjectBuilder::new("printf_main.o");
    let sect = b.add_section(ObjectSection::text("__text", text, Vec::new()));
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    let main_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    let printf_sym = b.add_symbol(ObjectSymbol::Undefined {
        name: "_printf".into(),
        weak_ref: false,
    });
    let main = b.sym_index(main_sym);
    let printf = b.sym_index(printf_sym);
    b.section_mut(sect).relocs = vec![
        ObjectReloc::got_page21(printf).at(0),
        ObjectReloc::got_pageoff12(printf).at(4),
        ObjectReloc::branch26(printf).at(8),
    ];
    // An UNSIGNED pointer against a *defined* symbol: a pure rebase slot
    // in __data (the bind rides the GOT relocs above).
    b.section_mut(data)
        .relocs
        .push(ObjectReloc::unsigned(main).at(0));
    b.build().unwrap()
}

/// Writes the inputs into `dir` and parses the arm64e option set.
fn parsed_opts(dir: &std::path::Path, extra: &[&str]) -> Options {
    let obj = dir.join("printf_main.o");
    std::fs::write(&obj, printf_main()).unwrap();
    let tbd = dir.join("libSystem.tbd");
    std::fs::write(&tbd, libsystem_tbd()).unwrap();
    let mut argv = vec![
        "-o".to_string(),
        dir.join("exe").display().to_string(),
        "-fixup_chains_format".to_string(),
        "arm64e".to_string(),
    ];
    argv.extend(extra.iter().map(|s| s.to_string()));
    argv.push(obj.display().to_string());
    argv.push(tbd.display().to_string());
    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    let mut opts = parse(&argv).expect("the arm64e flag set parses");
    opts.config.ident = "peregrine-m10-arm64e".into();
    opts
}

/// The output of one full link run (the bytes `run` writes to `-o`).
fn link(opts: &Options) -> Vec<u8> {
    pgr_driver::run(opts).expect("the link completes");
    std::fs::read(&opts.output).unwrap()
}

/// Finds one output section by (segment, section) name:
/// `(vmaddr, file offset, size)`.
fn find_section(image: &[u8], seg_name: &str, sect_name: &str) -> Option<(u64, u64, usize)> {
    let header = MachHeader64::parse(image).unwrap();
    let mut it =
        LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds).unwrap();
    while let Some(cmd) = it.next_command().unwrap() {
        if let LoadCommandKind::Segment64 = cmd.kind {
            let seg = SegmentCommand64::parse(cmd.bytes, 0).unwrap();
            if seg.name().unwrap() != seg_name {
                continue;
            }
            let sects = seg.sections(cmd.bytes, SegmentCommand64::SIZE).unwrap();
            for s in sects {
                if s.name().unwrap() == sect_name {
                    return Some((s.addr, u64::from(s.offset), s.size as usize));
                }
            }
        }
    }
    None
}

/// The `__chain_starts` mirror bytes, if the image carries one.
fn chain_starts_mirror(image: &[u8]) -> Option<Vec<u8>> {
    let header = MachHeader64::parse(image).unwrap();
    let mut it =
        LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds).unwrap();
    while let Some(cmd) = it.next_command().unwrap() {
        if let LoadCommandKind::Segment64 = cmd.kind {
            let seg = SegmentCommand64::parse(cmd.bytes, 0).unwrap();
            let sects = seg.sections(cmd.bytes, SegmentCommand64::SIZE).unwrap();
            for s in sects {
                if s.name().unwrap() == "__chain_starts" {
                    let at = s.offset as usize;
                    return Some(image[at..at + s.size as usize].to_vec());
                }
            }
        }
    }
    None
}

/// True when the image carries `LC_DYLD_CHAINED_FIXUPS`.
fn has_chained_fixups(image: &[u8]) -> bool {
    let header = MachHeader64::parse(image).unwrap();
    let mut it =
        LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds).unwrap();
    while let Some(cmd) = it.next_command().unwrap() {
        if cmd.kind == LoadCommandKind::LinkeditData(LC_DYLD_CHAINED_FIXUPS) {
            return true;
        }
    }
    false
}

fn assert_strict_clean(image: &[u8], what: &str) {
    let report = pgr_verify::verify(
        image,
        &pgr_verify::Options {
            strict_warnings: true,
            skip_hash_recompute: false,
        },
    );
    let errors: Vec<_> = report
        .issues
        .iter()
        .filter(|i| i.severity == pgr_verify::Severity::Error)
        .collect();
    assert!(errors.is_empty(), "{what} must verify strict: {errors:?}");
}

// ---- the flag surface -------------------------------------------------------

#[test]
fn the_flag_accepts_both_word_families_in_both_spellings() {
    let dir = scratch("parse");
    let obj = dir.join("printf_main.o");
    std::fs::write(&obj, printf_main()).unwrap();
    for (value, expected) in [
        ("arm64e", FixupPointerFormat::Arm64e),
        ("offset64", FixupPointerFormat::Offset64),
    ] {
        let attached = parse(&args(&[
            "-o",
            "out",
            &format!("-fixup_chains_format={value}"),
            obj.to_str().unwrap(),
        ]))
        .unwrap_or_else(|e| panic!("attached form must parse: {e}"));
        assert_eq!(attached.config.chain_word_format, expected, "attached {value}");
        let separated = parse(&args(&[
            "-o",
            "out",
            "-fixup_chains_format",
            value,
            obj.to_str().unwrap(),
        ]))
        .unwrap_or_else(|e| panic!("separated form must parse: {e}"));
        assert_eq!(separated.config.chain_word_format, expected, "separated {value}");
    }
    let default = parse(&args(&["-o", "out", obj.to_str().unwrap()])).unwrap();
    assert_eq!(
        default.config.chain_word_format,
        FixupPointerFormat::Offset64,
        "the default stays the M2 family (§7.2)"
    );
}

#[test]
fn an_unknown_word_family_refuses_with_the_vocabulary() {
    let dir = scratch("bad_value");
    let obj = dir.join("printf_main.o");
    std::fs::write(&obj, printf_main()).unwrap();
    let err = parse(&args(&[
        "-o",
        "out",
        "-fixup_chains_format",
        "arm64",
        obj.to_str().unwrap(),
    ]))
    .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("offset64"), "the refusal names the default: {msg}");
    assert!(msg.contains("arm64e"), "the refusal names the arm64e family: {msg}");
}

#[test]
fn arm64e_refuses_the_classic_opcode_path() {
    let dir = scratch("no_chains");
    let obj = dir.join("printf_main.o");
    std::fs::write(&obj, printf_main()).unwrap();
    let err = parse(&args(&[
        "-o",
        "out",
        "-fixup_chains_format",
        "arm64e",
        "-no_fixup_chains",
        obj.to_str().unwrap(),
    ]))
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("classic opcode"),
        "the refusal names the shape conflict: {msg}"
    );
}

#[test]
fn arm64e_refuses_the_resident_session() {
    let dir = scratch("resident");
    let obj = dir.join("printf_main.o");
    std::fs::write(&obj, printf_main()).unwrap();
    let err = parse(&args(&[
        "-o",
        "out",
        "-fixup_chains_format",
        "arm64e",
        "-resident",
        obj.to_str().unwrap(),
    ]))
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("resident"),
        "the refusal names the gated session: {msg}"
    );
}

#[test]
fn arm64e_refuses_the_relocatable_output() {
    let dir = scratch("reloc");
    let obj = dir.join("printf_main.o");
    std::fs::write(&obj, printf_main()).unwrap();
    let err = parse(&args(&[
        "-o",
        "out.o",
        "-r",
        "-fixup_chains_format",
        "arm64e",
        obj.to_str().unwrap(),
    ]))
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("-r"),
        "the refusal names the output kind: {msg}"
    );
}

// ---- the end-to-end producer gates -----------------------------------------

#[test]
fn an_arm64e_link_verifies_strict_and_names_format_one() {
    let dir = scratch("e2e");
    let opts = parsed_opts(&dir, &[]);
    let image = link(&opts);
    assert!(has_chained_fixups(&image), "the chained payload is present");
    assert_strict_clean(&image, "the arm64e image");

    // The mirror names pointer format 1.
    let mirror = chain_starts_mirror(&image).expect("__chain_starts present");
    assert_eq!(
        u32::from_le_bytes(mirror[0..4].try_into().unwrap()),
        u32::from(DYLD_CHAINED_PTR_ARM64E),
        "the static mirror names the arm64e family"
    );

    // The __data rebase slot carries the VM address (format-1 semantics):
    // the slot targets _main, whose output vaddr is __text's.
    let (text_addr, _text_off, _text_size) =
        find_section(&image, "__TEXT", "__text").expect("__text present");
    let (_data_addr, data_off, _size) =
        find_section(&image, "__DATA", "__data").expect("__data present");
    let raw = u64::from_le_bytes(image[data_off as usize..data_off as usize + 8].try_into().unwrap());
    let word = ChainWordArm64e::new(raw);
    assert!(
        !word.is_bind() && !word.is_auth(),
        "the __data slot is an unauth rebase"
    );
    assert_eq!(
        word.rebase_target(),
        text_addr,
        "the word carries the target's VM address"
    );

    // The __got bind slot carries the import ordinal.
    let (got_addr, got_off, _size) =
        find_section(&image, "__DATA_CONST", "__got").expect("__got present");
    let raw = u64::from_le_bytes(image[got_off as usize..got_off as usize + 8].try_into().unwrap());
    let word = ChainWordArm64e::new(raw);
    assert!(word.is_bind(), "the __got slot is a bind");
    assert!(!word.is_auth(), "plain binds stay unauth");
    assert_eq!(word.bind_ordinal(), 0, "first-use ordinal 0");
    let _ = got_addr; // the ordinal is the interesting shape, not the address

    // And the payload's segment record agrees with the mirror.
    let payload = {
        let header = MachHeader64::parse(&image).unwrap();
        let mut it = LoadCommandIter::new(
            &image,
            MachHeader64::SIZE,
            header.ncmds,
            header.sizeofcmds,
        )
        .unwrap();
        let mut found = None;
        while let Some(cmd) = it.next_command().unwrap() {
            if cmd.kind == LoadCommandKind::LinkeditData(LC_DYLD_CHAINED_FIXUPS) {
                let lc = pgr_format::LinkeditDataCommand::parse(cmd.bytes).unwrap();
                let at = lc.dataoff as usize;
                found = Some(image[at..at + lc.datasize as usize].to_vec());
            }
        }
        found.expect("the chained payload present")
    };
    let hdr = parse_header(&payload).unwrap();
    let starts = parse_starts_in_image(&payload, hdr.starts_offset as usize).unwrap();
    let mut formats = Vec::new();
    for &off in &starts.seg_info_offset {
        if off == 0 {
            continue;
        }
        let rec_at = hdr.starts_offset as usize + off as usize;
        formats.push(u16::from_le_bytes(payload[rec_at + 6..rec_at + 8].try_into().unwrap()));
    }
    assert!(
        formats.contains(&DYLD_CHAINED_PTR_ARM64E),
        "the segment record names the arm64e family: {formats:?}"
    );
}

#[test]
fn the_offset64_control_stays_the_default_bytes() {
    let dir = scratch("control");
    let obj = dir.join("printf_main.o");
    std::fs::write(&obj, printf_main()).unwrap();
    let tbd = dir.join("libSystem.tbd");
    std::fs::write(&tbd, libsystem_tbd()).unwrap();
    let mk = |argv: &[&str]| {
        let mut a: Vec<OsString> = argv.iter().map(OsString::from).collect();
        a.push(obj.display().to_string().into());
        a.push(tbd.display().to_string().into());
        let mut opts = parse(&a).unwrap();
        opts.config.ident = "peregrine-m10-arm64e-control".into();
        opts
    };
    let silent = mk(&["-o", &dir.join("a").display().to_string()]);
    let explicit = mk(&[
        "-o",
        &dir.join("b").display().to_string(),
        "-fixup_chains_format",
        "offset64",
    ]);
    let a = link(&silent);
    let b = link(&explicit);
    assert_eq!(a, b, "the explicit default is byte-identical to no flag");
    let mirror = chain_starts_mirror(&a).expect("__chain_starts present");
    assert_eq!(
        u32::from_le_bytes(mirror[0..4].try_into().unwrap()),
        u32::from(DYLD_CHAINED_PTR_64_OFFSET),
        "the control names the 64_OFFSET family"
    );
    let (_, data_off, _size) = find_section(&a, "__DATA", "__data").expect("__data present");
    let word = ChainWord64::new(u64::from_le_bytes(
        a[data_off as usize..data_off as usize + 8].try_into().unwrap(),
    ));
    assert!(
        !word.is_bind(),
        "the control's __data slot is a 64_OFFSET rebase"
    );
}

#[test]
fn arm64e_output_is_deterministic() {
    let dir = scratch("determinism");
    let opts = parsed_opts(&dir, &[]);
    let first = link(&opts);
    let second = link(&opts);
    assert_eq!(first, second, "double links are byte-identical (a CI gate)");
}
