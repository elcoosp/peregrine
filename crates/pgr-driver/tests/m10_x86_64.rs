//! M10 rung 5, slice 2 — the `x86_64` producer rides the driver surface:
//! `-arch` names the second CPU family the pipeline produces (the read
//! side has admitted `CPU_TYPE_X86_64` since slice 1; TDD §15.8 named
//! "the producer half and the driver surface" as the rung's next
//! slices). The gates: the flag parses both arches, refuses unknown
//! names with the linked vocabulary in the hint, and the end-to-end
//! `x86_64` link carries the family through the header words, the 4 KiB
//! packing and the format-2 chains — the verifier's strict pass reads
//! the produced image and finds it well-formed — with the arm64 default
//! byte-identical and the arm64e override beside `x86_64` refusing (the
//! layout's re-check, surfaced through the driver).

use pgr_driver::opts::{Options, parse};
use pgr_fixtures::{CpuKind, ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_format::consts::{CPU_TYPE_ARM64, CPU_TYPE_X86_64, PAGE_SIZE_4K};
use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64, SegmentCommand64};
use std::ffi::OsString;

fn args(list: &[&str]) -> Vec<OsString> {
    list.iter().map(OsString::from).collect()
}

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr-m10-x86e-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn libsystem_tbd() -> &'static str {
    "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: /usr/lib/libSystem.B.dylib\ncurrent-version: 1.2.3\ncompatibility-version: 1.0.0\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ _printf, _strlen ]\n...\n"
}

/// A self-contained `x86_64` `main.o` (M10 rung 5 slice 3: the input
/// surface rides the family — the fixture names `CpuKind::X86_64`) with
/// one rebase slot (`__data`) and a `_printf` GOT bind (the callsite
/// shape `x86_64` emits natively — the GOT-indirect pair, no stub
/// lane).
fn printf_main() -> Vec<u8> {
    let text: Vec<u8> = [
        &[0x48u8, 0x8B, 0x05, 0xFC, 0xFF, 0xFF, 0xFF][..], // movq _printf@GOTPCREL(%rip)
        &[0xC3],                                           // ret
    ]
    .concat();
    let mut b = ObjectBuilder::new("printf_main.o").set_cputype(CpuKind::X86_64);
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
    b.section_mut(sect)
        .relocs
        .push(ObjectReloc::x86_got_load(printf).at(3));
    // An UNSIGNED pointer against a *defined* symbol: a pure rebase slot
    // in __data (the bind rides the GOT reloc above).
    b.section_mut(data)
        .relocs
        .push(ObjectReloc::x86_unsigned(main).at(0));
    b.build().unwrap()
}

/// Writes the inputs into `dir` and parses the option set.
fn parsed_opts(dir: &std::path::Path, extra: &[&str]) -> Options {
    let obj = dir.join("printf_main.o");
    std::fs::write(&obj, printf_main()).unwrap();
    let tbd = dir.join("libSystem.tbd");
    std::fs::write(&tbd, libsystem_tbd()).unwrap();
    let mut argv = vec!["-o".to_string(), dir.join("exe").display().to_string()];
    argv.extend(extra.iter().copied().map(str::to_string));
    argv.push(obj.display().to_string());
    argv.push(tbd.display().to_string());
    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    parse(&argv).expect("the flag set parses")
}

/// The output of one full link run (the bytes `run` writes to `-o`).
fn link(opts: &Options) -> Vec<u8> {
    pgr_driver::run(opts).expect("the link completes");
    std::fs::read(&opts.output).unwrap()
}

fn strict() -> pgr_verify::Options {
    pgr_verify::Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// The emitted image's cputype word.
fn cputype_of(image: &[u8]) -> u32 {
    let header = MachHeader64::parse(image).unwrap();
    header.cputype
}

/// One output segment's vmsize by name, read from the emitted image.
fn segment_vmsize(image: &[u8], seg: &str) -> Option<u64> {
    let header = MachHeader64::parse(image).unwrap();
    let mut it =
        LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds).unwrap();
    while let Some(cmd) = it.next_command().unwrap() {
        if let LoadCommandKind::Segment64 = cmd.kind {
            let seg_cmd = SegmentCommand64::parse(cmd.bytes, 0).unwrap();
            if seg_cmd.name().unwrap() == seg {
                return Some(seg_cmd.vmsize);
            }
        }
    }
    None
}

// ---- the flag surface -----------------------------------------------------------

#[test]
fn the_flag_accepts_both_arches() {
    let dir = scratch("parse");
    let arm64 = parsed_opts(&dir, &["-arch", "arm64"]);
    assert_eq!(
        arm64.config.cpu,
        pgr_core::cpu::CpuFamily::Arm64,
        "the arm64 spelling names the default family"
    );
    let x86e = parsed_opts(&dir, &["-arch", "x86_64"]);
    assert_eq!(
        x86e.config.cpu,
        pgr_core::cpu::CpuFamily::X86_64,
        "the x86_64 spelling names the second family"
    );
}

#[test]
fn an_unknown_arch_refuses_with_the_vocabulary() {
    let err = parse(&args(&["-o", "out", "-arch", "armv7", "a.o"])).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("arm64") && msg.contains("x86_64"),
        "the refusal names the linked arches: {msg}"
    );
}

#[test]
fn the_usage_names_the_two_arches() {
    let s = pgr_driver::usage();
    assert!(
        s.contains("-arch arm64") && s.contains("x86_64"),
        "the usage carries the linked arch vocabulary"
    );
}

// ---- the producer, end to end ---------------------------------------------------

#[test]
fn the_produced_header_carries_the_family() {
    let dir = scratch("header");
    let opts = parsed_opts(&dir, &["-arch", "x86_64"]);
    let image = link(&opts);
    assert_eq!(
        cputype_of(&image),
        CPU_TYPE_X86_64,
        "the family cputype rides the produced header"
    );
}

#[test]
fn the_x86_64_image_verifies_strict() {
    // The pair gate, end to end through the CLI: the produced image
    // rides the 4 KiB packing and the format-2 chains the slice-1 walk
    // reads, and the strict pass returns no error-severity issue.
    let dir = scratch("strict");
    let opts = parsed_opts(&dir, &["-arch", "x86_64"]);
    let image = link(&opts);
    let report = pgr_verify::verify(&image, &strict());
    assert!(
        report
            .issues
            .iter()
            .all(|i| i.severity != pgr_verify::Severity::Error),
        "the CLI-produced x86_64 image verifies strict: {:?}",
        report.issues
    );
    assert_eq!(
        segment_vmsize(&image, "__TEXT"),
        Some(PAGE_SIZE_4K),
        "the produced packing rides the family page"
    );
}

#[test]
fn the_default_link_stays_arm64() {
    // The arm64 corpus (the pre-slice shape) under the flag-less link
    // keeps the arm64 family (slice 3: the input surface rides the
    // family, so the default's corpus is arm64-typed).
    let dir = scratch("default");
    let mut b = ObjectBuilder::new("arm64_main.o");
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    let sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: data,
        value: 0,
        weak: false,
    });
    let idx = b.sym_index(sym);
    b.section_mut(data)
        .relocs
        .push(ObjectReloc::unsigned(idx).at(0));
    let obj = dir.join("arm64_main.o");
    std::fs::write(&obj, b.build().unwrap()).unwrap();
    let tbd = dir.join("libSystem.tbd");
    std::fs::write(&tbd, libsystem_tbd()).unwrap();
    let argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        dir.join("exe").display().to_string(),
        obj.display().to_string(),
        tbd.display().to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let opts = parse(&argv).expect("the flag set parses");
    let image = link(&opts);
    assert_eq!(
        cputype_of(&image),
        CPU_TYPE_ARM64,
        "the flag-less link keeps the arm64 family"
    );
}

#[test]
fn arm64e_beside_x86_64_refuses_with_both_names() {
    // The arm64e word family is the arm64 CPU's (TDD §15.4): the
    // combination refuses through the layout's re-check, the message
    // naming both families.
    let dir = scratch("arm64e");
    let opts = parsed_opts(&dir, &["-arch", "x86_64", "-fixup_chains_format", "arm64e"]);
    let err = pgr_driver::run(&opts).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("arm64e") && msg.contains("x86_64"),
        "the refusal names both families: {msg}"
    );
}

#[test]
fn the_x86_64_family_refuses_the_relocatable_output() {
    // The `-r` object's header is the input's, verbatim (the M10
    // rung-1 contract): the family has no shape to name there. The
    // surface refusal names both sides and the fix (the M125 pattern;
    // the layout's re-check backs it for library callers).
    let dir = scratch("reloc");
    let err = parse(&args(&[
        "-o",
        &dir.join("obj").display().to_string(),
        "-arch",
        "x86_64",
        "-r",
        &dir.join("in.o").display().to_string(),
    ]))
    .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("x86_64") && msg.contains("relocatable"),
        "the refusal names the shape conflict: {msg}"
    );
}

#[test]
fn the_x86_64_link_is_deterministic() {
    // Double-link byte-equality (TDD §4.3): the family decisions ride
    // the plan, so the produced bytes are reproducible.
    let dir = scratch("determinism");
    let opts_a = parsed_opts(&dir, &["-arch", "x86_64"]);
    let image_a = link(&opts_a);
    let opts_b = parsed_opts(&dir, &["-arch", "x86_64"]);
    let image_b = link(&opts_b);
    assert_eq!(image_a, image_b, "the family link is byte-deterministic");
}
