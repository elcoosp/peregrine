//! M10 rung 5, slice 3 — the `x86_64` input surface rides the driver:
//! `-arch x86_64` links genuinely x86_64-typed inputs end to end (the
//! family gate reads every object's header, the Pass-1 decode walks the
//! `x86_64` relocation alphabet, the image verifies strict), the arm64
//! default refuses a foreign input with the `-arch` fix named, and the
//! resident lane serves the same shape byte-identically (the family
//! rides the config tail — wire v83 — and the inputs ride the request's
//! own bytes). The plan line this pins (TDD §15.9): *"The input surface
//! stays arm64 this rung"* — flipped by this slice.

use pgr_fixtures::{CpuKind, ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr-m10-x86e-in-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn libsystem_tbd() -> &'static str {
    "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: /usr/lib/libSystem.B.dylib\ncurrent-version: 1.2.3\ncompatibility-version: 1.0.0\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ _printf, _strlen ]\n...\n"
}

/// A pointer-shaped `x86_64` `main.o`: the GOT-indirect `_printf` bind and
/// a `__data` rebase slot (the slice-2 record's call shape, no stub
/// lane).
fn x86_printf_main() -> Vec<u8> {
    let text: Vec<u8> = [
        &[0x48u8, 0x8B, 0x05, 0xFC, 0xFF, 0xFF, 0xFF][..], // movq _printf@GOTPCREL(%rip)
        &[0xC3],                                           // ret
    ]
    .concat();
    let mut b = ObjectBuilder::new("x86e_main.o").set_cputype(CpuKind::X86_64);
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
    b.section_mut(data)
        .relocs
        .push(ObjectReloc::x86_unsigned(main).at(0));
    b.build().expect("the fixture object builds")
}

/// A pointer-shaped arm64 `main.o` (the pre-slice corpus shape).
fn arm64_main() -> Vec<u8> {
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
    b.build().expect("the fixture object builds")
}

/// Writes the inputs, parses `-arch x86_64` + the flag set, runs the
/// link, returns the produced bytes.
fn link_with(dir: &Path, extra: &[&str], obj_bytes: Vec<u8>, obj_name: &str) -> Vec<u8> {
    let obj = dir.join(obj_name);
    std::fs::write(&obj, obj_bytes).unwrap();
    let tbd = dir.join("libSystem.tbd");
    std::fs::write(&tbd, libsystem_tbd()).unwrap();
    let mut argv = vec!["-o".to_string(), dir.join("exe").display().to_string()];
    argv.extend(extra.iter().copied().map(str::to_string));
    argv.push(obj.display().to_string());
    argv.push(tbd.display().to_string());
    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    let opts = pgr_driver::opts::parse(&argv).expect("the flag set parses");
    pgr_driver::run(&opts).expect("the link completes");
    std::fs::read(&opts.output).unwrap()
}

fn strict() -> pgr_verify::Options {
    pgr_verify::Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

// ---- the input surface, end to end ---------------------------------------------

#[test]
fn the_x86_64_input_links_end_to_end_and_verifies_strict() {
    // The plan's acceptance, verbatim (TDD §15.9): *"The input surface
    // stays arm64 this rung"* — flipped: a genuinely x86_64-typed input
    // rides the driver face (`-arch x86_64`), the family gate reads its
    // header, and the produced image verifies strict.
    let dir = scratch("e2e");
    let image = link_with(&dir, &["-arch", "x86_64"], x86_printf_main(), "x86e_main.o");
    let report = pgr_verify::verify(&image, &strict());
    assert!(
        report
            .issues
            .iter()
            .all(|i| i.severity != pgr_verify::Severity::Error),
        "the CLI-produced x86_64 input verifies strict: {:?}",
        report.issues
    );
}

#[test]
fn an_x86_64_input_refuses_under_the_arm64_default() {
    // The pre-slice default: a foreign input refuses with the family and
    // the `-arch` fix named (the gate's driver face).
    let dir = scratch("default-refuses");
    let err = std::panic::catch_unwind(|| {
        link_with(&dir, &[], x86_printf_main(), "x86e_main.o");
    })
    .expect_err("the foreign input refuses under the default");
    let msg = err.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(
        msg.contains("x86_64") && msg.contains("-arch"),
        "the refusal names the family and the fix: {msg}"
    );
}

#[test]
fn an_arm64_input_refuses_beside_arch_x86_64() {
    // The symmetric face: an arm64 input under `-arch x86_64` refuses
    // with both families named (the gate runs before any parse work).
    let dir = scratch("arm64-refuses");
    let err = std::panic::catch_unwind(|| {
        link_with(&dir, &["-arch", "x86_64"], arm64_main(), "arm64_main.o");
    })
    .expect_err("the arm64 input refuses beside the x86_64 family");
    let msg = err.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(
        msg.contains("arm64") && msg.contains("x86_64"),
        "the refusal names both families: {msg}"
    );
}

#[test]
fn the_resident_lane_serves_the_x86_64_input() {
    // The family rides the config tail (wire v83) and the inputs ride
    // the request's own bytes, so the served link plans the same image
    // the cold lane does (the parity gate is byte-identical).
    let dir = scratch("resident_ref");
    let cold = link_with(&dir, &["-arch", "x86_64"], x86_printf_main(), "x86e_main.o");

    let dir2 = scratch("resident");
    let sock = dir2.join("pgrd.sock");
    let owned = sock.clone();
    std::thread::spawn(move || {
        let _ = pgr_daemon::serve(&owned, std::time::Duration::from_secs(120));
    });
    std::thread::sleep(std::time::Duration::from_millis(50));

    let obj = dir2.join("x86e_main.o");
    std::fs::write(&obj, x86_printf_main()).unwrap();
    let tbd = dir2.join("libSystem.tbd");
    std::fs::write(&tbd, libsystem_tbd()).unwrap();
    let argv: Vec<OsString> = [
        "-o".to_string(),
        dir2.join("exe").display().to_string(),
        "-arch".to_string(),
        "x86_64".to_string(),
        "-resident".to_string(),
        "-resident_socket".to_string(),
        sock.display().to_string(),
        obj.display().to_string(),
        tbd.display().to_string(),
    ]
    .iter()
    .map(OsString::from)
    .collect();
    let opts = pgr_driver::opts::parse(&argv).expect("the resident argv parses");
    pgr_driver::run(&opts).expect("the resident link runs");
    let served = std::fs::read(&opts.output).unwrap();
    assert_eq!(
        cold, served,
        "the resident lane serves the x86_64 input byte-identically"
    );
}
