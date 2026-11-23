//! The unused-dylib advisory consumer example (M136): ld64's
//! `-warn_unused_dylibs` — the advisory face over the M42 drop's own
//! used-marks predicate: the default ships silently, the named decision
//! prints one `pgr: warning: unused dylib` line per riding-but-unbound
//! dylib (the linked-but-unbound row ld64's face names), the image
//! byte-identical either way (a measurement, never a layout product —
//! the house consumer-example convention). The `-dead_strip_dylibs`
//! composition closes the walkthrough: the drop is the fix, the kept
//! needed mark is the per-dylib opt-out the face still names.
//!
//! Run: `cargo run -p pgr-driver --example warn_unused_dylibs_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use std::ffi::OsString;
use std::path::PathBuf;

/// `main.o`: `_main` referencing the bound library's `_greet` export —
/// `libbound` rides used, `libunused` rides unbound.
fn main_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("main.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6, 0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let undef = b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    b.section_mut(data).relocs = vec![pgr_fixtures::ObjectReloc::unsigned(undef as u32).at(0)];
    b.build().expect("the fixture object builds")
}

/// A stub `.tbd`: the install name plus its exports.
fn stub_library(dir: &std::path::Path, name: &str, install: &str, exports: &[&str]) -> PathBuf {
    let syms = exports
        .iter()
        .map(|s| format!("      - {s}"))
        .collect::<Vec<_>>()
        .join("\n");
    let tbd = format!(
        "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: \
         {install}\ncurrent-version: 1.0.0\ncompatibility-version: 1.0.0\nexports:\n  \
         - targets: [ arm64-macos ]\n    symbols:\n{syms}\n...\n"
    );
    let path = dir.join(name);
    std::fs::write(&path, tbd).unwrap();
    path
}

fn run(dir: &std::path::Path, out: &str, extra: &[&str], libs: &[std::path::PathBuf]) -> Vec<u8> {
    let obj = dir.join("main.o");
    let mut argv: Vec<String> = vec!["-o".into(), dir.join(out).display().to_string()];
    argv.push(obj.display().to_string());
    for lib in libs {
        argv.push(lib.display().to_string());
    }
    argv.extend(extra.iter().map(std::string::ToString::to_string));
    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link ships");
    std::fs::read(dir.join(out)).expect("the image reads")
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt().init();
    }
    let dir = std::env::temp_dir().join(format!("pgr_warn_unused_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("main.o"), main_object()).unwrap();
    let bound = stub_library(&dir, "libbound.tbd", "@rpath/libbound.dylib", &["_greet"]);
    let unused = stub_library(
        &dir,
        "libunused.tbd",
        "@rpath/libunused.dylib",
        &["_noone_uses_this"],
    );

    // The default: no advisory, the image ships.
    let silent = run(&dir, "app_silent", &[], &[bound.clone(), unused.clone()]);
    // The advisory: one `pgr: warning: unused dylib` line for the
    // unbound rider, the same image.
    let warned = run(
        &dir,
        "app_warned",
        &["-warn_unused_dylibs"],
        &[bound.clone(), unused.clone()],
    );
    assert_eq!(
        silent, warned,
        "the face never moves the bytes (the byte-identity the gate pins)"
    );

    // The fix beside the face: `-dead_strip_dylibs` drops the unbound
    // rider, so the named advisory names nothing (the query runs after
    // the drop — only the mark-kept survivors name).
    let dropped = run(
        &dir,
        "app_dropped",
        &["-dead_strip_dylibs", "-warn_unused_dylibs"],
        &[bound, unused],
    );
    assert_ne!(
        silent, dropped,
        "the drop moves the load commands (the fix is a layout product)"
    );

    println!(
        "\nimages: {} (strict gates in the tests; try PGR_TRACING=1 to watch the advisory walk)",
        dir.display()
    );
    println!("warn_unused_dylibs_link: ok");
}
