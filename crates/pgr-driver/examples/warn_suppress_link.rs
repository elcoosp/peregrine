//! The warning-suppression consumer example (M133): ld64's `-w` — the
//! advisory faces' print decision: the `-undefined warning` product
//! prints and exits 0 under the default, the same link ships silently
//! (the `pgr: warning:` lines silenced, the image unchanged, exit 0)
//! under `-w`, and the suppression composes with `-fatal_warnings` (the
//! tally counts what the faces recorded, never what they printed — the
//! suppressed warnings still elevate, ld64's own composition; the house
//! consumer-example convention).
//!
//! Run: `cargo run -p pgr-driver --example warn_suppress_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::ffi::OsString;

/// hello.o: `_main` references `_hole` — the unresolved name the
/// advisory face prints.
fn hole_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("hello.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let undef = b.add_symbol(ObjectSymbol::Undefined {
        name: "_hole".into(),
        weak_ref: false,
    });
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    let slot = b.sym_index(undef);
    b.section_mut(data)
        .relocs
        .push(ObjectReloc::unsigned(slot).at(0));
    b.build().expect("the fixture object builds")
}

fn run(
    dir: &std::path::Path,
    out: &str,
    extra: &[&str],
    obj: &std::path::Path,
) -> Result<(), String> {
    let mut argv: Vec<String> = vec!["-o".into(), dir.join(out).display().to_string()];
    argv.extend(extra.iter().map(std::string::ToString::to_string));
    argv.push(obj.display().to_string());
    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).map(|_| ()).map_err(|e| e.to_string())
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt().init();
    }
    let dir = std::env::temp_dir().join(format!("pgr_warn_suppress_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let obj = dir.join("hello.o");
    std::fs::write(&obj, hole_object()).unwrap();

    // The default: the advisory face prints, exit 0, the image ships.
    run(&dir, "hello_default", &["-undefined", "warning"], &obj)
        .expect("the default keeps the advisory exit");
    assert!(dir.join("hello_default").exists(), "the image ships");

    // The suppression: the same warnings silenced, the same exit 0, the
    // same image (the bytes never move — the decision is the print
    // face's).
    run(
        &dir,
        "hello_suppressed",
        &["-undefined", "warning", "-w"],
        &obj,
    )
    .expect("the suppressed link still exits 0");
    assert!(
        dir.join("hello_suppressed").exists(),
        "the suppressed image ships unchanged"
    );

    // The composition: the suppressed warnings still elevate (the tally
    // counts what the faces recorded, never what they printed).
    let elevated = run(
        &dir,
        "hello_composed",
        &["-undefined", "warning", "-w", "-fatal_warnings"],
        &obj,
    );
    let err = elevated.expect_err("the suppressed warnings still elevate");
    println!("the composed escalation refused: {err}");
    assert!(
        !dir.join("hello_composed").exists(),
        "the elevated link writes no image"
    );

    println!("\nwarn_suppress_link: ok");
}
