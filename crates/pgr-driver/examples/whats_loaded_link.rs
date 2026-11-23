//! The loaded-object inventory consumer example (M134): ld64's
//! `-whatsloaded` — the driver's inventory face: the default ships
//! silently, the named decision prints one name per object Pass 1
//! actually loaded (the explicit objects beside the archive members the
//! pull admitted), the image byte-identical either way (the face is a
//! measurement, never a layout product — the house consumer-example
//! convention).
//!
//! Run: `cargo run -p pgr-driver --example whats_loaded_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use std::ffi::OsString;

/// One object: one defined symbol, one section, no undefineds (a second
/// `_main` would refuse the link — the M108 default).
fn entry_object(name: &str, symbol: &str) -> Vec<u8> {
    let mut b = ObjectBuilder::new(name);
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: symbol.into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

fn run(dir: &std::path::Path, out: &str, extra: &[&str], objs: &[std::path::PathBuf]) {
    let mut argv: Vec<String> = vec!["-o".into(), dir.join(out).display().to_string()];
    argv.extend(extra.iter().map(std::string::ToString::to_string));
    argv.extend(objs.iter().map(|p| p.display().to_string()));
    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link ships");
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt().init();
    }
    let dir = std::env::temp_dir().join(format!("pgr_whats_loaded_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let a = dir.join("a.o");
    let b = dir.join("b.o");
    std::fs::write(&a, entry_object("a.o", "_main")).unwrap();
    std::fs::write(&b, entry_object("b.o", "_b_entry")).unwrap();

    // The default: no inventory, the image ships.
    run(&dir, "app_silent", &[], &[a.clone(), b.clone()]);
    assert!(dir.join("app_silent").exists(), "the image ships");

    // The inventory: one name per loaded object, the same image (the
    // bytes never move — the face is a measurement).
    run(&dir, "app_inventory", &["-whatsloaded"], &[a, b]);
    assert!(dir.join("app_inventory").exists(), "the image ships");
    let silent = std::fs::read(dir.join("app_silent")).expect("the silent image reads");
    let inventory = std::fs::read(dir.join("app_inventory")).expect("the inventory image reads");
    assert_eq!(
        silent, inventory,
        "the face never moves the bytes (the byte-identity the gate pins)"
    );

    println!("\nwhats_loaded_link: ok");
}
