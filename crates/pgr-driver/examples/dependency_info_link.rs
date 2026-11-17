//! The dependency-info consumer example (M60): one small executable
//! link — `main.o` binding `_greet` from `libgreet.a`, resolved through
//! `-L`/`-lgreet` so the search's probed misses ride the record — asked
//! *which files did the link read, and what did it write?* The driver
//! writes ld64's binary dependency record beside the link
//! (`-dependency_info <path>`), the strict reader
//! (`pgr_core::dep_info::DependencyRecord::parse`) reads it back, and
//! the re-render proves the file's bytes are the reader's own output —
//! the round-trip convention, on the artifact Xcode's incremental
//! builds consume.
//!
//! Run: `cargo run -p pgr-driver --example dependency_info_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_core::dep_info::{DependencyRecord, INPUT, NOT_FOUND, OUTPUT};
use pgr_fixtures::{ArchiveBuilder, ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// `main.o`: `_main` + a data pointer at `_greet`.
fn main_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
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
    let greet = b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    b.add_section(ObjectSection::data(
        "__data",
        vec![0u8; 8],
        vec![ObjectReloc::unsigned(greet as u32).at(0)],
    ));
    b.build().expect("the fixture object builds")
}

/// `greet.o`: `_greet` — the pulled member.
fn greet_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("greet.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

fn main() {
    let dir = std::env::temp_dir().join(format!("pgr_example_dep_info_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    std::fs::write(dir.join("main.o"), main_object()).expect("the fixture object lands");
    let mut a = ArchiveBuilder::new("libgreet.a");
    a.add_member("greet.o", greet_object());
    std::fs::write(dir.join("libgreet.a"), a.build()).expect("the fixture archive lands");

    let out = dir.join("app");
    let deps = dir.join("app.deps");
    let argv: Vec<std::ffi::OsString> = [
        "-o",
        out.to_str().unwrap(),
        "-dependency_info",
        deps.to_str().unwrap(),
        "-platform_version",
        "macos",
        "12.0",
        "14.0",
        "-L",
        dir.to_str().unwrap(),
        "-lgreet",
        dir.join("main.o").to_str().unwrap(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let opts = pgr_driver::opts::parse(&argv).expect("the example argv parses");
    let outcome = pgr_driver::run(&opts).expect("the example link links");

    println!("linked {} ({} bytes)", outcome.output, outcome.file_size);
    let bytes = std::fs::read(&deps).expect("the dependency file lands");
    let record = DependencyRecord::parse(&bytes).expect("the record parses");
    println!("record: {}", record.linker_version());
    for entry in record.entries() {
        let path = String::from_utf8_lossy(&entry.path);
        match entry.opcode {
            INPUT => println!("  0x10 input     {path}"),
            NOT_FOUND => println!("  0x11 not-found {path}"),
            OUTPUT => println!("  0x40 output    {path}"),
            other => println!("  {other:#04x}           {path}"),
        }
    }
    // The round-trip gate, on the real artifact: the reader's re-render
    // is the file's own bytes (the format's canonical order).
    assert_eq!(record.render(), bytes, "the record round-trips");
    println!("round-trip: the re-render is the file's own bytes");
    let _ = std::fs::remove_dir_all(&dir);
}
