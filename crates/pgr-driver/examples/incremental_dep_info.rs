//! The incremental ladder's dependency-record consumer example (M85):
//! the capture link records the state, one function's body changes, and
//! the relink rewrites the build-system sidecar from its own read set —
//! `-dependency_info` beside `-incremental` writes the record Pass 0
//! built while the relink's mapping read the inputs (the re-parse is
//! the digest source, so the read set is real): the linker-version row,
//! every file the ladder mapped, the probed misses, the output row
//! beside them. The decoded record prints its rows so the run's read
//! set is visible, not implied.
//!
//! Run: `cargo run -p pgr-driver --example incremental_dep_info`

use pgr_core::dep_info::{DependencyRecord, INPUT, NOT_FOUND, OUTPUT};
use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// hello.o: `_main` over 16 KiB of `__text` (the tier-1 edit shape),
/// a BL `_greet` site — the link the ladder records and patches. The
/// `flip` variant rewrites eight words mid-text: the edit the relink
/// patches.
fn hello(flip: bool) -> Vec<u8> {
    let mut text = vec![0xD5u8, 0x03, 0x20, 0x1F]; // nop
    text.resize(16 * 1024, 0xD5);
    if flip {
        let base = 8 * 1024 + 16;
        for i in 0..8 {
            text[base + i * 4] = 0xAA;
        }
    }
    let mut b = ObjectBuilder::new("hello.o");
    let sect = b.add_section(ObjectSection::text(
        "__text",
        text,
        vec![ObjectReloc::branch26(1).at(40)],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    b.build().expect("the fixture object builds")
}

/// greet.o: `_greet` — the linked definition.
fn greet() -> Vec<u8> {
    let mut b = ObjectBuilder::new("greet.o");
    let sect = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6], // ret
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// Links `argv` (the corpus paths appended) through the driver's own
/// parse + run pair.
fn run(
    dir: &std::path::Path,
    out: &str,
    extra: &[&str],
) -> Result<pgr_driver::LinkOutcome, String> {
    let hello_path = dir.join("hello.o");
    let greet_path = dir.join("greet.o");
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        dir.join(out).as_os_str().to_os_string(),
    ];
    for arg in extra {
        argv.push(std::ffi::OsString::from(arg));
    }
    argv.push(hello_path.as_os_str().to_os_string());
    argv.push(greet_path.as_os_str().to_os_string());
    let parsed = opts::parse(&argv).map_err(|e| format!("{:?}", miette::Report::new(e)))?;
    pgr_driver::run(&parsed).map_err(|e| e.to_string())
}

/// Decodes a sidecar and prints its rows (the reader is the same seam
/// the writer validates against).
fn print_record(path: &std::path::Path) {
    let bytes = std::fs::read(path).expect("the sidecar exists");
    let record = DependencyRecord::parse(&bytes).expect("the sidecar decodes");
    println!("-- {} --", path.display());
    println!("   version: {}", record.linker_version());
    for e in record.entries() {
        let kind = match e.opcode {
            INPUT => "input",
            NOT_FOUND => "missed",
            OUTPUT => "output",
            _ => "row",
        };
        println!("   {kind}: {}", String::from_utf8_lossy(&e.path));
    }
}

fn main() {
    let dir = std::env::temp_dir().join(format!("pgr_ladder_deps_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("hello.o"), hello(false)).unwrap();
    std::fs::write(dir.join("greet.o"), greet()).unwrap();
    let deps = dir.join("app.deps");
    let deps_arg = deps.display().to_string();

    // 1. The capture link: the ladder's first rung records the state
    //    beside the output and writes the sidecar its full link read.
    println!("== the capture link (the record sidecar is written) ==");
    run(
        &dir,
        "hello",
        &["-incremental", "-dependency_info", &deps_arg],
    )
    .expect("the capture link runs");
    print_record(&deps);

    // 2. The edit: the same object, eight words flipped mid-text — the
    //    tier-1 edit the anchored relink patches in place.
    std::fs::write(dir.join("hello.o"), hello(true)).unwrap();

    // 3. The record-bearing relink: the ladder's Pass 0 re-reads every
    //    input it maps (the re-parse is the digest source) and records
    //    the read set while the reads happen — the sidecar the relink
    //    rewrites names the files the ladder actually read, and the
    //    output row joins at the write site. Never the previous link's
    //    list, never a missing sidecar.
    println!("== the record-bearing relink: -incremental -dependency_info ==");
    let outcome = run(
        &dir,
        "hello",
        &["-incremental", "-dependency_info", &deps_arg],
    )
    .expect("the record-bearing relink runs");
    let patch = outcome.patch.expect("the relink reports its patch");
    println!(
        "outcome: {} of {} tiles patched ({} bytes, untouched={})",
        patch.dirty_tiles, patch.total_tiles, patch.bytes_patched, patch.untouched
    );
    print_record(&deps);

    let _ = std::fs::remove_dir_all(&dir);
}
