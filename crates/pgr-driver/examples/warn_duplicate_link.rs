//! M121 — the duplicate-symbol advisory: `-warn_duplicate` — ld64's flag
//! ("Cause ld to print a warning when a duplicate symbol definition is
//! found"). Distinct from `-multiply_defined warning` (which changes the
//! resolution policy to first-wins), `-warn_duplicate` is purely advisory:
//! it tallies the duplicate strong definitions found during Pass 2 resolve
//! and emits a warning to stderr, but the resolution policy itself is
//! unchanged (the default `error` still applies unless overridden). The
//! relocatable output refuses the knob (the object's symtab is the input's,
//! verbatim).
//!
//! Run: `cargo run -p pgr-driver --example warn_duplicate_link`
//! (`PGR_TRACING=1` installs a tracing subscriber).

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_core::resolve::MultiplyDefinedPolicy;
use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use std::ffi::OsString;

/// `main.o`: `_main` in a `__text` body — the entry symbol.
fn main_object(dir: &std::path::Path) -> std::path::PathBuf {
    let mut b = ObjectBuilder::new("main.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(4),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let path = dir.join("main.o");
    std::fs::write(&path, b.build().expect("the fixture builds")).expect("main.o writes");
    path
}

/// One object defining the named strong external — two of these under the
/// same name collide at the `install_sect_def` `Equal`/`Strong` tie.
fn dup_object(dir: &std::path::Path, name: &str, sym: &str) -> std::path::PathBuf {
    let mut b = ObjectBuilder::new(name);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: sym.into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let path = dir.join(name);
    std::fs::write(&path, b.build().expect("the fixture builds")).expect("the dup object writes");
    path
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt().init();
    }
    let dir = std::env::temp_dir().join(format!("pgr_warn_duplicate_link_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("the scratch dir creates");
    let main = main_object(&dir);
    let a = dup_object(&dir, "a.o", "_dup");
    let b = dup_object(&dir, "b.o", "_dup");
    let objs = [main.clone(), a.clone(), b.clone()];
    let inputs: Vec<LinkInput> = objs
        .iter()
        .map(|p| LinkInput {
            name: p
                .file_name()
                .expect("the name rides")
                .to_string_lossy()
                .into_owned(),
            bytes: std::fs::read(p).expect("the object reads"),
        })
        .collect();

    // Face 1 — the library seam: under the `warning` policy the duplicate's
    // first definition wins; `-warn_duplicate` tallies the collision (one
    // entry) without changing the resolution policy, and the bytes never
    // move under either face (the advisory is a measurement, never a
    // layout product).
    let plan_for = |warn: bool| {
        link(
            &inputs,
            &[],
            &LinkConfig {
                filetype: OutputType::Execute,
                multiply_defined: MultiplyDefinedPolicy::Warning,
                warn_duplicate: warn,
                ..LinkConfig::default()
            },
        )
        .expect("the link plans")
    };
    let off = plan_for(false);
    let on = plan_for(true);
    let off_n = off.resolution.warn_duplicate_open().count();
    let on_n = on.resolution.warn_duplicate_open().count();
    assert_eq!(off_n, 0, "the off face records no duplicate advisory");
    assert_eq!(on_n, 1, "the on face tallies the one duplicate collision");
    assert_eq!(
        off.layout.header_bytes, on.layout.header_bytes,
        "the advisory never moves the bytes"
    );
    println!(
        "face 1 (library seam): off records {off_n} duplicate advisory entries — \
         -warn_duplicate records {on_n} (the bytes never move, {} vs {} bytes)",
        off.layout.file_size, on.layout.file_size
    );

    // Face 2 — the driver face: under `-multiply_defined suppress
    // -warn_duplicate` the duplicate's first definition wins silently
    // (the suppress face prints nothing) and `-warn_duplicate` adds the
    // advisory — the collision prints as a `pgr: warning: duplicate
    // symbol` face on stderr and the link still exits 0 (the resolution
    // policy itself is unchanged). The warning rides the driver's stderr;
    // the image ships beside it.
    let mut argv: Vec<OsString> = vec![
        "-multiply_defined".into(),
        "suppress".into(),
        "-warn_duplicate".into(),
        "-o".into(),
        dir.join("app").to_string_lossy().into_owned().into(),
    ];
    argv.extend(objs.iter().map(|p| p.to_string_lossy().into_owned().into()));
    let o = opts::parse(&argv).expect("the surface parses");
    let outcome = pgr_driver::run(&o).expect("the link runs");
    let image = std::fs::read(dir.join("app")).expect("the image reads");
    assert!(!image.is_empty(), "the suppress+warn_duplicate image ships");
    println!(
        "face 2 (-multiply_defined suppress -warn_duplicate): the image ships ({} bytes); \
         the duplicate collision prints as `pgr: warning: duplicate symbol …` on stderr \
         (the advisory, the resolution policy unchanged)",
        outcome.file_size
    );

    // Face 3 — the relocatable refusal: the object's symtab is the input's,
    // verbatim.
    let mut full: Vec<OsString> = vec![
        "-r".into(),
        "-o".into(),
        dir.join("o.o").to_string_lossy().into_owned().into(),
        "-warn_duplicate".into(),
    ];
    full.extend(objs.iter().map(|p| p.to_string_lossy().into_owned().into()));
    match opts::parse(&full) {
        Ok(_) => panic!("the relocatable output must refuse the -warn_duplicate decision"),
        Err(err) => println!("face 3 (-r): refused — {:?}", miette::Report::new(err)),
    }

    println!("\nwarn_duplicate_link: ok");
}
