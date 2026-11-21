//! M116 — the common-symbol advisory: `-warn_commons` — ld64's face
//! ("Print a warning whenever a tentative definition in an object file
//! is found", the `ld64` man page). The decision rides the M107
//! `CommonsPolicy` seam without changing the resolution policy itself:
//! where every input common symbol's name resolved — a local definition
//! (the common's own coalesced ride included) or a linked dylib's
//! export — the resolver records the landing and the driver's advisory
//! face tallies it to stderr, still exiting 0. The advisory is a
//! measurement, never a layout product: the bytes never move.
//!
//! Run: `cargo run -p pgr-driver --example warn_commons_link`
//! (`PGR_TRACING=1` installs a tracing subscriber).

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link};
use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use std::ffi::OsString;

/// `common.o`: `_main` plus the `_tentative` common (the advisory's
/// subject — the tentative definition the resolution lands).
fn common_object(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut b = ObjectBuilder::new("common.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Common {
        name: "_tentative".into(),
        size: 32,
        align_log2: 3,
    });
    let path = dir.join("common.o");
    std::fs::write(&path, b.build().expect("the fixture builds")).expect("common.o writes");
    vec![path]
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt().init();
    }
    let dir = std::env::temp_dir().join(format!("pgr_warn_commons_link_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("the scratch dir creates");
    let objs = common_object(&dir);
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

    // Face 1 — the library face: the decision never moves the bytes
    // (the M109 pattern's face), and the advisory walk derives the
    // landing entries on the on face only (the common became the
    // definition — the missing-extern hazard the ld64 man page names).
    let plan_for = |warn: bool| {
        link(
            &inputs,
            &[],
            &LinkConfig {
                warn_commons: warn,
                ..LinkConfig::default()
            },
        )
        .expect("the link plans")
    };
    let off = plan_for(false);
    let on = plan_for(true);
    assert_eq!(
        off.layout.header_bytes, on.layout.header_bytes,
        "the advisory face never moves the bytes"
    );
    let landings: Vec<&str> = on.resolution.warn_commons_open().collect();
    assert!(
        landings
            .iter()
            .any(|e| e.contains("'_tentative'") && e.contains("resolved to 'input 0'")),
        "the landing names the definition the common resolved to: {landings:?}"
    );
    assert!(
        off.resolution.warn_commons_open().next().is_none(),
        "the off decision records nothing"
    );
    println!(
        "face 1 (library seam): the advisory is a measurement, never a layout product \
         ({} bytes on both faces); the landing: {}",
        on.layout.file_size,
        landings.first().copied().unwrap_or("")
    );

    // Face 2 — the driver face: `-warn_commons` prints the landing to
    // stderr and still exits 0 (the M103 warning-face pattern — the
    // image writes; run with 2>&1 to see the face).
    let mut argv: Vec<OsString> = vec![
        "-o".into(),
        dir.join("app").to_string_lossy().into_owned().into(),
        "-warn_commons".into(),
    ];
    argv.extend(objs.iter().map(|p| p.to_string_lossy().into_owned().into()));
    let o = opts::parse(&argv).expect("the surface parses");
    let outcome = pgr_driver::run(&o).expect("the link runs");
    println!(
        "face 2 (-warn_commons): the image ships beside the advisory ({} bytes) — \
         `pgr: warning: common symbol '_tentative' resolved to 'input 0'` printed to stderr",
        outcome.file_size
    );

    // Face 3 — the relocatable refusal: the object's symtab is the
    // input's, verbatim.
    let mut full: Vec<OsString> = vec![
        "-r".into(),
        "-o".into(),
        dir.join("o.o").to_string_lossy().into_owned().into(),
        "-warn_commons".into(),
    ];
    full.extend(objs.iter().map(|p| p.to_string_lossy().into_owned().into()));
    match opts::parse(&full) {
        Ok(_) => panic!("the relocatable output must refuse the advisory"),
        Err(err) => println!("face 3 (-r): refused — {:?}", miette::Report::new(err)),
    }

    println!("\nwarn_commons_link: ok");
}
