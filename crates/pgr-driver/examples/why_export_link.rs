//! The symbol-provenance consumer example (M56): one small executable —
//! `main.o` binding `_greet` from a pulled archive member — queried two
//! ways. The driver face (`-why_export`) prints the text reports beside
//! the link; the library face (`pgr_core::explain_export`) renders the
//! same answer as the deterministic JSON interchange. The vacuous query
//! (a misspelled name) is rendered as the refusal it is — miette help
//! text included, the fix and not just the verdict (the house
//! consumer-example convention).
//!
//! Run: `cargo run -p pgr-driver --example why_export_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ArchiveBuilder, ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// `main.o`: `_main` over a small `__text`; two 8-byte data pointers at
/// `__data` targeting `_greet` (the archive member's export).
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
        vec![0u8; 16],
        vec![
            ObjectReloc::unsigned(greet as u32).at(0),
            ObjectReloc::unsigned(greet as u32).at(8),
        ],
    ));
    b.build().expect("the fixture object builds")
}

/// `greet.o`: `_greet` over a small `__text` — the archive member the
/// S7 pull rides in.
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

/// Links `argv` (the corpus paths appended) through the driver's own
/// parse + run pair.
fn run(
    dir: &std::path::Path,
    out: &str,
    extra: &[&str],
) -> Result<pgr_driver::LinkOutcome, String> {
    let main = dir.join("main.o");
    let archive = dir.join("libgreet.a");
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        dir.join(out).as_os_str().to_os_string(),
    ];
    for arg in extra {
        argv.push(std::ffi::OsString::from(arg));
    }
    argv.push(main.as_os_str().to_os_string());
    argv.push(archive.as_os_str().to_os_string());
    let parsed = opts::parse(&argv).map_err(|e| format!("{:?}", miette::Report::new(e)))?;
    pgr_driver::run(&parsed).map_err(|e| e.to_string())
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    let dir = std::env::temp_dir().join(format!("pgr_why_export_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("main.o"), main_object()).unwrap();
    let mut archive = ArchiveBuilder::new("libgreet.a");
    archive.add_member("greet.o", greet_object());
    std::fs::write(dir.join("libgreet.a"), archive.build()).unwrap();

    // 1. The driver face: the query rides the command line — the
    //    reports print beside the link, one per queried name, in flag
    //    order (the pulled member's definition named, then the
    //    unreferenced entry point).
    println!("== the driver face: -why_export _greet -why_export _main ==");
    run(
        &dir,
        "hello",
        &["-why_export", "_greet", "-why_export", "_main"],
    )
    .expect("the queried link runs");

    // 2. The library face: the same story over the same inputs — main.o
    //    binding `_greet` from the pulled member — rendered as the
    //    deterministic JSON interchange (the M55 writer rules — fixed
    //    key order, one line, the escape table).
    println!("== the library face: explain_export -> render_json ==");
    let main_bytes = main_object();
    let archive_bytes = std::fs::read(dir.join("libgreet.a")).expect("the archive reads");
    let parsed = pgr_format::parse_archive(&archive_bytes).expect("the archive parses");
    let archives = vec![pgr_core::link::LinkArchive {
        name: dir.join("libgreet.a").display().to_string(),
        bytes: archive_bytes,
        index: parsed
            .index
            .iter()
            .map(|e| (e.name.clone().into_bytes(), e.member))
            .collect(),
        members: parsed
            .members
            .iter()
            .map(|m| pgr_core::link::LinkArchiveMember {
                name: m.name.clone(),
                offset: m.offset,
                size: m.size,
            })
            .collect(),
        all_load: false,
    }];
    let inputs = vec![pgr_core::link::LinkInput {
        name: dir.join("main.o").display().to_string(),
        bytes: main_bytes,
    }];
    let result = pgr_core::link(&inputs, &archives, &pgr_core::layout::LinkConfig::default())
        .expect("the in-process link runs");
    let index = pgr_core::ReverseIndex::build_all(&result.objects);
    let answer = pgr_core::explain_export(
        &index,
        &result.objects,
        &result.resolution,
        &result.interner,
        "_greet",
    )
    .expect("the name resolves");
    println!("{}", answer.render_json());

    // 3. The vacuous query: a misspelled name refuses the run — the
    //    misspelling named, the C-underscore hint the fix.
    println!("== the vacuous query: -why_export _grete ==");
    match run(&dir, "hello2", &["-why_export", "_grete"]) {
        Ok(_) => unreachable!("the misspelled query refuses"),
        Err(rendered) => println!("the refusal: {rendered}"),
    }

    let _ = std::fs::remove_dir_all(&dir);
}
