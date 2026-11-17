//! The load-provenance consumer example (M57): one small executable —
//! `main.o` binding `_greet` from `libgreet.a`, which also carries an
//! unreferenced member — asked *why did each member ride?* The lazy
//! pull names its seed and leaves the unreferenced member out (the
//! "why not" half of the question); `-all_load` names the eager family;
//! the JSON interchange renders both stories. The `-dead_strip_dylibs`
//! carriage rides the same report when the link carries input dylibs.
//!
//! Run: `cargo run -p pgr-driver --example why_load_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
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

/// `greet.o`: `_greet` — the member the fixpoint reaches.
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

/// `unused.o`: `_unused` — nothing references it (the pull skips it).
fn unused_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("unused.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_unused".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// Writes the corpus and links it through the driver's own parse + run
/// pair with `extra` argv.
fn run(dir: &std::path::Path, out: &str, extra: &[&str]) -> pgr_driver::LinkOutcome {
    std::fs::write(dir.join("main.o"), main_object()).unwrap();
    let mut a = ArchiveBuilder::new("libgreet.a");
    a.add_member("greet.o", greet_object());
    a.add_member("unused.o", unused_object());
    std::fs::write(dir.join("libgreet.a"), a.build()).unwrap();
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        dir.join(out).as_os_str().to_os_string(),
    ];
    for arg in extra {
        argv.push(std::ffi::OsString::from(arg));
    }
    argv.push(dir.join("main.o").as_os_str().to_os_string());
    argv.push(dir.join("libgreet.a").as_os_str().to_os_string());
    let parsed = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&parsed).expect("the link runs")
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    let dir = std::env::temp_dir().join(format!("pgr_why_load_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // 1. The reference-driven pull: greet.o rides for `_greet`; the
    //    unreferenced member stays out — the report says why, and also
    //    who never rode at all.
    println!("== the lazy pull: -why_load ==");
    run(&dir, "hello_lazy", &["-why_load"]);

    // 2. The eager family: `-all_load` admits every member; each row
    //    names the decision.
    println!("== the eager pull: -all_load -why_load ==");
    run(&dir, "hello_all", &["-all_load", "-why_load"]);

    // 3. The JSON interchange: the same story over the same inputs,
    //    rendered by the library face (`LoadReport::render_json`).
    println!("== the library face: LoadReport::render_json ==");
    let parsed_archive =
        pgr_format::parse_archive(&std::fs::read(dir.join("libgreet.a")).expect("reads"))
            .expect("the archive parses");
    let archives = vec![pgr_core::link::LinkArchive {
        name: dir.join("libgreet.a").display().to_string(),
        bytes: std::fs::read(dir.join("libgreet.a")).expect("reads"),
        index: parsed_archive
            .index
            .iter()
            .map(|e| (e.name.clone().into_bytes(), e.member))
            .collect(),
        members: parsed_archive
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
        bytes: main_object(),
    }];
    let result = pgr_core::link(&inputs, &archives, &pgr_core::layout::LinkConfig::default())
        .expect("the in-process link runs");
    println!("{}", result.loads.render_json());

    let _ = std::fs::remove_dir_all(&dir);
}
