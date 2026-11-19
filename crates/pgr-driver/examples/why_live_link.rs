//! The liveness-provenance consumer example (M92): one small
//! executable — `main.o` calling `_greet` (defined in `greet.o`)
//! through a `branch26`, an unreferenced `_dead` body riding in
//! `dead.o` — under `-dead_strip`, queried three ways. The driver face
//! (`-why_live`) prints the chains beside the link (the live body's
//! one-hop chain, the dead body's verdict); the library face
//! (`pgr_core::explain_live`) renders the same answer as the
//! deterministic JSON interchange. The vacuous query (a misspelled
//! name) and the premise mismatch (a link without `-dead_strip`) are
//! rendered as the refusals they are — the house convention: a vacuous
//! answer is never silently empty.
//!
//! Run: `cargo run -p pgr-driver --example why_live_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// `main.o`: `_main` (the entry root) calling `callee` through a
/// `branch26` at offset 0 — the entry atom carries the edge the strip
/// follows.
fn main_object(callee: &str) -> Vec<u8> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    b.add_section(ObjectSection::text(
        "__text",
        [0x9400_0000u32.to_le_bytes(), 0xD65F_03C0u32.to_le_bytes()].concat(),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: 0,
        value: 0,
        weak: false,
    });
    let _ = b.add_symbol(ObjectSymbol::Undefined {
        name: callee.into(),
        weak_ref: false,
    });
    b.section_mut(0).relocs.push(ObjectReloc::branch26(1).at(0));
    b.build().expect("the fixture object builds")
}

/// `greet.o`: `_greet` over a plain `ret` — the chain's tail.
fn greet_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("greet.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
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

/// `dead.o`: `_dead` defined and referenced by nothing — the strip
/// drops it, the verdict is the answer.
fn dead_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("dead.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_dead".into(),
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
    let greet = dir.join("greet.o");
    let dead = dir.join("dead.o");
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        dir.join(out).as_os_str().to_os_string(),
    ];
    for arg in extra {
        argv.push(std::ffi::OsString::from(arg));
    }
    argv.push(main.as_os_str().to_os_string());
    argv.push(greet.as_os_str().to_os_string());
    argv.push(dead.as_os_str().to_os_string());
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

    let dir = std::env::temp_dir().join(format!("pgr_why_live_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("main.o"), main_object("_greet")).unwrap();
    std::fs::write(dir.join("greet.o"), greet_object()).unwrap();
    std::fs::write(dir.join("dead.o"), dead_object()).unwrap();

    // 1. The driver face: the queries ride the command line beside
    //    `-dead_strip` — one chain per queried name, in flag order
    //    (the live body's keeper, then the dead body's verdict).
    println!("== the driver face: -dead_strip -why_live _greet -why_live _dead ==");
    run(
        &dir,
        "hello",
        &["-dead_strip", "-why_live", "_greet", "-why_live", "_dead"],
    )
    .expect("the queried link runs");

    // 2. The library face: the same story over the same inputs — the
    //    mark phase's own record on the link result — rendered as the
    //    deterministic JSON interchange (the M55 writer rules: fixed
    //    key order, one line, the escape table).
    println!("== the library face: explain_live -> render_json ==");
    let inputs = vec![
        pgr_core::link::LinkInput {
            name: dir.join("main.o").display().to_string(),
            bytes: main_object("_greet"),
        },
        pgr_core::link::LinkInput {
            name: dir.join("greet.o").display().to_string(),
            bytes: greet_object(),
        },
        pgr_core::link::LinkInput {
            name: dir.join("dead.o").display().to_string(),
            bytes: dead_object(),
        },
    ];
    let cfg = pgr_core::layout::LinkConfig {
        filetype: pgr_core::layout::OutputType::Execute,
        dead_strip: true,
        ..pgr_core::layout::LinkConfig::default()
    };
    let result = pgr_core::link(&inputs, &[], &cfg).expect("the in-process link runs");
    let live = result
        .liveness
        .as_ref()
        .expect("the strip ran: the record rides");
    let answer = pgr_core::explain_live(
        live,
        &result.objects,
        &result.resolution,
        &result.interner,
        "_greet",
    )
    .expect("the name stays live");
    println!("{}", answer.render_json());
    let text = pgr_core::explain_live(
        live,
        &result.objects,
        &result.resolution,
        &result.interner,
        "_dead",
    )
    .expect("the name resolves");
    println!("{}", text.render());

    // 3. The vacuous query: a misspelled name refuses the run — the
    //    misspelling named, the C-underscore hint the fix.
    println!("== the vacuous query: -why_live _grete ==");
    match run(&dir, "hello2", &["-dead_strip", "-why_live", "_grete"]) {
        Ok(_) => unreachable!("the misspelled query refuses"),
        Err(rendered) => println!("the refusal: {rendered}"),
    }

    // 4. The premise mismatch: without `-dead_strip` every definition
    //    rode — the query refuses with the fix named (the strip is the
    //    question's subject).
    println!("== the premise mismatch: -why_live without -dead_strip ==");
    match run(&dir, "hello3", &["-why_live", "_greet"]) {
        Ok(_) => unreachable!("the premise mismatch refuses"),
        Err(rendered) => println!("the refusal: {rendered}"),
    }

    let _ = std::fs::remove_dir_all(&dir);
}
