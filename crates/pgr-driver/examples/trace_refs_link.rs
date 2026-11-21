//! M113 — the reference trace: `-t` — ld64's "Print a trace of all
//! symbol references". Each symbol Pass 2's resolve visits rides the M54
//! observation seam's `on_reference` face (the name as the resolver saw
//! it, the input that carries it — one event per visit, in the walk's
//! own order), and the driver prints each to stderr. The trace is a
//! measurement, never a layout product; the relocatable output refuses
//! the knob (the object's symtab is the input's, verbatim).
//!
//! Run: `cargo run -p pgr-driver --example trace_refs_link`
//! (`PGR_TRACING=1` installs a tracing subscriber).

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, Parallelism, link, link_observed};
use pgr_core::observe::RefsCollector;
use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::ffi::OsString;

/// main.o: `_main` references `_greet`; greet.o defines `_greet` — the
/// resolved reference the trace names.
fn corpus(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut main = ObjectBuilder::new("main.o");
    let text = main.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    main.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let data = main.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    let undef = main.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    let slot = main.sym_index(undef);
    main.section_mut(data)
        .relocs
        .push(ObjectReloc::unsigned(slot).at(0));
    let mut greet = ObjectBuilder::new("greet.o");
    let gtext = greet.add_section(ObjectSection::text(
        "__text",
        vec![0xC0u8, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    greet.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: gtext,
        value: 0,
        weak: false,
    });
    let main_path = dir.join("main.o");
    std::fs::write(&main_path, main.build().expect("the fixture builds")).expect("main.o writes");
    let greet_path = dir.join("greet.o");
    std::fs::write(&greet_path, greet.build().expect("the fixture builds"))
        .expect("greet.o writes");
    vec![main_path, greet_path]
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt().init();
    }
    let dir = std::env::temp_dir().join(format!("pgr_trace_refs_link_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("the scratch dir creates");
    let objs = corpus(&dir);

    // Face 1 — the library face: the refs collector rides the M54
    // observation seam; the visits print in the walk's own order.
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
    let mut refs = RefsCollector::default();
    let result = link_observed(
        &inputs,
        &[],
        &LinkConfig::default(),
        Parallelism::Auto,
        None,
        &mut refs,
    )
    .expect("the corpus links");
    for event in refs.finish() {
        println!("face 1 (library seam): pgr: reference: {}", event.render());
    }
    let plain = link(&inputs, &[], &LinkConfig::default()).expect("the plain link plans");
    assert_eq!(
        format!("{:?}", plain.layout),
        format!("{:?}", result.layout),
        "the observation never moves a byte of the plan"
    );

    // Face 2 — the driver face: `-t` prints the same trace to stderr at
    // the end of the link (this example's own process stderr).
    let mut argv: Vec<OsString> = vec![
        "-o".into(),
        dir.join("app").to_string_lossy().into_owned().into(),
        "-t".into(),
    ];
    for obj in &objs {
        argv.push(obj.to_string_lossy().into_owned().into());
    }
    let o = opts::parse(&argv).expect("the surface parses");
    let outcome = pgr_driver::run(&o).expect("the link runs");
    println!(
        "face 2 (-t): the trace printed to stderr beside the outcome ({} bytes)",
        outcome.file_size
    );
    let image = std::fs::read(dir.join("app")).expect("the image reads");
    let strict = VerifyOptions::default();
    assert!(
        verify(&image, &strict).is_ok(&strict),
        "the image verifies strict"
    );

    // Face 3 — the relocatable refusal: the object's symtab is the
    // input's, verbatim.
    let mut argv: Vec<OsString> = vec![
        "-r".into(),
        "-o".into(),
        dir.join("o.o").to_string_lossy().into_owned().into(),
        "-t".into(),
    ];
    argv.push(objs[0].to_string_lossy().into_owned().into());
    match opts::parse(&argv) {
        Ok(_) => panic!("the relocatable output must refuse the trace"),
        Err(err) => println!("face 3 (-r): refused — {:?}", miette::Report::new(err)),
    }

    println!("\ntrace_refs_link: ok");
}
