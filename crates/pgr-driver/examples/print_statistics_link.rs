//! M112 — the link-statistics report: `-print_statistics` — ld64's
//! "Print statistics about the linker's performance". The counts the
//! link's own passes already had in hand — the objects Pass 1 parsed and
//! the names the interner batched (the M54 observation seam's phase
//! details), the fixups Pass 3 planned and the bytes the emit produced —
//! and the wall time, rendered to stderr at the end of the link. The
//! report is a measurement, never a layout product; the relocatable
//! output refuses the knob (the object path has no full-emit layout or
//! fixup planning to report in the same way).
//!
//! Run: `cargo run -p pgr-driver --example print_statistics_link`
//! (`PGR_TRACING=1` installs a tracing subscriber).

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, Parallelism, link, link_observed};
use pgr_core::statistics::StatsCollector;
use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::ffi::OsString;
use std::time::Instant;

/// hello.o: `_main` references `_greet` — one bind slot, the counts the
/// report names.
fn hello() -> Vec<u8> {
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
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    let undef = b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    let slot = b.sym_index(undef);
    b.section_mut(data)
        .relocs
        .push(ObjectReloc::unsigned(slot).at(0));
    b.build().expect("the fixture object builds")
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt().init();
    }
    let dir =
        std::env::temp_dir().join(format!("pgr_print_statistics_link_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("the scratch dir creates");
    let bytes = hello();
    let obj_path = dir.join("hello.o");
    std::fs::write(&obj_path, &bytes).expect("the object writes");
    let inputs = vec![LinkInput {
        name: "hello.o".into(),
        bytes: bytes.clone(),
    }];

    // Face 1 — the library face: the stats collector rides the M54
    // observation seam, the counts finish off the run's own product, the
    // render is the report the driver prints. The unresolved `_greet`
    // rides the flat-lookup slot (the `-undefined dynamic_lookup`
    // contract — the reference is the report's subject here).
    let cfg = LinkConfig {
        undefined_policy: pgr_core::resolve::UndefinedPolicy::DynamicLookup,
        ..LinkConfig::default()
    };
    let mut stats = StatsCollector::default();
    let started = Instant::now();
    let result = link_observed(&inputs, &[], &cfg, Parallelism::Auto, None, &mut stats)
        .expect("the corpus links");
    let report = stats.finish(
        result.layout.fixups.slot_count,
        result.layout.file_size,
        started.elapsed(),
    );
    print!("face 1 (library seam):\n{}", report.render());
    let plain = link(&inputs, &[], &cfg).expect("the plain link plans");
    assert_eq!(
        format!("{:?}", plain.layout),
        format!("{:?}", result.layout),
        "the observation never moves a byte of the plan"
    );

    // Face 2 — the driver face: `-print_statistics` renders the same
    // report to stderr at the end of the link (this example's own
    // process stderr). The unresolved `_greet` rides the warning policy
    // beside the report (the run's faces are independent).
    let argv: Vec<OsString> = vec![
        "-o".into(),
        dir.join("app").to_string_lossy().into_owned().into(),
        "-undefined".into(),
        "dynamic_lookup".into(),
        "-print_statistics".into(),
        obj_path.to_string_lossy().into_owned().into(),
    ];
    let o = opts::parse(&argv).expect("the surface parses");
    let outcome = pgr_driver::run(&o).expect("the link runs");
    println!(
        "face 2 (-print_statistics): the report printed to stderr beside the outcome \
         ({} bytes)",
        outcome.file_size
    );
    let image = std::fs::read(dir.join("app")).expect("the image reads");
    let strict = VerifyOptions::default();
    assert!(
        verify(&image, &strict).is_ok(&strict),
        "the image verifies strict"
    );

    // Face 3 — the relocatable refusal: the object path has no full-emit
    // layout or fixup planning to report in the same way.
    let argv: Vec<OsString> = vec![
        "-r".into(),
        "-o".into(),
        dir.join("o.o").to_string_lossy().into_owned().into(),
        "-print_statistics".into(),
        obj_path.to_string_lossy().into_owned().into(),
    ];
    match opts::parse(&argv) {
        Ok(_) => panic!("the relocatable output must refuse the report"),
        Err(err) => println!("face 3 (-r): refused — {:?}", miette::Report::new(err)),
    }

    println!("\nprint_statistics_link: ok");
}
