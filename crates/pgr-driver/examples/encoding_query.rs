//! The encoding-query consumer example (M10 rung 3, slice 2): the
//! build-system loop the roadmap scopes — *ask* the driver surface
//! which fixup encoding a `-platform_version` target plans, *then*
//! link the at-floor row with exactly that platform/target and
//! strict-verify the image. The query
//! (`pgr_driver::fixup_encoding_report`) reads the same per-platform
//! floor table the layout encodes (`pgr_format::consts::
//! chained_fixups_floor`, via `pgr_core::platform::FixupEncoding`),
//! so tooling predicts the encoding without re-deriving the table,
//! and the below-floor rows render their miette advisory (the fix,
//! not just the verdict) — the CLI's `--print-fixup-encoding` is the
//! same seam one shell call earlier.
//!
//! Run: `cargo run -p pgr-driver --example encoding_query`
//! (`PGR_TRACING=1` installs a subscriber so the seam's spans print —
//! the same inert-until-subscriber convention the binaries use).

use std::path::PathBuf;

use pgr_core::layout::LinkConfig;
use pgr_driver::fixup_encoding_report;
use pgr_driver::opts::Options;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// hello.o: `_main` ADRP+ADD loads `_msg`, `mov w0, #0`, ret — the
/// pointer relocations give the image real chained-fixup slots, so the
/// queried encoding is the encoding the output actually carries.
fn hello() -> Vec<u8> {
    let words: Vec<u32> = vec![
        0x9000_0000, // adrp x0, _msg@page
        0x9100_0000, // add x0, x0, #_msg@pageoff
        0x5280_0000, // mov w0, #0
        0xD65F_03C0, // ret
    ];
    let text: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let mut b = ObjectBuilder::new("hello.o");
    let sect = b.add_section(ObjectSection::text(
        "__text",
        text,
        vec![
            ObjectReloc::addend(0).at(0),
            ObjectReloc::page21(1).at(0),
            ObjectReloc::addend(0).at(4),
            ObjectReloc::pageoff12(1).at(4),
        ],
    ));
    b.add_section(ObjectSection::cstring("hello, peregrine\n"));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    b.build().expect("fixture builds")
}

fn main() {
    // The query spans stay inert until a subscriber installs — the
    // workspace convention (the binaries do it under their debug envs).
    // DEBUG surfaces the decision event: platform, minos, floor and the
    // named encoding on every row.
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    // 1. The query: every linked platform asked once below and once at
    //    its chained-fixups floor. Below-floor rows answer classic
    //    opcodes and carry the miette advisory; the answer comes from
    //    the same table the layout reads, never a re-derivation.
    println!("{:<9} {:>8}  {}", "platform", "target", "encoding (Pass 3 plans)");
    for (name, minos, sdk) in [
        ("macos", "11.0", "14.0"),
        ("macos", "12.0", "14.0"),
        ("ios", "14.0", "16.0"),
        ("ios", "15.0", "16.0"),
        ("watchos", "7.0", "10.0"),
        ("visionos", "1.0", "1.0"),
    ] {
        let report = fixup_encoding_report(name, minos, sdk).expect("the linked platforms query");
        println!("{:<9} {:>8}  {:?}", name, report.minos_text(), report.encoding);
        if let Some(advisory) = report.advisory {
            println!("{:?}", miette::Report::new(advisory));
        }
    }

    // 2. The at-floor row links for real: the query said chained
    //    fixups, so the link honors the same platform/target triple and
    //    the output must carry the chained words — the strict verifier
    //    (hash recompute on) closes the loop the roadmap scopes.
    let at_floor = fixup_encoding_report("macos", "12.0", "14.0").expect("the at-floor row");
    assert!(at_floor.advisory.is_none(), "the at-floor row is advisory-free");
    let dir = std::env::temp_dir().join("pgr_driver_encoding_query");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    let obj_path: PathBuf = dir.join("hello.o");
    let out_path = dir.join("hello");
    std::fs::write(&obj_path, hello()).expect("write hello.o");
    let opts = Options {
        inputs: vec![obj_path.display().to_string()],
        output: out_path.display().to_string(),
        config: LinkConfig {
            ident: "encoding-query".into(),
            platform: pgr_format::consts::PLATFORM_MACOS,
            minos: at_floor.minos,
            sdk: 0x000E_0000,
            ..LinkConfig::default()
        },
        ..Options::default()
    };
    let outcome = pgr_driver::run(&opts).expect("the at-floor link");
    println!(
        "\nat-floor link: wrote {} ({} bytes, {} chained-fixup slot(s), entryoff {:#x})",
        outcome.output, outcome.file_size, outcome.fixup_slots, outcome.entryoff
    );
    let bytes = std::fs::read(&out_path).expect("read the linked image");
    let strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let report = verify(&bytes, &strict);
    assert!(
        report.is_ok(&strict) && report.issues.is_empty(),
        "the at-floor image must verify strict: {:#?}",
        report.issues
    );
    println!(
        "pgr-verify: strict pass clean — the encoding the query predicted \
         is the encoding the image carries"
    );
}
