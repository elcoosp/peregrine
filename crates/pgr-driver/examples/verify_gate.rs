//! The link's own gate, runnable (M73): a cold dylib link under
//! `-verify` — the strict verifier runs on the produced bytes before
//! the write, the verdict rides the outcome, and the file ships only
//! when the gate is clean — then the corrupted twin through the same
//! gate face ([`pgr_driver::verify_gate`]): the strict pass names the
//! findings, the refusal renders the fix (the miette help text), and a
//! gate run through the driver would have shipped nothing. The
//! `-no_adhoc` carve-out applies the audit's way: a config that refused
//! a signature is never a defect the gate names.
//!
//! ```sh
//! cargo run -p pgr-driver --example verify_gate
//! ```

use pgr_driver::verify_gate;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// One input object: `_main` and `_helper` over a small `__text`.
fn object(name: &str) -> Vec<u8> {
    let mut b = ObjectBuilder::new(name).set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        vec![],
    ));
    for (i, sym) in ["_main", "_helper"].iter().enumerate() {
        b.add_symbol(ObjectSymbol::Defined {
            name: (*sym).into(),
            section_index: text,
            value: (i * 4) as u64,
            weak: false,
        });
    }
    b.build().expect("the fixture object builds")
}

fn main() {
    // The demo runs unobserved by default; `PGR_TRACING=1` installs the
    // house tracing subscriber (the workspace convention — the demo
    // prints its own verdict either way).
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt::init();
    }

    let dir = std::env::temp_dir().join("pgr_example_verify_gate");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    let obj = dir.join("main.o");
    std::fs::write(&obj, object("main.o")).expect("the object writes");
    let out = dir.join("hello.dylib");

    // The cold link under `-verify`: the gate sits before the write, so
    // the outcome exists only when the image passed its own gate.
    let argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        out.display().to_string(),
        "-dylib".to_string(),
        "-verify".to_string(),
        obj.display().to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let opts = pgr_driver::opts::parse(&argv).expect("the argv parses");
    let outcome = pgr_driver::run(&opts).expect("the gated link runs");
    let summary = outcome.verify.expect("the gate's verdict rides");
    println!(
        "linked {} ({} bytes) — the gate's verdict: ok={} ({} error(s), {} warning(s))",
        outcome.output, outcome.file_size, summary.ok, summary.errors, summary.warnings,
    );
    assert!(out.is_file(), "a passing gate ships the file");

    // The corrupted twin through the same face: one byte flipped past
    // the segment contract — the strict pass names the finding, the
    // refusal renders the fix, and the driver would have exited before
    // writing anything.
    let mut corrupted = std::fs::read(&out).expect("the image reads");
    let mid = corrupted.len() / 2 + 0x4000;
    corrupted[mid] ^= 0xff;
    let gate = verify_gate(&corrupted, true);
    println!(
        "the corrupted twin: ok={} ({} issue(s) named):",
        gate.summary.ok,
        gate.issues.len()
    );
    for issue in &gate.issues {
        println!("    {issue}");
    }
    let rendered = gate.refusal().render();
    println!("-- the refusal the driver would have printed --");
    println!("{rendered}");
    assert!(!gate.summary.ok, "the corrupted image fails its gate");
}
