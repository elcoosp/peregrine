//! The gate's check selection, runnable (M77): a dylib link under
//! `-verify -verify-checks <families>` — the M12 selector narrows the
//! link's own gate to the named families, the same subtractive contract
//! the verifier CLI's `--checks` carries, on the cold lane. The narrowed
//! gate's honest face on a corrupted twin: the finding the selection
//! named refuses, the finding it did not name passes — selection is
//! strictly subtractive, never a re-shape — and the refusal renders the
//! fix (the miette help text) exactly like the full gate's. The
//! selection rides the resident lane too (wire v44): the session's
//! served pass narrows to the same families, so one selector governs
//! both lanes.
//!
//! ```sh
//! cargo run -p pgr-driver --example verify_checks_gate
//! ```

use pgr_driver::{verify_gate, verify_gate_selected};
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

    let dir = std::env::temp_dir().join("pgr_example_verify_checks_gate");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    let obj = dir.join("main.o");
    std::fs::write(&obj, object("main.o")).expect("the object writes");
    let out = dir.join("hello.dylib");

    // The cold link under the selected gate: the strict pass narrows to
    // the named families, the verdict rides the outcome, the file ships
    // only when the selected pass is clean.
    let argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        out.display().to_string(),
        "-dylib".to_string(),
        "-verify".to_string(),
        "-verify-checks".to_string(),
        "segments,signature".to_string(),
        obj.display().to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let opts = pgr_driver::opts::parse(&argv).expect("the argv parses");
    let outcome = pgr_driver::run(&opts).expect("the gated link runs");
    let summary = outcome.verify.expect("the gate's verdict rides");
    println!(
        "linked {} ({} bytes) — the selected gate's verdict: ok={} ({} error(s), {} warning(s))",
        outcome.output, outcome.file_size, summary.ok, summary.errors, summary.warnings,
    );

    // The corrupted twin through the narrowed face: one byte flipped —
    // its finding rides the signature family the selection named, the
    // gate refuses, the refusal renders the fix.
    let mut corrupted = std::fs::read(&out).expect("the image reads");
    let mid = corrupted.len() / 2 + 0x4000;
    corrupted[mid] ^= 0xff;
    let selection = pgr_verify::CheckSet::parse("segments,signature").expect("canonical names");
    let gate = verify_gate_selected(&corrupted, true, &selection);
    println!(
        "the corrupted twin (segments,signature): ok={} ({} issue(s) named):",
        gate.summary.ok,
        gate.issues.len()
    );
    for issue in &gate.issues {
        println!("    {issue}");
    }
    assert!(!gate.summary.ok, "the selected family names the finding");

    // The same bytes through a narrower selection: the finding rides a
    // family this selection did not name — the gate passes it. Selection
    // is strictly subtractive; the full pass names it either way.
    let segments_only = pgr_verify::CheckSet::parse("segments").expect("canonical names");
    let narrow = verify_gate_selected(&corrupted, true, &segments_only);
    let full = verify_gate(&corrupted, true);
    println!(
        "the same bytes, segments only: ok={} (the full pass: ok={}, {} issue(s))",
        narrow.summary.ok,
        full.summary.ok,
        full.issues.len()
    );
    assert!(narrow.summary.ok, "the unselected finding stays out");
    assert!(!full.summary.ok, "the full pass names it");
}
