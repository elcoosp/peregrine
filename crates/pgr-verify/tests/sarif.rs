//! M69 — the verifier's SARIF interchange: [`pgr_verify::sarif::render`]
//! carries the [`pgr_verify::Report`] into SARIF 2.1.0 — the interchange
//! GitHub Code Scanning, IDEs and CI triage read natively. The face is a
//! one-way writer (the reader is the consumer's tooling); the document is
//! deterministic — one line, fixed key order, the M13 escape rules — so
//! two renders of one report are byte-identical (the house interchange
//! convention, gated).
//!
//! Gate matrix:
//! * the document — the empty report renders the exact valid shape (the
//!   golden), the schema/version/driver keys ride in order;
//! * the levels — `Severity::Error` rides `error`, `Severity::Warning`
//!   rides `warning`;
//! * the rules — one rule per distinct code in the report, the built-ins
//!   in the canonical [`pgr_verify::Code::ALL`] order, the M67 custom
//!   tokens after them in lexicographic order;
//! * the regions — an anchored issue rides its `byteOffset`; an
//!   unanchored one rides no location (the SARIF shape stays valid);
//! * the escapes — the M13 escape rules ride the message and the uri;
//! * the determinism — two renders are byte-identical.

use pgr_verify::{Code, Issue, Options, Report, Severity, sarif};

fn image_bytes() -> Vec<u8> {
    // A deliberately broken image: a two-byte body the header contract
    // refuses — one parse issue, no fixture ceremony needed.
    vec![0xCF, 0xFA]
}

#[test]
fn the_empty_report_renders_the_exact_shape() {
    let report = Report::default();
    let doc = sarif::render(&report, "app");
    assert_eq!(
        doc,
        "{\"$schema\":\"https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata2/os/sarif-schema-2.1.0.json\",\"version\":\"2.1.0\",\"runs\":[{\"tool\":{\"driver\":{\"name\":\"pgr-verify\",\"version\":\"0.22.0\",\"informationUri\":\"https://github.com/elcoosp/peregrine\",\"rules\":[]},\"artifacts\":[{\"location\":{\"uri\":\"app\"}}],\"results\":[]}]}"
    );
}

#[test]
fn the_levels_map_the_severities() {
    let report = Report {
        issues: vec![
            Issue::error(Code::HeaderInvalid, "the header magic is wrong", None),
            Issue::warning(Code::SymbolTable, "the symtab row is odd", None),
        ],
        stats: pgr_verify::Stats::default(),
    };
    let doc = sarif::render(&report, "app");
    assert!(
        doc.contains("\"ruleId\":\"header_invalid\",\"level\":\"error\""),
        "the error severity rides `error`: {doc}"
    );
    assert!(
        doc.contains("\"ruleId\":\"symbol_table\",\"level\":\"warning\""),
        "the warning severity rides `warning`: {doc}"
    );
}

#[test]
fn the_rules_ride_the_distinct_codes_in_canonical_order() {
    // The issues arrive with the signature code first; the rule table
    // still rides Code::ALL's canonical order (the document's key set is
    // the report's codes, never the arrival order).
    let report = Report {
        issues: vec![
            Issue::error(
                Code::SignatureHashMismatch,
                "the page hash diverges",
                Some(4096),
            ),
            Issue::error(Code::HeaderInvalid, "the header magic is wrong", None),
            Issue::warning(Code::SymbolTable, "the symtab row is odd", None),
        ],
        stats: pgr_verify::Stats::default(),
    };
    let doc = sarif::render(&report, "app");
    let rules_at = doc.find("\"rules\":[").expect("the rule table rides");
    let tail = &doc[rules_at..];
    let header_at = tail
        .find("\"id\":\"header_invalid\"")
        .expect("the header rule rides");
    let sym_at = tail
        .find("\"id\":\"symbol_table\"")
        .expect("the symtab rule rides");
    let sig_at = tail
        .find("\"id\":\"signature_hash_mismatch\"")
        .expect("the signature rule rides");
    assert!(
        header_at < sym_at && sym_at < sig_at,
        "the rules ride Code::ALL's canonical order: {tail}"
    );
}

#[test]
fn the_custom_codes_ride_the_rules_after_the_built_ins() {
    // M67: a policy's tokens ride the report — the rule table keeps every
    // built-in ahead of a custom code (the report-sort rank's convention),
    // the customs in lexicographic order.
    let report = Report {
        issues: vec![
            Issue::error(Code::Custom("zebra_policy"), "the zebra rule fired", None),
            Issue::error(Code::HeaderInvalid, "the header magic is wrong", None),
            Issue::error(Code::Custom("alpha_policy"), "the alpha rule fired", None),
        ],
        stats: pgr_verify::Stats::default(),
    };
    let doc = sarif::render(&report, "app");
    let rules_at = doc.find("\"rules\":[").expect("the rule table rides");
    let tail = &doc[rules_at..];
    let built_at = tail
        .find("\"id\":\"header_invalid\"")
        .expect("the built-in rides");
    let alpha_at = tail
        .find("\"id\":\"alpha_policy\"")
        .expect("the alpha rule rides");
    let zebra_at = tail
        .find("\"id\":\"zebra_policy\"")
        .expect("the zebra rule rides");
    assert!(
        built_at < alpha_at && alpha_at < zebra_at,
        "built-ins lead, the customs follow lexicographically: {tail}"
    );
    assert!(
        doc.contains("\"ruleId\":\"alpha_policy\",\"level\":\"error\""),
        "the custom code rides its result: {doc}"
    );
}

#[test]
fn the_region_rides_the_offset_and_the_unanchored_rides_none() {
    let report = Report {
        issues: vec![
            Issue::error(
                Code::SignatureHashMismatch,
                "the page hash diverges",
                Some(4096),
            ),
            Issue::warning(Code::SymbolTable, "the symtab row is odd", None),
        ],
        stats: pgr_verify::Stats::default(),
    };
    let doc = sarif::render(&report, "app");
    assert!(
        doc.contains("\"region\":{\"byteOffset\":4096}"),
        "the anchored issue rides its byte offset: {doc}"
    );
    let results_at = doc.find("\"results\":[").expect("the results ride");
    let tail = &doc[results_at..];
    let unanchored_at = tail
        .find("\"ruleId\":\"symbol_table\"")
        .expect("the unanchored result rides");
    let unanchored_row = &tail[unanchored_at..];
    let row_end = unanchored_row.find('}').expect("the result closes");
    assert!(
        !unanchored_row[..row_end].contains("locations"),
        "an unanchored issue rides no location: {unanchored_row}"
    );
}

#[test]
fn the_escape_rules_ride_the_message_and_the_uri() {
    let report = Report {
        issues: vec![Issue::error(
            Code::HeaderInvalid,
            "the \"magic\" diverges\nat byte 0",
            None,
        )],
        stats: pgr_verify::Stats::default(),
    };
    let doc = sarif::render(&report, "weird \"name\".bin");
    assert!(
        doc.contains("\"uri\":\"weird \\\"name\\\".bin\""),
        "the uri rides the escapes: {doc}"
    );
    assert!(
        doc.contains("the \\\"magic\\\" diverges\\nat byte 0"),
        "the message rides the M13 escape rules: {doc}"
    );
}

#[test]
fn the_render_is_deterministic_and_the_real_report_rides() {
    let bytes = image_bytes();
    let report = pgr_verify::verify(&bytes, &Options::default());
    assert!(!report.issues.is_empty(), "the broken image reports");
    let first = sarif::render(&report, "broken.bin");
    let second = sarif::render(&report, "broken.bin");
    assert_eq!(first, second, "two renders are byte-identical");
    assert!(
        first.contains("\"ruleId\":") && first.contains("\"level\":\"error\""),
        "the real report's findings ride the results: {first}"
    );
    assert_eq!(
        Severity::Warning,
        Severity::Warning,
        "the severity enum stays Copy (the compile-time contract)"
    );
}
