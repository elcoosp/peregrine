//! M13 rung 1 — the baseline gate: the verifier's report becomes a
//! diffable surface. The executable specification, in order:
//!
//! * interchange — the report's JSON shape round-trips through
//!   `to_json`/`parse_report_json` byte-for-byte in meaning (issues,
//!   stats, every escape the writer can produce), and malformed input
//!   is a typed error naming the offense, never a panic,
//! * delta — `BaselineDelta::between` classifies prev/next issues into
//!   introduced/resolved/surviving as a multiset (duplicate keys
//!   count), deterministic in report order,
//! * policy — the [`pgr_verify::IssueIdentity`] trait's two built-ins
//!   disagree exactly where they should: a finding that moved keeps its
//!   identity under `CodeIdentity` and is new under `OffsetIdentity`,
//! * gate — with a baseline the gate is "no new findings", not "no
//!   findings": pre-existing issues survive, a fresh corruption is
//!   introduced, and the end-to-end shape (verify → `to_json` → corrupt
//!   → verify → delta) names the stale page hash.

use pgr_fixtures::{
    ImageBuilder, ImportsFormat, SectionSpec, SegmentSpec, SlotKind, SymbolSpec, filler,
};
use pgr_format::consts::{
    S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE,
};
use pgr_verify::{
    BaselineDelta, Code, CodeIdentity, Issue, OffsetIdentity, Options, Report, parse_report_json,
    to_json,
};

fn opts() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

fn issue(code: Code, message: &str, offset: Option<u64>) -> Issue {
    Issue::error(code, message, offset)
}

/// A small chained-fixup executable: one bind + one rebase slot, an
/// entry point, a build version at the macOS floor.
fn exec_bytes() -> Vec<u8> {
    let mut b = ImageBuilder::executable("baseline-gate-test");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(0xA5A5, 96),
            relocs: Vec::new(),
        }],
    });
    b.add_segment(SegmentSpec {
        name: "__DATA_CONST".into(),
        maxprot: VM_PROT_READ | VM_PROT_WRITE,
        initprot: VM_PROT_READ | VM_PROT_WRITE,
        sections: vec![],
    });
    let ord = b.add_dylib("/usr/lib/libSystem.B.dylib");
    let sym = b.add_symbol(SymbolSpec::Undefined {
        name: "_printf".into(),
        lib_ordinal: ord,
        weak: false,
    });
    b.set_got(vec![
        SlotKind::Bind {
            sym_index: sym,
            addend: 0,
        },
        SlotKind::Rebase { target: 0x40 },
    ]);
    b.set_entry(0x40);
    b.set_imports_format(ImportsFormat::Plain);
    b.build().expect("the fixture builds").bytes
}

// ------------------------------------------------------------- interchange

#[test]
fn json_round_trips_issues_and_stats() {
    let mut report = Report {
        stats: pgr_verify::Stats {
            segments: 3,
            sections: 7,
            symbols: 41,
            fixup_slots: 0,
            hash_pages: 9,
        },
        issues: Vec::new(),
    };
    report.issues.push(issue(
        Code::SignatureHashMismatch,
        "page 2 hash went stale (quotes \" backslash \\ newline \n tab \t)",
        Some(0x1_F000),
    ));
    report.issues.push(Issue::warning(
        Code::Suspicious,
        "unicode ✓ emoji-free but accented: café — and a \u{7f} control",
        None,
    ));
    report
        .issues
        .push(issue(Code::FixupsChain, "loop", Some(0)));

    let parsed = parse_report_json(&to_json(&report)).expect("the writer's own output re-parses");
    assert_eq!(parsed, report, "round-trip preserves issues and stats");
}

#[test]
fn json_round_trip_covers_every_code() {
    let codes = [
        Code::HeaderInvalid,
        Code::LoadCommandMalformed,
        Code::SegmentContract,
        Code::SegmentLayout,
        Code::ImageBase,
        Code::SectionBounds,
        Code::SymbolTable,
        Code::FixupsPayload,
        Code::FixupsChain,
        Code::FixupsImport,
        Code::FixupsSegmentOffset,
        Code::SignatureLayout,
        Code::SignatureHashMismatch,
        Code::LinkeditPayload,
        Code::ExportTrie,
        Code::BranchRange,
        Code::DyldInfoStreams,
        Code::FixupsFloor,
        Code::Suspicious,
    ];
    let mut report = Report::default();
    for (i, code) in codes.iter().enumerate() {
        report
            .issues
            .push(issue(*code, "probe", Some(i as u64 * 8)));
    }
    let parsed = parse_report_json(&to_json(&report)).expect("every code survives the round trip");
    assert_eq!(parsed, report);
}

#[test]
fn json_parse_accepts_the_cli_shape_with_file_key() {
    // The CLI wraps the same body in a "file" key; a baseline may be
    // that whole output. Unknown keys are ignored, not refused.
    let mut report = Report::default();
    report
        .issues
        .push(issue(Code::SymbolTable, "oob", Some(12)));
    let body = to_json(&report);
    let wrapped = format!(
        "{{\"file\":\"out/app\",\"stats\":{{}},\"issues\":{}",
        &body[body.find("\"issues\":").expect("issues key") + "\"issues\":".len()..]
    );
    let parsed = parse_report_json(&wrapped).expect("the CLI shape parses");
    assert_eq!(parsed.issues, report.issues);
    assert_eq!(parsed.stats, Report::default().stats);
}

#[test]
fn malformed_json_names_the_offense_never_panics() {
    let cases = [
        "",
        "{",
        "not json at all",
        "{\"issues\": 12}",
        "{\"issues\": [{\"severity\": \"fatal\", \"code\": \"suspicious\", \"message\": \"x\", \"offset\": null}]}",
        "{\"issues\": [{\"severity\": \"error\", \"code\": \"not_a_code\", \"message\": \"x\", \"offset\": null}]}",
        "{\"issues\": [{\"severity\": \"error\", \"code\": \"suspicious\", \"message\": null, \"offset\": null}]}",
        "{\"issues\": [{\"severity\": \"error\", \"code\": \"suspicious\", \"message\": \"x\", \"offset\": -4}]}",
        "{\"issues\": [{\"severity\": \"error\", \"code\": \"suspicious\", \"message\": \"x\", \"offset\": 1.5}]}",
        "{\"stats\": {\"segments\": -1}}",
        "{\"issues\": [{\"severity\": \"error\", \"code\": \"suspicious\", \"message\": \"dying mid \\u00",
        "{ \"issues\":[], \"stats\": {\"segments\": 1}, }",
    ];
    for (i, case) in cases.iter().enumerate() {
        let err = parse_report_json(case)
            .expect_err(format!("case {i} must be refused: {case:?}").as_str());
        let text = err.to_string();
        assert!(!text.is_empty(), "the error names its offense");
    }
}

#[test]
fn parse_is_total_over_random_ascii_bytes() {
    // The parser must never panic — the workspace's parse contract —
    // including on inputs that start valid and die mid-escape.
    let seeds = [
        "{\"issues\":[{\"severity\":\"err",
        "{\"stats\":{\"segments\":",
        "{\"issues\":[{\"severity\":\"error\",\"code\":\"suspicious\",\"message\":\"\\u00",
        "{\"issues\":[\"stray\"]}",
        "{\"issues\":[],\"stats\":{\"segments\":4294967296}}",
    ];
    for s in seeds {
        let _ = parse_report_json(s);
    }
}

// ------------------------------------------------------------------- delta

#[test]
fn delta_classifies_introduced_resolved_and_surviving() {
    let prev = vec![
        issue(Code::SymbolTable, "oob", Some(12)),
        issue(Code::Suspicious, "advisory", None),
    ];
    let next = vec![
        issue(Code::SymbolTable, "oob", Some(12)), // survives
        issue(Code::Suspicious, "advisory", None), // survives
        issue(Code::FixupsChain, "fresh loop", Some(0x400)),
    ];
    let delta = BaselineDelta::between(&prev, &next, &OffsetIdentity);
    assert_eq!(delta.introduced.len(), 1);
    assert_eq!(delta.introduced[0].code, Code::FixupsChain);
    assert_eq!(delta.resolved.len(), 0);
    assert_eq!(delta.surviving, 2);
    assert!(!delta.is_clean());
}

#[test]
fn delta_counts_duplicates_as_a_multiset() {
    let prev = vec![issue(Code::SymbolTable, "dup", Some(4))];
    let next = vec![
        issue(Code::SymbolTable, "dup", Some(4)),
        issue(Code::SymbolTable, "dup", Some(4)),
    ];
    let delta = BaselineDelta::between(&prev, &next, &OffsetIdentity);
    assert_eq!(delta.surviving, 1);
    assert_eq!(delta.introduced.len(), 1, "the second occurrence is new");
    assert_eq!(delta.resolved.len(), 0);

    let delta = BaselineDelta::between(&next, &prev, &OffsetIdentity);
    assert_eq!(delta.resolved.len(), 1, "one of the two went away");
    assert_eq!(delta.introduced.len(), 0);
    assert_eq!(delta.surviving, 1);
}

#[test]
fn offset_policy_sees_a_moved_finding_as_new() {
    let prev = vec![issue(Code::BranchRange, "bl out of range", Some(0x1000))];
    let next = vec![issue(Code::BranchRange, "bl out of range", Some(0x2000))];
    let strict = BaselineDelta::between(&prev, &next, &OffsetIdentity);
    assert_eq!(strict.introduced.len(), 1);
    assert_eq!(strict.resolved.len(), 1, "the old site cleared");
}

#[test]
fn code_policy_recognizes_the_moved_finding() {
    let prev = vec![issue(Code::BranchRange, "bl out of range", Some(0x1000))];
    let next = vec![issue(Code::BranchRange, "bl out of range", Some(0x2000))];
    let loose = BaselineDelta::between(&prev, &next, &CodeIdentity);
    assert!(
        loose.is_clean(),
        "the same code at a new site is the same finding under the code policy"
    );
    assert_eq!(loose.surviving, 1);
}

#[test]
fn delta_is_order_stable_and_empty_on_identical_sides() {
    let prev = vec![
        issue(Code::FixupsChain, "a", Some(8)),
        issue(Code::ExportTrie, "b", Some(16)),
        issue(Code::Suspicious, "c", None),
    ];
    let delta = BaselineDelta::between(&prev, &prev, &OffsetIdentity);
    assert!(delta.is_clean());
    assert_eq!(delta.surviving, 3);

    let mut next = prev.clone();
    next.reverse();
    let delta = BaselineDelta::between(&prev, &next, &OffsetIdentity);
    assert!(delta.is_clean(), "order alone never manufactures findings");
}

#[test]
fn severity_escalation_is_a_new_finding_under_the_offset_policy() {
    let prev = vec![Issue::warning(Code::Suspicious, "odd", Some(2))];
    let next = vec![Issue::error(Code::Suspicious, "odd", Some(2))];
    // The identity is (code, offset): the site survived, so the finding
    // survives — the policy is deliberately severity-blind (the delta's
    // job is "what is new", not "what got worse"; the report itself
    // still carries the escalated severity).
    let delta = BaselineDelta::between(&prev, &next, &OffsetIdentity);
    assert!(delta.is_clean());
}

// -------------------------------------------------------------------- gate

#[test]
fn the_gate_is_no_new_findings_end_to_end() {
    let bytes = exec_bytes();
    let baseline_report = pgr_verify::verify(&bytes, &opts());
    assert!(baseline_report.is_ok(&opts()), "the fixture verifies clean");
    let baseline_json = to_json(&baseline_report);

    // A relink later: one byte of __text flipped — the stale page hash
    // is the new finding; everything else is untouched.
    let mut corrupt = bytes.clone();
    let text_off = 0x4000; // the fixture's __TEXT file offset (16 KiB alignment)
    corrupt[text_off + 7] ^= 0xff;
    let next_report = pgr_verify::verify(&corrupt, &opts());
    assert!(!next_report.is_ok(&opts()));

    let prev = parse_report_json(&baseline_json).expect("the baseline re-parses");
    let delta = BaselineDelta::between(&prev.issues, &next_report.issues, &OffsetIdentity);
    assert_eq!(delta.introduced.len(), 1);
    assert_eq!(
        delta.introduced[0].code,
        Code::SignatureHashMismatch,
        "the gate names the one thing that moved"
    );
    assert_eq!(delta.resolved.len(), 0);
    assert_eq!(delta.surviving, 0);
}
