//! M10 rung 3, slice 2 — the encoding-query gates: the answer a build
//! system reads *before* the link (`pgr_driver::fixup_encoding_report`
//! and the `--print-fixup-encoding` CLI intercept) agrees with the
//! per-platform floor table the layout encodes — one table, three
//! readers — and the refusals match the `-platform_version` surface
//! (an unknown platform names the five, `sdk < minos` refuses, a
//! malformed version refuses). The below-floor advisory renders its
//! miette help text on the CLI's stderr without turning the answer
//! into an error: an advisory is a plan, not a failure.

use pgr_core::platform::FixupEncoding;
use pgr_driver::fixup_encoding_report;

#[test]
fn at_the_floor_the_query_names_chained_fixups() {
    let report = fixup_encoding_report("macos", "12.0", "14.4").expect("macos at the floor");
    assert_eq!(report.encoding, FixupEncoding::ChainedFixups);
    assert_eq!(report.floor, 0x000C_0000);
    assert_eq!(report.floor_text(), "12.0.0");
    assert_eq!(report.minos, 0x000C_0000);
    assert_eq!(report.minos_text(), "12.0.0");
    assert!(report.advisory.is_none(), "at-floor rows carry no advisory");
}

#[test]
fn below_the_floor_the_query_carries_the_advisory() {
    let report = fixup_encoding_report("ios", "14.0", "16.0").expect("ios below the floor");
    assert_eq!(report.encoding, FixupEncoding::ClassicOpcodes);
    assert_eq!(report.floor_text(), "15.0.0");
    let advisory = report.advisory.expect("below-floor rows carry the advisory");
    let rendered = advisory.to_string();
    assert!(
        rendered.contains("14.0.0") && rendered.contains("15.0.0"),
        "the advisory names the target and the floor: {rendered}"
    );
}

#[test]
fn every_linked_platform_answers_at_its_floor() {
    // The at-floor words the layout table encodes — the query must
    // answer chained fixups for every linked platform, with no advisory.
    let floors = [
        ("macos", "12.0"),
        ("ios", "15.0"),
        ("tvos", "15.0"),
        ("watchos", "8.0"),
        ("visionos", "1.0"),
    ];
    for (name, minos) in floors {
        let report = fixup_encoding_report(name, minos, "99.0").expect(name);
        assert_eq!(
            report.encoding,
            FixupEncoding::ChainedFixups,
            "{name} at its floor plans chained fixups"
        );
        assert!(
            report.advisory.is_none(),
            "{name} at its floor carries no advisory"
        );
    }
}

#[test]
fn an_unknown_platform_names_the_linked_surface() {
    let err =
        fixup_encoding_report("watchsimulator", "1.0", "1.0").expect_err("unknown platforms refuse");
    let rendered = err.to_string();
    assert!(
        rendered.contains("not a linked platform"),
        "the refusal names the surface: {rendered}"
    );
    assert!(
        rendered.contains("visionos"),
        "the five linked platforms ride the hint: {rendered}"
    );
}

#[test]
fn an_sdk_below_the_target_refuses_like_the_flag() {
    let err = fixup_encoding_report("macos", "14.0", "12.0").expect_err("sdk < minos refuses");
    assert!(
        err.to_string().contains("older than the deployment target"),
        "the order refusal matches -platform_version: {err}"
    );
}

#[test]
fn a_malformed_version_refuses_like_the_flag() {
    let err = fixup_encoding_report("macos", "twelve", "14.0").expect_err("bad versions refuse");
    assert!(
        err.to_string().contains("invalid value"),
        "the value refusal matches -platform_version: {err}"
    );
}

// ---- the CLI intercept ------------------------------------------------------

/// Runs the `pgr` binary and captures status, stdout and stderr.
fn run_query(args: &[&str]) -> (std::process::ExitStatus, String, String) {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_pgr"))
        .args(args)
        .output()
        .expect("the pgr binary runs");
    (
        out.status,
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn the_cli_answers_before_the_link() {
    let (status, stdout, stderr) = run_query(&["--print-fixup-encoding", "ios", "14.0", "16.0"]);
    assert!(status.success(), "an advisory is not an error: {stderr}");
    assert!(
        stdout.contains("classic-opcodes") && stdout.contains("15.0.0"),
        "the verdict names the encoding and the floor: {stdout}"
    );
    assert!(
        stderr.contains("raise the deployment target"),
        "the advisory renders its miette help text: {stderr}"
    );
}

#[test]
fn the_cli_at_floor_row_ships_no_advisory() {
    let (status, stdout, stderr) = run_query(&["--print-fixup-encoding", "macos", "12.0", "14.0"]);
    assert!(status.success(), "{stderr}");
    assert!(stdout.contains("chained-fixups"), "{stdout}");
    assert!(
        stderr.is_empty(),
        "at-floor rows are silent on stderr: {stderr}"
    );
}

#[test]
fn the_cli_refusals_match_the_flag_surface() {
    let (status, _, stderr) = run_query(&["--print-fixup-encoding", "watchos2", "1.0", "1.0"]);
    assert_eq!(status.code(), Some(2), "option refusals exit 2: {stderr}");
    assert!(stderr.contains("not a linked platform"), "{stderr}");

    let (status, _, stderr) = run_query(&["--print-fixup-encoding", "macos", "14.0", "12.0"]);
    assert_eq!(status.code(), Some(2));
    assert!(stderr.contains("older than the deployment target"), "{stderr}");

    let (status, _, stderr) = run_query(&["--print-fixup-encoding", "macos", "14.0"]);
    assert_eq!(status.code(), Some(2));
    assert!(
        stderr.contains("<platform> <minos> <sdk>"),
        "the arity refusal names the grammar: {stderr}"
    );
}
