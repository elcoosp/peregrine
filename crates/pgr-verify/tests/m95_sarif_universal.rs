//! M95 — the SARIF face for the universal container: the M75 refusal
//! ("SARIF anchors name file bytes; a container's slices ride their own
//! windows — re-anchoring would re-shape") had its premise backwards —
//! the slices ride *inside* the container's file, so
//! [`pgr_verify::sarif::render_universal`] renders the container's
//! whole verdict as ONE SARIF 2.1.0 document: one run per declared
//! slice, in table order (the same order `verify_universal` walks), the
//! rule table the union of the slices' codes (the built-ins in
//! [`Code::ALL`] canonical order, the custom tokens after them), and
//! every anchored result riding a container-absolute
//! `region.byteOffset` (`slice.offset + anchor`) — the anchor names the
//! audited file's own bytes, which is what a triage tool reads. An
//! unanchored issue rides no location (the M69 convention), a
//! `Severity::Error` rides `error` and a `Severity::Warning` rides
//! `warning`, the document is one deterministic line, and the CLI's
//! `--sarif` face rides the same render — the whole-verdict exit gate
//! unchanged.
//!
//! Gate matrix:
//! * the honest container's document: one line, byte-identical across
//!   runs, one run per slice, every slice's `results` empty;
//! * the flagged slice's finding rides the container-absolute anchor
//!   and fails the exit gate;
//! * the rule table carries the union of the slices' codes;
//! * the CLI face serves the container (the retired M75 refusal's text
//!   is gone), the two-machine-face and baseline refusals stay.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SymbolSpec, filler, universal_image};
use pgr_format::consts::{
    CPU_TYPE_ARM64, MH_HAS_TLV_DESCRIPTORS, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE,
    VM_PROT_READ, VM_PROT_WRITE,
};
use pgr_verify::{Options, sarif, verify_universal};

fn opts() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// A small arm64 dylib (an export surface over a `__text` body);
/// `flagged` pins the hand-broken initializer/TLV surface — the
/// `MH_HAS_TLV_DESCRIPTORS` marker without thread-local data (the M37
/// parity finding, unanchored), a `__thread_vars` section off the
/// 16-byte descriptor stride and a `__mod_init_func` section off the
/// 8-byte pointer stride (the M37/M94 geometry findings, anchored at
/// their sections) — three issues, two codes, both anchored and
/// unanchored shapes in one slice.
fn dylib_image(seed: u64, flagged: bool) -> Vec<u8> {
    let mut b = ImageBuilder::dylib("@rpath/libm95.dylib", "m95-sarif");
    let mut text_sects = vec![SectionSpec {
        name: "__text".into(),
        align_log2: 2,
        flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
        data: filler(seed, 128),
        relocs: Vec::new(),
    }];
    if flagged {
        text_sects.push(SectionSpec {
            name: "__thread_vars".into(),
            align_log2: 3,
            flags: pgr_format::consts::S_THREAD_LOCAL_VARIABLES,
            data: vec![0u8; 10],
            relocs: Vec::new(),
        });
        b.set_mh_flags(MH_HAS_TLV_DESCRIPTORS);
    }
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: text_sects,
    });
    if flagged {
        b.add_segment(SegmentSpec {
            name: "__DATA_CONST".into(),
            maxprot: VM_PROT_READ | VM_PROT_WRITE,
            initprot: VM_PROT_READ | VM_PROT_WRITE,
            sections: vec![SectionSpec {
                name: "__mod_init_func".into(),
                align_log2: 3,
                flags: pgr_format::consts::S_MOD_INIT_FUNC_POINTERS,
                data: vec![0u8; 12],
                relocs: Vec::new(),
            }],
        });
    }
    b.add_symbol(SymbolSpec::Defined {
        name: "_greet".into(),
        section_index: 0,
    });
    b.build().expect("the fixture dylib builds").bytes
}

/// One two-slice container: the honest slice first, the flagged one
/// second (table order is the face's order).
fn two_slice_container() -> Vec<u8> {
    universal_image(&[
        (dylib_image(0x95A1, false).as_slice(), CPU_TYPE_ARM64),
        (dylib_image(0x95A2, true).as_slice(), CPU_TYPE_ARM64),
    ])
    .expect("the container wraps")
}

fn container_report() -> pgr_verify::UniversalReport {
    let container = two_slice_container();
    verify_universal(&container, &opts()).expect("the container decodes")
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m95_cli_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

fn write_image(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).expect("the image writes");
    path
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pgr-verify"))
        .args(args)
        .output()
        .expect("the CLI spawns")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

// ------------------------------------------------------------ library

#[test]
fn the_container_renders_one_deterministic_document() {
    let report = container_report();
    let first = sarif::render_universal(&report, "fat.dylib");
    let second = sarif::render_universal(&report, "fat.dylib");
    assert_eq!(
        first, second,
        "two renders of one verdict are byte-identical"
    );
    assert!(
        !first.contains('\n'),
        "the document rides one line: {first}"
    );
    assert!(
        first.starts_with("{\"$schema\":"),
        "SARIF declares itself: {first}"
    );
    assert!(
        first.contains("\"version\":\"2.1.0\""),
        "SARIF 2.1.0 declares itself: {first}"
    );
    assert_eq!(
        first.matches("\"tool\":{\"driver\"").count(),
        report.slices.len(),
        "one run per declared slice, in table order: {first}"
    );
}

#[test]
fn the_honest_slices_results_ride_empty() {
    let report = container_report();
    let doc = sarif::render_universal(&report, "fat.dylib");
    assert!(
        doc.contains("\"results\":[]"),
        "the honest slice carries no findings: {doc}"
    );
    assert!(
        doc.contains("\"results\":[{\"ruleId\":"),
        "the flagged slice carries its findings: {doc}"
    );
}

#[test]
fn the_flagged_slice_rides_the_container_absolute_anchor() {
    let report = container_report();
    let flagged = &report.slices[1];
    let anchored = flagged
        .report
        .issues
        .iter()
        .find(|i| i.offset.is_some())
        .expect("the stride findings anchor their sections");
    let anchor = anchored.offset.expect("checked above");
    let want = flagged.arch.offset + anchor;
    let doc = sarif::render_universal(&report, "fat.dylib");
    assert!(
        doc.contains(&format!("\"byteOffset\":{want}")),
        "the anchor names the container's own bytes (slice {:#x} + {anchor:#x} = {want:#x}): {doc}",
        flagged.arch.offset
    );
    assert!(
        doc.contains("\"ruleId\":\"tlv\""),
        "the stable code token names the finding: {doc}"
    );
    assert!(
        doc.contains("\"level\":\"error\""),
        "the severity rides the SARIF level: {doc}"
    );
}

#[test]
fn the_rule_table_carries_the_union_of_the_slices_codes() {
    let report = container_report();
    let doc = sarif::render_universal(&report, "fat.dylib");
    // The union rides each run's driver table once — canonical
    // `Code::ALL` order (`tlv` declares before `init_offsets`), never
    // once per issue and never once per slice carrying it.
    assert!(
        doc.contains("\"rules\":[{\"id\":\"tlv\"},{\"id\":\"init_offsets\"}]"),
        "each run's table is the union in canonical order: {doc}"
    );
}

#[test]
fn an_artifact_uri_names_the_container_once_per_run() {
    let report = container_report();
    let doc = sarif::render_universal(&report, "fat.dylib");
    assert_eq!(
        doc.matches("\"artifacts\":[{\"location\":{\"uri\":\"fat.dylib\"}}]")
            .count(),
        report.slices.len(),
        "each run audits the container: {doc}"
    );
}

// --------------------------------------------------------------- CLI

#[test]
fn the_cli_face_serves_the_container() {
    let dir = scratch("served");
    let container = two_slice_container();
    let path = write_image(&dir, "fat.dylib", &container);
    let path_str = path.display().to_string();
    let out = run(&["--sarif", &path_str]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "the flagged slice fails the whole-verdict gate: {}",
        stdout(&out)
    );
    let doc = stdout(&out);
    let lines: Vec<&str> = doc.lines().collect();
    assert_eq!(lines.len(), 1, "the document rides one line");
    assert!(
        doc.contains("\"ruleId\":\"tlv\""),
        "the finding rides the served document: {doc}"
    );
    let again = run(&["--sarif", &path_str]);
    assert_eq!(
        stdout(&again),
        doc,
        "two renders of one run are byte-identical"
    );
}

#[test]
fn the_honest_container_passes_the_cli_face() {
    let dir = scratch("honest");
    let container = universal_image(&[
        (dylib_image(0x95B1, false).as_slice(), CPU_TYPE_ARM64),
        (dylib_image(0x95B2, false).as_slice(), CPU_TYPE_ARM64),
    ])
    .expect("the container wraps");
    let path = write_image(&dir, "fat.dylib", &container);
    let out = run(&["--sarif", &path.display().to_string()]);
    assert_eq!(out.status.code(), Some(0), "clean: {}", stdout(&out));
    assert!(
        stdout(&out).contains("\"results\":[]"),
        "every slice rides empty: {}",
        stdout(&out)
    );
}

#[test]
fn the_retired_refusal_is_gone() {
    let dir = scratch("retired");
    let container = two_slice_container();
    let path = write_image(&dir, "fat.dylib", &container);
    let out = run(&["--sarif", &path.display().to_string()]);
    assert!(
        !stderr(&out).contains("slices ride their own windows"),
        "the M75 refusal's text retired with its premise: {}",
        stderr(&out)
    );
}

#[test]
fn the_two_machine_faces_still_refuse_each_other() {
    let dir = scratch("two-faces");
    let container = two_slice_container();
    let path = write_image(&dir, "fat.dylib", &container);
    let path_str = path.display().to_string();
    let out = run(&["--sarif", "--json", &path_str]);
    assert_eq!(out.status.code(), Some(2), "usage refusal");
    let text = stderr(&out);
    assert!(
        text.contains("--json") && text.contains("--sarif"),
        "the refusal names both faces: {text}"
    );
}
