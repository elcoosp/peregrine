//! M75 — the CLI's SARIF face: `pgr-verify --sarif` stops being a
//! library-only render (`pgr_verify::sarif::render`, M69) and rides the
//! CLI — one deterministic SARIF 2.1.0 document per verified image, the
//! shape GitHub Code Scanning, IDE problem panels and CI triage read
//! natively. The face refuses where it cannot apply honestly: beside the
//! other machine face (`--json`) and beside the baseline gate (the delta
//! has no SARIF shape). (The M75 container refusal — "a slice's anchors
//! ride their own windows" — retired with its premise at M95: the slices
//! ride *inside* the audited file, so `render_universal` re-anchors
//! honestly; the container's gates live in `m95_sarif_universal.rs`.)
//!
//! Gate matrix:
//! * the clean image's document rides an empty `results` array, one
//!   line, byte-identical across runs (the determinism gate);
//! * the corrupted twin's document carries the findings (`ruleId` the
//!   stable code token, `level` the severity, the anchor offset) and
//!   fails the exit gate;
//! * the two machine faces refuse each other;
//! * the baseline gate refuses the face.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SymbolSpec, filler, universal_image};
use pgr_format::consts::{
    CPU_TYPE_ARM64, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ,
};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m75_cli_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// A small arm64 dylib (an export surface over a `__text` body).
fn dylib_image(seed: u64) -> Vec<u8> {
    let mut b = ImageBuilder::dylib("@rpath/libm75.dylib", "m75-cli");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(seed, 128),
            relocs: Vec::new(),
        }],
    });
    b.add_symbol(SymbolSpec::Defined {
        name: "_greet".into(),
        section_index: 0,
    });
    b.build().expect("the fixture dylib builds").bytes
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

#[test]
fn the_clean_image_renders_one_deterministic_document() {
    let dir = scratch("clean");
    let path = write_image(&dir, "one.dylib", &dylib_image(0x75));
    let path_str = path.display().to_string();
    let first = run(&["--sarif", &path_str]);
    assert_eq!(first.status.code(), Some(0), "clean: {}", stdout(&first));
    let doc = stdout(&first);
    let lines: Vec<&str> = doc.lines().collect();
    assert_eq!(lines.len(), 1, "the document rides one line");
    assert!(
        doc.contains("\"version\":\"2.1.0\""),
        "SARIF 2.1.0 declares itself: {doc}"
    );
    assert!(
        doc.contains("\"results\":[]"),
        "the clean image's findings ride empty: {doc}"
    );
    let second = run(&["--sarif", &path_str]);
    assert_eq!(
        stdout(&second),
        doc,
        "two renders of one run are byte-identical"
    );
}

#[test]
fn the_corrupted_image_rides_findings_and_fails_the_gate() {
    let dir = scratch("corrupt");
    let mut bytes = dylib_image(0x75);
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;
    let path = write_image(&dir, "broken.dylib", &bytes);
    let path_str = path.display().to_string();
    let out = run(&["--sarif", &path_str]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "the gate fails: {}",
        stdout(&out)
    );
    let doc = stdout(&out);
    assert!(
        doc.contains("\"ruleId\":\""),
        "the code token names itself: {doc}"
    );
    assert!(
        doc.contains("\"level\":\"error\""),
        "the severity rides the SARIF level: {doc}"
    );
    assert!(
        doc.contains("\"byteOffset\":"),
        "the anchor rides the binary region: {doc}"
    );
    assert!(
        doc.contains("signature_hash_mismatch"),
        "the page-hash refusal keeps the verifier's own words: {doc}"
    );
}

#[test]
fn the_two_machine_faces_refuse_each_other() {
    let dir = scratch("two-faces");
    let path = write_image(&dir, "one.dylib", &dylib_image(0x75));
    let path_str = path.display().to_string();
    let out = run(&["--sarif", "--json", &path_str]);
    assert_eq!(out.status.code(), Some(2), "usage refusal");
    let text = stderr(&out);
    assert!(
        text.contains("--json") && text.contains("--sarif"),
        "the refusal names both faces: {text}"
    );
}

#[test]
fn the_sarif_face_refuses_the_baseline_gate() {
    let dir = scratch("baseline");
    let path = write_image(&dir, "one.dylib", &dylib_image(0x75));
    let path_str = path.display().to_string();
    // The previous report comes from the CLI's own flow (the --json face).
    let prev_report = run(&["--json", &path_str]);
    let prev = dir.join("prev.json");
    std::fs::write(&prev, stdout(&prev_report)).expect("the baseline writes");
    let prev_str = prev.display().to_string();
    let out = run(&["--sarif", "--baseline", &prev_str, &path_str]);
    assert_eq!(out.status.code(), Some(2), "usage refusal");
    let text = stderr(&out);
    assert!(
        text.contains("baseline"),
        "the fix names the baseline conflict: {text}"
    );
}

#[test]
fn the_sarif_face_serves_the_container_since_m95() {
    // The M75 refusal retired with its premise (the slices ride inside
    // the audited file); the served face's gates live in
    // m95_sarif_universal.rs — this rung keeps one honest pin: the
    // container renders the SARIF document instead of the refusal.
    let dir = scratch("container");
    let a = dylib_image(0x75);
    let b = dylib_image(0x76);
    let container = universal_image(&[
        (a.as_slice(), CPU_TYPE_ARM64),
        (b.as_slice(), CPU_TYPE_ARM64),
    ])
    .expect("the container wraps");
    let path = write_image(&dir, "fat.dylib", &container);
    let path_str = path.display().to_string();
    let out = run(&["--sarif", &path_str]);
    assert_eq!(out.status.code(), Some(0), "the honest container passes");
    let doc = stdout(&out);
    assert!(
        doc.contains("\"version\":\"2.1.0\""),
        "the container rides the SARIF document: {doc}"
    );
}
