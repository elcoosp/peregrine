//! M97 — the SARIF `baselineState` face: the M75 refusal ("the baseline
//! delta has no SARIF shape") retires with its premise — SARIF 2.1.0
//! results carry a `baselineState` (`new` / `unchanged` / `absent`),
//! which is exactly the M13 delta's story. `render_with_baseline`
//! renders the whole-verdict document the gate audited: every current
//! finding rides `unchanged` or `new` (the report's order, the M69
//! conventions unchanged), every cleared baseline finding rides `absent`
//! (anchored at the baseline image's own offsets), and the rule table is
//! the union of both sides' codes — a resolved-only code still names
//! itself, so a triage tool sees the rule the finding rode.
//!
//! The container rides the same face since M96's pairing (`render_universal_with_baseline`):
//! one run per declared slice, each run's results stated against its own
//! slice delta, the anchors container-absolute (the M95 convention — the
//! window agreement holds for the baseline's offsets too).
//!
//! Gate matrix:
//! * a fresh corruption rides `new` and fails the gate;
//! * the tolerated history rides `unchanged` and passes;
//! * a cleared baseline finding rides `absent`, its code named in the
//!   rule table, the gate passes;
//! * two renders of one run are byte-identical (the determinism gate);
//! * the container renders one run per slice with per-slice states;
//! * the two machine faces still refuse each other.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SymbolSpec, filler, universal_image};
use pgr_format::consts::{
    CPU_TYPE_ARM64, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ,
};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m97_cli_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// A small arm64 dylib (an export surface over a `__text` body).
fn dylib_image(seed: u64) -> Vec<u8> {
    let mut b = ImageBuilder::dylib("@rpath/libm97.dylib", "m97-cli");
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

/// The corrupted twin: one flipped `__text` byte rides a stale page hash.
fn corrupted(image: &[u8]) -> Vec<u8> {
    let mut bytes = image.to_vec();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;
    bytes
}

#[test]
fn a_new_finding_rides_the_new_state_and_fails_the_gate() {
    let dir = scratch("new");
    let clean = dylib_image(0x97);
    let path = write_image(&dir, "clean.dylib", &clean);
    let path_str = path.display().to_string();
    let record = run(&["--json", &path_str]);
    assert_eq!(record.status.code(), Some(0));
    let baseline = dir.join("baseline.json");
    std::fs::write(&baseline, stdout(&record)).expect("the baseline writes");
    let baseline_str = baseline.display().to_string();

    let broken_path = write_image(&dir, "broken.dylib", &corrupted(&clean));
    let broken_str = broken_path.display().to_string();
    let out = run(&["--sarif", "--baseline", &baseline_str, &broken_str]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "the introduced finding fails: {}{}",
        stdout(&out),
        stderr(&out)
    );
    let doc = stdout(&out);
    assert!(
        doc.contains("\"baselineState\":\"new\""),
        "the fresh finding rides the new state: {doc}"
    );
    assert!(
        doc.contains("signature_hash_mismatch"),
        "the finding keeps its code: {doc}"
    );
    let again = run(&["--sarif", "--baseline", &baseline_str, &broken_str]);
    assert_eq!(
        stdout(&again),
        doc,
        "two renders of one run are byte-identical"
    );
}

#[test]
fn the_tolerated_history_rides_unchanged_and_passes() {
    let dir = scratch("unchanged");
    let clean = dylib_image(0x97);
    let broken = corrupted(&clean);
    let broken_path = write_image(&dir, "broken.dylib", &broken);
    let broken_str = broken_path.display().to_string();
    // The corrupted run records the baseline (the tolerated history).
    let record = run(&["--json", &broken_str]);
    assert_eq!(record.status.code(), Some(1));
    let baseline = dir.join("baseline.json");
    std::fs::write(&baseline, stdout(&record)).expect("the baseline writes");
    let baseline_str = baseline.display().to_string();

    // The same corrupted image rides its own baseline: nothing new, the
    // SARIF face states the surviving finding `unchanged`.
    let out = run(&["--sarif", "--baseline", &baseline_str, &broken_str]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "the tolerated history passes: {}{}",
        stdout(&out),
        stderr(&out)
    );
    let doc = stdout(&out);
    assert!(
        doc.contains("\"baselineState\":\"unchanged\""),
        "the surviving finding rides the unchanged state: {doc}"
    );
    assert!(
        !doc.contains("\"baselineState\":\"new\""),
        "nothing is new: {doc}"
    );
}

#[test]
fn a_resolved_finding_rides_absent_with_its_code_named() {
    let dir = scratch("absent");
    let clean = dylib_image(0x97);
    let clean_path = write_image(&dir, "clean.dylib", &clean);
    let clean_str = clean_path.display().to_string();
    let broken = corrupted(&clean);
    let broken_path = write_image(&dir, "broken.dylib", &broken);
    let broken_str = broken_path.display().to_string();
    // The corrupted run records the baseline.
    let record = run(&["--json", &broken_str]);
    assert_eq!(record.status.code(), Some(1));
    let baseline = dir.join("baseline.json");
    std::fs::write(&baseline, stdout(&record)).expect("the baseline writes");
    let baseline_str = baseline.display().to_string();

    // The clean relink cleared the finding: it rides `absent`, the code
    // still named in the rule table, and the gate passes.
    let out = run(&["--sarif", "--baseline", &baseline_str, &clean_str]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "the cleared finding passes: {}{}",
        stdout(&out),
        stderr(&out)
    );
    let doc = stdout(&out);
    assert!(
        doc.contains("\"baselineState\":\"absent\""),
        "the cleared finding rides the absent state: {doc}"
    );
    assert!(
        doc.contains("\"id\":\"signature_hash_mismatch\""),
        "the resolved-only code names itself in the rules: {doc}"
    );
}

#[test]
fn the_container_renders_one_run_per_slice_with_per_slice_states() {
    let dir = scratch("container");
    let slice = dylib_image(0x97);
    let container = universal_image(&[(&slice, CPU_TYPE_ARM64), (&slice, CPU_TYPE_ARM64)])
        .expect("the container wraps");
    let path = write_image(&dir, "fat.dylib", &container);
    let path_str = path.display().to_string();
    let record = run(&["--json", &path_str]);
    assert_eq!(record.status.code(), Some(0), "clean: {}", stdout(&record));
    let baseline = dir.join("baseline.json");
    std::fs::write(&baseline, stdout(&record)).expect("the baseline writes");
    let baseline_str = baseline.display().to_string();

    // The corrupted twin breaks slice 0 only: the document rides one run
    // per declared slice, slice 0's results stated `new`.
    let mut broken = container.clone();
    let parsed = pgr_format::universal::parse_universal(&container).expect("the table decodes");
    let arch = &parsed.arches[0];
    let mid = usize::try_from(arch.offset + arch.size / 2).expect("the window fits usize");
    broken[mid] ^= 0xFF;
    let broken_path = write_image(&dir, "broken.dylib", &broken);
    let broken_str = broken_path.display().to_string();
    let out = run(&["--sarif", "--baseline", &baseline_str, &broken_str]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "the introduced finding fails: {}{}",
        stdout(&out),
        stderr(&out)
    );
    let doc = stdout(&out);
    assert_eq!(
        doc.matches("\"$schema\"").count(),
        1,
        "one document, the M95 shape: {doc}"
    );
    assert_eq!(
        doc.matches("\"tool\"").count(),
        2,
        "one run per declared slice: {doc}"
    );
    assert!(
        doc.contains("\"baselineState\":\"new\""),
        "the broken slice's findings ride new: {doc}"
    );
}

#[test]
fn the_two_machine_faces_still_refuse_each_other() {
    let dir = scratch("two-faces");
    let path = write_image(&dir, "one.dylib", &dylib_image(0x97));
    let path_str = path.display().to_string();
    let out = run(&["--sarif", "--json", &path_str]);
    assert_eq!(out.status.code(), Some(2), "usage refusal");
    let text = stderr(&out);
    assert!(
        text.contains("--json") && text.contains("--sarif"),
        "the refusal names both faces: {text}"
    );
}
