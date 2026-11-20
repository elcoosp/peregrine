//! M96 — the container's baseline gate: the M74 refusal ("--baseline
//! gates one image's offsets; a container's slices ride their own
//! windows") retires with its premise, the M95 way. The slices ride
//! *inside* the audited file and every slice's verdict is its own M13
//! report, so the container's own `--json` face — one report line per
//! declared slice, the label naming the window it rode — *is* the
//! baseline document: record the container once, gate every relink on
//! what the baseline already vouches for, slice by slice, under the
//! same [`pgr_verify::IssueIdentity`] policies the single-image gate
//! rides (`pgr_verify::UniversalDelta::between_slices`).
//!
//! Gate matrix:
//! * the container's `--json` face records one report line per declared
//!   slice (the baseline document's own shape, byte-stable);
//! * the untouched container passes its own baseline (`--fail-on new`
//!   default), every slice's delta clean;
//! * a fresh corruption is *introduced* on its own slice only — the
//!   other slice's delta stays clean, the exit gate fails;
//! * the corrupted container passes the corrupted baseline (the
//!   tolerated history), and `--fail-on any` restores the whole verdict;
//! * a baseline naming fewer slices refuses (the count is the document's
//!   own shape), a container whose windows moved since the baseline
//!   refuses (the baseline vouches for windows, not just a count), a
//!   garbage line refuses, and a hand-authored report without the slice
//!   label refuses — every refusal exit 2 with the fix named.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SymbolSpec, filler, universal_image};
use pgr_format::consts::{
    CPU_TYPE_ARM64, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ,
};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m96_cli_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// A small arm64 dylib slice (an export surface over a `__text` body).
fn dylib_slice(seed: u64) -> Vec<u8> {
    let mut b = ImageBuilder::dylib("@rpath/libm96.dylib", "m96-cli");
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

/// The byte range one declared slice's window rides in the container.
fn slice_window(container: &[u8], index: usize) -> std::ops::Range<usize> {
    let parsed = pgr_format::universal::parse_universal(container).expect("the container parses");
    let arch = &parsed.arches[index];
    let start = usize::try_from(arch.offset).expect("the offset fits usize");
    start..start + usize::try_from(arch.size).expect("the size fits usize")
}

/// The container's baseline document as the CLI records it: the `--json`
/// face's own output, one report line per declared slice.
fn record_baseline(out: &Output) -> String {
    stdout(out)
}

#[test]
fn the_json_face_records_one_report_line_per_slice() {
    let dir = scratch("record");
    let a = dylib_slice(0x96);
    let b = dylib_slice(0x97);
    let container = universal_image(&[(&a, CPU_TYPE_ARM64), (&b, CPU_TYPE_ARM64)])
        .expect("the container wraps");
    let path = write_image(&dir, "fat.dylib", &container);
    let path_str = path.display().to_string();
    let out = run(&["--json", &path_str]);
    assert_eq!(out.status.code(), Some(0), "clean: {}", stdout(&out));
    let body = stdout(&out);
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 2, "one report line per declared slice");
    for (i, line) in lines.iter().enumerate() {
        assert!(
            line.contains(&format!("[slice {i} cputype")),
            "the label names the slice it rode: {line}"
        );
        assert!(
            line.contains("\"issues\":"),
            "the line is the M13 report shape: {line}"
        );
    }
}

#[test]
fn the_untouched_container_passes_its_own_baseline() {
    let dir = scratch("clean-gate");
    let a = dylib_slice(0x96);
    let b = dylib_slice(0x97);
    let container = universal_image(&[(&a, CPU_TYPE_ARM64), (&b, CPU_TYPE_ARM64)])
        .expect("the container wraps");
    let path = write_image(&dir, "fat.dylib", &container);
    let path_str = path.display().to_string();
    let record = run(&["--json", &path_str]);
    assert_eq!(record.status.code(), Some(0));
    let baseline = dir.join("baseline.json");
    std::fs::write(&baseline, record_baseline(&record)).expect("the baseline writes");
    let baseline_str = baseline.display().to_string();

    let out = run(&["--json", "--baseline", &baseline_str, &path_str]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "every slice's delta is clean: {}{}",
        stdout(&out),
        stderr(&out)
    );
    let body = stdout(&out);
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 2, "the gate face rides one line per slice");
    for line in lines {
        assert!(
            line.contains("\"baseline\":{\"policy\":\"offset\",\"introduced\":["),
            "each slice's delta rides the machine block: {line}"
        );
    }
}

#[test]
fn a_new_finding_fails_only_its_own_slice() {
    let dir = scratch("new-finding");
    let a = dylib_slice(0x96);
    let b = dylib_slice(0x97);
    let container = universal_image(&[(&a, CPU_TYPE_ARM64), (&b, CPU_TYPE_ARM64)])
        .expect("the container wraps");
    let path = write_image(&dir, "fat.dylib", &container);
    let path_str = path.display().to_string();
    let record = run(&["--json", &path_str]);
    assert_eq!(record.status.code(), Some(0));
    let baseline = dir.join("baseline.json");
    std::fs::write(&baseline, record_baseline(&record)).expect("the baseline writes");
    let baseline_str = baseline.display().to_string();

    // The fresh corruption rides slice 0's window only — slice 1's
    // verdict stays clean, and the exit gate is every slice's delta.
    let mut broken = container.clone();
    let window = slice_window(&container, 0);
    let mid = window.start + (window.len() / 2);
    broken[mid] ^= 0xFF;
    let broken_path = write_image(&dir, "broken.dylib", &broken);
    let broken_str = broken_path.display().to_string();

    let out = run(&["--json", "--baseline", &baseline_str, &broken_str]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "the introduced finding fails the gate: {}{}",
        stdout(&out),
        stderr(&out)
    );
    let body = stdout(&out);
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 2, "the gate face rides one line per slice");
    assert!(
        lines[0].contains("signature_hash_mismatch"),
        "the corrupted slice names the stale page hash: {}",
        lines[0]
    );
    assert!(
        lines[0].contains("\"introduced\":[{"),
        "slice 0's delta carries the introduced finding: {}",
        lines[0]
    );
    assert!(
        lines[1].contains("\"introduced\":[]"),
        "slice 1's delta stays clean: {}",
        lines[1]
    );
}

#[test]
fn the_corrupted_baseline_passes_its_own_container_and_any_restores_the_verdict() {
    let dir = scratch("resolved");
    let a = dylib_slice(0x96);
    let b = dylib_slice(0x97);
    let container = universal_image(&[(&a, CPU_TYPE_ARM64), (&b, CPU_TYPE_ARM64)])
        .expect("the container wraps");
    let mut broken = container.clone();
    let window = slice_window(&container, 0);
    let mid = window.start + (window.len() / 2);
    broken[mid] ^= 0xFF;
    let broken_path = write_image(&dir, "broken.dylib", &broken);
    let broken_str = broken_path.display().to_string();

    // The corrupted run records the baseline (the tolerated history).
    let record = run(&["--json", &broken_str]);
    assert_eq!(record.status.code(), Some(1), "the corrupted run fails");
    let baseline = dir.join("baseline.json");
    std::fs::write(&baseline, record_baseline(&record)).expect("the baseline writes");
    let baseline_str = baseline.display().to_string();

    // The same corrupted container rides its own baseline: nothing is
    // new, the gate passes (the whole point of the delta).
    let out = run(&["--json", "--baseline", &baseline_str, &broken_str]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "the tolerated history survives: {}{}",
        stdout(&out),
        stderr(&out)
    );
    assert!(
        stdout(&out).contains("\"resolved\":[]"),
        "nothing cleared either: {}",
        stdout(&out)
    );

    // --fail-on any restores the whole verdict: the surviving findings
    // fail again, exactly the single-image gate's contract.
    let out = run(&["--baseline", &baseline_str, "--fail-on", "any", &broken_str]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "the whole verdict gate keeps: {}{}",
        stdout(&out),
        stderr(&out)
    );
}

#[test]
fn a_baseline_naming_fewer_slices_refuses() {
    let dir = scratch("count");
    let a = dylib_slice(0x96);
    let one = universal_image(&[(&a, CPU_TYPE_ARM64)]).expect("the one-slice container wraps");
    let one_path = write_image(&dir, "one.dylib", &one);
    let one_str = one_path.display().to_string();
    let record = run(&["--json", &one_str]);
    assert_eq!(record.status.code(), Some(0));
    let baseline = dir.join("baseline.json");
    std::fs::write(&baseline, record_baseline(&record)).expect("the baseline writes");
    let baseline_str = baseline.display().to_string();

    let b = dylib_slice(0x97);
    let two = universal_image(&[(&a, CPU_TYPE_ARM64), (&b, CPU_TYPE_ARM64)])
        .expect("the two-slice container wraps");
    let two_path = write_image(&dir, "two.dylib", &two);
    let two_str = two_path.display().to_string();
    let out = run(&["--baseline", &baseline_str, &two_str]);
    assert_eq!(out.status.code(), Some(2), "usage refusal");
    let text = stderr(&out);
    assert!(
        text.contains("vouches for 1 slice(s) but the container declares 2"),
        "the refusal names the slice counts: {text}"
    );
}

#[test]
fn a_container_whose_windows_moved_since_the_baseline_refuses() {
    let dir = scratch("window");
    let small = dylib_slice(0x96);
    let large = {
        let mut b = ImageBuilder::dylib("@rpath/libm96.dylib", "m96-cli");
        b.add_segment(SegmentSpec {
            name: "__TEXT".into(),
            maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
            initprot: VM_PROT_READ | VM_PROT_EXECUTE,
            sections: vec![SectionSpec {
                name: "__text".into(),
                align_log2: 2,
                flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
                data: filler(0x97, 0x5000),
                relocs: Vec::new(),
            }],
        });
        b.add_symbol(SymbolSpec::Defined {
            name: "_greet".into(),
            section_index: 0,
        });
        b.build().expect("the large fixture builds").bytes
    };
    let before = universal_image(&[(&small, CPU_TYPE_ARM64), (&small, CPU_TYPE_ARM64)])
        .expect("the before container wraps");
    let before_path = write_image(&dir, "before.dylib", &before);
    let before_str = before_path.display().to_string();
    let record = run(&["--json", &before_str]);
    assert_eq!(record.status.code(), Some(0));
    let baseline = dir.join("baseline.json");
    std::fs::write(&baseline, record_baseline(&record)).expect("the baseline writes");
    let baseline_str = baseline.display().to_string();

    // The after container's second slice is bigger: the slice table's
    // windows moved since the baseline named them — the document vouches
    // for windows, not just a count.
    let after = universal_image(&[(&small, CPU_TYPE_ARM64), (&large, CPU_TYPE_ARM64)])
        .expect("the after container wraps");
    let after_path = write_image(&dir, "after.dylib", &after);
    let after_str = after_path.display().to_string();
    let out = run(&["--baseline", &baseline_str, &after_str]);
    assert_eq!(out.status.code(), Some(2), "usage refusal");
    let text = stderr(&out);
    assert!(
        text.contains("window"),
        "the refusal names the moved window: {text}"
    );
}

#[test]
fn a_garbage_baseline_line_refuses() {
    let dir = scratch("garbage");
    let a = dylib_slice(0x96);
    let b = dylib_slice(0x97);
    let container = universal_image(&[(&a, CPU_TYPE_ARM64), (&b, CPU_TYPE_ARM64)])
        .expect("the container wraps");
    let path = write_image(&dir, "fat.dylib", &container);
    let path_str = path.display().to_string();
    let baseline = dir.join("baseline.json");
    std::fs::write(
        &baseline,
        "{\"file\":\"app[slice 0 cputype 0x100000c at 0x0, 8 bytes]\",\"issues\":[]}\nnot json\n",
    )
    .expect("the baseline writes");
    let baseline_str = baseline.display().to_string();
    let out = run(&["--baseline", &baseline_str, &path_str]);
    assert_eq!(out.status.code(), Some(2), "usage refusal");
    let text = stderr(&out);
    assert!(
        text.contains("line 2"),
        "the refusal names the line it died at: {text}"
    );
}

#[test]
fn a_hand_authored_report_without_the_slice_label_refuses() {
    let dir = scratch("unlabeled");
    let a = dylib_slice(0x96);
    let b = dylib_slice(0x97);
    let container = universal_image(&[(&a, CPU_TYPE_ARM64), (&b, CPU_TYPE_ARM64)])
        .expect("the container wraps");
    let path = write_image(&dir, "fat.dylib", &container);
    let path_str = path.display().to_string();
    let baseline = dir.join("baseline.json");
    std::fs::write(&baseline, "{\"issues\":[]}\n{\"issues\":[]}\n").expect("the baseline writes");
    let baseline_str = baseline.display().to_string();
    let out = run(&["--baseline", &baseline_str, &path_str]);
    assert_eq!(out.status.code(), Some(2), "usage refusal");
    let text = stderr(&out);
    assert!(
        text.contains("label"),
        "the refusal names the missing slice label: {text}"
    );
}
