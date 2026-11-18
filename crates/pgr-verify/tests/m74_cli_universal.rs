//! M74 — the CLI's universal-container face: `pgr-verify <fat-container>`
//! stops running the single-image pass over the container's bytes (the
//! fat magic is no Mach-O magic, so the pass refused the *container* and
//! never named the slice) and walks `verify_universal_with_checks`
//! instead — one verdict per declared slice, printed slice by slice, the
//! exit code every slice's.
//!
//! Gate matrix:
//! * the clean container exits 0, one OK line per slice;
//! * the corrupted twin exits 1 and names the refusing slice (its
//!   neighbour still rides OK);
//! * `--json` serves one M13 document per slice (each line the strict
//!   reader's own shape, the file field naming the slice it rode);
//! * `--baseline` refuses a container (the baseline identity gates one
//!   image's offsets, never a slice table);
//! * the malformed table refuses with the format reader's own words;
//! * `--checks` composes — the narrowed lane prices the corrupted byte's
//!   absence honestly.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SymbolSpec, filler, universal_image};
use pgr_format::consts::{
    CPU_TYPE_ARM64, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ,
};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m74_cli_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// A small arm64 dylib slice (an export surface over a `__text` body).
fn dylib_slice(seed: u64) -> Vec<u8> {
    let mut b = ImageBuilder::dylib("@rpath/libm74.dylib", "m74-cli");
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

/// A two-slice container of real arm64 images written to `dir/fat.dylib`
/// (both slices verify clean — the containers a build gate audits carry
/// real images in every window).
fn write_container(dir: &Path, first: &[u8], second: &[u8]) -> PathBuf {
    let path = dir.join("fat.dylib");
    let container = universal_image(&[(first, CPU_TYPE_ARM64), (second, CPU_TYPE_ARM64)])
        .expect("the container wraps");
    std::fs::write(&path, container).expect("the container writes");
    path
}

/// A single slice written as a plain Mach-O file (the baseline gate's
/// previous report comes from verifying it first, the CLI's own flow).
fn write_slice(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).expect("the slice writes");
    path
}

/// The corrupted twin: one flipped `__text` byte (the page-hash
/// recompute refuses on the slice's verdict).
fn corrupted(slice: &[u8]) -> Vec<u8> {
    let mut bytes = slice.to_vec();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;
    bytes
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
fn the_clean_container_exits_zero_one_line_per_slice() {
    let dir = scratch("clean");
    let path = write_container(&dir, &dylib_slice(0x74), &dylib_slice(0x75));
    let path_str = path.display().to_string();
    let out = run(&[&path_str]);
    assert_eq!(out.status.code(), Some(0), "clean: {}", stdout(&out));
    let text = stdout(&out);
    assert!(
        text.contains("slice 0"),
        "the first slice names itself: {text}"
    );
    assert!(
        text.contains("slice 1"),
        "the second slice names itself: {text}"
    );
    assert_eq!(text.matches(" OK").count(), 2, "both slices ride: {text}");
}

#[test]
fn the_corrupted_slice_refuses_and_names_itself() {
    let dir = scratch("corrupt");
    let path = write_container(&dir, &corrupted(&dylib_slice(0x74)), &dylib_slice(0x75));
    let path_str = path.display().to_string();
    let out = run(&[&path_str]);
    assert_eq!(out.status.code(), Some(1), "corrupted: {}", stdout(&out));
    let text = stdout(&out);
    assert!(
        text.contains("slice 0"),
        "the refusing slice is named: {text}"
    );
    assert!(
        text.matches(" FAILED").count() == 1,
        "only the corrupted slice refuses: {text}"
    );
    assert!(
        text.contains("signature_hash_mismatch"),
        "the page-hash refusal rides in the verifier's own words: {text}"
    );
}

#[test]
fn the_json_face_serves_one_document_per_slice() {
    let dir = scratch("json");
    let path = write_container(&dir, &corrupted(&dylib_slice(0x74)), &dylib_slice(0x75));
    let path_str = path.display().to_string();
    let out = run(&["--json", &path_str]);
    assert_eq!(out.status.code(), Some(1), "corrupted: {}", stdout(&out));
    let text = stdout(&out);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "one document per declared slice");
    for (i, line) in lines.iter().enumerate() {
        let _ = pgr_verify::parse_report_json(line)
            .unwrap_or_else(|e| panic!("slice {i}'s document rides the M13 shape: {e}"));
        assert!(
            line.contains(&format!("slice {i}")),
            "the document names the slice it rode: {line}"
        );
    }
    let first = pgr_verify::parse_report_json(lines[0]).expect("the first slice parses");
    assert!(
        !first.issues.is_empty(),
        "the corrupted slice's findings ride its own document"
    );
}

#[test]
fn the_baseline_face_refuses_a_container() {
    let dir = scratch("baseline");
    let slice = write_slice(&dir, "one.dylib", &dylib_slice(0x74));
    let slice_str = slice.display().to_string();
    // The baseline is a previous run's --json output (the CLI's own flow:
    // verify without --baseline, save the document).
    let prev_report = run(&["--json", &slice_str]);
    let prev = dir.join("prev.json");
    std::fs::write(&prev, stdout(&prev_report)).expect("the baseline writes");
    let prev_str = prev.display().to_string();
    let path = write_container(&dir, &dylib_slice(0x74), &dylib_slice(0x75));
    let path_str = path.display().to_string();
    let out = run(&["--baseline", &prev_str, &path_str]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "usage refusal: {}",
        stderr(&out)
    );
    let text = stderr(&out);
    assert!(
        text.contains("slice"),
        "the fix names the per-slice face: {text}"
    );
}

#[test]
fn the_malformed_table_refuses_with_the_readers_words() {
    let dir = scratch("malformed");
    let path = dir.join("lying.dylib");
    // A fat header promising seven slices the file does not carry.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0xCAFE_BABEu32.to_be_bytes());
    bytes.extend_from_slice(&7u32.to_be_bytes());
    std::fs::write(&path, bytes).expect("the lying table writes");
    let path_str = path.display().to_string();
    let out = run(&[&path_str]);
    assert_eq!(out.status.code(), Some(1), "the image fails the gate");
    let text = stdout(&out);
    assert!(
        text.contains("REFUSED"),
        "the container refuses, it does not report: {text}"
    );
}

#[test]
fn the_checks_face_composes_with_the_container() {
    let dir = scratch("checks");
    let path = write_container(&dir, &corrupted(&dylib_slice(0x74)), &dylib_slice(0x75));
    let path_str = path.display().to_string();
    let narrow = run(&["--checks", "segments,fixups", &path_str]);
    assert_eq!(
        narrow.status.code(),
        Some(0),
        "the unselected families carry no finding: {}",
        stdout(&narrow)
    );
    let signature = run(&["--checks", "signature", &path_str]);
    assert_eq!(
        signature.status.code(),
        Some(1),
        "the selected family still gates: {}",
        stdout(&signature)
    );
}
