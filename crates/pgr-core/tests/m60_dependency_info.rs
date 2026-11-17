//! M60 — the build-system dependency record (`pgr_core::dep_info`, the
//! `-dependency_info <path>` driver flag): ld64's sidecar artifact — the
//! file Xcode's incremental builds read to learn which files a link read
//! and which one it wrote. The format is ld64's own
//! (`Options::writeDependencyInfo`, apple-oss-distributions ld64): a
//! linker-version row (opcode `0x00`, then the version string,
//! NUL-terminated) followed by `(opcode, path)` rows — every input `0x10`
//! (ld64's `depObjectFile`/`depDirectDylib`/`depArchive`/`depFileList`/
//! `depSection`/`depBundleLoader`/`depMisc` family, one opcode in the
//! field), a probed-but-missing candidate `0x11`, the output (and the
//! `-map` beside it) `0x40` — each row NUL-terminated, the entries sorted
//! by `(opcode, path)` for build reproducibility (ld64's
//! <rdar://30750137> sort).
//!
//! Gate matrix:
//! * the format — the ld64 opcode family, the version row, the
//!   NUL-terminated rows, the reproducibility sort;
//! * the determinism — two records built in different insertion orders
//!   render identically (the sidecar is diffable, the image is
//!   byte-identical);
//! * the reader — `parse` restores the writer's data exactly (the
//!   `to_json`/`parse_report_json` round-trip convention, gated) and
//!   refuses the broken shapes with the byte position named;
//! * the rows — duplicates ride verbatim (ld64's own shape, no
//!   deduplication the consumer would not expect).

use pgr_core::dep_info::{
    DepInfoError, DependencyEntry, DependencyRecord, INPUT, LINKER_VERSION, NOT_FOUND, OUTPUT,
};

/// A record as the driver builds it: the version row, two inputs in
/// scrambled order, a probed miss and the output.
fn sample() -> DependencyRecord {
    let mut r = DependencyRecord::new("pgr (Peregrine) 0.22.0").expect("the version row validates");
    r.record_output("out/app").expect("the path validates");
    r.record_input("b.o").expect("the path validates");
    r.record_input("a.o").expect("the path validates");
    r.record_not_found("libs/libgreet.tbd")
        .expect("the path validates");
    r
}

#[test]
fn the_ld64_opcode_family_is_the_field_shape() {
    // ld64's enum collapses the input family onto one opcode (0x10): the
    // object/dylib/archive/filelist/section/bundle-loader/misc names are
    // aliases, the field carries 0x10; the not-found probe is 0x11, the
    // output 0x40, the linker-version row 0x00.
    assert_eq!(LINKER_VERSION, 0x00);
    assert_eq!(INPUT, 0x10);
    assert_eq!(NOT_FOUND, 0x11);
    assert_eq!(OUTPUT, 0x40);
}

#[test]
fn entries_sort_by_opcode_then_path() {
    // ld64's <rdar://30750137> reproducibility sort: opcode ascending, then
    // path ascending. The record sorts eagerly, so every face (entries,
    // render, parse) reads the same canonical order.
    let r = sample();
    let rows: Vec<(u8, &str)> = r
        .entries()
        .iter()
        .map(|e| (e.opcode, std::str::from_utf8(&e.path).unwrap()))
        .collect();
    assert_eq!(
        rows,
        vec![
            (INPUT, "a.o"),
            (INPUT, "b.o"),
            (NOT_FOUND, "libs/libgreet.tbd"),
            (OUTPUT, "out/app"),
        ]
    );
}

#[test]
fn render_writes_the_ld64_shape() {
    let r = sample();
    let bytes = r.render();
    let mut expected: Vec<u8> = Vec::new();
    expected.push(LINKER_VERSION);
    expected.extend_from_slice(b"pgr (Peregrine) 0.22.0\0");
    for (opcode, path) in [
        (INPUT, "a.o"),
        (INPUT, "b.o"),
        (NOT_FOUND, "libs/libgreet.tbd"),
        (OUTPUT, "out/app"),
    ] {
        expected.push(opcode);
        expected.extend_from_slice(path.as_bytes());
        expected.push(b'\0');
    }
    assert_eq!(bytes, expected);
}

#[test]
fn render_is_deterministic_across_insertion_orders() {
    let mut other = DependencyRecord::new("pgr (Peregrine) 0.22.0").expect("the version validates");
    other.record_not_found("libs/libgreet.tbd").expect("valid");
    other.record_input("a.o").expect("valid");
    other.record_output("out/app").expect("valid");
    other.record_input("b.o").expect("valid");
    assert_eq!(sample().render(), other.render());
}

#[test]
fn parse_restores_the_rendered_record() {
    // The round-trip convention (the map JSON, the report JSON): the
    // reader restores the writer's data exactly — gated here.
    let r = sample();
    let parsed = DependencyRecord::parse(&r.render()).expect("the record parses");
    assert_eq!(parsed, r);
    assert_eq!(parsed.linker_version(), "pgr (Peregrine) 0.22.0");
}

#[test]
fn duplicate_rows_ride_verbatim() {
    // ld64 records the same path once per decision that read it and never
    // deduplicates; a consumer counting rows sees the link's own shape.
    let mut r = DependencyRecord::new("v").expect("the version validates");
    r.record_input("a.o").expect("valid");
    r.record_input("a.o").expect("valid");
    assert_eq!(r.entries().len(), 2);
    let parsed = DependencyRecord::parse(&r.render()).expect("parses");
    assert_eq!(parsed, r);
}

#[test]
fn an_empty_version_refuses() {
    assert_eq!(DependencyRecord::new(""), Err(DepInfoError::EmptyVersion));
}

#[test]
fn a_nul_in_the_version_refuses() {
    assert_eq!(
        DependencyRecord::new("pgr\0evil"),
        Err(DepInfoError::NulVersion { offset: 3 })
    );
}

#[test]
fn empty_and_nul_paths_refuse_at_record_time() {
    let mut r = DependencyRecord::new("v").expect("the version validates");
    assert_eq!(
        r.record_input(""),
        Err(DepInfoError::EmptyPath { row: "input" })
    );
    assert_eq!(
        r.record_input("a\0.o"),
        Err(DepInfoError::NulPath {
            row: "input",
            offset: 1
        })
    );
    assert_eq!(
        r.record_output(""),
        Err(DepInfoError::EmptyPath { row: "output" })
    );
    assert_eq!(
        r.record_not_found(""),
        Err(DepInfoError::EmptyPath { row: "not-found" })
    );
}

#[test]
fn parse_refuses_the_broken_shapes_with_positions() {
    // No version row: the first opcode is not 0x00.
    let no_version = [INPUT, b'a', b'\0'];
    assert_eq!(
        DependencyRecord::parse(&no_version),
        Err(DepInfoError::VersionRowMissing { opcode: INPUT })
    );
    // An unknown opcode: outside the ld64 family.
    let unknown = [LINKER_VERSION, b'v', b'\0', 0x7f, b'x', b'\0'];
    assert_eq!(
        DependencyRecord::parse(&unknown),
        Err(DepInfoError::UnknownOpcode {
            opcode: 0x7f,
            offset: 3
        })
    );
    // A row with no NUL terminator: the record is truncated.
    let truncated = [LINKER_VERSION, b'v', b'\0', INPUT, b'a', b'.'];
    assert_eq!(
        DependencyRecord::parse(&truncated),
        Err(DepInfoError::Truncated { offset: 3 })
    );
    // An empty path in a row: the writer never emits one, so a reader
    // that sees one is reading a broken file (the rigid-schema rule).
    let empty_path = [LINKER_VERSION, b'v', b'\0', INPUT, b'\0'];
    assert_eq!(
        DependencyRecord::parse(&empty_path),
        Err(DepInfoError::EmptyRowPath { offset: 3 })
    );
    // The version row with no NUL terminator.
    let no_version_nul = [LINKER_VERSION, b'v'];
    assert_eq!(
        DependencyRecord::parse(&no_version_nul),
        Err(DepInfoError::Truncated { offset: 0 })
    );
}

#[test]
fn parse_accepts_non_utf8_path_bytes() {
    // Paths are filesystem bytes, not UTF-8 promises: the reader restores
    // them verbatim (the house treats names as bytes).
    let bytes = [LINKER_VERSION, b'v', b'\0', INPUT, 0xFF, b'.', b'o', b'\0'];
    let parsed = DependencyRecord::parse(&bytes).expect("the bytes parse");
    assert_eq!(
        parsed.entries(),
        [DependencyEntry {
            opcode: INPUT,
            path: vec![0xFF, b'.', b'o']
        }]
    );
}

#[test]
fn the_error_types_are_shared_shapes() {
    // The record and the reader name the same refusals; every error
    // carries the position or the row it names (the fix, not just the
    // verdict — the house error convention).
    let msg = DepInfoError::UnknownOpcode {
        opcode: 0x55,
        offset: 9,
    }
    .to_string();
    assert!(msg.contains("0x55"));
    assert!(msg.contains('9'));
}
