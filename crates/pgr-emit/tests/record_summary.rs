//! M13 rung 2 — the record inspector: the `.pgr-inc` sidecar becomes
//! readable as a *surface*, not just by the relink engine. The
//! executable specification, in order:
//!
//! * summary — `read_summary` names the record's shape (identity,
//!   skeleton, span/digest/hash counts, the resolve-capture flag) and
//!   the rows match the in-memory record's own tables,
//! * read — `read_record` returns the whole record (the engine's
//!   decoder, now with a typed error surface instead of `None`),
//! * frame honesty — every way a sidecar can be wrong (missing, too
//!   small, foreign, truncated, corrupt, foreign revision) refuses
//!   with the layer named and the fix in the message,
//! * render — the text form is deterministic (the house contract) and
//!   plan-ordered.
//!
//! The record's trust model is unchanged: the sidecar is an
//! accelerator, and every refusal here is diagnosable, never fatal —
//! the next full link re-records.

use std::path::PathBuf;

use pgr_core::layout::{Layout, LinkConfig, OutputType};
use pgr_core::link::{LinkInput, Parallelism, link_cached};
use pgr_emit::build_image_fused;
use pgr_emit::incremental::{LinkRecord, RecordReadError, read_record, read_summary};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// hello.o: `_main` returns 0, a `__cstring`, no imports — a static
/// executable the pipeline links clean with no library inputs.
fn hello_o() -> ObjectBuilder {
    let mut b = ObjectBuilder::new("hello.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0x00u8, 0x00, 0x80, 0xD2, 0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_section(ObjectSection::cstring("hello, record\n"));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b
}

/// Links the corpus and records it: the sidecar bytes plus the
/// in-memory record the assertions compare against.
fn recorded_link(tag: &str) -> (PathBuf, LinkRecord) {
    let cfg = LinkConfig {
        ident: format!("m13-record-{tag}"),
        filetype: OutputType::Execute,
        ..LinkConfig::default()
    };
    let inputs = vec![LinkInput {
        name: "hello.o".into(),
        bytes: hello_o().build().expect("the fixture builds"),
    }];
    let result = link_cached(&inputs, &[], &cfg, Parallelism::Auto, None)
        .expect("the static link links clean");
    let Layout { .. } = result.layout;
    let image = build_image_fused(&result.layout, &result.objects).expect("the image emits");
    let record = LinkRecord::record(&result.layout, &result.objects, &image, None)
        .expect("the finished image records");
    let dir = std::env::temp_dir().join(format!(
        "pgr_m13_record_{tag}_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the clock runs")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("the scratch dir creates");
    let path = dir.join("app.pgr-inc");
    std::fs::write(&path, record.encode()).expect("the sidecar writes");
    (path, record)
}

// ------------------------------------------------------------------ summary

#[test]
fn the_summary_names_the_record_it_read() {
    let (path, record) = recorded_link("summary");
    let summary = read_summary(&path).expect("the sidecar reads");
    assert_eq!(summary.format_version, record.format_version);
    assert_eq!(summary.ident, record.ident);
    assert_eq!(summary.filetype, record.filetype);
    assert_eq!(summary.file_size, record.file_size);
    assert_eq!(summary.image_base, record.image_base);
    assert_eq!(summary.text_vmsize, record.text_vmsize);
    assert_eq!(summary.entryoff, record.entryoff);
    assert!(summary.signed, "the ad-hoc default signs the image");
    assert_eq!(summary.code_limit, record.code_limit);
    assert_eq!(summary.resolve_captured, record.resolution.is_some());

    assert_eq!(summary.segments.len(), record.segments.len());
    for (row, seg) in summary.segments.iter().zip(&record.segments) {
        assert_eq!(row.name, seg.name);
        assert_eq!(row.vmaddr, seg.vmaddr);
        assert_eq!(row.vmsize, seg.vmsize);
        assert_eq!(row.fileoff, seg.fileoff);
        assert_eq!(row.filesize, seg.filesize);
    }
    assert_eq!(summary.sections.len(), record.sections.len());
    assert_eq!(
        summary.spans,
        record.spans.runs.len()
            + record.spans.synths.len()
            + record.spans.blobs.len()
            + record.spans.patches.len()
            + record.spans.words.len()
    );
    assert_eq!(summary.imports, record.imports.len());
    assert_eq!(summary.section_digests, record.section_digests.len());
    assert_eq!(summary.content_digests, record.content_digests.len());
    assert_eq!(summary.page_hashes, record.page_hashes.len());
}

#[test]
fn read_record_returns_the_whole_record() {
    let (path, record) = recorded_link("whole");
    let read = read_record(&path).expect("the sidecar reads");
    assert_eq!(read, record, "the typed read returns the engine's record");
}

#[test]
fn the_render_is_deterministic_and_names_the_shape() {
    let (path, _record) = recorded_link("render");
    let summary = read_summary(&path).expect("the sidecar reads");
    let a = summary.render();
    let b = summary.render();
    assert_eq!(a, b, "the same record renders byte-identical text");
    assert!(a.starts_with("# Peregrine link record"), "{a}");
    assert!(a.contains("m13-record-render"), "the ident rides: {a}");
    assert!(a.contains("segment __TEXT"), "{a}");
    assert!(a.contains("section __text"), "{a}");
    assert!(a.contains("spans:"), "{a}");
    assert!(a.contains("record version:"), "{a}");
}

// -------------------------------------------------------------------- frame

#[test]
fn a_missing_file_is_a_typed_io_error() {
    let err = read_record(std::path::Path::new("/nonexistent/pgr/app.pgr-inc"))
        .expect_err("nothing recorded there");
    assert!(matches!(err, RecordReadError::Io { .. }), "{err:?}");
    assert!(err.to_string().contains("No such file"), "{err}");
}

#[test]
fn frame_offenses_name_their_layer() {
    let (_path, record) = recorded_link("frame");
    let encoded = record.encode();

    // Too small to carry the frame header.
    let tiny = &encoded[..40.min(encoded.len())];
    match read_err(tiny) {
        RecordReadError::TooSmall { len, need } => {
            assert_eq!(len, tiny.len());
            assert!(need > len);
        }
        other => panic!("expected TooSmall, got {other:?}"),
    }

    // Foreign bytes (a Mach-O, a cache entry, anything else).
    let mut foreign = encoded.clone();
    foreign[..8].copy_from_slice(b"NOTAREC\0");
    assert!(matches!(read_err(&foreign), RecordReadError::Magic));

    // The right magic, the wrong length on the wire.
    let mut truncated = encoded.clone();
    truncated.pop();
    match read_err(&truncated) {
        RecordReadError::Length { expected, found } => {
            assert!(expected > found, "{expected} > {found}");
        }
        other => panic!("expected Length, got {other:?}"),
    }

    // A flipped payload byte: the checksum names the corruption.
    let mut corrupt = encoded.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 0xff;
    assert!(matches!(read_err(&corrupt), RecordReadError::Checksum));

    // A foreign revision whose checksum was honestly recomputed: the
    // version refusal names both sides.
    let mut other_rev = encoded.clone();
    let found = record.format_version + 1;
    other_rev[8..12].copy_from_slice(&found.to_le_bytes());
    let digest = sha_of(&other_rev[52..]);
    other_rev[20..52].copy_from_slice(&digest);
    match read_err(&other_rev) {
        RecordReadError::Version { found, supported } => {
            assert_ne!(found, supported);
            let text = read_err(&other_rev).to_string();
            assert!(
                text.contains("re-record"),
                "the fix is in the message: {text}"
            );
        }
        other => panic!("expected Version, got {other:?}"),
    }
}

fn read_err(bytes: &[u8]) -> RecordReadError {
    let dir = std::env::temp_dir().join("pgr_m13_frame_probe");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let path = dir.join("probe.pgr-inc");
    std::fs::write(&path, bytes).expect("probe writes");
    match read_record(&path) {
        Err(e) => e,
        Ok(_) => panic!("the probe bytes must not read as a record"),
    }
}

fn sha_of(payload: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(payload).into()
}
