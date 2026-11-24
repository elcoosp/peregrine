//! The parameterized corpus generator's gate matrix (the
//! `pgr_fixtures::corpus` seam).
//!
//! Plan fidelity: docs/BENCHMARKS.md, "How to read these numbers" —
//! "**Known follow-ups**: … parameterized corpus generator behind an
//! `xtask` for nightly shape sweeps" — and the performance architecture
//! doc §9.2 ("Baselines to run on every rig … commit the harness"), whose
//! corpus table's committable shapes the presets name (the many-tiny
//! links, the parse-heavy large-debug set, the archive-heavy set, the
//! single giant object). The gates pin the shapes the sweeps will ride:
//! determinism (identical bytes every run — the BENCHMARKS corpora
//! contract), parameter responsiveness (a knob moves the shape in pinned
//! arithmetic), preset shapes (the §9.2 rows), parse validity (every
//! object summarizes), and link honesty (a generated corpus links and
//! strict-verifies end to end).
//!
//! The `write` face (the xtask command's) emits into a temp dir — fixture
//! bytes never touch the repo tree (the `.gitignore` contract).

use std::path::PathBuf;

use pgr_core::ids::FileId;
use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{Parallelism, link_from_objects};
use pgr_core::object::InputObject;
use pgr_fixtures::corpus::{CorpusContents, CorpusPreset, CorpusSpec, build_corpus, write_corpus};
use pgr_verify::{Options as VerifyOptions, verify};

/// The strict verifier options the in-process gates ride.
fn strict() -> VerifyOptions {
    VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// A temp directory the write-face tests emit into (removed on return).
fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr-corpus-gate-{tag}"));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

// ---- determinism ---------------------------------------------------------------

#[test]
fn same_spec_builds_identical_bytes() {
    let spec = CorpusSpec::new(CorpusPreset::ManyTiny);
    let first: CorpusContents = build_corpus(&spec).expect("the corpus builds");
    let second: CorpusContents = build_corpus(&spec).expect("the corpus builds");
    assert_eq!(first.files.len(), second.files.len(), "same file count");
    for (a, b) in first.files.iter().zip(second.files.iter()) {
        assert_eq!(a.0, b.0, "same file name");
        assert_eq!(
            a.1, b.1,
            "identical bytes every run (the BENCHMARKS corpora contract)"
        );
    }
    assert_eq!(first.manifest, second.manifest, "same manifest");
}

// ---- parameter responsiveness --------------------------------------------------

#[test]
fn parameters_move_the_shape() {
    let spec = CorpusSpec {
        objects: Some(8),
        text_kib: Some(2),
        ..CorpusSpec::new(CorpusPreset::ManyTiny)
    };
    let contents = build_corpus(&spec).expect("the corpus builds");
    assert_eq!(contents.files.len(), 8, "one file per object");
    let names: Vec<&str> = contents.files.iter().map(|f| f.0.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "obj_0001.o",
            "obj_0002.o",
            "obj_0003.o",
            "obj_0004.o",
            "obj_0005.o",
            "obj_0006.o",
            "obj_0007.o",
            "obj_0008.o",
        ],
        "zero-padded command-line order"
    );
    // The payload arithmetic the sweeps read: `text_kib` KiB of `__text`
    // per object — 2 KiB × 8 objects.
    assert_eq!(contents.manifest.payload_bytes, 8 * 2 * 1024);
    // The same shape at twice the payload: the knob moves the corpus, the
    // names stay pinned.
    let bigger = CorpusSpec {
        objects: Some(8),
        text_kib: Some(4),
        ..CorpusSpec::new(CorpusPreset::ManyTiny)
    };
    let bigger = build_corpus(&bigger).expect("the corpus builds");
    assert_eq!(bigger.manifest.payload_bytes, 8 * 4 * 1024);
    assert_eq!(
        bigger.manifest.payload_bytes,
        contents.manifest.payload_bytes * 2,
        "the knob doubles the payload"
    );
    assert_eq!(
        bigger.manifest.file_bytes,
        bigger.manifest.payload_bytes + bigger.manifest.metadata_bytes
    );
    assert!(
        bigger.manifest.metadata_bytes > 0,
        "the metadata is accounted too"
    );
}

// ---- preset shapes (the §9.2 corpus-table rows) ---------------------------------

#[test]
fn many_tiny_matches_the_plan_shape() {
    // §9.2: "`hello` and a 50-link 'many tiny links' script".
    let spec = CorpusSpec::new(CorpusPreset::ManyTiny);
    let contents = build_corpus(&spec).expect("the corpus builds");
    assert_eq!(contents.manifest.objects, 50);
    assert_eq!(contents.manifest.archive_members, 0);
    assert_eq!(
        contents.manifest.symbols,
        50 * (8 + 2),
        "the per-object symtab shape"
    );
    for (name, bytes) in &contents.files {
        let summary = pgr_format::summarize(bytes).expect("every corpus object parses");
        assert_eq!(summary.sections, 1, "{name}: one __text section");
        assert_eq!(summary.relocations, 1, "{name}: the cross-object branch");
    }
}

#[test]
fn large_debug_matches_the_parse_heavy_shape() {
    // The BENCHMARKS parse-heavy corpus: "16 objects × 4 096 syms × 4 KiB".
    let spec = CorpusSpec::new(CorpusPreset::LargeDebug);
    let contents = build_corpus(&spec).expect("the corpus builds");
    assert_eq!(contents.manifest.objects, 16);
    assert_eq!(contents.manifest.symbols, 16 * (4_096 + 2));
    assert_eq!(contents.manifest.payload_bytes, 16 * 4 * 1024);
    let (_, bytes) = &contents.files[7];
    let summary = pgr_format::summarize(bytes).expect("the object parses");
    assert_eq!(summary.symbols, 4_098, "the metadata the sweep prices");
}

#[test]
fn archive_heavy_writes_the_member_archive() {
    // §9.2: "Archive-heavy (hundreds of static libs, most members unused)".
    let spec = CorpusSpec::new(CorpusPreset::ArchiveHeavy);
    let contents = build_corpus(&spec).expect("the corpus builds");
    let archive = contents
        .files
        .iter()
        .find(|(name, _)| name == "libcorpus.a")
        .expect("the member archive rides the corpus");
    let parsed = pgr_format::parse_archive(&archive.1).expect("the archive parses");
    assert_eq!(parsed.members.len(), 300, "hundreds of members");
    assert_eq!(contents.manifest.objects, 8, "the direct inputs beside it");
    assert_eq!(
        contents.manifest.payload_bytes,
        8 * 4 * 1024 + 300 * 4 * 1024,
        "direct objects plus members"
    );
}

#[test]
fn single_giant_builds_one_object() {
    // §9.2: "Single giant object (unity/LTO-style)".
    let spec = CorpusSpec::new(CorpusPreset::SingleGiant);
    let contents = build_corpus(&spec).expect("the corpus builds");
    assert_eq!(contents.files.len(), 1);
    assert_eq!(contents.manifest.objects, 1);
    assert_eq!(contents.manifest.payload_bytes, 4096 * 1024);
    let (_, bytes) = &contents.files[0];
    let summary = pgr_format::summarize(bytes).expect("the object parses");
    assert_eq!(summary.sections, 1);
    assert_eq!(
        summary.relocations, 0,
        "no cross-object work in a one-object corpus"
    );
}

// ---- the write face (the xtask command's) ---------------------------------------

#[test]
fn write_corpus_emits_the_manifest_tree() {
    let dir = temp_dir("write");
    let spec = CorpusSpec {
        objects: Some(3),
        ..CorpusSpec::new(CorpusPreset::ManyTiny)
    };
    let manifest = write_corpus(&spec, &dir).expect("the corpus writes");
    assert_eq!(manifest.objects, 3);
    for info in &manifest.files {
        let path = dir.join(&info.name);
        let on_disk = std::fs::read(&path).expect("the file exists");
        assert_eq!(
            on_disk.len() as u64,
            info.bytes,
            "{}: the manifest size is the file's",
            info.name
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- the byte-touching shape (the parse bench's corpus) -------------------------

#[test]
fn byte_touching_preset_is_payload_dominated() {
    // docs/BENCHMARKS.md, "Conditions & harness": "`summarize` walks
    // _metadata tables_, not section payload — these are metadata-walk
    // rates, not DRAM streaming. The byte-touching parse starts well
    // below them." The byte-touching preset is the shape that prices the
    // streaming half: the section payload carries the file, so the parse
    // bench's `Throughput::Bytes` denominates by the bytes the file
    // streams, not by the metadata tables.
    let spec = CorpusSpec::new(CorpusPreset::ByteTouching);
    let contents = build_corpus(&spec).expect("the corpus builds");
    assert_eq!(contents.manifest.objects, 1, "one object carries the file");
    assert_eq!(contents.manifest.archive_members, 0);
    // The plan's own gate: payload-dominated — the payload rides at
    // least 99% of the file, every run.
    assert!(
        contents.manifest.payload_bytes * 100 >= contents.manifest.file_bytes * 99,
        "the payload carries the file: {} of {} bytes",
        contents.manifest.payload_bytes,
        contents.manifest.file_bytes
    );
    let (_, bytes) = &contents.files[0];
    let summary = pgr_format::summarize(bytes).expect("the object parses");
    assert_eq!(
        summary.sections, 1,
        "one __text section carries the payload"
    );
    assert_eq!(
        summary.relocations, 0,
        "no metadata beyond the symtab's own"
    );
    assert_eq!(
        summary.symbols, 3,
        "the entry definition plus the shape's two extras"
    );
}

// ---- link honesty ---------------------------------------------------------------

#[test]
fn the_corpus_links_and_verifies_strict() {
    let spec = CorpusSpec {
        objects: Some(8),
        ..CorpusSpec::new(CorpusPreset::ManyTiny)
    };
    let contents = build_corpus(&spec).expect("the corpus builds");
    let arena: Vec<InputObject> = contents
        .files
        .iter()
        .enumerate()
        .map(|(i, (name, bytes))| {
            InputObject::parse(FileId(i as u32), name.as_str(), bytes.clone())
                .expect("every corpus object parses")
        })
        .collect();
    let cfg = LinkConfig {
        filetype: OutputType::Execute,
        ..LinkConfig::default()
    };
    let first =
        link_from_objects(arena, &[], &cfg, Parallelism::Serial, None).expect("the corpus links");
    let image = pgr_emit::build_image(&first.layout, &first.objects).expect("the image emits");
    let report = verify(&image, &strict());
    assert!(
        report
            .issues
            .iter()
            .all(|i| i.severity != pgr_verify::Severity::Error),
        "the linked corpus image verifies strict: {:?}",
        report.issues
    );
    // The determinism contract the corpora ride: the same corpus links
    // byte-identically.
    let arena2: Vec<InputObject> = contents
        .files
        .iter()
        .enumerate()
        .map(|(i, (name, bytes))| {
            InputObject::parse(FileId(i as u32), name.as_str(), bytes.clone())
                .expect("every corpus object parses")
        })
        .collect();
    let second =
        link_from_objects(arena2, &[], &cfg, Parallelism::Serial, None).expect("the corpus links");
    let image2 = pgr_emit::build_image(&second.layout, &second.objects).expect("the image emits");
    assert_eq!(image, image2, "double-link byte-identity");
}
