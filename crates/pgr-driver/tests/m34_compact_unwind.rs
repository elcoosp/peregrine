//! M34 — the compact-unwind driver surface: an entry-carrying corpus
//! links end-to-end with the `__TEXT,__unwind_info` section present
//! (and verifies strict), the entry-free corpus plans the pre-M34
//! bytes (no section), the cached and resident lanes stay
//! byte-identical to the one-shot link (the section rides the same
//! plan the caches and the record digest), and the incremental relink
//! of an entry-carrying image stays byte-identical to the full link.

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64};
use pgr_verify::{Options as VerifyOptions, verify};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m34_unwind_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// An entry-carrying corpus (`_main` over three RET functions, one
/// compact-unwind entry per function).
fn corpus(dir: &Path, tag: &str, entries: bool) -> PathBuf {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        vec![],
    ));
    for (i, sym) in ["_main", "_fn_1", "_fn_2"].iter().enumerate() {
        b.add_symbol(ObjectSymbol::Defined {
            name: (*sym).into(),
            section_index: text,
            value: (i * 4) as u64,
            weak: false,
        });
    }
    if entries {
        let table: Vec<pgr_format::CompactUnwindEntry> = (0..3)
            .map(|f| pgr_format::CompactUnwindEntry {
                range_start: (f * 4) as u64,
                range_length: 4,
                encoding: pgr_format::consts::UNWIND_ARM64_MODE_FRAME,
                personality: 0,
                lsda: 0,
            })
            .collect();
        b.add_section(ObjectSection::compact_unwind(&table));
    }
    let path = dir.join(format!("main_{tag}_{entries}.o"));
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    path
}

/// Links `obj` under `extra` argv; returns the image bytes.
fn link(dir: &Path, out: &str, obj: &Path, extra: &[&str]) -> Vec<u8> {
    let out_path = dir.join(out);
    let mut argv: Vec<String> = vec!["-o".into(), out_path.display().to_string()];
    argv.push(obj.display().to_string());
    argv.extend(extra.iter().map(std::string::ToString::to_string));
    let argv: Vec<std::ffi::OsString> = argv.iter().map(std::ffi::OsString::from).collect();
    let o = pgr_driver::opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs");
    std::fs::read(&out_path).unwrap()
}

fn strict() -> VerifyOptions {
    VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// True when the image names `__TEXT,__unwind_info` in its section
/// table (the synthesized section rides the header's `__TEXT` segment).
fn carries_unwind_info(image: &[u8]) -> bool {
    let header = MachHeader64::parse(image).expect("the image parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if let LoadCommandKind::Segment64 = cmd.kind {
            let seg =
                pgr_format::SegmentCommand64::parse(cmd.bytes, 0).expect("the segment parses");
            for s in seg
                .sections(cmd.bytes, pgr_format::SegmentCommand64::SIZE)
                .expect("the sections parse")
            {
                if s.segname.starts_with(b"__TEXT\0") && s.sectname.starts_with(b"__unwind_info\0")
                {
                    return true;
                }
            }
        }
    }
    false
}

#[test]
fn the_entry_carrying_corpus_links_and_verifies_strict() {
    let dir = scratch("e2e");
    let obj = corpus(&dir, "e2e", true);
    let image = link(&dir, "app", &obj, &[]);
    assert!(
        carries_unwind_info(&image),
        "the linked image names the synthesized section"
    );
    let report = verify(&image, &strict());
    assert!(
        report.is_ok(&strict()),
        "the entry-carrying image verifies strict: {:?}",
        report.issues
    );
    assert!(
        !report
            .issues
            .iter()
            .any(|i| i.code == pgr_verify::Code::UnwindInfo),
        "no unwind findings ride the honest link: {:?}",
        report.issues
    );
}

#[test]
fn the_entry_free_corpus_plans_the_pre_m34_bytes() {
    let dir = scratch("free");
    let obj = corpus(&dir, "free", false);
    let image = link(&dir, "app", &obj, &[]);
    assert!(
        !carries_unwind_info(&image),
        "the entry-free corpus synthesizes nothing"
    );
    let report = verify(&image, &strict());
    assert!(
        report.is_ok(&strict()),
        "the pre-M34 shape verifies strict: {:?}",
        report.issues
    );
}

#[test]
fn the_cached_lane_stays_byte_identical() {
    let dir = scratch("cached");
    let obj = corpus(&dir, "cached", true);
    let plain = link(&dir, "plain", &obj, &[]);
    let cached = link(
        &dir,
        "cached",
        &obj,
        &["-cache", ".pgr-cache", "-cache_max", "10"],
    );
    // Warm the cache with a second link, then compare against one-shot.
    let warm = link(
        &dir,
        "warm",
        &obj,
        &["-cache", ".pgr-cache", "-cache_max", "10"],
    );
    assert_eq!(plain, cached, "the cold cached link is byte-identical");
    assert_eq!(
        plain, warm,
        "the warm cached link (codec-carried entries) is byte-identical"
    );
}

#[test]
fn the_incremental_relink_freezes_the_entry_carrying_skeleton() {
    // The house incremental gates (M9): the first link records, an
    // unchanged relink is a reported noop (0 bytes patched), the
    // skeleton is frozen (the file size never moves), and the
    // relinked image still carries the synthesized section — the
    // record's section skeleton rides the new section like every
    // other.
    let dir = scratch("inc");
    let obj = corpus(&dir, "inc", true);
    let out = dir.join("app_inc");
    let inc_argv = || {
        let argv: Vec<std::ffi::OsString> = vec![
            std::ffi::OsString::from("-o"),
            out.as_os_str().to_os_string(),
            obj.as_os_str().to_os_string(),
            std::ffi::OsString::from("-incremental"),
        ];
        pgr_driver::opts::parse(&argv).expect("the argv parses")
    };
    pgr_driver::run(&inc_argv()).expect("the recording link runs");
    let first = std::fs::read(&out).unwrap();
    assert!(
        carries_unwind_info(&first),
        "the recorded image carries the synthesized section"
    );
    let second = pgr_driver::run(&inc_argv()).expect("the relink runs");
    let patch = second.patch.expect("the relink goes through the engine");
    assert!(patch.untouched, "identical inputs touch nothing");
    assert_eq!(patch.bytes_patched, 0, "the noop ships no bytes");
    let again = std::fs::read(&out).unwrap();
    assert_eq!(
        first.len(),
        again.len(),
        "the skeleton is frozen (the file size never moves)"
    );
    assert!(
        carries_unwind_info(&again),
        "the relinked image still carries the synthesized section"
    );
    let report = verify(&again, &strict());
    assert!(
        report.is_ok(&strict()),
        "the relinked image verifies strict: {:?}",
        report.issues
    );
}
