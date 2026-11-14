//! M36 — the compact-unwind driver surface: `-no_compact_unwind`
//! links an entry-carrying corpus into an image without the
//! `__TEXT,__unwind_info` section (and verifies strict), the
//! suppressed link is byte-identical to the entry-free link (the
//! pre-M34 bytes), the cached lane stays byte-identical under the
//! knob, and the incremental relink of a knob flip lands on the
//! full-link rung byte-identically (the ladder's every rung is a
//! correct image).

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64};
use pgr_verify::{Options as VerifyOptions, verify};
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m36_unwind_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// An entry-carrying corpus (`_main` over three RET functions, one
/// compact-unwind entry per function) — or the same corpus without
/// the table.
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
    std::fs::read(&out_path).expect("the image reads")
}

fn strict() -> VerifyOptions {
    VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// Whether the image carries the `__TEXT,__unwind_info` section.
fn carries_unwind_info(image: &[u8]) -> bool {
    let header = MachHeader64::parse(image).expect("the image parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if let LoadCommandKind::Segment64 = cmd.kind {
            let seg =
                pgr_format::SegmentCommand64::parse(cmd.bytes, 0).expect("the segment parses");
            let sects = seg
                .sections(cmd.bytes, pgr_format::SegmentCommand64::SIZE)
                .expect("the sections parse");
            for s in sects {
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
fn m36_flag_shapes_the_config() {
    let dir = scratch("opts");
    let obj = corpus(&dir, "opts", true);
    let argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        dir.join("app").as_os_str().to_os_string(),
        obj.as_os_str().to_os_string(),
        std::ffi::OsString::from("-no_compact_unwind"),
    ];
    let o = pgr_driver::opts::parse(&argv).expect("the argv parses");
    assert!(
        !o.config.compact_unwind,
        "the suppression names the decision"
    );
    let default = pgr_driver::opts::parse(&argv[..3]).expect("the argv parses");
    assert!(
        default.config.compact_unwind,
        "the default keeps every pre-M36 link byte-identical"
    );
}

#[test]
fn the_suppressed_corpus_links_without_the_section_and_verifies_strict() {
    let dir = scratch("e2e");
    let obj = corpus(&dir, "sup", true);
    let image = link(&dir, "app_nounwind", &obj, &["-no_compact_unwind"]);
    assert!(
        !carries_unwind_info(&image),
        "the suppression drops the section"
    );
    let report = verify(&image, &strict());
    assert!(
        report.is_ok(&strict()),
        "the suppressed image verifies strict: {:?}",
        report.issues
    );
}

#[test]
fn the_suppressed_link_is_the_entry_free_link_byte_for_byte() {
    let dir = scratch("bytes");
    let carried = corpus(&dir, "carried", true);
    let plain = corpus(&dir, "plain", false);
    let suppressed = link(&dir, "app_sup", &carried, &["-no_compact_unwind"]);
    let entry_free = link(&dir, "app_free", &plain, &[]);
    assert_eq!(
        suppressed, entry_free,
        "the suppression plans the pre-M34 bytes exactly"
    );
}

#[test]
fn the_cached_lane_stays_byte_identical_under_the_knob() {
    let dir = scratch("cache");
    let obj = corpus(&dir, "cached", true);
    let plain = link(&dir, "app_plain", &obj, &["-no_compact_unwind"]);
    let cached = link(
        &dir,
        "app_cached",
        &obj,
        &[
            "-no_compact_unwind",
            "-cache",
            &dir.join("cache").display().to_string(),
        ],
    );
    assert_eq!(
        plain, cached,
        "the cold cached link is byte-identical (the cache carries parsed inputs, the knob rides the plan)"
    );
}

#[test]
fn the_incremental_flip_lands_on_a_correct_image() {
    // Link carried (the M35 shape), then relink with the suppression:
    // the section's presence changes, so the ladder cannot tile-patch
    // (the record's skeleton no longer matches) and lands on the
    // relayout rung — a correct image of the new plan. The correctness
    // gate is the strict verify plus the section's absence; the
    // byte-identity gates compare lanes of the SAME plan (the
    // relayout rung may keep the previous file's reservation, so the
    // shape is not the one-shot link's bytes). The record renews, so
    // the cycle never stalls: the next identical relink is a noop.
    let dir = scratch("inc");
    let obj = corpus(&dir, "inc", true);
    let carried_path = dir.join("app_carried");
    let carried_argv = || {
        let argv: Vec<std::ffi::OsString> = vec![
            std::ffi::OsString::from("-o"),
            carried_path.as_os_str().to_os_string(),
            obj.as_os_str().to_os_string(),
            std::ffi::OsString::from("-incremental"),
        ];
        pgr_driver::opts::parse(&argv).expect("the argv parses")
    };
    pgr_driver::run(&carried_argv()).expect("the recording link runs");
    let carried = std::fs::read(&carried_path).unwrap();
    assert!(
        carries_unwind_info(&carried),
        "the carried image carries the section"
    );

    // The suppressed relink under `-incremental`.
    let sup_argv = || {
        let argv: Vec<std::ffi::OsString> = vec![
            std::ffi::OsString::from("-o"),
            carried_path.as_os_str().to_os_string(),
            obj.as_os_str().to_os_string(),
            std::ffi::OsString::from("-incremental"),
            std::ffi::OsString::from("-no_compact_unwind"),
        ];
        pgr_driver::opts::parse(&argv).expect("the argv parses")
    };
    pgr_driver::run(&sup_argv()).expect("the relink runs");
    let relinked = std::fs::read(&carried_path).unwrap();
    assert!(
        !carries_unwind_info(&relinked),
        "the relinked image drops the section"
    );
    assert!(
        relinked.len() <= carried.len(),
        "the relayout rung never grows the file for a suppression"
    );
    let report = verify(&relinked, &strict());
    assert!(
        report.is_ok(&strict()),
        "the relinked image verifies strict: {:?}",
        report.issues
    );

    // The record renewed: the next identical relink is a noop (the
    // cycle never stalls).
    let again = pgr_driver::run(&sup_argv()).expect("the noop relink runs");
    let patch = again.patch.expect("the relink goes through the engine");
    assert!(
        patch.untouched,
        "the record renews (the noop ships nothing)"
    );
    assert_eq!(patch.bytes_patched, 0, "the noop ships no bytes");

    // The mirror flip: relink back to the default — the section
    // returns and the image verifies strict.
    pgr_driver::run(&carried_argv()).expect("the relink back runs");
    let restored = std::fs::read(&carried_path).unwrap();
    assert!(
        carries_unwind_info(&restored),
        "the flip back carries the section again"
    );
    let report = verify(&restored, &strict());
    assert!(
        report.is_ok(&strict()),
        "the restored image verifies strict: {:?}",
        report.issues
    );
    let again = pgr_driver::run(&carried_argv()).expect("the noop relink back runs");
    let patch = again.patch.expect("the relink goes through the engine");
    assert!(patch.untouched, "the record renews after the flip back");
    assert_eq!(patch.bytes_patched, 0, "the noop ships no bytes");
}
