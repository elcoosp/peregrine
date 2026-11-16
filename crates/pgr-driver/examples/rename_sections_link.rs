//! The section-rename consumer example (M53): the same corpus linked
//! plain (the pre-M53 shape — `__DATA,__mydata` rides unnamed) and with
//! `-rename_section __DATA __mydata __DATA_CONST __mydata` (the section
//! groups with its new name and lands in the `__DATA_CONST` segment —
//! the protections follow the segment, ld64's reader-level rename) —
//! the load-command section entries read back from both images, the
//! strict verifier on both, and the grammar refusals (a 16-byte
//! overflow, a synthetic target) rendered as miette help.
//!
//! Run: `cargo run -p pgr-driver --example rename_sections_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// main.o: `_main` over a small `__text`, plus `__DATA,__mydata` (16
/// bytes) — the section the rename moves.
fn main_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        Vec::new(),
    ));
    let data = b.add_section(ObjectSection::data(
        "__mydata",
        vec![0x41u8; 16],
        Vec::new(),
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_mydata_sym".into(),
        section_index: data,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

fn link(dir: &std::path::Path, out: &str, extra: &[&str]) -> Vec<u8> {
    let main = dir.join("main.o");
    std::fs::write(&main, main_object()).unwrap();
    let out_path = dir.join(out);
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        out_path.as_os_str().to_os_string(),
        main.as_os_str().to_os_string(),
    ];
    for arg in extra {
        argv.push(std::ffi::OsString::from(arg));
    }
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs");
    std::fs::read(&out_path).expect("the image reads")
}

/// The `(segname, sectname)` pairs the image's `LC_SEGMENT_64` entries
/// record, in command order.
fn section_pairs(image: &[u8]) -> Vec<(String, String)> {
    let header = pgr_format::MachHeader64::parse(image).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands parse");
    let mut pairs = Vec::new();
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if cmd.kind == pgr_format::LoadCommandKind::Segment64 {
            let seg =
                pgr_format::SegmentCommand64::parse(cmd.bytes, 0).expect("the segment parses");
            let seg_name = seg.name().expect("the segment name reads").to_string();
            let sections = seg
                .sections(cmd.bytes, pgr_format::SegmentCommand64::SIZE)
                .expect("the sections parse");
            for sect in sections {
                let end = sect
                    .sectname
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(sect.sectname.len());
                pairs.push((
                    seg_name.clone(),
                    String::from_utf8_lossy(&sect.sectname[..end]).into_owned(),
                ));
            }
        }
    }
    pairs
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    let dir = std::env::temp_dir().join(format!("pgr_rename_sections_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let opts_strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };

    // 1. The pre-M53 shape: the input pair rides unnamed.
    let plain = link(&dir, "hello_plain", &[]);
    let plain_pairs = section_pairs(&plain);
    assert!(
        plain_pairs.contains(&("__DATA".to_string(), "__mydata".to_string())),
        "the input pair rides unnamed: {plain_pairs:?}"
    );
    let report = verify(&plain, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the default image verifies strict"
    );

    // 2. The decision: `-rename_section` moves the section — the new
    //    pair rides, the old pair is gone, and the image verifies
    //    strict like the default one.
    let renamed = link(
        &dir,
        "hello_renamed",
        &[
            "-rename_section",
            "__DATA",
            "__mydata",
            "__DATA_CONST",
            "__mydata",
        ],
    );
    let renamed_pairs = section_pairs(&renamed);
    assert!(
        renamed_pairs.contains(&("__DATA_CONST".to_string(), "__mydata".to_string())),
        "the renamed pair rides: {renamed_pairs:?}"
    );
    assert!(
        !renamed_pairs.contains(&("__DATA".to_string(), "__mydata".to_string())),
        "the old pair is gone: {renamed_pairs:?}"
    );
    let report = verify(&renamed, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the renamed image verifies strict like the default one"
    );
    println!("bytes: default {}, renamed {}", plain.len(), renamed.len());

    // 3. The grammar: the refusals render the fix (the house
    //    convention — the seam's refusal rides the help, not just the
    //    verdict).
    let over_wide = opts::parse(&[
        "-o".into(),
        "out".into(),
        "-rename_section".into(),
        "__DATA".into(),
        "__mydata".into(),
        "__DATA".into(),
        "___________seventeen".into(),
        "main.o".into(),
    ]);
    assert!(
        over_wide.is_err(),
        "a name over the 16-byte field width refuses"
    );
    let synthetic = opts::parse(&[
        "-o".into(),
        "out".into(),
        "-rename_section".into(),
        "__DATA".into(),
        "__mydata".into(),
        "__TEXT".into(),
        "__unwind_info".into(),
        "main.o".into(),
    ]);
    assert!(
        synthetic.is_err(),
        "a rename into a house-synthesized target refuses"
    );

    println!("\nrename_sections_link: ok");
}
