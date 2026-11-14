//! The sect-align consumer example (M28): the same corpus linked as a
//! plain executable (the pre-M28 input-only alignment) and as one
//! naming `-sectalign __DATA __data 0x4000` — the named section's
//! address and align field read back from both images, the strict
//! verifier on both, and the unknown-segment refusal rendered as miette
//! help text (the fix, not just the verdict: the house consumer-example
//! convention).
//!
//! Run: `cargo run -p pgr-driver --example sectalign_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// A corpus with two `__DATA` sections — `__data` (the floor's target)
/// and `__more` (the section the raised boundary pushes forward).
fn corpus_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        Vec::new(),
    ));
    for (i, sym) in ["_main", "_helper"].iter().enumerate() {
        b.add_symbol(ObjectSymbol::Defined {
            name: (*sym).into(),
            section_index: text,
            value: (i * 4) as u64,
            weak: false,
        });
    }
    b.add_section(ObjectSection::data("__data", vec![0xAA; 8], Vec::new()));
    b.add_section(ObjectSection::data("__more", vec![0x55; 12], Vec::new()));
    b.build().expect("the fixture object builds")
}

/// The image's `section_64` rows: `(segment, section, addr, align)`.
fn sections_of(image: &[u8]) -> Vec<(String, String, u64, u32)> {
    let header = pgr_format::MachHeader64::parse(image).expect("the image parses");
    let mut out = Vec::new();
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if cmd.kind == pgr_format::LoadCommandKind::Segment64 {
            let seg =
                pgr_format::SegmentCommand64::parse(cmd.bytes, 0).expect("the segment parses");
            for s in seg
                .sections(cmd.bytes, pgr_format::SegmentCommand64::SIZE)
                .expect("the sections parse")
            {
                out.push((
                    seg.name().expect("utf8 segment").to_string(),
                    s.name().expect("utf8 section").to_string(),
                    s.addr,
                    s.align,
                ));
            }
        }
    }
    out
}

fn link(dir: &std::path::Path, out: &str, extra: &[&str]) -> Vec<u8> {
    let obj = dir.join("main.o");
    std::fs::write(&obj, corpus_object()).unwrap();
    let out_path = dir.join(out);
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        out_path.as_os_str().to_os_string(),
        obj.as_os_str().to_os_string(),
    ];
    for arg in extra {
        argv.push(std::ffi::OsString::from(arg));
    }
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs");
    std::fs::read(&out_path).expect("the image reads")
}

fn data_section(image: &[u8]) -> (u64, u32) {
    sections_of(image)
        .iter()
        .find(|(seg, name, _, _)| seg == "__DATA" && name == "__data")
        .map(|(_, _, addr, align)| (*addr, *align))
        .expect("the named section exists")
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    let dir = std::env::temp_dir().join(format!("pgr_sectalign_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // 1. The plain executable: the pre-M28 shape — the input alignment
    //    rides (the fixture's `__data` is 8-aligned).
    let plain = link(&dir, "hello_plain", &[]);
    let (plain_addr, plain_align) = data_section(&plain);
    assert_eq!(plain_align, 3, "the input alignment rides");
    let opts_strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let report = verify(&plain, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the pre-M28 shape verifies strict"
    );

    // 2. The decision: `-sectalign __DATA __data 0x4000` raises the
    //    named section's alignment — the align field carries the
    //    exponent and the address lands on the raised boundary — and
    //    the image verifies strict like the default one.
    let knobbed = link(
        &dir,
        "hello_sectalign",
        &["-sectalign", "__DATA", "__data", "0x4000"],
    );
    let (knob_addr, knob_align) = data_section(&knobbed);
    println!(
        "__DATA,__data: default addr {plain_addr:#x} align 2^{plain_align}, \
         floored addr {knob_addr:#x} align 2^{knob_align}"
    );
    assert_eq!(knob_align, 14, "the named decision raises the exponent");
    assert_eq!(
        knob_addr % 0x4000,
        0,
        "the address lands on the raised boundary"
    );
    let report = verify(&knobbed, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the floored executable verifies strict like the default one"
    );

    // 3. The refusal: the knob off a section-bearing segment is a
    //    parse-time refusal — `__LINKEDIT` carries no sections —
    //    rendered as miette help text (the fix, not just the verdict).
    let argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        dir.join("hello_out").display().to_string(),
        "-sectalign".to_string(),
        "__LINKEDIT".to_string(),
        "__symtab".to_string(),
        "0x1000".to_string(),
        dir.join("main.o").display().to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    match opts::parse(&argv) {
        Ok(_) => unreachable!("the unknown-segment conflict refuses"),
        Err(err) => {
            eprintln!("\nthe refusal (verdict + fix):");
            eprintln!("{:?}", miette::Report::new(err));
        }
    }

    println!("\nsectalign_link: ok");
}
