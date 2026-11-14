//! The headerpad consumer example (M29): the same corpus linked as a
//! plain executable (the pre-M29 natural header region) and as one
//! naming `-headerpad 0x2000` — the first `__TEXT` section's offset
//! read back from both images, the strict verifier on both, and the
//! zero-floor refusal rendered as miette help text (the fix, not just
//! the verdict: the house consumer-example convention).
//!
//! Run: `cargo run -p pgr-driver --example headerpad_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// hello.o: `_main` over a small `__text` — the executable the example
/// links twice.
fn hello_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("hello.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        Vec::new(),
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// The first `__TEXT` section's file offset (from the `section_64` row).
fn first_text_offset(image: &[u8]) -> u32 {
    let header = pgr_format::MachHeader64::parse(image).expect("the image parses");
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
            if seg.name() == Ok("__TEXT") {
                let sects = seg
                    .sections(cmd.bytes, pgr_format::SegmentCommand64::SIZE)
                    .expect("the sections parse");
                return sects
                    .first()
                    .expect("the text segment carries a section")
                    .offset;
            }
        }
    }
    unreachable!("a segmented image carries a __TEXT section")
}

fn link(dir: &std::path::Path, out: &str, extra: &[&str]) -> Vec<u8> {
    let obj = dir.join("hello.o");
    std::fs::write(&obj, hello_object()).unwrap();
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

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    let dir = std::env::temp_dir().join(format!("pgr_headerpad_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // 1. The plain executable: the pre-M29 shape — the natural header
    //    region rides.
    let plain = link(&dir, "hello_natural", &[]);
    let natural = first_text_offset(&plain);
    let opts_strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let report = verify(&plain, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the natural region verifies strict"
    );

    // 2. The decision: `-headerpad 0x2000` grows the reserved region —
    //    the first section moves past the named floor and every later
    //    byte follows — and the image verifies strict like the default
    //    one.
    let knobbed = link(&dir, "hello_padded", &["-headerpad", "0x2000"]);
    let padded = first_text_offset(&knobbed);
    println!("first __TEXT section: natural {natural:#x}, floored {padded:#x}");
    assert_eq!(
        u64::from(padded),
        0x2000,
        "the named decision grows the reserved region"
    );
    let report = verify(&knobbed, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the padded executable verifies strict like the default one"
    );

    // 3. The refusal: `-headerpad 0` is a parse-time refusal — zero
    //    names the absence of the knob, not a decision — rendered as
    //    miette help text (the fix, not just the verdict).
    let argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        dir.join("hello_out").display().to_string(),
        "-headerpad".to_string(),
        "0".to_string(),
        dir.join("hello.o").display().to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    match opts::parse(&argv) {
        Ok(_) => unreachable!("the zero floor refuses"),
        Err(err) => {
            eprintln!("\nthe refusal (verdict + fix):");
            eprintln!("{:?}", miette::Report::new(err));
        }
    }

    println!("\nheaderpad_link: ok");
}
