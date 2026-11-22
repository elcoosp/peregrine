//! The output-image-atomization consumer example (M126): the same
//! `hello.o` linked twice as an executable — once at the default (no
//! `MH_SUBSECTIONS_VIA_SYMBOLS` bit) and once under
//! `-allow_subsections_via_symbols` — with the flags word read back
//! from both images (the named face adds exactly the one bit, the
//! default carries none), the strict verifier on both, and the `-r`
//! refusal rendered as miette help text (the fix, not just the verdict:
//! the house consumer-example convention).
//!
//! Run: `cargo run -p pgr-driver --example subsections_via_symbols_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use; the seam's
//! own decision event rides it).

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

/// The image header's flags word (byte 24..28 of the 32-byte header).
fn flags_word(image: &[u8]) -> u32 {
    u32::from_le_bytes(image[24..28].try_into().expect("the flags word"))
}

fn link(dir: &std::path::Path, out: &str, atomize: bool) -> Vec<u8> {
    let obj = dir.join("hello.o");
    std::fs::write(&obj, hello_object()).unwrap();
    let out_path = dir.join(out);
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        out_path.as_os_str().to_os_string(),
        obj.as_os_str().to_os_string(),
    ];
    if atomize {
        argv.push(std::ffi::OsString::from("-allow_subsections_via_symbols"));
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

    let dir = std::env::temp_dir().join(format!(
        "pgr_subsections_via_symbols_{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    // The two links: the default (no `MH_SUBSECTIONS_VIA_SYMBOLS` bit)
    // and the named atomization.
    let default_image = link(&dir, "hello_default", false);
    let atomized_image = link(&dir, "hello_atomized", true);
    let opts = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    for (label, image, expect_bit) in [
        ("default (no bit)", &default_image, false),
        (
            "named (-allow_subsections_via_symbols)",
            &atomized_image,
            true,
        ),
    ] {
        let report = verify(image, &opts);
        assert!(
            report.is_ok(&opts),
            "the {label} image verifies strict: {:#?}",
            report.issues
        );
        let has_bit = flags_word(image) & pgr_format::consts::MH_SUBSECTIONS_VIA_SYMBOLS != 0;
        assert_eq!(
            has_bit, expect_bit,
            "the {label} image's MH_SUBSECTIONS_VIA_SYMBOLS bit"
        );
        println!("{label}: MH_SUBSECTIONS_VIA_SYMBOLS = {has_bit}");
    }

    // The byte-identity lock: the default and the named-off face plan
    // byte-identical bytes (the named off names the pre-knob shape).
    let off_image = link(&dir, "hello_off", false);
    assert_eq!(
        default_image, off_image,
        "the pre-knob shape: the named-off face is the default"
    );

    // The relocatable refusal: the object's header is the input's,
    // verbatim — the fix in the help text.
    let argv: Vec<std::ffi::OsString> = [
        "-o".as_ref(),
        dir.join("refused").as_os_str(),
        "-r".as_ref(),
        "-allow_subsections_via_symbols".as_ref(),
        dir.join("hello.o").as_os_str(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    match opts::parse(&argv) {
        Ok(_) => unreachable!("the relocatable conflict refuses"),
        Err(err) => {
            let report = miette::Report::new(err);
            println!("-allow_subsections_via_symbols on a relocatable refusal:");
            println!("  {report}");
            if let Some(help) = report.help() {
                println!("  fix: {help}");
            }
        }
    }

    println!(
        "both executables verify strict — the bit is loader-advisory, never a contract the gate gates on"
    );
}
