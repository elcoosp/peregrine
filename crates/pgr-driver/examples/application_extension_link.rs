//! The app-extension-safe consumer example (M128): the same `hello.o`
//! linked twice as an executable — once at the default (no
//! `MH_APP_EXTENSION_SAFE` bit) and once under `-application_extension` —
//! with the flags word read back from both images (the named face adds
//! exactly the one bit, the default carries none), the strict verifier
//! on both, and the `-r` refusal rendered as miette help text (the fix,
//! not just the verdict: the house consumer-example convention).
//!
//! Run: `cargo run -p pgr-driver --example application_extension_link`
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

fn link(dir: &std::path::Path, out: &str, app_ext: bool) -> Vec<u8> {
    let obj = dir.join("hello.o");
    std::fs::write(&obj, hello_object()).unwrap();
    let out_path = dir.join(out);
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        out_path.as_os_str().to_os_string(),
        obj.as_os_str().to_os_string(),
    ];
    if app_ext {
        argv.push(std::ffi::OsString::from("-application_extension"));
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

    let dir =
        std::env::temp_dir().join(format!("pgr_application_extension_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // The two links: the default (no `MH_APP_EXTENSION_SAFE` bit) and
    // the named app-extension-safe decision.
    let default_image = link(&dir, "hello_default", false);
    let app_ext_image = link(&dir, "hello_app_ext", true);
    let opts = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    for (label, image, expect_bit) in [
        ("default (no bit)", &default_image, false),
        ("named (-application_extension)", &app_ext_image, true),
    ] {
        let report = verify(image, &opts);
        assert!(
            report.is_ok(&opts),
            "the {label} image verifies strict: {:#?}",
            report.issues
        );
        let has_bit = flags_word(image) & pgr_format::consts::MH_APP_EXTENSION_SAFE != 0;
        assert_eq!(
            has_bit, expect_bit,
            "the {label} image's MH_APP_EXTENSION_SAFE bit"
        );
        println!("{label}: MH_APP_EXTENSION_SAFE = {has_bit}");
    }

    // The byte-identity lock: the default is the pre-knob shape (the
    // off face names it — there is no `-no_application_extension` knob,
    // the decision is one-byte, the default is off). A re-link with the
    // same argv reproduces byte-identical bytes (determinism lock).
    let again = link(&dir, "hello_again", false);
    assert_eq!(
        default_image, again,
        "the double link is stable (the off face)"
    );

    // The relocatable refusal: the object's header is the input's,
    // verbatim — the fix in the help text.
    let argv: Vec<std::ffi::OsString> = [
        "-o".as_ref(),
        dir.join("refused").as_os_str(),
        "-r".as_ref(),
        "-application_extension".as_ref(),
        dir.join("hello.o").as_os_str(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    match opts::parse(&argv) {
        Ok(_) => unreachable!("the relocatable conflict refuses"),
        Err(err) => {
            let report = miette::Report::new(err);
            println!("-application_extension on a relocatable refusal:");
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
