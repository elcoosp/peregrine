//! The dylib's export-interposability consumer example (M127): the same
//! `hello.o` linked twice as a dylib — once at the default (no
//! `MH_WEAK_DEFINES | MH_BINDS_TO_WEAK` bits) and once under
//! `-interposable` — with the flags word read back from both images (the
//! named face adds exactly the two bits, the default carries none), the
//! strict verifier on both, and the executable / bundle / `-r` refusals
//! rendered as miette help text (the fix, not just the verdict: the
//! house consumer-example convention).
//!
//! Run: `cargo run -p pgr-driver --example interposable_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use; the seam's
//! own decision event rides it).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// The interpose-all bits the loader consults (`MH_WEAK_DEFINES` |
/// `MH_BINDS_TO_WEAK`) — the producer's `-interposable` decision ORs
/// them into the flags word.
const INTERPOSE_BITS: u32 =
    pgr_format::consts::MH_WEAK_DEFINES | pgr_format::consts::MH_BINDS_TO_WEAK;

/// hello.o: `_main` over a small `__text` — the dylib the example links
/// twice.
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

fn link(dir: &std::path::Path, out: &str, interposable: bool) -> Vec<u8> {
    let obj = dir.join("hello.o");
    std::fs::write(&obj, hello_object()).unwrap();
    let out_path = dir.join(out);
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        out_path.as_os_str().to_os_string(),
        std::ffi::OsString::from("-dylib"),
        std::ffi::OsString::from("-install_name"),
        std::ffi::OsString::from("@rpath/libinterposable.dylib"),
        obj.as_os_str().to_os_string(),
    ];
    if interposable {
        argv.push(std::ffi::OsString::from("-interposable"));
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

    let dir = std::env::temp_dir().join(format!("pgr_interposable_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // The two links: the default (no interpose bits) and the named
    // interposability.
    let default_image = link(&dir, "lib_default.dylib", false);
    let interposable_image = link(&dir, "lib_interposable.dylib", true);
    let opts = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    for (label, image, expect_bits) in [
        ("default (no bits)", &default_image, false),
        ("named (-interposable)", &interposable_image, true),
    ] {
        let report = verify(image, &opts);
        assert!(
            report.is_ok(&opts),
            "the {label} dylib verifies strict: {:#?}",
            report.issues
        );
        let has_bits = flags_word(image) & INTERPOSE_BITS == INTERPOSE_BITS;
        assert_eq!(has_bits, expect_bits, "the {label} dylib's interpose bits");
        println!("{label}: MH_WEAK_DEFINES | MH_BINDS_TO_WEAK = {has_bits}");
    }

    // The refusals: an executable, a bundle and the relocatable output
    // all refuse — interposability is a dylib's property. The fix in the
    // help text.
    for (kind, label) in [
        ("", "executable"),
        ("-bundle", "bundle"),
        ("-r", "relocatable"),
    ] {
        let mut argv: Vec<std::ffi::OsString> = vec!["-o".into(), dir.join("refused").into()];
        if !kind.is_empty() {
            argv.push(kind.into());
        }
        argv.push("-interposable".into());
        argv.push(dir.join("hello.o").into());
        match opts::parse(&argv) {
            Ok(_) => unreachable!("the {label} conflict refuses"),
            Err(err) => {
                let report = miette::Report::new(err);
                println!("-interposable on an {label} refusal:");
                println!("  {report}");
                if let Some(help) = report.help() {
                    println!("  fix: {help}");
                }
            }
        }
    }

    println!(
        "both dylibs verify strict — the bits are loader-advisory, never a contract the gate gates on"
    );
}
