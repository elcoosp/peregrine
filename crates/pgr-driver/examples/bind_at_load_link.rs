//! The bind-at-load consumer example (M102): the same `hello.o` linked
//! as a plain executable (the pre-M102 bitless default, ld64's own) and
//! as one naming `-bind_at_load` — the `MH_BINDATLOAD` flag read back
//! from both images (the `dlopen(RTLD_NOW)` contract: dyld binds every
//! undefined symbol at load time, before `main` runs), the strict
//! verifier on both, and the dylib-conflict refusal rendered as miette
//! help text (the fix, not just the verdict: the house consumer-example
//! convention).
//!
//! Run: `cargo run -p pgr-driver --example bind_at_load_link`
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

/// The image header's flags word (byte 24..28 of the 32-byte header).
fn header_flags(image: &[u8]) -> u32 {
    u32::from_le_bytes(image[24..28].try_into().expect("flags word"))
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

    let dir = std::env::temp_dir().join(format!("pgr_bind_at_load_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // 1. The plain executable: the pre-M102 shape — dyld binds lazily
    //    and at first use (ld64's own default).
    let plain = link(&dir, "hello_plain", &[]);
    assert_eq!(
        header_flags(&plain) & pgr_format::consts::MH_BINDATLOAD,
        0,
        "the default executable opts into nothing"
    );
    let opts_strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let report = verify(&plain, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the bitless default verifies strict"
    );

    // 2. The decision: `-bind_at_load` sets exactly the `MH_BINDATLOAD`
    //    bit (dyld binds all undefineds before `main`), and the image
    //    verifies strict like the default one.
    let knobbed = link(&dir, "hello_bind_at_load", &["-bind_at_load"]);
    println!(
        "flags: default {:#x}, bind_at_load {:#x}",
        header_flags(&plain),
        header_flags(&knobbed)
    );
    assert_eq!(
        header_flags(&knobbed) & pgr_format::consts::MH_BINDATLOAD,
        pgr_format::consts::MH_BINDATLOAD,
        "the named decision sets MH_BINDATLOAD"
    );
    let report = verify(&knobbed, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the bind-at-load executable verifies strict like the default one"
    );

    // 3. The refusal: the bind-at-load decision off an executable is a
    //    parse-time refusal — `MH_BINDATLOAD` is an executable-only bit
    //    — rendered as miette help text (the fix, not just the verdict).
    let obj = dir.join("hello.o");
    let argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        dir.join("libhello.dylib").display().to_string(),
        "-dylib".to_string(),
        "-install_name".to_string(),
        "@rpath/libhello.dylib".to_string(),
        "-bind_at_load".to_string(),
        obj.display().to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    match opts::parse(&argv) {
        Ok(_) => unreachable!("the dylib conflict refuses"),
        Err(err) => {
            eprintln!("\nthe refusal (verdict + fix):");
            eprintln!("{:?}", miette::Report::new(err));
        }
    }

    println!("\nbind_at_load_link: ok");
}
