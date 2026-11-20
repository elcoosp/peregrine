//! The flat-namespace consumer example (the M2 binding decision's
//! flag pair): the same `hello.o` linked as the plain executable (the
//! pre-M2 two-level default — `MH_TWOLEVEL` rides the header word),
//! as one naming `-flat_namespace` (the bit drops: every undefined
//! binds through dyld's flat lookup slot, the `dynamic_lookup` slot
//! the M103 policies encode), and as one naming
//! `-twolevel_namespace` (the default's mirror — the same bytes), the
//! flag word read back from all three images and the strict verifier
//! on every face.
//!
//! Run: `cargo run -p pgr-driver --example flat_namespace_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// hello.o: `_main` over a small `__text` — the executable the
/// example links three times.
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

    let dir = std::env::temp_dir().join(format!("pgr_flat_namespace_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let opts_strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };

    // 1. The plain executable: the two-level default — dyld binds
    //    through the exporting image's own symbol table.
    let two_level = link(&dir, "hello_two_level", &[]);
    assert_ne!(
        header_flags(&two_level) & pgr_format::consts::MH_TWOLEVEL,
        0,
        "the default executable binds two-level"
    );
    let report = verify(&two_level, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the two-level default verifies strict"
    );

    // 2. The flat face: `-flat_namespace` drops the bit — every
    //    undefined binds through dyld's flat lookup slot.
    let flat = link(&dir, "hello_flat", &["-flat_namespace"]);
    assert_eq!(
        header_flags(&flat) & pgr_format::consts::MH_TWOLEVEL,
        0,
        "-flat_namespace drops MH_TWOLEVEL"
    );
    let report = verify(&flat, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the flat-namespace executable verifies strict like the default one"
    );

    // 3. The named two-level face: `-twolevel_namespace` (and its
    //    `-no_flat_namespace` spelling) is the default's mirror — the
    //    same bytes.
    let named_two_level = link(&dir, "hello_named_two_level", &["-twolevel_namespace"]);
    assert_ne!(
        header_flags(&named_two_level) & pgr_format::consts::MH_TWOLEVEL,
        0,
        "-twolevel_namespace rides the bit"
    );
    assert_eq!(
        two_level, named_two_level,
        "-twolevel_namespace is the default's mirror: the same bytes"
    );

    println!("\nflat_namespace_link: ok");
}
