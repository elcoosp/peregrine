//! The ad-hoc signature consumer example (the `-adhoc`/`-no_adhoc`
//! decision's flag pair): the same `hello.o` linked as the plain
//! executable (the default signs — `LC_CODE_SIGNATURE` rides, the
//! ad-hoc SHA-256 over the page hashes), as one naming `-no_adhoc`
//! (the command drops: no `__LINKEDIT` slot, the image verifies under
//! the relaxed contract — the shape the `-no_adhoc` carve-out pattern
//! is named after), and as one naming `-adhoc` (the default's mirror —
//! the same bytes), the command shapes read back from all three
//! images and the strict verifier on the signed faces.
//!
//! Run: `cargo run -p pgr-driver --example adhoc_link`
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

/// True when the image header carries `LC_CODE_SIGNATURE`.
fn carries_signature(image: &[u8]) -> bool {
    let header = pgr_format::MachHeader64::parse(image).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if let pgr_format::LoadCommandKind::LinkeditData(pgr_format::consts::LC_CODE_SIGNATURE) =
            cmd.kind
        {
            return true;
        }
    }
    false
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

    let dir = std::env::temp_dir().join(format!("pgr_adhoc_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let opts_strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };

    // 1. The plain executable: the default signs — the ad-hoc
    //    signature rides `LC_CODE_SIGNATURE`.
    let signed = link(&dir, "hello_signed", &[]);
    assert!(
        carries_signature(&signed),
        "the default executable carries the ad-hoc signature"
    );
    let report = verify(&signed, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the signed image verifies strict"
    );

    // 2. The suppression: `-no_adhoc` drops the command — no
    //    `__LINKEDIT` slot, the image verifies under the relaxed
    //    contract (the shape the carve-out pattern is named after).
    let unsigned = link(&dir, "hello_unsigned", &["-no_adhoc"]);
    assert!(
        !carries_signature(&unsigned),
        "-no_adhoc drops LC_CODE_SIGNATURE"
    );
    assert!(
        unsigned.len() < signed.len(),
        "the signature leaves the file ({} < {})",
        unsigned.len(),
        signed.len()
    );

    // 3. The named face: `-adhoc` is the default's mirror — the same
    //    bytes, and the signature rides again.
    let named_signed = link(&dir, "hello_named_signed", &["-adhoc"]);
    assert!(carries_signature(&named_signed), "-adhoc signs the image");
    assert_eq!(
        signed, named_signed,
        "-adhoc is the default's mirror: the same bytes"
    );
    let report = verify(&named_signed, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the named-signed image verifies strict like the default one"
    );

    println!("\nadhoc_link: ok");
}
