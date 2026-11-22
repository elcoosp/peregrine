//! The CPU-subtype-override consumer example (M125): the same `hello.o`
//! linked twice as an executable — once at the default cpusubtype word
//! and once under `-force_cpusubtype_ALL` — with the
//! `mach_header_64.cpusubtype` word read back from both (the override
//! forces `CPU_SUBTYPE_ARM64_ALL`, the same value the default already
//! carries — byte-identity, the M122 `-pie` pattern over the cpusubtype
//! word), the strict verifier on both, and the `-r` refusal rendered as
//! miette help text (the fix, not just the verdict: the house
//! consumer-example convention).
//!
//! Run: `cargo run -p pgr-driver --example force_cpusubtype_all_link`
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

/// The header's cpusubtype word (byte 8..12 of the 32-byte header).
fn cpusubtype(image: &[u8]) -> u32 {
    u32::from_le_bytes(image[8..12].try_into().expect("cpusubtype word"))
}

fn link(dir: &std::path::Path, out: &str, force: bool) -> Vec<u8> {
    let obj = dir.join("hello.o");
    std::fs::write(&obj, hello_object()).unwrap();
    let out_path = dir.join(out);
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        out_path.as_os_str().to_os_string(),
        obj.as_os_str().to_os_string(),
    ];
    if force {
        argv.push(std::ffi::OsString::from("-force_cpusubtype_ALL"));
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

    let dir = std::env::temp_dir().join(format!("pgr_force_cpusubtype_all_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // The two links: the default cpusubtype word and the named
    // `-force_cpusubtype_ALL` override. The word is
    // CPU_SUBTYPE_ARM64_ALL either way (the default already carries it
    // — the knob is byte-identity), so the two images are byte-identical
    // and both verify strict.
    let default_image = link(&dir, "hello_default", false);
    let forced_image = link(&dir, "hello_forced", true);
    for (label, image) in [
        ("default", &default_image),
        ("forced (CPU_SUBTYPE_ARM64_ALL)", &forced_image),
    ] {
        let opts = VerifyOptions {
            strict_warnings: true,
            skip_hash_recompute: false,
        };
        let report = verify(image, &opts);
        assert!(
            report.is_ok(&opts),
            "the {label} image verifies strict: {:#?}",
            report.issues
        );
        println!(
            "{label}: cpusubtype = {:#x} (CPU_SUBTYPE_ARM64_ALL = 0)",
            cpusubtype(image)
        );
    }
    assert_eq!(
        default_image, forced_image,
        "the knob is byte-identity — the two images are identical"
    );

    // The refusal: the relocatable output's header is the input's,
    // verbatim — the fix in the help text.
    let argv: Vec<std::ffi::OsString> = [
        "-o".as_ref(),
        dir.join("refused").as_os_str(),
        "-r".as_ref(),
        "-force_cpusubtype_ALL".as_ref(),
        dir.join("hello.o").as_os_str(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    match opts::parse(&argv) {
        Ok(_) => unreachable!("the relocatable conflict refuses"),
        Err(err) => {
            let report = miette::Report::new(err);
            println!("-force_cpusubtype_ALL on a relocatable output refusal:");
            println!("  {report}");
            if let Some(help) = report.help() {
                println!("  fix: {help}");
            }
        }
    }

    println!("both executables verify strict — the cpusubtype word is ALL either way");
}
