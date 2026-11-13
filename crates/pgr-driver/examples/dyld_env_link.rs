//! The dyld-environment consumer example (M22): the same `hello.o`
//! linked as a plain executable and as one exporting
//! `-dyld_env DYLD_PRINT_LIBRARIES=1` — the environment command read
//! back from the image (after `LC_MAIN`), the strict verifier on both,
//! and the dylib-conflict refusal rendered as miette help text (the
//! fix, not just the verdict: the house consumer-example convention).
//!
//! Run: `cargo run -p pgr-driver --example dyld_env_link`
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

/// The image's `LC_DYLD_ENVIRONMENT` pairs in flag order.
fn env_rows(image: &[u8]) -> Vec<String> {
    let hdr = pgr_format::MachHeader64::parse(image).expect("the image parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands parse");
    let mut rows = Vec::new();
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if cmd.kind == pgr_format::LoadCommandKind::DyldEnvironment {
            let off = u32::from_le_bytes(cmd.bytes[8..12].try_into().expect("lc_str")) as usize;
            let pair = String::from_utf8_lossy(&cmd.bytes[off..]).to_string();
            rows.push(pair.trim_end_matches('\0').to_string());
        }
    }
    rows
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

    let dir = std::env::temp_dir().join(format!("pgr_dyld_env_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // 1. The plain executable: the pre-M22 shape — no environment
    //    commands.
    let plain = link(&dir, "hello_plain", &[]);
    assert!(
        env_rows(&plain).is_empty(),
        "the default carries no environment commands"
    );
    let opts_strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let report = verify(&plain, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the plain executable verifies strict"
    );

    // 2. The configured executable: the environment commands ride the
    //    loader-configuration block (after `LC_MAIN`), in flag order.
    let configured = link(
        &dir,
        "hello",
        &[
            "-dyld_env",
            "DYLD_PRINT_LIBRARIES=1",
            "-dyld_env",
            "DYLD_PRINT_RPATHS=1",
        ],
    );
    let rows = env_rows(&configured);
    println!("dyld environment:");
    for pair in &rows {
        println!("  {pair}");
    }
    assert_eq!(
        rows,
        vec![
            "DYLD_PRINT_LIBRARIES=1".to_string(),
            "DYLD_PRINT_RPATHS=1".to_string(),
        ],
        "the pairs ride the loader-configuration block in flag order"
    );
    let report = verify(&configured, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the configured executable verifies strict like the plain one"
    );

    // 3. The refusal: the environment off an executable is a parse-time
    //    refusal — dyld reads the command from the main executable only
    //    — rendered as miette help text (the fix, not just the verdict).
    let obj = dir.join("hello.o");
    let argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        dir.join("libhello.dylib").display().to_string(),
        "-dylib".to_string(),
        "-install_name".to_string(),
        "@rpath/libhello.dylib".to_string(),
        "-dyld_env".to_string(),
        "DYLD_PRINT_LIBRARIES=1".to_string(),
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

    println!("\ndyld_env_link: ok");
}
