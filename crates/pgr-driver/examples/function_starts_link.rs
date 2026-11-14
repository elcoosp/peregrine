//! The function-starts consumer example (M31): the same corpus linked
//! as a plain executable (the `LC_FUNCTION_STARTS` command rides, its
//! ULEB delta stream encoding every `__text` symbol start) and under
//! `-no_function_starts` (the driver surface's accepted no-op since
//! M1, promoted to the suppression decision — no command, no
//! `__LINKEDIT` slot, one 16-byte command narrower), both run through
//! the strict verifier and the command's presence/absence read back
//! from the images.
//!
//! Run: `cargo run -p pgr-driver --example function_starts_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans —
//! the same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64};
use pgr_verify::{Options as VerifyOptions, verify};

/// hello.o: `_main` over three RET functions — the executable the
/// example links twice.
fn hello_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("hello.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        Vec::new(),
    ));
    for (i, sym) in ["_main", "_fn_1", "_fn_2"].iter().enumerate() {
        b.add_symbol(ObjectSymbol::Defined {
            name: (*sym).into(),
            section_index: text,
            value: (i * 4) as u64,
            weak: false,
        });
    }
    b.build().expect("the fixture object builds")
}

/// True when the image carries `LC_FUNCTION_STARTS`.
fn carries_function_starts(image: &[u8]) -> bool {
    let header = MachHeader64::parse(image).expect("the image parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if let LoadCommandKind::LinkeditData(pgr_format::consts::LC_FUNCTION_STARTS) = cmd.kind {
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

    let dir = std::env::temp_dir().join(format!("pgr_funcstarts_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let opts_strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };

    // 1. The plain executable: the pre-M31 shape — the command rides
    //    and the image verifies strict like any other.
    let carrying = link(&dir, "hello_fs", &[]);
    assert!(
        carries_function_starts(&carrying),
        "the default plans the function-starts command"
    );
    let report = verify(&carrying, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the carrying image verifies strict: {:?}",
        report.issues
    );

    // 2. The decision: `-no_function_starts` suppresses — no command,
    //    no `__LINKEDIT` slot — and the image verifies strict like the
    //    carrying one (a suppression is a decision, not a defect).
    let suppressed = link(&dir, "hello_plain", &["-no_function_starts"]);
    assert!(
        !carries_function_starts(&suppressed),
        "the suppression drops the command"
    );
    let report = verify(&suppressed, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the suppressed image verifies strict: {:?}",
        report.issues
    );

    println!(
        "carrying: LC_FUNCTION_STARTS present ({} bytes of image)",
        carrying.len()
    );
    println!(
        "suppressed: LC_FUNCTION_STARTS absent ({} bytes of image — one 16-byte command \
         narrower in sizeofcmds)",
        suppressed.len()
    );

    println!("\nfunction_starts_link: ok");
}
