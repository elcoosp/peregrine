//! The data-in-code consumer example (M30): the entry-carrying corpus
//! linked as a plain executable (the metadata rides the output
//! `LC_DATA_IN_CODE` — the TDD §8.2 `__LINKEDIT` order's slot right
//! after `LC_FUNCTION_STARTS`), the same corpus linked under
//! `-no_data_in_code` (the driver surface's accepted no-op since M1,
//! promoted to the suppression decision), both run through the strict
//! verifier, and the decoded streams printed beside each other — the
//! command's presence/absence read back from the images.
//!
//! Run: `cargo run -p pgr-driver --example data_in_code_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans —
//! the same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64};
use pgr_verify::{Options as VerifyOptions, verify};

/// hello.o: `_main` over three RET functions, one data-in-code entry
/// per function (`__text`-relative — the input convention the
/// carriage translates from).
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
    let b = b.set_data_in_code(
        (0..3)
            .map(|f| pgr_format::DataInCodeEntry {
                offset: (f * 4) as u32,
                length: 4,
                kind: 1,
            })
            .collect(),
    );
    b.build().expect("the fixture object builds")
}

/// True when the image carries `LC_DATA_IN_CODE`.
fn carries_data_in_code(image: &[u8]) -> bool {
    let header = MachHeader64::parse(image).expect("the image parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if let LoadCommandKind::LinkeditData(pgr_format::consts::LC_DATA_IN_CODE) = cmd.kind {
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

    let dir = std::env::temp_dir().join(format!("pgr_dice_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let opts_strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };

    // 1. The plain executable: the metadata rides — the output's
    //    `LC_DATA_IN_CODE` command carries the translated stream and
    //    the image verifies strict like any other.
    let carried = link(&dir, "hello_dice", &[]);
    assert!(
        carries_data_in_code(&carried),
        "the carriage lands the LC_DATA_IN_CODE command"
    );
    let report = verify(&carried, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the carrying image verifies strict: {:?}",
        report.issues
    );

    // 2. The decision: `-no_data_in_code` suppresses — no command, no
    //    `__LINKEDIT` slot — and the image verifies strict like the
    //    carrying one (a suppression is a decision, not a defect).
    let suppressed = link(&dir, "hello_plain", &["-no_data_in_code"]);
    assert!(
        !carries_data_in_code(&suppressed),
        "the suppression drops the command"
    );
    let report = verify(&suppressed, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the suppressed image verifies strict: {:?}",
        report.issues
    );

    println!(
        "carried: LC_DATA_IN_CODE present ({} bytes of image)",
        carried.len()
    );
    println!(
        "suppressed: LC_DATA_IN_CODE absent ({} bytes of image — one 16-byte command narrower)",
        suppressed.len()
    );

    println!("\ndata_in_code_link: ok");
}
