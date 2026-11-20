//! The debug-suppression consumer example (M105): the same `hello.o` —
//! carrying an `S_ATTR_DEBUG` `__debug_info` section inside `__TEXT`
//! beside `__text` — linked as the plain executable (the pre-M105
//! debug-carrying default: the shape the segment-name rule misses
//! buckets as load-time bytes) and as one naming `-S` (the debug
//! pieces drop, the symtab's debug entries drop with them, the
//! `LC_FUNCTION_STARTS` / `LC_DATA_IN_CODE` commands drop), the
//! command shapes and file sizes read back from both images, the
//! strict verifier on both faces (debug metadata is a dyld-consumed
//! surface, never a format defect), and the relocatable-conflict
//! refusal rendered as miette help text (the fix, not just the
//! verdict: the house consumer-example convention).
//!
//! Run: `cargo run -p pgr-driver --example strip_debug_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::consts::{S_ATTR_DEBUG, S_REGULAR};
use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64};
use pgr_verify::{Options as VerifyOptions, verify};

/// hello.o: `_main` over a small `__text`, an `S_ATTR_DEBUG`
/// `__debug_info` section inside `__TEXT` carrying a local, and a
/// `__DWARF` segment section (the always-swept shape) — the executable
/// the example links twice.
fn hello_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("hello.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        Vec::new(),
    ));
    let debug_sect = b.add_section(ObjectSection {
        name: "__debug_info".into(),
        segment: "__TEXT".into(),
        align_log2: 0,
        flags: S_ATTR_DEBUG,
        data: vec![0xAA; 16],
        relocs: Vec::new(),
    });
    let _dwarf = b.add_section(ObjectSection {
        name: "__debug_info".into(),
        segment: "__DWARF".into(),
        align_log2: 0,
        flags: S_REGULAR,
        data: vec![0xBB; 8],
        relocs: Vec::new(),
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::LocalDefined {
        name: "_debug_local".into(),
        section_index: debug_sect,
        value: 0,
    });
    let b = b.set_data_in_code(vec![pgr_format::DataInCodeEntry {
        offset: 0,
        length: 4,
        kind: 1,
    }]);
    b.build().expect("the fixture object builds")
}

/// True when the image header carries `kind` (a `LC_LINKEDIT_DATA`).
fn carries_linkedit_data(image: &[u8], kind: u32) -> bool {
    let header = MachHeader64::parse(image).expect("the header parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if let LoadCommandKind::LinkeditData(k) = cmd.kind
            && k == kind
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

    let dir = std::env::temp_dir().join(format!("pgr_strip_debug_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let opts_strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };

    // 1. The plain executable: the pre-M105 shape — the
    //    `S_ATTR_DEBUG` shape buckets as load-time bytes and both
    //    metadata commands ride.
    let carried = link(&dir, "hello_carried", &[]);
    assert!(
        carries_linkedit_data(&carried, pgr_format::consts::LC_FUNCTION_STARTS),
        "the default plans LC_FUNCTION_STARTS"
    );
    assert!(
        carries_linkedit_data(&carried, pgr_format::consts::LC_DATA_IN_CODE),
        "the default plans LC_DATA_IN_CODE"
    );
    let report = verify(&carried, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the debug-carrying default verifies strict"
    );

    // 2. The suppression: `-S` drops the debug pieces, their symtab
    //    entries, and both metadata commands — the image narrows and
    //    verifies strict like the carried one.
    let stripped = link(&dir, "hello_stripped", &["-S"]);
    assert!(
        !carries_linkedit_data(&stripped, pgr_format::consts::LC_FUNCTION_STARTS),
        "-S drops LC_FUNCTION_STARTS"
    );
    assert!(
        !carries_linkedit_data(&stripped, pgr_format::consts::LC_DATA_IN_CODE),
        "-S drops LC_DATA_IN_CODE"
    );
    assert!(
        stripped.len() < carried.len(),
        "the debug pieces leave the file ({} < {})",
        stripped.len(),
        carried.len()
    );
    let report = verify(&stripped, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the stripped image verifies strict like the carried one"
    );

    // 3. The refusal: the suppression off a final image is a parse-time
    //    refusal — the relocatable output's sections are the input's,
    //    verbatim — rendered as miette help text (the fix, not just
    //    the verdict).
    let obj = dir.join("hello.o");
    let argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        dir.join("hello_reloc.o").display().to_string(),
        "-r".to_string(),
        "-S".to_string(),
        obj.display().to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    match opts::parse(&argv) {
        Ok(_) => unreachable!("the relocatable conflict refuses"),
        Err(err) => {
            eprintln!("\nthe refusal (verdict + fix):");
            eprintln!("{:?}", miette::Report::new(err));
        }
    }

    println!("\nstrip_debug_link: ok");
}
