//! The export-trie suppression consumer example (M40): one `main.o`
//! (`_main` plus a second defined external `_f`) linked twice — once
//! plain (the default: `LC_DYLD_EXPORTS_TRIE` carries
//! `__mh_execute_header` and every defined external, the pre-M40
//! shape) and once under `-no_exported_symbols` (the command drops:
//! `ncmds` −1, `sizeofcmds` −16, the `__LINKEDIT` trie chunk is gone,
//! the strict verifier still passes). The dylib conflict refusal
//! renders as miette help text (the fix, not just the verdict: the
//! house consumer-example convention) — a dylib's trie *is* the
//! two-level contract its clients bind through.
//!
//! This is ld64's `-no_exported_symbols`: the export surface is
//! `dlsym`/debugger-facing on a main executable, so a program nothing
//! binds against through its exports can name the build off and skip
//! the trie walk.
//!
//! Run: `cargo run -p pgr-driver --example no_exported_symbols_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// main.o: `_main` (RET) plus a second defined external `_f` — the
/// trie the suppression drops carried both names.
fn main_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0u8, 0x03, 0x5F, 0xD6, 0xC0u8, 0x03, 0x5F, 0xD6], // ret; ret
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_f".into(),
        section_index: text,
        value: 4,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// Whether the image carries `LC_DYLD_EXPORTS_TRIE`.
fn carries_trie_command(image: &[u8]) -> bool {
    let hdr = pgr_format::MachHeader64::parse(image).expect("the image parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if cmd.kind
            == pgr_format::LoadCommandKind::LinkeditData(pgr_format::consts::LC_DYLD_EXPORTS_TRIE)
        {
            return true;
        }
    }
    false
}

/// The exported names the trie carries (empty when the command is
/// absent).
fn trie_exports(image: &[u8]) -> Vec<Vec<u8>> {
    let hdr = pgr_format::MachHeader64::parse(image).expect("the image parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if cmd.kind
            == pgr_format::LoadCommandKind::LinkeditData(pgr_format::consts::LC_DYLD_EXPORTS_TRIE)
        {
            let lc: pgr_format::LinkeditDataCommand =
                pgr_format::cursor::pod_read_unaligned_at(image, cmd.offset)
                    .expect("the command parses");
            let dataoff = usize::try_from(lc.dataoff).expect("the dataoff rides u32");
            let datasize = usize::try_from(lc.datasize).expect("the datasize rides u32");
            let payload = &image[dataoff..dataoff + datasize];
            return pgr_format::trie::exports(payload)
                .expect("the trie walks")
                .into_iter()
                .map(|e| e.name)
                .collect();
        }
    }
    Vec::new()
}

fn link(dir: &std::path::Path, out: &str, extra: &[&str]) -> Vec<u8> {
    let obj = dir.join("main.o");
    std::fs::write(&obj, main_object()).unwrap();
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

    let dir = std::env::temp_dir().join(format!("pgr_no_exported_symbols_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };

    // 1. The plain link: the default carries the trie — the exported
    //    surface the `dlsym` walk answers, the pre-M40 shape.
    let plain = link(&dir, "app_plain", &[]);
    let exports = trie_exports(&plain);
    println!(
        "plain: carries LC_DYLD_EXPORTS_TRIE = {}, exports = {:?}",
        carries_trie_command(&plain),
        exports
            .iter()
            .map(|n| String::from_utf8_lossy(n))
            .collect::<Vec<_>>()
    );
    assert!(carries_trie_command(&plain), "the default carries the trie");
    assert!(
        exports.iter().any(|n| n == b"__mh_execute_header"),
        "the executable exports its own header"
    );
    let report = verify(&plain, &strict);
    assert!(report.is_ok(&strict), "the plain image verifies strict");

    // 2. The suppressed link: `-no_exported_symbols` drops the command —
    //    the header narrows, the __LINKEDIT chunk is gone, the image
    //    still verifies strict (absence is the decision, never a defect).
    let bare = link(&dir, "app_bare", &["-no_exported_symbols"]);
    println!(
        "suppressed: carries LC_DYLD_EXPORTS_TRIE = {}, plain = {} bytes, bare = {} bytes",
        carries_trie_command(&bare),
        plain.len(),
        bare.len()
    );
    assert!(
        !carries_trie_command(&bare),
        "the suppression drops the command"
    );
    assert!(
        trie_exports(&bare).is_empty(),
        "the export surface is gone with the command"
    );
    assert!(
        plain.len() - bare.len() >= 16,
        "the image shrinks past the command slot"
    );
    let report = verify(&bare, &strict);
    assert!(
        report.is_ok(&strict),
        "the suppressed image verifies strict: {:#?}",
        report.issues
    );

    // 3. The dylib conflict: the trie IS the two-level contract a
    //    dylib's clients bind through — rendered as miette help text
    //    (the fix, not just the verdict).
    let obj = dir.join("main.o");
    let argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        dir.join("libout.dylib").display().to_string(),
        "-dylib".to_string(),
        "-install_name".to_string(),
        "@rpath/libout.dylib".to_string(),
        "-no_exported_symbols".to_string(),
        obj.display().to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    match opts::parse(&argv) {
        Ok(_) => unreachable!("the dylib conflict refuses"),
        Err(err) => {
            println!("dylib conflict (miette help text):");
            println!("{:?}", miette::Report::new(err));
        }
    }
}
