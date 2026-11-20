//! The symtab-shaping consumer example (M104): the same `hello.o` —
//! carrying a section-defined static and a name-only local beside
//! `_main` — linked three ways: the plain executable (the pre-M104
//! kept default, ld64's own `kLocalSymbolsAll`), the `-x` drop face
//! (the plain local-symbol subrange leaves the output symtab, the
//! string table shrinks with the names), and the explicit
//! `-keep_local_symbols` keep (the default's mirror — the same bytes),
//! the dysymtab subrange counts read back from all three images, the
//! strict verifier on the faces (local symbols are a dyld-consumed
//! surface, never a format defect), and the relocatable-conflict
//! refusal rendered as miette help text (the fix, not just the verdict:
//! the house consumer-example convention).
//!
//! Run: `cargo run -p pgr-driver --example keep_local_symbols_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::LoadCommandKind;
use pgr_format::MachHeader64;
use pgr_verify::{Options as VerifyOptions, verify};

/// hello.o: `_main`, the static `_local_fn` (the `N_SECT & ~N_EXT`
/// shape) and the name-only `ltmp0` over a small `__text` — the
/// executable the example links three times.
fn hello_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("hello.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        Vec::new(),
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::LocalDefined {
        name: "_local_fn".into(),
        section_index: text,
        value: 8,
    });
    b.add_symbol(ObjectSymbol::Local("ltmp0".into()));
    b.build().expect("the fixture object builds")
}

/// The image's dysymtab subrange counts `(ilocalsym, nlocalsym)`.
fn locals_range(image: &[u8]) -> (u32, u32) {
    let header = MachHeader64::parse(image).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if let LoadCommandKind::Dysymtab = cmd.kind {
            let d =
                pgr_format::DysymtabCommand::parse(image, cmd.offset).expect("the dysymtab parses");
            return (d.ilocalsym, d.nlocalsym);
        }
    }
    panic!("no LC_DYSYMTAB in the linked image");
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

    let dir = std::env::temp_dir().join(format!("pgr_keep_local_symbols_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let opts_strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };

    // 1. The plain executable: the pre-M104 shape — the locals subrange
    //    rides (ld64's own default), both plain locals in the symtab.
    let kept = link(&dir, "hello_kept", &[]);
    assert_eq!(
        locals_range(&kept),
        (0, 2),
        "the default keeps the locals subrange"
    );
    let report = verify(&kept, &opts_strict);
    assert!(report.is_ok(&opts_strict), "the kept face verifies strict");

    // 2. The drop: `-x` empties the subrange — the plain locals leave
    //    the symtab, the image narrows, and the image verifies strict
    //    like the kept one (local symbols are a dyld-consumed surface,
    //    never a format defect).
    let dropped = link(&dir, "hello_dropped", &["-x"]);
    assert_eq!(locals_range(&dropped), (0, 0), "-x empties the subrange");
    assert!(
        dropped.len() < kept.len(),
        "the dropped face plans a narrower image ({} < {})",
        dropped.len(),
        kept.len()
    );
    let report = verify(&dropped, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the dropped face verifies strict like the kept one"
    );

    // 3. The named keep: `-keep_local_symbols` is the default's mirror —
    //    the same bytes as the plain executable.
    let named_keep = link(&dir, "hello_named_keep", &["-keep_local_symbols"]);
    assert_eq!(
        locals_range(&named_keep),
        (0, 2),
        "the named keep rides the subrange"
    );
    assert_eq!(
        kept, named_keep,
        "-keep_local_symbols is the default's mirror: the same bytes"
    );

    // 4. The refusal: the drop face off a final image is a parse-time
    //    refusal — the relocatable output's symtab is the input's,
    //    verbatim — rendered as miette help text (the fix, not just
    //    the verdict).
    let obj = dir.join("hello.o");
    let argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        dir.join("hello_reloc.o").display().to_string(),
        "-r".to_string(),
        "-x".to_string(),
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

    println!("\nkeep_local_symbols_link: ok");
}
