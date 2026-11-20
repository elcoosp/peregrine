//! The singular-export-filter consumer example (M100): shipping an SDK
//! surface composed on the command line — `-exported_symbol <name>` /
//! `-unexported_symbol <name>`, ld64's command-line siblings of the
//! M14 list files. Each occurrence appends one entry to the ONE
//! composed filter table in flag order (the M90 compose pattern), the
//! singular flags and a list file interleave, the composed surface is
//! exactly the union of the sources' selections (everything else rides
//! `N_PEXT`-hidden in the symtab), and the output verifies strict.
//!
//! Run: `cargo run -p pgr-driver --example exported_symbol_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// sdk.o: the public surface (`_sdk_init`/`_sdk_read`), the entry
/// (`_sdk_main`) and one internal helper the filter must hide.
fn sdk_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("sdk.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(4),
        vec![],
    ));
    for (i, sym) in ["_sdk_main", "_sdk_init", "_sdk_read", "_internal_seed"]
        .iter()
        .enumerate()
    {
        b.add_symbol(ObjectSymbol::Defined {
            name: (*sym).into(),
            section_index: text,
            value: (i * 4) as u64,
            weak: false,
        });
    }
    b.build().expect("the fixture object builds")
}

/// The image's export-trie names.
fn trie_names(image: &[u8]) -> Vec<String> {
    let header = pgr_format::MachHeader64::parse(image).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands walk");
    while let Ok(Some(cmd)) = it.next_command() {
        if cmd.kind
            == pgr_format::LoadCommandKind::LinkeditData(pgr_format::consts::LC_DYLD_EXPORTS_TRIE)
        {
            let lc = pgr_format::LinkeditDataCommand::parse(cmd.bytes).expect("the LC parses");
            let blob = lc.data(image).expect("the trie payload is in range");
            return pgr_format::trie::exports(blob)
                .expect("the trie parses")
                .into_iter()
                .map(|e| String::from_utf8_lossy(&e.name).into_owned())
                .collect();
        }
    }
    panic!("no LC_DYLD_EXPORTS_TRIE in the image");
}

fn strict_ok(image: &[u8]) -> bool {
    verify(
        image,
        &VerifyOptions {
            strict_warnings: true,
            skip_hash_recompute: false,
        },
    )
    .is_ok(&VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    })
}

/// Links `lib.o` with the named extra flags; returns the image bytes.
fn link_dylib(extra: &[&str], tag: &str) -> Vec<u8> {
    let dir = std::env::temp_dir().join(format!("pgr_exported_symbol_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let lib = dir.join("sdk.o");
    std::fs::write(&lib, sdk_object()).unwrap();
    // The list file the compose face interleaves: one exact entry (the
    // M3 form) — blank lines and `#` comments skip.
    let list = dir.join("exports.txt");
    std::fs::write(
        &list,
        "# the middle source (M100 composes it in)\n_sdk_read\n",
    )
    .unwrap();
    let out = dir.join(format!("lib-{tag}.dylib"));
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        std::ffi::OsString::from(out.to_str().unwrap()),
        std::ffi::OsString::from(lib.to_str().unwrap()),
        std::ffi::OsString::from("-dylib"),
        std::ffi::OsString::from("-install_name"),
        std::ffi::OsString::from("@rpath/libsdk.dylib"),
    ];
    for a in extra {
        argv.push(std::ffi::OsString::from(*a));
    }
    let list_flag = std::ffi::OsString::from(list.to_str().unwrap());
    // Splice the list file's argv form wherever the placeholder sits.
    let argv: Vec<std::ffi::OsString> = argv
        .iter()
        .map(|a| {
            if a == "@LIST@" {
                list_flag.clone()
            } else {
                a.clone()
            }
        })
        .collect();
    let o = opts::parse(&argv).expect("the dylib argv parses");
    pgr_driver::run(&o).expect("the dylib link runs");
    std::fs::read(&out).expect("the image reads")
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    // The default: no filter — every definition exports (the pre-knob
    // bytes, the composed tables empty).
    let plain = link_dylib(&[], "plain");
    assert!(strict_ok(&plain), "the default image verifies strict");
    let names = trie_names(&plain);
    assert!(names.contains(&"_internal_seed".to_string()), "{names:?}");
    println!(
        "default: {} bytes — all four definitions export",
        plain.len()
    );

    // The singular flags: one entry each, the internal helper hidden —
    // it leaves the trie and stays in the symtab as an `N_PEXT` private
    // (the list files' contract, one flag occurrence at a time).
    let singular = link_dylib(&["-exported_symbol", "_sdk_main"], "singular");
    assert!(strict_ok(&singular), "the singular image verifies strict");
    let names = trie_names(&singular);
    assert!(names.contains(&"_sdk_main".to_string()), "{names:?}");
    assert!(!names.contains(&"_internal_seed".to_string()), "{names:?}");
    println!(
        "singular: {} bytes — one -exported_symbol entry gates the surface",
        singular.len()
    );

    // The compose: flag entries and a list file interleave in flag
    // order into ONE table — every source's selection rides.
    let composed = link_dylib(
        &[
            "-exported_symbol",
            "_sdk_init",
            "-exported_symbols_list",
            "@LIST@",
            "-exported_symbol",
            "_sdk_main",
        ],
        "composed",
    );
    assert!(strict_ok(&composed), "the composed image verifies strict");
    let names = trie_names(&composed);
    for expected in ["_sdk_main", "_sdk_init", "_sdk_read"] {
        assert!(names.contains(&expected.to_string()), "{names:?}");
    }
    assert!(!names.contains(&"_internal_seed".to_string()), "{names:?}");
    println!(
        "composed: {} bytes — flag + list file + flag in flag order: \
         _sdk_main, _sdk_init, _sdk_read",
        composed.len()
    );

    // The glob form: the singular flags accept the same grammar the
    // M14 lists widened to — a `*` in the value is a glob.
    let glob = link_dylib(&["-exported_symbol", "_sdk_*"], "glob");
    assert!(strict_ok(&glob), "the glob image verifies strict");
    let names = trie_names(&glob);
    assert!(names.contains(&"_sdk_init".to_string()), "{names:?}");
    assert!(names.contains(&"_sdk_read".to_string()), "{names:?}");
    assert!(!names.contains(&"_internal_seed".to_string()), "{names:?}");
    println!(
        "glob:     {} bytes — _sdk_* matched like the lists match",
        glob.len()
    );

    // The refusals: the parse-time validation names the fix (an empty
    // value matches nothing; interior whitespace is not a symbol name).
    let dir = std::env::temp_dir().join(format!("pgr_exported_symbol_{}", std::process::id()));
    let lib = dir.join("sdk.o");
    for (value, why) in [
        ("", "an empty pattern matches nothing"),
        ("_foo bar", "whitespace"),
    ] {
        let argv: Vec<std::ffi::OsString> = [
            "-o",
            dir.join("out.dylib").to_str().unwrap(),
            lib.to_str().unwrap(),
            "-dylib",
            "-exported_symbol",
            value,
        ]
        .iter()
        .map(std::ffi::OsString::from)
        .collect();
        let err = opts::parse(&argv).expect_err("the bad value refuses");
        let report = miette::Report::new(err);
        println!("refusal ({why}): {report:?}");
    }
    println!(
        "\n-exported_symbol/-unexported_symbol are ld64's singular filter face; try \
         PGR_TRACING=1 to watch the layout's export-filter contract"
    );
}
