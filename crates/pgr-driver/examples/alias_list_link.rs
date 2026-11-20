//! The alias-list consumer example (M101): shipping an ABI shim
//! surface from a file — `-alias_list <file>`, ld64's file form of
//! M24's `-alias`. One `alias definition` pair per line (blank lines
//! and `#` comments skip), the pairs compose into the ONE alias table
//! in flag order beside the `-alias` flags (the M90 compose pattern),
//! every alias exports at its definition's address (one body, two
//! names), and the output verifies strict. The M24 refusals ride the
//! file form unchanged: a pair of a name no input defines refuses with
//! the misspelling named, a repeat name refuses.
//!
//! Run: `cargo run -p pgr-driver --example alias_list_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// lib.o: `_main`, `_lib_fn` and `_api` — three bodies the shim file
/// points at.
fn lib_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("lib.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        vec![],
    ));
    for (i, sym) in ["_main", "_lib_fn", "_api"].iter().enumerate() {
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

/// The symtab row's `n_value` for the named symbol (the alias rows
/// carry the definition's address — one body, two names).
fn symbol_value(image: &[u8], name: &[u8]) -> Option<u64> {
    let header = pgr_format::MachHeader64::parse(image).expect("the image parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if let pgr_format::LoadCommandKind::Symtab = cmd.kind {
            let st = pgr_format::SymtabCommand::parse(image, cmd.offset).expect("the lc parses");
            let strtab = &image[st.stroff as usize..(st.stroff + st.strsize) as usize];
            for i in 0..st.nsyms {
                let at = st.symoff as usize + i as usize * 16;
                let n_strx =
                    u32::from_le_bytes(image[at..at + 4].try_into().expect("n_strx rides byte 0"));
                let n_value = u64::from_le_bytes(
                    image[at + 8..at + 16]
                        .try_into()
                        .expect("n_value rides byte 8"),
                );
                let nul = strtab[n_strx as usize..]
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(0);
                if &strtab[n_strx as usize..n_strx as usize + nul] == name {
                    return Some(n_value);
                }
            }
        }
    }
    None
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

/// Writes the example's scratch files and returns (lib.o path, alias
/// file path).
fn scratch() -> (std::path::PathBuf, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("pgr_alias_list_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let lib = dir.join("lib.o");
    std::fs::write(&lib, lib_object()).unwrap();
    // The shim file: the house list-file grammar — one `alias
    // definition` pair per line, blank lines and `#` comments skip.
    let list = dir.join("aliases.txt");
    std::fs::write(
        &list,
        "# the compat shims (the old names keep resolving)\n\n\
         _lib_compat _lib_fn\n\
         _api_compat _api\n",
    )
    .unwrap();
    (lib, list)
}

/// Links the dylib with the named extra flags; returns the image bytes.
fn link_dylib(lib: &std::path::Path, extra: &[&str], tag: &str) -> Vec<u8> {
    let dir = lib.parent().unwrap();
    let out = dir.join(format!("lib-{tag}.dylib"));
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        std::ffi::OsString::from(out.to_str().unwrap()),
        std::ffi::OsString::from(lib.to_str().unwrap()),
        std::ffi::OsString::from("-dylib"),
        std::ffi::OsString::from("-install_name"),
        std::ffi::OsString::from("@rpath/lib.dylib"),
    ];
    for a in extra {
        argv.push(std::ffi::OsString::from(*a));
    }
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
    let (lib, list) = scratch();
    let list_arg = list.to_str().unwrap().to_string();

    // The default: no aliases — the plain surface (the pre-knob bytes).
    let plain = link_dylib(&lib, &[], "plain");
    assert!(strict_ok(&plain), "the default image verifies strict");
    let names = trie_names(&plain);
    assert!(!names.contains(&"_lib_compat".to_string()), "{names:?}");
    println!("default: {} bytes — the plain surface", plain.len());

    // The file form: both pairs ride — each alias exports at its
    // definition's address (one body, two names).
    let shimmed = link_dylib(&lib, &["-alias_list", &list_arg], "shimmed");
    assert!(strict_ok(&shimmed), "the shimmed image verifies strict");
    let names = trie_names(&shimmed);
    for expected in ["_lib_compat", "_api_compat"] {
        assert!(names.contains(&expected.to_string()), "{names:?}");
    }
    for (alias, definition) in [("_lib_compat", "_lib_fn"), ("_api_compat", "_api")] {
        let alias_at = symbol_value(&shimmed, alias.as_bytes()).expect("the alias row rides");
        let defined_at =
            symbol_value(&shimmed, definition.as_bytes()).expect("the definition row rides");
        assert_eq!(
            alias_at, defined_at,
            "{alias} resolves at {definition}'s address"
        );
    }
    println!(
        "file:    {} bytes — two pairs from the file, each at its definition's address",
        shimmed.len()
    );

    // The compose: a flag pair and the file's pairs in ONE table, flag
    // order — the flag's row first, the file's rows after it.
    let composed = link_dylib(
        &lib,
        &["-alias", "_flag_shim", "_main", "-alias_list", &list_arg],
        "composed",
    );
    assert!(strict_ok(&composed), "the composed image verifies strict");
    let names = trie_names(&composed);
    for expected in ["_flag_shim", "_lib_compat", "_api_compat"] {
        assert!(names.contains(&expected.to_string()), "{names:?}");
    }
    println!(
        "compose: {} bytes — one flag pair + the file's pairs in flag order",
        composed.len()
    );

    // The refusals: the M24 contracts ride the file form unchanged. A
    // misspelled definition refuses with the misspelling named; a
    // repeat name refuses; a malformed line names itself.
    let dir = lib.parent().unwrap();
    let bad = dir.join("bad.txt");
    std::fs::write(&bad, "_shim _lib_fnn\n").unwrap();
    let out = dir.join("lib-refused.dylib");
    let argv: Vec<std::ffi::OsString> = [
        "-o",
        out.to_str().unwrap(),
        lib.to_str().unwrap(),
        "-dylib",
        "-alias_list",
        bad.to_str().unwrap(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let err = pgr_driver::run(&opts::parse(&argv).expect("the argv parses"))
        .expect_err("the misspelled definition refuses");
    println!("refusal (misspelled): {err}");
    assert!(!out.exists(), "the refused link writes no image");

    let dup = dir.join("dup.txt");
    std::fs::write(&dup, "_lib_compat _api\n").unwrap();
    let out = dir.join("lib-dup.dylib");
    let argv: Vec<std::ffi::OsString> = [
        "-o",
        out.to_str().unwrap(),
        lib.to_str().unwrap(),
        "-dylib",
        "-alias",
        "_lib_compat",
        "_lib_fn",
        "-alias_list",
        dup.to_str().unwrap(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let err = pgr_driver::run(&opts::parse(&argv).expect("the argv parses"))
        .expect_err("the duplicate refuses");
    println!("refusal (duplicate):  {err}");

    let malformed = dir.join("malformed.txt");
    std::fs::write(&malformed, "just_one_name\n").unwrap();
    let out = dir.join("lib-malformed.dylib");
    let argv: Vec<std::ffi::OsString> = [
        "-o",
        out.to_str().unwrap(),
        lib.to_str().unwrap(),
        "-dylib",
        "-alias_list",
        malformed.to_str().unwrap(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let err = pgr_driver::run(&opts::parse(&argv).expect("the argv parses"))
        .expect_err("the malformed line refuses");
    println!("refusal (malformed):  {err}");

    println!(
        "\n-alias_list is the file face of M24's -alias; try PGR_TRACING=1 to watch \
         the pipeline"
    );
}
