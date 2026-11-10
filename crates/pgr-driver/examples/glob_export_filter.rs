//! The export-filter consumer example (M14): shipping an SDK surface
//! with a *glob* exported-symbols list — the ld64 syntax the exact-name
//! subset kept out until now. The list file carries `_sdk_*`, the link
//! exports exactly the matched names, everything else stays in the
//! image as `N_PEXT` privates (visible to `nm -m`, invisible to dyld),
//! and the output verifies strict. A pattern that matched nothing — a
//! typo in the list — renders as the miette advisory (the fix, not
//! just the verdict), the same contract the order-file example shows.
//!
//! Run: `cargo run -p pgr-driver --example glob_export_filter`
//! (`PGR_TRACING=1` installs a subscriber so the layout's export-filter
//! contract span prints — the same inert-until-subscriber convention
//! the binaries use).

use std::path::PathBuf;

use pgr_core::SymbolMatcher;
use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// The advisory: an export-list pattern matched no symbol in the plan
/// (a typo, a renamed symbol) — the link is correct, the intent is
/// not. The diagnostic names the pattern and the fix, per the house
/// convention.
#[derive(Debug, thiserror::Error, miette::Diagnostic)]
#[error("export-list pattern {pattern} matched no symbol")]
#[diagnostic(help(
    "check the pattern against the inputs' symbol table (globs are ld64's `*` subset: each star matches any, possibly empty, byte run)"
))]
struct UnmatchedPattern {
    /// The pattern that matched nothing, as written.
    pattern: String,
}

/// sdk.o: the public surface (`_sdk_init`/`_sdk_read`), the entry
/// (`_sdk_main`) and one internal helper the filter must hide.
fn sdk_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("sdk.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(4),
        vec![],
    ));
    b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    for (i, name) in ["_sdk_main", "_sdk_init", "_sdk_read", "_sdk_internal_state"]
        .iter()
        .enumerate()
    {
        b.add_symbol(ObjectSymbol::Defined {
            name: (*name).into(),
            section_index: text,
            value: (i * 4) as u64,
            weak: false,
        });
    }
    b.build().expect("the fixture object builds")
}

/// util.o: a second `_sdk_*` definition and a util helper.
fn util_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("util.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    for (i, name) in ["_sdk_write", "_util_scratch"].iter().enumerate() {
        b.add_symbol(ObjectSymbol::Defined {
            name: (*name).into(),
            section_index: text,
            value: (i * 4) as u64,
            weak: false,
        });
    }
    b.build().expect("the fixture object builds")
}

/// The image's defined-extern surface: `(name, n_type)` pairs from the
/// symtab — both the exported names and the `N_PEXT` privates.
fn extern_surface(image: &[u8]) -> Vec<(String, u8)> {
    let hdr = pgr_format::MachHeader64::parse(image).expect("the image parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands parse");
    let mut out = Vec::new();
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if let pgr_format::LoadCommandKind::Symtab = cmd.kind {
            let st = pgr_format::SymtabCommand::parse(cmd.bytes, 0).expect("the symtab parses");
            let strtab = &image[st.stroff as usize..st.stroff as usize + st.strsize as usize];
            for i in 0..st.nsyms {
                let nl: pgr_format::symtab::Nlist64 = pgr_format::cursor::pod_read_unaligned_at(
                    image,
                    st.symoff as usize + i as usize * 16,
                )
                .expect("the symbol reads");
                if nl.n_type & pgr_format::consts::N_TYPE == pgr_format::consts::N_SECT {
                    let name = &strtab[nl.n_strx as usize..];
                    let name = &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())];
                    out.push((String::from_utf8_lossy(name).into_owned(), nl.n_type));
                }
            }
        }
    }
    out.sort();
    out
}

/// The image's export-trie names (the surface dyld actually binds).
fn trie_names(image: &[u8]) -> Vec<String> {
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
            let lc = pgr_format::LinkeditDataCommand::parse(cmd.bytes).expect("the LC parses");
            let blob = lc.data(image).expect("the trie payload is in range");
            return pgr_format::trie::exports(blob)
                .expect("the trie parses")
                .into_iter()
                .map(|e| String::from_utf8_lossy(&e.name).into_owned())
                .collect();
        }
    }
    Vec::new()
}

fn main() {
    // The spans stay inert until a subscriber installs; PGR_TRACING=1
    // turns them into stderr lines (the binaries do the same under
    // their debug envs).
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    let dir = std::env::temp_dir().join(format!("pgr_glob_filter_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sdk = dir.join("sdk.o");
    let util = dir.join("util.o");
    std::fs::write(&sdk, sdk_object()).unwrap();
    std::fs::write(&util, util_object()).unwrap();

    // 1. The exported-symbols list: the ld64 glob form. The header
    //    symbol is an export like any other — a filter that omits it
    //    ships an image without `__mh_execute_header` (ld64 behaves the
    //    same way); the list names it explicitly.
    let list: PathBuf = dir.join("sdk.exports");
    std::fs::write(
        &list,
        "# the SDK surface (globs: each * matches any, possibly empty, run)\n__mh_execute_header\n_sdk_*\n",
    )
    .unwrap();

    // 2. The link through the driver surface: the same
    //    `-exported_symbols_list` the CLI takes.
    let out = dir.join("sdktool");
    let argv: Vec<std::ffi::OsString> = [
        "-o".as_ref(),
        out.as_os_str(),
        sdk.as_os_str(),
        util.as_os_str(),
        "-e".as_ref(),
        "_sdk_main".as_ref(),
        "-exported_symbols_list".as_ref(),
        list.as_os_str(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let o = opts::parse(&argv).expect("the filtered argv parses");
    pgr_driver::run(&o).expect("the filtered link runs");

    // 3. Read the surface back from the image: the trie carries only
    //    the matched names; the rest survive as N_PEXT privates.
    let image = std::fs::read(&out).expect("the image reads");
    let report = verify(
        &image,
        &VerifyOptions {
            strict_warnings: true,
            skip_hash_recompute: false,
        },
    );
    assert!(
        report.is_ok(&VerifyOptions {
            strict_warnings: true,
            skip_hash_recompute: false,
        }),
        "the filtered image verifies strict: {:#?}",
        report.issues
    );
    let exported = trie_names(&image);
    println!("exported (the trie dyld binds):");
    for name in &exported {
        println!("  {name}");
    }
    println!("hidden in the image (N_PEXT privates, absent from the trie):");
    for (name, n_type) in extern_surface(&image) {
        let pext = n_type & pgr_format::consts::N_PEXT != 0;
        let external = n_type & pgr_format::consts::N_EXT != 0;
        if !external || pext {
            println!("  {name}{}", if pext { " (private external)" } else { "" });
        }
    }

    // 4. The advisory: a pattern that matched nothing is a typo. The
    //    driver warns on stderr during the link; the same condition
    //    renders as the miette diagnostic here — the fix, not just the
    //    verdict.
    let universe: Vec<String> = extern_surface(&image).into_iter().map(|(n, _)| n).collect();
    let typo = "_sdk_pub_*";
    let pat = pgr_core::SymbolPattern::parse(typo.as_bytes()).expect("the pattern parses");
    let matched = universe.iter().any(|n| pat.matches(n.as_bytes()));
    if !matched {
        eprintln!(
            "{:?}",
            miette::Report::new(UnmatchedPattern {
                pattern: typo.to_string(),
            })
        );
    }
    println!(
        "\nimage: {} (filtered link, strict-verified; try PGR_TRACING=1 to watch the filter contract)",
        out.display()
    );
}
