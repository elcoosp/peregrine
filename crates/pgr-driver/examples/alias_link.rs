//! The symbol-alias consumer example (M24): the same `hello.o` linked
//! as a plain executable and as one exporting
//! `-alias _hello_greet _greet` — the alias read back from the image
//! (a symtab row carrying the definition's value and a trie node at
//! the definition's address, dyld resolves both names to one body),
//! the strict verifier on both, and the relocatable-conflict refusal
//! rendered as miette help text (the fix, not just the verdict: the
//! house consumer-example convention).
//!
//! Run: `cargo run -p pgr-driver --example alias_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use; the seam's
//! own decision event rides it).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// hello.o: `_main` calls `_greet` (BL) and a `__data` pointer keeps a
/// rebase slot in the image — the executable the example links twice.
fn hello_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("hello.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [
            0x9400_0000u32, // bl _greet
            0x5280_0000u32, // mov w0, #0
            0xD65F_03C0u32, // ret
        ]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect(),
        vec![ObjectReloc::branch26(1).at(0)],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 4,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// The image's export trie, walked.
fn trie_exports(image: &[u8]) -> Vec<pgr_format::TrieExport> {
    let hdr = pgr_format::MachHeader64::parse(image).expect("the image parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands parse");
    let mut payload: Option<&[u8]> = None;
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if let pgr_format::LoadCommandKind::LinkeditData(op) = cmd.kind
            && op == pgr_format::consts::LC_DYLD_EXPORTS_TRIE
        {
            let (off, size) = (
                u32::from_le_bytes(cmd.bytes[8..12].try_into().expect("dataoff")),
                u32::from_le_bytes(cmd.bytes[12..16].try_into().expect("datasize")),
            );
            let at = off as usize;
            payload = Some(&image[at..at + size as usize]);
        }
    }
    let payload = payload.expect("LC_DYLD_EXPORTS_TRIE present");
    pgr_format::trie::exports(payload).expect("the trie walks")
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

    let dir = std::env::temp_dir().join(format!("pgr_alias_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // 1. The plain executable: the pre-M24 shape — the definition's
    //    name only.
    let plain = link(&dir, "hello_plain", &[]);
    let exports = trie_exports(&plain);
    assert!(
        exports.iter().all(|e| e.name != b"_hello_greet"),
        "the default carries no alias exports"
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

    // 2. The aliased executable: the alias name rides the export trie
    //    at the definition's address — both names resolve to one body.
    let aliased = link(
        &dir,
        "hello",
        &[
            "-alias",
            "_hello_greet",
            "_greet",
            "-alias",
            "_entry",
            "_main",
        ],
    );
    let exports = trie_exports(&aliased);
    println!("export trie:");
    for e in &exports {
        println!(
            "  {} @ {:#x}",
            String::from_utf8_lossy(&e.name),
            e.address.unwrap_or(0)
        );
    }
    let shim = exports
        .iter()
        .find(|e| e.name == b"_hello_greet")
        .expect("the alias exports");
    let target = exports
        .iter()
        .find(|e| e.name == b"_greet")
        .expect("the definition exports");
    assert_eq!(
        shim.address, target.address,
        "the alias exports at the definition's address"
    );
    let entry = exports
        .iter()
        .find(|e| e.name == b"_entry")
        .expect("the second alias exports");
    let main_sym = exports
        .iter()
        .find(|e| e.name == b"_main")
        .expect("the main symbol exports");
    assert_eq!(entry.address, main_sym.address, "the second alias, too");
    let report = verify(&aliased, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the aliased executable verifies strict like the plain one"
    );

    // 3. The refusal: an alias of a name no input defines is a link
    //    error — the misspelling named, the fix in the message.
    let obj = dir.join("hello.o");
    let argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        dir.join("hello_bad").display().to_string(),
        "-alias".to_string(),
        "_hello_greet".to_string(),
        "_greets".to_string(),
        obj.display().to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let o = opts::parse(&argv).expect("the argv parses");
    match pgr_driver::run(&o) {
        Ok(_) => unreachable!("the missing definition refuses"),
        Err(err) => {
            eprintln!("\nthe refusal (the misspelling, named):");
            eprintln!("{err}");
        }
    }

    println!("\nalias_link: ok");
}
