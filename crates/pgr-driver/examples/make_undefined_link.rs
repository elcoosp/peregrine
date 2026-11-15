//! The make-undefined consumer example (M39): one `override.o` whose
//! `_main` calls `_greet` and whose own `__text` also carries the
//! `_greet` body — linked twice, once plain (the local definition
//! answers the call) and once under `-U _greet -undefined
//! dynamic_lookup` (the mark strips the definition *as it is linked*:
//! the symtab row turns undefined, the bind rides the flat-lookup
//! ordinal, the strict verifier still passes). The relocatable
//! conflict refusal renders as miette help text (the fix, not just the
//! verdict: the house consumer-example convention), and the vacuous
//! mark (`-U _typo`) refuses at link time with the misspelling named.
//!
//! This is ld64's overridable-symbol escape hatch: the definition
//! compiles in, but the host's runtime definition wins at load time.
//!
//! Run: `cargo run -p pgr-driver --example make_undefined_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use; the seam's
//! own decision event rides it).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// override.o: `_main` calls `_greet` (a `Branch26` at offset 4) and
/// defines `_greet` right behind it — the body the mark strips.
fn override_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("override.o").set_subsections_via_symbols(true);
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
    let greet = b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 4,
        weak: false,
    });
    b.section_mut(text).relocs = vec![ObjectReloc::branch26(u32::try_from(greet).unwrap()).at(4)];
    b.build().expect("the fixture object builds")
}

/// The image's external symbol rows as `(name, n_type, n_desc)` — the
/// readback the example asserts against.
fn symbol_rows(image: &[u8]) -> Vec<(String, u8, u16)> {
    let hdr = pgr_format::MachHeader64::parse(image).expect("the image parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if cmd.kind == pgr_format::LoadCommandKind::Symtab {
            let st: pgr_format::SymtabCommand =
                pgr_format::cursor::pod_read_unaligned_at(image, cmd.offset)
                    .expect("the command parses");
            let mut rows = Vec::new();
            for i in 0..st.nsyms {
                let sym: pgr_format::symtab::Nlist64 = pgr_format::cursor::pod_read_unaligned_at(
                    image,
                    st.symoff as usize + i as usize * 16,
                )
                .expect("the symbol parses");
                if sym.n_type & pgr_format::consts::N_EXT != 0 {
                    // N_EXT: an external row (defined or undefined — the
                    // undefined extern's N_TYPE is zero, the mark's shape).
                    let str_at = st.stroff as usize + sym.n_strx as usize;
                    let end = image[str_at..]
                        .iter()
                        .position(|b| *b == 0)
                        .expect("the name is NUL-terminated");
                    rows.push((
                        String::from_utf8_lossy(&image[str_at..str_at + end]).into_owned(),
                        sym.n_type,
                        sym.n_desc,
                    ));
                }
            }
            return rows;
        }
    }
    panic!("the image carries LC_SYMTAB");
}

fn link(dir: &std::path::Path, out: &str, extra: &[&str]) -> Vec<u8> {
    let obj = dir.join("override.o");
    std::fs::write(&obj, override_object()).unwrap();
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

    let dir = std::env::temp_dir().join(format!("pgr_make_undefined_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // 1. The plain link: the local `_greet` body answers the call — a
    //    defined external row, the pre-M39 shape.
    let plain = link(&dir, "app_plain", &[]);
    let plain_rows = symbol_rows(&plain);
    let greet_defined = plain_rows.iter().any(|(n, t, _)| {
        n == "_greet" && t & pgr_format::consts::N_TYPE == pgr_format::consts::N_SECT
    });
    println!("plain: _greet defined = {greet_defined}");
    assert!(greet_defined, "the plain link keeps the local definition");
    let strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let report = verify(&plain, &strict);
    assert!(report.is_ok(&strict), "the plain image verifies strict");

    // 2. The marked link: `-U _greet` strips the definition as it is
    //    linked — the row turns undefined and the bind rides the
    //    flat-lookup ordinal (dyld resolves it at launch).
    let marked = link(
        &dir,
        "app_marked",
        &["-U", "_greet", "-undefined", "dynamic_lookup"],
    );
    let marked_rows = symbol_rows(&marked);
    println!("marked symbol rows:");
    for (name, n_type, n_desc) in &marked_rows {
        let kind = if n_type & pgr_format::consts::N_TYPE == pgr_format::consts::N_UNDF {
            "undef"
        } else {
            "def"
        };
        println!("  {name:<12} {kind} (n_type {n_type:#04x}, n_desc {n_desc:#06x})");
    }
    let greet_row = marked_rows
        .iter()
        .find(|(n, _, _)| n == "_greet")
        .expect("the marked name still rides the symtab (as a reference)");
    assert!(
        greet_row.1 & pgr_format::consts::N_TYPE == pgr_format::consts::N_UNDF,
        "the mark turned the definition undefined"
    );
    assert_eq!(
        greet_row.2 >> 8,
        pgr_format::consts::BIND_SPECIAL_DYLIB_FLAT_LOOKUP,
        "the dynamic lookup binds with the flat-lookup ordinal"
    );
    let report = verify(&marked, &strict);
    assert!(
        report.is_ok(&strict),
        "the marked image verifies strict like the plain one: {:#?}",
        report.issues
    );

    // 3. The relocatable conflict: a mark has nothing to strip on `-r` —
    //    rendered as miette help text (the fix, not just the verdict).
    let obj = dir.join("override.o");
    let argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        dir.join("object").display().to_string(),
        "-r".to_string(),
        "-U".to_string(),
        "_greet".to_string(),
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

    // 4. The vacuous mark: a name nothing defines has nothing to strip —
    //    the link-time refusal names the misspelling.
    let argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        dir.join("app_typo").display().to_string(),
        "-U".to_string(),
        "_typo".to_string(),
        obj.display().to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let o = opts::parse(&argv).expect("the argv parses (the grammar is fine)");
    match pgr_driver::run(&o) {
        Ok(_) => unreachable!("the vacuous mark refuses"),
        Err(err) => {
            eprintln!("\nthe vacuous mark (the misspelling is named):");
            eprintln!("{err}");
        }
    }

    println!("\nmake_undefined_link: ok");
}
