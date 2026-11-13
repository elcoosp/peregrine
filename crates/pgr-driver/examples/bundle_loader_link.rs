//! The bundle-loader consumer example (M25): the same `bundle.o`
//! linked as a plain `-bundle` (its externals riding
//! `-undefined dynamic_lookup`) and as one bound against a host
//! executable (`-bundle_loader host`) — the loader bind read back from
//! the image (the main-executable ordinal `0xFF` in the symtab and the
//! import table, no `LC_LOAD_DYLIB` for the host), the pair gate on
//! both images, and the executable-conflict refusal rendered as miette
//! help text (the fix, not just the verdict: the house
//! consumer-example convention).
//!
//! Run: `cargo run -p pgr-driver --example bundle_loader_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use; the seam's
//! own decision event rides it).

use pgr_driver::opts;
use pgr_fixtures::{
    ImageBuilder, ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol, SectionSpec,
    SegmentSpec, SymbolSpec, filler,
};
use pgr_format::consts::{S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ};
use pgr_verify::pair::verify_bundle_loader;
use pgr_verify::{Options as VerifyOptions, verify};

/// bundle.o: `_bundle_main` calls `_host_fn` (BL against the loader).
fn bundle_object(dir: &std::path::Path) -> std::path::PathBuf {
    let mut b = ObjectBuilder::new("bundle.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [
            0x9400_0000u32, // bl _host_fn
            0x5280_0000u32, // mov w0, #0
            0xD65F_03C0u32, // ret
        ]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect(),
        vec![ObjectReloc::branch26(1).at(0)],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_bundle_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_host_fn".into(),
        weak_ref: false,
    });
    let path = dir.join("bundle.o");
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    path
}

/// The host executable: a legal image exporting `_host_fn` (the
/// fixture builder's shape — the trie plus the symtab externals the
/// scan reads).
fn host_executable(dir: &std::path::Path) -> std::path::PathBuf {
    let mut b = ImageBuilder::executable("host");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(0x5AA5, 96),
            relocs: Vec::new(),
        }],
    });
    b.set_entry(0);
    b.add_symbol(SymbolSpec::Defined {
        name: "_host_fn".into(),
        section_index: 0,
    });
    let path = dir.join("host");
    std::fs::write(&path, b.build().expect("the host fixture builds").bytes).unwrap();
    path
}

/// The image's undefined symtab rows: `(name, library ordinal)`.
fn undef_rows(image: &[u8]) -> Vec<(String, u16)> {
    let hdr = pgr_format::MachHeader64::parse(image).expect("the image parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands parse");
    let mut st = None;
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if cmd.kind == pgr_format::LoadCommandKind::Symtab {
            st = Some(
                pgr_format::symtab::SymtabCommand::parse(cmd.bytes, 0).expect("the symtab parses"),
            );
        }
    }
    let st = st.expect("LC_SYMTAB present");
    let mut rows = Vec::new();
    for i in 0..st.nsyms {
        let off = st.symoff as usize + i as usize * 16;
        let sym: pgr_format::symtab::Nlist64 =
            pgr_format::cursor::pod_read_unaligned_at(image, off).expect("the symbol reads");
        if sym.is_undefined() && sym.is_external() {
            let str_at = st.stroff as usize + sym.n_strx as usize;
            let tail = &image[str_at..st.stroff as usize + st.strsize as usize];
            let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
            rows.push((
                String::from_utf8_lossy(&tail[..end]).into_owned(),
                sym.library_ordinal(),
            ));
        }
    }
    rows
}

fn link(dir: &std::path::Path, out: &str, extra: &[String]) -> Vec<u8> {
    let obj = bundle_object(dir);
    let out_path = dir.join(out);
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        out_path.as_os_str().to_os_string(),
        std::ffi::OsString::from("-bundle"),
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

    let dir = std::env::temp_dir().join(format!("pgr_bundle_loader_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let host = host_executable(&dir);

    // 1. The plain bundle: the pre-M25 shape — the externals ride
    //    `-undefined dynamic_lookup` (the flat-lookup ordinal), no
    //    host named.
    let plain = link(
        &dir,
        "plain.dylib",
        &["-undefined".into(), "dynamic_lookup".into()],
    );
    let rows = undef_rows(&plain);
    println!("plain bundle undefined rows: {rows:?}");
    assert!(
        rows.iter().any(|(n, o)| n == "_host_fn" && *o == 0xFE),
        "the externals ride the flat-lookup ordinal"
    );
    let opts_strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let report = verify(&plain, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the plain bundle verifies strict"
    );

    // 2. The loader-bound bundle: the externals ride the
    //    main-executable ordinal (`0xFF`) — dyld resolves them against
    //    the host process at load time; no `LC_LOAD_DYLIB` for the host.
    let loader_argv = vec!["-bundle_loader".to_string(), host.display().to_string()];
    let bound = link(&dir, "bound.dylib", &loader_argv);
    let rows = undef_rows(&bound);
    println!("loader-bound bundle undefined rows: {rows:?}");
    assert!(
        rows.iter().any(|(n, o)| n == "_host_fn"
            && *o == pgr_format::consts::BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE),
        "the externals ride the main-executable ordinal"
    );

    // 3. The pair gate: every `0xFF` bind names an export the host's
    //    surface carries.
    let host_bytes = std::fs::read(&host).expect("the host reads");
    let pair = verify_bundle_loader(&bound, &host_bytes, &opts_strict);
    assert!(
        pair.is_ok(&opts_strict),
        "the bundle + loader pair verifies: bundle {:?}, loader {:?}, pair {:?}",
        pair.bundle.issues,
        pair.loader.issues,
        pair.pair_issues
    );
    let report = verify(&bound, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the loader-bound bundle verifies strict like the plain one"
    );

    // 4. The refusal: the knob off a bundle is a parse-time refusal —
    //    an executable is the host of its own bundles — rendered as
    //    miette help text (the fix, not just the verdict).
    let obj = bundle_object(&dir);
    let argv: Vec<std::ffi::OsString> = [
        "-o".to_string(),
        dir.join("exe").display().to_string(),
        "-bundle_loader".to_string(),
        host.display().to_string(),
        obj.display().to_string(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    match opts::parse(&argv) {
        Ok(_) => unreachable!("the executable conflict refuses"),
        Err(err) => {
            eprintln!("\nthe refusal (verdict + fix):");
            eprintln!("{:?}", miette::Report::new(err));
        }
    }

    println!("\nbundle_loader_link: ok");
}
