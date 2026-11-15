//! The ObjC-pull consumer example (M43): a caller that references no
//! Objective-C symbol at all, linked against an archive whose members
//! implement a class, a category and a plain external — under the
//! default the metadata members stay unparsed (the reference-driven
//! S7 pull), under `-ObjC` they ride (the runtime registers the
//! metadata by section address, so no static reference could ever pull
//! them), and both images run through the strict verifier — the knob a
//! build system names when its link line carries a static `ObjC` library
//! whose classes the code reaches only through the runtime.
//!
//! Run: `cargo run -p pgr-driver --example objc_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans —
//! the `objc_pull` span names the metadata members per archive).

use pgr_driver::opts;
use pgr_fixtures::{ArchiveBuilder, ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64, SymtabCommand};
use pgr_verify::{Options as VerifyOptions, verify};

/// main.o: `_main` over two RET functions — no `ObjC` reference at all.
fn caller_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("main.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// An object defining the named symbols over RET bodies.
fn member(name: &str, symbols: &[&str]) -> Vec<u8> {
    let mut b = ObjectBuilder::new(name);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(symbols.len() * 2),
        vec![],
    ));
    for (i, sym) in symbols.iter().enumerate() {
        b.add_symbol(ObjectSymbol::Defined {
            name: (*sym).into(),
            section_index: text,
            value: (i as u64) * 8,
            weak: false,
        });
    }
    b.build().expect("the fixture object builds")
}

/// `libclasses.a`: the class member, the category member and the plain
/// member — none referenced by the caller.
fn archive_bytes() -> Vec<u8> {
    let mut builder = ArchiveBuilder::new("libclasses.a");
    builder.add_member(
        "dog.o",
        member("dog.o", &["_OBJC_CLASS_$_Dog", "_OBJC_METACLASS_$_Dog"]),
    );
    builder.add_member(
        "tricks.o",
        member("tricks.o", &["_OBJC_CATEGORY_$_Dog_Tricks"]),
    );
    builder.add_member("plain.o", member("plain.o", &["_plain_fn"]));
    builder.build()
}

/// True when the image's symtab defines `name` externally.
fn defines(image: &[u8], name: &[u8]) -> bool {
    let header = MachHeader64::parse(image).expect("the image parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load commands parse");
    let mut st = None;
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if let LoadCommandKind::Symtab = cmd.kind {
            st = Some(SymtabCommand::parse(image, cmd.offset).expect("the symtab parses"));
        }
    }
    let st = st.expect("the symtab command rides the header");
    for i in 0..st.nsyms {
        let off = st.symoff as usize + i as usize * 16;
        let sym: pgr_format::Nlist64 =
            pgr_format::cursor::pod_read_unaligned_at(image, off).expect("the row parses");
        let at = st.stroff as usize + sym.n_strx as usize;
        let end = image[at..].iter().position(|&b| b == 0).expect("NUL") + at;
        if &image[at..end] == name {
            return sym.n_type & pgr_format::consts::N_TYPE != pgr_format::consts::N_UNDF;
        }
    }
    false
}

fn link(dir: &std::path::Path, out: &str, extra: &[&str]) -> Vec<u8> {
    let out_path = dir.join(out);
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        out_path.as_os_str().to_os_string(),
    ];
    let obj = dir.join("main.o");
    std::fs::write(&obj, caller_object()).unwrap();
    argv.push(obj.as_os_str().to_os_string());
    let arch = dir.join("libclasses.a");
    std::fs::write(&arch, archive_bytes()).unwrap();
    argv.push(arch.as_os_str().to_os_string());
    argv.extend(extra.iter().map(std::ffi::OsString::from));
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

    let dir = std::env::temp_dir().join(format!("pgr_objc_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let opts_strict = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };

    // 1. The default: the pull stays reference-driven — the class and
    //    category members nothing references stay unparsed, the plain
    //    provider stays out, and the image verifies strict like any
    //    other.
    let reference_driven = link(&dir, "app_default", &[]);
    let names: [&[u8]; 4] = [
        b"_OBJC_CLASS_$_Dog",
        b"_OBJC_METACLASS_$_Dog",
        b"_OBJC_CATEGORY_$_Dog_Tricks",
        b"_plain_fn",
    ];
    let pulled_default: Vec<bool> = names
        .iter()
        .map(|n| defines(&reference_driven, n))
        .collect();
    assert!(
        pulled_default.iter().all(|p| !p),
        "the default keeps every unreferenced member unparsed: {pulled_default:?}"
    );
    let report = verify(&reference_driven, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the default image verifies strict: {:?}",
        report.issues
    );

    // 2. The pull: the same corpus under `-ObjC` — the class (with its
    //    metaclass) and the category members ride; the plain member
    //    still stays out (the rule is class-or-category, not
    //    -all_load), and the image verifies strict.
    let objc = link(&dir, "app_objc", &["-ObjC"]);
    assert!(
        defines(&objc, b"_OBJC_CLASS_$_Dog"),
        "the class rides the pull"
    );
    assert!(
        defines(&objc, b"_OBJC_METACLASS_$_Dog"),
        "the metaclass rides beside its class"
    );
    assert!(
        defines(&objc, b"_OBJC_CATEGORY_$_Dog_Tricks"),
        "the category rides the pull"
    );
    assert!(
        !defines(&objc, b"_plain_fn"),
        "the plain member stays out — the knob is not -all_load"
    );
    let report = verify(&objc, &opts_strict);
    assert!(
        report.is_ok(&opts_strict),
        "the pulled image verifies strict: {:?}",
        report.issues
    );

    println!(
        "default: {} metadata symbols in the image ({} bytes) — the reference-driven pull",
        pulled_default.iter().filter(|p| **p).count(),
        reference_driven.len()
    );
    println!(
        "objc:    3 metadata symbols in the image ({} bytes) — the class, the metaclass \
         and the category ride; the plain member stays out",
        objc.len()
    );
}
