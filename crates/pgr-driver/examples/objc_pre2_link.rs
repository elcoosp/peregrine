//! The GCC-era ObjC-pull consumer example (M49): shipping an archive of
//! ObjC1/GCC-era members — `.objc_class_name_<Class>` classes and
//! `.objc_category_name_<Class>_<Category>` categories — and linking it
//! under `-ObjC`. ld64's archive matcher names the ranlib-index
//! prefixes `.objc_c*` (the `ObjC1` C symbols) beside `_OBJC_CLASS_$_`
//! (ld64-609 `archive_file.cpp`); the M43 release shipped the modern
//! `$_`-prefixed family only, and M49 widens the classifier so the
//! GCC-era members ride the pull too. The protocol member
//! (`_OBJC_PROTOCOL_$_`) stays out — a protocol is neither a class nor
//! a category, and ld64's matcher reads neither. Both images verify
//! strict; the symtab rows are read back — the surface a build system
//! audits after the link.
//!
//! Run: `cargo run -p pgr-driver --example objc_pre2_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ArchiveBuilder, ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// main.o: `_main` over two RET functions — no `ObjC` reference at all
/// (the pull must be the knob's work, never a reference's).
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

/// pre2.o: the GCC-era class symbol beside a reference to `_helper` —
/// the transitive edge (the pulled member's own undefineds keep
/// pulling their providers).
fn pre2_class_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("pre2.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: ".objc_class_name_Dog".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_helper".into(),
        weak_ref: false,
    });
    b.build().expect("the fixture object builds")
}

/// pre2tricks.o: the GCC-era category symbol.
fn pre2_category_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("pre2tricks.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: ".objc_category_name_Dog_Tricks".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// proto.o: a protocol definition — stays out under the knob.
fn protocol_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("proto.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_OBJC_PROTOCOL_$_Foo".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// helper.o: the provider the pulled class member demands.
fn helper_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("helper.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_helper".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// Builds the archive and writes the corpus; returns the input paths.
fn corpus(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut builder = ArchiveBuilder::new("libpre2.a");
    builder.add_member("pre2.o", pre2_class_object());
    builder.add_member("pre2tricks.o", pre2_category_object());
    builder.add_member("proto.o", protocol_object());
    builder.add_member("helper.o", helper_object());
    let arch = dir.join("libpre2.a");
    std::fs::write(&arch, builder.build()).expect("the archive writes");
    let main = dir.join("main.o");
    std::fs::write(&main, caller_object()).expect("the caller writes");
    vec![main, arch]
}

fn strict_ok(image: &[u8]) -> bool {
    let opts = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    verify(image, &opts).is_ok(&opts)
}

/// True when the image's symtab defines `name` externally.
fn defines(image: &[u8], name: &[u8]) -> bool {
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
        if let pgr_format::LoadCommandKind::Symtab = cmd.kind {
            st = Some(pgr_format::SymtabCommand::parse(image, cmd.offset).expect("the lc parses"));
        }
    }
    let st = st.expect("the symtab command rides the header");
    for i in 0..st.nsyms {
        let at = st.symoff as usize + i as usize * 16;
        let n_strx = u32::from_le_bytes(image[at..at + 4].try_into().expect("n_strx rides byte 0"));
        let n_type = image[at + 4];
        let strtab = st.stroff as usize;
        let nul = image[strtab + n_strx as usize..]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(0);
        let name_bytes = &image[strtab + n_strx as usize..strtab + n_strx as usize + nul];
        if name_bytes == name {
            return n_type & pgr_format::consts::N_TYPE != pgr_format::consts::N_UNDF;
        }
    }
    false
}

/// Links the corpus with the named extra flags; returns the image bytes.
fn link_app(extra: &[&str]) -> Vec<u8> {
    let dir = std::env::temp_dir().join(format!("pgr_objc_pre2_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    let out = dir.join("app");
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        std::ffi::OsString::from(out.to_str().expect("the output path names")),
    ];
    for input in corpus(&dir) {
        argv.push(std::ffi::OsString::from(
            input.to_str().expect("the path names"),
        ));
    }
    for a in extra {
        argv.push(std::ffi::OsString::from(*a));
    }
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs");
    std::fs::read(&out).expect("the image reads")
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    // The default: reference-driven — the GCC-era members nothing
    // references stay unparsed (the pre-M49 shape).
    let plain = link_app(&[]);
    assert!(strict_ok(&plain), "the default image verifies strict");
    assert!(
        !defines(&plain, b".objc_class_name_Dog"),
        "the default keeps the GCC-era member unparsed"
    );
    println!(
        "default: {} bytes — reference-driven, no GCC-era member rides",
        plain.len()
    );

    // The named pull: both metadata families ride, the pulled member's
    // own undefineds continue the fixpoint (helper.o lands beside it),
    // and the protocol member stays out.
    let pulled = link_app(&["-ObjC"]);
    assert!(strict_ok(&pulled), "the pulled image verifies strict");
    for (name, note) in [
        (
            &b".objc_class_name_Dog"[..],
            "the GCC-era class rides the pull",
        ),
        (
            &b".objc_category_name_Dog_Tricks"[..],
            "the GCC-era category rides the pull",
        ),
        (
            &b"_helper"[..],
            "the pulled member's own undefined keeps its provider",
        ),
    ] {
        assert!(defines(&pulled, name), "{note}");
        println!(
            "pulled:  {} — {}",
            std::str::from_utf8(name).expect("the symbol names"),
            note
        );
    }
    assert!(
        !defines(&pulled, b"_OBJC_PROTOCOL_$_Foo"),
        "a protocol is neither a class nor a category — the member stays out"
    );
    println!("pulled:  _OBJC_PROTOCOL_$_Foo stays out (the man page names class or category)");

    println!(
        "\nThe .objc_c family is ld64's own index-prefix rule for -ObjC; \
         try PGR_TRACING=1 to watch the objc_pull span"
    );
}
