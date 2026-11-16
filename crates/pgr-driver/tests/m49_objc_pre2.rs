//! M49 — the GCC-era `ObjC` symbols join the `-ObjC` pull, driver
//! surface: the flag names the decision on the CLI (`o.config.objc`, a
//! M43 release — the widened classifier is core-side, so the driver
//! surface rides unchanged), a GCC-era class-defining archive member
//! rides the pull and the image verifies strict, the default stays
//! reference-driven, the protocol member the knob must not admit stays
//! out, and the relocatable output rides the same pull.

use pgr_fixtures::{ArchiveBuilder, ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64, SymtabCommand};
use pgr_verify::{Options as VerifyOptions, verify};
use std::path::PathBuf;

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m49_objc_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

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

/// `libpre2.a`: the GCC-era class member (`pre2.o`), the GCC-era
/// category member (`pre2tricks.o`), the protocol member (`proto.o` —
/// stays out) and the plain member (`plain.o`) — none referenced by the
/// caller.
fn archive(dir: &std::path::Path, tag: &str) -> PathBuf {
    let mut builder = ArchiveBuilder::new("libpre2.a");
    builder.add_member("pre2.o", member("pre2.o", &[".objc_class_name_Dog"]));
    builder.add_member(
        "pre2tricks.o",
        member("pre2tricks.o", &[".objc_category_name_Dog_Tricks"]),
    );
    builder.add_member("proto.o", member("proto.o", &["_OBJC_PROTOCOL_$_Foo"]));
    builder.add_member("plain.o", member("plain.o", &["_plain_fn"]));
    let path = dir.join(format!("{tag}_libpre2.a"));
    std::fs::write(&path, builder.build()).expect("the archive writes");
    path
}

/// Writes the corpus (the caller and the archive); returns the paths.
fn corpus(dir: &std::path::Path, tag: &str) -> Vec<PathBuf> {
    let obj = dir.join(format!("{tag}_main.o"));
    std::fs::write(&obj, caller_object()).unwrap();
    let arch = archive(dir, tag);
    vec![obj, arch]
}

/// Links `inputs` under `extra` argv; returns the image bytes.
fn link(dir: &std::path::Path, out: &str, inputs: &[PathBuf], extra: &[&str]) -> Vec<u8> {
    let out_path = dir.join(out);
    let mut argv: Vec<String> = vec!["-o".into(), out_path.display().to_string()];
    argv.extend(inputs.iter().map(|p| p.display().to_string()));
    argv.extend(extra.iter().map(std::string::ToString::to_string));
    let argv: Vec<std::ffi::OsString> = argv.iter().map(std::ffi::OsString::from).collect();
    let o = pgr_driver::opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs");
    std::fs::read(&out_path).expect("the image reads")
}

fn strict() -> VerifyOptions {
    VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// True when the image's symtab defines `name` externally.
fn defines(image: &[u8], name: &[u8]) -> bool {
    let header = MachHeader64::parse(image).expect("the header parses");
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

#[test]
fn the_flag_shapes_the_config() {
    let dir = scratch("opts");
    let inputs = corpus(&dir, "opts");
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        dir.join("app").as_os_str().to_os_string(),
    ];
    argv.extend(inputs.iter().map(|p| p.as_os_str().to_os_string()));
    argv.push(std::ffi::OsString::from("-ObjC"));
    let o = pgr_driver::opts::parse(&argv).expect("the argv parses");
    assert!(o.config.objc, "the flag names the pull decision");
    let default = pgr_driver::opts::parse(&argv[..2 + inputs.len()]).expect("the argv parses");
    assert!(
        !default.config.objc,
        "the default keeps every pull reference-driven"
    );
}

#[test]
fn the_pre2_members_ride_and_verify_strict() {
    let dir = scratch("e2e");
    let inputs = corpus(&dir, "e2e");
    let image = link(&dir, "app_objc", &inputs, &["-ObjC"]);
    assert!(
        defines(&image, b".objc_class_name_Dog"),
        "the GCC-era class-defining member rides the pull"
    );
    assert!(
        defines(&image, b".objc_category_name_Dog_Tricks"),
        "the GCC-era category-defining member rides the pull"
    );
    let report = verify(&image, &strict());
    assert!(
        report.is_ok(&strict()),
        "the pulled image verifies strict: {:?}",
        report.issues
    );
}

#[test]
fn the_protocol_member_stays_out() {
    let dir = scratch("proto");
    let inputs = corpus(&dir, "proto");
    let image = link(&dir, "app_proto", &inputs, &["-ObjC"]);
    assert!(
        !defines(&image, b"_OBJC_PROTOCOL_$_Foo"),
        "a protocol names neither a class nor a category — the member \
         stays out under the knob"
    );
}

#[test]
fn the_default_stays_reference_driven() {
    let dir = scratch("default");
    let inputs = corpus(&dir, "default");
    let image = link(&dir, "app_default", &inputs, &[]);
    assert!(
        !defines(&image, b".objc_class_name_Dog"),
        "the default keeps the unreferenced GCC-era member unparsed"
    );
}

#[test]
fn the_relocatable_output_rides_the_pull() {
    let dir = scratch("reloc");
    let inputs = corpus(&dir, "reloc");
    let out = dir.join("reloc.o");
    let mut argv: Vec<String> = vec!["-r".into(), "-o".into(), out.display().to_string()];
    argv.extend(inputs.iter().map(|p| p.display().to_string()));
    argv.push("-ObjC".into());
    let argv: Vec<std::ffi::OsString> = argv.iter().map(std::ffi::OsString::from).collect();
    let o = pgr_driver::opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the relocatable link runs");
    let image = std::fs::read(&out).expect("the object reads");
    assert!(
        defines(&image, b".objc_class_name_Dog"),
        "the relocatable pull admits the GCC-era class member (the object \
         output carries the pulled member verbatim)"
    );
    assert!(
        !defines(&image, b"_OBJC_PROTOCOL_$_Foo"),
        "the relocatable pull still refuses the protocol member"
    );
}
