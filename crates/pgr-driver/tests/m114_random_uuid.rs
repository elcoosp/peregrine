//! M114 — the `-random_uuid` surface: ld64's random-UUID flag rides the
//! driver as the typed `UuidSource` alphabet's second value — the parse
//! face sets the source, the conflicts are `finish`'s (the surface sees
//! the whole argv): `-random_uuid` × `-uuid` and `-random_uuid` ×
//! `-no_uuid` refuse each other (two answers to the identity question —
//! the M99 conflict shape, order-independent), and `-r` refuses
//! (the object carries no `LC_UUID` command — the surface's knob
//! refusal mirrored exactly). The end-to-end gate: the emitted image
//! carries a whole `UUIDv4` identity and verifies strict.

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::ffi::OsString;

/// hello.o: `_main` (`ret` in `__text`) — the corpus the M32/M99 driver
/// tests share.
fn hello_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("hello.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6, 0xC0, 0x03, 0x5F, 0xD6],
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

fn scratch(name: &str) -> (std::path::PathBuf, Vec<OsString>) {
    let dir = std::env::temp_dir().join(format!("pgr_m114_{name}_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("the scratch dir creates");
    let obj = dir.join("hello.o");
    std::fs::write(&obj, hello_object()).expect("hello.o writes");
    let out = dir.join("hello");
    let mut argv: Vec<OsString> = vec!["-o".into(), out.to_string_lossy().into_owned().into()];
    argv.push(obj.to_string_lossy().into_owned().into());
    (out, argv)
}

/// The image's `LC_UUID` payload when the command rides (the M99 read).
fn uuid_of(image: &[u8]) -> Option<[u8; 16]> {
    let hdr = pgr_format::MachHeader64::parse(image).expect("the image parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if let pgr_format::LoadCommandKind::Uuid = cmd.kind {
            let st = pgr_format::UuidCommand::parse(cmd.bytes).expect("the lc parses");
            return Some(st.uuid);
        }
    }
    None
}

#[test]
fn the_flag_names_the_random_source() {
    let (out, argv) = scratch("face");
    let o = opts::parse(&argv).expect("the plain argv parses");
    assert_eq!(
        o.config.uuid_source,
        pgr_core::layout::UuidSource::Content,
        "the default is the content source"
    );
    let mut random_argv = argv.clone();
    random_argv.push("-random_uuid".into());
    let o = opts::parse(&random_argv).expect("the flag parses");
    assert_eq!(
        o.config.uuid_source,
        pgr_core::layout::UuidSource::Random,
        "the flag names the random source"
    );
    let _ = std::fs::remove_file(&out);
}

#[test]
fn the_random_link_carries_a_whole_identity_and_verifies_strict() {
    let (out, argv) = scratch("e2e");
    let mut random_argv = argv.clone();
    random_argv.push("-random_uuid".into());
    let o = opts::parse(&random_argv).expect("the surface parses");
    let outcome = pgr_driver::run(&o).expect("the link runs");
    assert!(outcome.file_size > 0, "the image writes");
    let image = std::fs::read(&out).expect("the image reads");
    let uuid = uuid_of(&image).expect("the image carries the LC_UUID command");
    assert_ne!(uuid, [0u8; 16], "the identity is a draw, never zero");
    assert_eq!(uuid[6] >> 4, 4, "the version nibble names UUIDv4");
    assert_eq!(
        uuid[8] >> 6,
        0b10,
        "the variant bits name the RFC 4122 form"
    );
    let strict = VerifyOptions::default();
    assert!(
        verify(&image, &strict).is_ok(&strict),
        "the random-carrying image verifies strict"
    );
    // The content face beside it derives (the deterministic contract):
    // a second run without the flag derives the same identity twice
    // across runs (the reproducible-builds contract).
    let out_a = {
        let o = opts::parse(&argv).expect("the content surface parses");
        pgr_driver::run(&o).expect("the content link runs");
        std::fs::read(&out).expect("the content image reads")
    };
    let o = opts::parse(&argv).expect("the content surface parses again");
    pgr_driver::run(&o).expect("the content link runs again");
    let out_b = std::fs::read(&out).expect("the content image reads again");
    assert_eq!(
        uuid_of(&out_a),
        uuid_of(&out_b),
        "the content face derives the same identity across runs"
    );
    assert_eq!(out_a, out_b, "the content face's image is reproducible");
    let _ = std::fs::remove_file(&out);
}

#[test]
fn random_uuid_and_uuid_refuse_each_other() {
    // Two answers to the identity question — order-independent (the
    // M99 pair shape; the argv order is not the shape).
    const NAMED: &str = "7d1e6f2a-93c4-4b8d-a1e2-3f4c5d6e7f80";
    for order in 0..2 {
        let (_, argv) = scratch("pair_named");
        let mut full: Vec<OsString> = argv.clone();
        if order == 0 {
            full.push("-random_uuid".into());
            full.push("-uuid".into());
            full.push(NAMED.into());
        } else {
            full.push("-uuid".into());
            full.push(NAMED.into());
            full.push("-random_uuid".into());
        }
        match opts::parse(&full) {
            Ok(_) => panic!("order {order}: the identity flags refuse each other"),
            Err(err) => {
                let rendered = format!("{:?}", miette::Report::new(err));
                assert!(
                    rendered.contains("-random_uuid") && rendered.contains("-uuid"),
                    "the refusal names both flags: {rendered}"
                );
            }
        }
    }
    let (_, argv) = scratch("pair_none");
    let mut full: Vec<OsString> = argv.clone();
    full.push("-random_uuid".into());
    full.push("-no_uuid".into());
    match opts::parse(&full) {
        Ok(_) => panic!("the random draw and the suppression refuse each other"),
        Err(err) => {
            let rendered = format!("{:?}", miette::Report::new(err));
            assert!(
                rendered.contains("-random_uuid") && rendered.contains("-no_uuid"),
                "the refusal names both flags: {rendered}"
            );
        }
    }
    // The suppression and the named value keep their M99 refusal (the
    // alphabet's other pair).
    let mut full: Vec<OsString> = argv.clone();
    full.push("-no_uuid".into());
    full.push("-uuid".into());
    full.push(NAMED.into());
    assert!(
        opts::parse(&full).is_err(),
        "the M99 pair keeps its refusal"
    );
}

#[test]
fn random_uuid_refuses_on_the_relocatable_output() {
    // `-r` keeps its refusal: the object carries no LC_UUID command —
    // the surface's knob refusal mirrored exactly (the M99 shape).
    let (out, argv) = scratch("reloc");
    let mut full: Vec<OsString> = vec![
        "-r".into(),
        "-o".into(),
        out.with_extension("o")
            .to_string_lossy()
            .into_owned()
            .into(),
    ];
    full.extend(argv.iter().skip(2).cloned());
    full.push("-random_uuid".into());
    match opts::parse(&full) {
        Ok(_) => panic!("the relocatable output must refuse the random source"),
        Err(err) => {
            let rendered = format!("{:?}", miette::Report::new(err));
            assert!(
                rendered.contains("-random_uuid") && rendered.contains("LC_UUID"),
                "the refusal names the flag and the missing command: {rendered}"
            );
        }
    }
    let _ = std::fs::remove_file(&out);
}
