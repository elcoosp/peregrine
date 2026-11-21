//! M114 — the UUID source: `-random_uuid` — ld64's random-UUID face,
//! the typed `UuidSource` alphabet's second value. The decision rides
//! `LinkConfig::uuid_source`: `content` (the default — the content-
//! derived derivation from the page hashes, the reproducible face),
//! `random` (a fresh `UUIDv4` identity the emit draws at emit time), and
//! `none` (`-no_uuid` — the M32 suppression, no `LC_UUID` command at
//! all). The conflicts: `-random_uuid` × `-uuid` and × `-no_uuid`
//! refuse each other (two answers to the identity question), and `-r`
//! refuses (the object carries no `LC_UUID` command — the surface's
//! knob refusal mirrored exactly).
//!
//! Run: `cargo run -p pgr-driver --example random_uuid_link`
//! (`PGR_TRACING=1` installs a tracing subscriber).

use pgr_core::layout::{LinkConfig, OutputType, UuidSource};
use pgr_core::link::{LinkInput, link};
use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::ffi::OsString;

/// hello.o: `_main` (`ret; ret` in `__text`) — the corpus the uuid
/// faces shape.
fn corpus(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
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
    let path = dir.join("hello.o");
    std::fs::write(&path, b.build().expect("the fixture builds")).expect("hello.o writes");
    vec![path]
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

fn hex(uuid: &[u8; 16]) -> String {
    uuid.iter()
        .fold(String::with_capacity(32), |acc, b| format!("{acc}{b:02x}"))
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt().init();
    }
    let dir = std::env::temp_dir().join(format!("pgr_random_uuid_link_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("the scratch dir creates");
    let objs = corpus(&dir);
    let inputs: Vec<LinkInput> = objs
        .iter()
        .map(|p| LinkInput {
            name: p
                .file_name()
                .expect("the name rides")
                .to_string_lossy()
                .into_owned(),
            bytes: std::fs::read(p).expect("the object reads"),
        })
        .collect();

    // Face 1 — the library face: the content default derives (the
    // reproducible face); two emits of the same corpus derive the same
    // identity. The random face draws (fresh per emit).
    let plan_for = |source| {
        link(
            &inputs,
            &[],
            &LinkConfig {
                filetype: OutputType::Execute,
                uuid_source: source,
                ..LinkConfig::default()
            },
        )
        .expect("the link plans")
    };
    let content = plan_for(UuidSource::Content);
    let content_image =
        pgr_emit::build_image_fused(&content.layout, &content.objects).expect("the image emits");
    let content_again_image =
        pgr_emit::build_image_fused(&content.layout, &content.objects).expect("the image emits");
    let derived = uuid_of(&content_image).expect("the content image carries the command");
    assert_eq!(
        Some(derived),
        uuid_of(&content_again_image),
        "the content face derives the same identity across emits"
    );
    println!(
        "face 1 (content): derived {} (reproducible across emits)",
        hex(&derived)
    );

    let random = plan_for(UuidSource::Random);
    let random_image =
        pgr_emit::build_image_fused(&random.layout, &random.objects).expect("the image emits");
    let drawn = uuid_of(&random_image).expect("the random image carries the command");
    assert_ne!(drawn, derived, "the draw is its own identity");
    assert_ne!(
        drawn, [0u8; 16],
        "the draw never lands on the zero identity"
    );
    assert_eq!(drawn[6] >> 4, 4, "the version nibble names UUIDv4");
    assert_eq!(
        drawn[8] >> 6,
        0b10,
        "the variant bits name the RFC 4122 form"
    );
    println!("face 1 (random):  drew    {drawn:?} (fresh per emit, whole UUIDv4)");

    // Face 2 — the driver face: `-random_uuid` names the source; the
    // image writes and verifies strict. The suppressed face beside it
    // (`-no_uuid`) carries no LC_UUID command at all.
    let mut argv: Vec<OsString> = vec![
        "-o".into(),
        dir.join("app_random").to_string_lossy().into_owned().into(),
        "-random_uuid".into(),
    ];
    argv.extend(objs.iter().map(|p| p.to_string_lossy().into_owned().into()));
    let o = opts::parse(&argv).expect("the surface parses");
    let outcome = pgr_driver::run(&o).expect("the link runs");
    let image = std::fs::read(dir.join("app_random")).expect("the image reads");
    let strict = VerifyOptions::default();
    assert!(
        verify(&image, &strict).is_ok(&strict),
        "the random-carrying image verifies strict"
    );
    println!(
        "face 2 (-random_uuid): drew {} beside the outcome ({} bytes); verifies strict",
        hex(&uuid_of(&image).expect("the image carries the command")),
        outcome.file_size
    );

    let mut argv: Vec<OsString> = vec![
        "-o".into(),
        dir.join("app_none").to_string_lossy().into_owned().into(),
        "-no_uuid".into(),
    ];
    argv.extend(objs.iter().map(|p| p.to_string_lossy().into_owned().into()));
    let o = opts::parse(&argv).expect("the surface parses");
    pgr_driver::run(&o).expect("the suppressed link runs");
    let suppressed = std::fs::read(dir.join("app_none")).expect("the image reads");
    assert!(
        uuid_of(&suppressed).is_none(),
        "the suppressed image carries no LC_UUID command (the M32 shape)"
    );
    println!("face 2 (-no_uuid): the image carries no LC_UUID command at all");

    // Face 3 — the refusals: the identity pairs refuse each other, and
    // the relocatable output refuses the draw (the object carries no
    // LC_UUID command — the M99 shape mirrored exactly).
    for argv in [
        vec![
            "-random_uuid",
            "-uuid",
            "7d1e6f2a-93c4-4b8d-a1e2-3f4c5d6e7f80",
        ],
        vec!["-random_uuid", "-no_uuid"],
    ] {
        let mut full: Vec<OsString> = vec![
            "-o".into(),
            dir.join("refused").to_string_lossy().into_owned().into(),
        ];
        full.extend(argv.iter().map(OsString::from));
        full.extend(objs.iter().map(|p| p.to_string_lossy().into_owned().into()));
        match opts::parse(&full) {
            Ok(_) => panic!("the identity pair must refuse ({argv:?})"),
            Err(err) => println!("face 3: refused — {:?}", miette::Report::new(err)),
        }
    }
    let mut full: Vec<OsString> = vec![
        "-r".into(),
        "-o".into(),
        dir.join("o.o").to_string_lossy().into_owned().into(),
        "-random_uuid".into(),
    ];
    full.extend(objs.iter().map(|p| p.to_string_lossy().into_owned().into()));
    match opts::parse(&full) {
        Ok(_) => panic!("the relocatable output must refuse the draw"),
        Err(err) => println!("face 3 (-r): refused — {:?}", miette::Report::new(err)),
    }

    println!("\nrandom_uuid_link: ok");
}
