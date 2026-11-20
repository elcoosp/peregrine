//! M99 — the named output UUID on the driver surface: `-uuid <uuid>` —
//! ld64's named-UUID face, the other half of M32's `-no_uuid`. The
//! 8-4-4-4-12 hex form validates at the parse (36 chars, hyphens at
//! 8/13/18/23, case-insensitive hex — malformed refuses with the fix);
//! `-no_uuid` × `-uuid` refuse each other (two answers to one question,
//! order-independent); `-r` refuses (the relocatable output carries no
//! `LC_UUID`); the named value replaces the content-derived derivation
//! in the emit two-pass patch (the identity is the name, not the
//! content); the image verifies strict — the verifier's UUID contract
//! stays structural (a named value is the config's own choice, never a
//! defect).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// A unique scratch dir per test (the house pattern: no tempfile dep).
fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m99_uuid").join(format!(
        "{tag}_{}_{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The canonical example value (lowercase) and its raw bytes.
const NAMED_LOWER: &str = "7d1e6f2a-93c4-4b8d-a1e2-3f4c5d6e7f80";
/// The same value uppercase — hex is case-insensitive.
const NAMED_UPPER: &str = "7D1E6F2A-93C4-4B8D-A1E2-3F4C5D6E7F80";
const NAMED_BYTES: [u8; 16] = [
    0x7d, 0x1e, 0x6f, 0x2a, 0x93, 0xc4, 0x4b, 0x8d, 0xa1, 0xe2, 0x3f, 0x4c, 0x5d, 0x6e, 0x7f, 0x80,
];

/// lib.o: `_api` (the exported surface) — one `ret` body whose second
/// byte carries the tag (two corpora = two contents).
fn lib_o(dir: &Path, tag: u8) -> PathBuf {
    let mut b = ObjectBuilder::new("lib.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6, tag], // ret; <tag>
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_api".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let path = dir.join(format!("lib-{tag}.o"));
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    path
}

/// The image's `LC_UUID` payload when the command rides.
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

fn link_dylib(dir: &Path, tag: u8, extra: &[&str], out: &str) -> Vec<u8> {
    let lib = lib_o(dir, tag);
    let out_path = dir.join(out);
    let mut argv = vec![
        OsString::from("-o"),
        OsString::from(out_path.to_str().unwrap()),
        OsString::from(lib.to_str().unwrap()),
        OsString::from("-dylib"),
        OsString::from("-install_name"),
        OsString::from("@rpath/lib.dylib"),
    ];
    for a in extra {
        argv.push(OsString::from(*a));
    }
    let o = opts::parse(&argv).expect("the dylib argv parses");
    pgr_driver::run(&o).expect("the dylib link runs");
    std::fs::read(&out_path).expect("the image reads")
}

#[test]
fn a_named_uuid_rides_the_output_and_verifies_strict() {
    let dir = scratch("named");
    let image = link_dylib(&dir, 0xA0, &["-uuid", NAMED_LOWER], "named.dylib");
    assert!(strict_ok(&image), "the named image verifies strict");
    assert_eq!(
        uuid_of(&image),
        Some(NAMED_BYTES),
        "LC_UUID carries the named value verbatim"
    );
}

#[test]
fn the_named_value_replaces_the_content_derivation() {
    // The identity is the name, not the content: two different corpora
    // linked under the same named value ride the same LC_UUID bytes
    // (the content-derived derivation would differ), and the default
    // link's derived value differs from the named one.
    let dir = scratch("identity");
    let a = link_dylib(&dir, 0xA0, &["-uuid", NAMED_LOWER], "a.dylib");
    let b = link_dylib(&dir, 0xBB, &["-uuid", NAMED_LOWER], "b.dylib");
    assert_eq!(
        uuid_of(&a),
        uuid_of(&b),
        "the named identity is content-independent"
    );
    let plain = link_dylib(&dir, 0xA0, &[], "plain.dylib");
    let derived = uuid_of(&plain).expect("the default plans the LC_UUID command");
    assert_ne!(
        Some(derived),
        Some(NAMED_BYTES),
        "the derived value is not the named value"
    );
}

#[test]
fn the_grammar_validates_the_named_form() {
    // The 8-4-4-4-12 hex form: 36 chars, hyphens at 8/13/18/23,
    // case-insensitive hex. Malformed refuses with the fix; uppercase
    // hex links the same bytes.
    let dir = scratch("grammar");
    for (bad, note) in [
        ("7d1e6f2a-93c4-4b8d-a1e2-3f4c5d6e7f8", "35 chars"),
        ("7d1e6f2a-93c4-4b8d-a1e2-3f4c5d6e7f800", "37 chars"),
        ("7d1e6f2a93c4-4b8d-a1e2-3f4c5d6e7f80", "hyphens drifted"),
        ("7d1e6f2a-93c4-4b8d-a1e2-3f4c5d6e7fg0", "non-hex digit"),
        ("7d1e6f2a93c44b8da1e23f4c5d6e7f80", "no hyphens"),
        ("", "empty"),
    ] {
        let argv: Vec<OsString> = [
            "-o",
            dir.join("x.dylib").to_str().unwrap(),
            lib_o(&dir, 0xA0).to_str().unwrap(),
            "-dylib",
            "-install_name",
            "@rpath/lib.dylib",
            "-uuid",
            bad,
        ]
        .iter()
        .map(OsString::from)
        .collect();
        let err = opts::parse(&argv).expect_err("the malformed value refuses");
        let message = err.to_string();
        assert!(
            message.contains("-uuid"),
            "the {note} refusal names the flag: {message}"
        );
    }
    // Case-insensitivity: the uppercase form rides the same bytes.
    let upper = link_dylib(&dir, 0xA0, &["-uuid", NAMED_UPPER], "upper.dylib");
    assert_eq!(
        uuid_of(&upper),
        Some(NAMED_BYTES),
        "the uppercase form parses to the same bytes"
    );
}

#[test]
fn no_uuid_and_uuid_refuse_each_other() {
    // Two answers to one question — the refusal is order-independent
    // and names both flags.
    let dir = scratch("conflict");
    let lib = lib_o(&dir, 0xA0);
    for argv in [
        vec!["-no_uuid", "-uuid", NAMED_LOWER],
        vec!["-uuid", NAMED_LOWER, "-no_uuid"],
    ] {
        let mut full: Vec<OsString> = vec![
            OsString::from("-o"),
            OsString::from(dir.join("x.dylib").to_str().unwrap()),
            OsString::from(lib.to_str().unwrap()),
            OsString::from("-dylib"),
            OsString::from("-install_name"),
            OsString::from("@rpath/lib.dylib"),
        ];
        for a in &argv {
            full.push(OsString::from(*a));
        }
        let err = opts::parse(&full).expect_err("the pair refuses");
        let message = err.to_string();
        assert!(
            message.contains("-no_uuid") && message.contains("-uuid"),
            "the refusal names both flags: {message}"
        );
    }
}

#[test]
fn uuid_refuses_on_the_relocatable_output() {
    // The relocatable output carries no LC_UUID at all — a named value
    // has no field to land on (the M32 shape: the object's header has
    // no uuid command).
    let dir = scratch("reloc");
    let lib = lib_o(&dir, 0xA0);
    let argv: Vec<OsString> = [
        "-o",
        dir.join("reloc.o").to_str().unwrap(),
        lib.to_str().unwrap(),
        "-r",
        "-uuid",
        NAMED_LOWER,
    ]
    .iter()
    .map(OsString::from)
    .collect();
    let err = opts::parse(&argv).expect_err("the relocatable argv refuses");
    let message = err.to_string();
    assert!(
        message.contains("-uuid"),
        "the relocatable refusal names the knob: {message}"
    );
}
