//! The named-UUID consumer example (M99): shipping an image with a
//! named identity — `-uuid <uuid>` — ld64's named-UUID face, the other
//! half of M32's `-no_uuid` (the named 16 bytes ride the `LC_UUID`
//! field the emit two-pass patch already writes, replacing the
//! content-derived derivation — the identity is the name, not the
//! content). The 8-4-4-4-12 hex form validates at the parse (36 chars,
//! hyphens at 8/13/18/23, case-insensitive — malformed refuses with the
//! fix); `-no_uuid` × `-uuid` refuse each other; `-r` refuses (the
//! object carries no `LC_UUID`). The image verifies strict — the
//! verifier's UUID contract stays structural (a named value is the
//! config's own choice, never a defect).
//!
//! Run: `cargo run -p pgr-driver --example named_uuid_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// The example's named identity (lowercase and the same value in
/// uppercase — hex is case-insensitive).
const NAMED: &str = "7d1e6f2a-93c4-4b8d-a1e2-3f4c5d6e7f80";
const NAMED_UPPER: &str = "7D1E6F2A-93C4-4B8D-A1E2-3F4C5D6E7F80";

/// lib.o: `_api` (the exported surface) — one `ret` body whose second
/// byte carries the tag (two corpora = two contents).
fn lib_object(tag: u8) -> Vec<u8> {
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
    b.build().expect("the fixture object builds")
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

/// Links a dylib from a tagged corpus with the named extra flags.
fn link_dylib(tag: u8, extra: &[&str], out: &str) -> Vec<u8> {
    let dir = std::env::temp_dir().join(format!("pgr_named_uuid_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let lib = dir.join(format!("lib-{tag}.o"));
    std::fs::write(&lib, lib_object(tag)).unwrap();
    let out_path = dir.join(out);
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        std::ffi::OsString::from(out_path.to_str().unwrap()),
        std::ffi::OsString::from(lib.to_str().unwrap()),
        std::ffi::OsString::from("-dylib"),
        std::ffi::OsString::from("-install_name"),
        std::ffi::OsString::from("@rpath/lib.dylib"),
    ];
    for a in extra {
        argv.push(std::ffi::OsString::from(*a));
    }
    let o = opts::parse(&argv).expect("the dylib argv parses");
    pgr_driver::run(&o).expect("the dylib link runs");
    std::fs::read(&out_path).expect("the image reads")
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    // The default: the derivation is content-derived.
    let plain = link_dylib(0xA0, &[], "plain.dylib");
    assert!(strict_ok(&plain), "the default image verifies strict");
    let derived = uuid_of(&plain).expect("the default plans the LC_UUID command");
    println!(
        "default: {} bytes — LC_UUID derived from content",
        plain.len()
    );

    // The named value: the identity is the name — two different corpora
    // under the same named value ride the same bytes.
    let a = link_dylib(0xA0, &["-uuid", NAMED], "a.dylib");
    let b = link_dylib(0xBB, &["-uuid", NAMED], "b.dylib");
    assert!(strict_ok(&a), "the named image verifies strict");
    let expected: [u8; 16] = [
        0x7d, 0x1e, 0x6f, 0x2a, 0x93, 0xc4, 0x4b, 0x8d, 0xa1, 0xe2, 0x3f, 0x4c, 0x5d, 0x6e, 0x7f,
        0x80,
    ];
    assert_eq!(uuid_of(&a), Some(expected), "LC_UUID carries the name");
    assert_eq!(
        uuid_of(&a),
        uuid_of(&b),
        "the named identity is content-independent"
    );
    assert_ne!(
        uuid_of(&a),
        Some(derived),
        "the name replaced the derivation"
    );
    println!(
        "named:   {} bytes — LC_UUID {NAMED} (the name, not the content)",
        a.len()
    );

    // Case-insensitivity: the uppercase form parses to the same bytes.
    let upper = link_dylib(0xA0, &["-uuid", NAMED_UPPER], "upper.dylib");
    assert_eq!(uuid_of(&upper), Some(expected), "hex is case-insensitive");
    println!("upper:   the uppercase form rides the same bytes");

    // The refusals: the grammar, the `-no_uuid` pair, the relocatable
    // output.
    let dir = std::env::temp_dir().join(format!("pgr_named_uuid_{}", std::process::id()));
    let lib = dir.join("lib-0xA0.o");
    for (kind, tail) in [
        (
            "malformed",
            vec!["-dylib", "-uuid", "7d1e6f2a-93c4-4b8d-a1e2-3f4c5d6e7fg0"],
        ),
        (
            "suppressed+named",
            vec!["-dylib", "-no_uuid", "-uuid", NAMED],
        ),
        ("relocatable", vec!["-r", "-uuid", NAMED]),
    ] {
        let mut argv: Vec<std::ffi::OsString> = vec![
            std::ffi::OsString::from("-o"),
            std::ffi::OsString::from(dir.join("x").to_str().unwrap()),
            std::ffi::OsString::from(lib.to_str().unwrap()),
        ];
        for a in tail {
            argv.push(std::ffi::OsString::from(a));
        }
        let err = opts::parse(&argv).expect_err("the refused argv refuses");
        println!("{kind}: refuses — {err}");
    }
    println!(
        "\nLC_UUID is the image's identity; the named form is the config's own choice; \
         try PGR_TRACING=1 to watch the pipeline"
    );
}
