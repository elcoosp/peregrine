//! The lazy-dylib consumer example (M14 rung 2): shipping an image
//! against a delay-loaded library — `-lazy_library` names the `.tbd`,
//! the image carries `LC_LAZY_LOAD_DYLIB` for it (dyld's delay-load
//! surface; under chained fixups the command rides the two-level
//! ordinal space exactly like a plain load, so the binds and the pair
//! contract are unchanged), and the output verifies strict. The image's
//! dylib commands are read back kind-by-kind — the surface a build
//! system audits after the link.
//!
//! Run: `cargo run -p pgr-driver --example lazy_library_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// hello.o: `_main` BLs `_greet` and returns — one external bind into
/// the lazy library.
fn hello_object() -> Vec<u8> {
    let text: Vec<u8> = [
        0x9400_0000u32, // bl _greet
        0x5280_0000u32, // mov w0, #0
        0xD65F_03C0u32, // ret
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect();
    let mut b = ObjectBuilder::new("hello.o");
    let sect = b.add_section(ObjectSection::text("__text", text, Vec::new()));
    let greet = b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    b.section_mut(sect)
        .relocs
        .push(ObjectReloc::branch26(u32::try_from(greet).unwrap()).at(0));
    b.build().expect("the fixture object builds")
}

/// A greet `.tbd` (v4) exporting `_greet` — the same stub the driver
/// accepts for a plain load.
fn greet_tbd() -> &'static str {
    "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: @rpath/libgreet.dylib\ncurrent-version: 1.0.0\ncompatibility-version: 1.0.0\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ _greet ]\n...\n"
}

/// The image's dylib load commands: `(opcode, install name)` — the
/// family decodes as `LoadDylib`/`ReexportDylib` kinds, the opcode byte
/// tells weak (`0x18|REQ`) from lazy (`0x20`) from plain (`0xc`).
fn dylib_commands(image: &[u8]) -> Vec<(u32, String)> {
    let hdr = pgr_format::MachHeader64::parse(image).expect("the image parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands parse");
    let mut out = Vec::new();
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if cmd.kind == pgr_format::LoadCommandKind::LoadDylib
            || cmd.kind == pgr_format::LoadCommandKind::ReexportDylib
        {
            let d = pgr_format::DylibCommand::parse(cmd.bytes).expect("the command parses");
            let name = d.name(cmd.bytes).expect("the name is in range");
            let opcode = u32::from_le_bytes(cmd.bytes[0..4].try_into().unwrap());
            out.push((
                opcode,
                String::from_utf8_lossy(name)
                    .trim_end_matches('\0')
                    .to_string(),
            ));
        }
    }
    out
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    let dir = std::env::temp_dir().join(format!("pgr_lazy_link_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let obj = dir.join("hello.o");
    let tbd = dir.join("libgreet.tbd");
    std::fs::write(&obj, hello_object()).unwrap();
    std::fs::write(&tbd, greet_tbd()).unwrap();

    // The link: `-lazy_library` instead of the path-as-input form — the
    // same search surface, the lazy load-command kind.
    let out = dir.join("hello");
    let argv: Vec<std::ffi::OsString> = [
        "-o".as_ref(),
        out.as_os_str(),
        obj.as_os_str(),
        "-lazy_library".as_ref(),
        tbd.as_os_str(),
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let o = opts::parse(&argv).expect("the lazy argv parses");
    pgr_driver::run(&o).expect("the lazy link runs");

    // Read the surface back: the lazy command carries the install name;
    // the image verifies strict (the bind into the lazy library rides
    // the ordinary two-level ordinal space — the verifier's walk just
    // enforced it).
    let image = std::fs::read(&out).expect("the image reads");
    let report = verify(
        &image,
        &VerifyOptions {
            strict_warnings: true,
            skip_hash_recompute: false,
        },
    );
    assert!(
        report.is_ok(&VerifyOptions {
            strict_warnings: true,
            skip_hash_recompute: false,
        }),
        "the lazy image verifies strict: {:#?}",
        report.issues
    );
    println!("dylib load commands:");
    for (opcode, name) in dylib_commands(&image) {
        let kind = match opcode {
            pgr_format::consts::LC_LOAD_DYLIB => "LC_LOAD_DYLIB",
            pgr_format::consts::LC_LOAD_WEAK_DYLIB => "LC_LOAD_WEAK_DYLIB",
            pgr_format::consts::LC_LAZY_LOAD_DYLIB => "LC_LAZY_LOAD_DYLIB",
            pgr_format::consts::LC_REEXPORT_DYLIB => "LC_REEXPORT_DYLIB",
            _ => "other",
        };
        println!("  {kind:<22} {name}");
    }
    println!(
        "\nimage: {} (lazy-linked, strict-verified; try PGR_TRACING=1 to watch the pipeline)",
        out.display()
    );
}
