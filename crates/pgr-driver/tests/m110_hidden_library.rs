//! M110 — the hidden-dylib surface (`-hidden_library`/`-hidden_framework`
//! /`-hidden-l`): the driver scans the dylib through the same search
//! paths as `-weak_library`/`-lazy_library`, hands Pass 2 the exports,
//! and the header assembly drops the load command. A weak reference to
//! a hidden export rides dyld's flat lookup; a strong one refuses the
//! link with the fix. `-r` refuses the knob at the parse; the library
//! re-check backs it.

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::path::Path;

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "pgr_m110_{tag}_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the clock ticks")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("the scratch dir creates");
    dir
}

/// An object calling `_greet` through a `__data` pointer (strong) and
/// `_greet_weak` through a weak symtab row (no reloc — the weak ride's
/// symtab lane).
fn hello_o(dir: &Path, strong: bool) -> String {
    let mut b = ObjectBuilder::new("hello.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0u8, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    let undef = b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: !strong,
    });
    let slot = b.sym_index(undef);
    if strong {
        b.section_mut(data)
            .relocs
            .push(ObjectReloc::unsigned(slot).at(0));
    }
    let bytes = b.build().expect("the fixture object builds");
    let path = dir.join("hello.o");
    std::fs::write(&path, &bytes).expect("the object writes");
    path.to_string_lossy().into_owned()
}

fn lib_tbd(dir: &Path, name: &str, symbol: &str) -> String {
    let path = dir.join(format!("lib{name}.tbd"));
    std::fs::write(
        &path,
        format!(
            "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name:              @rpath/lib{name}.tbd\ncurrent-version: 1.0.0\ncompatibility-version: 1.0.0\n             exports:\n  - targets: [ arm64-macos ]\n    symbols: [ {symbol} ]\n...\n"
        ),
    )
    .expect("the stub writes");
    path.to_string_lossy().into_owned()
}

fn framework(dir: &Path, name: &str, symbol: &str) -> String {
    let fw = dir.join(format!("{name}.framework"));
    std::fs::create_dir_all(&fw).expect("the framework dir creates");
    let path = fw.join(name);
    std::fs::write(
        &path,
        format!(
            "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: \
             @rpath/{name}.framework/{name}\ncurrent-version: 1.0.0\ncompatibility-version: \
             1.0.0\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ {symbol} ]\n...\n"
        ),
    )
    .expect("the stub writes");
    path.to_string_lossy().into_owned()
}

/// The header's dylib commands: `(opcode, install name)` in command order.
fn dylib_commands(image: &[u8]) -> Vec<(u32, String)> {
    let header = pgr_format::MachHeader64::parse(image).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands walk");
    let mut out = Vec::new();
    while let Ok(Some(cmd)) = it.next_command() {
        if matches!(
            cmd.kind,
            pgr_format::LoadCommandKind::LoadDylib | pgr_format::LoadCommandKind::ReexportDylib
        ) {
            let name = pgr_format::DylibCommand::parse(cmd.bytes)
                .ok()
                .and_then(|c| c.name(cmd.bytes).ok())
                .map(|n| {
                    String::from_utf8_lossy(n)
                        .trim_end_matches('\0')
                        .to_string()
                });
            if let Some(name) = name {
                let opcode = u32::from_le_bytes(cmd.bytes[0..4].try_into().expect("the opcode"));
                out.push((opcode, name));
            }
        }
    }
    out
}

fn link(dir: &Path, out: &str, extra: &[&str], obj: &str) -> Vec<u8> {
    let mut argv: Vec<OsString> = vec![
        "-o".into(),
        dir.join(out).to_string_lossy().into_owned().into(),
    ];
    for a in extra {
        argv.push((*a).into());
    }
    argv.push(obj.into());
    let o = opts::parse(&argv).expect("the surface parses");
    pgr_driver::run(&o).expect("the link runs");
    std::fs::read(dir.join(out)).expect("the image reads")
}

use std::ffi::OsString;

#[test]
fn the_hidden_library_rides_no_load_command_and_the_weak_bind_rides_flat() {
    let dir = scratch("hidden_weak");
    let obj = hello_o(&dir, false);
    let _stub = lib_tbd(&dir, "greet", "_greet");
    let image = link(
        &dir,
        "hello",
        &[
            "-hidden_library",
            &dir.join("libgreet.tbd").to_string_lossy(),
        ],
        &obj,
    );
    let cmds = dylib_commands(&image);
    assert!(
        cmds.is_empty(),
        "the hidden dylib rides no load command: {cmds:?}"
    );
    let strict = pgr_verify::Options::default();
    let report = pgr_verify::verify(&image, &strict);
    assert!(report.is_ok(&strict), "the image verifies strict");
}

#[test]
fn a_strong_reference_to_a_hidden_export_refuses_with_the_fix() {
    let dir = scratch("hidden_strong");
    let obj = hello_o(&dir, true);
    let _stub = lib_tbd(&dir, "greet", "_greet");
    let argv: Vec<OsString> = vec![
        "-o".into(),
        dir.join("hello").to_string_lossy().into_owned().into(),
        "-hidden_library".into(),
        dir.join("libgreet.tbd")
            .to_string_lossy()
            .into_owned()
            .into(),
        obj.into(),
    ];
    let o = opts::parse(&argv).expect("the surface parses");
    let err = pgr_driver::run(&o).expect_err("the strong bind refuses");
    let msg = err.to_string();
    assert!(
        msg.contains("hidden dylib") && msg.contains("@rpath/libgreet.tbd"),
        "the refusal names the lane and the provider: {msg}"
    );
}

#[test]
fn the_hidden_framework_and_hidden_l_forms_ride_the_search() {
    let dir = scratch("hidden_forms");
    let obj = hello_o(&dir, false);
    let _fw = framework(&dir, "Greet", "_greet");
    let image = link(
        &dir,
        "hello",
        &["-hidden_framework", "Greet", "-F", &dir.to_string_lossy()],
        &obj,
    );
    assert!(
        dylib_commands(&image).is_empty(),
        "the hidden framework rides no command"
    );
    let _stub = lib_tbd(&dir, "greet", "_greet");
    let image = link(
        &dir,
        "hello2",
        &["-hidden-lgreet", "-L", &dir.to_string_lossy()],
        &obj,
    );
    assert!(
        dylib_commands(&image).is_empty(),
        "the attached -hidden-l form rides no command"
    );
}

#[test]
fn the_relocatable_output_refuses_the_hidden_flags() {
    let dir = scratch("hidden_reloc");
    let obj = hello_o(&dir, false);
    let _stub = lib_tbd(&dir, "greet", "_greet");
    for flag in [
        "-hidden_library",
        "-hidden_framework",
        "-hidden-l",
        "-hidden-lgreet",
    ] {
        let mut argv: Vec<OsString> = vec!["-r".into(), "-o".into(), "o.o".into(), flag.into()];
        match flag {
            "-hidden_library" => {
                argv.push(
                    dir.join("libgreet.tbd")
                        .to_string_lossy()
                        .into_owned()
                        .into(),
                );
            }
            "-hidden_framework" | "-hidden-l" => {
                argv.push("greet".into());
            }
            _ => {}
        }
        argv.push(obj.clone().into());
        let err = opts::parse(&argv).expect_err("the relocatable output refuses the mark");
        assert!(
            err.to_string().contains("-hidden"),
            "the refusal names the knob ({flag}): {err}"
        );
    }
}
