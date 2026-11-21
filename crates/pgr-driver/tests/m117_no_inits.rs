//! M117 — the `-no_inits` driver surface: the flag parses onto the
//! config decision, the relocatable output refuses it (the object's
//! sections are the input's, verbatim), and the end-to-end gate: the
//! suppressed image carries no `__mod_init_func`/`__mod_term_func`
//! section and no `LC_ROUTINES_64` command (the dylib's `-init`/`-term`
//! surface drops with them) and verifies strict; the default keeps the
//! sections. The spawn gates run the real binary.

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_format::consts::{S_MOD_INIT_FUNC_POINTERS, S_MOD_TERM_FUNC_POINTERS};
use pgr_format::{LoadCommandIter, MachHeader64};
use pgr_verify::{Options as VerifyOptions, verify};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m117_no_inits").join(format!(
        "{tag}_{}_{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn args(items: &[&str]) -> Vec<OsString> {
    items.iter().map(OsString::from).collect()
}

/// `main.o`: `_main` plus initializer/terminator bodies, each targeted
/// by one 8-byte pointer in its `__mod_init_func`/`__mod_term_func`
/// section — the machinery the decision drops.
fn corpus(dir: &Path, name: &str) -> PathBuf {
    let mut b = ObjectBuilder::new(name);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(4),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let init_ptr = b.add_symbol(ObjectSymbol::Defined {
        name: "_init_ptr".into(),
        section_index: text,
        value: 4,
        weak: false,
    });
    let term_ptr = b.add_symbol(ObjectSymbol::Defined {
        name: "_term_ptr".into(),
        section_index: text,
        value: 8,
        weak: false,
    });
    let modinit = b.add_section(ObjectSection::data(
        "__mod_init_func",
        vec![0u8; 8],
        vec![ObjectReloc::unsigned(init_ptr as u32).at(0)],
    ));
    b.section_mut(modinit).flags = S_MOD_INIT_FUNC_POINTERS;
    let modterm = b.add_section(ObjectSection::data(
        "__mod_term_func",
        vec![0u8; 8],
        vec![ObjectReloc::unsigned(term_ptr as u32).at(0)],
    ));
    b.section_mut(modterm).flags = S_MOD_TERM_FUNC_POINTERS;
    let path = dir.join(name);
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    path
}

/// The output section names the image's segment commands carry (the
/// raw load-command walk — the layout's own source).
fn image_sections(image: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let Ok(hdr) = MachHeader64::parse(image) else {
        return names;
    };
    let Ok(mut it) = LoadCommandIter::new(image, MachHeader64::SIZE, hdr.ncmds, hdr.sizeofcmds)
    else {
        return names;
    };
    while let Ok(Some(cmd)) = it.next_command() {
        if cmd.kind != pgr_format::LoadCommandKind::Segment64 || cmd.bytes.len() < 72 {
            continue;
        }
        let nsects = u32::from_le_bytes(cmd.bytes[64..68].try_into().unwrap_or([0; 4]));
        for i in 0..nsects as usize {
            let base = 72 + i * 80;
            if base + 80 > cmd.bytes.len() {
                break;
            }
            let seg = String::from_utf8_lossy(&cmd.bytes[base + 32..base + 48]);
            let name = String::from_utf8_lossy(&cmd.bytes[base..base + 16]);
            names.push(format!(
                "{},{}",
                seg.trim_end_matches('\0'),
                name.trim_end_matches('\0')
            ));
        }
    }
    names
}

/// The `LC_ROUTINES_64` count the image's header carries.
fn routines_count(image: &[u8]) -> usize {
    let Ok(hdr) = MachHeader64::parse(image) else {
        return 0;
    };
    let Ok(mut it) = LoadCommandIter::new(image, MachHeader64::SIZE, hdr.ncmds, hdr.sizeofcmds)
    else {
        return 0;
    };
    let mut count = 0;
    while let Ok(Some(cmd)) = it.next_command() {
        if matches!(cmd.kind, pgr_format::LoadCommandKind::Routines) {
            count += 1;
        }
    }
    count
}

fn strict() -> VerifyOptions {
    VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// Runs the real `pgr` binary: `(exit code, stderr)`.
fn spawn_pgr(argv: &[&str]) -> (Option<i32>, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_pgr"))
        .args(argv)
        .output()
        .expect("the pgr binary spawns");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn the_flag_names_the_decision() {
    let dir = scratch("parse");
    let obj = corpus(&dir, "main.o");
    let obj = obj.display().to_string();
    let o = opts::parse(&args(&["-o", "out", &obj])).expect("the plain argv parses");
    assert!(
        !o.config.no_inits,
        "the default keeps the init/term machinery (every pre-knob link byte-identical)"
    );
    let o = opts::parse(&args(&["-no_inits", "-o", "out", &obj])).expect("the flag parses");
    assert!(o.config.no_inits, "the flag names the suppression");
}

#[test]
fn the_suppressed_image_drops_the_sections_and_verifies_strict() {
    let dir = scratch("e2e");
    let obj = corpus(&dir, "main.o");
    let out = dir.join("app").display().to_string();
    let obj = obj.display().to_string();
    let (code, stderr) = spawn_pgr(&["-o", &out, "-no_inits", &obj]);
    assert_eq!(code, Some(0), "the suppressed link exits 0: {stderr}");
    let image = std::fs::read(&out).expect("the image writes");
    let names = image_sections(&image);
    assert!(
        !names.iter().any(|n| n.contains("__mod_init_func"))
            && !names.iter().any(|n| n.contains("__mod_term_func")),
        "the suppressed image carries no init/term sections: {names:?}"
    );
    assert!(
        names.iter().any(|n| n.contains("__text")),
        "the rest of the image still places: {names:?}"
    );
    assert!(
        verify(&image, &strict()).is_ok(&strict()),
        "the init-free image verifies strict"
    );
}

#[test]
fn the_default_image_keeps_the_sections() {
    let dir = scratch("default");
    let obj = corpus(&dir, "main.o");
    let out = dir.join("app").display().to_string();
    let obj = obj.display().to_string();
    let (code, _) = spawn_pgr(&["-o", &out, &obj]);
    assert_eq!(code, Some(0), "the default link exits 0");
    let image = std::fs::read(&out).expect("the image writes");
    let names = image_sections(&image);
    assert!(
        names.iter().any(|n| n.contains("__mod_init_func")),
        "the default image keeps the initializer pointers: {names:?}"
    );
    assert!(
        names.iter().any(|n| n.contains("__mod_term_func")),
        "the default image keeps the terminator pointers: {names:?}"
    );
}

#[test]
fn no_inits_drops_lc_routines_from_the_dylib() {
    // The M48/M98 command rides only while init machinery remains:
    // beside `-no_inits` the dylib's `-init`/`-term` surface drops from
    // the header.
    let dir = scratch("dylib");
    let obj = corpus(&dir, "main.o");
    let carried = dir.join("carried.dylib").display().to_string();
    let suppressed = dir.join("free.dylib").display().to_string();
    let obj = obj.display().to_string();
    let (code, stderr) = spawn_pgr(&[
        "-dylib",
        "-install_name",
        "@rpath/lib.dylib",
        "-init",
        "_init_ptr",
        "-term",
        "_term_ptr",
        "-o",
        &carried,
        &obj,
    ]);
    assert_eq!(code, Some(0), "the carrying dylib links: {stderr}");
    let image = std::fs::read(&carried).expect("the image reads");
    assert_eq!(
        routines_count(&image),
        1,
        "the default dylib carries LC_ROUTINES_64"
    );
    let (code, stderr) = spawn_pgr(&[
        "-dylib",
        "-install_name",
        "@rpath/lib.dylib",
        "-init",
        "_init_ptr",
        "-term",
        "_term_ptr",
        "-no_inits",
        "-o",
        &suppressed,
        &obj,
    ]);
    assert_eq!(code, Some(0), "the suppressed dylib links: {stderr}");
    let image = std::fs::read(&suppressed).expect("the image reads");
    assert_eq!(
        routines_count(&image),
        0,
        "-no_inits drops the command from the header"
    );
}

#[test]
fn no_inits_refuses_on_the_relocatable_output() {
    let dir = scratch("reloc");
    let obj = corpus(&dir, "main.o");
    let out = dir.join("out.o").display().to_string();
    let obj = obj.display().to_string();
    let err = opts::parse(&args(&["-r", "-o", &out, &obj, "-no_inits"]))
        .expect_err("the relocatable output refuses the knob");
    let rendered = err.to_string();
    assert!(
        rendered.contains("-no_inits") && rendered.contains("verbatim"),
        "the refusal names the flag and the verbatim contract: {rendered}"
    );
}
