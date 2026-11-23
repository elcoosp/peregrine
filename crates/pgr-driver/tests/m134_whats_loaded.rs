//! M134 — the loaded-object inventory face (`-whatsloaded`): ld64's flag
//! ("Print the names of all object files loaded") — the driver's
//! inventory face over the objects Pass 1 actually loaded (the explicit
//! objects beside the archive members the S7 pull admitted). The default
//! prints nothing; the named decision prints one name per loaded object,
//! the link unchanged (the bytes never move — the face is a
//! measurement). The face composes with every output kind (an `-r`
//! object's inventory is its own inputs) and with `-w` (the suppression
//! is the advisory faces' decision, never the inventory's). The spawn
//! gates run the real binary (the face is stderr — the driver library
//! cannot assert its own stderr).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir()
        .join("pgr_m134_whats_loaded")
        .join(format!(
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

/// hello.o: one defined symbol, one section, no undefineds — the
/// inventory's row (the symbol is unique per object: a second `_main`
/// would refuse the link, the M108 default).
fn hello_object(dir: &Path, name: &str, symbol: &str) -> PathBuf {
    let mut b = ObjectBuilder::new(name);
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: symbol.into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let path = dir.join(name);
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    path
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
fn the_flag_parses() {
    let dir = scratch("parse");
    let obj = hello_object(&dir, "hello.o", "_main");
    let obj = obj.display().to_string();
    let o = opts::parse(&args(&["-o", "out", "-whatsloaded", &obj])).expect("the inventory parses");
    assert!(o.config.whats_loaded, "the inventory rides the config");
    // The flag is idempotent (ld64's `-whatsloaded` carries no mirror):
    // a second occurrence is the same decision.
    let o = opts::parse(&args(&["-o", "out", "-whatsloaded", "-whatsloaded", &obj]))
        .expect("the repeated flag parses");
    assert!(o.config.whats_loaded, "the repeated flag is idempotent");
}

#[test]
fn the_default_prints_no_inventory() {
    let dir = scratch("default");
    let obj = hello_object(&dir, "hello.o", "_main");
    let out = dir.join("app").display().to_string();
    let obj_str = obj.display().to_string();
    let (code, stderr) = spawn_pgr(&["-o", &out, &obj_str]);
    assert_eq!(code, Some(0), "the default link exits 0");
    assert!(
        !stderr.contains("hello.o"),
        "the default prints no inventory: {stderr}"
    );
}

#[test]
fn whatsloaded_prints_the_loaded_objects() {
    let dir = scratch("inventory");
    let a = hello_object(&dir, "a.o", "_main");
    let b = hello_object(&dir, "b.o", "_b_entry");
    let out = dir.join("app").display().to_string();
    let (a, b) = (a.display().to_string(), b.display().to_string());
    let (code, stderr) = spawn_pgr(&["-o", &out, "-whatsloaded", &a, &b]);
    assert_eq!(code, Some(0), "the inventory face is a measurement");
    assert!(
        stderr.contains("a.o") && stderr.contains("b.o"),
        "both loaded objects print: {stderr}"
    );
    assert!(Path::new(&out).exists(), "the image ships");
    // The image is byte-identical to the un-named decision's (the face
    // never moves the bytes): the same link without the flag produces
    // the same image.
    let plain = dir.join("plain");
    let (code, _) = spawn_pgr(&["-o", &plain.display().to_string(), &a, &b]);
    assert_eq!(code, Some(0));
    assert_eq!(
        std::fs::read(&out).expect("the inventory image reads"),
        std::fs::read(&plain).expect("the plain image reads"),
        "the face never moves the bytes"
    );
}

#[test]
fn whatsloaded_rides_the_relocatable_output() {
    // The inventory applies to every output kind: an `-r` object's
    // loaded list is its own inputs (ld64's face accepts the flag on
    // every link).
    let dir = scratch("reloc");
    let obj = hello_object(&dir, "hello.o", "_main");
    let out = dir.join("out.o").display().to_string();
    let obj_str = obj.display().to_string();
    let (code, stderr) = spawn_pgr(&["-o", &out, "-r", "-whatsloaded", &obj_str]);
    assert_eq!(code, Some(0), "the relocatable output carries the face");
    assert!(
        stderr.contains("hello.o"),
        "the object's inventory prints: {stderr}"
    );
}

#[test]
fn whatsloaded_composes_with_w() {
    // The suppression is the advisory faces' decision, never the
    // inventory's: `-w -whatsloaded` silences the warnings and keeps the
    // inventory.
    let dir = scratch("compose");
    let mut b = ObjectBuilder::new("hole.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let undef = b.add_symbol(ObjectSymbol::Undefined {
        name: "_hole".into(),
        weak_ref: false,
    });
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    let slot = b.sym_index(undef);
    b.section_mut(data)
        .relocs
        .push(ObjectReloc::unsigned(slot).at(0));
    let obj = dir.join("hole.o");
    std::fs::write(&obj, b.build().expect("the fixture object builds")).unwrap();
    let out = dir.join("app").display().to_string();
    let obj_str = obj.display().to_string();
    let (code, stderr) = spawn_pgr(&[
        "-o",
        &out,
        "-undefined",
        "warning",
        "-w",
        "-whatsloaded",
        &obj_str,
    ]);
    assert_eq!(code, Some(0), "the composed link exits 0");
    assert!(
        !stderr.contains("pgr: warning:"),
        "the advisory faces stay suppressed: {stderr}"
    );
    assert!(
        stderr.contains("hole.o"),
        "the inventory still prints: {stderr}"
    );
}
