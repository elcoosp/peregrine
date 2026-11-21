//! M116 — the `-warn_commons` driver surface: the flag parses onto the
//! config decision, the relocatable output refuses it (the object's
//! symtab is the input's, verbatim), and the exit face is the e2e
//! contract — every common-symbol landing the resolver recorded prints
//! as the `pgr: warning:` face (the M103/M108 convention) and the link
//! still exits 0 with the image written. The spawn gates run the real
//! binary (the advisory face is stderr + exit code — the driver
//! library cannot assert its own stderr).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir()
        .join("pgr_m116_warn_commons")
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

/// `common.o`: `_main` plus the `_tentative` common (the advisory's
/// subject — the tentative definition the resolution lands).
fn common_object(dir: &Path, name: &str) -> PathBuf {
    let mut b = ObjectBuilder::new(name);
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6], // ret
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Common {
        name: "_tentative".into(),
        size: 32,
        align_log2: 3,
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
fn the_flag_names_the_decision() {
    let dir = scratch("parse");
    let obj = common_object(&dir, "common.o");
    let obj = obj.display().to_string();
    let o = opts::parse(&args(&["-o", "out", &obj])).expect("the plain argv parses");
    assert!(
        !o.config.warn_commons,
        "the default keeps the advisory off (every pre-knob link byte-identical)"
    );
    let o = opts::parse(&args(&["-warn_commons", "-o", "out", &obj])).expect("the flag parses");
    assert!(o.config.warn_commons, "the flag names the advisory");
}

#[test]
fn the_advisory_face_prints_and_exits_zero() {
    let dir = scratch("face");
    let obj = common_object(&dir, "common.o");
    let out = dir.join("app").display().to_string();
    let obj = obj.display().to_string();
    let (code, stderr) = spawn_pgr(&["-o", &out, "-warn_commons", &obj]);
    assert_eq!(code, Some(0), "the advisory face exits 0");
    assert!(
        stderr.contains("pgr: warning: common symbol") && stderr.contains("_tentative"),
        "the face names the common and its landing: {stderr}"
    );
    assert!(
        Path::new(&out).exists(),
        "the image ships despite the advisory (the M103 warning-face pattern)"
    );
}

#[test]
fn the_default_stays_silent() {
    let dir = scratch("silent");
    let obj = common_object(&dir, "common.o");
    let out = dir.join("app").display().to_string();
    let obj = obj.display().to_string();
    let (code, stderr) = spawn_pgr(&["-o", &out, &obj]);
    assert_eq!(code, Some(0), "the plain link exits 0");
    assert!(
        !stderr.contains("common symbol"),
        "the default prints no advisory: {stderr}"
    );
}

#[test]
fn the_advisory_tallies_into_fatal_warnings() {
    // M109's composition: the face's product is the tally's — under
    // `-fatal_warnings` the commons advisory elevates to the hard exit
    // (no image written), the same shape the other advisory faces ride.
    let dir = scratch("fatal");
    let obj = common_object(&dir, "common.o");
    let out = dir.join("app").display().to_string();
    let obj = obj.display().to_string();
    let (code, stderr) = spawn_pgr(&["-o", &out, "-warn_commons", "-fatal_warnings", &obj]);
    assert_ne!(code, Some(0), "the escalation refuses the link");
    assert!(
        stderr.contains("fatal_warnings") || stderr.contains("warning(s) elevated"),
        "the refusal names the escalation: {stderr}"
    );
    assert!(
        !Path::new(&out).exists(),
        "the elevated link writes no image"
    );
}

#[test]
fn warn_commons_refuses_on_the_relocatable_output() {
    let dir = scratch("reloc");
    let obj = common_object(&dir, "common.o");
    let out = dir.join("out.o").display().to_string();
    let obj = obj.display().to_string();
    let err = opts::parse(&args(&["-r", "-o", &out, &obj, "-warn_commons"]))
        .expect_err("the relocatable output refuses the knob");
    let rendered = err.to_string();
    assert!(
        rendered.contains("-warn_commons") && rendered.contains("verbatim"),
        "the refusal names the flag and the verbatim contract: {rendered}"
    );
}

#[test]
fn the_local_landing_names_the_defining_input() {
    // The two-object corpus: a.o's `_tentative` loses to b.o's real
    // definition — the face names the input the definition landed on
    // (the winner's file index, the M108 entry convention).
    let dir = scratch("local");
    let a = common_object(&dir, "a.o");
    let mut b = ObjectBuilder::new("b.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_tentative".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let b_path = dir.join("b.o");
    std::fs::write(&b_path, b.build().expect("the fixture object builds")).unwrap();
    let out = dir.join("app").display().to_string();
    let (a, b) = (a.display().to_string(), b_path.display().to_string());
    let (code, stderr) = spawn_pgr(&["-o", &out, "-warn_commons", &a, &b]);
    assert_eq!(code, Some(0), "the advisory face exits 0");
    assert!(
        stderr.contains("'_tentative' resolved to 'input 1'"),
        "the face names the definition's input: {stderr}"
    );
}
