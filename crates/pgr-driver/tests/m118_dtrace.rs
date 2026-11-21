//! M118 — the `-dtrace` driver surface: the flag parses onto the config
//! decision, the relocatable output refuses it (the object's sections are
//! the input's, verbatim), and the end-to-end gates: the `-dtrace` image
//! carries the `__dtrace_dof` section and verifies strict (the producer
//! validated the `DOF` header at emit; the read-side backstop passes on a
//! well-formed header); the producer refuses a malformed `DOF` header
//! under `-dtrace`; and the read-side backstop reports a malformed header
//! the producer never saw (the default carries the bytes verbatim, no
//! emit validation — the verifier catches it read-side). The spawn gates
//! run the real binary.

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::consts::S_DTRACE_DOF;
use pgr_format::dof::DOF_MAGIC;
use pgr_format::{LoadCommandIter, MachHeader64};
use pgr_verify::{Code, Options as VerifyOptions, verify};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m118_dtrace").join(format!(
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

/// `main.o`: `_main` plus a `__dtrace_dof` (`S_DTRACE_DOF`) section
/// carrying a `DOF` header — the identification magic at the head (the
/// valid face) or a stand-in (the malformed face the producer's emit-side
/// gate refuses under `-dtrace` and the read-side backstop reports either
/// way).
fn corpus(dir: &Path, name: &str, valid_dof: bool) -> PathBuf {
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
    let mut dof = vec![0u8; 32];
    dof[..DOF_MAGIC.len()].copy_from_slice(if valid_dof { &DOF_MAGIC } else { b"XXXX" });
    let dof_sect = b.add_section(ObjectSection::text("__dtrace_dof", dof, vec![]));
    b.section_mut(dof_sect).flags = S_DTRACE_DOF;
    let path = dir.join(name);
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    path
}

/// The output section names the image's segment commands carry (the raw
/// load-command walk — the layout's own source).
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
        if cmd.kind != pgr_format::LoadCommandKind::Segment64 {
            continue;
        }
        if cmd.bytes.len() < 72 {
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
    let obj = corpus(&dir, "main.o", true);
    let obj = obj.display().to_string();
    let o = opts::parse(&args(&["-o", "out", &obj])).expect("the plain argv parses");
    assert!(
        !o.config.dtrace,
        "the default carries the section verbatim (every pre-knob link byte-identical)"
    );
    let o = opts::parse(&args(&["-dtrace", "-o", "out", &obj])).expect("the flag parses");
    assert!(o.config.dtrace, "the flag names the dtrace decision");
}

#[test]
fn the_dtrace_image_carries_the_section_and_verifies_strict() {
    // The producer validated the DOF header at emit; the read-side
    // backstop passes on a well-formed header (the section rides and the
    // image verifies strict).
    let dir = scratch("e2e");
    let obj = corpus(&dir, "main.o", true);
    let out = dir.join("app").display().to_string();
    let obj = obj.display().to_string();
    let (code, stderr) = spawn_pgr(&["-dtrace", "-o", &out, &obj]);
    assert_eq!(code, Some(0), "the dtrace link exits 0: {stderr}");
    let image = std::fs::read(&out).expect("the image writes");
    let names = image_sections(&image);
    assert!(
        names.iter().any(|n| n.contains("__dtrace_dof")),
        "the dtrace image carries the __dtrace_dof section: {names:?}"
    );
    assert!(
        verify(&image, &strict()).is_ok(&strict()),
        "the DOF-bearing image (a well-formed header) verifies strict"
    );
}

#[test]
fn the_default_carries_a_dtrace_section() {
    // The pre-M118 shape: the default carries the section's bytes
    // verbatim (no emit validation; a well-formed header still verifies).
    let dir = scratch("default");
    let obj = corpus(&dir, "main.o", true);
    let out = dir.join("app").display().to_string();
    let obj = obj.display().to_string();
    let (code, stderr) = spawn_pgr(&["-o", &out, &obj]);
    assert_eq!(code, Some(0), "the default link exits 0: {stderr}");
    let image = std::fs::read(&out).expect("the image writes");
    let names = image_sections(&image);
    assert!(
        names.iter().any(|n| n.contains("__dtrace_dof")),
        "the default image carries the __dtrace_dof section: {names:?}"
    );
    assert!(
        verify(&image, &strict()).is_ok(&strict()),
        "a well-formed DOF header verifies strict under the default too"
    );
}

#[test]
fn the_producer_refuses_a_malformed_dof_header_under_dtrace() {
    // The emit-side gate: under `-dtrace` a malformed DOF header (the
    // identification magic mismatch) refuses the link — the section is
    // emitted with its DOF header validated, the producer never ships a
    // payload the consumer would misread.
    let dir = scratch("bad_producer");
    let obj = corpus(&dir, "main.o", false);
    let out = dir.join("app").display().to_string();
    let obj = obj.display().to_string();
    let (code, stderr) = spawn_pgr(&["-dtrace", "-o", &out, &obj]);
    assert_ne!(
        code,
        Some(0),
        "the producer refuses a malformed DOF header under -dtrace: {stderr}"
    );
    assert!(
        stderr.contains("DOF") || stderr.contains("dtrace"),
        "the refusal names the DOF contract: {stderr}"
    );
}

#[test]
fn the_read_side_backstop_reports_a_malformed_dof_header() {
    // The read-side backstop: the default carries a malformed DOF header
    // verbatim (no emit validation — the producer never saw it), but the
    // verifier catches it read-side on every `__dtrace_dof` section (the
    // M115 read-side-backstop shape, one section type over).
    let dir = scratch("bad_backstop");
    let obj = corpus(&dir, "main.o", false);
    let out = dir.join("app").display().to_string();
    let obj = obj.display().to_string();
    let (code, stderr) = spawn_pgr(&["-o", &out, &obj]);
    assert_eq!(
        code,
        Some(0),
        "the default carries a malformed DOF header verbatim (no emit validation): {stderr}"
    );
    let image = std::fs::read(&out).expect("the image writes");
    let report = verify(&image, &strict());
    assert!(
        !report.is_ok(&strict()),
        "the read-side backstop catches the malformed DOF header the producer never saw"
    );
    assert!(
        report.issues.iter().any(|i| i.code == Code::DtraceDof),
        "the backstop reports the DtraceDof code (the read-side contract): {:?}",
        report.issues
    );
}

#[test]
fn dtrace_refuses_on_the_relocatable_output() {
    let dir = scratch("reloc");
    let obj = corpus(&dir, "main.o", true);
    let out = dir.join("out.o").display().to_string();
    let obj = obj.display().to_string();
    let err = opts::parse(&args(&["-r", "-o", &out, &obj, "-dtrace"]))
        .expect_err("the relocatable output refuses the knob");
    let rendered = err.to_string();
    assert!(
        rendered.contains("-dtrace") && rendered.contains("verbatim"),
        "the refusal names the flag and the verbatim contract: {rendered}"
    );
}
