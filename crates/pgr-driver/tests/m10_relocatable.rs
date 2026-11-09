//! M10 rung 1 — `-r` relocatable output through the driver: the flag
//! surface (parse + the mutual exclusions), the two-step self-consumption
//! gate (`pgr -r` → the emitted object re-links into an executable), and
//! the determinism contract on the new path.

use pgr_core::layout::OutputType;
use pgr_driver::opts::parse;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::ffi::OsString;

fn args(list: &[&str]) -> Vec<OsString> {
    list.iter().map(std::ffi::OsString::from).collect()
}

fn scratch(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir()
        .join("pgr_m10_relocatable")
        .join(format!(
            "{tag}_{}_{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn main_object() -> (String, Vec<u8>) {
    let mut b = ObjectBuilder::new("hello_main.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![
            0x90, 0x00, 0x00, 0x00, // adrp x0, _msg@page
            0x91, 0x00, 0x00, 0x00, // add x0, x0, #_msg@pageoff
            0x94, 0x00, 0x00, 0x00, // bl _greet
            0xC0, 0x03, 0x5F, 0xD6, // ret
        ],
        vec![
            ObjectReloc::addend(0).at(0),
            ObjectReloc::page21(1).at(0),
            ObjectReloc::addend(0).at(4),
            ObjectReloc::pageoff12(1).at(4),
            ObjectReloc::branch26(2).at(8),
        ],
    ));
    b.add_section(ObjectSection::cstring("hello, peregrine\n"));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_msg".into(),
        section_index: 1,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    (String::from("hello_main.o"), b.build().unwrap())
}

fn greet_object() -> (String, Vec<u8>) {
    let mut b = ObjectBuilder::new("greet.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6], // ret
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    (String::from("greet.o"), b.build().unwrap())
}

#[test]
fn r_flag_parses_into_the_relocatable_output_type() {
    let o = parse(&args(&["-o", "out.o", "-r", "a.o"])).unwrap();
    assert_eq!(o.config.filetype, OutputType::Relocatable);
}

#[test]
fn r_flag_conflicts_are_rejected_actionably() {
    for conflict in [
        vec!["-o", "x", "-r", "-incremental", "a.o"],
        vec!["-o", "x", "-r", "-resident", "a.o"],
        vec!["-o", "x", "-r", "-dead_strip", "a.o"],
        vec!["-o", "x", "-r", "-icf=safe", "a.o"],
        vec!["-o", "x", "-r", "-dylib", "a.o"],
        vec!["-o", "x", "-r", "-bundle", "a.o"],
    ] {
        let err = parse(&args(&conflict)).unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains("-r"),
            "the refusal must name the conflict: {rendered}"
        );
    }
}

#[test]
fn r_flag_accepts_the_object_irrelevant_knobs() {
    // `-fixup_chains`/`-adhoc`/`-no_adhoc` are meaningless for objects —
    // accepted, forced off by the emit's contract (no fixups, no
    // signature on MH_OBJECT).
    let o = parse(&args(&["-o", "x", "-r", "-fixup_chains", "-adhoc", "a.o"])).unwrap();
    assert_eq!(o.config.filetype, OutputType::Relocatable);
}

#[test]
fn repeated_output_kind_flag_is_idempotent() {
    // Micro-debt fix: a repeated `-dylib` used to be reported as
    // "-dylib and -bundle are mutually exclusive" — a diagnosis about a
    // conflict that never happened.
    let o = parse(&args(&["-o", "x", "-dylib", "-dylib", "a.o"])).unwrap();
    assert_eq!(o.config.filetype, OutputType::Dylib);
    let o = parse(&args(&["-o", "x", "-r", "-r", "a.o"])).unwrap();
    assert_eq!(o.config.filetype, OutputType::Relocatable);
    // The real conflict still refuses.
    assert!(parse(&args(&["-o", "x", "-dylib", "-bundle", "a.o"])).is_err());
}

#[test]
fn r_output_relinks_into_an_executable() {
    // The two-step gate: `pgr -r a.o b.o -o out.o`, then `pgr out.o -o
    // exe` — the emitted object is an input, by construction.
    let dir = scratch("two_step");
    let (a_name, a_bytes) = main_object();
    let (b_name, b_bytes) = greet_object();
    std::fs::write(dir.join(&a_name), &a_bytes).unwrap();
    std::fs::write(dir.join(&b_name), &b_bytes).unwrap();

    let a_path = dir.join(&a_name);
    let b_path = dir.join(&b_name);
    let mut opts = parse(&args(&[
        "-o",
        dir.join("out.o").to_str().unwrap(),
        "-r",
        a_path.to_str().unwrap(),
        b_path.to_str().unwrap(),
    ]))
    .unwrap();
    opts.config.ident = "m10-reloc".into();
    let outcome = pgr_driver::run(&opts).unwrap();
    assert!(outcome.entryoff == 0 && outcome.fixup_slots == 0);
    let obj_bytes = std::fs::read(dir.join("out.o")).unwrap();

    // The object is verifier-clean and re-links (undefined `_greet` is
    // open in step one, resolved in step two).
    let report = pgr_verify::verify(
        &obj_bytes,
        &pgr_verify::Options {
            strict_warnings: true,
            skip_hash_recompute: false,
        },
    );
    let errors: Vec<_> = report
        .issues
        .iter()
        .filter(|i| i.severity == pgr_verify::Severity::Error)
        .collect();
    assert!(errors.is_empty(), "step-one output must verify: {errors:?}");

    let mut relink = parse(&args(&[
        "-o",
        dir.join("exe").to_str().unwrap(),
        dir.join("out.o").to_str().unwrap(),
    ]))
    .unwrap();
    relink.config.ident = "m10-relink".into();
    let exe = pgr_driver::run(&relink).unwrap();
    assert!(exe.file_size > 0 && exe.entryoff > 0);
    let exe_bytes = std::fs::read(dir.join("exe")).unwrap();
    let exe_report = pgr_verify::verify(
        &exe_bytes,
        &pgr_verify::Options {
            strict_warnings: true,
            skip_hash_recompute: false,
        },
    );
    let exe_errors: Vec<_> = exe_report
        .issues
        .iter()
        .filter(|i| i.severity == pgr_verify::Severity::Error)
        .collect();
    assert!(exe_errors.is_empty(), "step-two output must verify");
}

#[test]
fn r_output_is_deterministic_across_runs() {
    let dir = scratch("determinism");
    let (a_name, a_bytes) = main_object();
    let (b_name, b_bytes) = greet_object();
    std::fs::write(dir.join(&a_name), &a_bytes).unwrap();
    std::fs::write(dir.join(&b_name), &b_bytes).unwrap();

    let a_path = dir.join(&a_name);
    let b_path = dir.join(&b_name);
    let mut first = parse(&args(&[
        "-o",
        dir.join("one.o").to_str().unwrap(),
        "-r",
        a_path.to_str().unwrap(),
        b_path.to_str().unwrap(),
    ]))
    .unwrap();
    first.config.ident = "m10-det".into();
    pgr_driver::run(&first).unwrap();
    let mut second = parse(&args(&[
        "-o",
        dir.join("two.o").to_str().unwrap(),
        "-r",
        a_path.to_str().unwrap(),
        b_path.to_str().unwrap(),
    ]))
    .unwrap();
    second.config.ident = "m10-det".into();
    pgr_driver::run(&second).unwrap();
    assert_eq!(
        std::fs::read(dir.join("one.o")).unwrap(),
        std::fs::read(dir.join("two.o")).unwrap(),
        "double -r is byte-identical"
    );
}
