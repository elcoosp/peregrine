//! M77 — the gate's check selection: `-verify-checks <families>`
//! composes the M12 selector into the link's own verify gate. The
//! selection narrows the strict pass to the named families — the same
//! `CheckSet` the verifier CLI's `--checks` parses, the same subtractive
//! contract (selection runs fewer families against the same parsed
//! image; the parse pre-pass and the stats ride regardless) — on the
//! cold lane and, over wire v44, the resident lane's served pass. A
//! selection without a gate is dead weight: the flag refuses beside no
//! `-verify`. The refusals `-verify` already carries (`-r`,
//! `-incremental`) apply the same.

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m77_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// A single-object corpus (`_main`, `_helper`) written to `dir`.
fn corpus(dir: &Path) -> Vec<PathBuf> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(3),
        vec![],
    ));
    for (i, sym) in ["_main", "_helper"].iter().enumerate() {
        b.add_symbol(ObjectSymbol::Defined {
            name: (*sym).into(),
            section_index: text,
            value: (i * 4) as u64,
            weak: false,
        });
    }
    let path = dir.join("main.o");
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    vec![path]
}

fn parse(extra: &[&str]) -> Result<pgr_driver::opts::Options, pgr_driver::opts::OptsError> {
    let argv: Vec<std::ffi::OsString> = extra.iter().map(std::ffi::OsString::from).collect();
    pgr_driver::opts::parse(&argv)
}

// ---- the surface ---------------------------------------------------------------

#[test]
fn the_selection_parses_onto_the_surface() {
    let o = parse(&[
        "-o",
        "out",
        "-verify",
        "-verify-checks",
        "segments,fixups",
        "main.o",
    ])
    .expect("the argv parses");
    let set = o.verify_checks.expect("the selection rides the options");
    assert!(set.contains(pgr_verify::Check::Segments), "segments rides");
    assert!(set.contains(pgr_verify::Check::Fixups), "fixups rides");
    assert!(
        !set.contains(pgr_verify::Check::Signature),
        "the unselected family stays out"
    );
    let plain = parse(&["-o", "out", "-verify", "main.o"]).expect("the argv parses");
    assert!(
        plain.verify_checks.is_none(),
        "no selection names the full pass"
    );
}

#[test]
fn an_unknown_family_refuses_with_the_fix() {
    let err = parse(&[
        "-o",
        "out",
        "-verify",
        "-verify-checks",
        "segmants",
        "main.o",
    ])
    .expect_err("the unknown token refuses");
    let rendered = format!("{:?}", miette::Report::new(err));
    assert!(
        rendered.contains("segmants") && rendered.contains("segments"),
        "the refusal names the token and the canonical spelling: {rendered}"
    );
}

#[test]
fn the_selection_without_a_gate_refuses() {
    let err = parse(&["-o", "out", "-verify-checks", "segments", "main.o"])
        .expect_err("a selection with no gate refuses");
    let rendered = format!("{:?}", miette::Report::new(err));
    assert!(
        rendered.contains("-verify"),
        "the fix names the gate the selection narrows: {rendered}"
    );
}

#[test]
fn the_gate_refusals_outrank_the_selection() {
    // The image-output refusals `-verify` carries apply with a selection
    // riding: the knob composes, the conflicts do not.
    let relocatable = parse(&[
        "-o",
        "out",
        "-r",
        "-verify",
        "-verify-checks",
        "segments",
        "main.o",
    ]);
    assert!(relocatable.is_err(), "-r still refuses");
    let incremental = parse(&[
        "-o",
        "out",
        "-incremental",
        "-verify",
        "-verify-checks",
        "segments",
        "main.o",
    ]);
    assert!(incremental.is_err(), "-incremental still refuses");
}

// ---- the narrowed gate -----------------------------------------------------------

/// Flips one mid-image byte past the signature contract.
fn corrupt(image: &mut [u8]) {
    let mid = image.len() / 2 + 0x4000;
    image[mid] ^= 0xff;
}

#[test]
fn the_selection_narrows_the_gate_on_the_corrupted_twin() {
    let dir = scratch("narrow");
    let objs = corpus(&dir);
    let out_path = dir.join("hello");
    let mut argv: Vec<String> = vec!["-o".into(), out_path.display().to_string(), "-dylib".into()];
    for obj in &objs {
        argv.push(obj.display().to_string());
    }
    let argv: Vec<std::ffi::OsString> = argv.iter().map(std::ffi::OsString::from).collect();
    let o = pgr_driver::opts::parse(&argv).expect("the argv parses");
    let mut image = pgr_driver::link_to_bytes(&o).expect("the dylib links");
    corrupt(&mut image);

    // The full pass names the flipped byte — its finding rides the
    // signature family (the recomputed page hash no longer matches).
    let full = pgr_driver::verify_gate(&image, true);
    assert!(!full.summary.ok, "the full pass names the finding");

    // The signature family in the selection: the corrupted twin refuses.
    let signature = pgr_verify::CheckSet::parse("signature").expect("canonical names");
    let gate = pgr_driver::verify_gate_selected(&image, true, &signature);
    assert!(!gate.summary.ok, "the selected family names the finding");
    assert!(gate.summary.errors > 0, "the signature contract refuses");

    // The same bytes through a selection that leaves the family out: the
    // finding rides a family the selection did not name, the gate passes
    // it — selection is strictly subtractive, never a re-shape.
    let segments = pgr_verify::CheckSet::parse("segments").expect("canonical names");
    let narrow = pgr_driver::verify_gate_selected(&image, true, &segments);
    assert!(
        narrow.summary.ok,
        "the unselected family's finding stays out: {:?}",
        narrow.summary
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_selected_gate_rides_the_outcome_and_the_file_ships() {
    let dir = scratch("clean");
    let objs = corpus(&dir);
    let out_path = dir.join("hello");
    let mut argv: Vec<String> = vec![
        "-o".into(),
        out_path.display().to_string(),
        "-verify".into(),
    ];
    argv.push("-verify-checks".into());
    argv.push("segments,fixups".into());
    for obj in &objs {
        argv.push(obj.display().to_string());
    }
    let argv: Vec<std::ffi::OsString> = argv.iter().map(std::ffi::OsString::from).collect();
    let o = pgr_driver::opts::parse(&argv).expect("the argv parses");
    let outcome = pgr_driver::run(&o).expect("the link runs");
    let summary = outcome
        .verify
        .expect("the selected gate's verdict rides the outcome");
    assert!(summary.ok, "the clean link passes its selected gate");
    assert!(out_path.is_file(), "the gate wrote the image");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_selection_rides_the_resident_lane() {
    let dir = scratch("resident");
    let objs = corpus(&dir);
    let out_path = dir.join("hello");
    let sock = dir.join("m77.sock");
    let owned = sock.clone();
    std::thread::spawn(move || {
        let _ = pgr_daemon::serve(&owned, std::time::Duration::from_secs(120));
    });
    for _ in 0..500 {
        if UnixStream::connect(&sock).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let mut argv: Vec<String> = vec![
        "-o".into(),
        out_path.display().to_string(),
        "-dylib".into(),
        "-resident".into(),
        "-resident_socket".into(),
        sock.display().to_string(),
        "-verify".into(),
        "-verify-checks".into(),
        "segments,signature".into(),
    ];
    for obj in &objs {
        argv.push(obj.display().to_string());
    }
    let argv: Vec<std::ffi::OsString> = argv.iter().map(std::ffi::OsString::from).collect();
    let o = pgr_driver::opts::parse(&argv).expect("the argv parses");
    let outcome = pgr_driver::run(&o).expect("the resident link runs");
    let summary = outcome
        .verify
        .expect("the served verdict rides the resident outcome");
    assert!(
        summary.ok,
        "the clean link passes its selected served pass: {summary:?}"
    );
    assert!(out_path.is_file(), "the gate wrote the image");
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&sock);
}
