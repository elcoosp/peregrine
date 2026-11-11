//! M17 — the `-segprot` surface: the flag parses (`-segprot <seg> <max>
//! <init>`, the protections subsets of `rwx`), every malformed value
//! refuses with the fix in the help text (the house miette convention),
//! a non-relocatable output is the only taker (`-r` carries no
//! segments — a refusal, never a silently dropped flag), the
//! custom-protection image links and verifies strict (the verifier's
//! protection invariants), the explicit house value links
//! byte-identical to the default, and the resident cycle plans the
//! same bytes — the wire (protocol v10) carries the named decisions,
//! not just the house table.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// A unique scratch dir per test (the house pattern: no tempfile dep).
fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m17_driver").join(format!(
        "{tag}_{}_{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A small executable corpus with two rebase slots.
fn corpus(dir: &Path) -> Vec<PathBuf> {
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 16], vec![]));
    let main_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let helper_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_helper".into(),
        section_index: text,
        value: 4,
        weak: false,
    });
    b.section_mut(data).relocs = vec![
        ObjectReloc::unsigned(main_sym as u32).at(0),
        ObjectReloc::unsigned(helper_sym as u32).at(8),
    ];
    let path = dir.join("main.o");
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    vec![path]
}

/// Links the corpus as an executable under `extra` argv entries; returns
/// the image bytes.
fn link_exe(dir: &Path, out: &str, extra: &[&str]) -> Vec<u8> {
    let objs = corpus(dir);
    let out_path = dir.join(out);
    let mut argv = vec!["-o".to_string(), out_path.display().to_string()];
    for obj in &objs {
        argv.push(obj.display().to_string());
    }
    argv.extend(extra.iter().map(std::string::ToString::to_string));
    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the executable links");
    std::fs::read(&out_path).unwrap()
}

/// The named segment's `(maxprot, initprot)` pair read back from the
/// image's `LC_SEGMENT_64` commands.
fn seg_prots(image: &[u8], seg: &str) -> (u32, u32) {
    let header = pgr_format::MachHeader64::parse(image).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands walk");
    while let Ok(Some(cmd)) = it.next_command() {
        if cmd.kind == pgr_format::LoadCommandKind::Segment64 {
            let seg_cmd =
                pgr_format::SegmentCommand64::parse(cmd.bytes, 0).expect("the command parses");
            if seg_cmd.name().expect("utf8") == seg {
                return (seg_cmd.maxprot, seg_cmd.initprot);
            }
        }
    }
    panic!("{seg} is in the image");
}

fn strict() -> VerifyOptions {
    VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

// ---- the surface -------------------------------------------------------------

#[test]
fn the_flag_parses_and_names_the_decision() {
    let argv: Vec<OsString> = ["-o", "out", "main.o", "-segprot", "__DATA_CONST", "rw", "r"]
        .iter()
        .map(OsString::from)
        .collect();
    let o = opts::parse(&argv).expect("the argv parses");
    let p = o
        .config
        .seg_prots
        .prot_for("__DATA_CONST")
        .expect("the decision is on the config");
    assert_eq!((p.maxprot(), p.initprot()), (0b011, 0b001));
}

#[test]
fn a_malformed_protection_refuses_with_the_grammar() {
    for args in [
        vec!["-o", "out", "main.o", "-segprot", "__DATA_CONST", "q", "r"],
        vec!["-o", "out", "main.o", "-segprot", "__DATA_CONST", "rw", ""],
        vec!["-o", "out", "main.o", "-segprot", "__DATA_CONST", "rr", "r"],
    ] {
        let argv: Vec<OsString> = args.iter().map(OsString::from).collect();
        let err = opts::parse(&argv).expect_err("the grammar refuses");
        let report = miette::Report::new(err);
        assert!(
            format!("{report}").contains("rwx"),
            "the refusal names the grammar: {report}"
        );
    }
}

#[test]
fn an_unknown_segment_refuses_with_the_set() {
    let argv: Vec<OsString> = ["-o", "out", "main.o", "-segprot", "__PAGEZERO", "rw", "r"]
        .iter()
        .map(OsString::from)
        .collect();
    let err = opts::parse(&argv).expect_err("__PAGEZERO carries no protections");
    let report = miette::Report::new(err);
    assert!(
        format!("{report}").contains("__LINKEDIT"),
        "the refusal names the planned set: {report}"
    );
}

#[test]
fn init_beyond_max_refuses() {
    let argv: Vec<OsString> = ["-o", "out", "main.o", "-segprot", "__TEXT", "rx", "rwx"]
        .iter()
        .map(OsString::from)
        .collect();
    let err = opts::parse(&argv).expect_err("init beyond max refuses");
    assert!(
        err.to_string().contains("maxprot"),
        "the refusal names the kernel rule: {err}"
    );
}

#[test]
fn a_writable_executable_init_refuses() {
    let argv: Vec<OsString> = ["-o", "out", "main.o", "-segprot", "__DATA", "rwx", "rwx"]
        .iter()
        .map(OsString::from)
        .collect();
    let err = opts::parse(&argv).expect_err("a W+X initial mapping refuses");
    assert!(
        err.to_string().to_lowercase().contains("writable"),
        "the refusal names the W^X contract: {err}"
    );
}

#[test]
fn a_duplicate_segment_refuses() {
    let argv: Vec<OsString> = [
        "-o", "out", "main.o", "-segprot", "__TEXT", "rx", "rx", "-segprot", "__TEXT", "r", "r",
    ]
    .iter()
    .map(OsString::from)
    .collect();
    let err = opts::parse(&argv).expect_err("one decision per segment");
    assert!(
        err.to_string().contains("twice"),
        "the refusal names the shape: {err}"
    );
}

#[test]
fn the_relocatable_output_refuses_the_knob() {
    let argv: Vec<OsString> = [
        "-o",
        "out.o",
        "main.o",
        "-r",
        "-segprot",
        "__DATA_CONST",
        "rw",
        "r",
    ]
    .iter()
    .map(OsString::from)
    .collect();
    let err = opts::parse(&argv).expect_err("-r carries no segments");
    assert!(
        err.to_string().contains("segments"),
        "the refusal names the shape conflict: {err}"
    );
}

// ---- the link ----------------------------------------------------------------

#[test]
fn a_custom_decision_links_and_verifies_strict() {
    let dir = scratch("custom");
    let image = link_exe(&dir, "hello", &["-segprot", "__DATA_CONST", "rw", "r"]);
    assert_eq!(
        seg_prots(&image, "__DATA_CONST"),
        (0b011, 0b001),
        "the named pair landed"
    );
    assert_eq!(seg_prots(&image, "__TEXT"), (0b101, 0b101), "house __TEXT");
    let report = verify(&image, &strict());
    assert!(
        report.is_ok(&strict()),
        "the custom image verifies strict: {:?}",
        report.issues
    );
}

#[test]
fn the_explicit_house_value_links_byte_identical_to_the_default() {
    let dir = scratch("house");
    let default = link_exe(&dir, "hello_default", &[]);
    let explicit = link_exe(&dir, "hello_explicit", &["-segprot", "__DATA", "rw", "rw"]);
    assert_eq!(
        default, explicit,
        "naming the house pair plans the default bytes"
    );
}

#[test]
fn the_resident_cycle_carries_the_decision() {
    // One-shot reference.
    let dir = scratch("resident_ref");
    let one_shot = link_exe(&dir, "hello_ref", &["-segprot", "__DATA_CONST", "rw", "r"]);

    // The same link through the resident path: the daemon relinks with
    // the same config, so the named decisions crossed the wire (v10).
    let dir2 = scratch("resident");
    let sock = dir2.join("pgrd.sock");
    let owned = sock.clone();
    std::thread::spawn(move || {
        let _ = pgr_daemon::serve(&owned, Duration::from_secs(120));
    });
    std::thread::sleep(Duration::from_millis(50));

    let objs = corpus(&dir2);
    let out_path = dir2.join("hello");
    let mut argv = vec![
        "-o".to_string(),
        out_path.display().to_string(),
        "-segprot".to_string(),
        "__DATA_CONST".to_string(),
        "rw".to_string(),
        "r".to_string(),
        "-resident".to_string(),
        "-resident_socket".to_string(),
        sock.display().to_string(),
    ];
    for obj in &objs {
        argv.push(obj.display().to_string());
    }
    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    let o = opts::parse(&argv).expect("the resident argv parses");
    pgr_driver::run(&o).expect("the resident link runs");
    let resident = std::fs::read(&out_path).unwrap();
    assert_eq!(
        one_shot, resident,
        "the resident cycle plans the same bytes with named protections"
    );
    assert_eq!(
        seg_prots(&resident, "__DATA_CONST"),
        (0b011, 0b001),
        "the decisions crossed the wire"
    );
}
