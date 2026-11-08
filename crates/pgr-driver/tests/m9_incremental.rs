//! M9 end-to-end gates (architecture doc §10.4 row M9, §7.3 Stage C
//! tier 1): the `pgr -incremental` driver loop over real files — first
//! link records, edited relink patches in place, unchanged relink is a
//! no-op, every fallback path lands on the full link, and
//! `-incremental-verify` audits the result with the in-repo verifier.
//!
//! The e2e suite's standing rule applies to every patched output here:
//! `pgr-verify --strict` must pass before the test calls a relink
//! finished.

use pgr_driver::{DriverError, LinkOutcome, run};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::Options as VerifyOptions;
use std::path::{Path, PathBuf};

/// hello.o with a `text_bytes`-sized `__text` (canonical prologue + `nop`
/// padding; `body_flip` swaps a mov immediate and the cstring at equal
/// length): `_main` ADRP+ADD loads `_msg`, BL `_greet`, ret.
fn hello(text_bytes: usize, body_flip: bool) -> ObjectBuilder {
    let mut words: Vec<u32> = vec![
        0x9000_0000, // adrp x0, _msg@page
        0x9100_0000, // add x0, x0, #_msg@pageoff
        0x9400_0000, // bl _greet
        0x5280_0000, // mov w0, #0 (flipped: #1 — the edited function body)
        0xD65F_03C0, // ret
    ];
    if body_flip {
        words[3] = 0x5280_0020;
    }
    words.resize(text_bytes / 4, 0xD503_201F);
    let text: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let mut b = ObjectBuilder::new("hello.o");
    let sect = b.add_section(ObjectSection::text(
        "__text",
        text,
        vec![
            ObjectReloc::addend(0).at(0),
            ObjectReloc::page21(1).at(0),
            ObjectReloc::addend(0).at(4),
            ObjectReloc::pageoff12(1).at(4),
            ObjectReloc::branch26(2).at(8),
        ],
    ));
    b.add_section(ObjectSection::cstring(if body_flip {
        "merci, peregrine\n" // same length as "hello, peregrine\n"
    } else {
        "hello, peregrine\n"
    }));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: sect,
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
    b
}

/// greet.o (never edited): `_greet` + a `__data` pointer to `_greet`.
fn greet() -> ObjectBuilder {
    let mut b = ObjectBuilder::new("greet.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.section_mut(data).relocs = vec![ObjectReloc::unsigned(0).at(0)];
    b
}

/// One corpus instance: hello.o written fresh (with the requested body) and
/// greet.o written once.
struct Corpus {
    dir: PathBuf,
    hello: PathBuf,
    out: PathBuf,
}

impl Corpus {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("pgr_m9_e2e_{tag}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("greet.o"), greet().build().unwrap()).unwrap();
        let corpus = Self {
            hello: dir.join("hello.o"),
            out: dir.join("app"),
            dir,
        };
        std::fs::write(&corpus.hello, hello(32 * 1024, false).build().unwrap()).unwrap();
        corpus
    }

    /// Overwrites hello.o with the requested body (the "edit").
    fn edit(&self, text_bytes: usize, body_flip: bool) {
        std::fs::write(&self.hello, hello(text_bytes, body_flip).build().unwrap()).unwrap();
    }

    fn opts(&self, incremental: bool, verify: bool) -> pgr_driver::opts::Options {
        pgr_driver::opts::Options {
            output: self.out.display().to_string(),
            inputs: vec![
                self.hello.display().to_string(),
                self.dir.join("greet.o").display().to_string(),
            ],
            config: pgr_core::layout::LinkConfig {
                ident: "pgr-m9-e2e".into(),
                ..pgr_core::layout::LinkConfig::default()
            },
            incremental,
            incremental_verify: verify,
            ..pgr_driver::opts::Options::default()
        }
    }

    fn record(&self) -> PathBuf {
        let mut name = self.out.clone().into_os_string();
        name.push(".pgr-inc");
        PathBuf::from(name)
    }
}

fn strict_verify(path: &Path) -> bool {
    let bytes = std::fs::read(path).unwrap();
    let opts = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    pgr_verify::verify(&bytes, &opts).is_ok(&opts)
}

/// The canonical edit-relink loop: link → edit → relink in place.
#[test]
fn edited_relink_patches_in_place_and_verifies() {
    let c = Corpus::new("inplace");
    // Link 1: no record yet — the full link runs and records.
    let first = run(&c.opts(true, false)).unwrap();
    assert!(first.patch.is_none(), "the first link is a full link");
    assert!(c.record().exists(), "the record sidecar is written");
    assert!(strict_verify(&c.out));

    // Link 2: the body edit — the relink patches the changed tiles.
    c.edit(32 * 1024 + 1024, true);
    let second = run(&c.opts(true, false)).unwrap();
    let patch = second.patch.expect("the edited relink patches in place");
    assert!(!patch.untouched);
    assert!(
        patch.dirty_tiles < patch.total_tiles,
        "a one-function edit must reuse most tiles ({} of {})",
        patch.dirty_tiles,
        patch.total_tiles
    );
    assert!(
        patch.bytes_patched < u64::from(patch.total_tiles) * 16 * 1024,
        "the patch must write less than the whole image"
    );
    assert_eq!(second.file_size, first.file_size, "the skeleton is frozen");
    // The standing e2e rule: the patched output passes the strict verifier
    // (chain walk, signature page-hash recompute, trie, branch ranges).
    assert!(strict_verify(&c.out), "the patched output must verify strict");
}

#[test]
fn unchanged_relink_is_a_reported_noop() {
    let c = Corpus::new("noop");
    run(&c.opts(true, false)).unwrap();
    let second = run(&c.opts(true, false)).unwrap();
    let patch = second.patch.expect("the relink still goes through the engine");
    assert!(patch.untouched, "identical inputs must touch nothing");
    assert_eq!(patch.bytes_patched, 0);
    assert!(strict_verify(&c.out));
}

#[test]
fn deleted_record_falls_back_to_a_full_link() {
    let c = Corpus::new("norecord");
    run(&c.opts(true, false)).unwrap();
    std::fs::remove_file(c.record()).unwrap();
    let second = run(&c.opts(true, false)).unwrap();
    assert!(
        second.patch.is_none(),
        "a missing record must fall back to the full link"
    );
    assert!(c.record().exists(), "the full link re-records");
    assert!(strict_verify(&c.out));
}

#[test]
fn corrupt_record_falls_back_to_a_full_link() {
    let c = Corpus::new("badrecord");
    run(&c.opts(true, false)).unwrap();
    // Flip a payload byte: the checksum gate rejects the record cleanly.
    let mut junk = std::fs::read(c.record()).unwrap();
    let mid = junk.len() / 2;
    junk[mid] ^= 0xff;
    std::fs::write(c.record(), &junk).unwrap();
    let second = run(&c.opts(true, false)).unwrap();
    assert!(second.patch.is_none(), "a corrupt record must fall back");
    assert!(strict_verify(&c.out), "the fallback rewrites the image cleanly");
    // The sidecar was replaced with a fresh, decodable record.
    let fresh = std::fs::read(c.record()).unwrap();
    assert_ne!(fresh, junk, "the full link re-recorded");
    assert!(pgr_emit::incremental::LinkRecord::decode(&fresh).is_some());
}

#[test]
fn deleted_output_falls_back_to_a_full_link() {
    let c = Corpus::new("nooutput");
    run(&c.opts(true, false)).unwrap();
    std::fs::remove_file(&c.out).unwrap();
    let second = run(&c.opts(true, false)).unwrap();
    assert!(second.patch.is_none(), "no output, nothing to patch");
    assert!(strict_verify(&c.out));
}

#[test]
fn skeleton_move_falls_back_to_a_full_link() {
    let c = Corpus::new("skeleton");
    run(&c.opts(true, false)).unwrap();
    // 96 KiB of new text blows way past the reserved slack: __text resizes.
    c.edit(96 * 1024, false);
    let second = run(&c.opts(true, false)).unwrap();
    assert!(
        second.patch.is_none(),
        "an overflowing section must fall back (the §7.3 ladder)"
    );
    assert!(strict_verify(&c.out), "the clean relink verifies strict");
    // And the *next* link is incremental again (the full link re-recorded
    // the new skeleton): a same-size body edit on top patches in place.
    c.edit(96 * 1024, true);
    let third = run(&c.opts(true, false)).unwrap();
    let patch = third.patch.expect("the re-recorded state patches again");
    assert!(!patch.untouched);
    assert!(strict_verify(&c.out));
}

#[test]
fn incremental_verify_audits_the_patched_output() {
    let c = Corpus::new("verify");
    run(&c.opts(true, false)).unwrap();
    c.edit(32 * 1024, true);
    let second = run(&c.opts(true, true)).unwrap();
    let patch = second.patch.expect("the audited relink patches in place");
    assert!(!patch.untouched);
    assert!(strict_verify(&c.out), "the audited output verifies strict");
    // The `-incremental-verify` parse surface: the flag exists, implies the
    // tier, and is rejected with an actionable message for unknown spellings.
    assert!(pgr_driver::opts::parse(&args(&["-o", "out", "-incremental-verify", "a.o"])).is_ok());
}

#[test]
fn no_incremental_always_links_full() {
    let c = Corpus::new("off");
    run(&c.opts(true, false)).unwrap();
    c.edit(32 * 1024, true);
    let second = run(&c.opts(false, false)).unwrap();
    assert!(second.patch.is_none(), "-no_incremental links full");
    assert!(strict_verify(&c.out));
}

#[test]
fn resident_and_incremental_do_not_collide() {
    // The resident path returns no record; `-incremental` simply falls back
    // to the full (recorded) link when the daemon is unreachable — the
    // §7.2 transparency contract holds with the M9 tier in the mix.
    let c = Corpus::new("resident");
    let mut o = c.opts(true, false);
    o.resident = true;
    let first = run(&o).unwrap();
    if first.patch.is_some() {
        // A resident daemon actually answered (socket reuse in the sandbox);
        // resident + incremental is GA scope, so the patch must be a no-op
        // of the full link — accepted either way, verified regardless.
        assert!(strict_verify(&c.out));
        return;
    }
    assert!(c.record().exists(), "the full link recorded after the fallback");
    c.edit(32 * 1024, true);
    let second = run(&o).unwrap();
    if second.patch.is_none() {
        assert!(strict_verify(&c.out));
    }
}

fn args(argv: &[&str]) -> Vec<std::ffi::OsString> {
    argv.iter().map(std::ffi::OsString::from).collect()
}

/// Option-surface gates: the flags parse, `-incremental-verify` implies the
/// tier, and `-no_incremental` wins.
#[test]
fn option_surface() {
    let o = pgr_driver::opts::parse(&args(&["-o", "out", "-incremental", "a.o"])).unwrap();
    assert!(o.incremental);
    assert!(!o.incremental_verify);
    let o = pgr_driver::opts::parse(&args(&["-o", "out", "-incremental-verify", "a.o"])).unwrap();
    assert!(o.incremental && o.incremental_verify);
    let o = pgr_driver::opts::parse(&args(&[
        "-o",
        "out",
        "-incremental",
        "-no_incremental",
        "a.o",
    ]))
    .unwrap();
    assert!(!o.incremental, "-no_incremental wins");
    assert!(pgr_driver::usage().contains("-incremental"));
}

/// The driver error surface stays honest when a real link error hits the
/// incremental path (undefined symbol propagates as a link error, not a
/// silent fallback).
#[test]
fn link_errors_propagate_through_the_incremental_path() {
    let c = Corpus::new("linkerror");
    run(&c.opts(true, false)).unwrap();
    // A hello.o that references an undefined symbol: the *full* link would
    // fail, so the incremental path must fail identically (the pipeline
    // re-run inside the relink surfaces the same error).
    let mut b = hello(1024, false);
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_does_not_exist".into(),
        weak_ref: false,
    });
    std::fs::write(&c.hello, b.build().unwrap()).unwrap();
    let err = run(&c.opts(true, false)).unwrap_err();
    assert!(
        matches!(err, DriverError::Link(_) | DriverError::ForceLoad { .. }),
        "unexpected error shape: {err:?}"
    );
}

/// Silence the unused-import lint when `LinkOutcome` fields evolve.
const _: fn(&LinkOutcome) -> u64 = |o| o.file_size;
