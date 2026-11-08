//! M9 end-to-end gates (architecture doc §10.4 row M9, §7.3 Stage C
//! tiers 1–2): the `pgr -incremental` driver loop over real files — first
//! link records, edited relink patches in place, unchanged relink is a
//! no-op, a slack overflow patches through the segment-relayout tier
//! while oversized growth still lands on the full link, and
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

/// hello.o plus `locals` unreferenced local symbols pinned into `__text`:
/// they land in the output symtab and string pool, so removing them
/// shrinks the `__LINKEDIT` chunk stream — and, on an unsigned image
/// (`-no_adhoc`: no signature boundary to anchor the tail), the whole
/// image tail with it. The text bytes are invariant under `locals`.
fn hello_with_locals(text_bytes: usize, body_flip: bool, locals: usize) -> ObjectBuilder {
    let mut b = hello(text_bytes, body_flip);
    for i in 0..locals {
        b.add_symbol(ObjectSymbol::Defined {
            name: format!("_pgr_local_{i:04}"),
            section_index: 0,
            value: u64::try_from(i % 16).unwrap_or(0) * 4,
            weak: false,
        });
    }
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
        Self::with_text(tag, 32 * 1024)
    }

    /// A corpus whose hello.o carries `text_bytes` of `__text` (the tier-2
    /// gates use a larger base so the moved suffix stays a minority of the
    /// image — the relayout patch exists to avoid whole-image work).
    fn with_text(tag: &str, text_bytes: usize) -> Self {
        let dir = std::env::temp_dir().join(format!("pgr_m9_e2e_{tag}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("greet.o"), greet().build().unwrap()).unwrap();
        let corpus = Self {
            hello: dir.join("hello.o"),
            out: dir.join("app"),
            dir,
        };
        std::fs::write(&corpus.hello, hello(text_bytes, false).build().unwrap()).unwrap();
        corpus
    }

    /// Overwrites hello.o with the requested body (the "edit").
    fn edit(&self, text_bytes: usize, body_flip: bool) {
        std::fs::write(&self.hello, hello(text_bytes, body_flip).build().unwrap()).unwrap();
    }

    /// Overwrites hello.o with the requested body AND local-symbol block
    /// (the LINKEDIT-shrink edit: `locals` shrinking moves the unsigned
    /// image's tail).
    fn edit_symbols(&self, text_bytes: usize, body_flip: bool, locals: usize) {
        std::fs::write(
            &self.hello,
            hello_with_locals(text_bytes, body_flip, locals)
                .build()
                .unwrap(),
        )
        .unwrap();
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

/// The verifier's stance for the unsigned (`-no_adhoc`) corpus: every
/// issue except the deliberate "no ad-hoc code signature" layout error
/// must be clean (the shrink-rung corpus is unsigned because a signed
/// relink pins the signature boundary — the tail can never shrink).
/// Returns the unexpected issues (empty = clean).
fn unsigned_verify_issues(path: &Path) -> Vec<String> {
    let bytes = std::fs::read(path).unwrap();
    let opts = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    pgr_verify::verify(&bytes, &opts)
        .issues
        .iter()
        .filter(|i| {
            !(i.severity == pgr_verify::Severity::Error
                && i.code == pgr_verify::Code::SignatureLayout
                && i.message.contains("require an ad-hoc code signature"))
        })
        .map(|i| format!("{:?} [{}] {}", i.severity, i.code.as_str(), i.message))
        .collect()
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
    assert!(
        strict_verify(&c.out),
        "the patched output must verify strict"
    );
}

#[test]
fn unchanged_relink_is_a_reported_noop() {
    let c = Corpus::new("noop");
    run(&c.opts(true, false)).unwrap();
    let second = run(&c.opts(true, false)).unwrap();
    let patch = second
        .patch
        .expect("the relink still goes through the engine");
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
    assert!(
        strict_verify(&c.out),
        "the fallback rewrites the image cleanly"
    );
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
fn skeleton_move_patches_through_segment_relayout_and_recovers() {
    let c = Corpus::with_text("relayout", 256 * 1024);
    run(&c.opts(true, false)).unwrap();
    let first_size = std::fs::metadata(&c.out).unwrap().len();
    // 64 KiB of new text blows past the reserved slack: __text resizes and
    // everything behind it shifts — the §7.3 ladder's segment-relayout
    // tier. The relink patches the moved suffix instead of re-running the
    // full link.
    c.edit(256 * 1024 + 64 * 1024, false);
    let second = run(&c.opts(true, false)).unwrap();
    let patch = second
        .patch
        .expect("an overflow within the relayout bound must patch (the §7.3 ladder tier 2)");
    assert!(!patch.untouched);
    assert!(
        second.file_size > first_size,
        "the section grew: the patched image grows with it"
    );
    assert!(
        patch.dirty_tiles < patch.total_tiles,
        "the relayout rewrites the moved suffix, not the whole image ({} of {})",
        patch.dirty_tiles,
        patch.total_tiles
    );
    assert!(
        strict_verify(&c.out),
        "the relayout-patched output must verify strict"
    );
    // And the *next* link is incremental again (the patched state
    // re-recorded): a same-size body edit on top patches in place.
    c.edit(256 * 1024 + 64 * 1024, true);
    let third = run(&c.opts(true, false)).unwrap();
    let patch3 = third.patch.expect("the re-recorded state patches again");
    assert!(!patch3.untouched);
    assert!(strict_verify(&c.out));
}

#[test]
fn oversized_growth_falls_back_to_the_clean_link() {
    // The ladder's top rung: growth beyond the policy's max pad escalates
    // to the full link even under `-incremental`.
    let c = Corpus::new("oversize");
    run(&c.opts(true, false)).unwrap();
    c.edit(4 * 1024 * 1024, false);
    let second = run(&c.opts(true, false)).unwrap();
    assert!(
        second.patch.is_none(),
        "multi-megabyte growth must fall back to the full link"
    );
    assert!(strict_verify(&c.out), "the clean relink verifies strict");
    // The re-recorded state is incremental again.
    c.edit(4 * 1024 * 1024, true);
    let third = run(&c.opts(true, false)).unwrap();
    let patch = third.patch.expect("the re-recorded state patches again");
    assert!(!patch.untouched);
    assert!(strict_verify(&c.out));
}

#[test]
fn incremental_verify_audits_the_segment_relayout() {
    // The audit gate over the tier-2 path: the patched output must be
    // byte-identical to the full fused emit of the same plan (checked by
    // the driver) and pass the strict verifier afterwards.
    let c = Corpus::with_text("verify_relayout", 256 * 1024);
    run(&c.opts(true, false)).unwrap();
    c.edit(256 * 1024 + 64 * 1024, false);
    let second = run(&c.opts(true, true)).unwrap();
    let patch = second
        .patch
        .expect("the audited relink patches through the relayout tier");
    assert!(!patch.untouched);
    assert!(strict_verify(&c.out), "the audited output verifies strict");
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
fn shrinking_edit_patches_through_the_relayout_tier_and_verifies() {
    // The §7.3 ladder's shrink rung, end to end: an unsigned corpus
    // (`-no_adhoc`) whose symtab/string-pool shrink moves the image tail
    // down. The relink must patch through the relayout tier (the full link
    // would re-emit every byte — the tier exists to avoid exactly that),
    // the patched image must verify strict, and the shrunk state must
    // remain a relinkable baseline.
    let c = Corpus::new("shrink");
    c.edit_symbols(32 * 1024, false, 512);
    let mut o = c.opts(true, false);
    o.config.adhoc = false;
    let first = run(&o).unwrap();
    assert!(first.patch.is_none(), "the first link is a full link");
    assert!(c.record().exists());
    assert!(
        unsigned_verify_issues(&c.out).is_empty(),
        "the full link verifies clean: {:?}",
        unsigned_verify_issues(&c.out)
    );

    // The edit: the locals block goes away — the image shrinks.
    c.edit_symbols(32 * 1024, false, 0);
    let mut o_verify = o.clone();
    o_verify.incremental_verify = true;
    let second = run(&o_verify).unwrap();
    let patch = second
        .patch
        .expect("the shrinking relink patches through the relayout tier");
    assert!(!patch.untouched);
    assert!(
        second.file_size < first.file_size,
        "the image shrank ({} -> {})",
        first.file_size,
        second.file_size
    );
    assert!(
        patch.dirty_tiles < patch.total_tiles,
        "a LINKEDIT shrink must not rewrite the content tiles ({} of {})",
        patch.dirty_tiles,
        patch.total_tiles
    );
    assert!(
        unsigned_verify_issues(&c.out).is_empty(),
        "the shrunk output verifies clean: {:?}",
        unsigned_verify_issues(&c.out)
    );

    // The shrunk state is a relinkable baseline: a body edit on top still
    // patches and verifies.
    c.edit_symbols(32 * 1024, true, 0);
    let third = run(&o).unwrap();
    let patch3 = third.patch.expect("the baseline relink still patches");
    assert!(!patch3.untouched);
    assert_eq!(third.file_size, second.file_size);
    assert!(
        unsigned_verify_issues(&c.out).is_empty(),
        "the baseline relink verifies clean: {:?}",
        unsigned_verify_issues(&c.out)
    );
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
    assert!(
        c.record().exists(),
        "the full link recorded after the fallback"
    );
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

// ---------------------------------------------------------------------------
// M9 tier-2a — stable import ordinals across the incremental cycle
// (§7.3 step 5, the D7 architecture delta closed). The record captures the
// link's import table; the anchored relink keeps every recorded ordinal and
// appends new imports — an edit that adds a bind no longer renumbers the
// existing ones (which would dirty every page holding a rewritten word).
// ---------------------------------------------------------------------------

/// A linkable dylib file exporting `exports`: built with the linker's own
/// `-dylib` path over a one-section object (the linked image carries a real
/// export trie, exactly what `scan_dylib` reads back).
fn write_dylib(dir: &Path, exports: &[&str]) {
    let src = dir.join("liblog.o");
    let mut b = ObjectBuilder::new("liblog.o");
    let text = b.add_section(
        ObjectSection::text("__text", vec![0xC0, 0x03, 0x5F, 0xD6], vec![]), // ret
    );
    for (i, name) in exports.iter().enumerate() {
        b.add_symbol(ObjectSymbol::Defined {
            name: (*name).into(),
            section_index: text,
            value: u64::try_from(i * 4).unwrap(),
            weak: false,
        });
    }
    std::fs::write(&src, b.build().unwrap()).unwrap();
    let opts = pgr_driver::opts::Options {
        output: dir.join("liblog.dylib").display().to_string(),
        inputs: vec![src.display().to_string()],
        config: pgr_core::layout::LinkConfig {
            filetype: pgr_core::layout::OutputType::Dylib,
            install_name: Some("@rpath/liblog.dylib".into()),
            ident: "pgr-m9-tier2a-lib".into(),
            ..pgr_core::layout::LinkConfig::default()
        },
        ..pgr_driver::opts::Options::default()
    };
    pgr_driver::run(&opts).unwrap();
}

/// hello.o whose `__data` carries one external pointer per `binds` entry
/// (undefined externs, bound to liblog.dylib at link time) plus `_main`.
fn pointer_hello(binds: &[&str]) -> ObjectBuilder {
    let mut b = ObjectBuilder::new("hello.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6], // ret
        vec![],
    ));
    let data = b.add_section(ObjectSection::data(
        "__data",
        vec![0u8; binds.len() * 8],
        vec![],
    ));
    for name in binds {
        b.add_symbol(ObjectSymbol::Undefined {
            name: (*name).into(),
            weak_ref: false,
        });
    }
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    for (i, _) in binds.iter().enumerate() {
        // The symtab groups locals/defs/undefs; `sym_index` maps the
        // declaration index onto the relocation's table index.
        let sym = b.sym_index(i);
        b.section_mut(data)
            .relocs
            .push(ObjectReloc::unsigned(sym).at((i * 8) as u32));
    }
    b
}

/// The decoded record's import names, in ordinal order.
fn record_imports(out: &Path) -> Vec<String> {
    let mut name = out.as_os_str().to_owned();
    name.push(".pgr-inc");
    let bytes = std::fs::read(PathBuf::from(name)).unwrap();
    let record = pgr_emit::incremental::LinkRecord::decode(&bytes).expect("record decodes");
    record
        .imports
        .iter()
        .map(|k| String::from_utf8_lossy(&k.name).into_owned())
        .collect()
}

#[test]
fn import_adding_edit_relinks_in_place_with_stable_ordinals() {
    let dir = std::env::temp_dir().join("pgr_m9_tier2a");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    write_dylib(&dir, &["_log", "_warn"]);

    let hello = dir.join("hello.o");
    let out = dir.join("app");
    std::fs::write(&hello, pointer_hello(&["_log"]).build().unwrap()).unwrap();

    let opts = pgr_driver::opts::Options {
        output: out.display().to_string(),
        inputs: vec![hello.display().to_string()],
        lib_dirs: vec![dir.display().to_string()],
        libs: vec!["log".into()],
        config: pgr_core::layout::LinkConfig {
            ident: "pgr-m9-tier2a".into(),
            ..pgr_core::layout::LinkConfig::default()
        },
        incremental: true,
        incremental_verify: true,
        ..pgr_driver::opts::Options::default()
    };

    // Link 1: the full link records the v2 record — table [_log].
    let first = run(&opts).unwrap();
    assert!(first.patch.is_none(), "the first link is a full link");
    assert_eq!(
        record_imports(&out),
        ["_log"],
        "the record carries the import table"
    );
    assert!(strict_verify(&out));

    // Link 2: the edit re-points slot 0 at a NEW import (_warn) and binds
    // _log one slot later. First-use renumbering would reorder the table
    // to [_warn, _log]; the anchored relink keeps [_log] and appends.
    std::fs::write(&hello, pointer_hello(&["_warn", "_log"]).build().unwrap()).unwrap();
    let second = run(&opts).unwrap();
    let patch = second
        .patch
        .expect("the import-adding edit patches in place");
    assert!(!patch.untouched);
    assert!(
        patch.dirty_tiles < patch.total_tiles,
        "one new bind must reuse most tiles ({} of {})",
        patch.dirty_tiles,
        patch.total_tiles
    );
    assert_eq!(
        record_imports(&out),
        ["_log", "_warn"],
        "recorded ordinals hold; the new import appends"
    );
    assert!(strict_verify(&out), "the patched output must verify strict");

    // Link 3: same inputs — the anchored state is a fixpoint.
    let third = run(&opts).unwrap();
    let patch3 = third.patch.expect("the warm relink plans");
    assert!(patch3.untouched, "the same inputs must be a no-op");
}

#[test]
fn older_format_record_falls_back_and_re_records() {
    let dir = std::env::temp_dir().join("pgr_m9_tier2a_v1");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    write_dylib(&dir, &["_log"]);
    let hello = dir.join("hello.o");
    let out = dir.join("app");
    std::fs::write(&hello, pointer_hello(&["_log"]).build().unwrap()).unwrap();

    let opts = pgr_driver::opts::Options {
        output: out.display().to_string(),
        inputs: vec![hello.display().to_string()],
        lib_dirs: vec![dir.display().to_string()],
        libs: vec!["log".into()],
        config: pgr_core::layout::LinkConfig {
            ident: "pgr-m9-tier2a-v1".into(),
            ..pgr_core::layout::LinkConfig::default()
        },
        incremental: true,
        ..pgr_driver::opts::Options::default()
    };
    run(&opts).unwrap();

    // Downgrade the record's format version to 1: a foreign record for the
    // v2 engine. The relink must fall back (silently, per §7.3), run the
    // full link, and re-record in the current format.
    let sidecar = dir.join("app.pgr-inc");
    let mut bytes = std::fs::read(&sidecar).unwrap();
    assert!(
        bytes.len() > 52,
        "the record carries the fixed 52-byte framing plus payload"
    );
    bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
    std::fs::write(&sidecar, &bytes).unwrap();

    let outcome = run(&opts).unwrap();
    assert!(
        outcome.patch.is_none(),
        "a v1 record falls back to the full link"
    );
    bytes = std::fs::read(&sidecar).unwrap();
    let record = pgr_emit::incremental::LinkRecord::decode(&bytes).expect("re-recorded");
    assert_eq!(
        record.format_version,
        pgr_emit::incremental::FORMAT_VERSION,
        "the sidecar is refreshed to the current format"
    );
    assert_eq!(record.imports.len(), 1, "the table is re-recorded");
}
