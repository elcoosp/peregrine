//! M9 GA — resident + incremental fusion (the wire rung): the
//! `pgr -resident -incremental` cycle over real files with a live daemon.
//!
//! The gates:
//!
//! * **the cycle survives the daemon** — the cold link records through the
//!   daemon, an edit relinks through the daemon's §7.3 ladder, an
//!   oversized growth falls back *inside* the daemon to its full link —
//!   which **renews the record** (before this rung the resident full link
//!   returned no record and the incremental cycle silently died) — and
//!   the next edit patches again;
//! * **byte-identity** — the fusion cycle's outputs are byte-identical to
//!   the one-shot incremental cycle's, step for step;
//! * **transparency** — with no daemon reachable the relink stands down
//!   to the in-process path and the output is unchanged;
//! * **the audit stays in-process** — `-incremental-verify` keeps the
//!   relink on the audited path even with a daemon up.
//!
//! The e2e suite's standing rule applies to every output here:
//! `pgr-verify --strict` must pass before the test calls a link finished.

use pgr_driver::run;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::Options as VerifyOptions;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

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
        "merci, peregrine\n"
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

/// One corpus instance: hello.o written fresh and greet.o written once.
struct Corpus {
    dir: PathBuf,
    hello: PathBuf,
    out: PathBuf,
}

impl Corpus {
    /// The tier-1 base size (32 KiB text): edits patch a minority of the
    /// image's tiles.
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("pgr_m9_fusion_{tag}"));
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

    /// `-resident -incremental` options against `sock`.
    fn fusion_opts(&self, sock: &Path, verify: bool) -> pgr_driver::opts::Options {
        let mut opts = self.plain_opts(verify);
        opts.resident = true;
        opts.resident_socket = Some(sock.display().to_string());
        opts
    }

    /// One-shot `-incremental` options (the byte-identity baseline).
    fn plain_opts(&self, verify: bool) -> pgr_driver::opts::Options {
        pgr_driver::opts::Options {
            output: self.out.display().to_string(),
            inputs: vec![
                self.hello.display().to_string(),
                self.dir.join("greet.o").display().to_string(),
            ],
            config: pgr_core::layout::LinkConfig {
                ident: "pgr-m9-fusion".into(),
                ..pgr_core::layout::LinkConfig::default()
            },
            incremental: true,
            incremental_verify: verify,
            ..pgr_driver::opts::Options::default()
        }
    }

    fn record(&self) -> PathBuf {
        let mut name = self.out.clone().into_os_string();
        name.push(".pgr-inc");
        PathBuf::from(name)
    }

    fn output_bytes(&self) -> Vec<u8> {
        std::fs::read(&self.out).unwrap()
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

/// One in-process daemon on a test-unique socket.
fn start_daemon(tag: &str) -> PathBuf {
    let sock = std::env::temp_dir().join(format!("pgr-m9-fusion-{tag}.sock"));
    let _ = std::fs::remove_file(&sock);
    let owned = sock.clone();
    std::thread::spawn(move || {
        let _ = pgr_daemon::serve(&owned, Duration::from_secs(120));
    });
    for _ in 0..500 {
        if UnixStream::connect(&sock).is_ok() {
            return sock;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("daemon socket {} never came up", sock.display());
}

/// The full fusion cycle: cold record → edit → daemon relink → oversized
/// growth (a daemon-internal fallback) → **the cycle patches again**. The
/// last step is the rung's regression gate: before it, the daemon's full
/// link returned no record, the sidecar went stale, and every link after a
/// fallback was a full link forever.
#[test]
fn fusion_cycle_patches_after_a_daemon_fallback() {
    let c = Corpus::new("cycle");
    let sock = start_daemon("cycle");
    let opts = c.fusion_opts(&sock, false);

    // Cold: no record yet — the full link runs (through the daemon) and
    // the capture rides back: the sidecar is born resident.
    let first = run(&opts).unwrap();
    assert!(first.patch.is_none(), "the first link is a full link");
    assert!(c.record().exists(), "the cold resident link records");
    assert!(strict_verify(&c.out));

    // Edit: the daemon's §7.3 ladder relinks — warm POIs, patched bytes
    // crossing the wire, the client writing the file.
    c.edit(32 * 1024 + 1024, true);
    let second = run(&opts).unwrap();
    let patch = second.patch.expect("the fusion relink patches");
    assert!(!patch.untouched);
    assert!(
        patch.bytes_patched < second.file_size,
        "a one-function edit patches a fraction ({} of {})",
        patch.bytes_patched,
        second.file_size
    );
    assert!(strict_verify(&c.out));

    // Structural edit: oversized growth (4 MiB past the anchor) falls
    // back — inside the daemon — to its clean full link, which RENEWS the
    // record. The sidecar must describe the new output exactly.
    let grown_size = 32 * 1024 + 1024 + 4 * 1024 * 1024;
    c.edit(grown_size, true);
    let third = run(&opts).unwrap();
    assert!(third.patch.is_none(), "oversized growth falls back");
    let record_bytes = std::fs::read(c.record()).unwrap();
    let record = pgr_emit::incremental::LinkRecord::decode(&record_bytes)
        .expect("the sidecar decodes after the fallback");
    assert_eq!(
        record.file_size,
        std::fs::metadata(&c.out).unwrap().len(),
        "the renewed record describes the fallback's output"
    );

    // The cycle is alive: the next equal-size edit patches again.
    c.edit(grown_size, false);
    let fourth = run(&opts).unwrap();
    let patch = fourth
        .patch
        .expect("the cycle survives the daemon fallback");
    assert!(!patch.untouched);
    assert!(strict_verify(&c.out), "the post-fallback patch verifies");
}

/// The fusion cycle and the one-shot incremental cycle produce identical
/// bytes at every step — and identical patch shapes where both patch.
#[test]
fn fusion_cycle_matches_the_one_shot_cycle_byte_for_byte() {
    let daemon = start_daemon("bytes");
    let resident = Corpus::new("bytes_resident");
    let oneshot = Corpus::new("bytes_oneshot");

    let edits: Vec<(usize, bool)> = vec![
        (32 * 1024, false),                          // cold full link
        (32 * 1024 + 1024, true),                    // body edit — patches
        (32 * 1024 + 1024 + 4 * 1024 * 1024, true),  // oversized — falls back
        (32 * 1024 + 1024 + 4 * 1024 * 1024, false), // post-fallback edit
    ];
    for (text_bytes, flip) in edits {
        resident.edit(text_bytes, flip);
        oneshot.edit(text_bytes, flip);
        let via_daemon = run(&resident.fusion_opts(&daemon, false)).unwrap();
        let via_oneshot = run(&oneshot.plain_opts(false)).unwrap();
        assert_eq!(
            resident.output_bytes(),
            oneshot.output_bytes(),
            "step {text_bytes}/{flip}: the cycles agree byte for byte"
        );
        assert_eq!(
            via_daemon.patch.is_some(),
            via_oneshot.patch.is_some(),
            "step {text_bytes}/{flip}: the patch shapes agree"
        );
        assert!(strict_verify(&resident.out));
    }
}

/// The daemon-absent shape: the fusion relink stands down, the in-process
/// relink patches, the bytes match the plain one-shot cycle.
#[test]
fn fusion_stands_down_to_the_in_process_relink_without_a_daemon() {
    let c = Corpus::new("absent");
    // A socket nothing listens on (and no pgrd binary beside the test exe):
    // every resident attempt stands down silently.
    let dead_sock =
        std::env::temp_dir().join(format!("pgr-m9-fusion-absent-{}.sock", std::process::id()));
    let opts = c.fusion_opts(&dead_sock, false);

    let first = run(&opts).unwrap();
    assert!(first.patch.is_none());
    assert!(c.record().exists(), "the one-shot fallback still records");

    c.edit(32 * 1024 + 1024, true);
    let second = run(&opts).unwrap();
    let patch = second.patch.expect("the in-process relink takes over");
    assert!(!patch.untouched);

    // The baseline runs the same cycle (cold record, then the same edit)
    // through the plain one-shot path.
    let baseline = Corpus::new("absent_baseline");
    run(&baseline.plain_opts(false)).unwrap();
    baseline.edit(32 * 1024 + 1024, true);
    run(&baseline.plain_opts(false)).unwrap();
    assert_eq!(
        c.output_bytes(),
        baseline.output_bytes(),
        "the stood-down cycle matches the one-shot cycle"
    );
    assert!(strict_verify(&c.out));
}

/// `-incremental-verify` keeps the relink in-process (the audit lives
/// there) even with a daemon up — the output is identical and strict.
#[test]
fn incremental_verify_keeps_the_relink_in_process() {
    let c = Corpus::new("verify");
    let sock = start_daemon("verify");
    let opts = c.fusion_opts(&sock, true);

    run(&opts).unwrap();
    c.edit(32 * 1024 + 1024, true);
    let second = run(&opts).unwrap();
    let patch = second.patch.expect("the audited relink patches");
    assert!(!patch.untouched);

    let baseline = Corpus::new("verify_baseline");
    run(&baseline.plain_opts(true)).unwrap();
    baseline.edit(32 * 1024 + 1024, true);
    run(&baseline.plain_opts(true)).unwrap();
    assert_eq!(
        c.output_bytes(),
        baseline.output_bytes(),
        "the audited fusion cycle matches the audited one-shot cycle"
    );
    assert!(strict_verify(&c.out));
}
