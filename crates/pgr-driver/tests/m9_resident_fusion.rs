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
//! * **the audit is served by the daemon** — `-incremental-verify` rides
//!   the wire rung (protocol v4): the daemon's ladder patches, audits its
//!   bytes against the reference emit and hands the verdict across; the
//!   client refuses to ship a failing verdict. Without a daemon the
//!   audited relink stands down to the in-process audit (§7.3).
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

/// `-incremental-verify` is served by the daemon when one is up (M9 GA
/// rung 2, wire v4): the relink patches through the ladder, the audit
/// (byte-identity against the reference emit + the strict verifier) runs
/// inside the session, and the verdict crosses the wire — the output is
/// identical to the audited one-shot cycle and strict.
#[test]
fn incremental_verify_is_served_by_the_daemon() {
    let c = Corpus::new("verify");
    let sock = start_daemon("verify");
    let opts = c.fusion_opts(&sock, true);

    run(&opts).unwrap();
    c.edit(32 * 1024 + 1024, true);
    let second = run(&opts).unwrap();
    let patch = second.patch.expect("the audited relink patches");
    assert!(!patch.untouched);
    let audit = second
        .audit
        .expect("the daemon served the audit on the wire");
    assert!(audit.identity_ok, "the engine contract holds: {audit:?}");
    assert!(audit.verify_ok, "the strict pass is clean: {audit:?}");
    assert!(!audit.healed, "nothing needed healing");

    let baseline = Corpus::new("verify_baseline");
    run(&baseline.plain_opts(true)).unwrap();
    baseline.edit(32 * 1024 + 1024, true);
    let baseline_out = run(&baseline.plain_opts(true)).unwrap();
    assert!(
        baseline_out.audit.is_some(),
        "the in-process audit reports on the same outcome shape"
    );
    assert_eq!(
        c.output_bytes(),
        baseline.output_bytes(),
        "the audited fusion cycle matches the audited one-shot cycle"
    );
    assert!(strict_verify(&c.out));
}

/// Without a daemon the audited relink stands down to the in-process
/// audit — every rung of the ladder stays available (§7.3).
#[test]
fn audited_relink_stands_down_to_the_in_process_audit() {
    let c = Corpus::new("verify_absent");
    let dead_sock = std::env::temp_dir().join(format!(
        "pgr-m9-fusion-verify-absent-{}.sock",
        std::process::id()
    ));
    let opts = c.fusion_opts(&dead_sock, true);

    run(&opts).unwrap();
    c.edit(32 * 1024 + 1024, true);
    let second = run(&opts).unwrap();
    assert!(second.patch.is_some(), "the in-process relink takes over");
    let audit = second
        .audit
        .expect("the in-process audit reports on the outcome");
    assert!(audit.identity_ok && audit.verify_ok, "clean: {audit:?}");
    assert!(strict_verify(&c.out));
}

/// The audit's first catch (M9 GA rung 2): a symbol-heavy corpus (the
/// benches' parse-heavy shape) overflowed the verifier's function-starts
/// delta accumulator because `build_func_starts` emitted absolute offsets
/// into a **delta** stream. The gate: such a corpus full-links AND
/// relinks strict-clean.
#[test]
fn symbol_heavy_corpus_verifies_strict_through_the_audit() {
    let dir = std::env::temp_dir().join("pgr_m9_fusion_symbol_heavy");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let mut inputs = Vec::new();
    for seed in 1..=8u64 {
        inputs.push(dir.join(format!("heavy_{seed}.o")).display().to_string());
        let mut b = pgr_fixtures::ObjectBuilder::new(&format!("heavy_{seed}.o"));
        let text_idx = b.add_section(ObjectSection::text(
            "__text",
            vec![0u8; 16 * 1024],
            Vec::new(),
        ));
        let data_idx = b.add_section(ObjectSection::data("__data", vec![0u8; 8], Vec::new()));
        b.section_mut(data_idx)
            .relocs
            .push(ObjectReloc::unsigned(0).at(0));
        for i in 0..512 {
            b.add_symbol(ObjectSymbol::Defined {
                name: format!("_heavy_fn_{seed}_{i}"),
                section_index: text_idx,
                value: (i * 32) as u64,
                weak: false,
            });
        }
        let ref_seed = if seed == 1 { seed } else { seed - 1 };
        for i in 0..512 {
            b.add_symbol(ObjectSymbol::Undefined {
                name: format!("_heavy_fn_{ref_seed}_{i}"),
                weak_ref: false,
            });
        }
        if seed == 1 {
            b.add_symbol(ObjectSymbol::Defined {
                name: "_main".into(),
                section_index: text_idx,
                value: 0,
                weak: false,
            });
        }
        std::fs::write(dir.join(format!("heavy_{seed}.o")), b.build().unwrap()).unwrap();
    }
    let out = dir.join("heavy_out");
    let opts = pgr_driver::opts::Options {
        output: out.display().to_string(),
        inputs,
        config: pgr_core::layout::LinkConfig {
            ident: "pgr-m9-fusion-heavy".into(),
            ..pgr_core::layout::LinkConfig::default()
        },
        incremental: true,
        incremental_verify: true,
        ..pgr_driver::opts::Options::default()
    };
    let cold = run(&opts).unwrap();
    assert!(cold.patch.is_none(), "the cold link is a full link");
    assert!(strict_verify(&out), "the full link is strict-clean");

    // The audited warm relink over the edited corpus: the audit's
    // identity + strict halves both hold.
    let mut edited = pgr_fixtures::ObjectBuilder::new("heavy_1.o");
    let t = edited.add_section(ObjectSection::text(
        "__text",
        vec![0u8; 16 * 1024],
        Vec::new(),
    ));
    let d = edited.add_section(ObjectSection::data("__data", vec![0xFFu8; 8], Vec::new()));
    edited
        .section_mut(d)
        .relocs
        .push(ObjectReloc::unsigned(0).at(0));
    for i in 0..512 {
        edited.add_symbol(ObjectSymbol::Defined {
            name: format!("_heavy_fn_1_{i}"),
            section_index: t,
            value: (i * 32) as u64,
            weak: false,
        });
    }
    for i in 0..512 {
        edited.add_symbol(ObjectSymbol::Undefined {
            name: format!("_heavy_fn_1_{i}"),
            weak_ref: false,
        });
    }
    edited.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: t,
        value: 0,
        weak: false,
    });
    std::fs::write(dir.join("heavy_1.o"), edited.build().unwrap()).unwrap();
    let second = run(&opts).unwrap();
    let audit = second.audit.expect("the audited relink serves the audit");
    assert!(
        audit.identity_ok && audit.verify_ok,
        "the symbol-heavy relink audits clean: {audit:?}"
    );
    assert!(strict_verify(&out));
}

/// The §7.2 output-residency rung (wire v5): the session holds every
/// served image as resident output state, so the warm cycle's previous
/// output never re-crosses the wire; a patched relink serves the
/// changed-tile stream (a fraction of the image), an untouched one ships
/// nothing — and the file the driver writes is still byte-identical to
/// the one-shot cycle (the standing parity gate) and strict-verified.
#[test]
fn resident_output_tiles_close_the_wire_crossing() {
    let c = Corpus::new("tiles");
    let sock = start_daemon("tiles");
    let opts = c.fusion_opts(&sock, false);

    // Cold: a full link through the daemon (capture rides back). The
    // image becomes the session's resident output state.
    let cold = run(&opts).unwrap();
    assert!(cold.patch.is_none(), "the first link is a full link");
    assert!(
        cold.transport.is_none(),
        "a full link carries no tile transport"
    );
    assert!(strict_verify(&c.out));

    // Edit: the daemon's ladder patches; the reply is the tile stream.
    c.edit(32 * 1024 + 1024, true);
    let warm = run(&opts).unwrap();
    let patch = warm.patch.expect("the fusion relink patches");
    assert!(!patch.untouched);
    let tiles = match warm.transport.expect("the tiles rung serves a transport") {
        pgr_daemon::Transport::Tiles { tiles, bytes } => (tiles, bytes),
        pgr_daemon::Transport::Full => panic!("the patched relink serves tiles, got Full"),
    };
    assert!(tiles.0 > 0, "the edited tiles crossed");
    assert!(
        tiles.1 < warm.file_size,
        "the stream is a fraction of the image ({} of {})",
        tiles.1,
        warm.file_size
    );
    assert!(strict_verify(&c.out));

    // Parity: the same steps through the one-shot cycle write identical
    // bytes (the resident client's tile replay is the file-path twin of
    // the engine's patch).
    let resident_bytes = c.output_bytes();
    let oneshot = Corpus::new("tiles_oneshot");
    oneshot.edit(32 * 1024, false);
    run(&oneshot.plain_opts(false)).unwrap();
    oneshot.edit(32 * 1024 + 1024, true);
    run(&oneshot.plain_opts(false)).unwrap();
    assert_eq!(
        resident_bytes,
        oneshot.output_bytes(),
        "the tile-replayed file is the one-shot cycle's bytes"
    );

    // Untouched: a third run with no edit ships zero bytes and rewrites
    // nothing — the output is already the answer.
    let before = std::fs::metadata(&c.out).unwrap().len();
    let untouched = run(&opts).unwrap();
    let patch = untouched.patch.expect("the untouched relink reports");
    assert!(patch.untouched);
    assert_eq!(
        untouched
            .transport
            .expect("the untouched relink still reports"),
        pgr_daemon::Transport::Tiles { tiles: 0, bytes: 0 },
        "nothing crossed the wire"
    );
    assert_eq!(
        std::fs::metadata(&c.out).unwrap().len(),
        before,
        "the output was not rewritten"
    );
}
