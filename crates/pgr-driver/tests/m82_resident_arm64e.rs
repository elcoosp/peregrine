//! M82 — the resident lane's arm64e chain words: the M10 rung-4 lane
//! contract (`-fixup_chains_format arm64e` rode Offset64 shapes beside
//! `-resident` — the surface's own verdict named the session's reuse
//! gates "planning Offset64 shapes this slice, the v6 wire mirrors the
//! family") flips to service the M80/M81 way: the family is config, the
//! config crosses the wire (the v6 tail byte has mirrored it since M10),
//! and the session's warm pipeline *is* the walk that plans it. The
//! record carries the family now (v7 — the patch cannot renegotiate the
//! word shape in place), `pgr_emit::incremental::LinkRecord::admits` is
//! the named admission both relink ladders read, and a relink whose
//! config names a different family declines to the full link — which
//! re-plans the family the request named and re-records. The fallback
//! story stays honest: either lane, the asked family lands or the run
//! says why it did not.
//!
//! Gate matrix:
//! * the served parity — a resident arm64e link plans the image the cold
//!   arm64e link plans (byte-identical; the fixup payload declares the
//!   arm64e family in both, the strict pass walks the served words);
//! * the fusion ladder — an arm64e record relinks in place, the patched
//!   bytes matching the one-shot cycle's step for step;
//! * the family flip, daemon lane — a relink naming the other family
//!   declines to the full link (no patch runs), which re-plans the asked
//!   family and re-records;
//! * the family flip, in-process lane — the same decline through the
//!   driver's own ladder (the daemon-absent shape).

use pgr_core::fixups::FixupPointerFormat;
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
        let dir = std::env::temp_dir().join(format!("pgr_m82_arm64e_{tag}"));
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

    /// One-shot options with the named chain word family.
    fn plain_opts(&self, family: FixupPointerFormat) -> pgr_driver::opts::Options {
        pgr_driver::opts::Options {
            output: self.out.display().to_string(),
            inputs: vec![
                self.hello.display().to_string(),
                self.dir.join("greet.o").display().to_string(),
            ],
            config: pgr_core::layout::LinkConfig {
                ident: "pgr-m82-arm64e".into(),
                chain_word_format: family,
                ..pgr_core::layout::LinkConfig::default()
            },
            incremental: false,
            ..pgr_driver::opts::Options::default()
        }
    }

    /// `-resident -incremental` options against `sock`, the named family.
    fn fusion_opts(&self, sock: &Path, family: FixupPointerFormat) -> pgr_driver::opts::Options {
        let mut opts = self.plain_opts(family);
        opts.incremental = true;
        opts.resident = true;
        opts.resident_socket = Some(sock.display().to_string());
        opts
    }

    /// `-incremental` (no daemon) options with the named family — the
    /// in-process ladder's shape.
    fn in_process_opts(&self, family: FixupPointerFormat) -> pgr_driver::opts::Options {
        let mut opts = self.plain_opts(family);
        opts.incremental = true;
        opts
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
    let sock = std::env::temp_dir().join(format!("pgr-m82-arm64e-{tag}.sock"));
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

/// The fixup payload's declared pointer format — the image's own word
/// family (`DYLD_CHAINED_PTR_ARM64E` = 1, `DYLD_CHAINED_PTR_64_OFFSET` = 6).
fn payload_family(bytes: &[u8]) -> u16 {
    use pgr_format::LoadCommandKind;
    let hdr = pgr_format::MachHeader64::parse(bytes).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        bytes,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands walk");
    while let Some(cmd) = it.next_command().expect("the commands iterate") {
        if cmd.kind == LoadCommandKind::LinkeditData(pgr_format::consts::LC_DYLD_CHAINED_FIXUPS) {
            let lc = pgr_format::LinkeditDataCommand::parse(cmd.bytes).expect("the lc parses");
            let at = lc.dataoff as usize;
            let payload = &bytes[at..at + lc.datasize as usize];
            let header = pgr_format::fixups::parse_header(payload).expect("the payload parses");
            let starts_at =
                usize::try_from(header.starts_offset).expect("the starts offset fits usize");
            let starts = pgr_format::fixups::parse_starts_in_image(payload, starts_at)
                .expect("the starts parse");
            // The first segment that carries chain starts declares the
            // family the whole payload encodes with (the per-segment
            // offsets count from the starts-in-image block).
            for (i, off) in starts.seg_info_offset.iter().enumerate() {
                if *off == 0 {
                    continue;
                }
                let seg_at = starts_at + usize::try_from(*off).expect("the offset fits usize");
                let seg = pgr_format::fixups::parse_starts_in_segment(payload, seg_at)
                    .unwrap_or_else(|e| panic!("segment {i}'s starts parse: {e}"));
                return seg.pointer_format;
            }
            panic!("the payload names no chain starts");
        }
    }
    panic!("the image carries no LC_DYLD_CHAINED_FIXUPS payload");
}

/// The served parity: a resident arm64e link plans the image the cold
/// arm64e link plans — one family, one walk, either lane. The payload
/// names the arm64e family in both (the service plans real auth-family
/// words, not the Offset64 default), and the strict pass walks the
/// served bytes.
#[test]
fn the_resident_arm64e_link_matches_the_cold_bytes() {
    let dir = std::env::temp_dir().join(format!("pgr_m82_parity_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("greet.o"), greet().build().unwrap()).unwrap();
    std::fs::write(dir.join("hello.o"), hello(4 * 1024, false).build().unwrap()).unwrap();
    let sock = start_daemon("parity");

    let mut cold = pgr_driver::opts::Options {
        output: dir.join("cold").display().to_string(),
        inputs: vec![
            dir.join("hello.o").display().to_string(),
            dir.join("greet.o").display().to_string(),
        ],
        config: pgr_core::layout::LinkConfig {
            ident: "pgr-m82-parity".into(),
            chain_word_format: FixupPointerFormat::Arm64e,
            ..pgr_core::layout::LinkConfig::default()
        },
        ..pgr_driver::opts::Options::default()
    };
    run(&cold).expect("the cold arm64e link runs");
    let cold_bytes = std::fs::read(dir.join("cold")).unwrap();
    assert_eq!(
        payload_family(&cold_bytes),
        pgr_format::consts::DYLD_CHAINED_PTR_ARM64E,
        "the cold image declares the arm64e family"
    );
    assert!(strict_verify(&dir.join("cold")), "the cold image verifies");

    cold.resident = true;
    cold.resident_socket = Some(sock.display().to_string());
    cold.output = dir.join("warm").display().to_string();
    run(&cold).expect("the resident arm64e link runs");
    let warm_bytes = std::fs::read(dir.join("warm")).unwrap();
    assert_eq!(
        cold_bytes, warm_bytes,
        "one family, one walk — either lane, the same bytes"
    );
    assert_eq!(
        payload_family(&warm_bytes),
        pgr_format::consts::DYLD_CHAINED_PTR_ARM64E,
        "the served image declares the arm64e family"
    );
    assert!(
        strict_verify(&dir.join("warm")),
        "the served image verifies"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&sock);
}

/// The fusion ladder under the family: an arm64e record relinks in place
/// (the record now carries the family the patch plans with), and the
/// patched bytes match the one-shot cycle's step for step — the M9
/// byte-identity contract over the arm64e corpus.
#[test]
fn the_fusion_ladder_patches_the_arm64e_record() {
    let daemon = start_daemon("fusion");
    let resident = Corpus::new("fusion_resident");
    let oneshot = Corpus::new("fusion_oneshot");

    let edits: Vec<(usize, bool)> = vec![
        (32 * 1024, false),        // cold full link (the record is born)
        (32 * 1024 + 1024, true),  // body edit — patches in place
        (32 * 1024 + 1024, false), // the edit undone — patches back
    ];
    for (text_bytes, flip) in edits {
        resident.edit(text_bytes, flip);
        oneshot.edit(text_bytes, flip);
        let via_daemon = run(&resident.fusion_opts(&daemon, FixupPointerFormat::Arm64e)).unwrap();
        let via_oneshot = run(&oneshot.in_process_opts(FixupPointerFormat::Arm64e)).unwrap();
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
        assert!(strict_verify(&resident.out), "the served image verifies");
    }
    // The record the ladder patched under names the family it plans with.
    let record_bytes = std::fs::read(resident.record()).unwrap();
    let record = pgr_emit::incremental::LinkRecord::decode(&record_bytes)
        .expect("the arm64e record decodes");
    assert_eq!(
        record.chain_word_format,
        FixupPointerFormat::Arm64e,
        "the record carries the family it encoded"
    );
    let _ = std::fs::remove_dir_all(&resident.dir);
    let _ = std::fs::remove_dir_all(&oneshot.dir);
    let _ = std::fs::remove_file(&daemon);
}

/// The family flip, daemon lane: a relink whose config names a different
/// family than the record's declines to the full link — no patch runs,
/// the full link re-plans the family the request named, and the renewed
/// record carries it (the knob the client asked for is the knob that
/// landed, never a silently patched-over shape).
#[test]
fn a_family_flip_relinks_through_the_full_link() {
    let c = Corpus::new("flip_daemon");
    let sock = start_daemon("flip_daemon");
    let arm64e = c.fusion_opts(&sock, FixupPointerFormat::Arm64e);
    let first = run(&arm64e).unwrap();
    assert!(first.patch.is_none(), "the cold link is a full link");
    assert_eq!(
        payload_family(&c.output_bytes()),
        pgr_format::consts::DYLD_CHAINED_PTR_ARM64E,
        "the record's image is arm64e"
    );

    // The flip: the same inputs, the default family (Offset64). The
    // ladder declines at admission — the patch cannot renegotiate the
    // word shape in place — and the full link plans the asked family.
    let flipped = c.fusion_opts(&sock, FixupPointerFormat::Offset64);
    let second = run(&flipped).unwrap();
    assert!(
        second.patch.is_none(),
        "the flipped relink declines to the full link"
    );
    assert_eq!(
        payload_family(&c.output_bytes()),
        pgr_format::consts::DYLD_CHAINED_PTR_64_OFFSET,
        "the full link planned the family the request named"
    );
    assert!(strict_verify(&c.out), "the re-planned image verifies");
    let record_bytes = std::fs::read(c.record()).unwrap();
    let record = pgr_emit::incremental::LinkRecord::decode(&record_bytes)
        .expect("the renewed record decodes");
    assert_eq!(
        record.chain_word_format,
        FixupPointerFormat::Offset64,
        "the renewed record carries the family that landed"
    );
    let _ = std::fs::remove_dir_all(&c.dir);
    let _ = std::fs::remove_file(&sock);
}

/// The family flip, in-process lane: the driver's own ladder reads the
/// same named admission — the daemon-absent shape declines the same way
/// and the full link re-plans the asked family.
#[test]
fn the_in_process_ladder_declines_a_family_flip() {
    let c = Corpus::new("flip_inprocess");
    let first = run(&c.in_process_opts(FixupPointerFormat::Arm64e)).unwrap();
    assert!(first.patch.is_none(), "the cold link is a full link");
    assert_eq!(
        payload_family(&c.output_bytes()),
        pgr_format::consts::DYLD_CHAINED_PTR_ARM64E,
        "the record's image is arm64e"
    );

    let flipped = c.in_process_opts(FixupPointerFormat::Offset64);
    let second = run(&flipped).unwrap();
    assert!(
        second.patch.is_none(),
        "the flipped relink declines to the full link"
    );
    assert_eq!(
        payload_family(&c.output_bytes()),
        pgr_format::consts::DYLD_CHAINED_PTR_64_OFFSET,
        "the full link planned the family the request named"
    );
    assert!(strict_verify(&c.out), "the re-planned image verifies");
    let record_bytes = std::fs::read(c.record()).unwrap();
    let record = pgr_emit::incremental::LinkRecord::decode(&record_bytes)
        .expect("the renewed record decodes");
    assert_eq!(
        record.chain_word_format,
        FixupPointerFormat::Offset64,
        "the renewed record carries the family that landed"
    );
    let _ = std::fs::remove_dir_all(&c.dir);
}
