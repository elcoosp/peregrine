//! The resident lane's arm64e chain words, runnable (M82): a link under
//! `-resident -fixup_chains_format arm64e` — the family is config, the
//! config crosses the wire (the v6 tail byte has mirrored it since M10),
//! and the session's warm pipeline plans it. The parity gate is the
//! rung's own contract: the cold arm64e link and the resident arm64e
//! link plan byte-identical images, and the fixup payload declares the
//! arm64e family in both. The record carries the family now (v7), so the
//! fusion ladder patches arm64e records in place, and a relink naming a
//! different family declines to the full link — which re-plans the
//! family the request named and re-records (`pgr_emit::incremental::
//! LinkRecord::admits`, the one named decision both ladders read).
//!
//! ```sh
//! cargo run -p pgr-driver --example resident_arm64e_link
//! ```

use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// hello.o: `_main` ADRP+ADD loads `_msg`, BL `_greet`, ret — the same
/// reloc shape the M9 fusion fixtures carry (a page pair, a branch, a
/// data pointer), so the arm64e words the image plans are real rebase
/// and bind slots.
fn hello_object() -> Vec<u8> {
    let words: Vec<u32> = vec![
        0x9000_0000, // adrp x0, _msg@page
        0x9100_0000, // add x0, x0, #_msg@pageoff
        0x9400_0000, // bl _greet
        0x5280_0000, // mov w0, #0
        0xD65F_03C0, // ret
    ];
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
    b.add_section(ObjectSection::cstring("hello, peregrine\n"));
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
    b.build().expect("the fixture object builds")
}

/// greet.o (never edited): `_greet` + a `__data` pointer to `_greet`.
fn greet_object() -> Vec<u8> {
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
    b.build().expect("the fixture object builds")
}

/// Starts an in-process daemon on `sock` and waits until it accepts.
fn start_daemon(sock: &std::path::Path) {
    let owned = sock.to_path_buf();
    std::thread::spawn(move || {
        let _ = pgr_daemon::serve(&owned, Duration::from_secs(120));
    });
    for _ in 0..500 {
        if UnixStream::connect(sock).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("daemon socket {} never came up", sock.display());
}

/// The link's argv: the arm64e family, the named lane flags.
fn argv(
    dir: &Path,
    resident: bool,
    incremental: bool,
    family: Option<&str>,
    obj: &Path,
) -> Vec<std::ffi::OsString> {
    let mut argv: Vec<String> = vec![
        "-o".to_string(),
        dir.join("app").display().to_string(),
        "-fixup_chains_format".to_string(),
        family.unwrap_or("arm64e").to_string(),
    ];
    if incremental {
        argv.push("-incremental".to_string());
    }
    if resident {
        argv.push("-resident".to_string());
        argv.push("-resident_socket".to_string());
        argv.push(dir.join("demo.sock").display().to_string());
    }
    argv.push(dir.join("greet.o").display().to_string());
    argv.push(obj.display().to_string());
    argv.iter().map(std::ffi::OsString::from).collect()
}

/// The fixup payload's declared pointer format (the image's own word
/// family): the first segment carrying chain starts names it.
fn payload_family(bytes: &[u8]) -> u16 {
    let hdr = pgr_format::MachHeader64::parse(bytes).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        bytes,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands walk");
    while let Some(cmd) = it.next_command().expect("the commands iterate") {
        if cmd.kind
            == pgr_format::LoadCommandKind::LinkeditData(pgr_format::consts::LC_DYLD_CHAINED_FIXUPS)
        {
            let lc = pgr_format::LinkeditDataCommand::parse(cmd.bytes).expect("the lc parses");
            let at = lc.dataoff as usize;
            let payload = &bytes[at..at + lc.datasize as usize];
            let header = pgr_format::fixups::parse_header(payload).expect("the payload parses");
            let starts_at =
                usize::try_from(header.starts_offset).expect("the starts offset fits usize");
            let starts = pgr_format::fixups::parse_starts_in_image(payload, starts_at)
                .expect("the starts parse");
            for off in &starts.seg_info_offset {
                if *off == 0 {
                    continue;
                }
                let seg_at = starts_at + usize::try_from(*off).expect("the offset fits usize");
                let seg = pgr_format::fixups::parse_starts_in_segment(payload, seg_at)
                    .expect("the segment's starts parse");
                return seg.pointer_format;
            }
            panic!("the payload names no chain starts");
        }
    }
    panic!("the image carries no LC_DYLD_CHAINED_FIXUPS payload");
}

fn main() {
    // The demo runs unobserved by default; `PGR_TRACING=1` installs the
    // house tracing subscriber (the workspace convention).
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt::init();
    }

    let dir = std::env::temp_dir().join("pgr_example_resident_arm64e");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    let obj = dir.join("hello.o");
    std::fs::write(&obj, hello_object()).expect("the object writes");
    std::fs::write(dir.join("greet.o"), greet_object()).expect("the object writes");
    let sock: PathBuf = dir.join("demo.sock");
    start_daemon(&sock);

    // The cold arm64e link: the reference bytes (the payload names the
    // arm64e family — real rebase/bind slots in the auth-family word
    // shape, unauth since the surface carries no signing policy).
    let opts = pgr_driver::opts::parse(&argv(&dir, false, false, None, &obj))
        .expect("the cold argv parses");
    pgr_driver::run(&opts).expect("the cold arm64e link runs");
    let cold = std::fs::read(dir.join("app")).expect("the cold image reads");
    println!(
        "== the cold arm64e link ({} bytes, pointer format {}) ==",
        cold.len(),
        payload_family(&cold)
    );

    // The resident arm64e link: the family rides the config, the
    // session's own walk plans it — the bytes the reply carries are the
    // cold lane's.
    let opts = pgr_driver::opts::parse(&argv(&dir, true, false, None, &obj))
        .expect("the resident argv parses");
    pgr_driver::run(&opts).expect("the resident arm64e link runs");
    let warm = std::fs::read(dir.join("app")).expect("the served image reads");
    println!(
        "== the resident arm64e link ({} bytes, pointer format {}) ==",
        warm.len(),
        payload_family(&warm)
    );
    assert_eq!(
        cold, warm,
        "one family, one walk — either lane, the same bytes"
    );
    println!("== the served image is the cold plan, byte-for-byte ==");

    // The fusion ladder under the family: the record carries the family
    // (v7), the relink patches in place, and a flip relinks through the
    // full link — which re-plans the family the request named.
    let opts = pgr_driver::opts::parse(&argv(&dir, true, true, None, &obj))
        .expect("the fusion argv parses");
    let cold_link = pgr_driver::run(&opts).expect("the recorded fusion link runs");
    assert!(cold_link.patch.is_none(), "the first link is a full link");
    let relink = pgr_driver::run(&opts).expect("the matching relink runs");
    let patch = relink.patch.expect("the matching relink rides the ladder");
    println!(
        "== the arm64e relink rode the ladder (untouched: {}, {} bytes rewritten) ==",
        patch.untouched, patch.bytes_patched
    );
    let record_bytes = std::fs::read(dir.join("app.pgr-inc")).expect("the sidecar record reads");
    let record = pgr_emit::incremental::LinkRecord::decode(&record_bytes)
        .expect("the arm64e record decodes");
    println!(
        "== the record carries the family it encoded: {:?} ==",
        record.chain_word_format
    );

    // The flip: the default family beside the same record. The ladder
    // declines (`LinkRecord::admits`) and the full link plans Offset64.
    let opts = pgr_driver::opts::parse(&argv(&dir, true, true, Some("offset64"), &obj))
        .expect("the flipped argv parses");
    let flipped = pgr_driver::run(&opts).expect("the flipped relink runs");
    assert!(
        flipped.patch.is_none(),
        "the flipped relink declines to the full link"
    );
    let renewed = pgr_emit::incremental::LinkRecord::decode(
        &std::fs::read(dir.join("app.pgr-inc")).expect("the renewed sidecar reads"),
    )
    .expect("the renewed record decodes");
    println!(
        "== the family flip relinked through the full link: the image now plans {:?} ==",
        renewed.chain_word_format
    );

    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_file(&sock);
}
