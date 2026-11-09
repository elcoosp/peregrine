//! The `pgr` driver as a library, runnable: the same two-step cycle the
//! CLI drives (`-o` then `-incremental`), at the [`pgr_driver::run`] API
//! level — a cold full link that records its emit plan, an edit, then the
//! in-place relink whose [`LinkOutcome`] names what the patch touched and
//! what the `-incremental-verify` audit said. The patched output is
//! checked two ways, the way the repo's own gates do: byte-identity
//! against the full link of the same inputs, and a `pgr-verify` pass.
//!
//! Set `PGR_TRACING=1` to install a tracing subscriber and watch the
//! relink seams emit spans (`resident_relink`, the audit path — inert
//! without a subscriber, the workspace convention).
//!
//! ```sh
//! cargo run -p pgr-driver --example library_link
//! ```

use std::path::{Path, PathBuf};

use pgr_core::layout::LinkConfig;
use pgr_driver::opts::Options;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

/// hello.o: `_main` ADRP+ADD loads `_msg`, BL `_greet`, ret; `body_flip`
/// swaps a mov immediate and the cstring at equal length (the edit the
/// relink patches in place).
fn hello(body_flip: bool) -> Vec<u8> {
    let mut words: Vec<u32> = vec![
        0x9000_0000, // adrp x0, _msg@page
        0x9100_0000, // add x0, x0, #_msg@pageoff
        0x9400_0000, // bl _greet
        0x5280_0000, // mov w0, #0 (flipped: #1 — the edited body)
        0xD65F_03C0, // ret
    ];
    if body_flip {
        words[3] = 0x5280_0020;
    }
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
    b.build().expect("fixture builds")
}

/// greet.o (never edited): `_greet` body.
fn greet() -> Vec<u8> {
    let mut b = ObjectBuilder::new("greet.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("fixture builds")
}

/// The options for one link over the fixture objects on disk.
fn opts(dir: &Path, hello_bytes: &[u8]) -> (Options, PathBuf) {
    let hello_path = dir.join("hello.o");
    std::fs::write(&hello_path, hello_bytes).expect("write hello.o");
    let greet_path = dir.join("greet.o");
    std::fs::write(&greet_path, greet()).expect("write greet.o");
    let opts = Options {
        inputs: vec![
            hello_path.display().to_string(),
            greet_path.display().to_string(),
        ],
        output: dir.join("hello").display().to_string(),
        config: LinkConfig {
            ident: "library-link".into(),
            ..LinkConfig::default()
        },
        ..Options::default()
    };
    (opts, hello_path)
}

fn main() {
    // The relink/audit spans stay inert until a subscriber installs;
    // PGR_TRACING=1 turns them into stderr lines (the binaries do the same
    // under their debug envs). Debug level: the tile diff, the audit and
    // the layout gate all log below info.
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }
    let dir = std::env::temp_dir().join("pgr_driver_library_link");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");

    // 1. The cold link, exactly what `pgr -incremental` does on its first
    //    run: a full Pass 0–5 link — slack-anchored (§7.3 "layout
    //    stability" implies slack for the whole cycle) — whose emit plan
    //    is recorded next to the output (`<output>.pgr-inc`).
    let (mut cold_opts, hello_path) = opts(&dir, &hello(false));
    cold_opts.incremental = true;
    let cold = pgr_driver::run(&cold_opts).expect("cold link");
    println!(
        "cold link: wrote {} ({} bytes, {} fixup slot(s), entryoff {:#x})",
        cold.output, cold.file_size, cold.fixup_slots, cold.entryoff
    );

    // 2. The edit and the relink: `-incremental` (the record drives the
    //    §7.3 ladder) with `-incremental-verify` (the bytes-level audit —
    //    byte-identity against the reference emit plus the strict
    //    verifier — gates the write).
    std::fs::write(&hello_path, hello(true)).expect("edit hello.o");
    let mut relink = cold_opts;
    relink.incremental = true;
    relink.incremental_verify = true;
    let warm = pgr_driver::run(&relink).expect("incremental relink");
    match &warm.patch {
        Some(patch) if patch.untouched => {
            println!(
                "relink: untouched (0 of {} tiles) — the output was left byte-for-byte alone",
                patch.total_tiles
            );
        }
        Some(patch) => {
            println!(
                "relink: {}/{} tile(s) patched, {} bytes written ({}% of the image)",
                patch.dirty_tiles,
                patch.total_tiles,
                patch.bytes_patched,
                patch.bytes_patched * 100 / warm.file_size.max(1)
            );
        }
        None => println!("relink: the ladder fell back to a full link"),
    }
    match &warm.audit {
        Some(audit) => println!(
            "audit: identity {}, strict pass {}, {} healing",
            if audit.identity_ok {
                "held"
            } else {
                "diverged"
            },
            if audit.verify_ok { "clean" } else { "FAILED" },
            if audit.healed { "in-memory" } else { "no" }
        ),
        None => println!("audit: not served"),
    }

    // 3. The consumer-visible proof, twice. First: the patched file is
    //    byte-identical to the full link of the same inputs under the same
    //    cycle config (the slack the `-incremental` cycle implies — the
    //    engine's contract, checked at the driver level). Second: the
    //    bundled verifier re-reads the image the way dyld will.
    let mut full = opts(&dir, &hello(true)).0;
    full.output = dir.join("hello-full").display().to_string();
    full.config.layout_slack = Some(pgr_core::slack::SlackPolicy::default());
    let reference = pgr_driver::link_to_bytes(&full).expect("reference full link");
    let patched = std::fs::read(&warm.output).expect("read patched output");
    assert!(
        patched == reference,
        "the patched output ({} bytes) must be byte-identical to the full link ({} bytes)",
        patched.len(),
        reference.len()
    );
    println!("byte identity: the patch equals the full link of the same inputs");

    let report = pgr_verify::verify(&patched, &pgr_verify::Options::default());
    let blocking: Vec<_> = report
        .issues
        .iter()
        .filter(|i| i.severity == pgr_verify::Severity::Error)
        .collect();
    println!(
        "pgr-verify: {} issue(s), {} blocking — output {}",
        report.issues.len(),
        blocking.len(),
        if blocking.is_empty() {
            "clean"
        } else {
            "REJECTED"
        }
    );
    assert!(blocking.is_empty(), "the verifier must pass the output");
}
