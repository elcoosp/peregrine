//! The chain-format floor gate's consumer cycle, runnable (M10 rung 4,
//! slice 5): one corpus, one `-fixup_chains_format arm64e` request, three
//! targets. First the *pre-link* answer a build system reads —
//! `--print-fixup-encoding` reports macOS 11.0 below the chained-fixups
//! floor with its advisory (the plan, not a failure). Then the *link-time*
//! honesty: explicitly naming a chain word family for a below-floor target
//! refuses — the layout would plan the classic opcode streams and the
//! named family would never reach the image (a refusal, never a silently
//! dropped knob) — and the refusal renders as a miette diagnostic whose
//! help names the fix. The two clean paths close the story: the flag-less
//! below-floor link keeps the documented silent fallback (the encoding
//! flips, the fixups do not), and the above-floor arm64e link carries the
//! family through — every image strict-verified.
//!
//! Set `PGR_TRACING=1` to install a subscriber and watch the seams (the
//! flag→config span, the encoding decision, the floor gate's refusal —
//! inert without a subscriber, the workspace convention).
//!
//! ```sh
//! cargo run -p pgr-driver --example chain_format_floor
//! ```

use pgr_driver::opts::{self, Options};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::Severity;
use std::ffi::OsString;

/// A self-contained `main.o` with one rebase slot (`__data`) and one GOT
/// bind (`_printf` via the `.tbd`): both fixup kinds ride every link.
fn printf_main() -> Vec<u8> {
    let text: Vec<u8> = [
        0x9000_0000u32, // adrp x0, _printf@GOTPAGE
        0xF940_0000u32, // ldr x0, [x0, _printf@GOTPAGEOFF]
        0x9400_0000u32, // bl _printf
        0xD65F_03C0u32, // ret
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect();
    let mut b = ObjectBuilder::new("printf_main.o");
    let sect = b.add_section(ObjectSection::text("__text", text, Vec::new()));
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    let main_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    let printf_sym = b.add_symbol(ObjectSymbol::Undefined {
        name: "_printf".into(),
        weak_ref: false,
    });
    let main = b.sym_index(main_sym);
    let printf = b.sym_index(printf_sym);
    b.section_mut(sect).relocs = vec![
        ObjectReloc::got_page21(printf).at(0),
        ObjectReloc::got_pageoff12(printf).at(4),
        ObjectReloc::branch26(printf).at(8),
    ];
    // An UNSIGNED pointer against a *defined* symbol: a pure rebase slot
    // in __data (the bind rides the GOT relocs above).
    b.section_mut(data)
        .relocs
        .push(ObjectReloc::unsigned(main).at(0));
    b.build().unwrap()
}

/// A libSystem-shaped `.tbd` (v4) exporting the printf surface.
fn libsystem_tbd() -> &'static str {
    "--- !tapi-tbd\ntbd-version: 4\ntargets: [ arm64-macos ]\ninstall-name: /usr/lib/libSystem.B.dylib\ncurrent-version: 1.2.3\ncompatibility-version: 1.0.0\nexports:\n  - targets: [ arm64-macos ]\n    symbols: [ _printf, _strlen ]\n...\n"
}

/// Parses one link line (the corpus paths pre-baked) and refuses loudly
/// on a parse error other than the demo's expected ones.
fn parse_args(dir: &std::path::Path, extra: &[&str]) -> Result<Options, opts::OptsError> {
    let obj = dir.join("printf_main.o");
    let tbd = dir.join("libSystem.tbd");
    let mut argv: Vec<OsString> = vec![
        "-o".into(),
        dir.join("out").display().to_string().into(),
    ];
    argv.extend(extra.iter().map(OsString::from));
    argv.push(obj.display().to_string().into());
    argv.push(tbd.display().to_string().into());
    opts::parse(&argv)
}

/// Runs one parsed link and strict-verifies the written image.
fn link_and_verify(opts: &Options, what: &str) {
    pgr_driver::run(opts).unwrap_or_else(|e| panic!("{what}: the link completes: {e}"));
    let image = std::fs::read(&opts.output).unwrap();
    let report = pgr_verify::verify(
        &image,
        &pgr_verify::Options {
            strict_warnings: true,
            skip_hash_recompute: false,
        },
    );
    let errors: Vec<_> = report
        .issues
        .iter()
        .filter(|i| i.severity == Severity::Error)
        .collect();
    assert!(errors.is_empty(), "{what} must verify strict: {errors:?}");
    println!("  strict-verified {what} ({} issues, all clean)", report.issues.len());
}

fn main() {
    // The spans stay inert until a subscriber installs; PGR_TRACING=1
    // turns them into stderr lines (the binaries do the same under their
    // debug envs).
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    let dir = std::env::temp_dir().join(format!("pgr_chain_format_floor_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("printf_main.o"), printf_main()).unwrap();
    std::fs::write(dir.join("libSystem.tbd"), libsystem_tbd()).unwrap();

    // 1. The pre-link answer: macOS 11.0 sits below the chained-fixups
    //    floor, the encoding query says so *before* any link runs, and
    //    the advisory renders with its fix (the plan, not a failure).
    let report = pgr_driver::fixup_encoding_report("macos", "11.0", "12.0")
        .expect("the linked platform queries");
    println!("1. the pre-link answer for macos 11.0 (sdk 12.0):");
    println!("   encoding = {:?}", report.encoding);
    if let Some(advisory) = &report.advisory {
        println!("{:?}", miette::Report::new(advisory.clone()));
    }

    // 2. The link-time honesty: the same target with an *explicitly
    //    named* family refuses — the named family would never reach the
    //    image. The refusal's help names the fix (the miette seam).
    println!("2. the explicit family below the floor:");
    let refused = parse_args(
        &dir,
        &[
            "-fixup_chains_format",
            "arm64e",
            "-platform_version",
            "macos",
            "11.0",
            "12.0",
        ],
    )
    .expect_err("an explicit family refuses a below-floor target");
    println!("{:?}", miette::Report::new(refused));

    // 3. The documented fallback: no family named, the same below-floor
    //    target links the classic opcode streams silently (the encoding
    //    flips, the fixups do not).
    println!("3. the flag-less fallback below the floor:");
    let fallback = parse_args(&dir, &["-platform_version", "macos", "11.0", "12.0"])
        .expect("the flag-less set parses");
    link_and_verify(&fallback, "the classic-stream link");

    // 4. Above the floor the explicit family rides chained fixups.
    println!("4. the explicit family above the floor:");
    let above = dir.join("out_arm64e").display().to_string();
    let mut opts = parse_args(
        &dir,
        &[
            "-fixup_chains_format",
            "arm64e",
            "-platform_version",
            "macos",
            "12.0",
            "14.0",
        ],
    )
    .expect("the above-floor arm64e set parses");
    opts.output = above;
    opts.config.ident = "peregrine-chain-format-floor".into();
    link_and_verify(&opts, "the arm64e link");

    println!("\nThe floor flips the encoding, never the fixups — and an explicitly \
              named family that no image will carry is a refusal, not a silently \
              dropped knob.");
}
