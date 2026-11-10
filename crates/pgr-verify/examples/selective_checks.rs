//! The M12 selective surface, runnable: build a deterministic executable,
//! corrupt one code-page byte, and run the whole-image pass beside two
//! selected families — the exact shape a build system uses to fail fast
//! on one contract without paying the full pass on every relink.
//!
//! ```sh
//! cargo run -p pgr-verify --example selective_checks
//! ```
//!
//! `PGR_TRACING=1` installs a subscriber so the selection's `debug`
//! event shows (the workspace's inert-until-subscriber convention):
//!
//! ```sh
//! PGR_TRACING=1 cargo run -p pgr-verify --example selective_checks
//! ```

use pgr_fixtures::{
    Image, ImageBuilder, ImportsFormat, SectionSpec, SegmentSpec, SlotKind, SymbolSpec, filler,
};
use pgr_format::consts::{
    S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE,
};
use pgr_verify::{CheckSet, Options, verify_with_checks};

/// A small, valid arm64 executable: one `__text` section, a `__got`
/// bind slot, chained-fixup imports, an entry point — the shapes the
/// verifier's contract checks.
fn fixture_image() -> Image {
    let mut b = ImageBuilder::executable("selective-checks-example");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(0xC0_FFEE, 64),
            relocs: Vec::new(),
        }],
    });
    b.add_segment(SegmentSpec {
        name: "__DATA_CONST".into(),
        maxprot: VM_PROT_READ | VM_PROT_WRITE,
        initprot: VM_PROT_READ | VM_PROT_WRITE,
        sections: vec![],
    });
    let libsystem = b.add_dylib("/usr/lib/libSystem.B.dylib");
    let printf = b.add_symbol(SymbolSpec::Undefined {
        name: "_printf".into(),
        lib_ordinal: libsystem,
        weak: false,
    });
    b.set_got(vec![SlotKind::Bind {
        sym_index: printf,
        addend: 0,
    }]);
    b.set_entry(0);
    b.set_imports_format(ImportsFormat::Plain);
    b.build().expect("the deterministic fixture builds")
}

/// Flips one byte in `__text`: exactly the page hash for that page goes
/// stale, and nothing else in the image is wrong.
fn corrupt_one_code_byte(bytes: &mut [u8], map: &pgr_fixtures::LayoutMap) {
    let text_off = map
        .sections
        .iter()
        .find(|s| s.name == "__text")
        .expect("the fixture carries __text")
        .fileoff as usize;
    bytes[text_off + 7] ^= 0xff;
}

/// Runs one selection and prints its verdict line.
fn run(label: &str, bytes: &[u8], opts: Options, set: CheckSet) {
    let report = verify_with_checks(bytes, &opts, &set);
    let codes: Vec<&str> = report.issues.iter().map(|i| i.code.as_str()).collect();
    println!(
        "{label:<24} ok={} issues={}",
        report.is_ok(&opts),
        if codes.is_empty() {
            "none".to_owned()
        } else {
            codes.join(",")
        }
    );
}

fn main() {
    // The selection names itself on the tracing seam — inert until a
    // subscriber installs (the binaries do it under their debug envs).
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    let Image { mut bytes, map } = fixture_image();
    corrupt_one_code_byte(&mut bytes, &map);
    let opts = Options::default();

    // The whole-image pass finds everything (here: the stale page hash).
    run("full (verify)", &bytes, opts, CheckSet::all());
    // The signature family alone: the same finding, none of the rest of
    // the pass — fail fast on the one contract that moved.
    run(
        "--checks signature",
        &bytes,
        opts,
        CheckSet::parse("signature").expect("canonical names"),
    );
    // Segments + fixups: the stale hash is invisible to this selection —
    // the complement proves the surface is subtractive, not advisory.
    run(
        "--checks segments,fixups",
        &bytes,
        opts,
        CheckSet::parse("segments,fixups").expect("canonical names"),
    );
}
