//! The M13 baseline gate, runnable: verify an accepted image, save its
//! report as the baseline, corrupt one code-page byte in the relinked
//! image, and let the delta name exactly what moved — the shape a build
//! system uses to gate a relink loop on "no *new* findings" instead of
//! "no findings, ever" (a tolerated warning must not fail every later
//! build).
//!
//! ```sh
//! cargo run -p pgr-verify --example baseline_gate
//! ```
//!
//! `PGR_TRACING=1` installs a subscriber so the delta's `debug` event
//! shows (the workspace's inert-until-subscriber convention):
//!
//! ```sh
//! PGR_TRACING=1 cargo run -p pgr-verify --example baseline_gate
//! ```

use pgr_fixtures::{
    Image, ImageBuilder, ImportsFormat, SectionSpec, SegmentSpec, SlotKind, SymbolSpec, filler,
};
use pgr_format::consts::{
    S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE,
};
use pgr_verify::{
    BaselineDelta, CodeIdentity, OffsetIdentity, Options, parse_report_json, to_json, verify,
};

/// A small, valid arm64 executable: one `__text` section, a `__got`
/// bind slot, chained-fixup imports, an entry point.
fn fixture_image() -> Image {
    let mut b = ImageBuilder::executable("baseline-gate-example");
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

fn main() {
    // The delta names itself on the tracing seam — inert until a
    // subscriber installs (the binaries do it under their debug envs).
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    let opts = Options::default();

    // The accepted image: its report is the baseline (the shape the
    // CLI's `--json` prints, saved next to the output).
    let Image { bytes, map } = fixture_image();
    let baseline_report = verify(&bytes, &opts);
    println!("accepted image: ok={}", baseline_report.is_ok(&opts));
    let baseline_json = to_json(&baseline_report);
    println!(
        "baseline saved: {} bytes of report JSON",
        baseline_json.len()
    );

    // The relinked image: one byte moved. The whole verdict fails —
    // and the baseline gate says *why* and *what*.
    let mut relinked = bytes.clone();
    corrupt_one_code_byte(&mut relinked, &map);
    let relink_report = verify(&relinked, &opts);
    println!(
        "relinked image: ok={} (the whole verdict)",
        relink_report.is_ok(&opts)
    );

    let prev = parse_report_json(&baseline_json).expect("the saved baseline re-parses");

    // The strict reading: the stale hash is at a fixed offset, so the
    // position-aware policy sees one introduced finding.
    let strict = BaselineDelta::between(&prev.issues, &relink_report.issues, &OffsetIdentity);
    println!(
        "offset policy:  {} introduced, {} resolved, {} surviving -> gate {}",
        strict.introduced.len(),
        strict.resolved.len(),
        strict.surviving,
        if strict.is_clean() { "clean" } else { "FAILED" }
    );
    for issue in &strict.introduced {
        println!(
            "  + [{}] {} (at {:?})",
            issue.code.as_str(),
            issue.message,
            issue.offset
        );
    }

    // The moved-finding policy: same codes pass, so a layout shift that
    // relocated the offending byte would keep the finding's identity.
    let loose = BaselineDelta::between(&prev.issues, &relink_report.issues, &CodeIdentity);
    println!(
        "code policy:    {} introduced, {} resolved, {} surviving -> gate {}",
        loose.introduced.len(),
        loose.resolved.len(),
        loose.surviving,
        if loose.is_clean() { "clean" } else { "FAILED" }
    );

    // An unchanged relink is the gate's quiet case: nothing new.
    let unchanged = BaselineDelta::between(&prev.issues, &baseline_report.issues, &OffsetIdentity);
    println!(
        "unchanged:      {} introduced -> gate {}",
        unchanged.introduced.len(),
        if unchanged.is_clean() {
            "clean"
        } else {
            "FAILED"
        }
    );
}
