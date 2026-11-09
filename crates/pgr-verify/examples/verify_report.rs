//! The verifier's library surface, runnable (the README's "natural entry
//! point" for tooling): build a deterministic Mach-O image with
//! `pgr-fixtures`, run `pgr_verify::verify`, and print the report — the
//! exact shape a build system's CI gate consumes.
//!
//! ```sh
//! cargo run -p pgr-verify --example verify_report
//! cargo run -p pgr-verify --example verify_report -- /path/to/image
//! ```

use pgr_fixtures::{
    ImageBuilder, ImportsFormat, SectionSpec, SegmentSpec, SlotKind, SymbolSpec, filler,
};
use pgr_format::consts::{
    S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE,
};

/// A small, valid arm64 executable: one `__text` section (nop padding), a
/// `__got` slot binding to a dylib, chained-fixup imports, an entry point
/// — the shapes the verifier's contract checks.
fn fixture_image() -> Vec<u8> {
    let mut b = ImageBuilder::executable("verify-report-example");
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
    b.build().expect("the deterministic fixture builds").bytes
}

fn main() {
    // Either a path argument (the CI-gate shape: verify a real image) or
    // the deterministic fixture.
    let bytes = match std::env::args().nth(1) {
        Some(path) => {
            std::fs::read(&path).unwrap_or_else(|e| panic!("verify_report: reading {path}: {e}"))
        }
        None => fixture_image(),
    };

    let opts = pgr_verify::Options::default();
    let report = pgr_verify::verify(&bytes, &opts);
    println!(
        "{} segments, {} sections, {} symbols, {} fixup slots, {} hash pages recomputed",
        report.stats.segments,
        report.stats.sections,
        report.stats.symbols,
        report.stats.fixup_slots,
        report.stats.hash_pages
    );
    for issue in &report.issues {
        println!(
            "{:?} [{}] {}",
            issue.severity,
            issue.code.as_str(),
            issue.message
        );
    }
    if report.is_ok(&opts) {
        println!("verdict: pass ({} issue(s))", report.issues.len());
    } else {
        println!("verdict: FAIL (the image breaks the arm64 contract)");
        std::process::exit(1);
    }
    // The example's own smoke gate: the deterministic fixture must verify
    // clean — the library surface answered exactly as the README promises.
    assert!(
        report.is_ok(&opts),
        "the deterministic fixture must verify clean"
    );
}
