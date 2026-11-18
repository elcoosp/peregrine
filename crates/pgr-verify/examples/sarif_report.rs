//! The M69 SARIF interchange, runnable: a valid fixture image and a
//! corrupted twin, verified and rendered into SARIF 2.1.0 — the
//! one-line documents GitHub Code Scanning, IDE problem panels and CI
//! triage read natively (`ruleId` the stable code token, `level` the
//! severity, the anchor offset as a binary `region.byteOffset`). The
//! valid image's document rides an empty `results` array; the corrupted
//! twin's carries the findings — the exact shape a build gate's
//! `pgr-verify app --json` pipeline would ship.
//!
//! ```sh
//! cargo run -p pgr-verify --example sarif_report
//! ```

fn main() {
    // The valid image: the `verify_report` example's own fixture shape —
    // one `__text` section, the contract's minimum viable executable.
    let mut image = fixture_image();
    let report = pgr_verify::verify(&image, &pgr_verify::Options::default());
    println!("-- the valid image's SARIF (results ride empty):");
    println!("{}", pgr_verify::sarif::render(&report, "hello"));

    // The corrupted twin: the header magic flipped — the parse contract
    // refuses it and the SARIF document carries the finding.
    image[0] = 0xDE;
    let broken = pgr_verify::verify(&image, &pgr_verify::Options::default());
    println!("-- the corrupted twin's SARIF (the findings ride):");
    println!("{}", pgr_verify::sarif::render(&broken, "broken.bin"));
}

/// The `verify_report` example's fixture: a small, valid arm64 executable
/// (one `__text` section of nop padding, a `__got` slot, the entry point
/// — the shapes the verifier's contract checks).
fn fixture_image() -> Vec<u8> {
    use pgr_fixtures::{
        ImageBuilder, ImportsFormat, SectionSpec, SegmentSpec, SlotKind, SymbolSpec, filler,
    };
    use pgr_format::consts::{
        S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE,
    };

    let mut b = ImageBuilder::executable("sarif-report-example");
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
