//! M33 — the verifier's symtab contract widens to the private-extern
//! rows the decision names: a kept private external (`N_EXT | N_SECT |
//! N_PEXT`, the form ld64 emits under `-keep_private_externs`) is an
//! honest extdef row and verifies strict; a row whose `N_TYPE` carries
//! no `N_EXT` inside the extdef subrange is the dysymtab lie the
//! fixture knob builds on purpose — the range dyld reads claims a
//! defined external the row is not.

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SymbolSpec, filler};
use pgr_format::consts::{S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ};
use pgr_verify::{Code, Options, Severity, verify};

fn opts() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// A minimal executable with one symbol row shaped by `spec`.
fn exec_with(spec: SymbolSpec) -> ImageBuilder {
    let mut b = ImageBuilder::executable("m33exec");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(0x5AA5, 96),
            relocs: Vec::new(),
        }],
    });
    b.set_entry(0);
    b.add_symbol(spec);
    b
}

// ---- the honest shapes ----------------------------------------------------------

#[test]
fn a_kept_private_external_verifies_strict() {
    // The form `-keep_private_externs` emits: the row stays in the
    // extdef subrange with `N_PEXT` set — an honest defined external.
    let img = exec_with(SymbolSpec::DefinedPrivate {
        name: "_kept_private".into(),
        section_index: 0,
    })
    .build()
    .expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the kept shape verifies strict: {:?}",
        report.issues
    );
    assert!(
        !report.issues.iter().any(|i| i.code == Code::SymbolTable),
        "no symtab findings ride the kept shape: {:?}",
        report.issues
    );
}

// ---- the broken shape (the fixture control) --------------------------------------

#[test]
fn a_misplaced_private_external_is_an_error() {
    // The fixture knob builds the dysymtab lie on purpose: the extdef
    // subrange claims the row but its `N_TYPE` carries no `N_EXT` —
    // the range dyld reads must agree with the rows.
    let img = exec_with(SymbolSpec::MisplacedPrivate {
        name: "_misplaced".into(),
        section_index: 0,
    })
    .build()
    .expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    let finding = report
        .issues
        .iter()
        .find(|i| i.code == Code::SymbolTable && i.severity == Severity::Error)
        .expect("the dysymtab lie is an error");
    assert!(
        finding.message.contains("extdef subrange"),
        "the finding names the range: {}",
        finding.message
    );
}
