//! M51 — the verifier reads the stack-execution decision: a stack-exec
//! executable verifies strict exactly like the default (the flag is a
//! named `-allow_stack_execute` decision, not a defect), and the
//! structural contract names the genuinely broken shape —
//! `MH_ALLOW_STACK_EXECUTION` on a non-executable image (the fixture
//! control: the kernel gives the privilege to an exec'd main
//! executable's stacks, never to an image it loads itself).

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SymbolSpec, filler};
use pgr_format::consts::{S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ};
use pgr_verify::{Options, verify};

fn opts() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// A minimal legal executable fixture with the stack-exec bit on or off.
fn exec_builder(stack_exec: bool) -> ImageBuilder {
    let mut b = ImageBuilder::executable("m51exec");
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
    if stack_exec {
        b.set_mh_flags(pgr_format::consts::MH_ALLOW_STACK_EXECUTION);
    }
    b
}

/// A minimal legal dylib fixture (the shape the bit must never ride).
fn dylib_builder(stack_exec: bool) -> ImageBuilder {
    let mut b = ImageBuilder::dylib("@rpath/libm51.dylib", "m51");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(0xA5A5, 96),
            relocs: Vec::new(),
        }],
    });
    b.add_symbol(SymbolSpec::Defined {
        name: "_m51_fn".into(),
        section_index: 0,
    });
    if stack_exec {
        b.set_mh_flags(pgr_format::consts::MH_ALLOW_STACK_EXECUTION);
    }
    b
}

// ---- the invariant -----------------------------------------------------------

#[test]
fn a_stack_exec_executable_verifies_strict() {
    let img = exec_builder(true).build().expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the -allow_stack_execute decision verifies like the default: {:?}",
        report.issues
    );
}

#[test]
fn the_default_verifies_strict() {
    let img = exec_builder(false).build().expect("builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the pre-M51 default verifies strict: {:?}",
        report.issues
    );
}

// ---- the broken shape --------------------------------------------------------

#[test]
fn mh_allow_stack_execution_on_a_non_executable_is_named() {
    // The knob cannot produce this shape (the layout refuses it) — the
    // hand-built fixture is the hostile third-party image the
    // structural contract exists to name.
    for (label, bytes) in [
        (
            "dylib",
            dylib_builder(true)
                .build()
                .expect("the dylib fixture builds")
                .bytes,
        ),
        ("bundle", {
            let mut b = ImageBuilder::bundle("m51bundle");
            b.add_segment(SegmentSpec {
                name: "__TEXT".into(),
                maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
                initprot: VM_PROT_READ | VM_PROT_EXECUTE,
                sections: vec![SectionSpec {
                    name: "__text".into(),
                    align_log2: 2,
                    flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
                    data: filler(0xA5A5, 96),
                    relocs: Vec::new(),
                }],
            });
            b.add_symbol(SymbolSpec::Defined {
                name: "_m51_bundle_fn".into(),
                section_index: 0,
            });
            b.set_mh_flags(pgr_format::consts::MH_ALLOW_STACK_EXECUTION);
            b.build().expect("the bundle fixture builds").bytes
        }),
    ] {
        let report = verify(&bytes, &opts());
        assert!(
            report.issues.iter().any(|i| i
                .message
                .contains("MH_ALLOW_STACK_EXECUTION is only meaningful")),
            "the misplaced stack-exec bit is named ({label}): {:?}",
            report.issues
        );
        assert!(
            !report.is_ok(&opts()),
            "strict fails on the misplaced bit ({label})"
        );
    }
}
