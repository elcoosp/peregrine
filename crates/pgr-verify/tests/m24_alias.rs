//! M24 — the alias surface's image contract: the exported alias names
//! ld64's `-alias` creates are *additional symtab rows*, so the
//! symtab's defined-external subrange must keep one row per name — a
//! duplicate external name (the shape a stray alias row or a
//! hand-built image produces) silently shadows: dyld and debuggers read
//! the first row and the second is a different symbol wearing the same
//! name.

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SymbolSpec, filler};
use pgr_format::consts::{S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ};
use pgr_verify::{Options, verify};

fn opts() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// A minimal legal dylib fixture with the named defined externals.
fn dylib_builder(names: &[&str]) -> ImageBuilder {
    let mut b = ImageBuilder::dylib("@rpath/libm24.dylib", "m24");
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
    for name in names {
        b.add_symbol(SymbolSpec::Defined {
            name: (*name).into(),
            section_index: 0,
        });
    }
    b
}

// ---- the invariant -----------------------------------------------------------

#[test]
fn distinct_externals_verify_strict() {
    let img = dylib_builder(&["_m24_one"])
        .build()
        .expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the plain surface verifies like the default: {:?}",
        report.issues
    );
}

// ---- the broken shape --------------------------------------------------------

#[test]
fn a_duplicate_external_name_is_named() {
    // Two symtab rows wearing one name: the alias surface's broken
    // shape (a real link refuses the collision — the verifier gates the
    // image, so a stray row is named wherever it came from).
    let img = dylib_builder(&["_m24_dup", "_m24_dup"])
        .build()
        .expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.issues.iter().any(|i| {
            i.message.contains("duplicate")
                && i.message.contains("_m24_dup")
                && matches!(i.severity, pgr_verify::Severity::Error)
        }),
        "the duplicate external is named: {:?}",
        report.issues
    );
    assert!(!report.is_ok(&opts()), "strict fails on the duplicate name");
}

#[test]
fn repeated_undefined_names_stay_legal() {
    // The contract scopes to the defined-external subrange: two rows
    // *referencing* one name stay legal (only defined externals wear
    // the one-name invariant).
    let mut b = dylib_builder(&["_m24_real"]);
    b.add_symbol(SymbolSpec::Undefined {
        name: "_m24_dyld_lookup".into(),
        lib_ordinal: 1,
        weak: true,
    });
    b.add_symbol(SymbolSpec::Undefined {
        name: "_m24_dyld_lookup".into(),
        lib_ordinal: 1,
        weak: true,
    });
    let img = b.build().expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report
            .issues
            .iter()
            .all(|i| !i.message.contains("duplicate")),
        "repeated undefined names stay legal: {:?}",
        report.issues
    );
}
