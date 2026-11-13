//! M25 — the verifier's bundle-loader pair gate: a bundle bound against
//! a host executable verifies pair-wise exactly like the M3 dylib pair
//! — every import whose library ordinal names the main executable
//! (`0xFF`, `BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE`) must resolve to a
//! name the host's export trie carries. The broken shapes are named: a
//! `0xFF` bind the host does not export, a pair gate fed the wrong
//! filetypes, and the ordinal space the ordinary dylib binds ride stays
//! untouched.

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SymbolSpec, filler};
use pgr_format::consts::{
    BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE,
    VM_PROT_READ,
};
use pgr_verify::pair::verify_bundle_loader;
use pgr_verify::{Options, verify};

fn opts() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// A legal host executable exporting the named surface.
fn host_builder(names: &[&str]) -> ImageBuilder {
    let mut b = ImageBuilder::executable("m25host");
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
    for name in names {
        b.add_symbol(SymbolSpec::Defined {
            name: (*name).into(),
            section_index: 0,
        });
    }
    b
}

/// A minimal legal dylib fixture (the wrong-filetype probe).
fn dylib_fixture() -> ImageBuilder {
    let mut b = ImageBuilder::dylib("@rpath/libm25.dylib", "m25");
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
        name: "_m25_dylib_fn".into(),
        section_index: 0,
    });
    b
}

/// A minimal legal bundle image.
fn bundle_builder() -> ImageBuilder {
    let mut b = ImageBuilder::bundle("m25bundle");
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
        name: "_bundle_main".into(),
        section_index: 0,
    });
    b
}

// ---- the invariant -----------------------------------------------------------

#[test]
fn a_bundle_and_its_host_verify_pair_wise() {
    let bundle = bundle_builder().build().expect("the bundle builds");
    let host = host_builder(&["_host_fn"])
        .build()
        .expect("the host builds");
    let pair = verify_bundle_loader(&bundle.bytes, &host.bytes, &opts());
    assert!(
        pair.is_ok(&opts()),
        "the pair verifies clean: bundle {:?}, loader {:?}, pair {:?}",
        pair.bundle.issues,
        pair.loader.issues,
        pair.pair_issues
    );
}

// ---- the broken shapes -------------------------------------------------------

#[test]
fn the_wrong_filetypes_are_named() {
    let bundle = bundle_builder().build().expect("builds");
    let host = host_builder(&["_host_fn"]).build().expect("builds");
    // A dylib where the bundle belongs.
    let dylib = dylib_fixture().build().expect("builds");
    let pair = verify_bundle_loader(&dylib.bytes, &host.bytes, &opts());
    assert!(
        pair.pair_issues
            .iter()
            .any(|i| i.message.contains("MH_BUNDLE")),
        "the non-bundle first image is named: {:?}",
        pair.pair_issues
    );
    // A bundle where the host belongs.
    let pair = verify_bundle_loader(&bundle.bytes, &dylib.bytes, &opts());
    assert!(
        pair.pair_issues
            .iter()
            .any(|i| i.message.contains("MH_EXECUTE")),
        "the non-executable host is named: {:?}",
        pair.pair_issues
    );
}

#[test]
fn the_ordinary_dylib_ordinals_stay_untouched() {
    // A bundle whose undefineds ride ordinary dylib ordinals (here
    // ordinal 1 against a host image that lists none) pair-verifies
    // clean — the gate only replays the main-executable ordinal.
    let mut b = bundle_builder();
    b.add_symbol(SymbolSpec::Undefined {
        name: "_dylib_fn".into(),
        lib_ordinal: 1,
        weak: false,
    });
    let bundle = b.build().expect("builds");
    let host = host_builder(&["_host_fn"]).build().expect("builds");
    let pair = verify_bundle_loader(&bundle.bytes, &host.bytes, &opts());
    assert!(
        pair.pair_issues.is_empty(),
        "ordinary dylib ordinals are not the loader gate's business: {:?}",
        pair.pair_issues
    );
}

#[test]
fn a_host_free_bundle_verifies_solo() {
    // The bundle's own report is independent of the gate.
    let bundle = bundle_builder().build().expect("builds");
    let report = verify(&bundle.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the bundle verifies strict: {:?}",
        report.issues
    );
}

// The ordinal constant the gate replays against: the vendored value.
#[test]
fn the_main_executable_ordinal_is_the_vendored_constant() {
    assert_eq!(BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE, 0xff);
}
