//! M74 — the container face's check selection: `verify_universal_with_checks`
//! is the M71 container face composed with the M12 selector surface — the
//! strict pass runs per declared slice over only the named families, so a
//! build gate auditing an SDK's fat dylibs can price a narrowed lane
//! (`--checks signature`) without re-running the whole pass.
//!
//! Gate matrix:
//! * the full set is the M71 face — `verify_universal_with_checks` with
//!   `CheckSet::all()` equals `verify_universal` verdict for verdict;
//! * the narrowed set still gates its own family — a flipped `__text` byte
//!   rides the signature family's page-hash refusal on its slice's verdict;
//! * the narrowed set excludes honestly — a set without `signature` leaves
//!   the same corrupted slice clean (no foreign code rides in);
//! * the malformed table refuses either way — the format reader's
//!   offset-tagged refusal verbatim, the face never invents a report.

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SymbolSpec, filler, universal_image};
use pgr_format::consts::{
    CPU_TYPE_ARM64, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ,
};
use pgr_verify::{CheckSet, Options, verify_universal, verify_universal_with_checks};

fn opts() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// A small arm64 dylib slice (an export surface over a `__text` body).
fn dylib_slice(seed: u64) -> Vec<u8> {
    let mut b = ImageBuilder::dylib("@rpath/libm74.dylib", "m74-universal");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(seed, 128),
            relocs: Vec::new(),
        }],
    });
    b.add_symbol(SymbolSpec::Defined {
        name: "_greet".into(),
        section_index: 0,
    });
    b.build().expect("the fixture dylib builds").bytes
}

/// A two-slice container of real arm64 images (the corrupted byte's
/// finding rides its own slice; the neighbour stays clean).
fn container(first: &[u8], second: &[u8]) -> Vec<u8> {
    universal_image(&[(first, CPU_TYPE_ARM64), (second, CPU_TYPE_ARM64)])
        .expect("the container wraps")
}

#[test]
fn the_full_set_is_the_m71_face_verdict_for_verdict() {
    let bytes = container(&dylib_slice(0x71), &dylib_slice(0x72));
    let opts = opts();
    let full = verify_universal(&bytes, &opts).expect("the container decodes");
    let selected = verify_universal_with_checks(&bytes, &opts, &CheckSet::all())
        .expect("the container decodes");
    assert_eq!(full, selected, "the full set plans the M71 face verbatim");
}

#[test]
fn the_narrowed_set_still_gates_its_own_family() {
    let mut corrupt = dylib_slice(0x71);
    let mid = corrupt.len() / 2;
    corrupt[mid] ^= 0xFF;
    let bytes = container(&corrupt, &dylib_slice(0x72));
    let opts = opts();
    let set = CheckSet::parse("signature").expect("the family parses");
    let report = verify_universal_with_checks(&bytes, &opts, &set).expect("the container decodes");
    assert!(
        !report.is_ok(&opts),
        "the signature family gates the flipped byte"
    );
    let slice_issue = report.slices[0]
        .report
        .issues
        .iter()
        .any(|issue| issue.code.as_str().contains("signature"));
    assert!(slice_issue, "the refusal rides the arm64 slice's verdict");
}

#[test]
fn the_narrowed_set_excludes_honestly() {
    let mut corrupt = dylib_slice(0x71);
    let mid = corrupt.len() / 2;
    corrupt[mid] ^= 0xFF;
    let bytes = container(&corrupt, &dylib_slice(0x72));
    let opts = opts();
    let set = CheckSet::parse("segments,fixups").expect("the families parse");
    let report = verify_universal_with_checks(&bytes, &opts, &set).expect("the container decodes");
    assert!(
        report.is_ok(&opts),
        "the unselected families carry no finding the set can name"
    );
}

#[test]
fn the_malformed_table_refuses_the_selected_set_too() {
    // A fat header promising more slices than the file carries: the
    // decode refuses, selected set or not — a malformed table is a
    // refusal, never a report.
    let mut truncated = Vec::new();
    truncated.extend_from_slice(&0xCAFE_BABEu32.to_be_bytes());
    truncated.extend_from_slice(&7u32.to_be_bytes());
    let opts = opts();
    let set = CheckSet::parse("signature").expect("the family parses");
    let err =
        verify_universal_with_checks(&truncated, &opts, &set).expect_err("the lying count refuses");
    let err_full = verify_universal(&truncated, &opts).expect_err("the lying count refuses");
    assert_eq!(
        format!("{err}"),
        format!("{err_full}"),
        "the selected set refuses with the format reader's own words"
    );
}
