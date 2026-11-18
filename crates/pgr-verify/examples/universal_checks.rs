//! The M74 selected container face, runnable: a two-slice
//! `FAT_MAGIC` container of real arm64 dylibs, verified full and with a
//! narrowed check set (`signature` only) — the per-slice shape a build
//! gate auditing an SDK's fat dylibs wants, priced honestly when the
//! gate only owes one family (`--checks signature` rides the same lane).
//! Then the corrupted twin: the flipped `__text` byte's refusal rides
//! its own slice's verdict under both selections — the narrowed set
//! still gates its own family.

//! ```sh
//! cargo run -p pgr-verify --example universal_checks
//! ```

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SymbolSpec, filler, universal_image};
use pgr_format::consts::{
    CPU_TYPE_ARM64, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ,
};

/// A small arm64 dylib slice (an export surface over a `__text` body).
fn dylib_slice(seed: u64) -> Vec<u8> {
    let mut b = ImageBuilder::dylib("@rpath/libu.dylib", "universal-checks-example");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(0x7071 + seed, 128),
            relocs: Vec::new(),
        }],
    });
    b.add_symbol(SymbolSpec::Defined {
        name: "_greet".into(),
        section_index: 0,
    });
    b.build().expect("the fixture dylib builds").bytes
}

/// Prints one slice's verdict under a named selection: the table row
/// beside its issue count.
fn print_verdict(prefix: &str, selection: &str, verdict: &pgr_verify::SliceVerdict) {
    let opts = pgr_verify::Options::default();
    let status = if verdict.report.is_ok(&opts) {
        "ok"
    } else {
        "refused"
    };
    println!(
        "{prefix} [{selection}] cputype {:#x} at offset {:#x} ({} bytes): {status}, {} issue(s)",
        verdict.arch.cputype,
        verdict.arch.offset,
        verdict.arch.size,
        verdict.report.issues.len()
    );
    for issue in &verdict.report.issues {
        println!(
            "    [{:?}] {}: {}",
            issue.severity,
            issue.code.as_str(),
            issue.message
        );
    }
}

fn main() {
    let opts = pgr_verify::Options::default();
    let signature = pgr_verify::CheckSet::parse("signature").expect("the signature family parses");

    // The clean container: every window is a real arm64 image, so both
    // selections ride clean — the narrowed lane prices one family.
    let a = dylib_slice(0);
    let b = dylib_slice(1);
    let container = universal_image(&[
        (a.as_slice(), CPU_TYPE_ARM64),
        (b.as_slice(), CPU_TYPE_ARM64),
    ])
    .expect("the container wraps");
    let full = pgr_verify::verify_universal(&container, &opts).expect("the container decodes");
    let narrowed = pgr_verify::verify_universal_with_checks(&container, &opts, &signature)
        .expect("the container decodes");
    println!("-- the clean container (2 slices, both selections):");
    for verdict in &full.slices {
        print_verdict("  ", "full", verdict);
    }
    for verdict in &narrowed.slices {
        print_verdict("  ", "signature", verdict);
    }

    // The corrupted twin: one flipped `__text` byte in the first slice —
    // the signature family refuses on that slice's verdict alone, the
    // narrowed selection included (the gate is the family's, the
    // selection only narrows who runs).
    let mut corrupt = a.clone();
    let mid = corrupt.len() / 2;
    corrupt[mid] ^= 0xFF;
    let broken = universal_image(&[
        (corrupt.as_slice(), CPU_TYPE_ARM64),
        (b.as_slice(), CPU_TYPE_ARM64),
    ])
    .expect("the container wraps");
    let broken_narrowed = pgr_verify::verify_universal_with_checks(&broken, &opts, &signature)
        .expect("the container decodes");
    println!("-- the corrupted twin (one flipped __text byte, signature lane):");
    for verdict in &broken_narrowed.slices {
        print_verdict("  ", "signature", verdict);
    }
    assert!(
        !broken_narrowed.is_ok(&opts),
        "the narrowed set still gates its own family"
    );
    assert!(
        !broken_narrowed.slices[0].report.is_ok(&opts)
            && broken_narrowed.slices[1].report.is_ok(&opts),
        "the refusal rides the corrupted slice's verdict, never its neighbour's"
    );
}
