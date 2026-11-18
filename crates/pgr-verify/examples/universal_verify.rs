//! The M71 universal-container face, runnable: a `FAT_MAGIC` container
//! carrying one real arm64 slice (and one foreign-arch window), verified
//! slice by slice with `pgr_verify::verify_universal` — then the
//! corrupted twin, where a flipped `__text` byte rides an error-severity
//! issue on its own slice's verdict. The per-slice shape is what a
//! build gate auditing an SDK's fat dylibs wants: *which* slice refuses,
//! named by the table row it rode.
//!
//! ```sh
//! cargo run -p pgr-verify --example universal_verify
//! ```

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SymbolSpec, filler, universal_image};
use pgr_format::consts::{
    CPU_TYPE_ARM64, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ,
};

/// The CPU type the foreign window's table row names (the slice's
/// bytes are never a real arm64 image — its verdict carries the refusal).
const FOREIGN: u32 = 0x0100_0007; // CPU_TYPE_X86_64

/// A small arm64 dylib slice (an export surface over a `__text` body).
fn dylib_slice() -> Vec<u8> {
    let mut b = ImageBuilder::dylib("@rpath/libu.dylib", "universal-example");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(0x7071, 128),
            relocs: Vec::new(),
        }],
    });
    b.add_symbol(SymbolSpec::Defined {
        name: "_greet".into(),
        section_index: 0,
    });
    b.build().expect("the fixture dylib builds").bytes
}

/// Prints one slice's verdict: the table row beside its issue count.
fn print_verdict(prefix: &str, verdict: &pgr_verify::SliceVerdict, opts: pgr_verify::Options) {
    let status = if verdict.report.is_ok(&opts) {
        "ok"
    } else {
        "refused"
    };
    println!(
        "{prefix} cputype {:#x} at offset {:#x} ({} bytes): {status}, {} issue(s)",
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

    // The clean container: one real arm64 slice beside the foreign
    // window (whose verdict honestly refuses — the face reports what
    // the table declares, every slice gets its own story).
    let slice = dylib_slice();
    let foreign = vec![0u8; 64];
    let container = universal_image(&[(&slice, CPU_TYPE_ARM64), (&foreign, FOREIGN)])
        .expect("the container wraps");
    let report = pgr_verify::verify_universal(&container, &opts).expect("the container decodes");
    println!("-- the clean container (2 slices):");
    for verdict in &report.slices {
        print_verdict("  ", verdict, opts);
    }

    // The corrupted twin: one flipped `__text` byte — the page-hash
    // recompute refuses on that slice's verdict alone.
    let mut corrupt = slice.clone();
    let mid = corrupt.len() / 2;
    corrupt[mid] ^= 0xFF;
    let broken = universal_image(&[(corrupt.as_slice(), CPU_TYPE_ARM64), (&foreign, FOREIGN)])
        .expect("the container wraps");
    let broken_report =
        pgr_verify::verify_universal(&broken, &opts).expect("the container decodes");
    println!("-- the corrupted twin (one flipped __text byte):");
    for verdict in &broken_report.slices {
        print_verdict("  ", verdict, opts);
    }
    assert!(
        !broken_report.is_ok(&opts),
        "the corrupted container refuses"
    );
}
