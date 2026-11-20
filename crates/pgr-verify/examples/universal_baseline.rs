//! The M96 container baseline gate, runnable: a two-slice `FAT_MAGIC`
//! container recorded once with the `--json` face's own document (one
//! whole-output report line per declared slice), then gated on relink
//! twins — the untouched container passes (every slice's delta clean),
//! the corrupted one is refused by the slice that grew a new finding
//! (the other slice stays clean, the exit gate is every slice's), and
//! the stale document refuses when the container's windows move.
//!
//! The library face a build system drives is
//! [`pgr_verify::parse_container_baseline`] +
//! [`pgr_verify::UniversalDelta::between_slices`]: the M74 refusal (the
//! baseline identity gates one image's offsets, never a slice table)
//! retired with its premise — the slices ride *inside* the audited file,
//! so the container's own `--json` output is the baseline.
//!
//! ```sh
//! cargo run -p pgr-verify --example universal_baseline
//! ```

use std::hint::black_box;

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SymbolSpec, filler, universal_image};
use pgr_format::consts::{
    CPU_TYPE_ARM64, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ,
};
use pgr_verify::{OffsetIdentity, UniversalDelta, parse_container_baseline};

/// A small arm64 dylib slice (an export surface over a `__text` body);
/// `body` sizes the section — past one 16 KiB page the built image's own
/// window grows with it, which is what moves a slice table's rows.
fn dylib_slice(seed: u64, body: usize) -> Vec<u8> {
    let mut b = ImageBuilder::dylib("@rpath/libub.dylib", "universal-baseline");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(seed, body),
            relocs: Vec::new(),
        }],
    });
    b.add_symbol(SymbolSpec::Defined {
        name: "_greet".into(),
        section_index: 0,
    });
    b.build().expect("the fixture dylib builds").bytes
}

/// The baseline document a build system records: the container's own
/// `--json` face output — one whole-output report line per declared
/// slice, in table order.
fn record_document(
    container: &[u8],
    opts: pgr_verify::Options,
    label: &str,
) -> pgr_verify::ContainerBaseline {
    let report = pgr_verify::verify_universal(container, &opts).expect("the container decodes");
    let lines: Vec<String> = report
        .slices
        .iter()
        .enumerate()
        .map(|(i, verdict)| {
            pgr_verify::to_json_with_file(
                &pgr_verify::slice_label(label, i, &verdict.arch),
                &verdict.report,
            )
        })
        .collect();
    parse_container_baseline(&lines.join("\n")).expect("the face's own output parses")
}

/// Gates one relink twin against the recorded document: prints each
/// slice's verdict beside its delta, and returns whether the gate ships.
fn gate(
    twin: &[u8],
    baseline: &pgr_verify::ContainerBaseline,
    opts: pgr_verify::Options,
    label: &str,
) -> bool {
    let report = pgr_verify::verify_universal(twin, &opts).expect("the twin decodes");
    let delta =
        UniversalDelta::between_slices(&report, baseline, &OffsetIdentity).expect("the pairing");
    let mut ships = true;
    for (i, slice) in delta.slices.iter().enumerate() {
        let verdict = &report.slices[i];
        let clean = slice.delta.is_clean();
        ships &= clean;
        println!(
            "{label}[slice {i} at {:#x}, {} bytes]: {}, {} issue(s)",
            verdict.arch.offset,
            verdict.arch.size,
            if clean {
                "no new findings"
            } else {
                "NEW FINDINGS"
            },
            slice.delta.introduced.len(),
        );
        for issue in &slice.delta.introduced {
            let at = issue
                .offset
                .map(|o| format!(" at {o:#x}"))
                .unwrap_or_default();
            println!(
                "    + [{}] {}{at} (new since the baseline)",
                issue.code.as_str(),
                issue.message
            );
        }
    }
    ships
}

fn main() {
    // The workspace's tracing convention: spans surface under PGR_TRACING=1.
    if std::env::var("PGR_TRACING").as_deref() == Ok("1") {
        let _ = tracing_subscriber::fmt().try_init();
    }
    let opts = pgr_verify::Options::default();

    let slice = dylib_slice(0x7071, 128);
    let container = universal_image(&[(&slice, CPU_TYPE_ARM64), (&slice, CPU_TYPE_ARM64)])
        .expect("the container wraps");
    let baseline = record_document(&container, opts, "fat.dylib");
    println!("recorded: {} slice(s) vouched for", baseline.entries.len());

    // The untouched relink: every slice's delta is clean — the gate ships.
    let ships = gate(&container, &baseline, opts, "untouched");
    println!(
        "untouched relink: {}\n",
        if ships { "ships" } else { "refused" }
    );

    // The corrupted twin: one flipped __text byte rides a stale page hash
    // on its own slice — the other slice stays clean, the gate refuses.
    let mut broken = container.clone();
    let parsed = pgr_format::universal::parse_universal(&container).expect("the table decodes");
    let arch = &parsed.arches[0];
    let mid = usize::try_from(arch.offset + arch.size / 2).expect("the window fits usize");
    broken[mid] ^= 0xFF;
    let ships = gate(&broken, &baseline, opts, "corrupted");
    println!(
        "corrupted relink: {}\n",
        if ships { "ships" } else { "refused" }
    );

    // A container whose slice table moved since the recording: the
    // document vouches for windows, not just a count — the pairing
    // refuses before any finding is compared.
    let wide = dylib_slice(0x7072, 0x5000);
    let moved = universal_image(&[(&wide, CPU_TYPE_ARM64), (&slice, CPU_TYPE_ARM64)])
        .expect("the moved container wraps");
    let report = pgr_verify::verify_universal(&moved, &opts).expect("the container decodes");
    match UniversalDelta::between_slices(black_box(&report), &baseline, &OffsetIdentity) {
        Ok(_) => println!("moved container: shipped (unexpected — the windows moved)"),
        Err(e) => println!("moved container: refused\n    {e}"),
    }
}
