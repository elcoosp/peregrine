//! The chain-family face of the format summary walk: one `__got` shape
//! planned twice — the `DYLD_CHAINED_PTR_64_OFFSET` control and the
//! `DYLD_CHAINED_PTR_ARM64E` family — and [`pgr_format::summarize`]
//! counting each image's fixup slots through the family its payload
//! declares. The walk reads the segment's `pointer_format` (the M10
//! rung-4 seam): the 64 families decode `ChainWord64` words and count
//! 4-byte strides, arm64e decodes `ChainWordArm64e` (bit 62, the auth
//! flag, stays out of the 11-bit `next` field) and counts 8-byte
//! strides, and a format no reader walks refuses with the format named.
//!
//! ```sh
//! cargo run -p pgr-format --example chain_family_summary
//! ```

use pgr_fixtures::{
    ImageBuilder, ImportsFormat, PointerFormatKind, SectionSpec, SegmentSpec, SlotKind, SymbolSpec,
    filler,
};
use pgr_format::consts::{
    S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE,
};

/// One executable fixture whose `__got` chains four bind slots under the
/// named pointer format — the same slot shape both families carry.
fn got_image(fmt: PointerFormatKind) -> Vec<u8> {
    let mut b = ImageBuilder::executable("chain-family-summary");
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(0xBEEF, 64),
            relocs: Vec::new(),
        }],
    });
    b.add_segment(SegmentSpec {
        name: "__DATA_CONST".into(),
        maxprot: VM_PROT_READ | VM_PROT_WRITE,
        initprot: VM_PROT_READ | VM_PROT_WRITE,
        sections: vec![],
    });
    b.add_dylib("/usr/lib/libSystem.B.dylib");
    let undef = b.add_symbol(SymbolSpec::Undefined {
        name: "_printf".into(),
        lib_ordinal: 1,
        weak: false,
    });
    b.set_got(vec![
        SlotKind::Bind {
            sym_index: undef,
            addend: 0,
        },
        SlotKind::Bind {
            sym_index: undef,
            addend: 1,
        },
        SlotKind::Bind {
            sym_index: undef,
            addend: 2,
        },
        SlotKind::Bind {
            sym_index: undef,
            addend: 3,
        },
    ]);
    b.set_entry(0);
    b.set_imports_format(ImportsFormat::Addend64);
    b.set_pointer_format(fmt);
    b.build().expect("the fixture builds").bytes
}

fn main() {
    for (name, fmt) in [
        (
            "DYLD_CHAINED_PTR_64_OFFSET (the 64_OFFSET default)",
            PointerFormatKind::Offset64,
        ),
        (
            "DYLD_CHAINED_PTR_ARM64E (the arm64e family)",
            PointerFormatKind::Arm64e,
        ),
    ] {
        let bytes = got_image(fmt);
        let summary = pgr_format::summarize(&bytes).expect("the declared family walks and counts");
        println!("{name}");
        println!(
            "  file {} bytes  segments {}  symbols {}",
            summary.file_size, summary.segments, summary.symbols
        );
        println!(
            "  chained fixups: {} slot(s) counted through the declared family",
            summary.fixup_slots
        );
    }
}
