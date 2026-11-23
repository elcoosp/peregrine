//! The x86e-walk consumer example (M10 rung 5, slice 1): the read-side
//! loop the roadmap scopes for the `x86_64` rung — *build* a
//! `DYLD_CHAINED_PTR_64` chained executable through the fixture builder's
//! CPU and pointer-format knobs (the M10 row's "4 KiB constants": the
//! segments pack at the family's 4 KiB page and the fixup payload names
//! it), *decode* every chain word through the format layer's 64 codec
//! (the same word layout as the `64_OFFSET` pair — the rebase target
//! just reads as a VM address), then *strict-verify* the image — the same
//! verifier gate dyld's chain-walk simulation rides, with the walk's
//! rebase translation dispatching on the segment's own pointer format.
//! The link surface stays arm64 this slice (the `-arch` refusal is the
//! honest face); the producer half names the rung's next slice.
//!
//! Run: `cargo run -p pgr-verify --example x86_64_walk`
//! (`PGR_TRACING=1` installs a subscriber so the walk's contract spans
//! print — the same inert-until-subscriber convention the binaries use).

use pgr_fixtures::{
    CpuKind, ImageBuilder, PointerFormatKind, SectionSpec, SegmentSpec, SlotKind, SymbolSpec,
    filler,
};
use pgr_format::consts::{
    PLATFORM_MACOS, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ,
    VM_PROT_WRITE,
};
use pgr_format::fixups::ChainWord64;
use pgr_format::header::MachHeader64;
use pgr_format::load_command::{LoadCommandIter, LoadCommandKind};
use pgr_format::segment::SegmentCommand64;
use pgr_verify::{Options, verify};

/// An `x86_64` chained executable: one VM-address rebase into `__text`, one
/// bind on the import — the shapes the slice's walker accepts, packed at
/// the family's 4 KiB page.
fn x86e_exec() -> Vec<u8> {
    let mut b = ImageBuilder::executable("x86e-walk");
    b.set_cputype(CpuKind::X86_64);
    b.set_pointer_format(PointerFormatKind::Format64);
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
    b.add_segment(SegmentSpec {
        name: "__DATA_CONST".into(),
        maxprot: VM_PROT_READ | VM_PROT_WRITE,
        initprot: VM_PROT_READ | VM_PROT_WRITE,
        sections: vec![],
    });
    let ord = b.add_dylib("/usr/lib/libSystem.B.dylib");
    let sym = b.add_symbol(SymbolSpec::Undefined {
        name: "_printf".into(),
        lib_ordinal: ord,
        weak: false,
    });
    b.set_got(vec![
        SlotKind::Rebase { target: 0x40 },
        SlotKind::Bind {
            sym_index: sym,
            addend: 0,
        },
    ]);
    b.set_entry(0x40);
    b.set_build_version(PLATFORM_MACOS, 0x000C_0000, 0x000E_0400);
    b.build().expect("the x86_64 fixture builds").bytes
}

/// Locates the `__got` section's file offset by walking the load commands
/// the way a hostile reader would.
fn got_fileoff(bytes: &[u8]) -> usize {
    let header = MachHeader64::parse(bytes).expect("the fixture header parses");
    let mut it = LoadCommandIter::new(bytes, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load-command region parses");
    while let Some(cmd) = it.next_command().expect("each load command parses") {
        if cmd.kind != LoadCommandKind::Segment64 {
            continue;
        }
        let seg = SegmentCommand64::parse(cmd.bytes, 0).expect("the segment parses");
        if seg.name() != Ok("__DATA_CONST") {
            continue;
        }
        let sects = seg
            .sections(cmd.bytes, SegmentCommand64::SIZE)
            .expect("the sections parse");
        for s in sects {
            if s.name() == Ok("__got") {
                return s.offset as usize;
            }
        }
    }
    panic!("the fixture carries a __got section");
}

fn main() {
    // The walk's contract spans stay inert until a subscriber installs —
    // the workspace convention (the binaries do it under their debug envs).
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    let bytes = x86e_exec();

    // 1. Decode the chain words through the format layer: the __got slots
    //    sit in __DATA_CONST, the builder linked them into one chain per
    //    page, and the words are plain little-endian u64s in the slots.
    let got_at = got_fileoff(&bytes);
    println!("slot  kind         composed             next");
    for (i, at) in [got_at, got_at + 8].into_iter().enumerate() {
        let raw = u64::from_le_bytes(bytes[at..at + 8].try_into().expect("file-backed slot"));
        let word = ChainWord64::new(raw);
        // The composition the walk reads: high8 << 56 | target — under the
        // 64 family the composed value is a VM address (the 4 GiB image
        // base + the image offset), under 64_OFFSET an image offset.
        let composed = (u64::from(word.rebase_high8()) << 56) | word.rebase_target();
        let (kind, payload) = if word.is_bind() {
            ("bind", format!("ordinal {}", word.bind_ordinal()))
        } else {
            ("rebase", format!("vmaddr {composed:#x}"))
        };
        println!(
            "{:<5} {:<12} {:>18}  {:>4}  ({payload})",
            i,
            kind,
            format!("{composed:#x}"),
            word.next()
        );
    }

    // 2. The strict verifier closes the loop: the walk strides the same
    //    words in 4-byte units, translates the rebase targets the way dyld
    //    reads the 64 family (VM addresses, the below-base refusal armed)
    //    and recomputes every signature page hash.
    let strict = Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let report = verify(&bytes, &strict);
    assert!(
        report.is_ok(&strict) && report.issues.is_empty(),
        "the x86_64 image must verify strict: {:#?}",
        report.issues
    );
    println!(
        "pgr-verify: strict pass clean — {} fixup slot(s) walked in the 64 family",
        report.stats.fixup_slots
    );
}
