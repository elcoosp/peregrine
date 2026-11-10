//! The arm64e-walk consumer example (M10 rung 4, slice 1): the read-side
//! loop the roadmap scopes for the arm64e rung — *build* a
//! `DYLD_CHAINED_PTR_ARM64E` chained executable through the fixture
//! builder's pointer-format knob, *decode* every chain word through the
//! format layer's typed arm64e codec (the two-bit bind/auth discriminator,
//! the PAC triple, the 8-byte strides), then *strict-verify* the image —
//! the same verifier gate dyld's chain-walk simulation rides. The word
//! family is read-side this slice: Pass 3's producer encoding and the
//! driver surface are the rung's next slice — shipped since: slice 2
//! (`plan_fixups_with_format` + `-fixup_chains_format`) and slice 3
//! (`plan_fixups_with_auth`, the authenticated words this walk reads).
//!
//! Run: `cargo run -p pgr-verify --example arm64e_walk`
//! (`PGR_TRACING=1` installs a subscriber so the walk's contract spans
//! print — the same inert-until-subscriber convention the binaries use).

use pgr_fixtures::{
    ImageBuilder, PointerFormatKind, SectionSpec, SegmentSpec, SlotKind, SymbolSpec, filler,
};
use pgr_format::consts::{
    PLATFORM_MACOS, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ,
    VM_PROT_WRITE,
};
use pgr_format::fixups::ChainWordArm64e;
use pgr_format::header::MachHeader64;
use pgr_format::load_command::{LoadCommandIter, LoadCommandKind};
use pgr_format::segment::SegmentCommand64;
use pgr_verify::{Options, verify};

/// An arm64e chained executable: one auth rebase into `__text`, one auth
/// bind on the import — the shapes the rung's walker accepts.
fn arm64e_exec() -> Vec<u8> {
    let mut b = ImageBuilder::executable("arm64e-walk");
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
        SlotKind::AuthRebase {
            offset: 0x40,
            diversity: 0x1234,
            addr_div: true,
            key: 2,
        },
        SlotKind::AuthBind {
            sym_index: sym,
            diversity: 0x4321,
            addr_div: false,
            key: 0,
        },
    ]);
    b.set_entry(0x40);
    b.set_pointer_format(PointerFormatKind::Arm64e);
    b.set_build_version(PLATFORM_MACOS, 0x000C_0000, 0x000E_0400);
    b.build().expect("the arm64e fixture builds").bytes
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
            .sections(bytes, SegmentCommand64::SIZE)
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

    let bytes = arm64e_exec();

    // 1. Decode the chain words through the format layer: the __got slots
    //    sit in __DATA_CONST, the builder linked them into one chain per
    //    page, and the words are plain little-endian u64s in the slots.
    let got_at = got_fileoff(&bytes);
    println!("slot  kind         key div addrDiv  next");
    for (i, at) in [got_at, got_at + 8].into_iter().enumerate() {
        let raw = u64::from_le_bytes(bytes[at..at + 8].try_into().expect("file-backed slot"));
        let word = ChainWordArm64e::new(raw);
        let (kind, payload) = if word.is_bind() {
            (
                "auth bind",
                format!("ordinal {}", word.bind_ordinal()),
            )
        } else {
            (
                "auth rebase",
                format!("offset {:#x}", word.auth_rebase_offset()),
            )
        };
        println!(
            "{:<5} {:<12} {:>2} {:#06x} {:>6}  {:>4}  ({payload})",
            i,
            kind,
            word.auth_key(),
            word.auth_diversity(),
            word.auth_addr_div(),
            word.next()
        );
    }

    // 2. The strict verifier closes the loop: the walk strides the same
    //    words in 8-byte units, translates the targets the way dyld does
    //    and recomputes every signature page hash.
    let strict = Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let report = verify(&bytes, &strict);
    assert!(
        report.is_ok(&strict) && report.issues.is_empty(),
        "the arm64e image must verify strict: {:#?}",
        report.issues
    );
    println!(
        "pgr-verify: strict pass clean — {} fixup slot(s) walked in the arm64e family",
        report.stats.fixup_slots
    );
}
