//! M127 — the verifier's interposability backstop: the read-side
//! `check_header` gate accepts the `MH_WEAK_DEFINES | MH_BINDS_TO_WEAK`
//! shape without warning (the bits are loader-advisory, not a contract
//! the strict verifier gates on — the gate warns on a wrong cputype or
//! an unusual filetype, never on the interpose bits). The producer's
//! `-interposable` dylib verifies strict exactly like the default one.

use pgr_fixtures::{ImageBuilder, SectionSpec, SegmentSpec, SymbolSpec, filler};
use pgr_format::consts::{S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ};
use pgr_verify::{Options, verify};

fn opts() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// A minimal executable fixture (one `__TEXT` with `__text`). The
/// builder writes the default flags word (no `MH_WEAK_DEFINES` bit).
fn builder() -> ImageBuilder {
    let mut b = ImageBuilder::executable("m127");
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
        name: "_m127_main".into(),
        section_index: 0,
    });
    b
}

/// The byte offset of the flags word inside the 32-byte header (byte 24).
const FLAGS_AT: usize = 24;

const INTERPOSE_BITS: u32 =
    pgr_format::consts::MH_WEAK_DEFINES | pgr_format::consts::MH_BINDS_TO_WEAK;

// ---- the invariant ------------------------------------------------------------

#[test]
fn the_default_flags_word_verifies_strict() {
    let img = builder().build().expect("the fixture builds");
    let report = verify(&img.bytes, &opts());
    assert!(
        report.is_ok(&opts()),
        "the default flags word verifies strict: {:?}",
        report.issues
    );
    let flags = u32::from_le_bytes(img.bytes[FLAGS_AT..FLAGS_AT + 4].try_into().expect("flags"));
    assert_eq!(
        flags & INTERPOSE_BITS,
        0,
        "the builder writes no interpose bits"
    );
}

#[test]
fn the_interpose_bits_verifies_strict() {
    // The hostile-but-valid fixture: OR the `MH_WEAK_DEFINES |
    // MH_BINDS_TO_WEAK` bits into the flags word — the shape the
    // producer's `-interposable` knob plans. The read-side backstop
    // accepts it (the bits are loader-advisory, the gate never warns on
    // them), so the interposable image verifies strict exactly like the
    // default.
    let mut img = builder().build().expect("the fixture builds");
    let flags = u32::from_le_bytes(img.bytes[FLAGS_AT..FLAGS_AT + 4].try_into().expect("flags"));
    img.bytes[FLAGS_AT..FLAGS_AT + 4].copy_from_slice(&(flags | INTERPOSE_BITS).to_le_bytes());
    // The signature page hashes no longer match the patched bytes —
    // skip the hash recompute so the flags-word finding is the one the
    // gate names (the signature gate is its own contract).
    let no_hash = Options {
        skip_hash_recompute: true,
        ..opts()
    };
    let report = verify(&img.bytes, &no_hash);
    assert!(
        report.is_ok(&no_hash),
        "the interpose bits verify strict (the bits are loader-advisory): {:?}",
        report.issues
    );
    assert!(
        !report.issues.iter().any(|i| i.message.contains("WEAK")),
        "no finding names the interpose bits: {:?}",
        report.issues
    );
}
