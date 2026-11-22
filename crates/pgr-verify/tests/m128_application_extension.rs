//! M128 — the verifier's app-extension-safe backstop: the read-side
//! `check_header` gate accepts the `MH_APP_EXTENSION_SAFE`-bearing
//! shape without warning (the bit is loader-advisory, not a contract
//! the strict verifier gates on — the gate warns on a wrong cputype or
//! an unusual filetype, never on the app-extension bit). The
//! producer's `-application_extension` image verifies strict exactly
//! like the default one.

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
/// builder writes the default flags word (no `MH_APP_EXTENSION_SAFE`
/// bit) — the shape the producer's off face plans.
fn builder() -> ImageBuilder {
    let mut b = ImageBuilder::executable("m128");
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
        name: "_m128_main".into(),
        section_index: 0,
    });
    b
}

/// The byte offset of the flags word inside the 32-byte header (byte 24).
const FLAGS_AT: usize = 24;

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
        flags & pgr_format::consts::MH_APP_EXTENSION_SAFE,
        0,
        "the builder writes no MH_APP_EXTENSION_SAFE bit"
    );
}

#[test]
fn the_app_extension_bit_verifies_strict() {
    // The hostile-but-valid fixture: OR the `MH_APP_EXTENSION_SAFE`
    // bit into the flags word — the shape the producer's
    // `-application_extension` knob plans. The read-side backstop
    // accepts it (the bit is loader-advisory, the gate never warns on
    // it), so the app-extension-safe image verifies strict exactly like
    // the default.
    let mut img = builder().build().expect("the fixture builds");
    let flags = u32::from_le_bytes(img.bytes[FLAGS_AT..FLAGS_AT + 4].try_into().expect("flags"));
    img.bytes[FLAGS_AT..FLAGS_AT + 4]
        .copy_from_slice(&(flags | pgr_format::consts::MH_APP_EXTENSION_SAFE).to_le_bytes());
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
        "the app-extension bit verifies strict (the bit is loader-advisory): {:?}",
        report.issues
    );
    assert!(
        !report
            .issues
            .iter()
            .any(|i| i.message.contains("APP_EXTENSION")),
        "no finding names the app-extension bit: {:?}",
        report.issues
    );
}
