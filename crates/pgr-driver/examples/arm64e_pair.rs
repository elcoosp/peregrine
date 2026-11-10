//! The pair gate's consumer cycle, runnable (M10 rung 4, slice 4): an
//! arm64e executable and the dylib it binds against, built with the
//! fixture builder and walked by `pgr_verify::pair::verify_dylib_pair` —
//! the M3 two-level-ordinal replay that since slice 1 skipped every
//! non-`64_OFFSET` segment, and since slice 4 walks both chain word
//! families. Two arm64e pairs: the honest one (the dylib exports
//! `_greet`, the executable's **authenticated** bind names it) verifies
//! clean, and the broken one (the dylib exports only `_other`) is
//! refused — the two-level bind finding rendered as a miette diagnostic
//! with help text, the fix and not just the verdict, the same convention
//! the planner refusals and the below-floor advisory render with. The
//! `64_OFFSET` control pair rides beside them: same contracts, 4-byte
//! strides.
//!
//! Set `PGR_TRACING=1` to install a subscriber and watch the pair
//! replay's spans (`pair bind replay contract` — inert without a
//! subscriber, the workspace convention).
//!
//! ```sh
//! cargo run -p pgr-driver --example arm64e_pair
//! ```

use miette::Diagnostic;
use pgr_fixtures::{
    ImageBuilder, PointerFormatKind, SectionSpec, SegmentSpec, SlotKind, SymbolSpec, filler,
};
use pgr_format::consts::{
    PLATFORM_MACOS, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ,
    VM_PROT_WRITE,
};
use pgr_verify::pair::verify_dylib_pair;
use pgr_verify::{Code, Options, Severity};
use thiserror::Error;

/// The executable's `__text`: filler bytes the entry point and the fixup
/// walk can ride on.
fn text_segment(bytes_len: usize, pattern: u64) -> SegmentSpec {
    SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(pattern, bytes_len),
            relocs: Vec::new(),
        }],
    }
}

/// The `__DATA_CONST` the builder expects behind a `__got`.
fn data_const_segment() -> SegmentSpec {
    SegmentSpec {
        name: "__DATA_CONST".into(),
        maxprot: VM_PROT_READ | VM_PROT_WRITE,
        initprot: VM_PROT_READ | VM_PROT_WRITE,
        sections: vec![],
    }
}

/// An arm64e executable binding `_greet` from dylib ordinal 1 through an
/// authenticated `__got` slot, at the macOS chained-fixups floor.
fn arm64e_exec() -> Vec<u8> {
    let mut b = ImageBuilder::executable("arm64e-pair-demo");
    b.add_segment(text_segment(96, 0xA5));
    b.add_segment(data_const_segment());
    let ord = b.add_dylib("@rpath/libgreet.dylib");
    let sym = b.add_symbol(SymbolSpec::Undefined {
        name: "_greet".into(),
        lib_ordinal: ord,
        weak: false,
    });
    b.set_got(vec![SlotKind::AuthBind {
        sym_index: sym,
        diversity: 0x1234,
        addr_div: false,
        key: 2,
    }]);
    b.set_entry(0x40);
    b.set_pointer_format(PointerFormatKind::Arm64e);
    b.set_build_version(PLATFORM_MACOS, 0x000C_0000, 0x000E_0400);
    b.build().expect("the arm64e pair fixture builds").bytes
}

/// A `64_OFFSET` control executable: the same bind, plain word shape.
fn offset64_exec() -> Vec<u8> {
    let mut b = ImageBuilder::executable("offset64-pair-demo");
    b.add_segment(text_segment(96, 0x5A));
    b.add_segment(data_const_segment());
    let ord = b.add_dylib("@rpath/libgreet.dylib");
    let sym = b.add_symbol(SymbolSpec::Undefined {
        name: "_greet".into(),
        lib_ordinal: ord,
        weak: false,
    });
    b.set_got(vec![SlotKind::Bind {
        sym_index: sym,
        addend: 0,
    }]);
    b.set_entry(0x40);
    b.set_pointer_format(PointerFormatKind::Offset64);
    b.set_build_version(PLATFORM_MACOS, 0x000C_0000, 0x000E_0400);
    b.build().expect("the control pair fixture builds").bytes
}

/// The dylib the pairs bind against. `exports_greet` decides whether its
/// export trie carries `_greet` (the honest shape) or only `_other` (the
/// missing-export refusal shape).
fn greet_dylib(exports_greet: bool) -> Vec<u8> {
    let mut b = ImageBuilder::dylib("@rpath/libgreet.dylib", "greet-pair-demo");
    b.add_segment(text_segment(64, 0x77));
    if exports_greet {
        b.add_symbol(SymbolSpec::Defined {
            name: "_greet".into(),
            section_index: 0,
        });
    } else {
        b.add_symbol(SymbolSpec::Defined {
            name: "_other".into(),
            section_index: 0,
        });
    }
    b.set_build_version(PLATFORM_MACOS, 0x000C_0000, 0x000E_0400);
    b.build().expect("the greet dylib fixture builds").bytes
}

/// The pair gate's missing-export finding, re-rendered as a miette
/// diagnostic: the verifier's issue message names the bind and the dylib;
/// the help names the fix. The miette seam the verifier stays out of (its
/// findings are programmatic `Issue`s a tool handles) lands here, at the
/// consumer — the house convention since the first refusal was rendered.
#[derive(Debug, Error, Diagnostic)]
#[error("the pair gate refuses the pair: {0}")]
#[diagnostic(help(
    "the two-level bind names an import the dylib does not export — add \
     the symbol to the dylib's export surface, or bind an ordinal that \
     carries it; the gate replays both chain word families, so a \
     signed-word bind is checked exactly like the plain one"
))]
struct PairRefusal(String);

fn main() {
    // The pair replay's spans stay inert until a subscriber installs;
    // PGR_TRACING=1 turns them into stderr lines (the binaries do the
    // same under their debug envs).
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    let opts = Options::default();
    let exec = arm64e_exec();
    let control_exec = offset64_exec();

    // The honest arm64e pair: the authenticated bind's ordinal resolves
    // against the dylib's trie — clean, both images and the pair checks.
    let honest = verify_dylib_pair(&exec, &greet_dylib(true), &opts);
    println!("arm64e pair, the dylib exports _greet:");
    println!(
        "  clean = {} ({} exec issues, {} dylib issues, {} pair issues)",
        honest.is_ok(&opts),
        honest.exec.issues.len(),
        honest.dylib.issues.len(),
        honest.pair_issues.len(),
    );

    // The refusal: the dylib's trie carries only `_other`, so the signed
    // bind's two-level contract breaches — rendered with the fix.
    let refused = verify_dylib_pair(&exec, &greet_dylib(false), &opts);
    let finding = refused
        .pair_issues
        .iter()
        .find(|i| i.severity == Severity::Error && i.code == Code::FixupsImport)
        .expect("the arm64e replay catches the missing export");
    println!("arm64e pair, the dylib exports only _other:");
    println!(
        "{:?}",
        miette::Report::new(PairRefusal(finding.message.clone()))
    );

    // The 64_OFFSET control: the plain bind is refused the same way (it
    // always was), the honest control pair stays clean.
    let control_refused = verify_dylib_pair(&control_exec, &greet_dylib(false), &opts);
    let control_honest = verify_dylib_pair(&control_exec, &greet_dylib(true), &opts);
    println!("64_OFFSET control:");
    println!(
        "  honest clean = {}; refused findings = {}",
        control_honest.is_ok(&opts),
        control_refused.pair_issues.len(),
    );
}
