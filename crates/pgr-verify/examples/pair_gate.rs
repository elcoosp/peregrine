//! The M3 pair gate, runnable: an executable and the dylib it binds
//! against, verified cross-image through
//! [`pgr_verify::pair::verify_dylib_pair`] — both images' own reports
//! plus the two-level-namespace contract between them (every bind whose
//! ordinal selects the dylib must resolve to a name the dylib's export
//! trie carries). The honest pair stays clean; the twin dylib that
//! exports `_other` where the executable binds `_greet` is caught, the
//! missing export named at the bind's own slot — the shape ld64's
//! two-level namespace turns into a dyld launch failure.
//!
//! ```sh
//! cargo run -p pgr-verify --example pair_gate
//! ```

use pgr_fixtures::{
    Image, ImageBuilder, PointerFormatKind, SectionSpec, SegmentSpec, SlotKind, SymbolSpec, filler,
};
use pgr_format::consts::{
    PLATFORM_MACOS, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ,
    VM_PROT_WRITE,
};
use pgr_verify::Options;
use pgr_verify::pair::verify_dylib_pair;

fn strict() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

fn text_segment(bytes_len: usize) -> SegmentSpec {
    SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![SectionSpec {
            name: "__text".into(),
            align_log2: 2,
            flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
            data: filler(0xA5A5, bytes_len),
            relocs: Vec::new(),
        }],
    }
}

fn data_const_segment() -> SegmentSpec {
    SegmentSpec {
        name: "__DATA_CONST".into(),
        maxprot: VM_PROT_READ | VM_PROT_WRITE,
        initprot: VM_PROT_READ | VM_PROT_WRITE,
        sections: vec![],
    }
}

/// An executable whose `__got` binds `_greet` from dylib ordinal 1
/// (the `64_OFFSET` chain family — the pair gate replays it family-blind,
/// the arm64e family included).
fn pair_exec() -> Image {
    let mut b = ImageBuilder::executable("pair-gate");
    b.add_segment(text_segment(96));
    b.add_segment(data_const_segment());
    let ord = b.add_dylib("@rpath/libgreet.dylib");
    let sym_index = b.add_symbol(SymbolSpec::Undefined {
        name: "_greet".into(),
        lib_ordinal: ord,
        weak: false,
    });
    b.set_got(vec![SlotKind::Bind {
        sym_index,
        addend: 0,
    }]);
    b.set_entry(0x40);
    b.set_pointer_format(PointerFormatKind::Offset64);
    b.set_build_version(PLATFORM_MACOS, 0x000C_0000, 0x000E_0400);
    b.build().expect("the pair fixture builds")
}

/// The dylib the pair binds against. `exports_greet` decides whether its
/// trie exports `_greet` (the honest shape) or only `_other` (the
/// missing-export refusal the pair gate must catch).
fn greet_dylib(exports_greet: bool) -> Image {
    let mut b = ImageBuilder::dylib("@rpath/libgreet.dylib", "greet-dylib");
    b.add_segment(text_segment(64));
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
    b.build().expect("the greet dylib fixture builds")
}

/// Prints one image's own report (the pair's first half).
fn print_image_report(label: &str, report: &pgr_verify::Report) {
    println!("-- {label} -- {} issue(s)", report.issues.len());
    for issue in &report.issues {
        println!(
            "    {:?} [{}] {}",
            issue.severity,
            issue.code.as_str(),
            issue.message
        );
    }
}

fn main() {
    let exec = pair_exec();

    // The honest pair: the dylib exports what the executable binds.
    let honest = greet_dylib(true);
    let report = verify_dylib_pair(&exec.bytes, &honest.bytes, &strict());
    print_image_report("the executable's own report", &report.exec);
    print_image_report("the dylib's own report", &report.dylib);
    println!(
        "-- the pair contract -- {} cross-image issue(s)",
        report.pair_issues.len()
    );
    for issue in &report.pair_issues {
        println!("    {:?}", issue.message);
    }
    assert!(
        report.is_ok(&strict()),
        "the honest pair verifies clean across both images and the contract"
    );

    // The refusal: the dylib exports `_other`, the executable binds
    // `_greet` — the two-level ordinal resolves to a name the trie does
    // not carry, caught at the bind's own slot.
    let broken = greet_dylib(false);
    let report = verify_dylib_pair(&exec.bytes, &broken.bytes, &strict());
    println!(
        "-- the broken pair -- {} cross-image issue(s):",
        report.pair_issues.len()
    );
    for issue in &report.pair_issues {
        println!(
            "    {:?} [{}] {}",
            issue.severity,
            issue.code.as_str(),
            issue.message
        );
    }
    assert!(
        !report.pair_issues.is_empty(),
        "the missing export is caught"
    );
    assert_eq!(report.error_count(), report.pair_issues.len());
}
