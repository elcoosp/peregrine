//! M10 rung 4, slice 4 — the pair gate walks the arm64e family: the M3
//! dylib+executable pair gate replays the executable's two-level binds for
//! **both** chain word families. Before the slice the walk skipped every
//! segment whose `pointer_format` was not `DYLD_CHAINED_PTR_64_OFFSET`
//! (the deferral §15.4 records), so an arm64e executable binding a name
//! its dylib does not export passed the pair gate silently — the exact
//! R4 contract (TDD §12 M3 row: "every import whose two-level ordinal
//! names the dylib must be exported by the dylib's trie") the gate
//! exists to enforce. The gates here pin the family-blind contract:
//! a missing export is caught under arm64e auth binds *and* the
//! 64_OFFSET control, the 8-byte stride replay reaches the second bind
//! of a chain (a 4-byte assumption lands mid-word and reads garbage),
//! and an honest pair stays clean in both families.

use pgr_fixtures::{
    Image, ImageBuilder, PointerFormatKind, SectionSpec, SegmentSpec, SlotKind, SymbolSpec,
    filler,
};
use pgr_format::consts::{
    PLATFORM_MACOS, S_ATTR_PURE_INSTRUCTIONS, S_REGULAR, VM_PROT_EXECUTE, VM_PROT_READ,
    VM_PROT_WRITE,
};
use pgr_verify::pair::verify_dylib_pair;
use pgr_verify::{Code, Options, Severity};

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

/// An executable whose `__got` binds `bind_names` (in order) from dylib
/// ordinal 1, born in `pf`'s chain word family: auth binds under arm64e,
/// plain binds under 64_OFFSET. Consecutive `__got` slots chain (the
/// builder packs one chain per page), so two binds ride one chain and the
/// second is reachable only through a correct stride replay.
fn pair_exec(pf: PointerFormatKind, bind_names: &[&str]) -> Image {
    let mut b = ImageBuilder::executable("arm64e-pair");
    b.add_segment(text_segment(96));
    b.add_segment(data_const_segment());
    let ord = b.add_dylib("@rpath/libgreet.dylib");
    let sym_indices: Vec<usize> = bind_names
        .iter()
        .map(|name| {
            b.add_symbol(SymbolSpec::Undefined {
                name: (*name).into(),
                lib_ordinal: ord,
                weak: false,
            })
        })
        .collect();
    let slots: Vec<SlotKind> = sym_indices
        .into_iter()
        .map(|sym_index| match pf {
            PointerFormatKind::Arm64e => SlotKind::AuthBind {
                sym_index,
                diversity: 0x1234,
                addr_div: false,
                key: 2,
            },
            PointerFormatKind::Offset64 => SlotKind::Bind {
                sym_index,
                addend: 0,
            },
        })
        .collect();
    b.set_got(slots);
    b.set_entry(0x40);
    b.set_pointer_format(pf);
    b.set_build_version(PLATFORM_MACOS, 0x000C_0000, 0x000E_0400);
    b.build().expect("the pair fixture builds")
}

/// The dylib the pair binds against. `exports_greet` decides whether its
/// trie exports `_greet` (the pair's positive shape) or only `_other`
/// (the missing-export refusal shape the pair gate must catch).
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

/// The core refusal: an arm64e executable whose **authenticated** bind
/// names `_greet` against a dylib that does not export it — the pair
/// gate must name the bind and the missing export. Before the slice the
/// arm64e segment was skipped and this gate failed.
#[test]
fn arm64e_auth_bind_missing_export_is_caught() {
    let exec = pair_exec(PointerFormatKind::Arm64e, &["_greet"]);
    let dylib = greet_dylib(false);
    let pair = verify_dylib_pair(&exec.bytes, &dylib.bytes, &strict());

    // The images themselves are honest; the contract breach is pair-wise.
    assert!(
        pair.exec.is_ok(&strict()),
        "exec verifies clean: {:?}",
        pair.exec
    );
    assert!(
        pair.dylib.is_ok(&strict()),
        "dylib verifies clean: {:?}",
        pair.dylib
    );
    let found = pair
        .pair_issues
        .iter()
        .find(|i| i.severity == Severity::Error && i.code == Code::FixupsImport)
        .unwrap_or_else(|| {
            panic!(
                "the arm64e auth bind's missing export is caught, got {:?}",
                pair.pair_issues
            )
        });
    assert!(found.message.contains("_greet"), "{:?}", found.message);
    assert!(
        found.message.contains("@rpath/libgreet.dylib"),
        "the refusal names the dylib: {:?}",
        found.message
    );
}

/// The stride replay: two auth binds chained in the same page — the
/// second is reachable only if the walk advances in the 8-byte strides
/// the arm64e family's `next` counts (a 4-byte assumption lands
/// mid-word). Both missing exports must be caught.
#[test]
fn arm64e_stride_replay_reaches_the_second_bind() {
    let exec = pair_exec(PointerFormatKind::Arm64e, &["_greet", "_farewell"]);
    let dylib = greet_dylib(false);
    let pair = verify_dylib_pair(&exec.bytes, &dylib.bytes, &strict());
    for name in ["_greet", "_farewell"] {
        assert!(
            pair.pair_issues
                .iter()
                .any(|i| i.severity == Severity::Error && i.message.contains(name)),
            "the second chained bind is replayed: {name} missing from {:?}",
            pair.pair_issues
        );
    }
}

/// The honest pair: the dylib exports the bound name — no pair issue in
/// either family. The positive control for the family-blind walk.
#[test]
fn arm64e_honest_pair_is_clean() {
    let exec = pair_exec(PointerFormatKind::Arm64e, &["_greet"]);
    let dylib = greet_dylib(true);
    let pair = verify_dylib_pair(&exec.bytes, &dylib.bytes, &strict());
    assert!(pair.is_ok(&strict()), "clean arm64e pair: {pair:?}");
    assert_eq!(pair.error_count(), 0, "{pair:?}");
}

/// The 64_OFFSET control keeps its pre-slice contract: a plain bind
/// naming a missing export is caught (it always was), and the honest
/// control pair stays clean.
#[test]
fn offset64_control_keeps_its_contract() {
    let missing = verify_dylib_pair(
        &pair_exec(PointerFormatKind::Offset64, &["_greet"]).bytes,
        &greet_dylib(false).bytes,
        &strict(),
    );
    assert!(
        missing
            .pair_issues
            .iter()
            .any(|i| i.severity == Severity::Error && i.code == Code::FixupsImport),
        "the 64_OFFSET control still catches the missing export: {:?}",
        missing.pair_issues
    );

    let honest = verify_dylib_pair(
        &pair_exec(PointerFormatKind::Offset64, &["_greet"]).bytes,
        &greet_dylib(true).bytes,
        &strict(),
    );
    assert!(honest.is_ok(&strict()), "clean control pair: {honest:?}");
}
