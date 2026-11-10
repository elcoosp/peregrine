//! M10 rung 4, slice 1 — the verifier's arm64e read side (roadmap §10.4
//! row M10): `DYLD_CHAINED_PTR_ARM64E` chains walk under the same closure
//! contract as the 64_OFFSET family — 8-byte strides, VM-address unauth
//! rebase targets, 32-bit auth runtime offsets — and every mutation the
//! walker refuses names the slot it refuses. Before the slice the read
//! side refused the format outright (`pointer format 1 unsupported`), so
//! an arm64e image could not pass `--strict` at all.

use pgr_fixtures::{
    Image, ImageBuilder, PointerFormatKind, SectionSpec, SegmentSpec, SlotKind, SymbolSpec,
    filler,
};
use pgr_format::consts::{
    DYLD_CHAINED_PTR_ARM64E, PLATFORM_IOS, PLATFORM_MACOS, S_REGULAR, S_ATTR_PURE_INSTRUCTIONS,
    VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE,
};
use pgr_format::fixups::ChainWordArm64e;
use pgr_verify::{Code, Options, Severity, verify};

fn strict() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// Signature recompute off: mutation tests patch bytes post-build, so the
/// stale page hashes would drown the chain findings being pinned.
fn structural_only() -> Options {
    Options {
        strict_warnings: true,
        skip_hash_recompute: true,
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

/// An arm64e chained executable born through the builder knob: one auth
/// rebase (into `__text`) and one auth bind (the import), at the macOS
/// chained-fixups floor.
fn arm64e_exec() -> Image {
    let mut b = ImageBuilder::executable("arm64e-gate");
    b.add_segment(text_segment(96));
    b.add_segment(data_const_segment());
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
    b.build().expect("the arm64e fixture builds")
}

/// The `__chain_starts` mirror bytes: u32 pointer format, u32 head count,
/// u32 heads[] (image offsets — file offsets under the constant-delta
/// contract).
fn mirror(fmt: u16, heads: &[u32]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&u32::from(fmt).to_le_bytes());
    b.extend_from_slice(&(heads.len() as u32).to_le_bytes());
    for h in heads {
        b.extend_from_slice(&h.to_le_bytes());
    }
    b
}

#[test]
fn arm64e_chains_verify_strict() {
    let img = arm64e_exec();
    let report = verify(&img.bytes, &strict());
    assert!(
        report.is_ok(&strict()) && report.issues.is_empty(),
        "the arm64e image must verify strict: {:#?}",
        report.issues
    );
    assert_eq!(report.stats.fixup_slots, 2, "both slots counted");
}

#[test]
fn arm64e_words_decode_back_through_the_format_layer() {
    let img = arm64e_exec();
    // The `__got` slots sit in `__DATA_CONST`; their file offsets are the
    // recorded VM addresses minus the executable base delta.
    for (i, addr) in img.map.got_slot_addrs.iter().enumerate() {
        let at = (addr - 0x1_0000_0000) as usize;
        let raw = u64::from_le_bytes(
            img.bytes[at..at + 8]
                .try_into()
                .expect("the slot is file-backed"),
        );
        let word = ChainWordArm64e::new(raw);
        match i {
            0 => {
                assert!(!word.is_bind() && word.is_auth(), "slot 0 is the auth rebase");
                assert_eq!(word.auth_rebase_offset(), 0x40);
                assert_eq!(word.auth_diversity(), 0x1234);
                assert!(word.auth_addr_div());
                assert_eq!(word.auth_key(), 2);
            }
            1 => {
                assert!(word.is_bind() && word.is_auth(), "slot 1 is the auth bind");
                assert_eq!(word.bind_ordinal(), 0, "first import");
                assert_eq!(word.auth_diversity(), 0x4321);
                assert_eq!(word.auth_key(), 0);
            }
            other => panic!("unexpected slot {other}"),
        }
        assert_eq!(word.next(), 0, "a single chain per page terminates at 0");
    }
}

#[test]
fn unauth_arm64e_rebase_targets_translate_as_vmaddrs() {
    let mut b = ImageBuilder::executable("arm64e-unauth");
    b.add_segment(text_segment(96));
    b.add_segment(data_const_segment());
    let ord = b.add_dylib("/usr/lib/libSystem.B.dylib");
    let sym = b.add_symbol(SymbolSpec::Undefined {
        name: "_printf".into(),
        lib_ordinal: ord,
        weak: false,
    });
    b.set_got(vec![
        SlotKind::AuthBind {
            sym_index: sym,
            diversity: 0x4321,
            addr_div: false,
            key: 0,
        },
        SlotKind::Rebase { target: 0x40 },
    ]);
    b.set_entry(0x40);
    b.set_pointer_format(PointerFormatKind::Arm64e);
    b.set_build_version(PLATFORM_MACOS, 0x000C_0000, 0x000E_0400);
    let img = b.build().expect("the unauth fixture builds");
    // The word carries `target + delta` (the VM address dyld subtracts the
    // base from); the walker translates back and stays strict-clean.
    let at = (img.map.got_slot_addrs[1] - 0x1_0000_0000) as usize;
    let raw = u64::from_le_bytes(img.bytes[at..at + 8].try_into().expect("file-backed"));
    let word = ChainWordArm64e::new(raw);
    assert!(!word.is_bind() && !word.is_auth(), "an unauth rebase word");
    assert_eq!(word.rebase_target(), 0x40 + 0x1_0000_0000);
    let report = verify(&img.bytes, &strict());
    assert!(
        report.is_ok(&strict()) && report.issues.is_empty(),
        "the unauth arm64e shape must verify strict: {:#?}",
        report.issues
    );
}

#[test]
fn below_floor_arm64e_still_refuses() {
    let mut b = ImageBuilder::executable("arm64e-below-floor");
    b.add_segment(text_segment(96));
    b.add_segment(data_const_segment());
    let ord = b.add_dylib("/usr/lib/libSystem.B.dylib");
    let sym = b.add_symbol(SymbolSpec::Undefined {
        name: "_printf".into(),
        lib_ordinal: ord,
        weak: false,
    });
    b.set_got(vec![SlotKind::AuthBind {
        sym_index: sym,
        diversity: 1,
        addr_div: false,
        key: 0,
    }]);
    b.set_entry(0x40);
    b.set_pointer_format(PointerFormatKind::Arm64e);
    // iOS 14.0 sits below the iOS 15.0 chained-fixups floor.
    b.set_build_version(PLATFORM_IOS, 0x000E_0000, 0x0010_0000);
    let img = b.build().expect("the below-floor fixture builds");
    let report = verify(&img.bytes, &strict());
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.code == Code::FixupsFloor && i.severity == Severity::Error),
        "the floor gate fires on the arm64e shape too: {:#?}",
        report.issues
    );
}

#[test]
fn mutated_arm64e_bind_ordinal_refuses() {
    let img = arm64e_exec();
    let at = (img.map.got_slot_addrs[1] - 0x1_0000_0000) as usize;
    let word = pgr_format::fixups::encode_arm64e_auth_bind_word(0xffff, 0x4321, false, 0, 0)
        .expect("the mutated word encodes");
    let mut bytes = img.bytes.clone();
    bytes[at..at + 8].copy_from_slice(&word.to_le_bytes());
    let report = verify(&bytes, &structural_only());
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.code == Code::FixupsImport && i.severity == Severity::Error),
        "ordinal 0xffff is beyond the one import: {:#?}",
        report.issues
    );
}

#[test]
fn mutated_arm64e_next_leaves_the_page() {
    let img = arm64e_exec();
    let at = (img.map.got_slot_addrs[0] - 0x1_0000_0000) as usize;
    let word =
        pgr_format::fixups::encode_arm64e_auth_rebase_word(0x40, 0x1234, true, 2, 0x7ff)
            .expect("the mutated word encodes");
    let mut bytes = img.bytes.clone();
    bytes[at..at + 8].copy_from_slice(&word.to_le_bytes());
    let report = verify(&bytes, &structural_only());
    assert!(
        report
            .issues
            .iter()
            .any(|i| i.code == Code::FixupsChain && i.severity == Severity::Error),
        "next 0x7ff strides 0x3ff8 — past the page end: {:#?}",
        report.issues
    );
}

#[test]
fn chain_starts_mirror_agrees_on_arm64e() {
    let base = arm64e_exec();
    // The builder links every slot of a page into one chain, so the
    // payload carries a single head — the first `__got` slot.
    let heads = [chain_head(&base)];
    build_mirror_exec("arm64e-mirror", DYLD_CHAINED_PTR_ARM64E, &heads)
        .map(|img| {
            let report = verify(&img.bytes, &strict());
            assert!(
                report.is_ok(&strict()) && report.issues.is_empty(),
                "the format-1 mirror must agree with the payload: {:#?}",
                report.issues
            );
        })
        .expect("the mirror fixture builds");
}

#[test]
fn chain_starts_mirror_disagreeing_format_refuses() {
    let base = arm64e_exec();
    let heads = [chain_head(&base)];
    // The payload says ARM64E (1); a 64_OFFSET mirror lies.
    build_mirror_exec("arm64e-mirror-wrong-fmt", 6, &heads)
        .map(|img| {
            let report = verify(&img.bytes, &structural_only());
            assert!(
                report
                    .issues
                    .iter()
                    .any(|i| i.code == Code::LinkeditPayload && i.severity == Severity::Error),
                "the mirror's 64_OFFSET format disagrees with the payload's ARM64E: {:#?}",
                report.issues
            );
        })
        .expect("the disagreeing fixture builds");
}

/// The mirror's single head: the first `__got` slot's image offset (its
/// VM address minus the executable base delta).
fn chain_head(img: &Image) -> u32 {
    u32::try_from(img.map.got_slot_addrs[0] - 0x1_0000_0000).expect("the head is a u32 offset")
}

/// An arm64e executable carrying a `__chain_starts` mirror section with
/// the requested pointer format and heads.
fn build_mirror_exec(
    ident: &str,
    fmt: u16,
    heads: &[u32],
) -> Result<Image, pgr_fixtures::BuildError> {
    let mut b = ImageBuilder::executable(ident);
    b.add_segment(SegmentSpec {
        name: "__TEXT".into(),
        maxprot: VM_PROT_READ | VM_PROT_EXECUTE,
        initprot: VM_PROT_READ | VM_PROT_EXECUTE,
        sections: vec![
            SectionSpec {
                name: "__text".into(),
                align_log2: 2,
                flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS,
                data: filler(0xA5A5, 96),
                relocs: Vec::new(),
            },
            SectionSpec {
                name: "__chain_starts".into(),
                align_log2: 2,
                flags: S_REGULAR,
                data: mirror(fmt, heads),
                relocs: Vec::new(),
            },
        ],
    });
    b.add_segment(data_const_segment());
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
    b.build()
}
