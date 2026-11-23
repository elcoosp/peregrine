//! M6/D-R3 (M130) — the `__objc_stubs` synthesis: modern clang emits
//! one per-callsite `_objc_msgSend$<selector>` UNDEFINED symbol; ld64
//! resolves each by synthesizing a stub. Peregrine now does the same,
//! automatically (no flag — like ld64):
//!
//! * a `__TEXT,__objc_stubs` section (one `OBJC_STUB_SIZE_ARM64`-byte
//!   stub per distinct selector) whose stubs load the selector string
//!   (from `__TEXT,__objc_methname`) into `x1`, the IMP (from a
//!   `__DATA_CONST,__got` slot bound to `_objc_msgSend`) into `x16`,
//!   and branch;
//! * a `__TEXT,__objc_methname` section deduping the selector strings
//!   (NUL-terminated, content-addressed like `__cstring`);
//! * a `__got` slot bound to `_objc_msgSend` (the chained-fixup bind
//!   dyld resolves against libobjc at load time);
//! * the call site's `BL` resolves through the stub (the Branch26
//!   redirect, mirroring the dylib-call `__stubs` family);
//! * dead-strip drops unreferenced stubs (a callsite whose caller died
//!   contributes no stub);
//! * the byte-identity lock — a corpus double-links byte-identical;
//! * the verify gate — the linked image verifies strict under the new
//!   `objcstubs` family.
//!
//! Gate matrix mirrors M129's debug-map gate (the same red→green shape
//! the TDD §2 contract names).

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::consts::{OBJC_STUB_SIZE_ARM64, S_SYMBOL_STUBS, SECTION_TYPE_MASK};
use pgr_format::segment::Section64;
use pgr_verify::{Options as VerifyOptions, verify};

/// One object whose `__text` carries `_main` (a RET) and one
/// `objc_msgSend` callsite per selector — the corpus the synthesizer
/// plans `__objc_stubs`/`__objc_methname` for.
fn objc_corpus(selectors: &[&str]) -> Vec<LinkInput> {
    let mut text_bytes: Vec<u8> = vec![0xC0, 0x03, 0x5F, 0xD6]; // _main: ret
    for _ in selectors {
        text_bytes.extend_from_slice(&ObjectBuilder::OBJC_MSGSEND_CALL_BYTES);
    }
    let mut b = ObjectBuilder::new("main.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text("__text", text_bytes, Vec::new()));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    for (i, sel) in selectors.iter().enumerate() {
        // The BL call site lands at offset 4 + i*4 (one word per callsite).
        b.add_objc_msgsend_call(text, 4 + (i as u32) * 4, sel);
    }
    vec![LinkInput {
        name: "main.o".into(),
        bytes: b.build().expect("the fixture object builds"),
    }]
}

/// Links the corpus as an executable with the default config.
fn link_corpus(selectors: &[&str]) -> pgr_core::link::LinkResult {
    let cfg = LinkConfig {
        filetype: OutputType::Execute,
        ident: "m130".into(),
        ..LinkConfig::default()
    };
    link(&objc_corpus(selectors), &[], &cfg).expect("the objc corpus links")
}

/// Finds an output section by `(segment, name)` (the raw walk the
/// verifier reads — `Layout.sections` carries the planned view).
fn section_named(bytes: &[u8], seg: &str, name: &str) -> Option<(Section64, u64)> {
    let hdr = pgr_format::MachHeader64::parse(bytes).ok()?;
    let mut it = pgr_format::LoadCommandIter::new(
        bytes,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .ok()?;
    while let Ok(Some(cmd)) = it.next_command() {
        if cmd.kind != pgr_format::LoadCommandKind::Segment64 || cmd.bytes.len() < 72 {
            continue;
        }
        let seg_cmd = pgr_format::SegmentCommand64::parse(cmd.bytes, 0).ok()?;
        let sects = seg_cmd
            .sections(cmd.bytes, pgr_format::SegmentCommand64::SIZE)
            .ok()?;
        for s in sects {
            let s_name = std::str::from_utf8(&s.sectname)
                .unwrap_or("")
                .trim_end_matches('\0');
            let s_seg = std::str::from_utf8(&s.segname)
                .unwrap_or("")
                .trim_end_matches('\0');
            if s_seg == seg && s_name == name {
                return Some((*s, seg_cmd.fileoff));
            }
        }
    }
    None
}

#[test]
fn the_objc_stubs_and_methname_sections_exist() {
    // The default — a corpus with two distinct selectors plans one
    // `__objc_stubs` section (stride `OBJC_STUB_SIZE_ARM64`, type
    // `S_SYMBOL_STUBS`) and one `__objc_methname` section (type
    // `S_CSTRING_LITERALS`).
    let result = link_corpus(&["alloc", "init"]);
    // The planned sections ride `Layout.sections`.
    let stubs = result
        .layout
        .sections
        .iter()
        .find(|s| s.seg_name == "__TEXT" && s.name == "__objc_stubs")
        .expect("the __objc_stubs section is planned");
    assert_eq!(
        stubs.size,
        u64::from(OBJC_STUB_SIZE_ARM64) * 2,
        "one stub per distinct selector"
    );
    let methname = result
        .layout
        .sections
        .iter()
        .find(|s| s.seg_name == "__TEXT" && s.name == "__objc_methname")
        .expect("the __objc_methname section is planned");
    // "alloc\0" (6) + "init\0" (5) = 11 bytes.
    assert_eq!(
        methname.size, 11,
        "the two selector strings dedup NUL-terminated"
    );
}

#[test]
fn the_stub_stride_and_type_match_the_ld64_abi() {
    // The emitted `__objc_stubs` section carries `S_SYMBOL_STUBS` and a
    // size that is a whole multiple of `OBJC_STUB_SIZE_ARM64` (the
    // verifier's `objcstubs` check reads the same contract).
    let result = link_corpus(&["count", "release", "autorelease"]);
    let bytes = pgr_emit::build_image(&result.layout, &result.objects).expect("the image emits");
    let (stubs, _) = section_named(&bytes, "__TEXT", "__objc_stubs")
        .expect("the __objc_stubs section rides the output");
    assert_eq!(stubs.flags & SECTION_TYPE_MASK, S_SYMBOL_STUBS);
    assert_eq!(stubs.size % u64::from(OBJC_STUB_SIZE_ARM64), 0);
    assert_eq!(
        stubs.size / u64::from(OBJC_STUB_SIZE_ARM64),
        3,
        "three distinct selectors, three stubs"
    );
}

#[test]
fn the_methname_strings_are_nul_terminated() {
    // The `__objc_methname` bytes carry the selector strings,
    // NUL-terminated, in first-use order (the dedup contract).
    let result = link_corpus(&["alloc", "init"]);
    let bytes = pgr_emit::build_image(&result.layout, &result.objects).expect("the image emits");
    let (methname, fileoff) = section_named(&bytes, "__TEXT", "__objc_methname")
        .expect("the __objc_methname section rides the output");
    let start = (fileoff + u64::from(methname.offset)) as usize;
    let end = start + methname.size as usize;
    let data = &bytes[start..end];
    assert_eq!(
        data, b"alloc\0init\0",
        "the selector strings ride NUL-terminated"
    );
}

#[test]
fn repeated_callsites_of_the_same_selector_plan_one_stub() {
    // Two callsites of the same selector plan exactly one stub (the
    // dedup contract — `__objc_stubs` is one entry per distinct
    // selector, not per callsite).
    let result = link_corpus(&["alloc", "alloc"]);
    let stubs = result
        .layout
        .sections
        .iter()
        .find(|s| s.seg_name == "__TEXT" && s.name == "__objc_stubs")
        .expect("the __objc_stubs section is planned");
    assert_eq!(
        stubs.size,
        u64::from(OBJC_STUB_SIZE_ARM64),
        "one stub for the deduped selector"
    );
    let methname = result
        .layout
        .sections
        .iter()
        .find(|s| s.seg_name == "__TEXT" && s.name == "__objc_methname")
        .expect("the __objc_methname section is planned");
    assert_eq!(
        methname.size, 6,
        "the selector string dedups to one 'alloc\\0'"
    );
}

#[test]
fn the_objc_stubs_corpus_double_links_byte_identical() {
    // The byte-identity lock — the determinism contract the gates pin.
    let cfg = LinkConfig {
        filetype: OutputType::Execute,
        ident: "m130-identity".into(),
        ..LinkConfig::default()
    };
    let inputs = objc_corpus(&["alloc", "init", "release"]);
    let a = link(&inputs, &[], &cfg).expect("the first link succeeds");
    let b = link(&inputs, &[], &cfg).expect("the second link succeeds");
    let bytes_a = pgr_emit::build_image(&a.layout, &a.objects).expect("the first image emits");
    let bytes_b = pgr_emit::build_image(&b.layout, &b.objects).expect("the second image emits");
    assert_eq!(bytes_a, bytes_b, "double link is byte-identical");
}

#[test]
fn the_objc_stubs_image_verifies_strict() {
    // The verify gate — the strict pass (the new `objcstubs` family rides
    // the full set once added; the gate is the contract the verifier
    // reads) passes on the synthesized image.
    let result = link_corpus(&["alloc", "init"]);
    let bytes = pgr_emit::build_image(&result.layout, &result.objects).expect("the image emits");
    let opts = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let report = verify(&bytes, &opts);
    assert!(
        report.is_ok(&opts),
        "the objc-stubs image verifies strict: {:#?}",
        report.issues
    );
}

#[test]
fn a_callsite_free_corpus_plans_no_objc_stubs() {
    // A corpus with no `_objc_msgSend$<selector>` callsite plans neither
    // `__objc_stubs` nor `__objc_methname` (the pre-M130 shape,
    // byte-identical — the synthesizer never engages).
    let result = link_corpus(&[]);
    assert!(
        !result
            .layout
            .sections
            .iter()
            .any(|s| s.name == "__objc_stubs"),
        "no callsite, no __objc_stubs"
    );
    assert!(
        !result
            .layout
            .sections
            .iter()
            .any(|s| s.name == "__objc_methname"),
        "no callsite, no __objc_methname"
    );
}
