//! The ObjC-stubs consumer example (M130 design record): the
//! `_objc_msgSend$<sel>` callsite shape the M130 `__objc_stubs` synthesis
//! will resolve. M130 is forthcoming — at this `base_commit` the synthesis
//! lane is not yet wired (the `__objc_stubs`/`__objc_methname` section
//! constants, the selector-classifying resolve arm, and the stub synthesis
//! pass all land in the M130 follow-up), so the callsite binds via the
//! pre-M130 dyld GOT path: `-undefined dynamic_lookup` defers the selector
//! pseudo-symbol to dyld, and the existing M2 `__stubs`/`__got` machinery
//! emits the bind. M130 will instead synthesize an `__objc_stubs` entry
//! that loads the selector string from `__objc_methname` and tail-calls
//! `_objc_msgSend` (the `ld64` contract the roadmap's M6 row and TDD R3
//! name). The walk: the callsite-bearing object, the dynamic-lookup link,
//! the strict verifier gating the image, and the design note on the
//! forthcoming synthesis. Run:
//! `cargo run -p pgr-driver --example objc_stubs_link`

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// msg.o: `_main` over a small `__text` whose second instruction is a
/// `bl _objc_msgSend$foo` — the M130 input shape (a callsite to the
/// selector pseudo-symbol). The `BL` at offset 4 carries a `BRANCH26`
/// reloc targeting the undefined `_objc_msgSend$foo` symbol (nlist index
/// 1, the second symbol after `_main`).
fn msgsend_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("msg.o").set_subsections_via_symbols(true);
    let _text = b.add_section(ObjectSection::text(
        "__text",
        // `ret` (offset 0) then `bl #0` (offset 4) — the BL immediate is
        // patched at link time against the target symbol; the dead code
        // after the ret keeps the callsite shape without a real branch
        // target inside the object.
        vec![0xC0u8, 0x03, 0x5F, 0xD6, 0x00, 0x00, 0x00, 0x94],
        vec![ObjectReloc::branch26(1).at(4)],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: 0,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_objc_msgSend$foo".into(),
        weak_ref: false,
    });
    b.build().expect("the fixture object builds")
}

fn main() {
    let dir = std::env::temp_dir().join("pgr_example_objc_stubs_link");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");

    let obj = dir.join("msg.o");
    std::fs::write(&obj, msgsend_object()).expect("the object writes");
    let out_path = dir.join("msg");
    // `-undefined dynamic_lookup` defers the selector pseudo-symbol to
    // dyld — the pre-M130 pass-through (M130's __objc_stubs synthesis is
    // forthcoming; today the callsite rides the M2 __stubs/__got bind).
    let argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        out_path.as_os_str().to_os_string(),
        obj.as_os_str().to_os_string(),
        std::ffi::OsString::from("-undefined"),
        std::ffi::OsString::from("dynamic_lookup"),
    ];
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs");
    let image = std::fs::read(&out_path).expect("the image reads");

    // The image verifies strict — the callsite binds via the pre-M130
    // dyld GOT path (no __objc_stubs synthesized at this base_commit).
    let opts = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let report = verify(&image, &opts);
    assert!(
        report.is_ok(&opts),
        "the callsite-bearing image verifies strict: {:#?}",
        report.issues
    );
    println!(
        "the _objc_msgSend$foo callsite bound via the pre-M130 dyld GOT path (dynamic_lookup)"
    );
    println!(
        "M130 will synthesize __objc_stubs resolving the callsite to a selector-loading stub \
         (the ld64 contract the roadmap's M6 row and TDD R3 name)"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
