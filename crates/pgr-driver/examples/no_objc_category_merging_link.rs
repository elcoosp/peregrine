//! M115 — the `ObjC` category-merging optimization:
//! `-no_objc_category_merging` — ld64's category-merging toggle (the
//! M43 `-ObjC` pattern's optimization). The default merges every
//! category whose base class rides the link — the category registers
//! through its base class's registration, and the
//! `__objc_catlist`/`__objc_nlcatlist` registration section folds away.
//! The flag disables the merge — categories stay as separate sections,
//! every load-time byte the input carried. The relocatable output
//! refuses the knob (the object's sections are the input's, verbatim).
//!
//! Run: `cargo run -p pgr-driver --example no_objc_category_merging_link`
//! (`PGR_TRACING=1` installs a tracing subscriber).

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, link};
use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::ffi::OsString;

/// cat.o: `_main`, the class family, the category family, and a
/// one-entry `__objc_catlist` registration binding the category symbol.
fn corpus(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut b = ObjectBuilder::new("cat.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let data = b.add_section(ObjectSection::data("__objc_data", vec![0u8; 16], vec![]));
    let cat_sym = b.add_symbol(ObjectSymbol::Defined {
        name: "_OBJC_CATEGORY_$_Dog".into(),
        section_index: data,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_OBJC_CLASS_$_Dog".into(),
        section_index: data,
        value: 8,
        weak: false,
    });
    let catlist = b.add_section(ObjectSection::data("__objc_catlist", vec![0u8; 8], vec![]));
    b.section_mut(catlist)
        .relocs
        .push(ObjectReloc::unsigned(cat_sym as u32).at(0));
    let path = dir.join("cat.o");
    std::fs::write(&path, b.build().expect("the fixture builds")).expect("cat.o writes");
    vec![path]
}

/// The image's `__objc_catlist` presence (the merge's observable shape —
/// the raw load-command walk, the verifier's `ObjC` gate's own source).
fn carries_catlist(image: &[u8]) -> bool {
    let Ok(hdr) = pgr_format::MachHeader64::parse(image) else {
        return false;
    };
    let Ok(mut it) = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    ) else {
        return false;
    };
    while let Ok(Some(cmd)) = it.next_command() {
        if cmd.kind != pgr_format::LoadCommandKind::Segment64 || cmd.bytes.len() < 72 {
            continue;
        }
        let nsects = u32::from_le_bytes(cmd.bytes[64..68].try_into().unwrap_or([0; 4]));
        for i in 0..nsects as usize {
            let base = 72 + i * 80;
            if base + 80 > cmd.bytes.len() {
                return false;
            }
            let name = String::from_utf8_lossy(&cmd.bytes[base..base + 16]);
            if name.trim_end_matches('\0') == "__objc_catlist" {
                return true;
            }
        }
    }
    false
}
fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt().init();
    }
    let dir = std::env::temp_dir().join(format!("pgr_objc_merging_link_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("the scratch dir creates");
    let objs = corpus(&dir);
    let inputs: Vec<LinkInput> = objs
        .iter()
        .map(|p| LinkInput {
            name: p
                .file_name()
                .expect("the name rides")
                .to_string_lossy()
                .into_owned(),
            bytes: std::fs::read(p).expect("the object reads"),
        })
        .collect();

    // Face 1 — the library face: the default merge drops the
    // registration section; the disabled face keeps it verbatim.
    let plan_for = |merging: bool| {
        link(
            &inputs,
            &[],
            &LinkConfig {
                objc_category_merging: merging,
                ..LinkConfig::default()
            },
        )
        .expect("the link plans")
    };
    let merged = plan_for(true);
    let disabled = plan_for(false);
    assert!(
        !merged
            .layout
            .sections
            .iter()
            .any(|s| s.name == "__objc_catlist"),
        "the merged plan carries no registration section"
    );
    assert!(
        disabled
            .layout
            .sections
            .iter()
            .any(|s| s.name == "__objc_catlist"),
        "the disabled plan keeps the registration section (categories stay as \
         separate sections)"
    );
    let merged_image =
        pgr_emit::build_image_fused(&merged.layout, &merged.objects).expect("the image emits");
    assert!(
        !carries_catlist(&merged_image),
        "the merged image carries no registration section"
    );
    println!(
        "face 1 (default merge): the registration folded away ({} bytes); \
         disabled: the section rides verbatim ({} bytes)",
        merged.layout.file_size, disabled.layout.file_size
    );

    // Face 2 — the driver face: `-no_objc_category_merging` names the
    // disable; the image writes and verifies strict (the registration
    // shape the verifier's ObjC gate reads).
    let mut argv: Vec<OsString> = vec![
        "-o".into(),
        dir.join("app_kept").to_string_lossy().into_owned().into(),
        "-no_objc_category_merging".into(),
    ];
    argv.extend(objs.iter().map(|p| p.to_string_lossy().into_owned().into()));
    let o = opts::parse(&argv).expect("the surface parses");
    let outcome = pgr_driver::run(&o).expect("the link runs");
    let image = std::fs::read(dir.join("app_kept")).expect("the image reads");
    let strict = VerifyOptions::default();
    assert!(
        verify(&image, &strict).is_ok(&strict),
        "the registration-carrying image verifies strict"
    );
    println!(
        "face 2 (-no_objc_category_merging): the section rides beside the outcome \
         ({} bytes); verifies strict",
        outcome.file_size
    );

    // Face 3 — the relocatable refusal: the object's sections are the
    // input's, verbatim.
    let mut full: Vec<OsString> = vec![
        "-r".into(),
        "-o".into(),
        dir.join("o.o").to_string_lossy().into_owned().into(),
        "-no_objc_category_merging".into(),
    ];
    full.extend(objs.iter().map(|p| p.to_string_lossy().into_owned().into()));
    match opts::parse(&full) {
        Ok(_) => panic!("the relocatable output must refuse the disable"),
        Err(err) => println!("face 3 (-r): refused — {:?}", miette::Report::new(err)),
    }

    println!("\nno_objc_category_merging_link: ok");
}
