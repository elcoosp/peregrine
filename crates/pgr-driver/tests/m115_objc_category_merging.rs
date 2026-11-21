//! M115 — the `-no_objc_category_merging` surface: ld64's
//! category-merging toggle rides the driver — the parse face sets the
//! disable, the relocatable conflict is `finish`'s (the object's
//! sections are the input's, verbatim — the M104/M105 pattern), and
//! the end-to-end gate: the disabled image keeps the registration
//! section and verifies strict, the default merge drops it.

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};
use std::ffi::OsString;

/// cat.o: `_main`, `_OBJC_CLASS_$_Dog` and `_OBJC_CATEGORY_$_Dog` all
/// defined, and a `__DATA,__objc_catlist` registration entry binding
/// the category symbol — the shape the merge decision reads.
fn category_object() -> Vec<u8> {
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
    b.build().expect("the fixture object builds")
}

fn scratch(name: &str) -> (std::path::PathBuf, Vec<OsString>) {
    let dir = std::env::temp_dir().join(format!("pgr_m115_{name}_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("the scratch dir creates");
    let obj = dir.join("cat.o");
    std::fs::write(&obj, category_object()).expect("cat.o writes");
    let mut argv: Vec<OsString> = vec![
        "-o".into(),
        dir.join(name).to_string_lossy().into_owned().into(),
    ];
    argv.push(obj.to_string_lossy().into_owned().into());
    (dir.join(name), argv)
}

/// The image's `__objc_catlist` presence (the raw load-command walk —
/// the verifier's `ObjC` gate's own source).
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

#[test]
fn the_flag_names_the_disable() {
    let (out, argv) = scratch("face");
    let o = opts::parse(&argv).expect("the plain argv parses");
    assert!(
        o.config.objc_category_merging,
        "the default is the merge (ld64's optimization)"
    );
    let mut disabled_argv = argv.clone();
    disabled_argv.push("-no_objc_category_merging".into());
    let o = opts::parse(&disabled_argv).expect("the flag parses");
    assert!(
        !o.config.objc_category_merging,
        "the flag names the disable"
    );
    let _ = std::fs::remove_file(&out);
}

#[test]
fn the_disabled_image_keeps_the_registration_and_verifies_strict() {
    let (out, argv) = scratch("disabled");
    let mut disabled_argv = argv.clone();
    disabled_argv.push("-no_objc_category_merging".into());
    let o = opts::parse(&disabled_argv).expect("the surface parses");
    let outcome = pgr_driver::run(&o).expect("the link runs");
    assert!(outcome.file_size > 0, "the image writes");
    let image = std::fs::read(&out).expect("the image reads");
    let kept = carries_catlist(&image);
    assert!(
        kept,
        "the disabled image keeps the registration section (categories stay as \
         separate sections)"
    );
    let strict = VerifyOptions::default();
    assert!(
        verify(&image, &strict).is_ok(&strict),
        "the registration-carrying image verifies strict"
    );
    let _ = std::fs::remove_file(&out);
}

#[test]
fn the_default_merge_drops_the_registration() {
    let (out, argv) = scratch("merged");
    let o = opts::parse(&argv).expect("the surface parses");
    pgr_driver::run(&o).expect("the merged link runs");
    let image = std::fs::read(&out).expect("the image reads");
    let kept = carries_catlist(&image);
    assert!(
        !kept,
        "the merged image carries no registration section (the category registers \
         through its base class)"
    );
    let _ = std::fs::remove_file(&out);
}

#[test]
fn no_objc_category_merging_refuses_on_the_relocatable_output() {
    let (out, _argv) = scratch("reloc");
    let full: Vec<OsString> = vec![
        "-r".into(),
        "-o".into(),
        out.with_extension("o")
            .to_string_lossy()
            .into_owned()
            .into(),
        "cat.o".into(),
        "-no_objc_category_merging".into(),
    ];
    match opts::parse(&full) {
        Ok(_) => panic!("the relocatable output must refuse the disable"),
        Err(err) => {
            let rendered = format!("{:?}", miette::Report::new(err));
            assert!(
                rendered.contains("-no_objc_category_merging") && rendered.contains("verbatim"),
                "the refusal names the flag and the verbatim contract: {rendered}"
            );
        }
    }
    let _ = std::fs::remove_file(&out);
}
