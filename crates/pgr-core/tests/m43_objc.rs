//! M43 — the `-ObjC` archive pull: ld64's liveness rule ("Loads all
//! members of static archive libraries that implement an Objective-C
//! class or category") rides the archive pull as a named decision. The
//! modern clang emitter names a class's implementation with
//! `_OBJC_CLASS_$_`/`_OBJC_METACLASS_$_` symbols and a category's with
//! `_OBJC_CATEGORY_$_` — a member defining any of those rides the pull
//! even though nothing in the link references it (the `ObjC` runtime
//! registers the class by section address at load time; no static
//! reference exists to seed the fixpoint). The default (`false`) keeps
//! the pre-M43 reference-driven pull byte-identical: an unreferenced
//! member stays unparsed.
//!
//! Gate matrix:
//! * the pull — an unreferenced class-defining member's symbols join
//!   the image under the knob and stay out under the default;
//! * the category — a category-defining member pulls the same way;
//! * the plain member stays — a member defining none of the metadata
//!   names is not pulled by the knob (the rule is class-or-category,
//!   not `-all_load`);
//! * the transitive fixpoint — a pulled member's own undefineds keep
//!   pulling their providers (the member joins the liveness walk);
//! * the relocatable path — `-r` rides the same pull (the members join
//!   the object output);
//! * determinism — two runs of the same link are byte-identical.

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkArchive, LinkArchiveMember, LinkInput, Parallelism, link, link_reloc};
use pgr_fixtures::{ArchiveBuilder, ObjectBuilder, ObjectSection, ObjectSymbol};

/// An object whose `__text` carries two RET functions and one defined
/// symbol named `names[0]` (plus `names[1..]` at later offsets) — the
/// member body the archive index ranks.
fn member(name: &str, symbols: &[&str]) -> Vec<u8> {
    let mut b = ObjectBuilder::new(name);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(symbols.len() * 2),
        vec![],
    ));
    for (i, sym) in symbols.iter().enumerate() {
        b.add_symbol(ObjectSymbol::Defined {
            name: (*sym).into(),
            section_index: text,
            value: (i as u64) * 8,
            weak: false,
        });
    }
    b.build().expect("the fixture object builds")
}

/// An object defining the named symbols over RET bodies and referencing
/// one undefined name — the class member's shape (its implementation
/// demands the provider member).
fn member_with_ref(name: &str, symbols: &[&str], undef: &str) -> Vec<u8> {
    let mut b = ObjectBuilder::new(name);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(symbols.len() * 2),
        vec![],
    ));
    for (i, sym) in symbols.iter().enumerate() {
        b.add_symbol(ObjectSymbol::Defined {
            name: (*sym).into(),
            section_index: text,
            value: (i as u64) * 8,
            weak: false,
        });
    }
    b.add_symbol(ObjectSymbol::Undefined {
        name: undef.into(),
        weak_ref: false,
    });
    b.build().expect("the fixture object builds")
}

/// An object defining `local` and referencing `undef` (the transitive
/// edge: the pulled member demands its provider).
fn referencing_member(name: &str, local: &str, undef: &str) -> Vec<u8> {
    member_with_ref(name, &[local], undef)
}

/// `libobjc.a`: the class member (`dog.o`: the class + metaclass pair),
/// the category member (`tricks.o`), the transitive provider
/// (`helper.o`: defines `_helper`) and the plain member (`plain.o`:
/// defines `_plain_fn`, no metadata names). Nothing in the direct
/// inputs references any of them.
fn objc_archive() -> (Vec<u8>, LinkArchive) {
    let mut builder = ArchiveBuilder::new("libobjc.a");
    builder.add_member(
        "dog.o",
        member_with_ref(
            "dog.o",
            &["_OBJC_CLASS_$_Dog", "_OBJC_METACLASS_$_Dog"],
            "_helper",
        ),
    );
    builder.add_member(
        "tricks.o",
        member("tricks.o", &["_OBJC_CATEGORY_$_Dog_Tricks"]),
    );
    builder.add_member(
        "helper.o",
        referencing_member("helper.o", "_helper", "_OBJC_CLASS_$_Dog"),
    );
    builder.add_member("plain.o", member("plain.o", &["_plain_fn"]));
    let bytes = builder.build();
    let parsed = pgr_format::parse_archive(&bytes).expect("the archive parses");
    let arch = LinkArchive {
        name: "libobjc.a".into(),
        index: parsed
            .index
            .iter()
            .map(|e| (e.name.clone().into_bytes(), e.member))
            .collect(),
        members: parsed
            .members
            .iter()
            .map(|m| LinkArchiveMember {
                name: m.name.clone(),
                offset: m.offset,
                size: m.size,
            })
            .collect(),
        bytes: bytes.clone(),
        all_load: false,
    };
    (bytes, arch)
}

/// `main.o`: `_main` over two RET functions — no `ObjC` reference at all.
fn direct() -> Vec<LinkInput> {
    let mut b = ObjectBuilder::new("main.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    vec![LinkInput {
        name: "main.o".into(),
        bytes: b.build().expect("the fixture object builds"),
    }]
}

fn plan(objc: bool) -> pgr_core::link::LinkResult {
    let (_bytes, arch) = objc_archive();
    let cfg = LinkConfig {
        filetype: OutputType::Execute,
        ident: "m43".into(),
        objc,
        ..LinkConfig::default()
    };
    link(&direct(), &[arch], &cfg).expect("the corpus links")
}

fn defines_in_image(result: &pgr_core::link::LinkResult, name: &str) -> bool {
    result.layout.symbols.iter().any(|s| {
        s.external
            && s.n_type & pgr_format::consts::N_TYPE != pgr_format::consts::N_UNDF
            && result.interner.bytes(s.name) == name.as_bytes()
    })
}

#[test]
fn the_class_member_pulls_under_the_knob() {
    let default = plan(false);
    assert!(
        !defines_in_image(&default, "_OBJC_CLASS_$_Dog"),
        "the default keeps the pre-M43 reference-driven pull (the class \
         member nothing references stays unparsed)"
    );

    let pulled = plan(true);
    assert!(
        defines_in_image(&pulled, "_OBJC_CLASS_$_Dog"),
        "the class-defining member rides the -ObjC pull"
    );
    assert!(
        defines_in_image(&pulled, "_OBJC_METACLASS_$_Dog"),
        "the metaclass rides beside its class (one member, one pull)"
    );
}

#[test]
fn the_category_member_pulls_under_the_knob() {
    let pulled = plan(true);
    assert!(
        defines_in_image(&pulled, "_OBJC_CATEGORY_$_Dog_Tricks"),
        "the category-defining member rides the -ObjC pull (the man page \
         names class or category)"
    );
}

#[test]
fn the_plain_member_stays_out() {
    let pulled = plan(true);
    assert!(
        !defines_in_image(&pulled, "_plain_fn"),
        "the knob is class-or-category, not -all_load: a member defining \
         no metadata name is not pulled by it"
    );
}

#[test]
fn the_pulled_member_continues_the_fixpoint() {
    let pulled = plan(true);
    assert!(
        defines_in_image(&pulled, "_helper"),
        "the pulled class member's own undefineds keep pulling their \
         providers (the member joins the liveness walk)"
    );
}

#[test]
fn the_relocatable_path_rides_the_pull() {
    let (_bytes, arch) = objc_archive();
    let cfg = LinkConfig {
        filetype: OutputType::Relocatable,
        objc: true,
        ..LinkConfig::default()
    };
    let rel = link_reloc(&direct(), &[arch], &cfg, Parallelism::Serial).expect("the -r link runs");
    assert!(
        rel.objects.iter().any(|o| o.name == "libobjc.a(dog.o)"),
        "the relocatable pull admits the class member (the object output \
         carries the pulled member verbatim)"
    );
    assert!(
        !rel.objects.iter().any(|o| o.name == "libobjc.a(plain.o)"),
        "the relocatable pull still refuses the plain member"
    );
}

#[test]
fn the_pull_is_deterministic() {
    let a = plan(true);
    let b = plan(true);
    assert_eq!(
        a.layout.header_bytes, b.layout.header_bytes,
        "the same corpus under the same flag links to identical headers"
    );
    assert_eq!(a.layout.symbols.len(), b.layout.symbols.len());
}
