//! M49 — the GCC-era `ObjC` symbols join the `-ObjC` pull: ld64's
//! archive matcher names the ranlib-index prefixes `.objc_c*` (the
//! `ObjC1`/GCC-era C symbols — `.objc_class_name_<Class>` for a class,
//! `.objc_category_name_<Class>_<Category>` for a category) beside
//! `_OBJC_CLASS_$_` (ld64-609 `archive_file.cpp:475`). The M43 rule
//! shipped the modern `$_`-prefixed family only; a member whose index
//! entry names the GCC-era forms stayed unparsed. The classifier
//! widens to both families and names each one — the public seam the
//! pull reads (`classify_objc_metadata`) — while the exclusions hold:
//! the protocol list (`_OBJC_PROTOCOL_$_`) names neither a class nor a
//! category (the man page and ld64's matcher agree — it stays out) and
//! the pre-2.0 method-symbol form (`+[Class(Category) method]`) has no
//! pull role (ld64's matcher reads index entries only; methods ride
//! their class/category symbols).
//!
//! Gate matrix:
//! * the pull — a GCC-era class member and a GCC-era category member
//!   ride the pull under the knob and stay out under the default;
//! * the protocol stays — a protocol-defining member is not pulled by
//!   the knob (the rule is class-or-category, not `-all_load`);
//! * the plain member stays — the non-metadata rule unchanged;
//! * the transitive fixpoint — a pulled member's own undefineds keep
//!   pulling their providers;
//! * the classifier — the family enum names every prefix family and
//!   keeps the exclusions named;
//! * the relocatable path — `-r` rides the same pull;
//! * determinism — two runs of the same link are byte-identical.

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkArchive, LinkArchiveMember, LinkInput, Parallelism, link, link_reloc};
use pgr_core::objc::{classify_objc_metadata, defines_objc_metadata};
use pgr_fixtures::{ArchiveBuilder, ObjectBuilder, ObjectSection, ObjectSymbol};

/// An object whose `__text` carries two RET functions per symbol and one
/// defined symbol named `names[0]` (plus `names[1..]` at later offsets).
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
/// one undefined name — the pulled member's transitive edge.
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

/// `libpre2.a`: the GCC-era class member (`pre2.o`: the
/// `.objc_class_name_Dog` C symbol), the GCC-era category member
/// (`pre2tricks.o`: `.objc_category_name_Dog_Tricks`), the protocol
/// member (`proto.o`: `_OBJC_PROTOCOL_$_Foo` — stays out), the
/// transitive provider (`helper.o`) and the plain member (`plain.o`).
/// Nothing in the direct inputs references any of them.
fn pre2_archive() -> LinkArchive {
    let mut builder = ArchiveBuilder::new("libpre2.a");
    builder.add_member(
        "pre2.o",
        member_with_ref("pre2.o", &[".objc_class_name_Dog"], "_helper"),
    );
    builder.add_member(
        "pre2tricks.o",
        member("pre2tricks.o", &[".objc_category_name_Dog_Tricks"]),
    );
    builder.add_member("proto.o", member("proto.o", &["_OBJC_PROTOCOL_$_Foo"]));
    builder.add_member("helper.o", member("helper.o", &["_helper"]));
    builder.add_member("plain.o", member("plain.o", &["_plain_fn"]));
    let bytes = builder.build();
    let parsed = pgr_format::parse_archive(&bytes).expect("the archive parses");
    LinkArchive {
        name: "libpre2.a".into(),
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
    }
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
    let arch = pre2_archive();
    let cfg = LinkConfig {
        filetype: OutputType::Execute,
        ident: "m49".into(),
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
fn the_pre2_class_member_pulls_under_the_knob() {
    let default = plan(false);
    assert!(
        !defines_in_image(&default, ".objc_class_name_Dog"),
        "the default keeps the reference-driven pull (the GCC-era member \
         nothing references stays unparsed)"
    );

    let pulled = plan(true);
    assert!(
        defines_in_image(&pulled, ".objc_class_name_Dog"),
        "the GCC-era class member rides the -ObjC pull (ld64's matcher \
         names the .objc_c index prefixes beside _OBJC_CLASS_$_)"
    );
}

#[test]
fn the_pre2_category_member_pulls_under_the_knob() {
    let pulled = plan(true);
    assert!(
        defines_in_image(&pulled, ".objc_category_name_Dog_Tricks"),
        "the GCC-era category member rides the -ObjC pull (the .objc_c \
         prefix covers the ObjC1 category symbols)"
    );
}

#[test]
fn the_protocol_member_stays_out() {
    let pulled = plan(true);
    assert!(
        !defines_in_image(&pulled, "_OBJC_PROTOCOL_$_Foo"),
        "a protocol names neither a class nor a category — the man page \
         and ld64's matcher agree, the member stays out"
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
        "the pulled GCC-era member's own undefineds keep pulling their \
         providers (the member joins the liveness walk)"
    );
}

#[test]
fn the_classifier_names_the_families() {
    use pgr_core::objc::ObjcFamily as F;
    for (name, family) in [
        (&b"_OBJC_CLASS_$_Dog"[..], F::Class),
        (&b"_OBJC_METACLASS_$_Dog"[..], F::Metaclass),
        (&b"_OBJC_CATEGORY_$_Dog_Tricks"[..], F::Category),
        (&b".objc_class_name_Dog"[..], F::PreTwoPointZeroClass),
        (
            &b".objc_category_name_Dog_Tricks"[..],
            F::PreTwoPointZeroCategory,
        ),
    ] {
        assert_eq!(
            classify_objc_metadata(name),
            Some(family),
            "{:?} names {} metadata",
            String::from_utf8_lossy(name),
            match family {
                F::Class => "modern class",
                F::Metaclass => "modern metaclass",
                F::Category => "modern category",
                F::PreTwoPointZeroClass => "GCC-era class",
                F::PreTwoPointZeroCategory => "GCC-era category",
            }
        );
        assert!(defines_objc_metadata(name), "the family pulls");
    }
    for name in [
        &b"_OBJC_PROTOCOL_$_Foo"[..],
        b"+[Dog(Tricks) bark]",
        b"_OBJC_IVAR_$_Dog._tail",
        b"_Dog",
        b"",
    ] {
        assert_eq!(
            classify_objc_metadata(name),
            None,
            "{:?} names no pull-family metadata",
            String::from_utf8_lossy(name)
        );
        assert!(!defines_objc_metadata(name), "the exclusion stays out");
    }
}

#[test]
fn the_relocatable_path_rides_the_pull() {
    let arch = pre2_archive();
    let cfg = LinkConfig {
        filetype: OutputType::Relocatable,
        objc: true,
        ..LinkConfig::default()
    };
    let rel = link_reloc(&direct(), &[arch], &cfg, Parallelism::Serial).expect("the -r link runs");
    assert!(
        rel.objects.iter().any(|o| o.name == "libpre2.a(pre2.o)"),
        "the relocatable pull admits the GCC-era class member"
    );
    assert!(
        !rel.objects.iter().any(|o| o.name == "libpre2.a(proto.o)"),
        "the relocatable pull still refuses the protocol member"
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
