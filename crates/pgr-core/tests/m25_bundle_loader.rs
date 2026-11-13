//! M25 — the bundle-loader seam (`pgr_core::bundle_loader`): the
//! `-bundle_loader <path>` decision stops being an unnameable input
//! shape and becomes a validated provider on
//! [`pgr_core::layout::LinkConfig`] — the main executable a bundle
//! binds against (ld64's bundle story: the bundle carries undefined
//! references the *host* resolves at load time; the linker needs the
//! host's export surface to plan those binds two-level).
//!
//! Gate matrix:
//! * the seam — a loader validates (non-empty NUL-free name, non-empty
//!   NUL-free exports, one row per name) with the fix in the refusal;
//! * resolution — a bundle's undefined names resolve against the
//!   loader's exports (the same Pass-2 contract dylib exports ride),
//!   and the binds carry the main-executable ordinal `0xFF`
//!   (`BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE`) in the symtab and the
//!   import table — dyld resolves them against the host at load time;
//! * the refusals — the knob on a non-bundle output (an executable
//!   binds nothing against a host; the relocatable output opens its
//!   undefineds by design), and a bundle without its loader naming a
//!   still-unresolvable name;
//! * the lock — the default (`None`) plans what the pre-seam layout
//!   planned, and a double link stays byte-identical (TDD §4.3).

use pgr_core::bundle_loader::BundleLoader;
use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkInput, link};
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_format::consts::BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE;

/// A bundle-body corpus: `_bundle_main` calls `_host_fn` (BL, resolved
/// against the loader) and defines `_bundle_export`.
fn corpus() -> Vec<LinkInput> {
    let mut b = ObjectBuilder::new("bundle.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [
            0x9400_0000u32, // bl _host_fn
            0x5280_0000u32, // mov w0, #0
            0xD65F_03C0u32, // ret
        ]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect(),
        vec![ObjectReloc::branch26(1).at(0)],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_bundle_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_host_fn".into(),
        weak_ref: false,
    });
    vec![LinkInput {
        name: "bundle.o".to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }]
}

/// The loader surface the gates use: the host exports `_host_fn`.
fn loader() -> BundleLoader {
    BundleLoader::new("/bin/host", vec![b"_host_fn".to_vec()]).expect("validates")
}

fn bundle_cfg() -> LinkConfig {
    LinkConfig {
        filetype: OutputType::Bundle,
        bundle_loader: Some(loader()),
        ..LinkConfig::default()
    }
}

// ---- the seam ----------------------------------------------------------------

#[test]
fn a_loader_validates_and_carries_its_surface() {
    let l = loader();
    assert_eq!(l.name(), "/bin/host");
    assert_eq!(l.exports(), [b"_host_fn".to_vec()]);
}

#[test]
fn refusals_name_the_fix() {
    // An empty path names no host.
    let err = BundleLoader::new("", vec![b"_f".to_vec()]).expect_err("empty name refuses");
    assert!(err.to_string().contains("non-empty"), "{err}");
    // The symtab strings are C strings: an interior NUL would silently
    // truncate the name.
    let err = BundleLoader::new("/bin/h\0ost", Vec::new()).expect_err("NUL refuses");
    assert!(err.to_string().contains("NUL"), "{err}");
    let err =
        BundleLoader::new("/bin/host", vec![b"_f\0".to_vec()]).expect_err("NUL export refuses");
    assert!(err.to_string().contains("NUL"), "{err}");
    // One row per name: a duplicate export is a scan bug, not a surface.
    let err = BundleLoader::new("/bin/host", vec![b"_f".to_vec(), b"_f".to_vec()])
        .expect_err("duplicate export refuses");
    assert!(err.to_string().contains("_f"), "{err}");
}

// ---- resolution + the image -----------------------------------------------------

#[test]
fn a_bundle_binds_its_loader_names_two_level() {
    let result = link(&corpus(), &[], &bundle_cfg()).expect("the bundle links");
    let layout = &result.layout;

    // The undefined external carries the main-executable ordinal (0xFF)
    // in `n_desc` — dyld resolves it against the host at load time.
    let undef = layout
        .symbols
        .iter()
        .find(|s| {
            s.external
                && s.n_type & pgr_format::consts::N_TYPE == pgr_format::consts::N_UNDF
                && result.interner.bytes(s.name) == b"_host_fn"
        })
        .expect("the loader bind rides the symtab");
    assert_eq!(
        undef.n_desc >> 8,
        BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE,
        "the bind names the main executable (0xFF)"
    );

    // The import table entry carries the same ordinal — the chained
    // fixups bind dyld replays names 0xFF.
    let plan = &layout.fixups;
    assert!(
        plan.imports
            .iter()
            .any(|imp| imp.lib_ordinal == BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE),
        "the import table carries the main-executable ordinal"
    );

    // The bundle verifies like the default: no loader commands, the
    // bind rides the special ordinal space.
    let exports = pgr_format::trie::exports(&layout.trie).expect("the trie walks");
    assert!(
        exports.iter().any(|e| e.name == b"_bundle_main"),
        "the bundle exports its own surface"
    );
}

#[test]
fn a_bundle_without_the_loader_refuses_the_unresolved_name() {
    // The same corpus, no loader: the undefined name has no host to
    // resolve against (`-undefined error` refuses — the bundle story
    // needs the loader named).
    let cfg = LinkConfig {
        filetype: OutputType::Bundle,
        ..LinkConfig::default()
    };
    let err = link(&corpus(), &[], &cfg).expect_err("the unresolved name refuses");
    assert!(err.to_string().contains("_host_fn"), "{err}");
}

#[test]
fn the_refusals_name_the_kind_that_cannot_bind_against_a_host() {
    for (kind, label) in [
        (OutputType::Execute, "executable"),
        (OutputType::Dylib, "dylib"),
        (OutputType::Relocatable, "relocatable"),
    ] {
        let cfg = LinkConfig {
            filetype: kind,
            bundle_loader: Some(loader()),
            ..LinkConfig::default()
        };
        let err = link(&corpus(), &[], &cfg).expect_err("the shape refuses");
        assert!(
            err.to_string().contains(label),
            "the refusal names the output kind ({label}): {err}"
        );
    }
}

// ---- the lock ----------------------------------------------------------------

#[test]
fn the_default_bundle_links_byte_identical_and_loader_free() {
    // A self-contained bundle (no undefineds) plans what the pre-seam
    // layout planned, and the double link stays byte-identical.
    let mut b = ObjectBuilder::new("solo.o").set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_bundle_main".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    let solo = vec![LinkInput {
        name: "solo.o".to_string(),
        bytes: b.build().expect("the fixture object builds"),
    }];
    let cfg = LinkConfig {
        filetype: OutputType::Bundle,
        ..LinkConfig::default()
    };
    let a = link(&solo, &[], &cfg).expect("the bundle links").layout;
    let c = link(&solo, &[], &cfg).expect("the bundle links").layout;
    assert_eq!(a.header_bytes, c.header_bytes, "the double link is stable");
    assert!(
        a.fixups
            .imports
            .iter()
            .all(|imp| imp.lib_ordinal != BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE),
        "the default carries no loader binds"
    );
}
