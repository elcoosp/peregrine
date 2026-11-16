//! The weak-import-refusal consumer example (M50): shipping a main
//! executable whose weak reference resolves at link time — and one
//! whose weak reference only dyld could resolve. ld64's
//! `-no_weak_imports` turns the second shape into a typed refusal
//! ("weak import of symbol '%s' not supported because of option:
//! `-no_weak_imports`"): a weak reference that rides dyld's runtime
//! lookup refuses with the symbol named, while a link-time resolution
//! (an input definition or a dylib export, weak-loaded or not) never
//! refuses — the knob prices the runtime lookup, not the weakness.
//! Both built images verify strict; the resolved pair is
//! byte-identical under both decisions.
//!
//! Run: `cargo run -p pgr-driver --example no_weak_imports_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// `weakref.o`: `_main` over two RET functions and an undefined `name`
/// (`weak` flips the reference's `N_WEAK_REF` bit).
fn weakref_object(name: &str, weak: bool, undef: &str) -> Vec<u8> {
    let mut b = ObjectBuilder::new(name);
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
    b.add_symbol(ObjectSymbol::Undefined {
        name: undef.into(),
        weak_ref: weak,
    });
    b.build().expect("the fixture object builds")
}

/// `provider.o`: defines `name` over one RET body (the link-time
/// resolution the knob never refuses).
fn provider_object(name: &str) -> Vec<u8> {
    let mut b = ObjectBuilder::new("provider.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: name.into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

fn strict_ok(image: &[u8]) -> bool {
    let opts = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    verify(image, &opts).is_ok(&opts)
}

/// Links `files` with the named extra flags; `Ok(bytes)` on a built
/// image, `Err(message)` on a typed refusal.
fn link_app(files: Vec<Vec<u8>>, extra: &[&str], tag: &str) -> Result<Vec<u8>, String> {
    let dir = std::env::temp_dir().join(format!("pgr_no_weak_imports_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    let out = dir.join(format!("app-{tag}"));
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        std::ffi::OsString::from(out.to_str().expect("the output path names")),
    ];
    for (i, bytes) in files.into_iter().enumerate() {
        let path = dir.join(format!("{tag}_in{i}.o"));
        std::fs::write(&path, bytes).expect("the input writes");
        argv.push(std::ffi::OsString::from(
            path.to_str().expect("the path names"),
        ));
    }
    for a in extra {
        argv.push(std::ffi::OsString::from(*a));
    }
    let o = opts::parse(&argv).expect("the argv parses");
    match pgr_driver::run(&o) {
        Ok(_) => Ok(std::fs::read(&out).expect("the image reads")),
        Err(e) => Err(e.to_string()),
    }
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    // The resolved weak reference: an input definition answers the bind
    // at link time — the knob never fires, the image is byte-identical
    // under both decisions and verifies strict.
    let resolved = vec![
        weakref_object("weakref.o", true, "_maybe"),
        provider_object("_maybe"),
    ];
    let default = link_app(resolved.clone(), &[], "resolved-default")
        .expect("the resolved weak bind links by default");
    let named = link_app(resolved, &["-no_weak_imports"], "resolved-named")
        .expect("a link-time resolution never refuses");
    assert_eq!(default, named, "the resolved pair plans identical bytes");
    assert!(strict_ok(&named), "the resolved image verifies strict");
    println!(
        "resolved: {} bytes — the weak bind answered at link time, byte-identical under both decisions",
        named.len()
    );

    // The runtime-lookup weak reference: the default ships the dyld
    // lookup bind (the pre-M50 shape), the knob refuses with the
    // symbol, the knob and the fix named.
    let unresolved = vec![weakref_object("weakref.o", true, "_maybe")];
    let shipped = link_app(unresolved.clone(), &[], "lookup-default")
        .expect("the default ships the runtime lookup");
    assert!(strict_ok(&shipped), "the lookup image verifies strict");
    println!(
        "default:  {} bytes — the unresolvable weak reference rides dyld's runtime lookup",
        shipped.len()
    );
    let err = link_app(unresolved, &["-no_weak_imports"], "lookup-named")
        .expect_err("the runtime-lookup weak import refuses under the knob");
    println!("named:    refuses — {err}");

    println!(
        "\n-no_weak_imports prices the runtime lookup, not the weakness — \
         try PGR_TRACING=1 to watch the pipeline"
    );
}
