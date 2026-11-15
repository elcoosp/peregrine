//! The export-dynamic consumer example (M46): shipping a plugin-style
//! main executable — `-dead_strip` alone drops the unreferenced global,
//! `-dead_strip -export_dynamic` keeps it (ld64's man page: *"Preserves
//! all global symbols in main executables during dead stripping"* — the
//! `dlsym` surface is a runtime contract the static fixpoint cannot
//! see). Both images verify strict; the export tries are read back —
//! the surface a build system audits after the link.
//!
//! Run: `cargo run -p pgr-driver --example export_dynamic_link`
//! (`PGR_TRACING=1` installs a subscriber for the pipeline spans — the
//! same inert-until-subscriber convention the binaries use).

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// plugin.o: `_main` calls `_live` (BL) and returns; `_dead_hook` is a
/// global definition nothing references — the body the `dlsym` caller
/// reaches at runtime. The fixture's symtab groups defs before
/// undefineds, so the reloc's `r_symbolnum` names the *final* index
/// (`_main` 0, `_dead_hook` 1, `_live` 2), and
/// `MH_SUBSECTIONS_VIA_SYMBOLS` splits the object at the symbol
/// boundaries the strip walks.
fn plugin_object() -> Vec<u8> {
    let text: Vec<u8> = [
        0x9400_0000u32, // bl _live
        0xD65F_03C0u32, // ret
        0xD65F_03C0u32, // _dead_hook: ret
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect();
    let mut b = ObjectBuilder::new("plugin.o").set_subsections_via_symbols(true);
    let sect = b.add_section(ObjectSection::text("__text", text, Vec::new()));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_dead_hook".into(),
        section_index: sect,
        value: 8,
        weak: false,
    });
    let live = b.add_symbol(ObjectSymbol::Undefined {
        name: "_live".into(),
        weak_ref: false,
    });
    b.section_mut(sect)
        .relocs
        .push(ObjectReloc::branch26(u32::try_from(live).unwrap()).at(0));
    b.build().expect("the fixture object builds")
}

/// greet.o: the `_live` body.
fn greet_object() -> Vec<u8> {
    let mut b = ObjectBuilder::new("greet.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6], // ret
        Vec::new(),
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_live".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// The image's exported symbol names (the export trie's terminals).
fn exported_names(image: &[u8]) -> Vec<String> {
    let hdr = pgr_format::MachHeader64::parse(image).expect("the image parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    )
    .expect("the load commands parse");
    let mut trie_at: Option<(u64, u64)> = None;
    while let Some(cmd) = it.next_command().expect("the command chain walks") {
        if let pgr_format::LoadCommandKind::LinkeditData(pgr_format::consts::LC_DYLD_EXPORTS_TRIE) =
            cmd.kind
        {
            let lc = pgr_format::LinkeditDataCommand::parse(cmd.bytes).expect("the lc parses");
            trie_at = Some((u64::from(lc.dataoff), u64::from(lc.datasize)));
        }
    }
    let Some((off, size)) = trie_at else {
        return Vec::new();
    };
    let end = usize::try_from(off + size).expect("the trie end fits");
    let start = usize::try_from(off).expect("the trie start fits");
    pgr_format::trie::exports(&image[start..end])
        .expect("the trie walks")
        .into_iter()
        .map(|e| String::from_utf8_lossy(&e.name).to_string())
        .collect()
}

/// Links the corpus with the named extra flags; returns (bytes, size).
fn link_with(dir: &std::path::Path, extra: &[&str], tag: &str) -> (Vec<u8>, u64) {
    let plugin = dir.join(format!("plugin-{tag}.o"));
    let greet = dir.join(format!("greet-{tag}.o"));
    let out = dir.join(format!("hello-{tag}"));
    std::fs::write(&plugin, plugin_object()).unwrap();
    std::fs::write(&greet, greet_object()).unwrap();
    let mut argv: Vec<std::ffi::OsString> = Vec::new();
    for a in [
        "-o",
        out.to_str().unwrap(),
        plugin.to_str().unwrap(),
        greet.to_str().unwrap(),
        "-dead_strip",
    ] {
        argv.push(std::ffi::OsString::from(a));
    }
    for a in extra {
        argv.push(std::ffi::OsString::from(*a));
    }
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs");
    let image = std::fs::read(&out).expect("the image reads");
    let size = image.len() as u64;
    (image, size)
}

fn strict_ok(image: &[u8]) -> bool {
    verify(
        image,
        &VerifyOptions {
            strict_warnings: true,
            skip_hash_recompute: false,
        },
    )
    .is_ok(&VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    })
}

fn main() {
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    let dir = std::env::temp_dir().join(format!("pgr_export_dynamic_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // The stripped lane: `-dead_strip` alone — the unreferenced global
    // drops (the mark phase never reaches it).
    let (stripped, stripped_size) = link_with(&dir, &[], "stripped");
    let stripped_exports = exported_names(&stripped);

    // The widened lane: `-dead_strip -export_dynamic` — the global
    // definition roots the mark phase, the body and its trie node ride.
    let (kept, kept_size) = link_with(&dir, &["-export_dynamic"], "kept");
    let kept_exports = exported_names(&kept);

    assert!(
        strict_ok(&stripped) && strict_ok(&kept),
        "both lanes verify strict"
    );
    println!(
        "dead_strip alone:        {stripped_size:>6} bytes — hook exported: {}",
        { stripped_exports.iter().any(|n| n.contains("_dead_hook")) }
    );
    println!(
        "dead_strip -export_dynamic: {kept_size:>3} bytes — hook exported: {}",
        { kept_exports.iter().any(|n| n.contains("_dead_hook")) }
    );
    println!("kept exports: {}", kept_exports.join(", "));
    println!(
        "\nthe widened roots preserve the dlsym surface; try PGR_TRACING=1 to watch the pipeline"
    );
}
