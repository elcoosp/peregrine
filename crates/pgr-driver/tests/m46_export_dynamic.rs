//! M46 — the export-dynamic roots on the driver surface:
//! `-dead_strip` alone drops the unreferenced global, `-dead_strip
//! -export_dynamic` keeps it (the `dlsym` surface ld64's man page
//! names), both images verify strict, and the knob refuses where it
//! has nothing to root (dylib, bundle, relocatable) with the fix.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// A unique scratch dir per test (the house pattern: no tempfile dep).
fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir()
        .join("pgr_m46_export_dynamic")
        .join(format!(
            "{tag}_{}_{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn args(items: &[&str]) -> Vec<OsString> {
    items.iter().map(|s| OsString::from(*s)).collect()
}

/// plugin.o: `_main` calls `_live` (BL) and returns; `_dead_hook` is a
/// global definition nothing references (the `dlsym` shape). The
/// fixture's symtab groups defs before undefineds, so the reloc's
/// `r_symbolnum` names the *final* index (`_main` 0, `_dead_hook` 1,
/// `_live` 2), and `MH_SUBSECTIONS_VIA_SYMBOLS` splits the object at
/// the symbol boundaries the strip walks.
fn plugin_o(dir: &Path) -> PathBuf {
    // _main: bl _live; ret. _dead_hook: ret (defined, never referenced).
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
    let path = dir.join("plugin.o");
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    path
}

/// greet.o: the `_live` body (kept in a second object so the bind is a
/// cross-input reference the mark phase walks).
fn greet_o(dir: &Path) -> PathBuf {
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
    let path = dir.join("greet.o");
    std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
    path
}

/// The image's exported symbol names (the export trie's terminals).
fn exported_names(image: &[u8]) -> Vec<String> {
    // The trie's offset rides the LC_DYLD_EXPORTS_TRIE command.
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

#[test]
fn dead_strip_alone_drops_the_dead_global() {
    let dir = scratch("stripped");
    let plugin = plugin_o(&dir);
    let greet = greet_o(&dir);
    let out = dir.join("hello");
    let argv = args(&[
        "-o",
        out.to_str().unwrap(),
        plugin.to_str().unwrap(),
        greet.to_str().unwrap(),
        "-dead_strip",
    ]);
    let o = opts::parse(&argv).expect("the stripped argv parses");
    pgr_driver::run(&o).expect("the stripped link runs");
    let image = std::fs::read(&out).unwrap();
    assert!(strict_ok(&image), "the stripped image verifies strict");
    assert!(
        !exported_names(&image)
            .iter()
            .any(|n| n.contains("_dead_hook")),
        "the unreferenced global strips by default"
    );
}

#[test]
fn export_dynamic_keeps_the_dead_global() {
    let dir = scratch("kept");
    let plugin = plugin_o(&dir);
    let greet = greet_o(&dir);
    let out = dir.join("hello");
    let argv = args(&[
        "-o",
        out.to_str().unwrap(),
        plugin.to_str().unwrap(),
        greet.to_str().unwrap(),
        "-dead_strip",
        "-export_dynamic",
    ]);
    let o = opts::parse(&argv).expect("the export-dynamic argv parses");
    pgr_driver::run(&o).expect("the export-dynamic link runs");
    let image = std::fs::read(&out).unwrap();
    assert!(strict_ok(&image), "the kept image verifies strict");
    assert!(
        exported_names(&image)
            .iter()
            .any(|n| n.contains("_dead_hook")),
        "the unreferenced global ships under -export_dynamic"
    );
}

#[test]
fn the_knob_refuses_where_it_has_nothing_to_root() {
    // A dylib's and a bundle's strip already roots every definition;
    // the relocatable output strips nothing. Each refusal names the
    // fix (the miette help-text convention).
    let dir = scratch("refusals");
    let plugin = plugin_o(&dir);
    for (flag, hint) in [
        ("-dylib", "dylib"),
        ("-bundle", "bundle"),
        ("-r", "relocatable"),
    ] {
        let argv = args(&[
            "-o",
            dir.join("out").to_str().unwrap(),
            plugin.to_str().unwrap(),
            flag,
            "-export_dynamic",
        ]);
        let err = opts::parse(&argv).expect_err("the non-executable argv refuses");
        assert!(
            err.to_string().contains("-export_dynamic"),
            "the {hint} refusal names the knob: {err}"
        );
    }
}
