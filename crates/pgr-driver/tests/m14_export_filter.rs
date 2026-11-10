//! M14 — the `-exported_symbols_list`/`-unexported_symbols_list` glob
//! surface: list files carry `*` wildcards (the ld64 subset), the
//! filtered image exports exactly the matched names and hides the rest
//! as `N_PEXT` privates, a malformed pattern refuses with the fix in
//! the message (never a silent drop), exact entries keep the M3
//! behavior, and the resident cycle plans the same bytes — the wire
//! (protocol v7) carries the patterns, not just the names.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

/// A unique scratch dir per test (the house pattern: no tempfile dep).
fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join("pgr_m14_driver").join(format!(
        "{tag}_{}_{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// sdk.o: `_main`, an `_sdk_*` surface, an internal helper; util.o: a
/// second `_sdk_*` definition and a util helper. The dylib surface has
/// names on both sides of every filter the gates exercise.
fn corpus(dir: &Path) -> Vec<PathBuf> {
    fn object(dir: &Path, name: &str, syms: &[&str]) -> PathBuf {
        let mut b = ObjectBuilder::new(name).set_subsections_via_symbols(true);
        let text = b.add_section(ObjectSection::text(
            "__text",
            [0xC0u8, 0x03, 0x5F, 0xD6].repeat(syms.len()),
            vec![],
        ));
        for (i, sym) in syms.iter().enumerate() {
            b.add_symbol(ObjectSymbol::Defined {
                name: (*sym).into(),
                section_index: text,
                value: (i * 4) as u64,
                weak: false,
            });
        }
        let path = dir.join(name);
        std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
        path
    }
    vec![
        object(
            dir,
            "sdk.o",
            &["_main", "_sdk_init", "_sdk_read", "_internal_seed"],
        ),
        object(dir, "util.o", &["_sdk_write", "_util_helper"]),
    ]
}

/// Links the corpus as a dylib under `extra` argv entries; returns the
/// image bytes.
fn link_dylib(dir: &Path, out: &str, extra: &[&str]) -> Vec<u8> {
    let objs = corpus(dir);
    let out_path = dir.join(out);
    let mut argv = vec![
        "-o".to_string(),
        out_path.display().to_string(),
        "-dylib".to_string(),
        "-install_name".to_string(),
        "@rpath/libsdk.dylib".to_string(),
    ];
    for obj in &objs {
        argv.push(obj.display().to_string());
    }
    argv.extend(extra.iter().map(std::string::ToString::to_string));
    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    let o = opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the dylib links");
    std::fs::read(&out_path).unwrap()
}

/// Writes a symbol-list file; returns its argv form.
fn list_file(dir: &Path, name: &str, text: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    path.display().to_string()
}

/// The image's export-trie names.
fn trie_names(image: &[u8]) -> Vec<String> {
    let header = pgr_format::MachHeader64::parse(image).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands walk");
    while let Ok(Some(cmd)) = it.next_command() {
        if cmd.kind
            == pgr_format::LoadCommandKind::LinkeditData(pgr_format::consts::LC_DYLD_EXPORTS_TRIE)
        {
            let lc = pgr_format::LinkeditDataCommand::parse(cmd.bytes).expect("the LC parses");
            let blob = lc.data(image).expect("the trie payload is in range");
            return pgr_format::trie::exports(blob)
                .expect("the trie parses")
                .into_iter()
                .map(|e| String::from_utf8_lossy(&e.name).into_owned())
                .collect();
        }
    }
    panic!("no LC_DYLD_EXPORTS_TRIE in the image");
}

/// The symtab's `n_type` for `name` (`None` when absent).
fn symtab_n_type(image: &[u8], name: &str) -> Option<u8> {
    let header = pgr_format::MachHeader64::parse(image).ok()?;
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .ok()?;
    while let Ok(Some(cmd)) = it.next_command() {
        if cmd.kind != pgr_format::LoadCommandKind::Symtab {
            continue;
        }
        let st = pgr_format::SymtabCommand::parse(cmd.bytes, 0).ok()?;
        for i in 0..st.nsyms as usize {
            let sym: pgr_format::Nlist64 =
                pgr_format::cursor::pod_read_unaligned_at(image, st.symoff as usize + i * 16)
                    .ok()?;
            let strx = st.stroff as usize + sym.n_strx as usize;
            let end = image[strx..].iter().position(|&b| b == 0)?;
            if String::from_utf8_lossy(&image[strx..strx + end]) == name {
                return Some(sym.n_type);
            }
        }
    }
    None
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
fn glob_list_file_shapes_the_export_surface() {
    let dir = scratch("glob");
    let list = list_file(
        &dir,
        "exports.txt",
        "# the SDK surface (M14: globs)\n\n__mh_execute_header\n_sdk_*\n",
    );
    let image = link_dylib(&dir, "libsdk.dylib", &["-exported_symbols_list", &list]);
    assert!(strict_ok(&image), "the glob-filtered image verifies strict");

    let names = trie_names(&image);
    assert!(names.contains(&"_sdk_init".to_string()), "{names:?}");
    assert!(names.contains(&"_sdk_write".to_string()), "{names:?}");
    assert!(
        names.contains(&"__mh_execute_header".to_string()),
        "{names:?}"
    );
    assert!(!names.contains(&"_internal_seed".to_string()), "{names:?}");
    assert!(!names.contains(&"_util_helper".to_string()), "{names:?}");

    // The unexported glob hides the internal surface as N_PEXT privates.
    let dir2 = scratch("unexported");
    let hide = list_file(&dir2, "hide.txt", "_internal_*\n");
    let image2 = link_dylib(&dir2, "libsdk.dylib", &["-unexported_symbols_list", &hide]);
    assert!(strict_ok(&image2), "the hidden image verifies strict");
    let names2 = trie_names(&image2);
    assert!(
        !names2.contains(&"_internal_seed".to_string()),
        "{names2:?}"
    );
    let n_type = symtab_n_type(&image2, "_internal_seed").expect("_internal_seed in the symtab");
    assert_eq!(n_type & pgr_format::consts::N_EXT, 0, "no longer external");
    assert!(n_type & pgr_format::consts::N_PEXT != 0, "marked private");
}

#[test]
fn malformed_pattern_refuses_with_the_fix() {
    let dir = scratch("malformed");
    let list = list_file(&dir, "exports.txt", "_sdk_init\n_foo bar\n");
    let objs = corpus(&dir);
    let out_path = dir.join("libsdk.dylib");
    let mut argv = vec![
        "-o".to_string(),
        out_path.display().to_string(),
        "-dylib".to_string(),
        "-install_name".to_string(),
        "@rpath/libsdk.dylib".to_string(),
    ];
    for obj in &objs {
        argv.push(obj.display().to_string());
    }
    argv.push("-exported_symbols_list".to_string());
    argv.push(list.clone());
    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    let o = opts::parse(&argv).expect("the argv parses");
    let err = pgr_driver::run(&o).expect_err("the whitespace pattern refuses");
    let rendered = err.to_string();
    assert!(rendered.contains("-exported_symbols_list"), "{rendered}");
    assert!(rendered.contains("exports.txt"), "{rendered}");
    assert!(rendered.contains("_foo bar"), "{rendered}");
    assert!(!out_path.exists(), "the refused link writes no image");
}

#[test]
fn exact_entries_keep_the_m3_behavior() {
    let dir = scratch("exact");
    let list = list_file(&dir, "exports.txt", "__mh_execute_header\n_sdk_write\n");
    let image = link_dylib(&dir, "libsdk.dylib", &["-exported_symbols_list", &list]);
    let names = trie_names(&image);
    assert!(names.contains(&"_sdk_write".to_string()), "{names:?}");
    assert!(!names.contains(&"_sdk_init".to_string()), "{names:?}");
    assert!(!names.contains(&"_sdk_read".to_string()), "{names:?}");
    assert!(
        strict_ok(&image),
        "the exact-filtered image verifies strict"
    );
}

#[test]
fn resident_cycle_carries_the_glob_filter() {
    // One-shot reference.
    let dir = scratch("resident_ref");
    let list = list_file(&dir, "exports.txt", "__mh_execute_header\n_sdk_*\n");
    let one_shot = link_dylib(&dir, "libsdk.dylib", &["-exported_symbols_list", &list]);

    // The same link through the resident path: the daemon relinks with
    // the same config, so the patterns crossed the wire (v7) intact.
    let dir2 = scratch("resident");
    let list2 = list_file(&dir2, "exports.txt", "__mh_execute_header\n_sdk_*\n");
    let sock = dir2.join("pgrd.sock");
    let owned = sock.clone();
    std::thread::spawn(move || {
        let _ = pgr_daemon::serve(&owned, Duration::from_secs(120));
    });
    std::thread::sleep(Duration::from_millis(50));

    let objs = corpus(&dir2);
    let out_path = dir2.join("libsdk.dylib");
    let mut argv = vec![
        "-o".to_string(),
        out_path.display().to_string(),
        "-dylib".to_string(),
        "-install_name".to_string(),
        "@rpath/libsdk.dylib".to_string(),
        "-resident".to_string(),
        "-resident_socket".to_string(),
        sock.display().to_string(),
    ];
    for obj in &objs {
        argv.push(obj.display().to_string());
    }
    argv.push("-exported_symbols_list".to_string());
    argv.push(list2);
    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    let o = opts::parse(&argv).expect("the resident argv parses");
    pgr_driver::run(&o).expect("the resident link runs");
    let resident = std::fs::read(&out_path).unwrap();
    assert_eq!(
        one_shot, resident,
        "the resident cycle plans the same bytes with a glob filter"
    );
    let names = trie_names(&resident);
    assert!(names.contains(&"_sdk_init".to_string()), "{names:?}");
    assert!(!names.contains(&"_internal_seed".to_string()), "{names:?}");
}
