//! M100 — the singular export filters on the driver surface:
//! `-exported_symbol <name>` / `-unexported_symbol <name>` are ld64's
//! command-line siblings of the M14 list files. Each occurrence appends
//! ONE entry to the ONE composed filter table in command-line order
//! (the M90 compose pattern — the singular flags and the list files
//! interleave in flag order), the composed table feeds the unchanged
//! M14 seam (the glob matcher, the `N_PEXT` marking and the trie
//! exclusion exactly as the lists shaped them), the empty default keeps
//! every pre-knob link byte-identical, and the resident cycle plans the
//! same bytes — the composed table crosses the wire as config (the v7
//! pattern carriage, v51 naming the round).

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
    let dir = std::env::temp_dir()
        .join("pgr_m100_exported_symbol")
        .join(format!(
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
fn the_singular_flags_parse_repeatable_in_flag_order() {
    // The parse surface: each occurrence appends one spec, in command-
    // line order (the M90 shape — the composition reads the order).
    let dir = scratch("parse");
    let objs = corpus(&dir);
    let list = list_file(&dir, "exports.txt", "_sdk_read\n");
    let argv: Vec<OsString> = [
        "-o",
        dir.join("out.dylib").to_str().unwrap(),
        "-dylib",
        "-install_name",
        "@rpath/libsdk.dylib",
        objs[0].to_str().unwrap(),
        objs[1].to_str().unwrap(),
        "-exported_symbol",
        "_sdk_init",
        "-exported_symbols_list",
        &list,
        "-exported_symbol",
        "_sdk_write",
        "-unexported_symbol",
        "_internal_seed",
    ]
    .iter()
    .map(OsString::from)
    .collect();
    let o = opts::parse(&argv).expect("the argv parses");
    let kinds: Vec<&str> = o
        .export_filter_specs
        .iter()
        .map(|s| match s {
            opts::ExportFilterSpec::Exported { .. } => "exported",
            opts::ExportFilterSpec::Unexported { .. } => "unexported",
            opts::ExportFilterSpec::ExportedList { .. } => "exported_list",
            opts::ExportFilterSpec::UnexportedList { .. } => "unexported_list",
        })
        .collect();
    assert_eq!(
        kinds,
        ["exported", "exported_list", "exported", "unexported"],
        "the specs ride in flag order: {kinds:?}"
    );
    // The singular entries parse as the same pattern grammar the lists
    // carry (an exact name here; the glob gate below).
    match &o.export_filter_specs[0] {
        opts::ExportFilterSpec::Exported { pattern } => {
            assert_eq!(pattern.source(), b"_sdk_init");
        }
        other => panic!("the first spec is the singular exported entry: {other:?}"),
    }
    match &o.export_filter_specs[3] {
        opts::ExportFilterSpec::Unexported { pattern } => {
            assert_eq!(pattern.source(), b"_internal_seed");
        }
        other => panic!("the last spec is the singular unexported entry: {other:?}"),
    }
}

#[test]
fn singular_flags_compose_with_the_list_files_into_one_table() {
    // The composed only-list is ONE table: `_sdk_init` (the flag), the
    // list file's `_sdk_read`, `_sdk_write` (the flag) — every source's
    // entries select, never last-wins.
    let dir = scratch("compose");
    let list = list_file(&dir, "exports.txt", "# the middle source\n_sdk_read\n");
    let image = link_dylib(
        &dir,
        "libsdk.dylib",
        &[
            "-exported_symbol",
            "_sdk_init",
            "-exported_symbols_list",
            &list,
            "-exported_symbol",
            "_sdk_write",
        ],
    );
    assert!(strict_ok(&image), "the composed image verifies strict");
    let names = trie_names(&image);
    assert!(names.contains(&"_sdk_init".to_string()), "{names:?}");
    assert!(names.contains(&"_sdk_read".to_string()), "{names:?}");
    assert!(names.contains(&"_sdk_write".to_string()), "{names:?}");
    assert!(!names.contains(&"_internal_seed".to_string()), "{names:?}");
    assert!(!names.contains(&"_util_helper".to_string()), "{names:?}");
    // The composed only-list gates everything it does not select — the
    // header symbol rides only when a source names it (the M3 gate,
    // unchanged).
    assert!(
        !names.contains(&"__mh_execute_header".to_string()),
        "{names:?}"
    );
    // The flag form accepts the same grammar the lists widened to
    // (M14): a `*` in the value is a glob, matched like the list's.
    let dir2 = scratch("glob");
    let image2 = link_dylib(&dir2, "libsdk.dylib", &["-exported_symbol", "_sdk_*"]);
    let names2 = trie_names(&image2);
    assert!(names2.contains(&"_sdk_init".to_string()), "{names2:?}");
    assert!(names2.contains(&"_sdk_write".to_string()), "{names2:?}");
    assert!(!names2.contains(&"_util_helper".to_string()), "{names2:?}");
}

#[test]
fn singular_unexported_hides_and_marks_n_pext() {
    // The unexported form rides the seam's existing rule: the name
    // leaves the trie and stays in the symtab as an `N_PEXT` private —
    // exactly the list files' contract.
    let dir = scratch("unexported");
    let image = link_dylib(
        &dir,
        "libsdk.dylib",
        &["-unexported_symbol", "_internal_seed"],
    );
    assert!(strict_ok(&image), "the hidden image verifies strict");
    let names = trie_names(&image);
    assert!(!names.contains(&"_internal_seed".to_string()), "{names:?}");
    assert!(names.contains(&"_sdk_init".to_string()), "{names:?}");
    let n_type = symtab_n_type(&image, "_internal_seed").expect("_internal_seed in the symtab");
    assert_eq!(n_type & pgr_format::consts::N_EXT, 0, "no longer external");
    assert!(n_type & pgr_format::consts::N_PEXT != 0, "marked private");
}

#[test]
fn the_empty_default_keeps_the_pre_knob_bytes() {
    // No filter flag: the composed tables stay empty and the link is
    // byte-identical to the control (the empty default's contract) —
    // and the double link stays byte-identical too (TDD §4.3).
    let dir = scratch("default");
    let baseline = link_dylib(&dir, "libsdk.dylib", &[]);
    let again = link_dylib(&dir, "libsdk2.dylib", &[]);
    assert_eq!(baseline, again, "the default link is deterministic");
    let names = trie_names(&baseline);
    assert!(names.contains(&"_internal_seed".to_string()), "{names:?}");
    assert!(names.contains(&"_util_helper".to_string()), "{names:?}");
}

#[test]
fn bad_values_refuse_with_the_fix() {
    // The parse-time validation mirrors the list files' line grammar:
    // an empty value matches nothing, interior whitespace is not a
    // Mach-O symbol name — each refusal names the flag and the fix.
    let dir = scratch("bad_values");
    let objs = corpus(&dir);
    for (value, needle) in [
        ("", "an empty pattern matches nothing"),
        ("_foo bar", "whitespace"),
    ] {
        let argv: Vec<OsString> = [
            "-o",
            dir.join("out.dylib").to_str().unwrap(),
            "-dylib",
            objs[0].to_str().unwrap(),
            objs[1].to_str().unwrap(),
            "-exported_symbol",
            value,
        ]
        .iter()
        .map(OsString::from)
        .collect();
        let err = opts::parse(&argv).expect_err("the bad value refuses");
        let report = miette::Report::new(err);
        let msg = format!("{report:?}");
        assert!(
            msg.contains("-exported_symbol") && msg.contains(needle),
            "the refusal names the flag and the fix ({needle}): {msg}"
        );
    }
    // The missing argument refuses like every valued flag.
    let argv: Vec<OsString> = [
        "-o",
        dir.join("out.dylib").to_str().unwrap(),
        objs[0].to_str().unwrap(),
        "-exported_symbol",
    ]
    .iter()
    .map(OsString::from)
    .collect();
    let err = opts::parse(&argv).expect_err("the bare flag refuses");
    assert!(
        err.to_string().contains("-exported_symbol"),
        "the missing-argument refusal names the flag: {err}"
    );
}

#[test]
fn the_list_files_keep_their_once_only_contract() {
    // The singular forms are the repeatable face; the list files stay
    // once-per-kind (the M3 contract the surface pinned).
    let dir = scratch("once");
    let objs = corpus(&dir);
    let list = list_file(&dir, "exports.txt", "_sdk_read\n");
    let argv: Vec<OsString> = [
        "-o",
        dir.join("out.dylib").to_str().unwrap(),
        "-dylib",
        objs[0].to_str().unwrap(),
        objs[1].to_str().unwrap(),
        "-exported_symbols_list",
        &list,
        "-exported_symbols_list",
        &list,
    ]
    .iter()
    .map(OsString::from)
    .collect();
    let err = opts::parse(&argv).expect_err("the second list file refuses");
    assert!(
        err.to_string().contains("given more than once"),
        "the once-only contract holds: {err}"
    );
}

#[test]
fn the_resident_cycle_plans_the_same_composed_bytes() {
    // One-shot reference: flag + list file composed.
    let dir = scratch("resident_ref");
    let list = list_file(&dir, "exports.txt", "_sdk_read\n");
    let one_shot = link_dylib(
        &dir,
        "libsdk.dylib",
        &[
            "-exported_symbol",
            "_sdk_init",
            "-exported_symbols_list",
            &list,
            "-exported_symbol",
            "_sdk_write",
        ],
    );

    // The same link through the resident path: the composed table rides
    // the config (the v7 pattern carriage), so the session's own walk
    // plans the identical bytes.
    let dir2 = scratch("resident");
    let list2 = list_file(&dir2, "exports.txt", "_sdk_read\n");
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
    argv.extend([
        "-exported_symbol".to_string(),
        "_sdk_init".to_string(),
        "-exported_symbols_list".to_string(),
        list2,
        "-exported_symbol".to_string(),
        "_sdk_write".to_string(),
    ]);
    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    let o = opts::parse(&argv).expect("the resident argv parses");
    pgr_driver::run(&o).expect("the resident link runs");
    let resident = std::fs::read(&out_path).unwrap();
    assert_eq!(
        one_shot, resident,
        "the resident cycle plans the same composed bytes"
    );
    let names = trie_names(&resident);
    assert!(names.contains(&"_sdk_read".to_string()), "{names:?}");
    assert!(!names.contains(&"_internal_seed".to_string()), "{names:?}");
}
