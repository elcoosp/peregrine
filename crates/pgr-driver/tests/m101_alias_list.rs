//! M101 — the `-alias_list <file>` driver surface: ld64's file form of
//! M24's `-alias`. One `alias definition` pair per line (the house
//! list-file grammar — blank lines and `#` comments skip), the pairs
//! append to the ONE alias table in command-line order beside the
//! `-alias` flags (the M90 compose pattern), and the M24 refusal
//! contracts ride unchanged — an alias of a name no input defines
//! refuses with the misspelling named, an alias name already defined or
//! referenced refuses, the alias keeps its definition alive under
//! `-dead_strip`. The composed table rides the v16 alias wire carriage
//! and the ladder exactly as the single flags' pairs always did (the
//! resident cycle plans the same bytes, wire v52 naming the round).

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
        .join("pgr_m101_alias_list")
        .join(format!(
            "{tag}_{}_{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// lib.o: `_main`, `_lib_fn` and one unreferenced body (`_orphan_fn`)
/// the dead-strip gate exercises; two functions per object so the
/// aliases have distinct definitions to point at.
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
        object(dir, "main.o", &["_main", "_lib_fn"]),
        object(dir, "util.o", &["_util_fn", "_orphan_fn"]),
    ]
}

/// Writes an alias-list file; returns its argv form.
fn alias_file(dir: &Path, name: &str, text: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    path.display().to_string()
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
        "@rpath/libalias.dylib".to_string(),
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

/// The symtab's names, in row order (the alias rows land in the
/// composed order the sources named — the emit order the seam pins).
fn symtab_names(image: &[u8]) -> Vec<String> {
    let header = pgr_format::MachHeader64::parse(image).expect("the header parses");
    let mut it = pgr_format::LoadCommandIter::new(
        image,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .expect("the load commands walk");
    while let Ok(Some(cmd)) = it.next_command() {
        if cmd.kind != pgr_format::LoadCommandKind::Symtab {
            continue;
        }
        let st = pgr_format::SymtabCommand::parse(cmd.bytes, 0).expect("the LC parses");
        let mut names = Vec::new();
        for i in 0..st.nsyms as usize {
            let sym: pgr_format::Nlist64 =
                pgr_format::cursor::pod_read_unaligned_at(image, st.symoff as usize + i * 16)
                    .expect("the row reads");
            let strx = st.stroff as usize + sym.n_strx as usize;
            let end = image[strx..].iter().position(|&b| b == 0).unwrap_or(0);
            names.push(String::from_utf8_lossy(&image[strx..strx + end]).into_owned());
        }
        return names;
    }
    panic!("no LC_SYMTAB in the image");
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
fn the_file_form_composes_with_the_flags_in_flag_order() {
    // The parse surface: pairs and files ride the ordered source list
    // (the M90 shape — the composition reads the order).
    let dir = scratch("parse");
    let objs = corpus(&dir);
    let list = alias_file(&dir, "aliases.txt", "_shim_m1 _lib_fn\n_shim_m2 _main\n");
    let argv: Vec<OsString> = [
        "-o",
        dir.join("out.dylib").to_str().unwrap(),
        "-dylib",
        objs[0].to_str().unwrap(),
        objs[1].to_str().unwrap(),
        "-alias",
        "_shim_a",
        "_lib_fn",
        "-alias_list",
        &list,
        "-alias",
        "_shim_b",
        "_main",
    ]
    .iter()
    .map(OsString::from)
    .collect();
    let o = opts::parse(&argv).expect("the argv parses");
    let kinds: Vec<&str> = o
        .alias_sources
        .iter()
        .map(|s| match s {
            opts::AliasSource::Pair { .. } => "pair",
            opts::AliasSource::ListFile { .. } => "file",
        })
        .collect();
    assert_eq!(
        kinds,
        ["pair", "file", "pair"],
        "the sources ride in flag order: {kinds:?}"
    );

    // The end-to-end shape: every pair rides — flag, file, flag — and
    // each alias resolves at its definition's address (the M24 symtab +
    // trie contract, composed).
    let image = link_dylib(
        &dir,
        "libalias.dylib",
        &[
            "-alias",
            "_shim_a",
            "_lib_fn",
            "-alias_list",
            &list,
            "-alias",
            "_shim_b",
            "_main",
        ],
    );
    assert!(strict_ok(&image), "the composed image verifies strict");
    let names = trie_names(&image);
    for expected in ["_shim_a", "_shim_m1", "_shim_m2", "_shim_b"] {
        assert!(names.contains(&expected.to_string()), "{names:?}");
    }
    // The symtab rows land in composed order (the file's pairs between
    // the flags' rows — the emit order the seam pins).
    let rows = symtab_names(&image);
    let at = |name: &str| rows.iter().position(|n| n == name);
    let (a, m1, m2, b) = (at("_shim_a"), at("_shim_m1"), at("_shim_m2"), at("_shim_b"));
    assert!(
        a < m1 && m1 < m2 && m2 < b,
        "composed order a < m1 < m2 < b: {rows:?}"
    );
}

#[test]
fn the_file_grammar_skips_blanks_and_comments() {
    // The house list-file grammar (the M11/M14 convention): blank lines
    // and `#` comments skip, one `alias definition` pair per line.
    let dir = scratch("grammar");
    let list = alias_file(
        &dir,
        "aliases.txt",
        "# the shim surface\n\n_shim_one _lib_fn\n   \n# a tail comment\n_shim_two _main\n",
    );
    let image = link_dylib(&dir, "libalias.dylib", &["-alias_list", &list]);
    assert!(strict_ok(&image), "the composed image verifies strict");
    let names = trie_names(&image);
    assert!(names.contains(&"_shim_one".to_string()), "{names:?}");
    assert!(names.contains(&"_shim_two".to_string()), "{names:?}");
}

#[test]
fn a_malformed_file_line_refuses_with_the_line_named() {
    // One pair per line: a one-field line is a typo the reader names —
    // never a silently dropped pair.
    let dir = scratch("malformed");
    let objs = corpus(&dir);
    let list = alias_file(&dir, "aliases.txt", "_shim _lib_fn\njust_one_name\n");
    let out_path = dir.join("libalias.dylib");
    let mut argv = vec![
        "-o".to_string(),
        out_path.display().to_string(),
        "-dylib".to_string(),
        objs[0].display().to_string(),
        objs[1].display().to_string(),
        "-alias_list".to_string(),
        list,
    ];
    argv.push(String::new());
    argv.pop();
    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    let o = opts::parse(&argv).expect("the argv parses");
    let err = pgr_driver::run(&o).expect_err("the malformed line refuses");
    let rendered = err.to_string();
    assert!(rendered.contains("-alias_list"), "{rendered}");
    assert!(rendered.contains("aliases.txt"), "{rendered}");
    assert!(rendered.contains("just_one_name"), "{rendered}");
    assert!(!out_path.exists(), "the refused link writes no image");
}

#[test]
fn a_file_pair_of_an_undefined_name_refuses_with_the_misspelling() {
    // The M24 layout refusal rides the file form unchanged: an alias of
    // a name no input defines names the misspelling (the fix), and no
    // image ships.
    let dir = scratch("undefined");
    let list = alias_file(&dir, "aliases.txt", "_shim _lib_fnn\n");
    let out_path = dir.join("libalias.dylib");
    let argv: Vec<OsString> = [
        "-o",
        out_path.to_str().unwrap(),
        "-dylib",
        dir.join("main.o").to_str().unwrap(),
        dir.join("util.o").to_str().unwrap(),
        "-alias_list",
        &list,
    ]
    .iter()
    .map(OsString::from)
    .collect();
    let o = opts::parse(&argv).expect("the argv parses");
    // The corpus does not exist in this scratch dir yet — link_dylib's
    // corpus is written per-dir, so write it here.
    let _ = corpus(&dir);
    let err = pgr_driver::run(&o).expect_err("the misspelled definition refuses");
    let rendered = err.to_string();
    assert!(rendered.contains("_shim"), "{rendered}");
    assert!(
        rendered.contains("_lib_fnn") && rendered.contains("not defined by any input"),
        "the refusal names the misspelling and the fix: {rendered}"
    );
    assert!(!out_path.exists(), "the refused link writes no image");
}

#[test]
fn a_file_pair_duplicating_a_flag_alias_refuses() {
    // One decision per name (the M24 duplicate contract): the file's
    // pairs compose into the SAME table the flags pushed, so a repeat —
    // flag then file, either order — refuses with the name named.
    let dir = scratch("duplicate");
    let objs = corpus(&dir);
    let list = alias_file(&dir, "aliases.txt", "_shim_dup _main\n");
    let out_path = dir.join("libalias.dylib");
    let argv: Vec<OsString> = [
        "-o",
        out_path.to_str().unwrap(),
        "-dylib",
        objs[0].to_str().unwrap(),
        objs[1].to_str().unwrap(),
        "-alias",
        "_shim_dup",
        "_lib_fn",
        "-alias_list",
        &list,
    ]
    .iter()
    .map(OsString::from)
    .collect();
    let o = opts::parse(&argv).expect("the argv parses");
    let err = pgr_driver::run(&o).expect_err("the duplicate refuses");
    let rendered = err.to_string();
    assert!(rendered.contains("_shim_dup"), "{rendered}");
    assert!(!out_path.exists(), "the refused link writes no image");
}

#[test]
fn the_relocatable_output_refuses_the_file_form() {
    // The M24 output-kind conflict rides the file form unchanged: the
    // relocatable output carries the input symtab verbatim — an alias
    // (flag or file) has no symtab row to grow.
    let dir = scratch("reloc");
    let objs = corpus(&dir);
    let list = alias_file(&dir, "aliases.txt", "_shim _lib_fn\n");
    let argv: Vec<OsString> = [
        "-o",
        dir.join("out.o").to_str().unwrap(),
        "-r",
        objs[0].to_str().unwrap(),
        "-alias_list",
        &list,
    ]
    .iter()
    .map(OsString::from)
    .collect();
    let err = opts::parse(&argv).expect_err("the relocatable output refuses");
    let msg = err.to_string();
    assert!(
        msg.contains("relocatable"),
        "the refusal names the output kind: {msg}"
    );
}

#[test]
fn the_file_alias_keeps_its_definition_alive_under_dead_strip() {
    // The M24 dead-strip root rides the composed table: an alias (flag
    // or file) of an otherwise-unreferenced body keeps it alive. The
    // gate runs on an executable (a dylib's export surface is its own
    // root set — the M5 contract — so the strip gate needs the
    // entry-rooted shape).
    let dir = scratch("deadstrip");
    let objs = corpus(&dir);
    let keep_list = alias_file(&dir, "keep.txt", "_shim_keep _orphan_fn\n");
    let link_exe = |out: &str, extra: &[&str]| {
        let out_path = dir.join(out);
        let mut argv = vec!["-o".to_string(), out_path.display().to_string()];
        for obj in &objs {
            argv.push(obj.display().to_string());
        }
        argv.extend(extra.iter().map(std::string::ToString::to_string));
        let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
        let o = opts::parse(&argv).expect("the argv parses");
        pgr_driver::run(&o).expect("the executable links");
        std::fs::read(&out_path).unwrap()
    };
    let control = link_exe("control", &["-dead_strip"]);
    let names = trie_names(&control);
    assert!(
        !names.contains(&"_orphan_fn".to_string()),
        "the control: the unreferenced body strips: {names:?}"
    );
    let kept = link_exe("kept", &["-dead_strip", "-alias_list", &keep_list]);
    assert!(strict_ok(&kept), "the kept image verifies strict");
    let names = trie_names(&kept);
    assert!(names.contains(&"_shim_keep".to_string()), "{names:?}");
    assert!(
        names.contains(&"_orphan_fn".to_string()),
        "the aliased definition stays alive: {names:?}"
    );
}

#[test]
fn the_resident_cycle_plans_the_same_composed_alias_bytes() {
    // One-shot reference: flag pairs and file pairs composed.
    let dir = scratch("resident_ref");
    let list = alias_file(&dir, "aliases.txt", "_shim_m _lib_fn\n");
    let one_shot = link_dylib(
        &dir,
        "libalias.dylib",
        &["-alias", "_shim_a", "_main", "-alias_list", &list],
    );

    // The same link through the resident path: the composed table rides
    // the v16 alias carriage (the pairs the client named cross as
    // config), so the session's own walk plans the identical bytes.
    let dir2 = scratch("resident");
    let list2 = alias_file(&dir2, "aliases.txt", "_shim_m _lib_fn\n");
    let sock = dir2.join("pgrd.sock");
    let owned = sock.clone();
    std::thread::spawn(move || {
        let _ = pgr_daemon::serve(&owned, Duration::from_secs(120));
    });
    std::thread::sleep(Duration::from_millis(50));

    let objs = corpus(&dir2);
    let out_path = dir2.join("libalias.dylib");
    let mut argv = vec![
        "-o".to_string(),
        out_path.display().to_string(),
        "-dylib".to_string(),
        "-install_name".to_string(),
        "@rpath/libalias.dylib".to_string(),
        "-resident".to_string(),
        "-resident_socket".to_string(),
        sock.display().to_string(),
    ];
    for obj in &objs {
        argv.push(obj.display().to_string());
    }
    argv.extend([
        "-alias".to_string(),
        "_shim_a".to_string(),
        "_main".to_string(),
        "-alias_list".to_string(),
        list2,
    ]);
    let argv: Vec<OsString> = argv.iter().map(OsString::from).collect();
    let o = opts::parse(&argv).expect("the resident argv parses");
    pgr_driver::run(&o).expect("the resident link runs");
    let resident = std::fs::read(&out_path).unwrap();
    assert_eq!(
        one_shot, resident,
        "the resident cycle plans the same composed alias bytes"
    );
    let names = trie_names(&resident);
    assert!(names.contains(&"_shim_a".to_string()), "{names:?}");
    assert!(names.contains(&"_shim_m".to_string()), "{names:?}");
}
