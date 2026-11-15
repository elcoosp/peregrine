//! M41 — the dedup-toggle driver surface: `-no_deduplicate` links a
//! duplicate-literal corpus into an image whose `__TEXT,__cstring`
//! carries every input copy verbatim (and verifies strict), the
//! default keeps the M5/D4 merge byte-identical, the cached lane stays
//! byte-identical under the knob (the cache carries parsed inputs, the
//! knob rides the plan), and the incremental relink of a knob flip
//! lands on the full-link rung byte-identically (the literal pool's
//! size changes — the record's skeleton no longer matches).

use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};
use pgr_format::{LoadCommandIter, LoadCommandKind, MachHeader64};
use pgr_verify::{Options as VerifyOptions, verify};
use std::path::{Path, PathBuf};

/// The literal both objects carry (identical bytes — the D4 merge's
/// input shape).
const LITERAL: &str = "shared literal v41";

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("pgr_m41_dedup_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch dir builds");
    dir
}

/// One object: `_main` (first object only) over two RET functions and a
/// `__cstring` carrying the shared literal, named by an external symbol.
fn dup_object(tag: &str, main: bool) -> Vec<u8> {
    let mut b = ObjectBuilder::new(&format!("{tag}.o")).set_subsections_via_symbols(true);
    let text = b.add_section(ObjectSection::text(
        "__text",
        [0xC0u8, 0x03, 0x5F, 0xD6].repeat(2),
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: if main {
            "_main".into()
        } else {
            format!("_{tag}_fn")
        },
        section_index: text,
        value: 0,
        weak: false,
    });
    let cstr = b.add_section(ObjectSection::cstring(LITERAL));
    b.add_symbol(ObjectSymbol::Defined {
        name: format!("_{tag}_str"),
        section_index: cstr,
        value: 0,
        weak: false,
    });
    b.build().expect("the fixture object builds")
}

/// Writes the two-object corpus; returns the object paths in
/// command-line order.
fn corpus(dir: &Path, tag: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for (name, main) in [("_a", true), ("_b", false)] {
        let path = dir.join(format!("{tag}{name}.o"));
        std::fs::write(&path, dup_object(name, main)).unwrap();
        paths.push(path);
    }
    paths
}

/// Links `objs` under `extra` argv; returns the image bytes.
fn link(dir: &Path, out: &str, objs: &[PathBuf], extra: &[&str]) -> Vec<u8> {
    let out_path = dir.join(out);
    let mut argv: Vec<String> = vec!["-o".into(), out_path.display().to_string()];
    argv.extend(objs.iter().map(|p| p.display().to_string()));
    argv.extend(extra.iter().map(std::string::ToString::to_string));
    let argv: Vec<std::ffi::OsString> = argv.iter().map(std::ffi::OsString::from).collect();
    let o = pgr_driver::opts::parse(&argv).expect("the argv parses");
    pgr_driver::run(&o).expect("the link runs");
    std::fs::read(&out_path).expect("the image reads")
}

fn strict() -> VerifyOptions {
    VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    }
}

/// The `__TEXT,__cstring` section's file offset and size.
fn cstring_span(image: &[u8]) -> (u32, u32) {
    let header = MachHeader64::parse(image).expect("the image parses");
    let mut it = LoadCommandIter::new(image, MachHeader64::SIZE, header.ncmds, header.sizeofcmds)
        .expect("the load commands parse");
    while let Some(cmd) = it.next_command().expect("the next command parses") {
        if let LoadCommandKind::Segment64 = cmd.kind {
            let seg =
                pgr_format::SegmentCommand64::parse(cmd.bytes, 0).expect("the segment parses");
            for s in seg
                .sections(cmd.bytes, pgr_format::SegmentCommand64::SIZE)
                .expect("the sections parse")
            {
                if s.segname.starts_with(b"__TEXT\0") && s.sectname.starts_with(b"__cstring\0") {
                    return (s.offset, s.size as u32);
                }
            }
        }
    }
    panic!("the corpus carries a cstring bucket")
}

/// The image's `__cstring` bytes.
fn cstring_bytes(image: &[u8]) -> Vec<u8> {
    let (off, size) = cstring_span(image);
    image[off as usize..(off + size) as usize].to_vec()
}

/// The image's symtab as `name → (value, n_sect, n_type)`.
fn output_symbols(bytes: &[u8]) -> Vec<(String, u64, u8, u8)> {
    let header = pgr_format::MachHeader64::parse(bytes).unwrap();
    let mut it = pgr_format::LoadCommandIter::new(
        bytes,
        pgr_format::MachHeader64::SIZE,
        header.ncmds,
        header.sizeofcmds,
    )
    .unwrap();
    let mut out = Vec::new();
    while let Some(cmd) = it.next_command().unwrap() {
        if let pgr_format::LoadCommandKind::Symtab = cmd.kind {
            let st = pgr_format::SymtabCommand::parse(cmd.bytes, 0).unwrap();
            for i in 0..st.nsyms {
                let sym: pgr_format::symtab::Nlist64 = pgr_format::cursor::pod_read_unaligned_at(
                    bytes,
                    st.symoff as usize + i as usize * 16,
                )
                .unwrap();
                let strx = sym.n_strx as usize;
                let end = bytes[st.stroff as usize + strx..]
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap();
                let name = String::from_utf8_lossy(
                    &bytes[st.stroff as usize + strx..st.stroff as usize + strx + end],
                )
                .into_owned();
                out.push((name, sym.n_value, sym.n_sect, sym.n_type));
            }
        }
    }
    out
}

#[test]
fn m41_flag_shapes_the_config() {
    let dir = scratch("opts");
    let objs = corpus(&dir, "opts");
    let mut argv: Vec<std::ffi::OsString> = vec![
        std::ffi::OsString::from("-o"),
        dir.join("app").as_os_str().to_os_string(),
    ];
    argv.extend(objs.iter().map(|p| p.as_os_str().to_os_string()));
    argv.push(std::ffi::OsString::from("-no_deduplicate"));
    let o = pgr_driver::opts::parse(&argv).expect("the argv parses");
    assert!(!o.config.deduplicate, "the toggle names the decision");
    let default = pgr_driver::opts::parse(&argv[..2 + objs.len()]).expect("the argv parses");
    assert!(
        default.config.deduplicate,
        "the default keeps every pre-M41 link byte-identical"
    );
}

#[test]
fn the_default_merges_and_the_suppression_keeps_verbatim() {
    let dir = scratch("e2e");
    let objs = corpus(&dir, "e2e");
    let literal = format!("{LITERAL}\0").into_bytes();

    // The default: one output copy (the D4 merge), the image verifies
    // strict like any other.
    let merged = link(&dir, "app_merged", &objs, &[]);
    assert_eq!(
        cstring_bytes(&merged),
        literal,
        "the default carries one output copy"
    );
    // The merged image's remap: the duplicate's definition reports the
    // canonical copy's address *and* its output section (a section that
    // merged away entirely owns no piece — the symtab contract refuses
    // an `n_sect 0` row).
    let syms = output_symbols(&merged);
    let a_str = syms
        .iter()
        .find(|(n, ..)| n == "__a_str")
        .expect("the canonical definition rides the symtab");
    let b_str = syms
        .iter()
        .find(|(n, ..)| n == "__b_str")
        .expect("the duplicate's definition rides the symtab");
    assert_eq!(
        a_str.1, b_str.1,
        "the duplicate resolves to the canonical copy"
    );
    assert_eq!(
        a_str.2, b_str.2,
        "the merged-away section's definition reports the canonical output section"
    );
    let report = verify(&merged, &strict());
    assert!(
        report.is_ok(&strict()),
        "the merged image verifies strict: {:?}",
        report.issues
    );

    // The suppression: both copies ride verbatim — the output bytes are
    // the input bytes in bucket order (object a, then object b).
    let verbatim = link(&dir, "app_verbatim", &objs, &["-no_deduplicate"]);
    assert_eq!(
        cstring_bytes(&verbatim),
        [literal.clone(), literal].concat(),
        "the suppression keeps every input copy byte-for-byte"
    );
    let report = verify(&verbatim, &strict());
    assert!(
        report.is_ok(&strict()),
        "the verbatim image verifies strict: {:?}",
        report.issues
    );
}

#[test]
fn the_cached_lane_stays_byte_identical_under_the_knob() {
    let dir = scratch("cache");
    let objs = corpus(&dir, "cached");
    let plain = link(&dir, "app_plain", &objs, &["-no_deduplicate"]);
    let cached = link(
        &dir,
        "app_cached",
        &objs,
        &[
            "-no_deduplicate",
            "-cache",
            &dir.join("cache").display().to_string(),
        ],
    );
    assert_eq!(
        plain, cached,
        "the cold cached link is byte-identical (the cache carries parsed inputs, the knob rides the plan)"
    );
    // The warm lane too: the second cached link hits the entries.
    let warm = link(
        &dir,
        "app_warm",
        &objs,
        &[
            "-no_deduplicate",
            "-cache",
            &dir.join("cache").display().to_string(),
        ],
    );
    assert_eq!(plain, warm, "the warm cached link is byte-identical");
}

#[test]
fn the_incremental_flip_lands_on_a_correct_image() {
    // Link merged (the D4 shape), then relink with the toggle: the
    // literal pool's size changes, so the ladder cannot tile-patch (the
    // record's skeleton no longer matches) and lands on the relayout
    // rung — a correct image of the new plan. The correctness gate is
    // the strict verify plus the verbatim bytes; the byte-identity
    // gates compare lanes of the SAME plan. The record renews, so the
    // cycle never stalls: the next identical relink is a noop.
    let dir = scratch("inc");
    let objs = corpus(&dir, "inc");
    let merged_path = dir.join("app_carried");
    let merged_argv = || {
        let mut argv: Vec<std::ffi::OsString> = vec![
            std::ffi::OsString::from("-o"),
            merged_path.as_os_str().to_os_string(),
            std::ffi::OsString::from("-incremental"),
        ];
        argv.extend(objs.iter().map(|p| p.as_os_str().to_os_string()));
        pgr_driver::opts::parse(&argv).expect("the argv parses")
    };
    pgr_driver::run(&merged_argv()).expect("the recording link runs");
    let merged = std::fs::read(&merged_path).unwrap();
    // The recording link carries slack (`-incremental` implies the
    // growth reservation), so the literal pool is padded — the copy
    // count reads through the bytes, not the section size.
    let literal = format!("{LITERAL}\0").into_bytes();
    assert!(
        cstring_bytes(&merged).starts_with(&literal),
        "the carried image carries one copy"
    );

    // The verbatim relink under `-incremental`.
    let verbatim_argv = || {
        let mut argv: Vec<std::ffi::OsString> = vec![
            std::ffi::OsString::from("-o"),
            merged_path.as_os_str().to_os_string(),
            std::ffi::OsString::from("-incremental"),
            std::ffi::OsString::from("-no_deduplicate"),
        ];
        argv.extend(objs.iter().map(|p| p.as_os_str().to_os_string()));
        pgr_driver::opts::parse(&argv).expect("the argv parses")
    };
    pgr_driver::run(&verbatim_argv()).expect("the relink runs");
    let relinked = std::fs::read(&merged_path).unwrap();
    let literal = format!("{LITERAL}\0").into_bytes();
    let doubled = [literal.clone(), literal.clone()].concat();
    assert!(
        cstring_bytes(&relinked).starts_with(&doubled),
        "the relinked image keeps every copy"
    );
    assert!(
        relinked.len() >= merged.len(),
        "the relayout rung never shrinks the file for a merge-off"
    );
    let report = verify(&relinked, &strict());
    assert!(
        report.is_ok(&strict()),
        "the relinked image verifies strict: {:?}",
        report.issues
    );

    // The record renewed: the next identical relink is a noop (the
    // cycle never stalls).
    let again = pgr_driver::run(&verbatim_argv()).expect("the noop relink runs");
    let patch = again.patch.expect("the relink goes through the engine");
    assert!(
        patch.untouched,
        "the record renews (the noop ships nothing)"
    );
    assert_eq!(patch.bytes_patched, 0, "the noop ships no bytes");

    // The mirror flip: relink back to the default — the merge returns
    // and the image verifies strict.
    pgr_driver::run(&merged_argv()).expect("the relink back runs");
    let restored = std::fs::read(&merged_path).unwrap();
    assert!(
        cstring_bytes(&restored).starts_with(&literal),
        "the flip back merges again"
    );
    let report = verify(&restored, &strict());
    assert!(
        report.is_ok(&strict()),
        "the restored image verifies strict: {:?}",
        report.issues
    );
    let again = pgr_driver::run(&merged_argv()).expect("the noop relink back runs");
    let patch = again.patch.expect("the relink goes through the engine");
    assert!(patch.untouched, "the record renews after the flip back");
    assert_eq!(patch.bytes_patched, 0, "the noop ships no bytes");
}
