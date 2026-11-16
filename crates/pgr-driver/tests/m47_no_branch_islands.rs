//! M47 — the branch-island suppression on the driver surface:
//! `-no_branch_islands` rides the argv, an in-range link plans
//! byte-identical output under either decision (both images verify
//! strict), and an out-of-range branch refuses the link with the site
//! named — the layout's re-check is the driver surface's backing.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use pgr_driver::opts;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Options as VerifyOptions, verify};

const MIB: usize = 1 << 20;

/// A unique scratch dir per test (the house pattern: no tempfile dep).
fn scratch(tag: &str) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir()
        .join("pgr_m47_no_branch_islands")
        .join(format!(
            "{tag}_{}_{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// An in-range corpus: `m.o` defines `_main`/`_far` and `f.o` defines
/// `_far`; every branch lands well inside the ±128 MiB `imm26` window.
fn in_range_objects(dir: &Path) -> (PathBuf, PathBuf) {
    let small = |name: &str, defs: &[(&str, bool)]| {
        let mut b = ObjectBuilder::new(name);
        let text = b.add_section(ObjectSection::text(
            "__text",
            vec![0xC0, 0x03, 0x5F, 0xD6, 0xC0, 0x03, 0x5F, 0xD6], // ret; ret
            vec![],
        ));
        let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
        for (i, (n, def)) in defs.iter().enumerate() {
            if *def {
                b.add_symbol(ObjectSymbol::Defined {
                    name: (*n).into(),
                    section_index: if i == 0 { text } else { data },
                    value: 0,
                    weak: false,
                });
            }
        }
        let path = dir.join(name);
        std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
        path
    };
    let main = small("m.o", &[("_main", true), ("_far", false)]);
    let far = small("f.o", &[("_far", true)]);
    (main, far)
}

/// The M6 giant-text corpus on disk: a.o (64 MiB, branch to `_far`),
/// b.o (66 MiB, pure distance), c.o (2 MiB, `_far` + branch back to
/// `_main`) — site→target distances land at ~130 MiB both ways.
fn giant_objects(dir: &Path) -> Vec<PathBuf> {
    let giant = |name: &str, size: usize, text_syms: &[(&str, bool)], branch: bool| {
        let mut b = ObjectBuilder::new(name);
        let mut relocs: Vec<ObjectReloc> = Vec::new();
        if branch {
            relocs.push(ObjectReloc::branch26(1).at(0));
        }
        let text = b.add_section(ObjectSection::text("__text", vec![0u8; size], relocs));
        for (i, (n, def)) in text_syms.iter().enumerate() {
            if *def {
                b.add_symbol(ObjectSymbol::Defined {
                    name: (*n).into(),
                    section_index: text,
                    value: 0,
                    weak: false,
                });
            } else {
                b.add_symbol(ObjectSymbol::Undefined {
                    name: (*n).into(),
                    weak_ref: false,
                });
            }
            let _ = i;
        }
        let path = dir.join(name);
        std::fs::write(&path, b.build().expect("the fixture object builds")).unwrap();
        path
    };
    vec![
        giant("a.o", 64 * MIB, &[("_main", true), ("_far", false)], true),
        giant("b.o", 66 * MIB, &[("_b", true)], false),
        giant("c.o", 2 * MIB, &[("_far", true), ("_main", false)], true),
    ]
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
fn the_suppression_refuses_the_overflowing_link() {
    // The fixed point cannot encode the ~130 MiB branch without a
    // veneer: the link fails with the site named — the layout's
    // re-check backs the driver surface (the miette-rendered refusal
    // the `pgr` binary prints, exit 2).
    let dir = scratch("overflow");
    let objs = giant_objects(&dir);
    let out = dir.join("giant");
    let mut argv = vec![OsString::from("-o"), OsString::from(out.to_str().unwrap())];
    for p in &objs {
        argv.push(OsString::from(p.to_str().unwrap()));
    }
    argv.push(OsString::from("-no_branch_islands"));
    let o = opts::parse(&argv).expect("the suppressed argv parses");
    let err = pgr_driver::run(&o).expect_err("the overflowing link refuses under the suppression");
    let message = err.to_string();
    assert!(
        message.contains("-no_branch_islands"),
        "the refusal names the knob: {message}"
    );
}

#[test]
fn in_range_links_stay_byte_identical_under_the_knob() {
    // The M47 lock on the driver surface: an in-range link plans the
    // same bytes with and without the flag — the suppression has
    // nothing to refuse — and both images verify strict.
    let dir = scratch("parity");
    let (main, far) = in_range_objects(&dir);
    let plain = dir.join("plain");
    let suppressed = dir.join("suppressed");
    for (out, extra) in [
        (&plain, &[] as &[&str]),
        (&suppressed, &["-no_branch_islands"]),
    ] {
        let mut argv = vec![
            OsString::from("-o"),
            OsString::from(out.to_str().unwrap()),
            OsString::from(main.to_str().unwrap()),
            OsString::from(far.to_str().unwrap()),
        ];
        for a in extra {
            argv.push(OsString::from(*a));
        }
        let o = opts::parse(&argv).expect("the in-range argv parses");
        pgr_driver::run(&o).expect("the in-range link runs");
    }
    let a = std::fs::read(&plain).unwrap();
    let b = std::fs::read(&suppressed).unwrap();
    assert_eq!(a.len(), b.len(), "the byte count holds");
    assert_eq!(
        a, b,
        "the in-range bytes are identical under both decisions"
    );
    assert!(strict_ok(&a), "the plain image verifies strict");
    assert!(strict_ok(&b), "the suppressed image verifies strict");
}
