//! The M9 GA randomized edit-sequence gate, end to end (architecture doc
//! §10.4 row M9: "`--incremental-verify` equals clean link semantically
//! across 10⁴ randomized edit sequences on the corpus"; risk register P4
//! lists the randomized edit-sequence tests as the staleness mitigation).
//!
//! The emit-level gate (`pgr-emit/tests/incremental.rs`) walks the engine
//! API; this one walks the **driver loop over real files** — the record
//! sidecar, the fallback ladder, the `-incremental-verify` audit and the
//! verifier all in the loop, over an unsigned corpus whose symtab churn
//! exercises the relayout tier's shrink rung (the signed boundary never
//! shrinks — the sig anchor pins it).
//!
//! Scaling: `PGR_RANDOMIZED_STEPS` sizes the walk (default: the CI
//! subset; 10⁴ is the GA profile run on the decision rig). The walk is a
//! seeded xorshift64* — same seed, same edits, so a failure reproduces
//! exactly.

use pgr_driver::run;
use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};
use pgr_verify::{Code, Options as VerifyOptions, Severity};
use std::path::{Path, PathBuf};

/// hello.o with `text_bytes` of `__text`, an optional body flip, and
/// `locals` unreferenced local symbols (the LINKEDIT-churn dimension):
/// `_main` ADRP+ADD loads `_msg`, BL `_greet`, ret. The relocations are
/// invariant under every dimension.
fn hello(text_bytes: usize, body_flip: bool, locals: usize) -> ObjectBuilder {
    let mut words: Vec<u32> = vec![
        0x9000_0000, // adrp x0, _msg@page
        0x9100_0000, // add x0, x0, #_msg@pageoff
        0x9400_0000, // bl _greet
        0x5280_0000, // mov w0, #0 (flipped: #1 — the edited function body)
        0xD65F_03C0, // ret
    ];
    if body_flip {
        words[3] = 0x5280_0020;
    }
    words.resize(text_bytes / 4, 0xD503_201F);
    let text: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let mut b = ObjectBuilder::new("hello.o");
    let sect = b.add_section(ObjectSection::text(
        "__text",
        text,
        vec![
            ObjectReloc::addend(0).at(0),
            ObjectReloc::page21(1).at(0),
            ObjectReloc::addend(0).at(4),
            ObjectReloc::pageoff12(1).at(4),
            ObjectReloc::branch26(2).at(8),
        ],
    ));
    b.add_section(ObjectSection::cstring(if body_flip {
        "merci, peregrine\n" // same length as "hello, peregrine\n"
    } else {
        "hello, peregrine\n"
    }));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: sect,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_msg".into(),
        section_index: 1,
        value: 0,
        weak: false,
    });
    for i in 0..locals {
        b.add_symbol(ObjectSymbol::Defined {
            name: format!("_pgr_local_{i:04}"),
            section_index: sect,
            value: u64::try_from(i % 16).unwrap_or(0) * 4,
            weak: false,
        });
    }
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    b
}

fn greet() -> ObjectBuilder {
    let mut b = ObjectBuilder::new("greet.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6],
        vec![],
    ));
    let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.section_mut(data).relocs = vec![ObjectReloc::unsigned(0).at(0)];
    b
}

struct Corpus {
    dir: PathBuf,
    hello: PathBuf,
    out: PathBuf,
}

impl Corpus {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("pgr_m9_randomized_{tag}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("greet.o"), greet().build().unwrap()).unwrap();
        let corpus = Self {
            hello: dir.join("hello.o"),
            out: dir.join("app"),
            dir,
        };
        corpus.write(32 * 1024, false, 0);
        corpus
    }

    fn write(&self, text_bytes: usize, body_flip: bool, locals: usize) {
        std::fs::write(
            &self.hello,
            hello(text_bytes, body_flip, locals).build().unwrap(),
        )
        .unwrap();
    }

    fn opts(&self) -> pgr_driver::opts::Options {
        pgr_driver::opts::Options {
            output: self.out.display().to_string(),
            inputs: vec![
                self.hello.display().to_string(),
                self.dir.join("greet.o").display().to_string(),
            ],
            config: pgr_core::layout::LinkConfig {
                ident: "pgr-m9-randomized".into(),
                // Unsigned: the sig boundary is unanchored, so symtab
                // churn moves the image tail — the shrink rung's shape.
                adhoc: false,
                ..pgr_core::layout::LinkConfig::default()
            },
            incremental: true,
            incremental_verify: true,
            ..pgr_driver::opts::Options::default()
        }
    }

    fn record(&self) -> PathBuf {
        let mut name = self.out.clone().into_os_string();
        name.push(".pgr-inc");
        PathBuf::from(name)
    }
}

/// The verifier's stance for the unsigned corpus: everything except the
/// deliberate "no ad-hoc code signature" error must be clean.
fn unsigned_verify_issues(path: &Path) -> Vec<String> {
    let bytes = std::fs::read(path).unwrap();
    let opts = VerifyOptions {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    pgr_verify::verify(&bytes, &opts)
        .issues
        .iter()
        .filter(|i| {
            !(i.severity == Severity::Error
                && i.code == Code::SignatureLayout
                && i.message.contains("require an ad-hoc code signature"))
        })
        .map(|i| format!("{:?} [{}] {}", i.severity, i.code.as_str(), i.message))
        .collect()
}

#[test]
fn randomized_edit_walk_survives_the_ladder_end_to_end() {
    let steps: usize = std::env::var("PGR_RANDOMIZED_STEPS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(24);
    let c = Corpus::new("walk");

    // Link 1: the seeded baseline (no record — the full link records).
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = move || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    };
    let mut text = 32 * 1024;
    let mut flip = false;
    let mut locals = usize::try_from(next() % 256).unwrap_or(0);
    c.write(text, flip, locals);
    let first = run(&c.opts()).unwrap();
    assert!(first.patch.is_none(), "the first link is a full link");
    assert!(c.record().exists(), "the record sidecar is written");

    let mut patched_steps = 0u32;
    let mut untouched_steps = 0u32;
    let mut fallback_steps = 0u32;
    let mut shrunk_steps = 0u32;

    for step in 0..steps {
        // The edit roll: body flip / growth within slack / symtab churn
        // (grow or shrink) / no-op. The dimensions compose.
        match next() % 4 {
            0 => flip = !flip,
            1 => text = 32 * 1024 + usize::try_from(next() % 2048).unwrap_or(0),
            2 => {
                let new_locals = usize::try_from(next() % 512).unwrap_or(0);
                if new_locals < locals {
                    shrunk_steps += 1;
                }
                locals = new_locals;
            }
            _ => {}
        }
        c.write(text, flip, locals);

        let outcome = run(&c.opts()).unwrap_or_else(|e| {
            panic!("step {step}: the relink must never error (fallback is the exit): {e}")
        });
        assert!(
            unsigned_verify_issues(&c.out).is_empty(),
            "step {step}: the relink output verifies clean: {:?}",
            unsigned_verify_issues(&c.out)
        );
        match outcome.patch {
            Some(patch) if patch.untouched => untouched_steps += 1,
            Some(patch) => {
                assert!(
                    patch.dirty_tiles < patch.total_tiles,
                    "step {step}: a patch must reuse most tiles ({} of {})",
                    patch.dirty_tiles,
                    patch.total_tiles
                );
                patched_steps += 1;
            }
            None => {
                // The ladder's honest exit: the full link re-ran and
                // re-recorded. Never an error, always verified above.
                fallback_steps += 1;
                assert!(c.record().exists(), "step {step}: the fallback re-records");
            }
        }
        assert!(
            c.record().exists(),
            "step {step}: every exit leaves a record for the next link"
        );
    }

    // The walk must actually walk: patches happened, and the symtab
    // dimension exercised the shrink rung's side of the ladder.
    assert!(
        patched_steps > 0,
        "the walk must patch (patched: {patched_steps}, untouched: {untouched_steps}, fallback: {fallback_steps})"
    );
    assert!(
        shrunk_steps > 0,
        "the walk must exercise the symtab-shrink dimension ({shrunk_steps} shrink steps)"
    );
}
