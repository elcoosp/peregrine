//! The M9 incremental resolve's consumer cycle, runnable (tier 2c): a cold
//! link that **records** its Pass 2 ([`LinkConfig::record_resolution`] —
//! the record's v5 section), an edit, then a relink whose Pass 2 plans
//! through the recorded decisions ([`LinkConfig::resolve_reuse`] —
//! digest-vouched winners ride verbatim, seed-touched names replay the
//! precedence rules, and a moved reuse shape falls back to the full
//! resolve). The equality gate the repo runs in
//! `crates/pgr-core/tests/m9_resolve_reuse.rs` is demonstrated at the
//! consumer level: the reused Pass 2 is snapshot-identical to the full
//! resolve of the same inputs.
//!
//! Set `PGR_TRACING=1` to install a subscriber and watch the seams emit
//! spans (`resolve_reuse_plan` with the refusal reasons,
//! `resolve_reuse_install` with the split counts — inert without a
//! subscriber, the workspace convention).
//!
//! ```sh
//! cargo run -p pgr-core --example incremental_resolve
//! ```

use pgr_core::layout::LinkConfig;
use pgr_core::link::{LinkInput, Parallelism, link_cached};
use pgr_core::propagate::section_digests;
use pgr_core::resolve_reuse::{ResolveReuseSeed, plan_reuse};
use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

/// main.o: `_main` (nop; ret), the `_msg` cstring, references to `_greet`
/// and `_util_fn`; `body_flip` swaps the `ret` for an equal-length
/// `.word 0` — the edit that seeds file 0's `__text` on the relink.
fn main_object(body_flip: bool) -> Vec<u8> {
    let text: Vec<u8> = if body_flip {
        vec![0x1F, 0x20, 0x03, 0xD5, 0x00, 0x00, 0x00, 0x00] // nop; .word 0
    } else {
        vec![0x1F, 0x20, 0x03, 0xD5, 0xC0, 0x03, 0x5F, 0xD6] // nop; ret
    };
    let mut b = ObjectBuilder::new("main.o");
    let text_sect = b.add_section(ObjectSection::text("__text", text, vec![]));
    b.add_section(ObjectSection::cstring("hello, peregrine\n"));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_main".into(),
        section_index: text_sect,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_msg".into(),
        section_index: 1,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet".into(),
        weak_ref: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_util_fn".into(),
        weak_ref: false,
    });
    b.build().expect("fixture builds")
}

/// greet.o (never edited): `_greet` body, references `_greet_text`.
fn greet() -> Vec<u8> {
    let mut b = ObjectBuilder::new("greet.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6], // ret
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Undefined {
        name: "_greet_text".into(),
        weak_ref: false,
    });
    b.build().expect("fixture builds")
}

/// util.o (never edited): `_util_fn` body plus the `_greet_text` cstring.
fn util() -> Vec<u8> {
    let mut b = ObjectBuilder::new("util.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6], // ret
        vec![],
    ));
    b.add_section(ObjectSection::cstring("greet text\n"));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_util_fn".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.add_symbol(ObjectSymbol::Defined {
        name: "_greet_text".into(),
        section_index: 1,
        value: 0,
        weak: false,
    });
    b.build().expect("fixture builds")
}

/// extra.o: a fourth input the cold record cannot vouch for — appending it
/// moves the file list, and the shape guard refuses the stale seed.
fn extra() -> Vec<u8> {
    let mut b = ObjectBuilder::new("extra.o");
    let text = b.add_section(ObjectSection::text(
        "__text",
        vec![0xC0, 0x03, 0x5F, 0xD6], // ret
        vec![],
    ));
    b.add_symbol(ObjectSymbol::Defined {
        name: "_extra".into(),
        section_index: text,
        value: 0,
        weak: false,
    });
    b.build().expect("fixture builds")
}

fn inputs(main_bytes: &[u8]) -> Vec<LinkInput> {
    vec![
        LinkInput {
            name: "main.o".into(),
            bytes: main_bytes.to_vec(),
        },
        LinkInput {
            name: "greet.o".into(),
            bytes: greet(),
        },
        LinkInput {
            name: "util.o".into(),
            bytes: util(),
        },
    ]
}

fn cfg(record: bool) -> LinkConfig {
    LinkConfig {
        ident: "incremental-resolve".into(),
        record_resolution: record,
        ..LinkConfig::default()
    }
}

fn main() {
    // The resolve-reuse spans stay inert until a subscriber installs;
    // PGR_TRACING=1 turns them into stderr lines (the binaries do the same
    // under their debug envs). Debug level: the refusals and the split
    // counts all log below info.
    if std::env::var_os("PGR_TRACING").is_some() {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::DEBUG)
            .init();
    }

    // 1. The cold link, exactly what `pgr -incremental` does on its first
    //    run: a full Pass 1–3 link whose Pass 2 is recorded into the link
    //    record (the v5 resolution snapshot plus the v3 section digests —
    //    here the [`LinkResult`] fields the record packer reads).
    let cold = link_cached(
        &inputs(&main_object(false)),
        &[],
        &cfg(true),
        Parallelism::Auto,
        None,
    )
    .expect("cold link");
    let snapshot = cold
        .resolve_snapshot
        .clone()
        .expect("the cold link recorded its Pass 2");
    let digests = section_digests(&cold.objects);
    println!(
        "cold link: {} inputs, {} section digest(s) recorded, Pass 2 captured",
        cold.objects.len(),
        digests.len()
    );
    let seed = ResolveReuseSeed {
        snapshot: snapshot.clone(),
        digests: digests.clone(),
    };

    // 2. The edit and the relink: `main.o`'s body flipped, everything else
    //    byte-identical. The pipeline's Pass 2 plans through the recorded
    //    decisions (`resolve_reuse`); the same plan is printed here, the
    //    way the spans report it under PGR_TRACING=1.
    let edited = inputs(&main_object(true));
    let mut relink_cfg = cfg(true);
    relink_cfg.resolve_reuse = Some(seed.clone());
    let reused =
        link_cached(&edited, &[], &relink_cfg, Parallelism::Auto, None).expect("reused relink");
    let plan = plan_reuse(
        &seed.snapshot,
        &seed.digests,
        &reused.interner,
        &reused.objects,
        &[],
        &[],
    )
    .expect("the same-shape relink plans");
    let redecided: Vec<&str> = plan
        .redecide
        .iter()
        .map(|name| std::str::from_utf8(name).unwrap_or("<binary>"))
        .collect();
    println!(
        "relink: seed section(s) {:?}, {} recorded winner(s) reused, re-decided {redecided:?}",
        plan.seeds, plan.reused,
    );

    // 3. The equality gate: the same edited inputs resolved in full must
    //    produce the Pass 2 the reuse path produced — snapshot-for-snapshot
    //    (winners, candidates, sites, the dylib surface: all of it).
    let full = link_cached(&edited, &[], &cfg(true), Parallelism::Auto, None).expect("full relink");
    assert_eq!(
        reused.resolve_snapshot, full.resolve_snapshot,
        "the reused Pass 2 must be indistinguishable from the full resolve"
    );
    println!("equality gate: the reused Pass 2 is snapshot-identical to the full resolve");

    // 4. The shape guard: a fourth input moves the file list the record
    //    vouches for. `plan_reuse` refuses, the pipeline answers with the
    //    ladder's bottom rung — the full resolve — and the link still
    //    succeeds, re-recording the fresh Pass 2 for the next cycle.
    let mut moved = edited.clone();
    moved.push(LinkInput {
        name: "extra.o".into(),
        bytes: extra(),
    });
    let mut stale_cfg = cfg(true);
    stale_cfg.resolve_reuse = Some(seed.clone());
    let fallen = link_cached(&moved, &[], &stale_cfg, Parallelism::Auto, None)
        .expect("the ladder's bottom rung still links");
    let refusal = plan_reuse(
        &seed.snapshot,
        &seed.digests,
        &fallen.interner,
        &fallen.objects,
        &[],
        &[],
    )
    .expect_err("the moved file list must refuse the stale seed");
    println!(
        "moved list: the stale seed refused ({refusal}) — the pipeline resolved in full, \
         the link carries {} object(s), and the fresh record was re-captured ({})",
        fallen.objects.len(),
        fallen.resolve_snapshot.is_some(),
    );
    assert!(
        fallen.resolve_snapshot.is_some(),
        "every fallback re-records"
    );
}
