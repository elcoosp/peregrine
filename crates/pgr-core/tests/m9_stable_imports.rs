//! M9 tier-2a gates — stable import ordinals across the incremental relink
//! cycle (architecture doc §7.3 step 5; architecture-delta D7 closed).
//!
//! A chained bind word carries its import's *ordinal*. The clean-link
//! builder assigns ordinals in first-use order over address-sorted slots —
//! minimal, deterministic, and **not reusable across links**: one new bind
//! that sorts before an existing one renumbers every later import, and the
//! relink rewrites (dirties) every data page holding one of those words.
//! The M8-b insertion-stable table is the fix: the recorded link captures
//! its import table; the anchored relink keeps every recorded ordinal and
//! appends genuinely new imports. Gates here:
//!
//! * `StableImports::anchored` — a table from a recorded first-use table,
//!   order-preserving (the anchor must not canonicalize the recorded
//!   order: the clean bytes on disk carry that order);
//! * `plan_fixups` without an anchor reproduces first-use exactly (the
//!   clean-link bytes are untouched — §7.3 determinism policy);
//! * the anchored plan keeps recorded ordinals and appends new imports
//!   (canonical order among the appended, the M8-b `insert` semantics);
//! * a bind word's ordinal lookup matches the **full** import identity
//!   (lib ordinal, name, addend, weak) — same name via two dylibs is two
//!   imports, each word pointing at its own library;
//!
//! Link-level coverage (the record, the anchored relink loop, and the
//! byte-identity contract under import churn) lives in
//! `pgr-emit/tests/incremental.rs` and `pgr-driver/tests/m9_incremental.rs`
//! — those crates sit downstream of `pgr-core` in the dependency graph.

use pgr_core::fixups::{FixupKind, FixupSlot, plan_fixups, plan_fixups_with_imports};
use pgr_core::ids::StringId;
use pgr_core::interner::Interner;
use pgr_core::stable_imports::{StableImport, StableImports};

/// A zero-addend strong bind identity for `name` via lib ordinal 1.
fn key(name: &str) -> StableImport {
    StableImport {
        lib_ordinal: 1,
        name: name.as_bytes().to_vec(),
        outlined_addend: 0,
        weak: false,
    }
}

/// A three-name interner: `_a` → 0, `_b` → 1, `_c` → 2 (canonical order).
fn interner3() -> Interner {
    let (inter, _ids) = Interner::build(&[b"_a".to_vec(), b"_b".to_vec(), b"_c".to_vec()]);
    inter
}

/// A bind slot against one of the interner3 names.
fn bind3(vaddr: u64, name: &str, lib: u8) -> FixupSlot {
    let id = match name {
        "_a" => StringId(0),
        "_b" => StringId(1),
        _ => StringId(2),
    };
    FixupSlot {
        vaddr,
        kind: FixupKind::Bind {
            lib_ordinal: lib,
            name: id,
            addend: 0,
            weak: false,
        },
    }
}

/// The import names of a plan, in table order.
fn import_names(plan: &pgr_core::FixupPlan) -> Vec<String> {
    plan.stable_keys
        .iter()
        .map(|k| String::from_utf8_lossy(&k.name).into_owned())
        .collect()
}

/// The bind ordinal encoded in the slot word at vaddr `vaddr`.
fn bind_ordinal_at(plan: &pgr_core::FixupPlan, vaddr: u64) -> u32 {
    let (_, word) = plan
        .slot_words
        .iter()
        .find(|(at, _)| *at == vaddr)
        .unwrap_or_else(|| panic!("no slot word at {vaddr:#x}"));
    pgr_format::fixups::ChainWord64::new(*word).bind_ordinal()
}

#[test]
fn anchored_table_preserves_the_recorded_order_and_dedups() {
    // The recorded table is whatever the previous link built (first-use
    // order on the clean path). The anchor must reproduce it verbatim —
    // NOT canonicalize it (that would renumber on the first anchored
    // relink, the exact churn the table exists to prevent).
    let anchor = vec![key("_b"), key("_a"), key("_b"), key("_a")];
    let table = StableImports::anchored(anchor);
    let names: Vec<&[u8]> = table.keys().iter().map(|k| k.name.as_slice()).collect();
    assert_eq!(
        names,
        [b"_b".as_slice(), b"_a".as_slice()],
        "recorded order, deduped"
    );

    // Growth through `insert`: existing ordinals hold, new keys append in
    // canonical order (the M8-b semantics, now over an anchored table).
    let mut table = StableImports::anchored(vec![key("_b")]);
    let assignments = table.insert(vec![key("_a"), key("_b"), key("_c")]);
    let by_name: Vec<(String, usize, bool)> = assignments
        .iter()
        .map(|a| {
            (
                String::from_utf8_lossy(&a.key.name).into_owned(),
                a.ordinal,
                a.is_new,
            )
        })
        .collect();
    assert!(
        by_name.contains(&("_a".into(), 1, true)),
        "_a is new, appended after the recorded _b: {by_name:?}"
    );
    assert!(
        by_name.contains(&("_b".into(), 0, false)),
        "_b keeps its recorded ordinal: {by_name:?}"
    );
    assert!(
        by_name.contains(&("_c".into(), 2, true)),
        "_c appends: {by_name:?}"
    );
    assert_eq!(import_order_names(&table), ["_b", "_a", "_c"]);
}

/// The table's key names in ordinal order.
fn import_order_names(table: &StableImports) -> Vec<String> {
    table
        .keys()
        .iter()
        .map(|k| String::from_utf8_lossy(&k.name).into_owned())
        .collect()
}

#[test]
fn plan_fixups_without_an_anchor_keeps_first_use_ordinals() {
    // Address order: _a first, then _b. First-use assigns ordinals in that
    // order — the shipped M2 behavior, byte-for-byte unchanged.
    let slots = vec![bind3(0x1_0000_4000, "_a", 1), bind3(0x1_0000_4008, "_b", 1)];
    let segments = [(0x1_0000_4000, pgr_format::consts::PAGE_SIZE_16K, 0x4000)];
    let inter = interner3();
    let plan = plan_fixups(
        slots,
        &segments,
        0x1_0000_0000,
        pgr_format::consts::PAGE_SIZE_16K,
        &inter,
    )
    .unwrap();
    assert_eq!(import_names(&plan), ["_a", "_b"]);
    assert_eq!(bind_ordinal_at(&plan, 0x1_0000_4000), 0);
    assert_eq!(bind_ordinal_at(&plan, 0x1_0000_4008), 1);
}

#[test]
fn plan_fixups_anchors_recorded_ordinals_and_appends_new_imports() {
    // Link 1 bound only _b (recorded table: [_b]). Link 2 adds a bind to
    // _a at an *earlier* address. First-use would renumber _b to 1; the
    // anchored plan keeps _b at 0 and appends _a at 1.
    let segments = [(0x1_0000_4000, pgr_format::consts::PAGE_SIZE_16K, 0x4000)];
    let inter = interner3();
    let page = pgr_format::consts::PAGE_SIZE_16K;

    let anchor = [key("_b")];
    let slots2 = vec![bind3(0x1_0000_4000, "_a", 1), bind3(0x1_0000_4008, "_b", 1)];
    let anchored = plan_fixups_with_imports(
        slots2,
        &segments,
        0x1_0000_0000,
        page,
        &inter,
        Some(&anchor),
    )
    .unwrap();
    assert_eq!(
        import_names(&anchored),
        ["_b", "_a"],
        "recorded ordinal holds, new import appends"
    );
    assert_eq!(
        bind_ordinal_at(&anchored, 0x1_0000_4008),
        0,
        "the recorded _b bind word is byte-stable"
    );
    assert_eq!(bind_ordinal_at(&anchored, 0x1_0000_4000), 1);

    // The same slots WITHOUT the anchor renumber (the old churn, pinned so
    // the anchored assertion above cannot pass vacuously).
    let unanchored = plan_fixups(
        vec![bind3(0x1_0000_4000, "_a", 1), bind3(0x1_0000_4008, "_b", 1)],
        &segments,
        0x1_0000_0000,
        page,
        &inter,
    )
    .unwrap();
    assert_eq!(import_names(&unanchored), ["_a", "_b"]);
    assert_eq!(bind_ordinal_at(&unanchored, 0x1_0000_4008), 1);
}

#[test]
fn bind_ordinals_follow_the_full_import_identity() {
    // The same name bound through two libraries is two imports. A lookup
    // keyed on name+addend alone would encode lib 1's ordinal into the
    // lib 2 slot (the latent M2 bug this gate pins shut).
    let slots = vec![bind3(0x1_0000_4000, "_a", 1), bind3(0x1_0000_4008, "_a", 2)];
    let segments = [(0x1_0000_4000, pgr_format::consts::PAGE_SIZE_16K, 0x4000)];
    let inter = interner3();
    let plan = plan_fixups(
        slots,
        &segments,
        0x1_0000_0000,
        pgr_format::consts::PAGE_SIZE_16K,
        &inter,
    )
    .unwrap();
    assert_eq!(plan.imports.len(), 2, "two libs, two imports");
    assert_eq!(plan.imports[0].lib_ordinal, 1);
    assert_eq!(plan.imports[1].lib_ordinal, 2);
    assert_eq!(bind_ordinal_at(&plan, 0x1_0000_4000), 0);
    assert_eq!(
        bind_ordinal_at(&plan, 0x1_0000_4008),
        1,
        "lib 2's bind is its own import"
    );
}
