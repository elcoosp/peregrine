//! Fuzz target (M1): the Pass 1 object parser + Pass 2/3 pipeline must
//! accept or reject arbitrary bytes with a typed error — never panic.
//! The M1 linker's inputs are hostile the same way its outputs are (TDD §11:
//! "a linker is a hostile-input parser; its crash is a build crash").

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Half the corpus drives the object parser; the other half drives the
    // full pipeline with a second (mutated) copy so resolution and layout
    // run over nontrivial input sets.
    let input = pgr_core::LinkInput {
        name: "fuzz.o".into(),
        bytes: data.to_vec(),
    };
    let mut twin = data.to_vec();
    if let Some(first) = twin.first_mut() {
        *first = first.wrapping_add(1);
    }
    let twin = pgr_core::LinkInput {
        name: "fuzz_twin.o".into(),
        bytes: twin,
    };
    let cfg = pgr_core::layout::LinkConfig {
        ident: "fuzz".into(),
        ..pgr_core::layout::LinkConfig::default()
    };
    let _ = pgr_core::link(&[input, twin], &[], &cfg);
});
