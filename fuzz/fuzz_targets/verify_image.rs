//! Fuzz target: the verifier must never panic on arbitrary bytes — every
//! malformed input is a typed issue in the report (TDD §11).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let opts = pgr_verify::Options {
        strict_warnings: false,
        skip_hash_recompute: false,
    };
    let report = pgr_verify::verify(data, &opts);
    // Total-behavior contract: bounded issue list, no panics.
    debug_assert!(report.issues.len() <= 4096);
});
