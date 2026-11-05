//! Fuzz target: the structural parser must accept or reject arbitrary bytes
//! with a typed error — never panic (TDD §10.3 M0: "fuzz targets for the
//! parsers").

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Every panic here is a bug in pgr-format; the CI fuzz job runs this
    // target nightly against a seed corpus of valid fixtures.
    let _ = pgr_format::summarize(data);
});
