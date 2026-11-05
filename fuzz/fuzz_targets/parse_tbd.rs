//! Fuzz target: the `.tbd` (TAPI stub) parser must accept or reject arbitrary
//! bytes with a typed error — never panic (M2: the tbd parser joins the
//! fuzz schedule alongside the Mach-O structural parser).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The parser is total: malformed or adversarial YAML-ish input returns
    // `Err(FormatError)`, never panics, never allocates unbounded.
    let _ = pgr_format::parse_tbd(data);
});
