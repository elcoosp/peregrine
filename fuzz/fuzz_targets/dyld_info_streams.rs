//! Fuzz target (M7 "fuzzing at scale"): the M6 classic `LC_DYLD_INFO`
//! rebase/bind opcode decoders must accept or reject arbitrary bytes with a
//! typed error — never panic (dyld walks the same streams on every legacy
//! link; a decoder crash is a link crash).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Both stream decoders are total: any byte string decodes, errors, or
    // ends — every panic here is a bug in pgr-format.
    let _ = pgr_format::dyld_info::decode_rebase_stream(data);
    let _ = pgr_format::dyld_info::decode_bind_stream(data);
    // The 48-byte command header parse rides the same corpus.
    let _ = pgr_format::dyld_info::DyldInfoCommand::parse(data);
});
