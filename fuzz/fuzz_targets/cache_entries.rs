//! Fuzz target (M7 "fuzzing at scale"): the versioned cache decoders are
//! corruption-tolerant by contract — any byte string yields an entry or
//! `None`, never a panic (the cache is an optimization only; a corrupt or
//! hostile entry is silently re-parsed).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Every panic here is a bug in pgr-core::cache (M7 versioned format).
    let _ = pgr_core::cache::decode_poi(data, pgr_core::FileId(1), "fuzz.o", true);
    let _ = pgr_core::cache::decode_poi(data, pgr_core::FileId(1), "fuzz.o", false);
    let _ = pgr_core::cache::decode_frozen_dylib(data);
});
