//! Fuzz target (M9): the link-record decoder is corruption-tolerant by
//! contract — any byte string yields a record or `None`, never a panic
//! (the record is an accelerator only; a corrupt or hostile sidecar is
//! deleted and the relink falls back to the full link).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Every panic here is a bug in pgr_emit::incremental (M9 record codec).
    if let Some(record) = pgr_emit::incremental::LinkRecord::decode(data) {
        // A decoded record re-encodes byte-for-byte (the codec is lossless;
        // digests stay stable) and reports its hashed-page count sanely.
        let bytes = record.encode();
        let back = pgr_emit::incremental::LinkRecord::decode(&bytes);
        assert_eq!(back.as_ref(), Some(&record), "record re-decode diverged");
        assert!(record.hashed_pages() < (1 << 40), "absurd hash-page count");
    }
});
