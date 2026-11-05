//! Peregrine fuzz harnesses (cargo-fuzz, nightly only).
//!
//! Run locally:
//!
//! ```sh
//! cargo +nightly fuzz run verify_image -- -max_total_time=60
//! ```
//!
//! CI runs both targets nightly with a seed corpus of valid fixtures; see
//! `.github/workflows/fuzz.yml`.
