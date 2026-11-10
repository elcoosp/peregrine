//! Peregrine resident link server (M8, architecture doc §7.2 + §10.4 row
//! M8): the `pgrd` daemon and the client `pgr -resident` speaks to it.
//!
//! The daemon keeps the state a one-shot link rebuilds every run:
//!
//! * the **POI** of every direct input — the Pass 1 product (sections with
//!   raw relocations, typed symbols, name pool, D1 atom ranges) as versioned
//!   frames keyed by content, decoded instead of re-parsed on a warm link;
//! * the input **bytes** themselves (Pass 4 copies section bytes);
//! * the fused-emit **output buffer**, reused across links
//!   ([`pgr_emit::build_image_fused_into`]) — the §10.4 M8 performance gate
//!   "page-fault cost eliminated (buffer reuse)";
//! * since the M9 output-residency rung (wire v5), every **served image**
//!   as resident output state (a content-addressed blob under the same
//!   ceiling) — the next cycle's previous output never re-crosses the
//!   wire, and a patched relink ships its changed 16 KiB tiles instead of
//!   the whole image ([`pgr_emit::incremental::TilePatch`]).
//!
//! The link itself is the *same* pipeline as the one-shot path
//! ([`pgr_core::link_from_objects`] + the fused emit), so resident output is
//! byte-identical to one-shot in deterministic mode — the M8 correctness
//! gate, asserted end-to-end in the driver tests. The daemon never touches
//! the filesystem beyond its socket: the client writes the output through
//! the normal Pass 5 atomic-rename path (verifying its tile replay against
//! the stream's content hash first), so a daemon crash or restart can
//! never corrupt an image (the second M8 correctness gate).
//!
//! This crate is unix-only (unix-domain sockets); the workspace CI matrix
//! (Linux + macOS) builds and gates it.

pub mod client;
pub mod protocol;
pub mod server;
pub mod session;

pub use client::{
    ClientError, DaemonClient, LinkJob, ResidentImage, Transport, connect_or_start, default_socket,
    link_via_daemon, shutdown_daemon,
};
pub use protocol::{
    ArchiveEntry, DecodeError, InputEntry, LinkRequest, PROTO_VERSION, content_hash,
};
pub use server::{ServerError, serve};
pub use session::{ResidentSession, SessionError};

/// The default daemon socket path (see [`client::default_socket`]).
#[must_use]
pub fn client_default_socket() -> String {
    default_socket().display().to_string()
}

/// Crate version, re-exported for the daemon's banner.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use crate::{LinkRequest, content_hash};
    use pgr_core::layout::LinkConfig;

    #[test]
    fn version_is_wired() {
        assert!(!crate::VERSION.is_empty(), "version line built");
        // v7 (M14): the fusion halves (v3), the audited relink (v4), the
        // §7.2 tile replay (v5), the request config's chain-word-family
        // byte (v6) — and now the export-filter lists re-encoded as
        // patterns (kind byte + source), so a resident relink's export
        // surface is the surface the client named.
        assert_eq!(crate::PROTO_VERSION, 7);
    }

    #[test]
    fn public_surface_compiles_into_a_request() {
        // A smoke gate over the re-exported names (the API the driver uses).
        let req = LinkRequest {
            config: LinkConfig::default(),
            force_load: Vec::new(),
            inputs: Vec::new(),
            archives: Vec::new(),
            record: None,
            record_resolution: false,
            prev_output: None,
            audit: false,
            tiles: false,
        };
        assert!(req.blob_hashes().is_empty(), "no archives to hash");
        assert_ne!(content_hash(b"x"), [0u8; 32]);
    }
}
