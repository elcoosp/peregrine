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
        // byte (v6), the export-filter lists re-encoded as patterns, the
        // config's image base as a u64 (M15, `-pagezero_size`), the
        // config's initializer form as a tail byte (M16,
        // `-init_offsets`), the config's segment-protection decisions as
        // a length-prefixed tail (M17, `-segprot`), the config's stack
        // reserve as a present-byte + u64 (M18, `-stack_size`) — and
        // now the config's dylib/bundle image base as a present-byte +
        // u64 (M19, `-image_base`) — and the config's umbrella region as
        // a length-prefixed member list (M20, `-sub_umbrella` /
        // `-sub_library`): a resident relink emits the region the
        // client named, never the pre-M20 absence — and the config's
        // sub-client list as a length-prefixed name list (M21,
        // `-sub_client`): a resident relink emits the clients the
        // linking image named, never the pre-M21 absence — and the
        // config's dyld-environment list as a length-prefixed pair list
        // (M22, `-dyld_env`): a resident relink exports the variables
        // the client named, never the pre-M22 absence — and the
        // config's symbol-alias list as a length-prefixed pair list
        // (M24, `-alias`): a resident relink exports the names the
        // client asked for, never the pre-M24 absence — and the
        // config's bundle-loader surface as a present-byte + name +
        // export list (M25, `-bundle_loader`): a resident relink binds
        // against the host the client named — and the config's loader
        // path as a present-byte + path (M26, `-dylinker`): a resident
        // relink execs the loader the client named, never the pre-M26
        // default — and the config's PIE decision as a tail byte (M27,
        // `-no_pie`): a resident relink carries the flag word the
        // client asked for, never the PIE-always default — and the
        // config's section-alignment floors as a length-prefixed
        // (segment, section, exponent) triple list (M28, `-sectalign`):
        // a resident relink aligns the sections the client named, never
        // the pre-M28 input-only shape — and the config's header-region
        // floor as a present byte + u64 (M29, `-headerpad`): a resident
        // relink reserves the region the client named, never the
        // pre-M29 natural size alone — and the config's data-in-code
        // suppression as a tail byte (M30, `-no_data_in_code`): a
        // resident relink carries the stream decision the client asked
        // for, never the pre-M30 carry-when-named default — and the
        // config's function-starts suppression as a tail byte (M31,
        // `-no_function_starts`): a resident relink carries the
        // linkedit-metadata decision the client asked for, never the
        // pre-M31 always-carried default — and the config's UUID
        // suppression as a tail byte (M32, `-no_uuid`): a resident
        // relink carries the derived-UUID decision the client asked
        // for, never the pre-M32 always-carried default — and the
        // config's private-extern keep as a tail byte (M33,
        // `-keep_private_externs`): a resident relink carries the
        // private-extern decision the client asked for, never the
        // pre-M33 conversion default — and the config's compact-unwind
        // suppression as a tail byte (M36, `-no_compact_unwind`): a
        // resident relink carries the suppression decision the client
        // asked for, never the pre-M36 carry default — and the
        // config's export-trie suppression as a tail byte (M40,
        // `-no_exported_symbols`): a resident relink carries the
        // export-surface decision the client asked for, never the
        // pre-M40 always-carried default — and the config's dedup
        // toggle as a tail byte (M41, `-no_deduplicate`): a resident
        // relink carries the D4 decision the client asked for, never
        // the pre-M41 merge default — and the config's unused-dylib
        // drop as a tail byte (M42, `-dead_strip_dylibs`): a resident
        // relink carries the drop decision the client asked for, never
        // the pre-M42 keep-every-dylib default — and the config's
        // ObjC pull as a tail byte (M43, `-ObjC`): a resident relink
        // carries the pull decision the client asked for, never the
        // pre-M43 reference-driven default — and the dylib list's
        // upward-load kind per dylib (M45, `-upward_library`/
        // `-upward_framework`): the wire never silently flattens the
        // umbrella mark into a plain load — and the export-dynamic
        // roots as a tail byte (M46, `-export_dynamic`): a resident
        // relink carries the dlsym decision the client asked for,
        // never the pre-M46 entry-root default — the branch-island
        // suppression as a tail byte (M47, `-no_branch_islands`), the
        // dylib initializer as a present byte + name (M48,
        // `-init <symbol>`) and the weak-import refusal as a tail byte
        // (M50, `-no_weak_imports`): a resident relink carries the
        // decision the client asked for, never the pre-M50
        // runtime-lookup fallthrough — and the stack-execution
        // decision as a tail byte (M51, `-allow_stack_execute`): a
        // resident relink carries the flag word the client asked for,
        // never the pre-M51 bitless default — and the dead-strip
        // init/term roots as a tail byte (M52,
        // `-no_dead_strip_inits_and_terms`): a resident relink strips
        // the routines the client asked to keep, never the pre-M52
        // term-strip default — and the section renames as a
        // count-prefixed tail table (M53, `-rename_section`): a
        // resident relink renames the sections the client named, never
        // the pre-M53 unnamed pairs — and the served time report (M58/M59,
        // `--time`): the request's flag asks the session to observe its own
        // pipeline, the reply's tail carries the report — and the served
        // Chrome-trace timeline (M61/M62, `--trace`): the request's flag
        // asks the same of the session's timeline (the collectors pair
        // when both faces ride), the reply's tail carries the rendered
        // document verbatim — and v42 registers the §7.3 ladder's rung
        // vocabulary in the time-report tail (M65) — and v43 serves the
        // strict verifier's verdict on the final bytes (M72, `verify`):
        // the request's flag asks the session to verify its own output,
        // the reply's tail carries the effective report in the M13
        // interchange form (the `-no_adhoc` carve-out applied the
        // audit's way) — v44 carries the verify gate's check
        // selection (M77, `verify_checks`): the M12 selector the
        // session's served pass narrows to rides beside the flag — and
        // v45 carries the provenance queries (M79, `why_export`/
        // `why_load`): the session's own full walk renders the answers,
        // the tail carries the renders verbatim — v46 carries the
        // link-map ask (M80, `map`): the session's own walk renders the
        // placed image's report, the tail carries the document verbatim
        // (the client writes the file; M87 rides it beside the `record`
        // too — the ladder's replay renders its own walk's document) —
        // and v47 carries the order-file rank table (M81, the config
        // tail): a resident ordered link ranks the entries the client
        // named, a table the constructor refuses is a malformed request.
        // v48 carries the liveness queries (M93, `why_live`): the
        // session's own mark record renders the chains, the provenance
        // tail carries them verbatim beside the M79 answers (a liveness
        // ask beside a relocatable config is a malformed request — `-r`
        // carries no strip) — and v49 carries the dylib terminator (M98,
        // the config tail): a resident relink carries the `-term` name
        // the client named, never the pre-M98 absence — and v50 carries
        // the named output UUID (M99, the config tail): a resident
        // relink carries the 16 bytes the client named, never the
        // content-derived default — and v51 names the M100 round: the
        // singular export filters compose into the ONE filter table the
        // v7 pattern carriage carries (a resident relink plans the
        // composed surface the client named; a rebuild-refusing pattern
        // is a malformed request, never a silently misread filter) —
        // and v52 names the M101 round: `-alias_list <file>` composes
        // into the ONE alias table the v16 pair carriage carries (the
        // same validation the flag parse pays; a resident relink ships
        // the composed aliases the client named) — and v53 carries the
        // bind-at-load decision (M102, the config tail): a resident
        // relink carries the flag word the client asked for, never the
        // pre-M102 bitless default — and v54 names the M103 round: the
        // `-undefined` policy byte widens to the four-value alphabet
        // (warning and suppress cross byte-for-byte; an unknown value is
        // a malformed frame) and the reply gains the warning-policy tail
        // (the session's own unresolved-open render — the exit-policy
        // face the client prints) — and v55 carries the symtab-shaping
        // decision (M104, the config tail): a resident relink carries
        // the symtab shape the client asked for, never the pre-M104
        // kept default — and v56 carries the debug-section suppression
        // (M105, the config tail): a resident relink carries the
        // debug-free shape the client asked for, never the pre-M105
        // debug-carrying default — and v57 carries the needed-dylib mark
        // (M106, one byte per dylib after the upward kind byte): a
        // resident relink keeps the survival mark the client named,
        // never a silently dropped one — and v58 carries the commons
        // resolution policy (M107, the config tail after the
        // debug-suppression byte): a resident relink resolves the
        // commons the client asked for, never the house default — and
        // v59 carries the multiply-defined resolution policy (M108, the
        // tail after the commons byte): a resident relink decides the
        // duplicated names the client asked for, never the house
        // escalation — and v60 carries the warnings-as-errors exit
        // decision (M109, the tail after the multiply-defined byte): a
        // resident relink exits the shape the client asked for — and v61
        // carries the hidden-dylib mark (M110, one byte per dylib after
        // the needed byte): a resident relink drops the same load
        // command the cold link drops, never a silently flattened
        // hidden load.
        // and v62 carries the read-only-relocations policy (M111, the
        // tail after the fatal-warnings byte): a resident relink prices
        // the same read-only targets the cold link prices, never the
        // pre-M111 default refusal.
        // and v63 carries the link-statistics report (M112, the tail
        // after the read-only-relocs byte): the session's warm pipeline
        // computes the counts its own run reported and the reply tail
        // carries the payload (the M62 convention — the client prints
        // the cold lane's face, the parity gate byte-identical).
        // and v64 carries the reference trace (M113, the tail after the
        // statistics byte): the session's warm pipeline records the
        // references its own Pass 2 visited and the reply tail carries
        // the facts verbatim (the client renders the cold lane's face —
        // the trace rides the ladder's replay too).
        // and v65 carries the UUID source (M114, the typed alphabet
        // widening the v23 suppression slot): the session's warm
        // pipeline plans the same identity shape the cold link plans
        // (the parity gate is byte-identical; the random face's draw is
        // the emit's own), and the ladder's replay rides the decision —
        // the record's v9 source byte, the M81 pattern).
        // and v66 carries the ObjC category-merging disable (M115, the
        // tail after the UUID-source byte): the session's warm pipeline
        // plans the same registration shape the cold link plans (the
        // parity gate is byte-identical; the merge is Pass 3's own
        // decision — the replay re-plans the shape the config names).
        // and v67 carries the common-symbol advisory (M116, the tail
        // after the category-merging byte): the session's warm pipeline
        // derives the same advisory product the cold walk derives (the
        // decision is config, the M81 pattern) and the reply tail
        // carries the landing entries verbatim (the client prints the
        // cold lane's face).
        // and v68 carries the init/term section suppression (M117, the
        // tail after the advisory byte): the session's warm pipeline
        // plans the same init-free shape the cold link plans (the
        // parity gate is byte-identical — the suppression is Pass 3's
        // own decision, the replay re-plans the shape the config
        // names), and the LC_ROUTINES_64 command drops from the served
        // header exactly as the cold header drops it.
        // and v69 carries the dtrace DOF section processing (M118, the
        // tail after the init/term byte): the session's warm pipeline
        // plans the same DOF-validated shape the cold link plans (the
        // parity gate is byte-identical — the classification is Pass 1's
        // own decision, the emit validation Pass 4's, the replay
        // re-plans the shape the config names), and the verifier's
        // read-side backstop gates the served __dtrace_dof section
        // exactly as the cold emit gates it; the ladder's replay rides
        // the decision (the M81 pattern — the decision is config, not a
        // product).
        // and v70 carries the dylib module contract (M119, the tail after
        // the dtrace byte): the session's warm pipeline plans the same
        // single-module resolve shape the cold link plans (the parity
        // gate is byte-identical — the escalation is Pass 2's own
        // decision, the LC_DYSYMTAB module-table emit Pass 4's, the
        // replay re-plans the shape the config names), and the verifier's
        // read-side backstop gates the served module table exactly as the
        // cold emit gates it; the ladder's replay rides the decision (the
        // M81 pattern — the decision is config, not a product).
        // and v71 carries the explicit executable override (M120, the tail
        // after the module-policy byte): the session's warm pipeline plans
        // the same MH_EXECUTE shape the cold link plans (the parity gate
        // is byte-identical — the override forces OutputType::Execute, the
        // __PAGEZERO/LC_MAIN/no-LC_ID_DYLIB shape the layout and emit
        // already key on, the replay re-plans the shape the config names),
        // and the verifier's read-side executable gate refuses an
        // LC_ID_DYLIB on the served MH_EXECUTE exactly as the cold
        // layout's re-check refuses it; the ladder's replay rides the
        // decision (the M81 pattern — the decision is config, not a
        // product).
        // and v72 carries the duplicate-symbol advisory (M121, the tail
        // after the executable byte): the session's warm pipeline plans the
        // same tally the cold link plans (the parity gate is byte-identical
        // — the advisory is a Pass-2 walk, the resolution policy itself
        // unchanged, the replay re-plans the shape the config names), and
        // the served duplicate_warnings tail carries the session's own
        // collision entries verbatim (the M62 convention — the client
        // prints the cold lane's face); the ladder's replay rides the
        // decision (the M81 pattern — the decision is config, not a
        // product).
        // and v80 carries the advisory faces' print-suppression decision
        // (M133, the tail byte after the fatal-warnings byte): the
        // session's warm pipeline plans the same tally the cold link
        // plans (the parity gate is byte-identical — the decision is the
        // client's print face, the bytes never move), and the served
        // warning tails tally either way (the suppression silences the
        // client's `pgr: warning:` lines, never the reply's records).
        // and v81 carries the loaded-object inventory's decision (M134,
        // the tail byte after the warn-suppression byte) beside its
        // inventory tail (the session's own Pass 1 list rides verbatim —
        // the M62 convention): a served relink renders the inventory the
        // client asked for, the bytes never moving either way.
        assert_eq!(crate::PROTO_VERSION, 82);
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
            time: false,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: Vec::new(),
            why_load: false,
            map: false,
            why_live: Vec::new(),
        };
        assert!(req.blob_hashes().is_empty(), "no archives to hash");
        assert_ne!(content_hash(b"x"), [0u8; 32]);
    }
}
