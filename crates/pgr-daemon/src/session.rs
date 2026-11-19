//! The resident session (M8, architecture doc §7.2): the state that survives
//! between links inside `pgrd`.
//!
//! * **blobs** — raw input/archive bytes, keyed by content hash. The client
//!   transfers each distinct byte string once per daemon lifetime.
//! * **POIs** — the *Pass 1 product* of every direct input, keyed by the
//!   same versioned content key the Stage A cache uses
//!   ([`pgr_core::cache::PoiCache::content_key`]): the frame holds the
//!   section table with raw relocations, the typed symbols, the name pool
//!   and the D1 atom ranges. A warm relink decodes frames instead of
//!   walking Mach-O — no mmap, no parse.
//! * **scratch** — the fused-emit output buffer, reused across links
//!   ([`pgr_emit::build_image_fused_into`]): the page-fault cost of a fresh
//!   output allocation disappears on every relink after the first.
//!
//! M9 GA (fusion rung): the session also serves the §7.3 ladder for a
//! record-bearing request — integrity gate on the previous output (a
//! blob like every input), the anchored relink config derived from the
//! record (slack anchors, stable imports, signature boundary, resolve
//! reuse seed), the warm pipeline, the patch plan, and the in-memory
//! patch ([`pgr_emit::incremental::apply_patch_bytes`]). Any refusal
//! falls back to the session's clean full link — which captures a fresh
//! record whenever the request asks, so the incremental cycle survives
//! the daemon path.
//!
//! M9 GA rung 2 (wire v4): the session also *serves the audit* — a
//! request with `audit` set runs the §7.3 gate's bytes-level twin
//! ([`pgr_emit::incremental::audit`]) on the in-memory patch: byte-identity
//! against the reference emit plus the strict verifier, and a divergence
//! is healed in memory before the verdict crosses the wire (the client
//! still refuses to ship a failing verdict by not writing the file).
//!
//! M9 output-residency rung (wire v5): the session closes §7.2's last
//! deferred fusion item — the **session-resident output buffer**. Every
//! served image is stored as resident output state (a content-addressed
//! blob under the same memory ceiling and LRU as every other blob), so the
//! next cycle's `prev_output` reference finds it and the previous output
//! stops crossing the wire once per changed state. A tiles-asking client
//! (v5 flag) further receives a patched relink as the changed 16 KiB-tile
//! stream ([`pgr_emit::incremental::TilePatch`]) instead of the whole
//! image — an untouched relink ships nothing. The file stays the client's:
//! the stream is hash-gated (`TilePatch::image_hash`), the client verifies
//! its replay before the atomic write, and a daemon crash loses only
//! resident state, never an output (the §7.2 crash-safety contract).
//!
//! Safety properties (the §7.2 constraints):
//!
//! * The session is an **optimization only** — a corrupt/unmatched frame
//!   decodes to `None` and the object is re-parsed; the link is a pure
//!   function of `(blobs, config)`, never of session history.
//! * A memory ceiling (`max_bytes`, 0 = unbounded) evicts
//!   least-recently-used entries; the entry a link just used is refreshed.
//! * Nothing in the session is keyed by path — concurrent builds of
//!   different corpora coexist; identical content shares entries.

use pgr_core::cache::{PoiCache, decode_poi, encode_poi};
use pgr_core::object::InputObject;
use pgr_emit::incremental::audit::{AuditOutcome, audit_image, audit_patch};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// A session operation failure (the daemon answers `ERROR`; the client
/// falls back to one-shot).
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// A manifest hash the `BLOB` exchange never delivered.
    #[error("session: bytes for hash {} missing", crate::protocol::hex(&.0))]
    MissingBlob([u8; 32]),
    /// The stored bytes do not match their manifest hash (a misbehaving
    /// client): refused rather than linked.
    #[error("session: blob {} does not match its hash", crate::protocol::hex(&.0))]
    HashMismatch([u8; 32]),
    /// The link failed (surfaced to the client as `ERROR`).
    #[error(transparent)]
    Link(#[from] pgr_core::LinkError),
    /// The emit failed.
    #[error(transparent)]
    Emit(#[from] pgr_emit::EmitError),
    /// The M9 record/patch state failed (record capture, plan contract).
    #[error(transparent)]
    Patch(#[from] pgr_emit::incremental::PatchError),
    /// A provenance query the link's own product refused (M79): the
    /// vacuous decision — a name nothing interned — is the cold lane's
    /// refusal, surfaced as the `ERROR` the client's one-shot fallback
    /// reproduces (the same refusal either lane).
    #[error(transparent)]
    Provenance(#[from] pgr_core::provenance::ProvenanceError),
}

/// One cached POI frame: the encoded Pass 1 product plus its last-use
/// stamp (the LRU clock for the memory ceiling).
type PoiFrame = (std::sync::Arc<Vec<u8>>, u64);

/// One served link: the image bytes plus the M9 fusion state — the
/// refreshed record (when the request asked for capture or renewed one)
/// and the in-place patch report (`None` on a full link).
#[derive(Debug, Clone)]
pub struct ServedLink {
    /// The complete output image bytes (patched when the ladder ran).
    pub image: Vec<u8>,
    /// Entry offset within `__TEXT` (executables).
    pub entryoff: u64,
    /// Chained-fixup slots packed.
    pub fixup_slots: u64,
    /// The refreshed record bytes (`None` when no capture was asked).
    pub record: Option<Vec<u8>>,
    /// The in-place patch outcome (`None` on a full link).
    pub patch: Option<pgr_emit::incremental::PatchOutcome>,
    /// The served audit verdict (`Some` when the request asked for the
    /// audit and the ladder patched; the audit's subject is the patch —
    /// a full link or an untouched relink serves none).
    pub audit: Option<AuditOutcome>,
    /// The changed-tile stream of a relink (v5, the §7.2 rung): `Some`
    /// only when the request asked for tiles and the reply is a relink
    /// (patched or untouched) — a full link has no previous state to
    /// stream against, and the server then ships `image` as before.
    pub tiles: Option<pgr_emit::incremental::TilePatch>,
    /// The served time report (v40, M58/M59): `Some` when the request
    /// asked for it — the phases the session's own pipeline reported
    /// (the M54 observation seam, [`pgr_core::time_report::TimeCollector`]
    /// subscribed), the ladder's notes, the measured bands. A relink's
    /// Pass-4 half is the in-memory patch, so its emit band rides
    /// `None`; a full link measures the fused emit.
    pub time_report: Option<pgr_core::time_report::TimeReport>,
    /// The served Chrome-trace timeline (v41, M61/M62): `Some` when the
    /// request asked for it — the rendered Trace Event Format document
    /// (the M54 observation seam,
    /// [`pgr_core::trace::TraceCollector`] subscribed — paired with the
    /// time collector when both faces ask). The wire carries the
    /// document verbatim; the strict reader is its own face.
    pub trace_json: Option<String>,
    /// The served verify verdict (v43, M72): `Some` when the request
    /// asked for it — the strict verifier's effective report on the
    /// final bytes (the full link's, the patched relink's and the
    /// untouched relink's alike; the `-no_adhoc` carve-out applied the
    /// audit's way, `effective_report`). The subject is the image —
    /// every outcome serves one — so a build system reads the gate's
    /// verdict without re-reading the file it is about to write.
    pub verify_report: Option<pgr_verify::Report>,
    /// The served provenance answers (v45, M79): `Some` when the request
    /// asked — the `-why_export` answers in flag order and the
    /// `-why_load` report, rendered from the session's own Pass-2
    /// product (the full link's walk; the ladder's replay serves none —
    /// the fusion lane's request is refused at the wire). The renders
    /// cross verbatim; the client prints the cold lane's face.
    pub provenance: Option<crate::protocol::ServedProvenance>,
    /// The served link map (v46, M80): `Some` when the request asked —
    /// the placed image's report rendered from the session's own walk
    /// (the full link's layout and interner). M87: the ladder's replay
    /// serves its own too — the walk ran the full Passes 1–3, so the
    /// document is the replay's own Pass-3 product (never the previous
    /// link's). The document crosses verbatim; the client writes the
    /// cold lane's file.
    pub map_text: Option<String>,
}

/// The verdict's effective shape (M72): the strict pass's report with
/// the `-no_adhoc` carve-out applied — the missing-signature shape is
/// the config's own choice, never a defect the verdict names (the
/// audit's rule, mirrored; everything else gates at full strictness).
/// The stats ride unfiltered — they describe the image.
fn effective_report(
    mut report: pgr_verify::Report,
    signature_expected: bool,
) -> pgr_verify::Report {
    report.issues.retain(|issue| match issue.severity {
        pgr_verify::Severity::Error => {
            issue.code != pgr_verify::Code::SignatureLayout || signature_expected
        }
        pgr_verify::Severity::Warning => true,
    });
    report
}

/// The strict verifier on the final bytes (M72): the served verdict's
/// body — full strictness, the `-no_adhoc` carve-out applied, one
/// `tracing` span (inert until a subscriber installs — the workspace
/// convention). M77: the request's check selection narrows the pass to
/// the named families (the M12 selector's subtractive contract — the
/// parse pre-pass and the stats ride regardless); `None` names the full
/// pass, the pre-M77 shape.
fn serve_verify(
    bytes: &[u8],
    signature_expected: bool,
    checks: Option<&pgr_verify::CheckSet>,
) -> pgr_verify::Report {
    let selection_text = match checks {
        Some(set) => set.to_string(),
        None => "all".to_string(),
    };
    let span = tracing::info_span!(
        "daemon_verify",
        len = bytes.len(),
        signature_expected,
        selection = selection_text
    );
    let _entered = span.enter();
    let opts = pgr_verify::Options {
        strict_warnings: true,
        skip_hash_recompute: false,
    };
    let full = pgr_verify::CheckSet::all();
    let selected = checks.unwrap_or(&full);
    let report = pgr_verify::verify_with_checks(bytes, &opts, selected);
    let effective = effective_report(report, signature_expected);
    tracing::debug!(
        issues = effective.issues.len(),
        "the daemon's verify finished"
    );
    effective
}

/// Why the session's §7.3 ladder declined: the caller (the link entry)
/// falls back to the clean full link — the ladder's bottom rung — which
/// is always available and always correct (§7.3).
enum RelinkDecline {
    /// A real session failure: surfaced as `ERROR`, not swallowed.
    Error(SessionError),
    /// A §7.3 refusal (integrity, shape, ladder): full link follows.
    Fallback,
}

/// The resident state (M8 §7.2).
#[derive(Debug)]
pub struct ResidentSession {
    blobs: HashMap<[u8; 32], std::sync::Arc<Vec<u8>>>,
    /// POI frame per (content key, split flag). The frame carries the flag
    /// it was produced under; a decode under the other flag misses.
    pois: HashMap<([u8; 32], bool), PoiFrame>,
    /// Last-use stamp per blob (the LRU clock for the ceiling).
    blob_uses: HashMap<[u8; 32], u64>,
    /// The reused fused-emit output buffer (the page-fault gate).
    pub scratch: Vec<u8>,
    /// Memory ceiling in bytes across blobs + POI frames (0 = unbounded).
    max_bytes: u64,
    /// Monotonic use clock (LRU ordering).
    clock: u64,
    /// POI frames decoded across the session's life (no Mach-O walk).
    pub hits: u64,
    /// Fresh parses across the session's life (stored as frames).
    pub misses: u64,
}

impl Default for ResidentSession {
    fn default() -> Self {
        Self::with_limit(0)
    }
}

impl ResidentSession {
    /// A session with a memory ceiling (`0` = unbounded).
    #[must_use]
    pub fn with_limit(max_bytes: u64) -> Self {
        Self {
            blobs: HashMap::new(),
            pois: HashMap::new(),
            blob_uses: HashMap::new(),
            scratch: Vec::new(),
            max_bytes,
            clock: 0,
            hits: 0,
            misses: 0,
        }
    }

    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    /// Bytes currently held as resident state (blobs + POI frames — the
    /// served images of past links ride as blobs, the §7.2 output
    /// residency). The scratch emit buffer is not session state — it is
    /// bounded by the output size and always reclaimable.
    #[must_use]
    pub fn bytes_held(&self) -> u64 {
        let blobs: u64 = self.blobs.values().map(|b| b.len() as u64).sum();
        let pois: u64 = self.pois.values().map(|(f, _)| f.len() as u64).sum();
        blobs + pois
    }

    /// Stores (or replaces) one byte string. The hash is the caller's
    /// transfer hash; content is verified here against it.
    ///
    /// # Errors
    /// [`SessionError::HashMismatch`] when `bytes` does not hash to `hash`.
    pub fn store_blob(&mut self, hash: &[u8; 32], bytes: Vec<u8>) -> Result<(), SessionError> {
        let got: [u8; 32] = Sha256::digest(&bytes).into();
        if &got != hash {
            return Err(SessionError::HashMismatch(*hash));
        }
        let use_at = self.tick();
        self.blob_uses.insert(*hash, use_at);
        self.blobs.insert(*hash, std::sync::Arc::new(bytes));
        self.enforce_limit();
        Ok(())
    }

    /// True when the blob is already resident.
    #[must_use]
    pub fn has_blob(&self, hash: &[u8; 32]) -> bool {
        self.blobs.contains_key(hash)
    }

    /// The resident blob (Arc clone — no copy).
    /// The bytes for a previously transferred hash.
    ///
    /// # Errors
    /// [`SessionError::MissingBlob`] when the hash was never transferred;
    /// [`SessionError::HashMismatch`] is checked at transfer time.
    pub fn blob(&mut self, hash: &[u8; 32]) -> Result<std::sync::Arc<Vec<u8>>, SessionError> {
        let use_at = self.tick();
        self.blob_uses.insert(*hash, use_at);
        self.blobs
            .get(hash)
            .cloned()
            .ok_or(SessionError::MissingBlob(*hash))
    }

    /// Pass 1 for one direct input (M8's whole point): a POI frame decodes
    /// with the link's `FileId`/name; a miss parses, atomizes and stores.
    ///
    /// # Errors
    /// [`SessionError::MissingBlob`] when the bytes never arrived;
    /// [`SessionError::Link`] on a malformed object.
    pub fn prepare_object(
        &mut self,
        hash: &[u8; 32],
        name: &str,
        file: pgr_core::ids::FileId,
        split_symbols: bool,
    ) -> Result<InputObject, SessionError> {
        let bytes = self.blob(hash)?;
        let key = PoiCache::content_key(&bytes, split_symbols);
        let use_at = self.tick();
        if let Some((frame, stamp)) = self.pois.get_mut(&(key, split_symbols)) {
            *stamp = use_at;
            if let Some(mut obj) = decode_poi(frame, file, name, split_symbols) {
                obj.bytes.clone_from(bytes.as_ref());
                self.hits += 1;
                return Ok(obj);
            }
            // A corrupt frame falls through to a fresh parse (the session
            // is an optimization only) and is dropped below.
            self.pois.remove(&(key, split_symbols));
        }
        let mut obj = InputObject::parse(file, name, bytes.as_ref().clone())?;
        obj.compute_atoms(split_symbols);
        let frame = std::sync::Arc::new(encode_poi(&obj, split_symbols));
        self.pois.insert((key, split_symbols), (frame, use_at));
        self.misses += 1;
        self.enforce_limit();
        Ok(obj)
    }

    /// Stores the served image as resident output state (v5, the §7.2
    /// rung): a content-addressed blob under the same ceiling and LRU as
    /// every other blob, so the next cycle's `prev_output` reference
    /// finds it and the previous output stops crossing the wire once per
    /// changed state. Eviction is harmless — the client re-uploads.
    fn hold_output(&mut self, image: &[u8]) {
        let hash: [u8; 32] = Sha256::digest(image).into();
        tracing::debug!(
            bytes = image.len(),
            "the served image became resident output"
        );
        // store_blob re-verifies the hash we just computed; failure is
        // impossible, and even it were, the client re-uploads next cycle.
        let _ = self.store_blob(&hash, image.to_vec());
    }

    /// Runs one link through the session: prepares direct inputs, pulls
    /// archive members through the normal S7 fixpoint, links, gates `-u`,
    /// emits into the reused scratch buffer.
    ///
    /// M9 GA (fusion rung): a record-bearing request runs the §7.3 ladder
    /// first (the private `serve_relink`); any refusal falls back here to
    /// the clean full link — which captures a fresh record whenever
    /// `record_resolution` is set, so the sidecar stays fresh across
    /// resident links (the rung that keeps the incremental cycle alive).
    ///
    /// # Errors
    /// [`SessionError`] on missing blobs, link failures (undefined
    /// symbols, duplicates, layout contract) or emit failures.
    pub fn link(&mut self, req: &crate::protocol::LinkRequest) -> Result<ServedLink, SessionError> {
        use pgr_core::Parallelism;
        // M83: the relocatable shape rides the session — the object walk
        // is Passes 1–2 over the raw blobs (`pgr_core::link_reloc`, the
        // cold lane's own entry; the POI cache is the segmented
        // pipeline's optimization, the object path re-parses) and
        // `pgr_emit::build_object_image` assembles the `MH_OBJECT` the
        // reply carries verbatim. The replay faces have no object shape:
        // a record, tiles, the audit, `-verify` or `-map` beside a
        // relocatable config refuses (the surface refuses the knobs
        // beside `-r`, so the driver never asks — no wire caller can
        // plan the shape either); the provenance queries ride (the
        // object's Pass-2 product is the same arena the query reads).
        if req.config.filetype == pgr_core::layout::OutputType::Relocatable {
            if req.record.is_some()
                || req.prev_output.is_some()
                || req.audit
                || req.tiles
                || req.verify
                || req.map
            {
                return Err(SessionError::Link(pgr_core::LinkError::Layout {
                    message: "the relocatable output has no ladder shape: no record, no tiles, \
                              no audit, no verify, no map beside -r"
                        .into(),
                }));
            }
            return self.serve_relocatable(req);
        }
        // The Pass-1 split rule is pgr-core's own (M11: a rank table
        // feeds the atom split the same way dead-strip does) — the M81
        // config tail carries the table, so the session's prepare reads
        // the same named decision the cold lane reads (one rule, both
        // lanes; a warm ordered link plans the atom shape the cold one
        // plans — the `m81_resident_order` parity gate pins it).
        let split = pgr_core::split_symbols_for(&req.config);
        let mut objects: Vec<InputObject> = Vec::with_capacity(req.inputs.len());
        for (i, entry) in req.inputs.iter().enumerate() {
            objects.push(self.prepare_object(
                &entry.hash,
                &entry.name,
                pgr_core::ids::FileId(i as u32),
                split,
            )?);
        }
        let archives: Vec<pgr_core::LinkArchive> = self.build_archives(req)?;
        // The §7.3 ladder (v3 fusion): a record plus the previous output
        // runs the relink inside the session. A record that will not
        // decode, a missing previous output or any ladder refusal falls
        // back to the clean full link below — never an error.
        if let Some(record_bytes) = &req.record {
            let prev = req.prev_output.and_then(|h| self.blob(&h).ok());
            if let Some(prev) = prev {
                if let Some(record) = pgr_emit::incremental::LinkRecord::decode(record_bytes) {
                    match Self::serve_relink(&record, prev.as_ref(), req, &objects, &archives) {
                        Ok(served) => {
                            self.hold_output(&served.image);
                            return Ok(served);
                        }
                        Err(RelinkDecline::Error(e)) => return Err(e),
                        Err(RelinkDecline::Fallback) => {}
                    }
                }
            }
        }
        // M58/M59/M61/M62 (v40/v41): a time- or trace-asking request
        // observes the session's own pipeline — the same warm run, the
        // [`pgr_core::time_report::TimeCollector`] and the
        // [`pgr_core::trace::TraceCollector`] subscribed (paired when
        // both faces ask; the report and the timeline never move a byte
        // of the plan — the M54 parity gate is the seam's own contract).
        // The warm pipeline has no `Parse` row: the POIs are resident,
        // the parse was paid when the blobs arrived.
        let started = std::time::Instant::now();
        let mut time_collector = pgr_core::TimeCollector::default();
        let mut traces = pgr_core::trace::TraceCollector::new();
        let result = if req.time && req.trace {
            let mut pair = pgr_core::ObserverPair::new(&mut time_collector, &mut traces);
            pgr_core::link_from_objects_observed(
                objects,
                &archives,
                &req.config,
                Parallelism::Auto,
                None,
                Some(&mut pair),
            )?
        } else if req.trace {
            pgr_core::link_from_objects_observed(
                objects,
                &archives,
                &req.config,
                Parallelism::Auto,
                None,
                Some(&mut traces),
            )?
        } else if req.time {
            pgr_core::link_from_objects_observed(
                objects,
                &archives,
                &req.config,
                Parallelism::Auto,
                None,
                Some(&mut time_collector),
            )?
        } else {
            pgr_core::link_from_objects(objects, &archives, &req.config, Parallelism::Auto, None)?
        };
        pgr_core::check_load_symbols(&result, &req.force_load)?;
        let entryoff = result.layout.entryoff;
        let fixup_slots = result.layout.fixups.slot_count;
        // The emit band: the fused tile emit the session ran (the report's
        // Passes-4–5 half, measured here so the served table names the
        // pipeline's second half).
        let emit_started = std::time::Instant::now();
        pgr_emit::build_image_fused_into(&mut self.scratch, &result.layout, &result.objects)?;
        let emit = if req.time {
            Some(emit_started.elapsed())
        } else {
            None
        };
        let total = req.time.then(|| started.elapsed());
        let time_report = req.time.then(|| {
            let mut report = time_collector.report();
            report.emit = emit;
            report.total = total;
            report
        });
        let trace_json = req.trace.then(|| traces.finish().render());
        let image = self.scratch.clone();
        // The §7.2 rung: the full link's image is the first cycle's
        // resident output state — the next relink's previous output is
        // already here.
        self.hold_output(&image);
        let verify_report = req
            .verify
            .then(|| serve_verify(&image, req.config.adhoc, req.verify_checks.as_ref()));
        let record = if req.record_resolution {
            Some(
                pgr_emit::incremental::LinkRecord::record(
                    &result.layout,
                    &result.objects,
                    &image,
                    result.resolve_snapshot.as_ref(),
                )
                .map_err(SessionError::from)?
                .encode(),
            )
        } else {
            None
        };
        // M79 (v45): the served provenance — the session's own Pass-2
        // product (the warm pipeline *is* the one-shot shape: the walk
        // ran, the arena, the resolution and the pull record are in
        // memory) renders the answers the cold lane renders. A vacuous
        // query refuses the link (the cold lane's own refusal — the
        // `ERROR` reply is the client's fallback cue, the same refusal
        // either lane); the index builds once per link, the queries read
        // it.
        let provenance = Self::serve_provenance(req, &result)?;
        // M80 (v46): the served map — the session's own walk renders the
        // placed image's report (the layout and the interner are the
        // warm pipeline's product; the render is the same pure function
        // the cold lane's `-map` calls, so the document cannot
        // disagree with the bytes the reply carries).
        let map_text = req
            .map
            .then(|| pgr_core::map::build_link_map(&result.layout, &result.interner).render());
        Ok(ServedLink {
            image,
            entryoff,
            fixup_slots: u64::try_from(fixup_slots).unwrap_or(u64::MAX),
            record,
            patch: None,
            audit: None,
            tiles: None,
            time_report,
            trace_json,
            verify_report,
            provenance,
            map_text,
        })
    }

    /// The served provenance answers (M79): the request's queries over
    /// the link's own Pass-2 product — one `-why_export` answer per name
    /// in flag order (a vacuous query refuses with the misspelling
    /// named), the `-why_load` report beside them when the flag asked.
    /// `None` when the request asked nothing (the pre-M79 shape — an
    /// unasked query crosses nothing).
    fn serve_provenance(
        req: &crate::protocol::LinkRequest,
        result: &pgr_core::LinkResult,
    ) -> Result<Option<crate::protocol::ServedProvenance>, SessionError> {
        Self::serve_provenance_from(
            req,
            &result.objects,
            &result.resolution,
            &result.interner,
            &result.loads,
        )
    }

    /// [`Self::serve_provenance`] over the shape's parts — the
    /// relocatable walk (M83) carries the same members on
    /// [`pgr_core::link_reloc`]'s own product, so the queries read the
    /// object's Pass-2 arena the way the cold lane's `-why_export` does.
    fn serve_provenance_from(
        req: &crate::protocol::LinkRequest,
        objects: &[pgr_core::object::InputObject],
        resolution: &pgr_core::resolve::Resolution,
        interner: &pgr_core::Interner,
        loads: &pgr_core::provenance::LoadReport,
    ) -> Result<Option<crate::protocol::ServedProvenance>, SessionError> {
        if req.why_export.is_empty() && !req.why_load {
            return Ok(None);
        }
        let index = pgr_core::ReverseIndex::build_all(objects);
        let mut exports = Vec::with_capacity(req.why_export.len());
        for name in &req.why_export {
            let answer = pgr_core::explain_export(&index, objects, resolution, interner, name)?;
            exports.push(crate::protocol::ServedExport {
                name: name.clone(),
                render: answer.render(),
            });
        }
        let loads = req.why_load.then(|| loads.render());
        Ok(Some(crate::protocol::ServedProvenance { exports, loads }))
    }

    /// Assembles the request's archives over the session's blobs — the
    /// ranlib index and member table the archive pull walks, `all_load`
    /// riding per archive. One assembly both link shapes read (the
    /// segmented pipeline and the relocatable walk, M83).
    fn build_archives(
        &mut self,
        req: &crate::protocol::LinkRequest,
    ) -> Result<Vec<pgr_core::LinkArchive>, SessionError> {
        let mut archives: Vec<pgr_core::LinkArchive> = Vec::with_capacity(req.archives.len());
        for a in &req.archives {
            let bytes = self.blob(&a.hash)?;
            let parsed =
                pgr_format::parse_archive(&bytes).map_err(|e| pgr_core::LinkError::Parse {
                    file: a.name.clone(),
                    message: e.to_string(),
                })?;
            archives.push(pgr_core::LinkArchive {
                name: a.name.clone(),
                bytes: bytes.as_ref().clone(),
                index: parsed
                    .index
                    .iter()
                    .map(|e| (e.name.clone().into_bytes(), e.member))
                    .collect(),
                members: parsed
                    .members
                    .iter()
                    .map(|m| pgr_core::LinkArchiveMember {
                        name: m.name.clone(),
                        offset: m.offset,
                        size: m.size,
                    })
                    .collect(),
                all_load: a.all_load,
            });
        }
        Ok(archives)
    }

    /// The relocatable shape's walk (M83): Passes 1–2 over the raw blobs
    /// (`pgr_core::link_reloc` — the cold lane's own entry; the POI cache
    /// is the segmented pipeline's optimization, the object path
    /// re-parses) and `pgr_emit::build_object_image` assembles the
    /// `MH_OBJECT` the reply carries verbatim. The faces ride the same
    /// wire tails the segmented shape serves: the time report names the
    /// object shape's own phases (the cold lane's report — the emit band
    /// stays absent, the `-r` Pass 4 is the object assembly, not the
    /// fused tile emit), the timeline renders the same run, and the
    /// provenance queries read the object's Pass-2 product. The daemon
    /// never touches the filesystem: the client writes the object.
    fn serve_relocatable(
        &mut self,
        req: &crate::protocol::LinkRequest,
    ) -> Result<ServedLink, SessionError> {
        use pgr_core::Parallelism;
        let started = std::time::Instant::now();
        let mut time_collector = pgr_core::TimeCollector::default();
        let mut traces = pgr_core::trace::TraceCollector::new();
        let mut inputs: Vec<pgr_core::link::LinkInput> = Vec::with_capacity(req.inputs.len());
        for entry in &req.inputs {
            let bytes = self.blob(&entry.hash)?;
            inputs.push(pgr_core::link::LinkInput {
                name: entry.name.clone(),
                bytes: bytes.as_ref().clone(),
            });
        }
        let archives = self.build_archives(req)?;
        let linked = if req.time && req.trace {
            let mut pair = pgr_core::ObserverPair::new(&mut time_collector, &mut traces);
            pgr_core::link_reloc_observed(
                &inputs,
                &archives,
                &req.config,
                Parallelism::Auto,
                &mut pair,
            )?
        } else if req.trace {
            pgr_core::link_reloc_observed(
                &inputs,
                &archives,
                &req.config,
                Parallelism::Auto,
                &mut traces,
            )?
        } else if req.time {
            pgr_core::link_reloc_observed(
                &inputs,
                &archives,
                &req.config,
                Parallelism::Auto,
                &mut time_collector,
            )?
        } else {
            pgr_core::link_reloc(&inputs, &archives, &req.config, Parallelism::Auto)?
        };
        let image = pgr_emit::build_object_image(&linked, &req.config)?;
        let total = req.time.then(|| started.elapsed());
        let time_report = req.time.then(|| {
            let mut report = time_collector.report();
            report.total = total;
            report
        });
        let trace_json = req.trace.then(|| traces.finish().render());
        let provenance = Self::serve_provenance_from(
            req,
            &linked.objects,
            &linked.resolution,
            &linked.interner,
            &linked.loads,
        )?;
        Ok(ServedLink {
            image,
            entryoff: 0,
            fixup_slots: 0,
            record: None,
            patch: None,
            audit: None,
            tiles: None,
            time_report,
            trace_json,
            verify_report: None,
            provenance,
            map_text: None,
        })
    }

    /// Reports one ladder rung through the watching faces (M66): the same
    /// event shape the pipeline's phases carry, delivered to each
    /// subscribed collector — the `serve_relink` body reads the request's
    /// flags once here, not at every rung.
    fn report_rung(
        req: &crate::protocol::LinkRequest,
        time_collector: &mut pgr_core::TimeCollector,
        traces: &mut pgr_core::trace::TraceCollector,
        phase: pgr_core::observe::Phase,
        detail: pgr_core::observe::PhaseDetail,
        elapsed: std::time::Duration,
    ) {
        use pgr_core::observe::LinkObserver as _;
        if !req.time && !req.trace {
            return;
        }
        let event = pgr_core::observe::PhaseEvent {
            phase,
            detail,
            elapsed,
        };
        if req.time {
            time_collector.on_phase(event.clone());
        }
        if req.trace {
            traces.on_phase(event);
        }
    }

    /// The §7.3 ladder inside the session (v3 fusion): gate the previous
    /// output, derive the anchored relink config from the record (the
    /// mirror of the driver's in-process assembly), run the pipeline warm
    /// over the session's POIs, plan the patch and apply it in memory.
    /// Every §7.3 refusal declines ([`RelinkDecline::Fallback`]) — the
    /// caller's full link is the ladder's bottom rung.
    fn serve_relink(
        record: &pgr_emit::incremental::LinkRecord,
        prev: &[u8],
        req: &crate::protocol::LinkRequest,
        objects: &[InputObject],
        archives: &[pgr_core::LinkArchive],
    ) -> Result<ServedLink, RelinkDecline> {
        use pgr_core::Parallelism;
        // M82: the ladder's named admission — `pgr_emit::incremental::LinkRecord::admits`,
        // the same decision the driver's in-process relink reads. A config
        // naming a different chain word family than the record's declines:
        // the patch cannot renegotiate the word shape in place, and the
        // full link re-plans the family the request named and re-records.
        if record.admits(&req.config).is_err() {
            return Err(RelinkDecline::Fallback);
        }
        // The integrity gate rides the timed block below (M66: the gate is
        // real work and reports beside the other rungs when a face asks).
        // The anchored relink config: exactly the assembly the driver's
        // in-process relink runs (slack anchors, stable imports, signature
        // boundary, resolve-reuse seed) — the layout the patch plan
        // assumes. Capture is unconditional: the relink re-records the
        // fresh state for the next cycle.
        let mut cfg = req.config.clone();
        cfg.slack_anchor = record
            .sections
            .iter()
            .map(|s| pgr_core::slack::SlackAnchor {
                seg: s.seg.clone(),
                name: s.name.clone(),
                padded: s.size,
            })
            .collect();
        cfg.stable_imports = Some(record.imports.clone());
        cfg.sig_anchor = (record.linkedit.sig_off > 0).then_some(record.linkedit.sig_off);
        cfg.record_resolution = true;
        if let Some(resolution) = &record.resolution {
            cfg.resolve_reuse = Some(pgr_core::resolve_reuse::ResolveReuseSeed {
                snapshot: resolution.clone(),
                digests: record.section_digests.clone(),
            });
        }
        // M58/M59/M61/M62 (v40/v41): a time- or trace-asking relink
        // observes the ladder's warm pipeline — the same run, the
        // collectors subscribed (paired when both faces ask). The emit
        // band rides absent (the relink's Pass-4 half is the in-memory
        // patch, not the fused tile emit); the total carries the ladder
        // wall through the patched image. M66 (v42 in service): the
        // ladder's own rungs ride the same faces — the integrity gate
        // (real work: the record's page-hash sample hashed against the
        // transferred bytes), the patch plan, the in-memory patch and the
        // audit report beside the pipeline's rows, and an untouched
        // relink's plan row names an empty dirty set with no patch row.
        let started = std::time::Instant::now();
        let mut time_collector = pgr_core::TimeCollector::default();
        let mut traces = pgr_core::trace::TraceCollector::new();
        let gate_started = std::time::Instant::now();
        let gate = pgr_emit::incremental::output_integrity(prev, record);
        match gate {
            Ok(pgr_emit::incremental::Integrity::Match) => {
                Self::report_rung(
                    req,
                    &mut time_collector,
                    &mut traces,
                    pgr_core::observe::Phase::RelinkGate,
                    pgr_core::observe::PhaseDetail::Gate {
                        pages: usize::try_from(record.hashed_pages()).unwrap_or(usize::MAX),
                    },
                    gate_started.elapsed(),
                );
            }
            Ok(pgr_emit::incremental::Integrity::Mismatch { .. }) => {
                return Err(RelinkDecline::Fallback);
            }
            Err(_) => return Err(RelinkDecline::Fallback),
        }
        let result = if req.time && req.trace {
            let mut pair = pgr_core::ObserverPair::new(&mut time_collector, &mut traces);
            pgr_core::link_from_objects_observed(
                objects.to_vec(),
                archives,
                &cfg,
                Parallelism::Auto,
                None,
                Some(&mut pair),
            )
            .map_err(|e| RelinkDecline::Error(e.into()))?
        } else if req.trace {
            pgr_core::link_from_objects_observed(
                objects.to_vec(),
                archives,
                &cfg,
                Parallelism::Auto,
                None,
                Some(&mut traces),
            )
            .map_err(|e| RelinkDecline::Error(e.into()))?
        } else if req.time {
            pgr_core::link_from_objects_observed(
                objects.to_vec(),
                archives,
                &cfg,
                Parallelism::Auto,
                None,
                Some(&mut time_collector),
            )
            .map_err(|e| RelinkDecline::Error(e.into()))?
        } else {
            pgr_core::link_from_objects(objects.to_vec(), archives, &cfg, Parallelism::Auto, None)
                .map_err(|e| RelinkDecline::Error(e.into()))?
        };
        pgr_core::check_load_symbols(&result, &req.force_load)
            .map_err(|e| RelinkDecline::Error(e.into()))?;
        let plan_started = std::time::Instant::now();
        let decision = pgr_emit::incremental::plan_patch(
            record,
            &result.layout,
            &result.objects,
            cfg.layout_slack.as_ref(),
        )
        .map_err(|e| RelinkDecline::Error(e.into()))?;
        let plan = match decision {
            pgr_emit::incremental::PatchDecision::InPlace(plan) => plan,
            pgr_emit::incremental::PatchDecision::Fallback(_) => {
                return Err(RelinkDecline::Fallback);
            }
        };
        Self::report_rung(
            req,
            &mut time_collector,
            &mut traces,
            pgr_core::observe::Phase::RelinkPlan,
            pgr_core::observe::PhaseDetail::Plan {
                tiles: usize::try_from(plan.total_tiles).unwrap_or(usize::MAX),
                dirty: plan.dirty_tiles.len(),
            },
            plan_started.elapsed(),
        );
        // Nothing changed: the previous output rides back untouched and
        // the record is renewed verbatim (the driver's untouched shape).
        // No audit: its subject — the patch — never exists here (parity
        // with the in-process gate, which runs after a patch only).
        if plan.is_untouched() {
            // The §7.2 rung: a tiles-asking client receives an empty
            // stream (its file already IS the output).
            let tiles = req.tiles.then(|| pgr_emit::incremental::TilePatch {
                final_size: prev.len() as u64,
                tiles: Vec::new(),
                image_hash: Sha256::digest(prev).into(),
            });
            let time_report = req.time.then(|| {
                let mut report = time_collector.report();
                report.total = Some(started.elapsed());
                report
            });
            let trace_json = req.trace.then(|| traces.finish().render());
            // M72: the verdict's subject is the image, every outcome
            // serves one — an untouched relink's is the resident previous
            // output itself.
            let verify_report = req
                .verify
                .then(|| serve_verify(prev, cfg.adhoc, req.verify_checks.as_ref()));
            return Ok(ServedLink {
                image: prev.to_vec(),
                entryoff: result.layout.entryoff,
                fixup_slots: u64::try_from(result.layout.fixups.slot_count).unwrap_or(u64::MAX),
                record: Some(record.encode()),
                patch: Some(pgr_emit::incremental::PatchOutcome {
                    bytes_patched: 0,
                    dirty_tiles: 0,
                    total_tiles: plan.total_tiles,
                    untouched: true,
                }),
                audit: None,
                tiles,
                time_report,
                trace_json,
                verify_report,
                // M79: the ladder's replay serves no provenance (the
                // fusion lane's request is refused at the wire — the
                // replay's Pass-2 product is the record's, not the
                // walk's).
                provenance: None,
                // M87: the ladder's replay serves its own map — the walk
                // ran the full Passes 1–3, so `result.layout` is the
                // replay's own Pass-3 product and the same pure function
                // the cold lane's `-map` calls renders it (the v46 tail
                // carries the document verbatim; the untouched walk
                // re-derived the placed image, the document says so).
                map_text: req.map.then(|| {
                    pgr_core::map::build_link_map(&result.layout, &result.interner).render()
                }),
            });
        }
        let patch_started = std::time::Instant::now();
        let (mut outcome, mut new_record, mut image) = pgr_emit::incremental::apply_patch_bytes(
            prev,
            record,
            &plan,
            &result.layout,
            &result.objects,
            result.resolve_snapshot.clone(),
        )
        .map_err(|e| match e {
            pgr_emit::incremental::PatchError::Fallback(_) => RelinkDecline::Fallback,
            other => RelinkDecline::Error(other.into()),
        })?;
        Self::report_rung(
            req,
            &mut time_collector,
            &mut traces,
            pgr_core::observe::Phase::RelinkPatch,
            pgr_core::observe::PhaseDetail::Patch {
                bytes: outcome.bytes_patched,
                tiles: usize::try_from(outcome.dirty_tiles).unwrap_or(usize::MAX),
            },
            patch_started.elapsed(),
        );
        let _span = tracing::info_span!(
            "daemon_relink",
            bytes_patched = outcome.bytes_patched,
            dirty_tiles = outcome.dirty_tiles,
            total_tiles = outcome.total_tiles
        )
        .entered();
        // The audited relink (v4, M9 GA rung 2): the §7.3 gate's
        // bytes-level twin runs here, in memory — identity against the
        // reference emit first, the strict verifier second, and a
        // divergence is healed from the reference before the verdict
        // crosses the wire. The client still owns the file: a failing
        // verdict ships nothing (§7.2 crash-safety unchanged).
        let audit = if req.audit {
            let audit_started = std::time::Instant::now();
            let reference = pgr_emit::build_image_fused(&result.layout, &result.objects)
                .map_err(SessionError::Emit)
                .map_err(RelinkDecline::Error)?;
            let identity_ok = audit_patch(&reference, &image);
            let healed = !identity_ok;
            if healed {
                // A divergence never ships: serve the reference emit and
                // re-record from it (the driver's file-path heal, in
                // memory).
                new_record = pgr_emit::incremental::LinkRecord::record(
                    &result.layout,
                    &result.objects,
                    &reference,
                    result.resolve_snapshot.as_ref(),
                )
                .map_err(|e| match e {
                    pgr_emit::incremental::PatchError::Fallback(_) => RelinkDecline::Fallback,
                    other => RelinkDecline::Error(other.into()),
                })?;
                image = reference;
                outcome.bytes_patched = image.len() as u64;
                outcome.dirty_tiles = plan.total_tiles;
            }
            let verify_blocking = audit_image(&image, !cfg.adhoc);
            tracing::debug!(
                identity_ok,
                healed,
                blocking = verify_blocking.len(),
                "the daemon's audit finished"
            );
            Self::report_rung(
                req,
                &mut time_collector,
                &mut traces,
                pgr_core::observe::Phase::RelinkAudit,
                pgr_core::observe::PhaseDetail::Audit {
                    healed,
                    issues: verify_blocking.len(),
                },
                audit_started.elapsed(),
            );
            Some(AuditOutcome {
                identity_ok,
                healed,
                verify_blocking,
            })
        } else {
            None
        };
        // The §7.2 rung (v5): a tiles-asking client receives the changed
        // 16 KiB tiles (plus the patched image's hash as its replay gate)
        // instead of the whole image — the resident session held the
        // previous output, so the warm cycle moves only the change.
        // Computed after the audit: a healed image (the reference emit)
        // is what ships, so the stream must diff against it.
        let tiles = req
            .tiles
            .then(|| pgr_emit::incremental::diff_tiles(prev, &image));
        let time_report = req.time.then(|| {
            let mut report = time_collector.report();
            report.total = Some(started.elapsed());
            report
        });
        let trace_json = req.trace.then(|| traces.finish().render());
        // M72: the verdict's subject is the image the reply serves —
        // computed after the audit's heal, so a healed image is what the
        // verdict answers for (the audit's ordering, mirrored).
        let verify_report = req
            .verify
            .then(|| serve_verify(&image, cfg.adhoc, req.verify_checks.as_ref()));
        Ok(ServedLink {
            image,
            entryoff: result.layout.entryoff,
            fixup_slots: u64::try_from(result.layout.fixups.slot_count).unwrap_or(u64::MAX),
            record: Some(new_record.encode()),
            patch: Some(outcome),
            audit,
            tiles,
            time_report,
            trace_json,
            verify_report,
            provenance: None,
            // M87: the patched replay serves its own map — the walk's
            // Pass-3 product is the layout the patch plan read, and the
            // same pure function the cold lane's `-map` calls renders
            // it (the v46 tail carries the document verbatim — the
            // placed image the reply's bytes carry, the report cannot
            // disagree with them).
            map_text: req
                .map
                .then(|| pgr_core::map::build_link_map(&result.layout, &result.interner).render()),
        })
    }

    /// Evicts least-recently-used entries until under the ceiling.
    fn enforce_limit(&mut self) {
        if self.max_bytes == 0 {
            return;
        }
        while self.bytes_held() > self.max_bytes {
            // Oldest POI frame first, then oldest blob; give up when
            // nothing is evictable.
            let oldest_poi = self
                .pois
                .iter()
                .min_by_key(|(_, (_, use_at))| *use_at)
                .map(|(k, _)| *k);
            let oldest_blob = self
                .blob_uses
                .iter()
                .min_by_key(|(_, use_at)| **use_at)
                .map(|(k, _)| *k);
            if let Some(key) = oldest_poi {
                self.pois.remove(&key);
                continue;
            }
            if let Some(hash) = oldest_blob {
                self.blobs.remove(&hash);
                self.blob_uses.remove(&hash);
                continue;
            }
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ResidentSession;
    use crate::protocol::{ArchiveEntry, InputEntry, LinkRequest, content_hash};
    use pgr_core::layout::{LinkConfig, OutputType};
    use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

    fn hello_main() -> Vec<u8> {
        let text: Vec<u8> = [
            0x9000_0000u32, // adrp x0, _msg@page
            0x9100_0000u32, // add x0, x0, #_msg@pageoff
            0x9400_0000u32, // bl _greet
            0x5280_0000u32, // mov w0, #0
            0xD65F_03C0u32, // ret
        ]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
        let mut b = ObjectBuilder::new("hello.o");
        let sect = b.add_section(ObjectSection::text(
            "__text",
            text,
            vec![
                ObjectReloc::addend(0).at(0),
                ObjectReloc::page21(1).at(0),
                ObjectReloc::addend(0).at(4),
                ObjectReloc::pageoff12(1).at(4),
                ObjectReloc::branch26(2).at(8),
            ],
        ));
        b.add_section(ObjectSection::cstring("hello, peregrine\n"));
        b.add_symbol(ObjectSymbol::Defined {
            name: "_main".into(),
            section_index: sect,
            value: 0,
            weak: false,
        });
        b.add_symbol(ObjectSymbol::Defined {
            name: "_msg".into(),
            section_index: 1,
            value: 0,
            weak: false,
        });
        b.add_symbol(ObjectSymbol::Undefined {
            name: "_greet".into(),
            weak_ref: false,
        });
        b.build().unwrap()
    }

    fn greet() -> Vec<u8> {
        greet_variant(0)
    }

    /// Two byte-distinct, both-valid versions of greet.o (the edit loop's
    /// "changed input").
    fn greet_variant(addend: u8) -> Vec<u8> {
        let mut b = ObjectBuilder::new("greet.o");
        let text = b.add_section(ObjectSection::text(
            "__text",
            vec![0x91, addend, 0x00, 0x00, 0xC0, 0x03, 0x5F, 0xD6],
            vec![],
        ));
        b.add_symbol(ObjectSymbol::Defined {
            name: "_greet".into(),
            section_index: text,
            value: 0,
            weak: false,
        });
        b.build().unwrap()
    }

    fn request(hello: &[u8], greet_bytes: &[u8]) -> (LinkRequest, Vec<[u8; 32]>) {
        let req = LinkRequest {
            config: LinkConfig {
                ident: "session-test".into(),
                filetype: OutputType::Execute,
                ..LinkConfig::default()
            },
            force_load: Vec::new(),
            inputs: vec![
                InputEntry {
                    name: "hello.o".into(),
                    hash: content_hash(hello),
                },
                InputEntry {
                    name: "greet.o".into(),
                    hash: content_hash(greet_bytes),
                },
            ],
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
        };
        (req.clone(), req.blob_hashes())
    }

    #[test]
    fn cold_then_warm_session_is_byte_identical() {
        let hello = hello_main();
        let greet_bytes = greet();
        let (req, hashes) = request(&hello, &greet_bytes);
        let mut session = ResidentSession::default();
        for h in &hashes {
            let bytes = if *h == content_hash(&hello) {
                hello.clone()
            } else {
                greet_bytes.clone()
            };
            session.store_blob(h, bytes).unwrap();
        }

        let cold = session.link(&req).unwrap();
        let (entryoff, slots) = (cold.entryoff, cold.fixup_slots);
        let cold = cold.image;
        assert_eq!((session.hits, session.misses), (0, 2));
        assert!(entryoff > 0, "executables carry an entry point");
        let _ = slots;

        let warm = session.link(&req).unwrap();
        let (entryoff2, slots2) = (warm.entryoff, warm.fixup_slots);
        let warm = warm.image;
        assert_eq!(
            (session.hits, session.misses),
            (2, 2),
            "warm relink hits both POIs"
        );
        assert_eq!(
            cold, warm,
            "resident output is a pure function of the inputs"
        );
        assert_eq!((entryoff, slots), (entryoff2, slots2));

        // One-shot parity: the same bytes come out of the plain driver path.
        let inputs: Vec<pgr_core::LinkInput> = vec![
            pgr_core::LinkInput {
                name: "hello.o".into(),
                bytes: hello.clone(),
            },
            pgr_core::LinkInput {
                name: "greet.o".into(),
                bytes: greet_bytes.clone(),
            },
        ];
        let cfg = LinkConfig {
            ident: "session-test".into(),
            filetype: OutputType::Execute,
            ..LinkConfig::default()
        };
        let one_shot =
            pgr_core::link_cached(&inputs, &[], &cfg, pgr_core::Parallelism::Auto, None).unwrap();
        let image = pgr_emit::build_image_fused(&one_shot.layout, &one_shot.objects).unwrap();
        assert_eq!(image, cold, "session link == one-shot link, byte for byte");
    }

    #[test]
    fn changed_input_reuses_the_unchanged_poi() {
        let hello = hello_main();
        let greet_bytes = greet();
        let (req, hashes) = request(&hello, &greet_bytes);
        let mut session = ResidentSession::default();
        for h in &hashes {
            let bytes = if *h == content_hash(&hello) {
                hello.clone()
            } else {
                greet_bytes.clone()
            };
            session.store_blob(h, bytes).unwrap();
        }
        session.link(&req).unwrap();

        // Edit greet.o's bytes (a valid second build): hello's POI must
        // still hit.
        let edited = greet_variant(8);
        let new_greet_hash = content_hash(&edited);
        session.store_blob(&new_greet_hash, edited).unwrap();
        let mut req2 = req.clone();
        req2.inputs[1].hash = new_greet_hash;
        session.link(&req2).unwrap();
        // hello hit (its POI survived), greet re-parsed (new bytes).
        assert_eq!((session.hits, session.misses), (1, 3));
    }

    #[test]
    fn missing_blob_is_an_error_not_a_crash() {
        let hello = hello_main();
        let greet_bytes = greet();
        let (req, _hashes) = request(&hello, &greet_bytes);
        let mut session = ResidentSession::default();
        // Only hello.o's bytes arrive: greet.o's hash stays missing.
        session.store_blob(&content_hash(&hello), hello).unwrap();
        let err = session.link(&req).unwrap_err();
        assert!(matches!(err, super::SessionError::MissingBlob(_)), "{err}");
    }

    #[test]
    fn hash_mismatch_is_refused() {
        let mut session = ResidentSession::default();
        let err = session.store_blob(&content_hash(b"expected"), b"actual".to_vec());
        assert!(matches!(err, Err(super::SessionError::HashMismatch(_))));
    }

    #[test]
    fn memory_ceiling_evicts_lru() {
        let mut session = ResidentSession::with_limit(64 * 1024);
        let hello = hello_main();
        let greet_bytes = greet();
        let (req, hashes) = request(&hello, &greet_bytes);
        for h in &hashes {
            let bytes = if *h == content_hash(&hello) {
                hello.clone()
            } else {
                greet_bytes.clone()
            };
            session.store_blob(h, bytes).unwrap();
        }
        session.link(&req).unwrap();
        let after_link = session.bytes_held();
        assert!(after_link > 0);

        // Shrink the ceiling: the next store evicts down to the bound.
        session.max_bytes = 16 * 1024;
        let filler = vec![0xAB; 4096];
        session.store_blob(&content_hash(&filler), filler).unwrap();
        assert!(
            session.bytes_held() <= 16 * 1024 + 4096,
            "held {} after eviction",
            session.bytes_held()
        );
        // The session still links correctly after eviction (a re-parse
        // repopulates what it needs). The §7.2 rung stores every served
        // image as resident output, so a tight ceiling evicts input blobs
        // too — the client's BLOB negotiation simply re-uploads them, the
        // same store this test replays.
        session.store_blob(&content_hash(&hello), hello).unwrap();
        session
            .store_blob(&content_hash(&greet_bytes), greet_bytes)
            .unwrap();
        let image = session.link(&req).unwrap().image;
        assert!(!image.is_empty(), "image built");
    }

    #[test]
    fn scratch_buffer_is_reused_across_links() {
        let hello = hello_main();
        let greet_bytes = greet();
        let (req, hashes) = request(&hello, &greet_bytes);
        let mut session = ResidentSession::default();
        for h in &hashes {
            let bytes = if *h == content_hash(&hello) {
                hello.clone()
            } else {
                greet_bytes.clone()
            };
            session.store_blob(h, bytes).unwrap();
        }
        session.link(&req).unwrap();
        let second = session.link(&req).unwrap();
        assert_eq!(session.scratch.capacity(), second.image.len());
        // Same capacity object across calls == reuse (the page-fault gate's
        // observable).
    }

    #[test]
    fn archive_inputs_link_through_the_session() {
        let hello = hello_main_only();
        let greet = greet();
        let mut archive = pgr_fixtures::ArchiveBuilder::new("libutil.a");
        archive.add_member("greet.o", greet);
        let archive_bytes = archive.build();
        let req = LinkRequest {
            config: LinkConfig {
                ident: "session-archive".into(),
                ..LinkConfig::default()
            },
            force_load: Vec::new(),
            inputs: vec![InputEntry {
                name: "hello.o".into(),
                hash: content_hash(&hello),
            }],
            archives: vec![ArchiveEntry {
                name: "libutil.a".into(),
                all_load: false,
                hash: content_hash(&archive_bytes),
            }],
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
        };
        let mut session = ResidentSession::default();
        session.store_blob(&content_hash(&hello), hello).unwrap();
        session
            .store_blob(&content_hash(&archive_bytes), archive_bytes)
            .unwrap();
        let image1 = session.link(&req).unwrap().image;
        let image2 = session.link(&req).unwrap().image;
        assert_eq!(image1, image2);
        assert!(!image1.is_empty(), "image built");
    }

    #[test]
    fn the_served_provenance_queries_ride_the_link() {
        // v45 (M79): a query-asking request serves the answers the
        // session's own Pass-2 product renders — the `-why_export`
        // answer naming the resolution's winner and every reference
        // site, the `-why_load` report naming the pulled member — and
        // an unasked query rides nothing (the tail is one byte).
        let hello = hello_main_only();
        let greet = greet();
        let mut archive = pgr_fixtures::ArchiveBuilder::new("libutil.a");
        archive.add_member("greet.o", greet);
        let archive_bytes = archive.build();
        let req = LinkRequest {
            config: LinkConfig {
                ident: "session-provenance".into(),
                ..LinkConfig::default()
            },
            force_load: Vec::new(),
            inputs: vec![InputEntry {
                name: "hello.o".into(),
                hash: content_hash(&hello),
            }],
            archives: vec![ArchiveEntry {
                name: "libutil.a".into(),
                all_load: false,
                hash: content_hash(&archive_bytes),
            }],
            record: None,
            record_resolution: false,
            prev_output: None,
            audit: false,
            tiles: false,
            time: false,
            trace: false,
            verify: false,
            verify_checks: None,
            why_export: vec!["_greet".to_string()],
            why_load: true,
            map: false,
        };
        let mut session = ResidentSession::default();
        session.store_blob(&content_hash(&hello), hello).unwrap();
        session
            .store_blob(&content_hash(&archive_bytes), archive_bytes)
            .unwrap();
        let served = session.link(&req).unwrap();
        let prov = served
            .provenance
            .expect("the asked queries serve their answers");
        assert_eq!(prov.exports.len(), 1, "one answer per query, in order");
        assert_eq!(prov.exports[0].name, "_greet");
        assert!(
            prov.exports[0].render.contains("_greet") && prov.exports[0].render.contains("greet.o"),
            "the answer names the definition and its file: {}",
            prov.exports[0].render
        );
        let loads = prov.loads.expect("the asked load report serves");
        assert!(
            loads.contains("libutil.a") && loads.contains("greet.o"),
            "the report names the pulled member: {loads}"
        );
        // An unasked query rides nothing (the pre-M79 shape).
        let mut quiet = req.clone();
        quiet.why_export.clear();
        quiet.why_load = false;
        let quiet_served = session.link(&quiet).unwrap();
        assert!(quiet_served.provenance.is_none());
    }

    #[test]
    fn a_vacuous_query_refuses_the_served_link() {
        // The vacuous decision is the cold lane's own refusal (the
        // misspelling named, never silently empty): the session errors,
        // the reply is the TAG_ERROR the client's one-shot fallback
        // reproduces — the same refusal either lane.
        let hello = hello_main_only();
        let greet = greet();
        let req = LinkRequest {
            config: LinkConfig {
                ident: "session-provenance-miss".into(),
                ..LinkConfig::default()
            },
            force_load: Vec::new(),
            inputs: vec![
                InputEntry {
                    name: "hello.o".into(),
                    hash: content_hash(&hello),
                },
                InputEntry {
                    name: "greet.o".into(),
                    hash: content_hash(&greet),
                },
            ],
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
            why_export: vec!["_nope".to_string()],
            why_load: false,
            map: false,
        };
        let mut session = ResidentSession::default();
        session.store_blob(&content_hash(&hello), hello).unwrap();
        session.store_blob(&content_hash(&greet), greet).unwrap();
        let err = session.link(&req).unwrap_err();
        assert!(
            err.to_string().contains("_nope"),
            "the refusal names the misspelling: {err}"
        );
    }

    fn hello_main_only() -> Vec<u8> {
        let text: Vec<u8> = [
            0x9000_0000u32,
            0x9100_0000u32,
            0x9400_0000u32,
            0x5280_0000u32,
            0xD65F_03C0u32,
        ]
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .collect();
        let mut b = ObjectBuilder::new("hello.o");
        let sect = b.add_section(ObjectSection::text(
            "__text",
            text,
            vec![ObjectReloc::branch26(1).at(8)],
        ));
        b.add_symbol(ObjectSymbol::Defined {
            name: "_main".into(),
            section_index: sect,
            value: 0,
            weak: false,
        });
        b.add_symbol(ObjectSymbol::Undefined {
            name: "_greet".into(),
            weak_ref: false,
        });
        b.build().unwrap()
    }
}

// ---- M9 GA: the fusion ladder inside the session ---------------------------
//
// A record-bearing request runs §7.3 inside the daemon: integrity gate on
// the transferred previous output, the anchored relink config (the record
// is the single cross-link carrier), the warm pipeline, the patch plan,
// and the in-memory patch. Any refusal falls back to the clean full link,
// which captures when asked — the rung that keeps the incremental cycle
// alive through daemon fallbacks.

#[cfg(test)]
mod fusion_tests {
    use super::ResidentSession;
    use crate::protocol::{
        InputEntry, LinkRequest, Reader, content_hash, decode_time_report, encode_time_report,
    };
    use pgr_core::layout::{LinkConfig, OutputType};
    use pgr_core::link::{LinkInput, Parallelism, link_cached};
    use pgr_core::slack::SlackAnchor;
    use pgr_emit::build_image_fused;
    use pgr_emit::incremental::LinkRecord;
    use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

    /// hello.o: `_main` ADRP+ADD loads `_msg`, BL `_greet`, ret (the M8
    /// session fixture's shape).
    fn hello(body_flip: bool) -> Vec<u8> {
        let mut words: Vec<u32> = vec![
            0x9000_0000, // adrp x0, _msg@page
            0x9100_0000, // add x0, x0, #_msg@pageoff
            0x9400_0000, // bl _greet
            0x5280_0000, // mov w0, #0 (flipped: #1)
            0xD65F_03C0, // ret
        ];
        if body_flip {
            words[3] = 0x5280_0020;
        }
        let text: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let mut b = ObjectBuilder::new("hello.o");
        let sect = b.add_section(ObjectSection::text(
            "__text",
            text,
            vec![
                ObjectReloc::addend(0).at(0),
                ObjectReloc::page21(1).at(0),
                ObjectReloc::addend(0).at(4),
                ObjectReloc::pageoff12(1).at(4),
                ObjectReloc::branch26(2).at(8),
            ],
        ));
        b.add_section(ObjectSection::cstring(if body_flip {
            "merci, peregrine\n"
        } else {
            "hello, peregrine\n"
        }));
        b.add_symbol(ObjectSymbol::Defined {
            name: "_main".into(),
            section_index: sect,
            value: 0,
            weak: false,
        });
        b.add_symbol(ObjectSymbol::Defined {
            name: "_msg".into(),
            section_index: 1,
            value: 0,
            weak: false,
        });
        b.add_symbol(ObjectSymbol::Undefined {
            name: "_greet".into(),
            weak_ref: false,
        });
        b.build().unwrap()
    }

    /// greet.o at a tunable text size (the structural edit grows it far
    /// past every ladder bound).
    fn greet(text_bytes: usize) -> Vec<u8> {
        let mut b = ObjectBuilder::new("greet.o");
        let mut words: Vec<u32> = vec![0xC0, 0x03, 0x5F, 0xD6]; // ret
        words.resize(text_bytes / 4, 0xD503_201F); // nop padding
        let text: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let sect = b.add_section(ObjectSection::text("__text", text, Vec::new()));
        b.add_symbol(ObjectSymbol::Defined {
            name: "_greet".into(),
            section_index: sect,
            value: 0,
            weak: false,
        });
        b.build().unwrap()
    }

    fn link_config() -> LinkConfig {
        LinkConfig {
            ident: "fusion-test".into(),
            filetype: OutputType::Execute,
            // The in-place tier stands on the slack anchors; `-incremental`
            // implies slack for the whole cycle (the driver does the same).
            layout_slack: Some(pgr_core::slack::SlackPolicy::default()),
            ..LinkConfig::default()
        }
    }

    fn request(
        cfg: &LinkConfig,
        hello_bytes: &[u8],
        greet_bytes: &[u8],
    ) -> (LinkRequest, Vec<[u8; 32]>) {
        let req = LinkRequest {
            config: cfg.clone(),
            force_load: Vec::new(),
            inputs: vec![
                InputEntry {
                    name: "hello.o".into(),
                    hash: content_hash(hello_bytes),
                },
                InputEntry {
                    name: "greet.o".into(),
                    hash: content_hash(greet_bytes),
                },
            ],
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
        };
        let hashes = req.blob_hashes();
        (req, hashes)
    }

    fn store(session: &mut ResidentSession, hashes: &[([u8; 32], Vec<u8>)]) {
        for (h, bytes) in hashes {
            session.store_blob(h, bytes.clone()).unwrap();
        }
    }

    /// The in-process reference for the daemon's ladder: the anchored
    /// config assembled from the record (the driver's exact mirror), the
    /// plain pipeline, and the full fused emit of the relink plan — the
    /// patched bytes must equal it byte for byte.
    fn fused_reference(record: &LinkRecord, hello_bytes: &[u8], greet_bytes: &[u8]) -> Vec<u8> {
        let mut cfg = link_config();
        cfg.slack_anchor = record
            .sections
            .iter()
            .map(|s| SlackAnchor {
                seg: s.seg.clone(),
                name: s.name.clone(),
                padded: s.size,
            })
            .collect();
        cfg.stable_imports = Some(record.imports.clone());
        cfg.sig_anchor = (record.linkedit.sig_off > 0).then_some(record.linkedit.sig_off);
        cfg.record_resolution = true;
        if let Some(resolution) = &record.resolution {
            cfg.resolve_reuse = Some(pgr_core::resolve_reuse::ResolveReuseSeed {
                snapshot: resolution.clone(),
                digests: record.section_digests.clone(),
            });
        }
        let inputs = vec![
            LinkInput {
                name: "hello.o".into(),
                bytes: hello_bytes.to_vec(),
            },
            LinkInput {
                name: "greet.o".into(),
                bytes: greet_bytes.to_vec(),
            },
        ];
        let result = link_cached(&inputs, &[], &cfg, Parallelism::Auto, None).unwrap();
        build_image_fused(&result.layout, &result.objects).unwrap()
    }

    #[test]
    fn full_link_captures_the_record_only_when_asked() {
        let hello_bytes = hello(false);
        let greet_bytes = greet(16);
        let (mut req, hashes) = request(&link_config(), &hello_bytes, &greet_bytes);
        let mut session = ResidentSession::default();
        store(
            &mut session,
            &hashes
                .into_iter()
                .zip([hello_bytes.clone(), greet_bytes.clone()])
                .collect::<Vec<_>>(),
        );

        req.record_resolution = true;
        let served = session.link(&req).unwrap();
        assert!(served.patch.is_none(), "a full link never reports a patch");
        let record_bytes = served.record.expect("capture was requested");
        let record = LinkRecord::decode(&record_bytes).expect("the fresh record decodes");
        assert_eq!(record.file_size, served.image.len() as u64);

        // Without the flag (the plain M8 resident link) no record rides.
        req.record_resolution = false;
        let plain = session.link(&req).unwrap();
        assert!(plain.record.is_none(), "no capture, no record");
        assert_eq!(plain.image, served.image, "bytes unchanged by the flag");
    }

    #[test]
    fn record_bearing_relink_patches_through_the_session() {
        let hello_bytes = hello(false);
        let greet_bytes = greet(16);
        let (mut req, hashes) = request(&link_config(), &hello_bytes, &greet_bytes);
        let mut session = ResidentSession::default();
        store(
            &mut session,
            &hashes
                .into_iter()
                .zip([hello_bytes.clone(), greet_bytes.clone()])
                .collect::<Vec<_>>(),
        );

        req.record_resolution = true;
        let cold = session.link(&req).unwrap();
        let record_bytes = cold.record.clone().expect("cold capture");
        let prev_output = cold.image.clone();

        // The edit: hello.o's body flips (equal-size, a one-function edit).
        let edited_hello = hello(true);
        let (mut relink, _) = request(&link_config(), &edited_hello, &greet_bytes);
        relink.record = Some(record_bytes.clone());
        relink.prev_output = Some(content_hash(&prev_output));
        // The previous output's bytes ride the BLOB exchange (the server
        // level negotiation; here the test stores them directly).
        session
            .store_blob(&content_hash(&prev_output), prev_output.clone())
            .unwrap();
        // hello.o's bytes ride again (its content hash changed).
        session
            .store_blob(&content_hash(&edited_hello), edited_hello.clone())
            .unwrap();

        let warm_hits = session.hits;
        let served = session.link(&relink).unwrap();
        let outcome = served.patch.expect("the ladder patches in place");
        assert!(!outcome.untouched);
        assert!(
            outcome.bytes_patched < prev_output.len() as u64,
            "a one-function edit patches a fraction of the image"
        );
        // The engine's contract at the wire: the patched image is
        // byte-identical to the full fused emit of the same (anchored)
        // plan — computed here through the plain in-process pipeline.
        let record = LinkRecord::decode(&record_bytes).unwrap();
        assert_eq!(
            served.image,
            fused_reference(&record, &edited_hello, &greet_bytes),
            "the daemon's patch matches the in-process fused emit"
        );
        // The refreshed record describes the new state.
        let renewed = LinkRecord::decode(served.record.as_ref().unwrap()).unwrap();
        assert_eq!(renewed.file_size, served.image.len() as u64);
        // The session's POIs served the pipeline (hello re-parsed as a
        // miss on the edit; greet's frame hit — warm).
        assert!(
            session.hits > warm_hits,
            "the warm session decoded POIs, hits {} -> {}",
            warm_hits,
            session.hits
        );
    }

    /// The in-process reference for the ladder's map: the anchored
    /// config assembled from the record (the driver's exact mirror),
    /// the plain pipeline's Pass-3 product, and
    /// [`pgr_core::map::build_link_map`] over it — the served map must
    /// equal it byte for byte.
    fn map_reference(record: &LinkRecord, hello_bytes: &[u8], greet_bytes: &[u8]) -> String {
        let mut cfg = link_config();
        cfg.slack_anchor = record
            .sections
            .iter()
            .map(|s| SlackAnchor {
                seg: s.seg.clone(),
                name: s.name.clone(),
                padded: s.size,
            })
            .collect();
        cfg.stable_imports = Some(record.imports.clone());
        cfg.sig_anchor = (record.linkedit.sig_off > 0).then_some(record.linkedit.sig_off);
        cfg.record_resolution = true;
        if let Some(resolution) = &record.resolution {
            cfg.resolve_reuse = Some(pgr_core::resolve_reuse::ResolveReuseSeed {
                snapshot: resolution.clone(),
                digests: record.section_digests.clone(),
            });
        }
        let inputs = vec![
            LinkInput {
                name: "hello.o".into(),
                bytes: hello_bytes.to_vec(),
            },
            LinkInput {
                name: "greet.o".into(),
                bytes: greet_bytes.to_vec(),
            },
        ];
        let result = link_cached(&inputs, &[], &cfg, Parallelism::Auto, None).unwrap();
        pgr_core::map::build_link_map(&result.layout, &result.interner).render()
    }

    #[test]
    fn the_fusion_ladder_serves_its_own_map() {
        // M87: the map renders from the ladder's own walk — the session's
        // relink runs the full Passes 1–3, so `result.layout` is the
        // walk's Pass-3 product and the v46 tail carries the document
        // verbatim (the M80 convention: the wire never re-shapes the
        // face the client writes). The patched exit and the untouched
        // one both answer; a map the session never planned is the only
        // thing it never serves.
        let hello_bytes = hello(false);
        let greet_bytes = greet(16);
        let (mut req, hashes) = request(&link_config(), &hello_bytes, &greet_bytes);
        req.record_resolution = true;
        req.map = true;
        let mut session = ResidentSession::default();
        store(
            &mut session,
            &hashes
                .into_iter()
                .zip([hello_bytes.clone(), greet_bytes.clone()])
                .collect::<Vec<_>>(),
        );

        let cold = session.link(&req).unwrap();
        let cold_map = cold
            .map_text
            .expect("the served map rides the full link's v46 tail");
        assert!(
            cold_map.contains("__TEXT") && cold_map.contains("__LINKEDIT"),
            "the full link's map names the placed segments"
        );
        let record_bytes = cold.record.clone().expect("the cold capture");
        let prev_image = cold.image.clone();

        // The patched relink asks too: the document is the ladder's own
        // Pass-3 product (the anchored relayout), byte-identical to the
        // in-process render over the same anchored plan — never the
        // previous link's document.
        let edited_hello = hello(true);
        let (mut relink, _) = request(&link_config(), &edited_hello, &greet_bytes);
        relink.record = Some(record_bytes.clone());
        relink.prev_output = Some(content_hash(&prev_image));
        relink.map = true;
        session
            .store_blob(&content_hash(&prev_image), prev_image)
            .unwrap();
        session
            .store_blob(&content_hash(&edited_hello), edited_hello.clone())
            .unwrap();
        let served = session.link(&relink).unwrap();
        assert!(
            !served.patch.expect("the ladder patches in place").untouched,
            "the edit patches"
        );
        let map = served
            .map_text
            .expect("the patched relink serves its own map");
        let record = LinkRecord::decode(&record_bytes).unwrap();
        assert_eq!(
            map,
            map_reference(&record, &edited_hello, &greet_bytes),
            "either ladder, one walk, one document"
        );

        // The untouched relink asks too — the walk ran, the document is
        // the same placed image re-derived (nothing moved).
        let (mut again, _) = request(&link_config(), &edited_hello, &greet_bytes);
        again.record = served.record.clone();
        again.prev_output = Some(content_hash(&served.image));
        again.map = true;
        session
            .store_blob(&content_hash(&served.image), served.image.clone())
            .unwrap();
        let warm = session.link(&again).unwrap();
        assert!(
            warm.patch.as_ref().expect("the relink plans").untouched,
            "an identical corpus relinks untouched"
        );
        let warm_map = warm
            .map_text
            .expect("the untouched relink serves its own map");
        assert_eq!(
            warm_map, map,
            "the untouched walk re-derived the same document"
        );
    }

    #[test]
    fn served_verify_verdict_rides_every_outcome() {
        // v43 (M72): the strict verifier runs inside the session on the
        // final bytes — the full link's, the untouched relink's alike —
        // and the report crosses as the reply's tail. Unasked, the tail
        // rides absent (nothing moves).
        let hello_bytes = hello(false);
        let greet_bytes = greet(16);
        let (mut req, hashes) = request(&link_config(), &hello_bytes, &greet_bytes);
        req.record_resolution = true;
        req.verify = true;
        let mut session = ResidentSession::default();
        store(
            &mut session,
            &hashes
                .into_iter()
                .zip([hello_bytes.clone(), greet_bytes.clone()])
                .collect::<Vec<_>>(),
        );

        let cold = session.link(&req).unwrap();
        let verdict = cold
            .verify_report
            .expect("the served verdict rides the full link");
        assert!(
            verdict.is_ok(&pgr_verify::Options::default()),
            "the clean link verifies: {:?}",
            verdict.issues
        );
        assert!(verdict.stats.segments > 0, "the stats ride the verdict");

        // The untouched relink asks too — its subject is the resident
        // previous output (nothing changed, the verdict says so again).
        let prev_output = cold.image.clone();
        let (mut relink, _) = request(&link_config(), &hello_bytes, &greet_bytes);
        relink.record = Some(cold.record.expect("the cold capture"));
        relink.prev_output = Some(content_hash(&prev_output));
        relink.verify = true;
        session
            .store_blob(&content_hash(&prev_output), prev_output)
            .unwrap();
        let warm = session.link(&relink).unwrap();
        assert!(
            warm.patch.as_ref().expect("the relink plans").untouched,
            "an identical corpus relinks untouched"
        );
        let warm_verdict = warm
            .verify_report
            .expect("the untouched relink serves its verdict");
        assert!(warm_verdict.is_ok(&pgr_verify::Options::default()));

        // Unasked, the verdict never crosses.
        relink.verify = false;
        let plain = session.link(&relink).unwrap();
        assert!(
            plain.verify_report.is_none(),
            "an unasked verdict rides absent"
        );
    }

    #[test]
    fn the_no_adhoc_carve_out_excuses_only_the_signature() {
        // M72: a `-no_adhoc` link has no signature to verify — the
        // missing-signature shape is the config's own choice, never a
        // defect the served verdict names (the audit's carve-out,
        // mirrored). Everything else gates at full strictness.
        let mut report = pgr_verify::Report::default();
        report.issues.push(pgr_verify::Issue::error(
            pgr_verify::Code::SignatureLayout,
            "arm64 images require an ad-hoc code signature",
            Some(0),
        ));
        report.issues.push(pgr_verify::Issue::error(
            pgr_verify::Code::SegmentContract,
            "the vmaddr breaks the 16 KiB congruence",
            Some(4096),
        ));
        report.stats.segments = 2;
        // A signed link's verdict names every defect.
        let signed = super::effective_report(report.clone(), true);
        assert_eq!(signed.issues.len(), 2);
        // A `-no_adhoc` link's verdict excuses the missing signature —
        // and nothing else; the stats ride unfiltered.
        let unsigned = super::effective_report(report, false);
        assert_eq!(unsigned.issues.len(), 1);
        assert_eq!(unsigned.issues[0].code, pgr_verify::Code::SegmentContract);
        assert_eq!(unsigned.stats.segments, 2);
    }

    #[test]
    fn unchanged_relink_through_the_session_is_untouched() {
        let hello_bytes = hello(false);
        let greet_bytes = greet(16);
        let (mut req, hashes) = request(&link_config(), &hello_bytes, &greet_bytes);
        let mut session = ResidentSession::default();
        store(
            &mut session,
            &hashes
                .into_iter()
                .zip([hello_bytes.clone(), greet_bytes.clone()])
                .collect::<Vec<_>>(),
        );
        req.record_resolution = true;
        let cold = session.link(&req).unwrap();

        let mut relink = req.clone();
        relink.record = Some(cold.record.clone().unwrap());
        relink.prev_output = Some(content_hash(&cold.image));
        session
            .store_blob(&content_hash(&cold.image), cold.image.clone())
            .unwrap();
        let served = session.link(&relink).unwrap();
        let outcome = served.patch.expect("the ladder runs");
        assert!(outcome.untouched, "nothing changed, nothing patched");
        assert_eq!(served.image, cold.image, "the output rides back as-is");
    }

    #[test]
    fn stale_previous_output_falls_back_to_the_full_link() {
        let hello_bytes = hello(false);
        let greet_bytes = greet(16);
        let (mut req, hashes) = request(&link_config(), &hello_bytes, &greet_bytes);
        let mut session = ResidentSession::default();
        store(
            &mut session,
            &hashes
                .into_iter()
                .zip([hello_bytes.clone(), greet_bytes.clone()])
                .collect::<Vec<_>>(),
        );
        req.record_resolution = true;
        let cold = session.link(&req).unwrap();

        // The previous output changed under the record (a flipped page-0
        // byte): the ladder declines, the full link answers — and it still
        // captures, so the sidecar the driver stores stays fresh.
        let mut stale = cold.image.clone();
        stale[0] ^= 0xFF;
        let mut relink = req.clone();
        relink.record = Some(cold.record.clone().unwrap());
        relink.prev_output = Some(content_hash(&stale));
        session.store_blob(&content_hash(&stale), stale).unwrap();

        let served = session.link(&relink).unwrap();
        assert!(
            served.patch.is_none(),
            "a refusal is a full link, not a patch"
        );
        assert!(served.record.is_some(), "the full link still captures");
        let record = LinkRecord::decode(served.record.as_ref().unwrap()).unwrap();
        assert_eq!(
            served.image,
            fused_reference(&record, &hello_bytes, &greet_bytes),
            "the fallback full link matches the clean pipeline"
        );
    }

    #[test]
    fn structural_edit_falls_back_inside_the_daemon_and_still_captures() {
        let hello_bytes = hello(false);
        let greet_bytes = greet(16);
        let (mut req, hashes) = request(&link_config(), &hello_bytes, &greet_bytes);
        let mut session = ResidentSession::default();
        store(
            &mut session,
            &hashes
                .into_iter()
                .zip([hello_bytes.clone(), greet_bytes.clone()])
                .collect::<Vec<_>>(),
        );
        req.record_resolution = true;
        let cold = session.link(&req).unwrap();

        // The edit: greet.o grows by 2 MiB — far past every slack anchor
        // and the relayout tier's bound. The ladder declines; the full
        // link answers and captures the fresh record (the regression
        // gate: before the fusion rung the daemon returned no record and
        // the driver's incremental cycle died here).
        let grown = greet(2 * 1024 * 1024);
        let (mut relink, _) = request(&link_config(), &hello_bytes, &grown);
        relink.record = Some(cold.record.clone().unwrap());
        relink.record_resolution = true;
        relink.prev_output = Some(content_hash(&cold.image));
        session
            .store_blob(&content_hash(&grown), grown.clone())
            .unwrap();
        session
            .store_blob(&content_hash(&cold.image), cold.image.clone())
            .unwrap();

        let served = session.link(&relink).unwrap();
        assert!(served.patch.is_none(), "oversized growth is a full link");
        let record = LinkRecord::decode(served.record.as_ref().unwrap()).unwrap();
        assert_eq!(
            served.image,
            fused_reference(&record, &hello_bytes, &grown),
            "the fallback full link matches the clean pipeline"
        );

        // The cycle lives on: the next edit (body flip) patches again —
        // off the record the fallback just renewed.
        let edited = hello(true);
        let (mut next, _) = request(&link_config(), &edited, &grown);
        next.record = served.record.clone();
        next.record_resolution = true;
        next.prev_output = Some(content_hash(&served.image));
        session
            .store_blob(&content_hash(&edited), edited.clone())
            .unwrap();
        session
            .store_blob(&content_hash(&served.image), served.image.clone())
            .unwrap();
        let served2 = session.link(&next).unwrap();
        let outcome = served2.patch.expect("the renewed record patches again");
        assert!(!outcome.untouched);
        let renewed = LinkRecord::decode(served2.record.as_ref().unwrap()).unwrap();
        assert_eq!(
            served2.image,
            fused_reference(&renewed, &edited, &grown),
            "byte-identity across the fallback boundary"
        );
    }

    /// M9 GA rung 2: the daemon serves the `-incremental-verify` audit —
    /// the ladder patches, audits its bytes against the reference emit and
    /// hands the verdict across the wire (`AuditOutcome`).
    #[test]
    fn audited_relink_reports_the_audit_outcome() {
        let hello_bytes = hello(false);
        let greet_bytes = greet(16);
        let (mut req, hashes) = request(&link_config(), &hello_bytes, &greet_bytes);
        let mut session = ResidentSession::default();
        store(
            &mut session,
            &hashes
                .into_iter()
                .zip([hello_bytes.clone(), greet_bytes.clone()])
                .collect::<Vec<_>>(),
        );

        req.record_resolution = true;
        let cold = session.link(&req).unwrap();
        let record_bytes = cold.record.clone().expect("cold capture");
        let prev_output = cold.image.clone();

        let edited_hello = hello(true);
        let (mut relink, _) = request(&link_config(), &edited_hello, &greet_bytes);
        relink.record = Some(record_bytes.clone());
        relink.prev_output = Some(content_hash(&prev_output));
        relink.audit = true;
        session
            .store_blob(&content_hash(&prev_output), prev_output.clone())
            .unwrap();
        session
            .store_blob(&content_hash(&edited_hello), edited_hello.clone())
            .unwrap();

        let served = session.link(&relink).unwrap();
        let patch = served.patch.expect("the audited relink patches");
        assert!(!patch.untouched);
        let audit = served.audit.expect("the audit rides the reply");
        assert!(
            audit.identity_ok,
            "the engine contract holds on the wire path"
        );
        assert!(!audit.healed, "nothing to heal");
        assert!(
            audit.verify_blocking.is_empty(),
            "a clean patch verifies strict: {:?}",
            audit.verify_blocking
        );
        // The audited image IS the reference the contract demands: the
        // full fused emit of the same plan.
        let record = LinkRecord::decode(served.record.as_deref().unwrap()).unwrap();
        let reference = fused_reference(&record, &edited_hello, &greet_bytes);
        assert_eq!(
            reference, served.image,
            "the audited image is the reference"
        );
    }

    /// M66 (v42 in service): the session's ladder reports its rungs beside
    /// the warm pipeline — a time- and trace-asking relink's served report
    /// carries the gate, the plan, the patch and the audit in ladder order,
    /// the served timeline parses back through the strict reader with the
    /// rung rows riding it (the round-trip convention), and the report
    /// restores exactly through the v42 wire tail.
    #[test]
    fn the_ladder_rungs_ride_the_served_faces() {
        use pgr_core::observe::{Phase, PhaseDetail};
        let hello_bytes = hello(false);
        let greet_bytes = greet(16);
        let (mut req, hashes) = request(&link_config(), &hello_bytes, &greet_bytes);
        let mut session = ResidentSession::default();
        store(
            &mut session,
            &hashes
                .into_iter()
                .zip([hello_bytes.clone(), greet_bytes.clone()])
                .collect::<Vec<_>>(),
        );

        req.record_resolution = true;
        let cold = session.link(&req).unwrap();
        let record_bytes = cold.record.clone().expect("cold capture");
        let prev_output = cold.image.clone();

        let edited_hello = hello(true);
        let (mut relink, _) = request(&link_config(), &edited_hello, &greet_bytes);
        relink.record = Some(record_bytes.clone());
        relink.prev_output = Some(content_hash(&prev_output));
        relink.time = true;
        relink.trace = true;
        relink.audit = true;
        session
            .store_blob(&content_hash(&prev_output), prev_output.clone())
            .unwrap();
        session
            .store_blob(&content_hash(&edited_hello), edited_hello.clone())
            .unwrap();

        let served = session.link(&relink).unwrap();
        assert!(served.patch.expect("the relink patches").dirty_tiles > 0);
        let report = served.time_report.expect("the served report rides");
        let phases: Vec<Phase> = report.phases.iter().map(|e| e.phase).collect();
        let pos = |rung: Phase, names: &[Phase]| {
            names
                .iter()
                .position(|p| *p == rung)
                .unwrap_or_else(|| panic!("the {rung:?} row rides the served report: {names:?}"))
        };
        let gate = pos(Phase::RelinkGate, &phases);
        let plan = pos(Phase::RelinkPlan, &phases);
        let patch = pos(Phase::RelinkPatch, &phases);
        let audit = pos(Phase::RelinkAudit, &phases);
        assert!(
            gate < plan && plan < patch && patch < audit,
            "the rungs ride in ladder order: {phases:?}"
        );
        // The warm pipeline's rows ride between the gate and the plan —
        // and no Parse row rides the session's run (the parse was paid
        // when the edited blob arrived; the M59 served-report shape).
        assert!(phases.contains(&Phase::Layout) && !phases.contains(&Phase::Parse));
        // The audit row names its verdict (the clean patch's shape).
        assert!(matches!(
            report.phases[audit].detail,
            PhaseDetail::Audit {
                healed: false,
                issues: 0
            }
        ));
        // The served timeline is the strict reader's own face: it restores
        // exactly, the rung rows riding it.
        let json = served.trace_json.as_deref().expect("the timeline rides");
        let parsed = pgr_core::trace::parse_trace_json(json).expect("the served timeline parses");
        assert!(parsed.spans.iter().any(|s| s.phase == Phase::RelinkPatch));
        assert_eq!(
            pgr_core::trace::parse_trace_json(&parsed.render()).expect("the round trip parses"),
            parsed,
            "the round trip restores the data exactly"
        );
        // The report restores exactly through the v42 wire tail (the rung
        // vocabulary the codec registered at M65).
        let mut body = Vec::new();
        encode_time_report(&mut body, Some(&report));
        let mut r = Reader::new(&body);
        let back = decode_time_report(&mut r).expect("the tail decodes");
        r.done().expect("no trailing bytes");
        // The tail carries whole microseconds (the v40 shape): the
        // expected report is the served one with its walls floored to µs.
        let floor = |d: std::time::Duration| {
            std::time::Duration::from_micros(
                u64::try_from(d.as_nanos() / 1_000).unwrap_or(u64::MAX),
            )
        };
        let expected = pgr_core::time_report::TimeReport {
            phases: report
                .phases
                .iter()
                .map(|e| pgr_core::observe::PhaseEvent {
                    phase: e.phase,
                    detail: e.detail.clone(),
                    elapsed: floor(e.elapsed),
                })
                .collect(),
            emit: None,
            total: report.total.map(floor),
            notes: report.notes.clone(),
        };
        assert_eq!(back, Some(expected), "the tail restores the rungs exactly");
    }

    /// M66: an untouched relink's served report ends at the plan — no
    /// patch row rides a relink that patched nothing (the plan row names
    /// the empty dirty set).
    #[test]
    fn the_untouched_relinks_served_report_names_no_patch_row() {
        use pgr_core::observe::Phase;
        let hello_bytes = hello(false);
        let greet_bytes = greet(16);
        let (mut req, hashes) = request(&link_config(), &hello_bytes, &greet_bytes);
        let mut session = ResidentSession::default();
        store(
            &mut session,
            &hashes
                .into_iter()
                .zip([hello_bytes.clone(), greet_bytes.clone()])
                .collect::<Vec<_>>(),
        );

        req.record_resolution = true;
        let cold = session.link(&req).unwrap();
        let record_bytes = cold.record.clone().expect("cold capture");
        let prev_output = cold.image.clone();

        // No edit: the same inputs relink to the same plan.
        let (mut relink, _) = request(&link_config(), &hello_bytes, &greet_bytes);
        relink.record = Some(record_bytes.clone());
        relink.prev_output = Some(content_hash(&prev_output));
        relink.time = true;
        relink.trace = true;
        session
            .store_blob(&content_hash(&prev_output), prev_output.clone())
            .unwrap();

        let served = session.link(&relink).unwrap();
        assert!(
            served
                .patch
                .expect("the untouched relink answers")
                .untouched
        );
        let report = served.time_report.expect("the served report rides");
        let phases: Vec<Phase> = report.phases.iter().map(|e| e.phase).collect();
        assert!(
            phases.contains(&Phase::RelinkGate) && phases.contains(&Phase::RelinkPlan),
            "the gate and the plan ride: {phases:?}"
        );
        assert!(
            !phases.contains(&Phase::RelinkPatch),
            "no patch row rides a relink that patched nothing: {phases:?}"
        );
        let json = served.trace_json.as_deref().expect("the timeline rides");
        let parsed = pgr_core::trace::parse_trace_json(json).expect("the served timeline parses");
        assert!(
            !parsed.spans.iter().any(|s| s.phase == Phase::RelinkPatch),
            "no patch span rides the untouched timeline"
        );
    }

    /// The audit's subject is the patch: a full link (no record) and an
    /// untouched relink serve no audit — parity with the in-process gate,
    /// which runs after a patch only.
    #[test]
    fn audited_full_link_and_untouched_relink_serve_no_audit() {
        let hello_bytes = hello(false);
        let greet_bytes = greet(16);
        let (mut req, hashes) = request(&link_config(), &hello_bytes, &greet_bytes);
        let mut session = ResidentSession::default();
        store(
            &mut session,
            &hashes
                .into_iter()
                .zip([hello_bytes.clone(), greet_bytes.clone()])
                .collect::<Vec<_>>(),
        );

        // Full link, audit requested: no patch, no audit.
        req.audit = true;
        req.record_resolution = true;
        let full = session.link(&req).unwrap();
        assert!(full.patch.is_none());
        assert!(full.audit.is_none(), "a full link serves no audit");

        // The untouched relink: the ladder rides but patches nothing —
        // the audit does not run (its subject never exists).
        let record_bytes = full.record.expect("cold capture");
        let prev_output = full.image.clone();
        let (mut relink, _) = request(&link_config(), &hello_bytes, &greet_bytes);
        relink.record = Some(record_bytes);
        relink.prev_output = Some(content_hash(&prev_output));
        relink.audit = true;
        session
            .store_blob(&content_hash(&prev_output), prev_output.clone())
            .unwrap();
        let served = session.link(&relink).unwrap();
        let patch = served.patch.expect("the untouched relink reports");
        assert!(patch.untouched);
        assert!(
            served.audit.is_none(),
            "an untouched relink serves no audit"
        );
    }

    // ---- the §7.2 output-residency rung (wire v5) ---------------------------

    /// Every served image becomes resident output state keyed by its
    /// content hash: the next cycle's `prev_output` reference finds it in
    /// the session, so the BLOB negotiation skips the upload — the deferral
    /// the rung closes (the previous output used to cross the wire once
    /// per changed output state even for a warm session).
    #[test]
    fn served_images_become_resident_output() {
        let hello_bytes = hello(false);
        let greet_bytes = greet(16);
        let (mut req, hashes) = request(&link_config(), &hello_bytes, &greet_bytes);
        let mut session = ResidentSession::default();
        store(
            &mut session,
            &hashes
                .into_iter()
                .zip([hello_bytes.clone(), greet_bytes.clone()])
                .collect::<Vec<_>>(),
        );
        req.record_resolution = true;
        let cold = session.link(&req).unwrap();
        assert!(
            session.has_blob(&content_hash(&cold.image)),
            "the served image is resident output state"
        );

        // The patched relink's image becomes the next cycle's state too —
        // and the previous output needs no re-upload (already resident).
        let edited = hello(true);
        let (mut relink, _) = request(&link_config(), &edited, &greet_bytes);
        relink.record = Some(cold.record.clone().unwrap());
        relink.prev_output = Some(content_hash(&cold.image));
        relink.tiles = true;
        session
            .store_blob(&content_hash(&edited), edited.clone())
            .unwrap();
        let served = session.link(&relink).unwrap();
        assert!(served.patch.is_some(), "the ladder patches");
        assert!(
            session.has_blob(&content_hash(&served.image)),
            "the patched image is the next cycle's resident output"
        );
    }

    /// A tiles-asking relink serves the changed-tile stream instead of the
    /// image: a fraction of the bytes that replays to the exact patched
    /// image, gated by its content hash (a divergence never ships).
    #[test]
    fn tiles_relink_serves_the_changed_tile_stream() {
        let hello_bytes = hello(false);
        let greet_bytes = greet(16);
        let (mut req, hashes) = request(&link_config(), &hello_bytes, &greet_bytes);
        let mut session = ResidentSession::default();
        store(
            &mut session,
            &hashes
                .into_iter()
                .zip([hello_bytes.clone(), greet_bytes.clone()])
                .collect::<Vec<_>>(),
        );
        req.record_resolution = true;
        let cold = session.link(&req).unwrap();
        let prev_output = cold.image.clone();

        let edited = hello(true);
        let (mut relink, _) = request(&link_config(), &edited, &greet_bytes);
        relink.record = Some(cold.record.unwrap());
        relink.prev_output = Some(content_hash(&prev_output));
        relink.tiles = true;
        session.store_blob(&content_hash(&edited), edited).unwrap();
        let served = session.link(&relink).unwrap();
        let patch = served.patch.expect("the ladder patches");
        assert!(!patch.untouched);
        let stream = served
            .tiles
            .as_ref()
            .expect("the tiles rung serves a stream");
        assert!(
            stream.wire_bytes() > 0 && stream.wire_bytes() < served.image.len() as u64,
            "the stream is a fraction of the image ({} of {})",
            stream.wire_bytes(),
            served.image.len()
        );
        assert_eq!(
            pgr_emit::incremental::apply_tiles(&prev_output, stream),
            served.image,
            "the replay is lossless"
        );
        assert_eq!(
            stream.image_hash,
            content_hash(&served.image),
            "the replay gate hashes the patched image"
        );
    }

    /// The untouched relink ships nothing: an empty stream (the file the
    /// client holds is already the output), with the record still renewed.
    #[test]
    fn untouched_relink_ships_an_empty_tile_stream() {
        let hello_bytes = hello(false);
        let greet_bytes = greet(16);
        let (mut req, hashes) = request(&link_config(), &hello_bytes, &greet_bytes);
        let mut session = ResidentSession::default();
        store(
            &mut session,
            &hashes
                .into_iter()
                .zip([hello_bytes.clone(), greet_bytes.clone()])
                .collect::<Vec<_>>(),
        );
        req.record_resolution = true;
        let cold = session.link(&req).unwrap();

        let mut relink = req.clone();
        relink.record = Some(cold.record.unwrap());
        relink.prev_output = Some(content_hash(&cold.image));
        relink.tiles = true;
        let served = session.link(&relink).unwrap();
        assert!(served.patch.as_ref().expect("the ladder runs").untouched);
        let stream = served
            .tiles
            .expect("the untouched relink still shapes a stream");
        assert!(
            stream.tiles.is_empty() && stream.wire_bytes() == 0,
            "nothing crossed the wire"
        );
        assert_eq!(stream.final_size, cold.image.len() as u64);
    }

    /// Without the request flag the reply carries no stream — the v4
    /// client shape is unchanged (it receives the image and writes it).
    #[test]
    fn tiles_not_asked_serves_no_stream() {
        let hello_bytes = hello(false);
        let greet_bytes = greet(16);
        let (mut req, hashes) = request(&link_config(), &hello_bytes, &greet_bytes);
        let mut session = ResidentSession::default();
        store(
            &mut session,
            &hashes
                .into_iter()
                .zip([hello_bytes.clone(), greet_bytes.clone()])
                .collect::<Vec<_>>(),
        );
        req.record_resolution = true;
        let cold = session.link(&req).unwrap();

        let edited = hello(true);
        let (mut relink, _) = request(&link_config(), &edited, &greet_bytes);
        relink.record = Some(cold.record.unwrap());
        relink.prev_output = Some(content_hash(&cold.image));
        session.store_blob(&content_hash(&edited), edited).unwrap();
        let served = session.link(&relink).unwrap();
        assert!(served.patch.is_some());
        assert!(served.tiles.is_none(), "no flag, no stream");
    }

    /// M59 (wire v40): a time-asking request observes the session's own
    /// pipeline — the report names the phases the warm run actually
    /// executed (no `Parse` row: the session's POIs are resident, the
    /// parse was paid when the blobs arrived) and carries the measured
    /// emit/total bands.
    #[test]
    fn the_served_report_names_the_warm_pipeline() {
        let hello_bytes = hello(false);
        let greet_bytes = greet(16);
        let (mut req, hashes) = request(&link_config(), &hello_bytes, &greet_bytes);
        req.time = true;
        let mut session = ResidentSession::default();
        store(
            &mut session,
            &hashes
                .into_iter()
                .zip([hello_bytes, greet_bytes])
                .collect::<Vec<_>>(),
        );
        let served = session.link(&req).unwrap();
        let report = served
            .time_report
            .as_ref()
            .expect("the time-asking request is served a report");
        let phases: Vec<pgr_core::observe::Phase> = report.phases.iter().map(|e| e.phase).collect();
        assert_eq!(
            phases,
            vec![
                pgr_core::observe::Phase::ArchivePull,
                pgr_core::observe::Phase::Intern,
                pgr_core::observe::Phase::Resolve,
                pgr_core::observe::Phase::Liveness,
                pgr_core::observe::Phase::Fold,
                pgr_core::observe::Phase::Layout,
            ],
            "the warm pipeline reports its own run — no parse row, the POIs are resident"
        );
        assert!(report.emit.is_some(), "the fused emit band is measured");
        assert!(report.total.is_some(), "the pipeline wall is measured");
    }

    /// Without the flag the reply carries no report — the v39 client
    /// shape is unchanged.
    #[test]
    fn the_report_absent_when_not_asked() {
        let hello_bytes = hello(false);
        let greet_bytes = greet(16);
        let (req, hashes) = request(&link_config(), &hello_bytes, &greet_bytes);
        let mut session = ResidentSession::default();
        store(
            &mut session,
            &hashes
                .into_iter()
                .zip([hello_bytes, greet_bytes])
                .collect::<Vec<_>>(),
        );
        let served = session.link(&req).unwrap();
        assert!(served.time_report.is_none(), "no flag, no report");
    }

    /// The relink's report: the ladder's warm pipeline rides the same
    /// rows; the emit band stays absent — the relink's Pass-4 half is
    /// the in-memory patch, not the fused tile emit (the `-r` shape:
    /// phases plus total, the emit band `None`).
    #[test]
    fn the_relink_report_names_the_ladder() {
        let hello_bytes = hello(false);
        let greet_bytes = greet(16);
        let (mut req, hashes) = request(&link_config(), &hello_bytes, &greet_bytes);
        req.record_resolution = true;
        let mut session = ResidentSession::default();
        store(
            &mut session,
            &hashes
                .into_iter()
                .zip([hello_bytes.clone(), greet_bytes.clone()])
                .collect::<Vec<_>>(),
        );
        let cold = session.link(&req).unwrap();

        let edited = hello(true);
        let (mut relink, _) = request(&link_config(), &edited, &greet_bytes.clone());
        relink.record = Some(cold.record.unwrap());
        relink.prev_output = Some(content_hash(&cold.image));
        relink.time = true;
        session.store_blob(&content_hash(&edited), edited).unwrap();
        let served = session.link(&relink).unwrap();
        assert!(served.patch.is_some(), "the relink patched");
        let report = served
            .time_report
            .as_ref()
            .expect("the time-asking relink is served a report");
        assert!(
            report
                .phases
                .iter()
                .any(|e| e.phase == pgr_core::observe::Phase::Resolve),
            "the ladder's warm pipeline reports its resolve"
        );
        assert!(
            report.emit.is_none(),
            "the relink's Pass-4 half is the patch — no fused-emit band"
        );
        assert!(report.total.is_some(), "the ladder wall is measured");
    }
}

#[cfg(test)]
mod family_tests {
    use super::ResidentSession;
    use crate::protocol::{InputEntry, LinkRequest, content_hash};
    use pgr_core::fixups::FixupPointerFormat;
    use pgr_core::layout::LinkConfig;
    use pgr_core::link::{LinkInput, Parallelism, link_cached};
    use pgr_emit::build_image_fused;
    use pgr_emit::incremental::LinkRecord;
    use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

    /// hello.o: `_main` ADRP+ADD loads `_msg`, BL `_greet`, ret (the
    /// fusion fixture's shape — the family gates ride the same corpus).
    fn hello() -> Vec<u8> {
        let words: Vec<u32> = vec![
            0x9000_0000, // adrp x0, _msg@page
            0x9100_0000, // add x0, x0, #_msg@pageoff
            0x9400_0000, // bl _greet
            0x5280_0000, // mov w0, #0
            0xD65F_03C0, // ret
        ];
        let text: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let mut b = ObjectBuilder::new("hello.o");
        let sect = b.add_section(ObjectSection::text(
            "__text",
            text,
            vec![
                ObjectReloc::addend(0).at(0),
                ObjectReloc::page21(1).at(0),
                ObjectReloc::addend(0).at(4),
                ObjectReloc::pageoff12(1).at(4),
                ObjectReloc::branch26(2).at(8),
            ],
        ));
        b.add_section(ObjectSection::cstring("hello, peregrine\n"));
        b.add_symbol(ObjectSymbol::Defined {
            name: "_main".into(),
            section_index: sect,
            value: 0,
            weak: false,
        });
        b.add_symbol(ObjectSymbol::Defined {
            name: "_msg".into(),
            section_index: 1,
            value: 0,
            weak: false,
        });
        b.add_symbol(ObjectSymbol::Undefined {
            name: "_greet".into(),
            weak_ref: false,
        });
        b.build().unwrap()
    }

    /// greet.o: `_greet` + a `__data` pointer to `_greet`.
    fn greet() -> Vec<u8> {
        let mut b = ObjectBuilder::new("greet.o");
        let text = b.add_section(ObjectSection::text(
            "__text",
            vec![0xC0, 0x03, 0x5F, 0xD6],
            vec![],
        ));
        let data = b.add_section(ObjectSection::data("__data", vec![0u8; 8], vec![]));
        b.add_symbol(ObjectSymbol::Defined {
            name: "_greet".into(),
            section_index: text,
            value: 0,
            weak: false,
        });
        b.section_mut(data).relocs = vec![ObjectReloc::unsigned(0).at(0)];
        b.build().unwrap()
    }

    fn cfg_with(family: FixupPointerFormat) -> LinkConfig {
        LinkConfig {
            ident: "family-test".into(),
            chain_word_format: family,
            layout_slack: Some(pgr_core::slack::SlackPolicy::default()),
            ..LinkConfig::default()
        }
    }

    fn request(
        cfg: &LinkConfig,
        hello_bytes: &[u8],
        greet_bytes: &[u8],
    ) -> (LinkRequest, Vec<[u8; 32]>) {
        let req = LinkRequest {
            config: cfg.clone(),
            force_load: Vec::new(),
            inputs: vec![
                InputEntry {
                    name: "hello.o".into(),
                    hash: content_hash(hello_bytes),
                },
                InputEntry {
                    name: "greet.o".into(),
                    hash: content_hash(greet_bytes),
                },
            ],
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
        };
        let hashes = req.blob_hashes();
        (req, hashes)
    }

    /// The plain full link's image over the given config (the reference
    /// the session's full link must match byte for byte).
    fn full_image(cfg: &LinkConfig, hello_bytes: &[u8], greet_bytes: &[u8]) -> Vec<u8> {
        let inputs = vec![
            LinkInput {
                name: "hello.o".into(),
                bytes: hello_bytes.to_vec(),
            },
            LinkInput {
                name: "greet.o".into(),
                bytes: greet_bytes.to_vec(),
            },
        ];
        let result = link_cached(&inputs, &[], cfg, Parallelism::Auto, None).unwrap();
        build_image_fused(&result.layout, &result.objects).unwrap()
    }

    /// M82: the record carries the family the session's walk encoded, and
    /// a record-bearing request naming a different family declines to the
    /// full link — the ladder never patches across word shapes. The
    /// served image is the full link's (the asked family planned), the
    /// renewed record carries the family that landed, and a matching
    /// relink still patches.
    #[test]
    fn a_family_flip_falls_back_inside_the_session() {
        let hello_bytes = hello();
        let greet_bytes = greet();
        let arm64e = cfg_with(FixupPointerFormat::Arm64e);
        let (mut req, hashes) = request(&arm64e, &hello_bytes, &greet_bytes);
        let mut session = ResidentSession::default();
        for (h, bytes) in hashes
            .into_iter()
            .zip([hello_bytes.clone(), greet_bytes.clone()])
        {
            session.store_blob(&h, bytes).unwrap();
        }

        req.record_resolution = true;
        let cold = session.link(&req).unwrap();
        let record_bytes = cold.record.expect("capture was requested");
        let record = LinkRecord::decode(&record_bytes).expect("the arm64e record decodes");
        assert_eq!(
            record.chain_word_format,
            FixupPointerFormat::Arm64e,
            "the record carries the family the session's walk encoded"
        );

        // The flip: the same inputs and previous output, the Offset64
        // config. The ladder declines at admission — the patch cannot
        // renegotiate the word shape in place — and the full link plans
        // the family the request named.
        let offset64 = cfg_with(FixupPointerFormat::Offset64);
        let (mut flipped, _) = request(&offset64, &hello_bytes, &greet_bytes);
        flipped.record = Some(record_bytes.clone());
        flipped.prev_output = Some(content_hash(&cold.image));
        flipped.record_resolution = true;
        session
            .store_blob(&content_hash(&cold.image), cold.image.clone())
            .unwrap();
        let served = session.link(&flipped).unwrap();
        assert!(
            served.patch.is_none(),
            "the flipped relink declines to the full link"
        );
        assert_eq!(
            served.image,
            full_image(&offset64, &hello_bytes, &greet_bytes),
            "the full link planned the family the request named"
        );
        let renewed = LinkRecord::decode(served.record.as_ref().expect("the full link re-records"))
            .expect("the renewed record decodes");
        assert_eq!(
            renewed.chain_word_format,
            FixupPointerFormat::Offset64,
            "the renewed record carries the family that landed"
        );

        // A matching relink still patches: the record's own family rides
        // the ladder the way every other recorded shape does.
        let (mut matching, _) = request(&arm64e, &hello_bytes, &greet_bytes);
        matching.record = Some(record_bytes.clone());
        matching.prev_output = Some(content_hash(&cold.image));
        session
            .store_blob(&content_hash(&cold.image), cold.image.clone())
            .unwrap();
        let warm = session.link(&matching).unwrap();
        assert!(warm.patch.is_some(), "the matching relink patches in place");
    }
}

#[cfg(test)]
mod reloc_tests {
    use super::ResidentSession;
    use crate::protocol::{InputEntry, LinkRequest, content_hash};
    use pgr_core::layout::{LinkConfig, OutputType};
    use pgr_core::link::{LinkInput, Parallelism, link_reloc};
    use pgr_emit::build_object_image;
    use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

    /// `hello_main.o`: `_main` ADRP+ADD loads `_msg`, BL `_greet`, ret —
    /// the M10 relocatable fixture's shape (an open `_greet`).
    fn hello_main() -> Vec<u8> {
        let mut b = ObjectBuilder::new("hello_main.o");
        let text = b.add_section(ObjectSection::text(
            "__text",
            vec![
                0x90, 0x00, 0x00, 0x00, // adrp x0, _msg@page
                0x91, 0x00, 0x00, 0x00, // add x0, x0, #_msg@pageoff
                0x94, 0x00, 0x00, 0x00, // bl _greet
                0xC0, 0x03, 0x5F, 0xD6, // ret
            ],
            vec![
                ObjectReloc::addend(0).at(0),
                ObjectReloc::page21(1).at(0),
                ObjectReloc::addend(0).at(4),
                ObjectReloc::pageoff12(1).at(4),
                ObjectReloc::branch26(2).at(8),
            ],
        ));
        b.add_section(ObjectSection::cstring("hello, peregrine\n"));
        b.add_symbol(ObjectSymbol::Defined {
            name: "_main".into(),
            section_index: text,
            value: 0,
            weak: false,
        });
        b.add_symbol(ObjectSymbol::Defined {
            name: "_msg".into(),
            section_index: 1,
            value: 0,
            weak: false,
        });
        b.add_symbol(ObjectSymbol::Undefined {
            name: "_greet".into(),
            weak_ref: false,
        });
        b.build().unwrap()
    }

    /// greet.o: `_greet` (the step-two resolution).
    fn greet() -> Vec<u8> {
        let mut b = ObjectBuilder::new("greet.o");
        let text = b.add_section(ObjectSection::text(
            "__text",
            vec![0xC0, 0x03, 0x5F, 0xD6],
            vec![],
        ));
        b.add_symbol(ObjectSymbol::Defined {
            name: "_greet".into(),
            section_index: text,
            value: 0,
            weak: false,
        });
        b.build().unwrap()
    }

    fn reloc_request() -> (LinkRequest, Vec<([u8; 32], Vec<u8>)>) {
        let hello_bytes = hello_main();
        let greet_bytes = greet();
        let req = LinkRequest {
            config: LinkConfig {
                filetype: OutputType::Relocatable,
                ..LinkConfig::default()
            },
            force_load: Vec::new(),
            inputs: vec![
                InputEntry {
                    name: "hello_main.o".into(),
                    hash: content_hash(&hello_bytes),
                },
                InputEntry {
                    name: "greet.o".into(),
                    hash: content_hash(&greet_bytes),
                },
            ],
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
        };
        let hashes = req.blob_hashes();
        (
            req,
            hashes.into_iter().zip([hello_bytes, greet_bytes]).collect(),
        )
    }

    /// The plain cold reference: the object shape's two steps over the
    /// same bytes (`link_reloc` + `build_object_image`).
    fn cold_object(config: &LinkConfig, hello_bytes: &[u8], greet_bytes: &[u8]) -> Vec<u8> {
        let inputs = vec![
            LinkInput {
                name: "hello_main.o".into(),
                bytes: hello_bytes.to_vec(),
            },
            LinkInput {
                name: "greet.o".into(),
                bytes: greet_bytes.to_vec(),
            },
        ];
        let linked = link_reloc(&inputs, &[], config, Parallelism::Auto).unwrap();
        build_object_image(&linked, config).unwrap()
    }

    /// M83: the session's walk serves the object shape — the same two
    /// steps the cold lane runs over the same raw bytes (the POI cache is
    /// the segmented pipeline's optimization; the object path re-parses),
    /// and the replay faces a record cannot ride refuse (the ladder has
    /// no object shape; the surface refuses the knobs beside `-r`, so the
    /// driver never asks — a wire caller cannot plan the shape either).
    #[test]
    fn a_relocatable_request_serves_the_object_shape() {
        let (req, blobs) = reloc_request();
        let mut session = ResidentSession::default();
        for (h, bytes) in &blobs {
            session.store_blob(h, bytes.clone()).unwrap();
        }
        let served = session.link(&req).unwrap();
        assert!(served.patch.is_none(), "an object never patches");
        assert!(served.record.is_none(), "an object never records");
        let hello_bytes = &blobs[0].1;
        let greet_bytes = &blobs[1].1;
        assert_eq!(
            served.image,
            cold_object(&req.config, hello_bytes, greet_bytes),
            "the session's object walk matches the cold one byte for byte"
        );

        // The replay faces refuse: a record beside a relocatable config
        // has no ladder to run (the §7.3 replay patches the recorded
        // plan; objects plan no record).
        let (mut req, blobs) = reloc_request();
        req.record = Some(Vec::new());
        for (h, bytes) in &blobs {
            session.store_blob(h, bytes.clone()).unwrap();
        }
        let refused = session.link(&req).expect_err("a record beside -r refuses");
        assert!(
            refused.to_string().contains("relocatable"),
            "the refusal names the shape: {refused}"
        );
    }
}
