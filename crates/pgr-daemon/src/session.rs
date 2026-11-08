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
    /// The link failed ( surfaced to the client as `ERROR`).
    #[error(transparent)]
    Link(#[from] pgr_core::LinkError),
    /// The emit failed.
    #[error(transparent)]
    Emit(#[from] pgr_emit::EmitError),
}

/// One prepared object outcome (for stats/diagnostics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrepareStats {
    /// POI frames decoded (no Mach-O walk).
    pub hits: u64,
    /// Fresh parses (also stored as frames for the next link).
    pub misses: u64,
}

/// One cached POI frame: the encoded Pass 1 product plus its last-use
/// stamp (the LRU clock for the memory ceiling).
type PoiFrame = (std::sync::Arc<Vec<u8>>, u64);

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

    /// Bytes currently held as resident state (blobs + POI frames). The
    /// scratch emit buffer is not session state — it is bounded by the
    /// output size and always reclaimable.
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
        self.enforce_limit(None);
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
        self.enforce_limit(None);
        Ok(obj)
    }

    /// Runs one link through the session: prepares direct inputs, pulls
    /// archive members through the normal S7 fixpoint, links, gates `-u`,
    /// emits into the reused scratch buffer.
    ///
    /// # Errors
    /// [`SessionError`] on missing blobs, link failures (undefined
    /// symbols, duplicates, layout contract) or emit failures.
    pub fn link(
        &mut self,
        req: &crate::protocol::LinkRequest,
    ) -> Result<(Vec<u8>, u64, u64), SessionError> {
        use pgr_core::Parallelism;
        let split = req.config.dead_strip;
        let mut objects: Vec<InputObject> = Vec::with_capacity(req.inputs.len());
        for (i, entry) in req.inputs.iter().enumerate() {
            objects.push(self.prepare_object(
                &entry.hash,
                &entry.name,
                pgr_core::ids::FileId(i as u32),
                split,
            )?);
        }
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
        let result =
            pgr_core::link_from_objects(objects, &archives, &req.config, Parallelism::Auto, None)?;
        pgr_core::check_load_symbols(&result, &req.force_load)?;
        let entryoff = result.layout.entryoff;
        let fixup_slots = result.layout.fixups.slot_count;
        pgr_emit::build_image_fused_into(&mut self.scratch, &result.layout, &result.objects)?;
        let image = self.scratch.clone();
        Ok((
            image,
            entryoff,
            u64::try_from(fixup_slots).unwrap_or(u64::MAX),
        ))
    }

    /// Evicts least-recently-used entries until under the ceiling. `keep`
    /// is protected (currently-unused hook for callers mid-store).
    fn enforce_limit(&mut self, _keep: Option<&[u8; 32]>) {
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

        let (cold, entryoff, slots) = session.link(&req).unwrap();
        assert_eq!((session.hits, session.misses), (0, 2));
        assert!(entryoff > 0, "executables carry an entry point");
        let _ = slots;

        let (warm, entryoff2, slots2) = session.link(&req).unwrap();
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
        // repopulates what it needs).
        let (image, _, _) = session.link(&req).unwrap();
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
        assert_eq!(
            session.scratch.capacity(),
            session.link(&req).unwrap().0.len()
        );
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
        };
        let mut session = ResidentSession::default();
        session.store_blob(&content_hash(&hello), hello).unwrap();
        session
            .store_blob(&content_hash(&archive_bytes), archive_bytes)
            .unwrap();
        let (image1, _, _) = session.link(&req).unwrap();
        let (image2, _, _) = session.link(&req).unwrap();
        assert_eq!(image1, image2);
        assert!(!image1.is_empty(), "image built");
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
