//! Stage A caches (M6 — architecture doc §7.1: "Compiled caches for stable
//! inputs"; M6 row: "**Stage A caches (7.1): POI + frozen `.tbd`**").
//!
//! Two content-addressed cache forms, both *pure accelerations*: a corrupt
//! or stale entry is detected (payload SHA-256) and silently re-parsed, and
//! a cache hit produces byte-identical link results (gated in tests).
//!
//! * **POI (Parsed Object Image)** — everything Pass 1 would produce for
//!   one `.o`/archive member *before* interning: the section table with
//!   raw relocations, the typed symbol table, the symbol-name pool and the
//!   D1 atom ranges. Loading is one allocation-light decode; the parse
//!   (Mach-O walk + reloc decode + atomization) disappears for unchanged
//!   inputs. Keys are the input content hash plus the parse-affecting flag
//!   (symbol splitting); the `FileId`/name stay call-site properties.
//! * **Frozen `.tbd`** — the parsed stub (install name, versions, export
//!   set) compiled out of the YAML text; startup for the SDK dylibs drops
//!   from text parsing to a decode. The per-input `weak`/`reexport` flags
//!   ride the driver, not the cache.
//!
//! Layout, M7 **versioned cache format** (little-endian, pointer-free):
//! `magic(8) | format_version(u32) | parser_revision(u32) | payload_len(u64)
//! | sha256(payload)(32) | payload`. The two revision fields are the §7.1
//! requirement that a cache entry "records the `pgr` format version"; the
//! payload starts with the parse-affecting flag byte it was produced under.
//! Writes are atomic (temp file + rename); keys are hex-encoded SHA-256
//! digests over the input bytes *and* both revisions *and* the
//! parse-affecting flags, so build-system parallelism is safe and stale
//! entries become unreachable rather than merely unread. The cache directory
//! carries a format marker (`PGR_CACHE_FORMAT`): a directory written by a
//! different format/parser self-heals on open (stale pgr-shaped files are
//! reclaimed, the marker is rewritten). Directories can be size-bounded with
//! oldest-mtime (LRU) eviction — a hit refreshes recency, and the
//! just-stored entry is never evicted.

use crate::ids::FileId;
use crate::object::{InputObject, InputSection, InputSymbol};
use crate::resolve::Dylib;
use pgr_format::reloc::RelocationInfo;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const POI_MAGIC: &[u8; 8] = b"PGRPOI1\0";

/// Cache format version (M7): the framing *and* payload layout revision.
/// Bump when the frame or codec changes shape; older entries are then
/// silently missed and reclaimed by the directory self-heal. **v3**
/// (M30) adds the parsed object's `LC_DATA_IN_CODE` entries to the
/// payload — v1/v2 entries decode to `None` and re-parse.
pub const CACHE_FORMAT_VERSION: u32 = 3;

/// Parser revision: bumped when Pass 1's parse semantics change in a way
/// that would make a stored POI stale even though the framing is unchanged.
pub const PARSER_REVISION: u32 = 1;

/// The directory-level format marker file name. Its payload is
/// `"PGR-CACHE-FORMAT\0" || format_version(u32) || parser_revision(u32)`;
/// a mismatch (or absence) on open reclaims every pgr-shaped file in the
/// directory and rewrites the marker.
pub const MARKER_NAME: &str = "PGR_CACHE_FORMAT";

const MARKER_TAG: &[u8; 17] = b"PGR-CACHE-FORMAT\0";
const MARKER_LEN: usize = MARKER_TAG.len() + 8;

/// Unique temp-file suffix for atomic stores (concurrent writers must never
/// share a temp path — the rename target is the content key, but the temp
/// file is shared scratch).
static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn tmp_path(dir: &Path, tag: &str) -> PathBuf {
    let n = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    dir.join(format!(".tmp-{tag}-{}-{n}", std::process::id()))
}
const FROZEN_TBD_MAGIC: &[u8; 8] = b"PGRFTBD1";
const HEADER_LEN: usize = 8 + 4 + 4 + 8 + 32;

/// Files pgr owns in a cache directory: 64-hex content keys and its own
/// `.tmp-*` scratch. The self-heal only ever removes these shapes.
fn is_own_file(name: &std::ffi::OsStr) -> bool {
    let Some(s) = name.to_str() else {
        return false;
    };
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit()) || s.starts_with(".tmp-")
}

/// Per-user content-addressed cache directory (Stage A, versioned at M7).
/// `None`-safe: all methods short-circuit when the cache is disabled.
#[derive(Debug, Clone)]
pub struct PoiCache {
    dir: PathBuf,
    /// Size bound in bytes (`None` = unbounded). Enforced after each store:
    /// entries beyond the bound are evicted oldest-mtime-first (LRU — a hit
    /// refreshes recency), and the just-stored entry is never evicted.
    max_bytes: Option<u64>,
    /// Serializes store+evict across the parse pool's threads: without it,
    /// two concurrent stores each spare their own entry and evict the
    /// other's — the bound can wipe the directory (regression-gated by the
    /// parallel-store stress test).
    store_lock: std::sync::Arc<std::sync::Mutex<()>>,
}

impl PoiCache {
    /// Opens (creating if needed) the cache directory, unbounded.
    ///
    /// The directory's format marker is validated: a directory written by a
    /// different cache format or parser revision self-heals (stale
    /// pgr-shaped files are reclaimed, the marker is rewritten); files pgr
    /// does not own are never touched.
    ///
    /// # Errors
    /// [`std::io::Error`] when the directory cannot be created.
    pub fn open(dir: &Path) -> std::io::Result<Self> {
        Self::open_limited(dir, 0)
    }

    /// [`PoiCache::open`] with a size bound in bytes (`0` = unbounded).
    ///
    /// # Errors
    /// [`std::io::Error`] when the directory cannot be created.
    pub fn open_limited(dir: &Path, max_bytes: u64) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let cache = Self {
            dir: dir.to_path_buf(),
            max_bytes: (max_bytes > 0).then_some(max_bytes),
            store_lock: std::sync::Arc::new(std::sync::Mutex::new(())),
        };
        cache.heal_marker()?;
        Ok(cache)
    }

    /// Validates (or writes, or heals) the directory format marker.
    fn heal_marker(&self) -> std::io::Result<()> {
        let marker = self.dir.join(MARKER_NAME);
        let mut want = Vec::with_capacity(MARKER_LEN);
        want.extend_from_slice(MARKER_TAG);
        want.extend_from_slice(&CACHE_FORMAT_VERSION.to_le_bytes());
        want.extend_from_slice(&PARSER_REVISION.to_le_bytes());
        if std::fs::read(&marker).is_ok_and(|got| got == want) {
            return Ok(());
        }
        // Missing or foreign marker: reclaim every file pgr owns (entries
        // from an incompatible format are unreachable under the current key
        // derivation anyway) and write our marker. Foreign files stay.
        for e in std::fs::read_dir(&self.dir)?.flatten() {
            let name = e.file_name();
            if name != MARKER_NAME
                && e.metadata().is_ok_and(|md| md.is_file())
                && is_own_file(&name)
            {
                let _ = std::fs::remove_file(e.path());
            }
        }
        std::fs::write(&marker, &want)
    }

    /// The cache key of one input (M7 v2): SHA-256 over the input bytes, the
    /// parse-affecting flag, **and both format revisions** — an entry written
    /// by another format/parser revision is unreachable under a v2 key, so
    /// stale data can never be read even if the self-heal has not run yet.
    #[must_use]
    pub fn content_key(bytes: &[u8], split_symbols: bool) -> [u8; 32] {
        Self::key_derive(bytes, split_symbols, CACHE_FORMAT_VERSION, PARSER_REVISION)
    }

    /// The key derivation itself, parameterized for tests.
    fn key_derive(bytes: &[u8], split_symbols: bool, format: u32, parser: u32) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(bytes);
        h.update([u8::from(split_symbols), 0, 0, 0]);
        h.update(format.to_le_bytes());
        h.update(parser.to_le_bytes());
        h.finalize().into()
    }

    fn path(&self, key: &[u8; 32]) -> PathBuf {
        let mut name = String::with_capacity(64);
        for b in key {
            name.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
            name.push(char::from_digit(u32::from(b & 0xF), 16).unwrap_or('0'));
        }
        self.dir.join(name)
    }

    /// Loads one cached parse. `bytes` is the (unchanged) input file — Pass
    /// 4 copies section bytes from it. `split_symbols` must match the flag
    /// the entry was stored under. Any decode failure (missing, truncated,
    /// corrupt, version mismatch, flag mismatch) yields `None` — the caller
    /// re-parses. A hit refreshes the entry's recency (LRU).
    #[must_use]
    pub fn load(
        &self,
        key: &[u8; 32],
        file: FileId,
        name: &str,
        bytes: Vec<u8>,
        split_symbols: bool,
    ) -> Option<InputObject> {
        let path = self.path(key);
        let cached = std::fs::read(&path).ok()?;
        let mut obj = decode_poi(&cached, file, name, split_symbols)?;
        obj.bytes = bytes;
        Self::touch(&path);
        Some(obj)
    }

    /// Refreshes one entry's mtime (the LRU recency mark). Best effort.
    fn touch(path: &Path) {
        if let Ok(f) = std::fs::File::options().write(true).open(path) {
            let _ = f.set_modified(std::time::SystemTime::now());
        }
    }

    /// Stores one parsed object (atomic replace; failures are silent — the
    /// cache is an optimization only), then enforces the size bound. The
    /// write-rename-evict sequence is serialized: concurrent stores from the
    /// parse pool must not evict each other's just-stored entries.
    pub fn store(&self, key: &[u8; 32], obj: &InputObject, split_symbols: bool) {
        let bytes = encode_poi(obj, split_symbols);
        let dst = self.path(key);
        let _serial = self.store_lock.lock();
        let tmp = tmp_path(&self.dir, "poi");
        if std::fs::write(&tmp, &bytes).is_ok() {
            let _ = std::fs::rename(&tmp, &dst);
        }
        self.enforce_limit(&dst);
    }

    /// Evicts entries oldest-mtime-first until the directory is within the
    /// bound. The just-stored entry (`keep`) is never evicted.
    fn enforce_limit(&self, keep: &Path) {
        let Some(max) = self.max_bytes else {
            return;
        };
        let mut entries: Vec<(PathBuf, u64, std::time::SystemTime)> = Vec::new();
        let Ok(rd) = std::fs::read_dir(&self.dir) else {
            return;
        };
        let mut total = 0u64;
        for e in rd.flatten() {
            let name = e.file_name();
            let is_entry = name
                .to_str()
                .is_some_and(|s| s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit()));
            if !is_entry {
                continue;
            }
            let Ok(md) = e.metadata() else { continue };
            total += md.len();
            entries.push((
                e.path(),
                md.len(),
                md.modified().unwrap_or(std::time::SystemTime::now()),
            ));
        }
        if total <= max {
            return;
        }
        entries.sort_by_key(|e| e.2);
        for (path, len, _) in entries {
            if total <= max {
                break;
            }
            if path == keep {
                continue;
            }
            if std::fs::remove_file(&path).is_ok() {
                total = total.saturating_sub(len);
            }
        }
    }

    /// Loads one frozen `.tbd` parse.
    #[must_use]
    pub fn load_dylib(&self, key: &[u8; 32]) -> Option<FrozenDylib> {
        let bytes = std::fs::read(self.path(key)).ok()?;
        decode_frozen_dylib(&bytes)
    }

    /// Stores one parsed `.tbd` (same serialization as [`PoiCache::store`]).
    pub fn store_dylib(&self, key: &[u8; 32], dylib: &FrozenDylib) {
        let bytes = encode_frozen_dylib(dylib);
        let dst = self.path(key);
        let _serial = self.store_lock.lock();
        let tmp = tmp_path(&self.dir, "tbd");
        if std::fs::write(&tmp, &bytes).is_ok() {
            let _ = std::fs::rename(&tmp, &dst);
        }
        self.enforce_limit(&dst);
    }
}

/// The parsed `.tbd` payload the cache stores (the per-input `weak` /
/// `reexport` markers are driver properties and stay out).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenDylib {
    /// `LC_ID_DYLIB` install name.
    pub install_name: String,
    /// Current version (packed).
    pub current_version: u32,
    /// Compatibility version (packed).
    pub compatibility_version: u32,
    /// Exported symbol names (C-underscored).
    pub exports: Vec<Vec<u8>>,
}

impl From<&Dylib> for FrozenDylib {
    fn from(d: &Dylib) -> Self {
        Self {
            install_name: d.install_name.clone(),
            current_version: d.current_version,
            compatibility_version: d.compatibility_version,
            exports: d.exports.clone(),
        }
    }
}

impl From<FrozenDylib> for Dylib {
    fn from(f: FrozenDylib) -> Self {
        Dylib {
            install_name: f.install_name,
            current_version: f.current_version,
            compatibility_version: f.compatibility_version,
            exports: f.exports,
            weak: false,
            reexport: false,
            lazy: false,
        }
    }
}

// ---- framing ----------------------------------------------------------------

fn frame(magic: [u8; 8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&magic);
    out.extend_from_slice(&CACHE_FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&PARSER_REVISION.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    let digest: [u8; 32] = Sha256::digest(payload).into();
    out.extend_from_slice(&digest);
    out.extend_from_slice(payload);
    out
}

struct Unframed<'a> {
    payload: &'a [u8],
}

/// Validates the frame (magic, both revisions, length, checksum) and returns
/// the payload slice; `None` on any mismatch (silent cache miss).
fn unframe(bytes: &[u8], magic: [u8; 8]) -> Option<Unframed<'_>> {
    if bytes.len() < HEADER_LEN || bytes[0..8] != magic {
        return None;
    }
    let format = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
    let parser = u32::from_le_bytes(bytes[12..16].try_into().ok()?);
    if format != CACHE_FORMAT_VERSION || parser != PARSER_REVISION {
        return None;
    }
    let len = u64::from_le_bytes(bytes[16..24].try_into().ok()?) as usize;
    // Checked: a hostile `len` must never wrap the sum (the M7 cache_entries
    // fuzzer found this as an `add with overflow` abort).
    if bytes.len() != HEADER_LEN.checked_add(len)? {
        return None;
    }
    let payload = &bytes[HEADER_LEN..];
    let want: [u8; 32] = bytes[24..56].try_into().ok()?;
    let got: [u8; 32] = Sha256::digest(payload).into();
    if want != got {
        return None;
    }
    Some(Unframed { payload })
}

// ---- little-endian scalar writers (the POI is hand-packed: stable bytes
// across platforms, no serde dependency in the hot path) ----------------------

fn put_u8(out: &mut Vec<u8>, v: u8) {
    out.push(v);
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    put_u32(out, s.len() as u32);
    out.extend_from_slice(s.as_bytes());
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_u32(out, b.len() as u32);
    out.extend_from_slice(b);
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let s = self.b.get(self.at..end)?;
        self.at = end;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|s| u32::from_le_bytes(s.try_into().expect("`take(4)` guarantees the byte count")))
    }
    fn u64(&mut self) -> Option<u64> {
        self.take(8)
            .map(|s| u64::from_le_bytes(s.try_into().expect("`take(8)` guarantees the byte count")))
    }
    fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    fn str(&mut self) -> Option<String> {
        self.bytes()
            .map(|b| String::from_utf8_lossy(b).into_owned())
    }
}

// ---- POI codec ---------------------------------------------------------------

/// Serializes one parsed object (post-`compute_atoms`, pre-intern) together
/// with the parse-affecting flag it was produced under (§7.1: the entry
/// "records the `pgr` format version and any parse-affecting flags").
#[must_use]
pub fn encode_poi(obj: &InputObject, split_symbols: bool) -> Vec<u8> {
    let mut p = Vec::new();
    put_u8(&mut p, u8::from(split_symbols));
    put_u8(&mut p, u8::from(obj.subsections_via_symbols));
    put_u8(&mut p, u8::from(obj.from_archive));
    put_str(&mut p, &obj.archive_name);
    put_u32(&mut p, obj.sections.len() as u32);
    for sect in &obj.sections {
        put_str(&mut p, &sect.name);
        put_str(&mut p, &sect.segment);
        put_u32(&mut p, sect.flags);
        put_u32(&mut p, sect.align_log2);
        put_u64(&mut p, sect.addr);
        put_u64(&mut p, sect.data.start);
        put_u64(&mut p, sect.data.end);
        put_u64(&mut p, sect.size);
        put_u8(&mut p, u8::from(sect.zerofill));
        put_u32(&mut p, sect.raw_relocs().len() as u32);
        for r in sect.raw_relocs() {
            put_u32(&mut p, r.r_address);
            put_u32(&mut p, r.r_info);
        }
    }
    put_u32(&mut p, obj.symbols.len() as u32);
    for s in &obj.symbols {
        put_u8(&mut p, u8::from(s.external));
        put_u8(&mut p, u8::from(s.stab));
        put_u32(&mut p, s.section.map_or(u32::MAX, |v| v as u32));
        put_u64(&mut p, s.value);
        put_u8(&mut p, u8::from(s.weak_def));
        put_u8(&mut p, u8::from(s.weak_ref));
        put_u32(&mut p, s.common_align.unwrap_or(u32::MAX));
        put_u8(&mut p, u8::from(s.alt_entry));
    }
    put_u32(&mut p, obj.peek_symbol_names().len() as u32);
    for name in obj.peek_symbol_names() {
        put_bytes(&mut p, name);
    }
    put_u32(&mut p, obj.atoms.len() as u32);
    for ranges in &obj.atoms {
        put_u32(&mut p, ranges.len() as u32);
        for r in ranges {
            put_u64(&mut p, r.start);
            put_u64(&mut p, r.end);
        }
    }
    // M30 (v3 payload): the data-in-code stream rides the tail — one
    // 8-byte entry per record, `__text`-relative as parsed.
    put_u32(&mut p, obj.data_in_code.len() as u32);
    for e in &obj.data_in_code {
        put_u32(&mut p, e.offset);
        put_u32(&mut p, u32::from(e.length) | (u32::from(e.kind) << 16));
    }
    frame(*POI_MAGIC, &p)
}

/// Rebuilds one object from its POI bytes. `want_split` must match the flag
/// the entry was stored under. Any inconsistency (truncation, checksum,
/// bounds, revision or flag mismatch) yields `None` — the caller re-parses.
#[must_use]
pub fn decode_poi(bytes: &[u8], file: FileId, name: &str, want_split: bool) -> Option<InputObject> {
    let Unframed { payload } = unframe(bytes, *POI_MAGIC)?;
    let mut r = Reader { b: payload, at: 0 };
    let stored_split = r.u8()? != 0;
    if stored_split != want_split {
        return None;
    }
    let subsections_via_symbols = r.u8()? != 0;
    let from_archive = r.u8()? != 0;
    let archive_name = r.str()?;
    let n_sections = r.u32()? as usize;
    let mut sections = Vec::with_capacity(n_sections.min(1 << 16));
    for _ in 0..n_sections {
        let sname = r.str()?;
        let segment = r.str()?;
        let flags = r.u32()?;
        let align_log2 = r.u32()?;
        let addr = r.u64()?;
        let data_start = r.u64()?;
        let data_end = r.u64()?;
        let size = r.u64()?;
        let zerofill = r.u8()? != 0;
        let n_relocs = r.u32()? as usize;
        let mut raw = Vec::with_capacity(n_relocs.min(1 << 20));
        for _ in 0..n_relocs {
            let r_address = r.u32()?;
            let r_info = r.u32()?;
            raw.push(RelocationInfo { r_address, r_info });
        }
        sections.push(InputSection::from_parts(crate::object::SectionParts {
            name: sname,
            segment,
            flags,
            align_log2,
            addr,
            data: data_start..data_end,
            size,
            zerofill,
            raw_relocs: raw,
        }));
    }
    let n_syms = r.u32()? as usize;
    let mut symbols = Vec::with_capacity(n_syms.min(1 << 20));
    for _ in 0..n_syms {
        let external = r.u8()? != 0;
        let stab = r.u8()? != 0;
        let section_raw = r.u32()?;
        let value = r.u64()?;
        let weakly_defined = r.u8()? != 0;
        let weakly_referenced = r.u8()? != 0;
        let common_raw = r.u32()?;
        let alt_entry = r.u8()? != 0;
        symbols.push(InputSymbol {
            name: crate::ids::StringId(0),
            external,
            stab,
            section: (section_raw != u32::MAX).then_some(section_raw as usize),
            value,
            weak_def: weakly_defined,
            weak_ref: weakly_referenced,
            common_align: (common_raw != u32::MAX).then_some(common_raw),
            alt_entry,
        });
    }
    let n_names = r.u32()? as usize;
    let mut symbol_names = Vec::with_capacity(n_names.min(1 << 20));
    for _ in 0..n_names {
        symbol_names.push(r.bytes()?.to_vec());
    }
    let n_atom_sects = r.u32()? as usize;
    let mut atoms = Vec::with_capacity(n_atom_sects.min(1 << 16));
    for _ in 0..n_atom_sects {
        let n = r.u32()? as usize;
        let mut ranges = Vec::with_capacity(n.min(1 << 20));
        for _ in 0..n {
            let start = r.u64()?;
            let end = r.u64()?;
            if end < start {
                return None;
            }
            ranges.push(start..end);
        }
        atoms.push(ranges);
    }
    // M30 (v3 payload): the data-in-code stream rides the tail.
    let n_dice = r.u32()? as usize;
    let mut data_in_code = Vec::with_capacity(n_dice.min(1 << 20));
    for _ in 0..n_dice {
        let offset = r.u32()?;
        let packed = r.u32()?;
        data_in_code.push(pgr_format::DataInCodeEntry {
            offset,
            length: packed as u16,
            kind: (packed >> 16) as u16,
        });
    }
    if r.at != r.b.len() {
        return None;
    }
    Some(InputObject::from_parts(crate::object::ObjectParts {
        file,
        name: name.to_string(),
        sections,
        symbols,
        symbol_names,
        atoms,
        data_in_code,
        subsections_via_symbols,
        from_archive,
        archive_name,
    }))
}

// ---- frozen .tbd codec -------------------------------------------------------

/// Serializes one parsed `.tbd`.
#[must_use]
pub fn encode_frozen_dylib(d: &FrozenDylib) -> Vec<u8> {
    let mut p = Vec::new();
    put_str(&mut p, &d.install_name);
    put_u32(&mut p, d.current_version);
    put_u32(&mut p, d.compatibility_version);
    put_u32(&mut p, d.exports.len() as u32);
    for e in &d.exports {
        put_bytes(&mut p, e);
    }
    frame(*FROZEN_TBD_MAGIC, &p)
}

/// Rebuilds one parsed `.tbd`; `None` on any inconsistency.
#[must_use]
pub fn decode_frozen_dylib(bytes: &[u8]) -> Option<FrozenDylib> {
    let Unframed { payload } = unframe(bytes, *FROZEN_TBD_MAGIC)?;
    let mut r = Reader { b: payload, at: 0 };
    let install_name = r.str()?;
    let current_version = r.u32()?;
    let compatibility_version = r.u32()?;
    let n = r.u32()? as usize;
    let mut exports = Vec::with_capacity(n.min(1 << 20));
    for _ in 0..n {
        exports.push(r.bytes()?.to_vec());
    }
    if r.at != r.b.len() {
        return None;
    }
    Some(FrozenDylib {
        install_name,
        current_version,
        compatibility_version,
        exports,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        FrozenDylib, PoiCache, decode_frozen_dylib, decode_poi, encode_frozen_dylib, encode_poi,
    };
    use crate::ids::FileId;
    use crate::link::LinkInput;
    use crate::resolve::Dylib;
    use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

    fn sample_object() -> (Vec<u8>, Vec<u8>) {
        // hello-ish object: text with relocs + cstring + symbols.
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
        let mut b = ObjectBuilder::new("hello.o").set_subsections_via_symbols(true);
        let sect = b.add_section(ObjectSection::text(
            "__text",
            text.clone(),
            vec![
                ObjectReloc::addend(0).at(0),
                ObjectReloc::page21(1).at(0),
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
        (b.build().unwrap(), text)
    }

    fn parse_object(bytes: Vec<u8>) -> crate::object::InputObject {
        let mut obj = crate::object::InputObject::parse(FileId(7), "hello.o", bytes).unwrap();
        obj.compute_atoms(true);
        obj
    }

    #[test]
    fn poi_roundtrip_preserves_the_parsed_shape() {
        let (bytes, _text) = sample_object();
        let bytes_for_finish = bytes.clone();
        let obj = parse_object(bytes);
        let enc = encode_poi(&obj, true);
        let dec = decode_poi(&enc, FileId(9), "hello.o", true).expect("decode");
        assert_eq!(dec.file.0, 9);
        assert_eq!(dec.name, "hello.o");
        assert_eq!(dec.subsections_via_symbols, obj.subsections_via_symbols);
        assert_eq!(dec.sections.len(), obj.sections.len());
        for (a, b) in dec.sections.iter().zip(obj.sections.iter()) {
            assert_eq!(a.name, b.name);
            assert_eq!(a.segment, b.segment);
            assert_eq!(a.flags, b.flags);
            assert_eq!(a.data, b.data);
            assert_eq!(a.zerofill, b.zerofill);
            assert_eq!(a.raw_relocs().len(), b.raw_relocs().len());
        }
        assert_eq!(dec.symbols.len(), obj.symbols.len());
        assert_eq!(dec.peek_symbol_names(), obj.peek_symbol_names());
        assert_eq!(dec.atoms, obj.atoms);

        // The decoded object finishes like a fresh parse: relocs decode.
        let (interner, ids) = Interner::build_with(dec.peek_symbol_names(), false);
        let mut dec = dec;
        dec.bytes = bytes_for_finish;
        dec.finish(&ids[..obj.symbols.len()]).unwrap();
        let _ = interner;
        assert!(!dec.sections[0].relocs.is_empty(), "relocs decoded");
    }

    #[test]
    fn poi_rejects_corruption_silently() {
        let (bytes, _) = sample_object();
        let obj = parse_object(bytes);
        let mut enc = encode_poi(&obj, true);
        // Flip a payload byte: checksum mismatch → None.
        let last = enc.len() - 1;
        enc[last] ^= 0xFF;
        assert!(decode_poi(&enc, FileId(1), "x", true).is_none());
        // Truncated frame → None.
        let enc = encode_poi(&obj, true);
        assert!(decode_poi(&enc[..enc.len() / 2], FileId(1), "x", true).is_none());
        // Wrong magic → None.
        let mut enc = encode_poi(&obj, true);
        enc[0] = b'X';
        assert!(decode_poi(&enc, FileId(1), "x", true).is_none());
    }

    use crate::interner::Interner;

    #[test]
    fn cache_dir_roundtrip_and_key_stability() {
        let (bytes, _) = sample_object();
        let obj = parse_object(bytes.clone());
        let dir = std::env::temp_dir().join(format!("pgr_poi_cache_{}", std::process::id()));
        let cache = PoiCache::open(&dir).unwrap();
        let key = PoiCache::content_key(&bytes, true);
        let key2 = PoiCache::content_key(&bytes, true);
        assert_eq!(key, key2, "keys are pure functions of content+flags");
        assert_ne!(key, PoiCache::content_key(&bytes, false), "flags split");
        cache.store(&key, &obj, true);
        let hit = cache
            .load(&key, FileId(3), "hello.o", bytes.clone(), true)
            .expect("hit");
        assert_eq!(hit.peek_symbol_names(), obj.peek_symbol_names());
        assert_eq!(hit.atoms, obj.atoms);
        assert_eq!(hit.file.0, 3);
        // A miss decodes to None without panicking.
        assert!(
            cache
                .load(&[9u8; 32], FileId(1), "x", Vec::new(), true)
                .is_none()
        );
        // Different bytes → different key → miss.
        let other = PoiCache::content_key(b"different-bytes", true);
        assert!(
            cache
                .load(&other, FileId(1), "x", Vec::new(), true)
                .is_none()
        );
    }

    #[test]
    fn cached_and_uncached_links_are_byte_identical() {
        // The §7.1 gate: a POI cache hit must produce the same layout.
        let (bytes, _) = sample_object();
        let greet = {
            let mut b = ObjectBuilder::new("greet.o");
            let t = b.add_section(ObjectSection::text(
                "__text",
                vec![0xC0, 0x03, 0x5F, 0xD6],
                vec![],
            ));
            b.add_symbol(ObjectSymbol::Defined {
                name: "_greet".into(),
                section_index: t,
                value: 0,
                weak: false,
            });
            b.build().unwrap()
        };
        let cfg = crate::layout::LinkConfig {
            ident: "cache-gate".into(),
            ..crate::layout::LinkConfig::default()
        };
        let inputs = vec![
            LinkInput {
                name: "hello.o".into(),
                bytes,
            },
            LinkInput {
                name: "greet.o".into(),
                bytes: greet,
            },
        ];
        let cold =
            crate::link::link_cached(&inputs, &[], &cfg, crate::Parallelism::Auto, None).unwrap();
        let dir = std::env::temp_dir().join(format!("pgr_poi_gate_{}", std::process::id()));
        let cache = PoiCache::open(&dir).unwrap();
        let warm =
            crate::link::link_cached(&inputs, &[], &cfg, crate::Parallelism::Auto, Some(&cache))
                .unwrap();
        assert_eq!(cold.layout.file_size, warm.layout.file_size);
        for (a, b) in cold.layout.sections.iter().zip(warm.layout.sections.iter()) {
            assert_eq!(a.size, b.size);
            assert_eq!(a.vm_addr, b.vm_addr);
            for (pa, pb) in a.pieces.iter().zip(b.pieces.iter()) {
                assert_eq!(pa.in_range, pb.in_range);
                assert_eq!(pa.patches, pb.patches);
            }
        }
    }

    #[test]
    fn frozen_tbd_roundtrip_and_corruption() {
        let d = Dylib {
            install_name: "/usr/lib/libSystem.B.dylib".into(),
            current_version: 1 << 16,
            compatibility_version: 1 << 16,
            exports: vec![b"_printf".to_vec(), b"_strlen".to_vec()],
            weak: false,
            reexport: false,
            lazy: false,
        };
        let frozen = FrozenDylib::from(&d);
        let enc = encode_frozen_dylib(&frozen);
        let dec = decode_frozen_dylib(&enc).expect("decode");
        assert_eq!(dec, frozen);
        let dylib: Dylib = dec.into();
        assert_eq!(dylib.install_name, d.install_name);
        assert_eq!(dylib.exports, d.exports);
        assert!(!dylib.weak, "weak stays a driver property");
        // Corruption → None.
        let mut enc = encode_frozen_dylib(&frozen);
        let last = enc.len() - 1;
        enc[last] ^= 0x55;
        assert!(decode_frozen_dylib(&enc).is_none());
    }
}

#[cfg(test)]
mod m7_versioned {
    //! M7 versioned-cache-format gates (architecture doc §10.3 row M7:
    //! "**versioned cache format**"; §7.1: "A cache entry also records the
    //! `pgr` format version and any parse-affecting flags" and
    //! "size-bounded with LRU eviction").
    use super::{
        CACHE_FORMAT_VERSION, FrozenDylib, PARSER_REVISION, PoiCache, decode_frozen_dylib,
        decode_poi, encode_frozen_dylib, encode_poi,
    };
    use crate::ids::FileId;
    use crate::resolve::Dylib;
    use pgr_fixtures::{ObjectBuilder, ObjectSection, ObjectSymbol};

    fn tiny_object(body: u8) -> (Vec<u8>, crate::object::InputObject) {
        let mut b = ObjectBuilder::new("tiny.o");
        let text = b.add_section(ObjectSection::text(
            "__text",
            vec![body, 0xC0, 0x03, 0x5F, 0xD6],
            vec![],
        ));
        b.add_symbol(ObjectSymbol::Defined {
            name: "_f".into(),
            section_index: text,
            value: 0,
            weak: false,
        });
        let bytes = b.build().unwrap();
        let mut obj =
            crate::object::InputObject::parse(FileId(1), "tiny.o", bytes.clone()).expect("parse");
        obj.compute_atoms(true);
        (bytes, obj)
    }

    fn tiny_dylib() -> FrozenDylib {
        FrozenDylib::from(&Dylib {
            install_name: "/usr/lib/libt.dylib".into(),
            current_version: 1 << 16,
            compatibility_version: 1 << 16,
            exports: vec![b"_f".to_vec()],
            weak: false,
            reexport: false,
            lazy: false,
        })
    }

    #[test]
    fn m7_hostile_frame_len_overflows_silently() {
        // Regression (cache_entries fuzzer, crash-642df7d7): a framed length
        // near usize::MAX wrapped `HEADER_LEN + len` and aborted. The decode
        // must be a silent miss instead.
        let mut hostile = Vec::with_capacity(56);
        hostile.extend_from_slice(b"PGRPOI1\0");
        hostile.extend_from_slice(&CACHE_FORMAT_VERSION.to_le_bytes());
        hostile.extend_from_slice(&PARSER_REVISION.to_le_bytes());
        hostile.extend_from_slice(&u64::MAX.to_le_bytes()); // len
        hostile.extend_from_slice(&[0u8; 32]); // checksum (never reached)
        assert!(decode_poi(&hostile, FileId(1), "tiny.o", true).is_none());
    }

    #[test]
    fn m7_frames_record_format_and_parser_revisions() {
        let (_bytes, obj) = tiny_object(0x91);
        let enc = encode_poi(&obj, true);
        assert_eq!(&enc[0..8], b"PGRPOI1\0", "magic stays");
        assert_eq!(
            u32::from_le_bytes(enc[8..12].try_into().unwrap()),
            CACHE_FORMAT_VERSION,
            "frame field 1 is the cache format version"
        );
        assert_eq!(
            u32::from_le_bytes(enc[12..16].try_into().unwrap()),
            PARSER_REVISION,
            "frame field 2 is the parser revision"
        );
        assert_eq!(CACHE_FORMAT_VERSION, 3, "M30 bumps the format to v3");
        let tenc = encode_frozen_dylib(&tiny_dylib());
        assert_eq!(
            u32::from_le_bytes(tenc[8..12].try_into().unwrap()),
            CACHE_FORMAT_VERSION
        );
        assert_eq!(
            u32::from_le_bytes(tenc[12..16].try_into().unwrap()),
            PARSER_REVISION
        );
        // Decodes agree.
        assert!(decode_poi(&enc, FileId(2), "tiny.o", true).is_some());
        assert!(decode_frozen_dylib(&tenc).is_some());
    }

    #[test]
    fn m7_v1_frames_are_silently_missed() {
        // Rebuild a legacy v1 frame (52-byte header: magic|ver|len|sha) around
        // the current payload: the v2 decoder must reject it (silent miss).
        use sha2::{Digest, Sha256};
        let (_bytes, obj) = tiny_object(0x92);
        let enc = encode_poi(&obj, true);
        let payload = &enc[56..];
        let mut v1 = Vec::with_capacity(52 + payload.len());
        v1.extend_from_slice(b"PGRPOI1\0");
        v1.extend_from_slice(&1u32.to_le_bytes());
        v1.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        let digest: [u8; 32] = Sha256::digest(payload).into();
        v1.extend_from_slice(&digest);
        v1.extend_from_slice(payload);
        assert!(
            decode_poi(&v1, FileId(1), "tiny.o", true).is_none(),
            "a v1 frame is not a v2 hit"
        );
    }

    #[test]
    fn m7_keys_bind_versions_and_flags() {
        // The v2 key is a pure function of (bytes, flags, format, parser) —
        // and it must differ from the v1 key shape (bytes ‖ flag) so stale
        // entries become unreachable, not merely unread.
        use sha2::{Digest, Sha256};
        let k_split = PoiCache::content_key(b"input-bytes", true);
        let k_nosplit = PoiCache::content_key(b"input-bytes", false);
        assert_ne!(k_split, k_nosplit, "flags split keys");
        let mut v1h = Sha256::new();
        v1h.update(b"input-bytes");
        v1h.update([1u8]);
        let v1_key: [u8; 32] = v1h.finalize().into();
        assert_ne!(k_split, v1_key, "v2 keys never collide with v1 keys");
        // Key stability: same inputs, same key (twice).
        assert_eq!(k_split, PoiCache::content_key(b"input-bytes", true));
    }

    #[test]
    fn m7_payload_flag_mismatch_is_a_miss() {
        let (_bytes, obj) = tiny_object(0x93);
        let enc = encode_poi(&obj, true);
        // The entry records the parse-affecting flag; a load that asks for
        // the other flag must not hit (defense in depth under key reuse).
        assert!(decode_poi(&enc, FileId(1), "tiny.o", true).is_some());
        assert!(decode_poi(&enc, FileId(1), "tiny.o", false).is_none());
    }

    #[test]
    fn m7_dir_marker_self_heals_foreign_and_legacy_dirs() {
        let dir = std::env::temp_dir().join(format!(
            "pgr_m7_marker_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // A "foreign" cache dir: a marker from a different format plus one
        // entry-shaped file and one scratch file.
        std::fs::write(dir.join(super::MARKER_NAME), b"garbage-from-another-pgr").unwrap();
        let stale_entry = dir.join("a".repeat(64));
        std::fs::write(&stale_entry, b"stale").unwrap();
        let stale_tmp = dir.join(".tmp-poi-999-1");
        std::fs::write(&stale_tmp, b"stale").unwrap();
        let stranger = dir.join("user-owns-this.txt");
        std::fs::write(&stranger, b"not ours").unwrap();
        // Opening heals: marker rewritten, our-shaped stale files removed,
        // foreign files untouched.
        let cache = PoiCache::open(&dir).unwrap();
        assert!(dir.join(super::MARKER_NAME).is_file(), "marker restored");
        let marker = std::fs::read(dir.join(super::MARKER_NAME)).unwrap();
        assert_eq!(&marker[0..17], b"PGR-CACHE-FORMAT\0");
        assert_eq!(
            u32::from_le_bytes(marker[17..21].try_into().unwrap()),
            CACHE_FORMAT_VERSION
        );
        assert_eq!(
            u32::from_le_bytes(marker[21..25].try_into().unwrap()),
            PARSER_REVISION
        );
        assert!(!stale_entry.exists(), "stale entry wiped");
        assert!(!stale_tmp.exists(), "stale temp wiped");
        assert!(stranger.is_file(), "files pgr does not own stay");
        // A legacy v1 dir (no marker, entry-shaped files) heals the same way.
        let legacy_entry = dir.join(format!("{:064x}", 42));
        std::fs::write(&legacy_entry, b"v1 entry").unwrap();
        std::fs::remove_file(dir.join(super::MARKER_NAME)).unwrap();
        let _cache2 = PoiCache::open(&dir).unwrap();
        assert!(!legacy_entry.exists(), "legacy v1 entries are reclaimed");
        assert!(dir.join(super::MARKER_NAME).is_file());
        // The healed cache stores and loads.
        let (bytes, obj) = tiny_object(0x94);
        let key = PoiCache::content_key(&bytes, true);
        cache.store(&key, &obj, true);
        let hit = cache.load(&key, FileId(3), "tiny.o", bytes, true);
        assert!(hit.is_some(), "healed cache still works");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn m7_size_bound_evicts_oldest_and_spares_the_new_entry() {
        let dir = std::env::temp_dir().join(format!(
            "pgr_m7_evict_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        // One entry is a few hundred bytes; cap at two entries' worth.
        let (_b1, o1) = tiny_object(0xA1);
        let (_b2, o2) = tiny_object(0xA2);
        let (_b3, o3) = tiny_object(0xA3);
        let e1 = encode_poi(&o1, true);
        let limit = (e1.len() as u64) * 2 + 10;
        let cache = PoiCache::open_limited(&dir, limit).unwrap();
        // Distinct key inputs (the object bytes share the Mach-O magic, so
        // the key material must not come from them).
        let k1 = PoiCache::content_key(&[0xA1], true);
        let k2 = PoiCache::content_key(&[0xA2], true);
        let k3 = PoiCache::content_key(&[0xA3], true);
        // Backdate mtimes so the eviction order is deterministic.
        let old = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000);
        let mid = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(2_000);
        cache.store(&k1, &o1, true);
        set_mtime(&dir.join(hex(&k1)), old);
        cache.store(&k2, &o2, true);
        set_mtime(&dir.join(hex(&k2)), mid);
        cache.store(&k3, &o3, true); // over limit → k1 (oldest) goes
        assert!(!dir.join(hex(&k1)).exists(), "oldest entry evicted");
        assert!(dir.join(hex(&k2)).exists(), "middle entry kept");
        assert!(
            dir.join(hex(&k3)).exists(),
            "just-stored entry never evicted"
        );
        let total: u64 = own_entries(&dir).iter().map(|(_, len, _)| *len).sum();
        assert!(
            total <= limit + e1.len() as u64,
            "size bounded (total {total})"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn m7_load_touches_recency_so_hot_entries_survive() {
        let dir = std::env::temp_dir().join(format!(
            "pgr_m7_lru_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let (b1, o1) = tiny_object(0xB1);
        let (_b2, o2) = tiny_object(0xB2);
        let (_b3, o3) = tiny_object(0xB3);
        let enc = encode_poi(&o1, true);
        let limit = (enc.len() as u64) * 2 + 10;
        let cache = PoiCache::open_limited(&dir, limit).unwrap();
        let k1 = PoiCache::content_key(&b1, true);
        let k2 = PoiCache::content_key(&[0xC2], true);
        let k3 = PoiCache::content_key(&[0xC3], true);
        let epoch = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(500);
        cache.store(&k1, &o1, true);
        set_mtime(&dir.join(hex(&k1)), epoch);
        cache.store(&k2, &o2, true);
        set_mtime(&dir.join(hex(&k2)), epoch);
        // A hit refreshes k1's recency…
        assert!(
            cache.load(&k1, FileId(1), "tiny.o", b1, true).is_some(),
            "k1 hits before the eviction pass"
        );
        // …so the third store evicts k2, not the hot k1.
        cache.store(&k3, &o3, true);
        assert!(dir.join(hex(&k1)).exists(), "recently used entry survives");
        assert!(!dir.join(hex(&k2)).exists(), "coldest entry evicted");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- helpers ------------------------------------------------------------

    fn hex(key: &[u8; 32]) -> String {
        let mut s = String::with_capacity(64);
        for b in key {
            s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
            s.push(char::from_digit(u32::from(b & 0xF), 16).unwrap_or('0'));
        }
        s
    }

    fn own_entries(dir: &std::path::Path) -> Vec<(std::path::PathBuf, u64, std::time::SystemTime)> {
        let mut out = Vec::new();
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().into_owned();
                let ok = name.len() == 64 && name.bytes().all(|c| c.is_ascii_hexdigit());
                if !ok {
                    continue;
                }
                let md = e.metadata().ok();
                let mtime = md
                    .as_ref()
                    .and_then(|m| m.modified().ok())
                    .unwrap_or(std::time::SystemTime::now());
                out.push((e.path(), md.map_or(0, |m| m.len()), mtime));
            }
        }
        out
    }

    fn set_mtime(path: &std::path::Path, t: std::time::SystemTime) {
        let f = std::fs::File::options().write(true).open(path).unwrap();
        f.set_modified(t).unwrap();
    }
}

#[cfg(test)]
mod hit_tests {
    use super::PoiCache;
    use crate::layout::LinkConfig;
    use crate::link::{LinkInput, link_cached};
    use pgr_fixtures::{ObjectBuilder, ObjectReloc, ObjectSection, ObjectSymbol};

    fn hello() -> Vec<u8> {
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
        let mut b = ObjectBuilder::new("hello.o").set_subsections_via_symbols(true);
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
        b.add_section(ObjectSection::cstring("hi\n"));
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
        let mut b = ObjectBuilder::new("greet.o").set_subsections_via_symbols(true);
        let t = b.add_section(ObjectSection::text(
            "__text",
            vec![0xC0, 0x03, 0x5F, 0xD6],
            vec![],
        ));
        b.add_symbol(ObjectSymbol::Defined {
            name: "_greet".into(),
            section_index: t,
            value: 0,
            weak: false,
        });
        b.build().unwrap()
    }

    /// Two consecutive links through one cache: the second link hits for
    /// every object and must stay error-free and byte-identical.
    #[test]
    fn consecutive_cache_hits_stay_identical() {
        let inputs = vec![
            LinkInput {
                name: "hello.o".into(),
                bytes: hello(),
            },
            LinkInput {
                name: "greet.o".into(),
                bytes: greet(),
            },
        ];
        let cfg = LinkConfig::default();
        let dir = std::env::temp_dir().join(format!("pgr_hit_{}", std::process::id()));
        let cache = PoiCache::open(&dir).unwrap();
        let cold = link_cached(&inputs, &[], &cfg, crate::Parallelism::Auto, None).unwrap();
        let _w1 = link_cached(&inputs, &[], &cfg, crate::Parallelism::Auto, Some(&cache)).unwrap();
        let w2 = link_cached(&inputs, &[], &cfg, crate::Parallelism::Auto, Some(&cache)).unwrap();
        assert_eq!(cold.layout.file_size, w2.layout.file_size);
        for (a, b) in cold.layout.symbols.iter().zip(w2.layout.symbols.iter()) {
            assert_eq!(a.name, b.name, "symbol identity drift on cache hits");
            assert_eq!(a.value, b.value);
        }
    }
}
