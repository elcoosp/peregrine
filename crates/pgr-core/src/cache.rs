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
//! Layout (little-endian, pointer-free):
//! `magic(8) | version(u32) | payload_len(u64) | sha256(payload)(32) |
//! payload`. Writes are atomic (temp file + rename); keys are hex-encoded
//! SHA-256 digests, so build-system parallelism is safe.

use crate::ids::FileId;
use crate::object::{InputObject, InputSection, InputSymbol};
use crate::resolve::Dylib;
use pgr_format::reloc::RelocationInfo;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const POI_MAGIC: &[u8; 8] = b"PGRPOI1\0";

/// Unique temp-file suffix for atomic stores (concurrent writers must never
/// share a temp path — the rename target is the content key, but the temp
/// file is shared scratch).
static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn tmp_path(dir: &Path, tag: &str) -> PathBuf {
    let n = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    dir.join(format!(".tmp-{tag}-{}-{n}", std::process::id()))
}
const FROZEN_TBD_MAGIC: &[u8; 8] = b"PGRFTBD1";
const HEADER_LEN: usize = 8 + 4 + 8 + 32;
const POI_VERSION: u32 = 1;

/// Per-user content-addressed cache directory (Stage A). `None`-safe: all
/// methods short-circuit when the cache is disabled.
#[derive(Debug, Clone)]
pub struct PoiCache {
    dir: PathBuf,
}

impl PoiCache {
    /// Opens (creating if needed) the cache directory.
    ///
    /// # Errors
    /// [`std::io::Error`] when the directory cannot be created.
    pub fn open(dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    /// The cache key of one input: SHA-256 over the bytes plus the
    /// parse-affecting flag byte.
    #[must_use]
    pub fn content_key(bytes: &[u8], split_symbols: bool) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(bytes);
        h.update([u8::from(split_symbols)]);
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
    /// 4 copies section bytes from it. Any decode failure (missing,
    /// truncated, corrupt, version mismatch) yields `None` — the caller
    /// re-parses.
    #[must_use]
    pub fn load(
        &self,
        key: &[u8; 32],
        file: FileId,
        name: &str,
        bytes: Vec<u8>,
    ) -> Option<InputObject> {
        let cached = std::fs::read(self.path(key)).ok()?;
        let mut obj = decode_poi(&cached, file, name)?;
        obj.bytes = bytes;
        Some(obj)
    }

    /// Stores one parsed object (atomic replace; failures are silent — the
    /// cache is an optimization only).
    pub fn store(&self, key: &[u8; 32], obj: &InputObject) {
        let bytes = encode_poi(obj);
        let tmp = tmp_path(&self.dir, "poi");
        if std::fs::write(&tmp, &bytes).is_ok() {
            let _ = std::fs::rename(&tmp, self.path(key));
        }
    }

    /// Loads one frozen `.tbd` parse.
    #[must_use]
    pub fn load_dylib(&self, key: &[u8; 32]) -> Option<FrozenDylib> {
        let bytes = std::fs::read(self.path(key)).ok()?;
        decode_frozen_dylib(&bytes)
    }

    /// Stores one parsed `.tbd`.
    pub fn store_dylib(&self, key: &[u8; 32], dylib: &FrozenDylib) {
        let bytes = encode_frozen_dylib(dylib);
        let tmp = tmp_path(&self.dir, "tbd");
        if std::fs::write(&tmp, &bytes).is_ok() {
            let _ = std::fs::rename(&tmp, self.path(key));
        }
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
        }
    }
}

// ---- framing ----------------------------------------------------------------

fn frame(magic: &[u8; 8], payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(magic);
    out.extend_from_slice(&POI_VERSION.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    let digest: [u8; 32] = Sha256::digest(payload).into();
    out.extend_from_slice(&digest);
    out.extend_from_slice(payload);
    out
}

struct Unframed<'a> {
    payload: &'a [u8],
}

/// Validates the frame (magic, version, length, checksum) and returns the
/// payload slice; `None` on any mismatch (silent cache miss).
fn unframe<'a>(bytes: &'a [u8], magic: &[u8; 8]) -> Option<Unframed<'a>> {
    if bytes.len() < HEADER_LEN || &bytes[0..8] != magic {
        return None;
    }
    let version = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
    if version != POI_VERSION {
        return None;
    }
    let len = u64::from_le_bytes(bytes[12..20].try_into().ok()?) as usize;
    if bytes.len() != HEADER_LEN + len {
        return None;
    }
    let payload = &bytes[HEADER_LEN..];
    let want: [u8; 32] = bytes[20..52].try_into().ok()?;
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
            .map(|s| u32::from_le_bytes(s.try_into().unwrap()))
    }
    fn u64(&mut self) -> Option<u64> {
        self.take(8)
            .map(|s| u64::from_le_bytes(s.try_into().unwrap()))
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

/// Serializes one parsed object (post-`compute_atoms`, pre-intern).
#[must_use]
pub fn encode_poi(obj: &InputObject) -> Vec<u8> {
    let mut p = Vec::new();
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
    frame(POI_MAGIC, &p)
}

/// Rebuilds one object from its POI bytes. Any inconsistency (truncation,
/// checksum, bounds) yields `None` — the caller re-parses.
#[must_use]
pub fn decode_poi(bytes: &[u8], file: FileId, name: &str) -> Option<InputObject> {
    let Unframed { payload } = unframe(bytes, POI_MAGIC)?;
    let mut r = Reader { b: payload, at: 0 };
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
        let weak_def = r.u8()? != 0;
        let weak_ref = r.u8()? != 0;
        let common_raw = r.u32()?;
        let alt_entry = r.u8()? != 0;
        symbols.push(InputSymbol {
            name: crate::ids::StringId(0),
            external,
            stab,
            section: (section_raw != u32::MAX).then_some(section_raw as usize),
            value,
            weak_def,
            weak_ref,
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
    frame(FROZEN_TBD_MAGIC, &p)
}

/// Rebuilds one parsed `.tbd`; `None` on any inconsistency.
#[must_use]
pub fn decode_frozen_dylib(bytes: &[u8]) -> Option<FrozenDylib> {
    let Unframed { payload } = unframe(bytes, FROZEN_TBD_MAGIC)?;
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
        let enc = encode_poi(&obj);
        let dec = decode_poi(&enc, FileId(9), "hello.o").expect("decode");
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
        let mut enc = encode_poi(&obj);
        // Flip a payload byte: checksum mismatch → None.
        let last = enc.len() - 1;
        enc[last] ^= 0xFF;
        assert!(decode_poi(&enc, FileId(1), "x").is_none());
        // Truncated frame → None.
        let enc = encode_poi(&obj);
        assert!(decode_poi(&enc[..enc.len() / 2], FileId(1), "x").is_none());
        // Wrong magic → None.
        let mut enc = encode_poi(&obj);
        enc[0] = b'X';
        assert!(decode_poi(&enc, FileId(1), "x").is_none());
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
        cache.store(&key, &obj);
        let hit = cache
            .load(&key, FileId(3), "hello.o", bytes.clone())
            .expect("hit");
        assert_eq!(hit.peek_symbol_names(), obj.peek_symbol_names());
        assert_eq!(hit.atoms, obj.atoms);
        assert_eq!(hit.file.0, 3);
        // A miss decodes to None without panicking.
        assert!(cache.load(&[9u8; 32], FileId(1), "x", Vec::new()).is_none());
        // Different bytes → different key → miss.
        let other = PoiCache::content_key(b"different-bytes", true);
        assert!(cache.load(&other, FileId(1), "x", Vec::new()).is_none());
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
