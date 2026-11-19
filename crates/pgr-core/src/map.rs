//! The link map (M11 rung 2): a structured, human-readable report of the
//! placed image — segments, their sections, and the symbols each section
//! carries. The data is the layout plan's own (`Layout::segments`,
//! `Layout::sections`, `Layout::symbols`) re-grouped for consumption; the
//! builder is a pure function of the plan, and the render is
//! deterministic (segments in plan order, symbols by address then name —
//! no hash iteration order reaches the text).
//!
//! The map is the build-system-facing seam ld64's `-map` serves: "what
//! landed where, and why is my binary this size". It reads the *plan* —
//! the same plan the fused emit writes — so the report and the bytes
//! cannot disagree.
//!
//! M55 adds the machine face: [`LinkMap::render_json`] is the
//! deterministic compact interchange (fixed key order, one line, the
//! report-JSON escape rules) and [`parse_link_map_json`] the strict
//! reader — a rigid schema (unknown or duplicate keys refuse,
//! integer-only numbers, no trailing commas, byte-positioned
//! [`MapJsonError`]s) with the data model's own structural gate (a
//! section's `seg_name` must name the segment it rode in on). The round
//! trip is gated beside the text render's gates (`tests/m55_map_json.rs`).

use crate::interner::Interner;
use crate::layout::Layout;

/// One symbol row in the map: its name, output address, and visibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapSymbol {
    /// The symbol name.
    pub name: String,
    /// Output vaddr (the `n_value` the symtab carries).
    pub value: u64,
    /// True when the symbol is exported (the dysymtab extdef surface).
    pub external: bool,
}

/// One section row: the placed section and the symbols that landed in it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MapSection {
    /// Output section name (`__text`...).
    pub name: String,
    /// Owning output segment name.
    pub seg_name: String,
    /// Absolute vaddr of the section start.
    pub vm_addr: u64,
    /// Section size in bytes.
    pub size: u64,
    /// File offset (0 for zero-fill sections).
    pub file_off: u64,
    /// True when the section is zero-fill (no file bytes).
    pub zerofill: bool,
    /// The section's symbols, by address then name.
    pub symbols: Vec<MapSymbol>,
}

/// One segment row: the `LC_SEGMENT_64` summary and its sections.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MapSegment {
    /// Segment name.
    pub name: String,
    /// vaddr start.
    pub vmaddr: u64,
    /// Virtual size (covers zero-fill tails).
    pub vmsize: u64,
    /// File offset.
    pub fileoff: u64,
    /// File-backed size.
    pub filesize: u64,
    /// The segment's sections, in plan order.
    pub sections: Vec<MapSection>,
}

/// The placed image's map: segments → sections → symbols. Build with
/// [`build_link_map`], render with [`LinkMap::render`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LinkMap {
    /// The signature identifier the image carries.
    pub ident: String,
    /// The Mach-O file type word (`MH_EXECUTE`/`MH_DYLIB`/`MH_BUNDLE`).
    pub filetype: u32,
    /// Total file size.
    pub file_size: u64,
    /// The segments, in plan order.
    pub segments: Vec<MapSegment>,
}

/// Builds the link map from a finished plan. Pure: the same layout and
/// interner render the same map, byte for byte.
#[must_use]
pub fn build_link_map(layout: &Layout, interner: &Interner) -> LinkMap {
    // Section rows in plan order; `n_sect` indexes this vec (1-based).
    let mut sections: Vec<MapSection> = layout
        .sections
        .iter()
        .map(|s| MapSection {
            name: s.name.clone(),
            seg_name: s.seg_name.clone(),
            vm_addr: s.vm_addr,
            size: s.size,
            file_off: s.file_off,
            zerofill: s.zerofill,
            symbols: Vec::new(),
        })
        .collect();
    for sym in &layout.symbols {
        if sym.n_sect == 0 {
            // Absolute symbols name no section; the map is a placement
            // report, so they ride no row (the symtab still carries them).
            continue;
        }
        let Some(row) = sections.get_mut(usize::from(sym.n_sect - 1)) else {
            continue;
        };
        row.symbols.push(MapSymbol {
            name: interner.name(sym.name),
            value: sym.value,
            external: sym.external,
        });
    }
    for row in &mut sections {
        // Deterministic rows: by address, then name (the plan's own order
        // is canonical already; the explicit sort keeps the render stable
        // against future symtab-order changes).
        row.symbols
            .sort_by(|a, b| a.value.cmp(&b.value).then_with(|| a.name.cmp(&b.name)));
    }
    let segments = layout
        .segments
        .iter()
        .map(|seg| MapSegment {
            name: seg.name.clone(),
            vmaddr: seg.vmaddr,
            vmsize: seg.vmsize,
            fileoff: seg.fileoff,
            filesize: seg.filesize,
            sections: seg
                .sections
                .iter()
                .filter_map(|si| sections.get(*si).cloned())
                .collect(),
        })
        .collect();
    LinkMap {
        ident: layout.ident.clone(),
        filetype: layout.filetype,
        file_size: layout.file_size,
        segments,
    }
}

impl LinkMap {
    /// Renders the map as deterministic text: one segment per block, one
    /// section per line, symbols indented under their section. The
    /// format is ld64-map-shaped (`#`-prefixed header, columns) — a
    /// build system can diff two maps line by line.
    #[must_use]
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(4096);
        s.push_str("# Peregrine link map\n");
        let _ = writeln!(s, "# ident: {}", self.ident);
        let _ = writeln!(s, "# filetype: {:#x}", self.filetype);
        let _ = writeln!(s, "# file size: {}", self.file_size);
        for seg in &self.segments {
            let _ = writeln!(
                s,
                "segment {:<16} vm 0x{:08x}..0x{:08x}  file 0x{:08x}..0x{:08x}",
                seg.name,
                seg.vmaddr,
                seg.vmaddr + seg.vmsize,
                seg.fileoff,
                seg.fileoff + seg.filesize,
            );
            for sect in &seg.sections {
                let _ = writeln!(
                    s,
                    "  section {:<12} vm 0x{:08x}  size 0x{:x}  file 0x{:x}{}",
                    sect.name,
                    sect.vm_addr,
                    sect.size,
                    sect.file_off,
                    if sect.zerofill { " (zerofill)" } else { "" },
                );
                for sym in &sect.symbols {
                    let _ = writeln!(
                        s,
                        "    0x{:08x}  {}{}",
                        sym.value,
                        sym.name,
                        if sym.external { "" } else { "  [local]" },
                    );
                }
            }
        }
        s
    }

    /// Renders the map as deterministic, compact JSON (M55): fixed key
    /// order, one line, the report-JSON escape rules — the house
    /// interchange writer (`pgr-verify`'s `report_json`). The shape is
    /// rigid: `parse_link_map_json` restores the exact data (the
    /// round-trip gate rides the module's tests and
    /// `tests/m55_map_json.rs`), so a build system reads segments,
    /// sections, sizes and symbols without a custom parser.
    #[must_use]
    pub fn render_json(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(256 + self.segments.len() * 512);
        let _ = write!(
            s,
            "{{\"ident\":{},\"filetype\":{},\"file_size\":{},\"segments\":[",
            escape_json(&self.ident),
            self.filetype,
            self.file_size,
        );
        for (si, seg) in self.segments.iter().enumerate() {
            if si > 0 {
                s.push(',');
            }
            let _ = write!(
                s,
                "{{\"name\":{},\"vmaddr\":{},\"vmsize\":{},\"fileoff\":{},\"filesize\":{},\"sections\":[",
                escape_json(&seg.name),
                seg.vmaddr,
                seg.vmsize,
                seg.fileoff,
                seg.filesize,
            );
            for (ti, sect) in seg.sections.iter().enumerate() {
                if ti > 0 {
                    s.push(',');
                }
                let _ = write!(
                    s,
                    "{{\"name\":{},\"seg_name\":{},\"vm_addr\":{},\"size\":{},\"file_off\":{},\"zerofill\":{},\"symbols\":[",
                    escape_json(&sect.name),
                    escape_json(&sect.seg_name),
                    sect.vm_addr,
                    sect.size,
                    sect.file_off,
                    sect.zerofill,
                );
                for (yi, sym) in sect.symbols.iter().enumerate() {
                    if yi > 0 {
                        s.push(',');
                    }
                    let _ = write!(
                        s,
                        "{{\"name\":{},\"value\":{},\"external\":{}}}",
                        escape_json(&sym.name),
                        sym.value,
                        sym.external,
                    );
                }
                s.push_str("]}");
            }
            s.push_str("]}");
        }
        s.push_str("]}");
        s
    }
}

/// JSON string escaping (the report-JSON rules): quotes, backslashes and
/// control characters ride `\"` `\\` `\n` `\r` `\t` and `\uXXXX`;
/// everything else — the multibyte UTF-8 included — verbatim. The house
/// writer's escape: the M56 provenance interchange shares it (one
/// escape table per crate, never a third copy).
pub(crate) fn escape_json(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The map JSON reader's refusals: the shape named, the byte positioned
/// (the `ReportJsonError` convention — typed, the fix in the message).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MapJsonError {
    /// The document is not the map's shape at `at`.
    #[error("invalid link-map JSON at byte {at}: {detail}")]
    Invalid {
        /// The byte the parser refused.
        at: usize,
        /// What the parser expected there.
        detail: String,
    },
    /// A field carries a value or a key the map's schema refuses.
    #[error("link-map JSON field `{name}`: {detail}")]
    Field {
        /// The refused field (or the unknown key, verbatim).
        name: String,
        /// Why the value refused.
        detail: String,
    },
}

/// Parses the link-map JSON the interchange writer emits — and the same
/// rigid schema any conforming writer produces (keys in any order, the
/// map's exact fields, no floats, no trailing commas). The reader
/// restores the writer's data exactly: the round-trip is gated in the
/// module's tests and `tests/m55_map_json.rs`.
///
/// # Errors
/// [`MapJsonError::Invalid`] on a malformed document (byte-positioned),
/// [`MapJsonError::Field`] on a key or value the map's schema refuses
/// (unknown or duplicate keys, a missing field, a non-u64 number, a
/// section whose `seg_name` names another segment than the one it rides
/// in on).
pub fn parse_link_map_json(raw: &str) -> Result<LinkMap, MapJsonError> {
    let mut rd = MapJsonReader {
        s: raw.as_bytes(),
        pos: 0,
    };
    let map = rd.parse_map()?;
    rd.skip_ws();
    if rd.pos != rd.s.len() {
        return rd.invalid("trailing bytes after the map object");
    }
    Ok(map)
}

/// The strict map-JSON reader: a recursive descent over the schema the
/// writer emits (byte-positioned [`MapJsonError`]s; integer-only numbers;
/// unknown, duplicate and missing keys refuse).
struct MapJsonReader<'a> {
    /// The document bytes.
    s: &'a [u8],
    /// The cursor.
    pos: usize,
}

impl MapJsonReader<'_> {
    /// A shape refusal at the current byte.
    fn invalid<T>(&self, detail: impl Into<String>) -> Result<T, MapJsonError> {
        Err(MapJsonError::Invalid {
            at: self.pos,
            detail: detail.into(),
        })
    }

    /// A field refusal (a key or value the schema refuses).
    fn field<T>(name: impl Into<String>, detail: impl Into<String>) -> Result<T, MapJsonError> {
        Err(MapJsonError::Field {
            name: name.into(),
            detail: detail.into(),
        })
    }

    /// Skips the JSON whitespace the compact writer never emits but a
    /// hand-edited document may carry.
    fn skip_ws(&mut self) {
        while matches!(self.s.get(self.pos), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    /// The next non-whitespace byte, or an end-of-document refusal.
    fn peek(&mut self) -> Result<u8, MapJsonError> {
        self.skip_ws();
        match self.s.get(self.pos) {
            Some(&b) => Ok(b),
            None => self.invalid("unexpected end of document"),
        }
    }

    /// Consumes the exact byte `c` (post-whitespace).
    fn expect(&mut self, c: u8) -> Result<(), MapJsonError> {
        let got = self.peek()?;
        if got != c {
            return self.invalid(format!("expected {:?}, found {:?}", c as char, got as char));
        }
        self.pos += 1;
        Ok(())
    }

    /// The next `"`key`":` pair inside an object: `Ok(None)` on the
    /// object's closing brace, the decoded key otherwise (the `:` is
    /// consumed). `first` marks the object's opening field (no comma
    /// precedes it — a leading or trailing comma is the malformed shape).
    fn next_key(&mut self, first: bool) -> Result<Option<String>, MapJsonError> {
        if self.peek()? == b'}' {
            self.pos += 1;
            return Ok(None);
        }
        if first {
            // The opening field carries no comma (`{,` is the malformed
            // shape — the parse below refuses the non-`"` byte).
        } else {
            self.expect(b',')?;
            if self.peek()? == b'}' {
                return self.invalid("trailing comma in object");
            }
        }
        let key = self.parse_string()?;
        self.expect(b':')?;
        Ok(Some(key))
    }

    /// Fills one object's slot, refusing a duplicate key by name.
    fn set<T>(slot: &mut Option<T>, name: impl Into<String>, value: T) -> Result<(), MapJsonError> {
        if slot.is_some() {
            return Err(MapJsonError::Field {
                name: name.into(),
                detail: "duplicate key".into(),
            });
        }
        *slot = Some(value);
        Ok(())
    }

    /// Requires one object's slot to be filled (the missing-field refusal
    /// names the key).
    fn require<T>(slot: Option<T>, name: &str) -> Result<T, MapJsonError> {
        slot.ok_or_else(|| MapJsonError::Field {
            name: name.to_string(),
            detail: "missing field".into(),
        })
    }

    /// A JSON string: the writer's escapes decoded, multibyte UTF-8 kept
    /// verbatim, raw control bytes refused.
    fn parse_string(&mut self) -> Result<String, MapJsonError> {
        self.expect(b'"')?;
        let start = self.pos;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let Some(&b) = self.s.get(self.pos) else {
                self.pos = self.s.len();
                return self.invalid("unterminated string");
            };
            self.pos += 1;
            match b {
                b'"' => {
                    return String::from_utf8(out).map_err(|_| MapJsonError::Invalid {
                        at: start,
                        detail: "the map JSON must be UTF-8".into(),
                    });
                }
                b'\\' => {
                    let Some(&esc) = self.s.get(self.pos) else {
                        self.pos = self.s.len();
                        return self.invalid("unterminated escape");
                    };
                    self.pos += 1;
                    match esc {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0C),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => out.extend(self.parse_unicode_escape()?),
                        _ => {
                            return self.invalid(format!("unknown escape \\{}", esc as char));
                        }
                    }
                }
                b if b < 0x20 => return self.invalid("raw control byte in string"),
                _ => out.push(b),
            }
        }
    }

    /// One `\uXXXX` escape (a surrogate pair decoded when the high half
    /// leads — a foreign writer may pair them; the house writer's escapes
    /// are always single control characters).
    fn parse_unicode_escape(&mut self) -> Result<Vec<u8>, MapJsonError> {
        let hi = self.hex4()?;
        let cp = if (0xD800..=0xDBFF).contains(&hi) {
            if self.peek()? != b'\\' {
                return self.invalid("unpaired high surrogate");
            }
            self.pos += 1;
            if self.peek()? != b'u' {
                return self.invalid("unpaired high surrogate");
            }
            self.pos += 1;
            let lo = self.hex4()?;
            if !(0xDC00..=0xDFFF).contains(&lo) {
                return self.invalid("unpaired low surrogate");
            }
            0x1_0000 + ((u32::from(hi) - 0xD800) << 10) + (u32::from(lo) - 0xDC00)
        } else if (0xDC00..=0xDFFF).contains(&hi) {
            return self.invalid("unpaired low surrogate");
        } else {
            u32::from(hi)
        };
        let mut buf = [0u8; 4];
        let enc = char::from_u32(cp)
            .ok_or_else(|| MapJsonError::Invalid {
                at: self.pos,
                detail: "the escape names no Unicode scalar".into(),
            })?
            .encode_utf8(&mut buf);
        Ok(enc.as_bytes().to_vec())
    }

    /// Four hex digits (the `\u` payload).
    fn hex4(&mut self) -> Result<u16, MapJsonError> {
        let mut v: u16 = 0;
        for _ in 0..4 {
            let b = self.peek()?;
            let d = match b {
                b'0'..=b'9' => u16::from(b - b'0'),
                b'a'..=b'f' => u16::from(b - b'a') + 10,
                b'A'..=b'F' => u16::from(b - b'A') + 10,
                _ => return self.invalid("expected a hex digit in \\u escape"),
            };
            self.pos += 1;
            v = (v << 4) | d;
        }
        Ok(v)
    }

    /// A non-negative integer: digits only — the map schema carries no
    /// floats or exponents, and every value is u64.
    fn parse_u64(&mut self) -> Result<u64, MapJsonError> {
        let b = self.peek()?;
        if !b.is_ascii_digit() {
            return self.invalid(format!(
                "expected a non-negative integer, found {:?}",
                b as char
            ));
        }
        let start = self.pos;
        while matches!(self.s.get(self.pos), Some(d) if d.is_ascii_digit()) {
            self.pos += 1;
        }
        let digits =
            std::str::from_utf8(&self.s[start..self.pos]).map_err(|_| MapJsonError::Invalid {
                at: start,
                detail: "the map JSON must be UTF-8".into(),
            })?;
        digits.parse::<u64>().map_err(|_| MapJsonError::Field {
            name: "number".into(),
            detail: format!("{digits} exceeds u64"),
        })
    }

    /// One u64 field's value (the `:` consumed by [`Self::next_key`]).
    fn u64_field(&mut self, name: &str) -> Result<u64, MapJsonError> {
        match self.parse_u64() {
            Ok(v) => Ok(v),
            Err(MapJsonError::Field { detail, .. }) => Self::field(name.to_string(), detail),
            Err(e @ MapJsonError::Invalid { .. }) => Err(e),
        }
    }

    /// One boolean field's value.
    fn bool_field(&mut self, name: &str) -> Result<bool, MapJsonError> {
        match self.peek()? {
            b't' if self.s[self.pos..].starts_with(b"true") => {
                self.pos += 4;
                Ok(true)
            }
            b'f' if self.s[self.pos..].starts_with(b"false") => {
                self.pos += 5;
                Ok(false)
            }
            _ => Self::field(name, "expected a boolean"),
        }
    }

    /// An array of objects (no trailing comma — the writer never emits
    /// one and a drifted reader would not notice it).
    fn parse_array<T>(
        &mut self,
        name: &str,
        mut element: impl FnMut(&mut Self) -> Result<T, MapJsonError>,
    ) -> Result<Vec<T>, MapJsonError> {
        self.expect(b'[')?;
        let mut out = Vec::new();
        loop {
            if self.peek()? == b']' {
                self.pos += 1;
                return Ok(out);
            }
            if !out.is_empty() {
                self.expect(b',')?;
                if self.peek()? == b']' {
                    return Self::field(name, "trailing comma in array");
                }
            }
            out.push(element(self)?);
        }
    }

    /// The top-level map object: `ident`, `filetype`, `file_size`,
    /// `segments` — all required, none twice, no unknown keys.
    fn parse_map(&mut self) -> Result<LinkMap, MapJsonError> {
        self.expect(b'{')?;
        let mut ident = None;
        let mut filetype = None;
        let mut file_size = None;
        let mut segments = None;
        let mut first = true;
        while let Some(key) = self.next_key(first)? {
            first = false;
            match key.as_str() {
                "ident" => Self::set(&mut ident, &key, self.parse_string()?)?,
                "filetype" => {
                    let v = self.u64_field(&key)?;
                    if v > u64::from(u32::MAX) {
                        return Self::field(&key, "exceeds the 32-bit MH_ file-type word");
                    }
                    Self::set(&mut filetype, &key, v)?;
                }
                "file_size" => Self::set(&mut file_size, &key, self.u64_field(&key)?)?,
                "segments" => {
                    let segs = self.parse_array(&key, Self::parse_segment)?;
                    Self::set(&mut segments, &key, segs)?;
                }
                _ => return Self::field(&key, "unknown field"),
            }
        }
        Ok(LinkMap {
            ident: Self::require(ident, "ident")?,
            filetype: u32::try_from(Self::require(filetype, "filetype")?).map_err(|_| {
                MapJsonError::Field {
                    name: "filetype".into(),
                    detail: "exceeds the 32-bit MH_ file-type word".into(),
                }
            })?,
            file_size: Self::require(file_size, "file_size")?,
            segments: Self::require(segments, "segments")?,
        })
    }

    /// One segment object: `name`, `vmaddr`, `vmsize`, `fileoff`,
    /// `filesize`, `sections` — and the parent gate: every section's
    /// `seg_name` must name this segment (the data model's own invariant —
    /// `build_link_map` groups sections by their owning segment).
    fn parse_segment(&mut self) -> Result<MapSegment, MapJsonError> {
        self.expect(b'{')?;
        let mut name = None;
        let mut vmaddr = None;
        let mut vmsize = None;
        let mut fileoff = None;
        let mut filesize = None;
        let mut sections = None;
        let mut first = true;
        while let Some(key) = self.next_key(first)? {
            first = false;
            match key.as_str() {
                "name" => Self::set(&mut name, &key, self.parse_string()?)?,
                "vmaddr" => Self::set(&mut vmaddr, &key, self.u64_field(&key)?)?,
                "vmsize" => Self::set(&mut vmsize, &key, self.u64_field(&key)?)?,
                "fileoff" => Self::set(&mut fileoff, &key, self.u64_field(&key)?)?,
                "filesize" => Self::set(&mut filesize, &key, self.u64_field(&key)?)?,
                "sections" => {
                    let sects = self.parse_array(&key, Self::parse_section)?;
                    Self::set(&mut sections, &key, sects)?;
                }
                _ => return Self::field(&key, "unknown field"),
            }
        }
        let seg = MapSegment {
            name: Self::require(name, "name")?,
            vmaddr: Self::require(vmaddr, "vmaddr")?,
            vmsize: Self::require(vmsize, "vmsize")?,
            fileoff: Self::require(fileoff, "fileoff")?,
            filesize: Self::require(filesize, "filesize")?,
            sections: Self::require(sections, "sections")?,
        };
        for sect in &seg.sections {
            if sect.seg_name != seg.name {
                return Self::field(
                    "seg_name",
                    format!(
                        "section {} names segment {} but rides in {} — a section's \
                         seg_name is the segment it landed in",
                        sect.name, sect.seg_name, seg.name
                    ),
                );
            }
        }
        Ok(seg)
    }

    /// One section object: `name`, `seg_name`, `vm_addr`, `size`,
    /// `file_off`, `zerofill`, `symbols`.
    fn parse_section(&mut self) -> Result<MapSection, MapJsonError> {
        self.expect(b'{')?;
        let mut name = None;
        let mut seg_name = None;
        let mut vm_addr = None;
        let mut size = None;
        let mut file_off = None;
        let mut zerofill = None;
        let mut symbols = None;
        let mut first = true;
        while let Some(key) = self.next_key(first)? {
            first = false;
            match key.as_str() {
                "name" => Self::set(&mut name, &key, self.parse_string()?)?,
                "seg_name" => Self::set(&mut seg_name, &key, self.parse_string()?)?,
                "vm_addr" => Self::set(&mut vm_addr, &key, self.u64_field(&key)?)?,
                "size" => Self::set(&mut size, &key, self.u64_field(&key)?)?,
                "file_off" => Self::set(&mut file_off, &key, self.u64_field(&key)?)?,
                "zerofill" => Self::set(&mut zerofill, &key, self.bool_field(&key)?)?,
                "symbols" => {
                    let syms = self.parse_array(&key, Self::parse_symbol)?;
                    Self::set(&mut symbols, &key, syms)?;
                }
                _ => return Self::field(&key, "unknown field"),
            }
        }
        Ok(MapSection {
            name: Self::require(name, "name")?,
            seg_name: Self::require(seg_name, "seg_name")?,
            vm_addr: Self::require(vm_addr, "vm_addr")?,
            size: Self::require(size, "size")?,
            file_off: Self::require(file_off, "file_off")?,
            zerofill: Self::require(zerofill, "zerofill")?,
            symbols: Self::require(symbols, "symbols")?,
        })
    }

    /// One symbol row: `name`, `value`, `external`.
    fn parse_symbol(&mut self) -> Result<MapSymbol, MapJsonError> {
        self.expect(b'{')?;
        let mut name = None;
        let mut value = None;
        let mut external = None;
        let mut first = true;
        while let Some(key) = self.next_key(first)? {
            first = false;
            match key.as_str() {
                "name" => Self::set(&mut name, &key, self.parse_string()?)?,
                "value" => Self::set(&mut value, &key, self.u64_field(&key)?)?,
                "external" => Self::set(&mut external, &key, self.bool_field(&key)?)?,
                _ => return Self::field(&key, "unknown field"),
            }
        }
        Ok(MapSymbol {
            name: Self::require(name, "name")?,
            value: Self::require(value, "value")?,
            external: Self::require(external, "external")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixups::FixupPlan;
    use crate::interner::Interner;
    use crate::layout::{LinkeditPlan, OutputSymbol, PlacedSection, SegmentPlan};

    /// A tiny hand-built plan: one segment, two sections, three symbols.
    fn tiny_layout() -> Layout {
        // The symbol names are interned with the same name table the
        // test's builder uses (id order: `_gamma` then `_alpha`).
        let (_, ids) = Interner::build(&[b"_gamma".to_vec(), b"_alpha".to_vec()]);
        let sect = PlacedSection {
            name: "__text".into(),
            seg_name: "__TEXT".into(),
            flags: 0,
            align_log2: 2,
            vm_addr: 0x1000,
            size: 16,
            file_off: 0x1000,
            zerofill: false,
            pieces: Vec::new(),
        };
        let data = PlacedSection {
            name: "__data".into(),
            seg_name: "__DATA".into(),
            flags: 0,
            align_log2: 3,
            vm_addr: 0x2000,
            size: 8,
            file_off: 0x2000,
            zerofill: false,
            pieces: Vec::new(),
        };
        Layout {
            ident: "tiny".into(),
            filetype: 2,
            order_unmatched: Vec::new(),
            cstring_order_unmatched: Vec::new(),
            image_base: 0,
            segments: vec![SegmentPlan {
                name: "__TEXT".into(),
                vmaddr: 0x1000,
                vmsize: 16,
                fileoff: 0x1000,
                filesize: 16,
                maxprot: 5,
                initprot: 5,
                sections: vec![0],
            }],
            sections: vec![sect, data],
            linkedit: LinkeditPlan::default(),
            header_bytes: Vec::new(),
            entryoff_at: 0,
            file_size: 0x2010,
            entryoff: 0,
            text_vmsize: 16,
            symbols: vec![
                OutputSymbol {
                    name: ids[1],
                    n_type: 0x0f,
                    n_sect: 1,
                    n_desc: 0,
                    value: 0x1004,
                    external: true,
                },
                OutputSymbol {
                    name: ids[0],
                    n_type: 0x0f,
                    n_sect: 1,
                    n_desc: 0,
                    value: 0x1000,
                    external: true,
                },
            ],
            trie: Vec::new(),
            func_starts: Vec::new(),
            data_in_code: Vec::new(),
            strtab: Vec::new(),
            str_offsets: Vec::new(),
            indirect_syms: Vec::new(),
            fixups: FixupPlan {
                payload: Vec::new(),
                chain_word_format: crate::fixups::FixupPointerFormat::Offset64,
                slot_words: Vec::new(),
                chain_starts: Vec::new(),
                slot_count: 0,
                imports: Vec::new(),
                import_names: Vec::new(),
                has_weak_binds: false,
                stable_keys: Vec::new(),
            },
            dyld_info: None,
            runs: Vec::new(),
            resolved: Vec::new(),
        }
    }

    #[test]
    fn the_map_groups_symbols_by_address_then_name() {
        let layout = tiny_layout();
        let (interner, _) = Interner::build(&[b"_gamma".to_vec(), b"_alpha".to_vec()]);
        let map = build_link_map(&layout, &interner);
        let text = &map.segments[0].sections[0];
        let names: Vec<&str> = text.symbols.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            ["_gamma", "_alpha"],
            "address order, not table order"
        );
    }

    #[test]
    fn the_render_is_deterministic_and_ld64_shaped() {
        let layout = tiny_layout();
        let (interner, _) = Interner::build(&[b"_gamma".to_vec(), b"_alpha".to_vec()]);
        let a = build_link_map(&layout, &interner).render();
        let b = build_link_map(&layout, &interner).render();
        assert_eq!(a, b, "the same plan renders byte-identical maps");
        assert!(a.starts_with("# Peregrine link map"));
        assert!(a.contains("segment __TEXT"));
        assert!(a.contains("section __text"));
        assert!(a.contains("0x00001000  _gamma"));
        assert!(a.contains("0x00001004  _alpha"));
    }

    // ---- M55: the JSON interchange -----------------------------------------

    /// A two-segment hand-built map (distinct `seg_name` values, so the
    /// reader's parent-segment gate has a false-shape to refuse).
    fn hand_map() -> LinkMap {
        LinkMap {
            ident: "hand".into(),
            filetype: 2,
            file_size: 0x2010,
            segments: vec![
                MapSegment {
                    name: "__TEXT".into(),
                    vmaddr: 0x1000,
                    vmsize: 16,
                    fileoff: 0x1000,
                    filesize: 16,
                    sections: vec![MapSection {
                        name: "__text".into(),
                        seg_name: "__TEXT".into(),
                        vm_addr: 0x1000,
                        size: 16,
                        file_off: 0x1000,
                        zerofill: false,
                        symbols: vec![
                            MapSymbol {
                                name: "_alpha".into(),
                                value: 0x1004,
                                external: true,
                            },
                            MapSymbol {
                                name: "_gamma".into(),
                                value: 0x1000,
                                external: false,
                            },
                        ],
                    }],
                },
                MapSegment {
                    name: "__DATA".into(),
                    vmaddr: 0x2000,
                    vmsize: 8,
                    fileoff: 0x2000,
                    filesize: 8,
                    sections: vec![MapSection {
                        name: "__data".into(),
                        seg_name: "__DATA".into(),
                        vm_addr: 0x2000,
                        size: 8,
                        file_off: 0x2000,
                        zerofill: true,
                        symbols: Vec::new(),
                    }],
                },
            ],
        }
    }

    #[test]
    fn the_json_round_trips_the_hand_built_map() {
        let map = hand_map();
        let json = map.render_json();
        let parsed = parse_link_map_json(&json).expect("the hand-built map parses");
        assert_eq!(parsed, map, "the reader restores the writer's data");
        assert_eq!(parsed.render_json(), json, "the re-render is identical");
    }

    #[test]
    fn the_json_render_is_deterministic_and_compact() {
        let map = hand_map();
        let a = map.render_json();
        let b = map.render_json();
        assert_eq!(a, b, "the same map renders byte-identical JSON");
        assert!(
            a.starts_with("{\"ident\":\"hand\""),
            "fixed key order, one line"
        );
        assert!(!a.contains('\n'), "the interchange is compact");
    }

    #[test]
    fn the_json_escapes_hostile_strings() {
        let mut map = hand_map();
        map.ident = "we\"ird\\map\n".into();
        map.segments[0].sections[0].symbols[0].name = "_sym\"quote\\".into();
        let json = map.render_json();
        let parsed = parse_link_map_json(&json).expect("the escaped map parses");
        assert_eq!(parsed, map, "the escape round-trips");
    }

    #[test]
    fn the_reader_refuses_the_broken_shapes() {
        let map = hand_map();
        let json = map.render_json();

        // A non-object document.
        assert!(parse_link_map_json("[]").is_err(), "the map is an object");
        // A truncated document.
        assert!(
            parse_link_map_json(&json[..json.len() - 1]).is_err(),
            "a truncated map refuses"
        );
        // An unknown key (the interchange is a rigid shape).
        let doctored = json.replace("\"filetype\":", "\"filetypo\":");
        assert!(
            parse_link_map_json(&doctored).is_err(),
            "a typo'd key refuses"
        );
        // A negative address (every address and size is u64).
        let doctored = json.replace("\"vmaddr\":4096", "\"vmaddr\":-4096");
        assert!(
            parse_link_map_json(&doctored).is_err(),
            "a negative base refuses"
        );
        // A section's seg_name disagreeing with the segment it rode in on.
        let doctored = json.replace("\"seg_name\":\"__DATA\"", "\"seg_name\":\"__OTHER\"");
        let err = parse_link_map_json(&doctored).expect_err("a misfiled section refuses");
        assert!(
            err.to_string().contains("__OTHER"),
            "the refusal names the misfiled shape: {err}"
        );
        // A trailing value after the object.
        let doctored = format!("{json} trailing");
        assert!(
            parse_link_map_json(&doctored).is_err(),
            "trailing bytes refuse"
        );
    }
}
