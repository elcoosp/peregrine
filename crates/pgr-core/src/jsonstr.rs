//! The JSON string-body decoder the workspace's two byte-cursor JSON
//! readers share (the map renderer's reader — `map.rs` — and the trace
//! timeline's reader — `trace.rs`). The decode contract is one shape:
//! the short escapes, the raw-control-byte refusal, one `\uXXXX` escape
//! with the surrogate-pair decode (a foreign writer may pair them; the
//! house writer's escapes are always single control characters), and
//! the whole body's UTF-8 check. The module is crate-internal (the
//! readers keep their own typed error enums — the callers map the
//! offset-tagged refusal onto their own `Invalid { at, detail }` arm,
//! the messages verbatim); the triplicated copy the two readers carried
//! was the micro-debt the M133 sweep healed — one contract, one decode.
//!
//! The verifier's report-JSON reader (`pgr-verify`'s `report_json.rs`)
//! carries its own variant of this shape: a different refusal alphabet
//! (`syntax` at offset, not `Invalid { at, detail }`) in a crate that
//! does not depend on this one — unifying it is a cross-crate seam this
//! sweep deliberately left alone.

/// One offset-tagged string-body refusal: the byte the decode sat on
/// when it refused, and the detail the reader's own error arm carries
/// verbatim.
pub(crate) struct JsonStringError {
    /// The byte the refusal names.
    pub at: usize,
    /// The detail (the caller's error arm carries it verbatim).
    pub detail: String,
}

/// Decodes one JSON string body (the bytes after the opening quote; the
/// caller consumed it) to the closing quote, the cursor left one past
/// the closing quote — or one past the document on the unterminated
/// refusals (the original readers' cursor contract, preserved).
///
/// `utf8_detail` names the whole-body UTF-8 refusal (the two readers
/// name their own document: the map's and the trace's).
pub(crate) fn parse_json_string(
    s: &[u8],
    pos: &mut usize,
    utf8_detail: &'static str,
) -> Result<String, JsonStringError> {
    let start = *pos;
    let mut out: Vec<u8> = Vec::new();
    loop {
        let Some(&b) = s.get(*pos) else {
            *pos = s.len();
            return Err(JsonStringError {
                at: *pos,
                detail: "unterminated string".into(),
            });
        };
        *pos += 1;
        match b {
            b'"' => {
                return String::from_utf8(out).map_err(|_| JsonStringError {
                    at: start,
                    detail: utf8_detail.into(),
                });
            }
            b'\\' => {
                let Some(&esc) = s.get(*pos) else {
                    *pos = s.len();
                    return Err(JsonStringError {
                        at: *pos,
                        detail: "unterminated escape".into(),
                    });
                };
                *pos += 1;
                match esc {
                    b'"' => out.push(b'"'),
                    b'\\' => out.push(b'\\'),
                    b'/' => out.push(b'/'),
                    b'b' => out.push(0x08),
                    b'f' => out.push(0x0C),
                    b'n' => out.push(b'\n'),
                    b'r' => out.push(b'\r'),
                    b't' => out.push(b'\t'),
                    b'u' => out.extend(parse_unicode_escape(s, pos)?),
                    _ => {
                        return Err(JsonStringError {
                            at: *pos,
                            detail: format!("unknown escape \\{}", esc as char),
                        });
                    }
                }
            }
            b if b < 0x20 => {
                return Err(JsonStringError {
                    at: *pos,
                    detail: "raw control byte in string".into(),
                });
            }
            _ => out.push(b),
        }
    }
}

/// One `\uXXXX` escape (a surrogate pair decoded when the high half
/// leads — a foreign writer may pair them; the house writer's escapes
/// are always single control characters).
fn parse_unicode_escape(s: &[u8], pos: &mut usize) -> Result<Vec<u8>, JsonStringError> {
    let hi = hex4(s, pos)?;
    let cp = if (0xD800..=0xDBFF).contains(&hi) {
        if peek(s, pos)? != b'\\' {
            return Err(JsonStringError {
                at: *pos,
                detail: "unpaired high surrogate".into(),
            });
        }
        *pos += 1;
        if peek(s, pos)? != b'u' {
            return Err(JsonStringError {
                at: *pos,
                detail: "unpaired high surrogate".into(),
            });
        }
        *pos += 1;
        let lo = hex4(s, pos)?;
        if !(0xDC00..=0xDFFF).contains(&lo) {
            return Err(JsonStringError {
                at: *pos,
                detail: "unpaired low surrogate".into(),
            });
        }
        0x1_0000 + ((u32::from(hi) - 0xD800) << 10) + (u32::from(lo) - 0xDC00)
    } else if (0xDC00..=0xDFFF).contains(&hi) {
        return Err(JsonStringError {
            at: *pos,
            detail: "unpaired low surrogate".into(),
        });
    } else {
        u32::from(hi)
    };
    let mut buf = [0u8; 4];
    let enc = char::from_u32(cp)
        .ok_or_else(|| JsonStringError {
            at: *pos,
            detail: "the escape names no Unicode scalar".into(),
        })?
        .encode_utf8(&mut buf);
    Ok(enc.as_bytes().to_vec())
}

/// Four hex digits (the `\u` payload).
fn hex4(s: &[u8], pos: &mut usize) -> Result<u16, JsonStringError> {
    let mut v: u16 = 0;
    for _ in 0..4 {
        let b = peek(s, pos)?;
        let d = match b {
            b'0'..=b'9' => u16::from(b - b'0'),
            b'a'..=b'f' => u16::from(b - b'a') + 10,
            b'A'..=b'F' => u16::from(b - b'A') + 10,
            _ => {
                return Err(JsonStringError {
                    at: *pos,
                    detail: "expected a hex digit in \\u escape".into(),
                });
            }
        };
        *pos += 1;
        v = (v << 4) | d;
    }
    Ok(v)
}

/// The byte under the cursor (the readers' `peek` shape: whitespace
/// skipped first, the refusal at the post-skip cursor).
fn peek(s: &[u8], pos: &mut usize) -> Result<u8, JsonStringError> {
    while matches!(s.get(*pos), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        *pos += 1;
    }
    s.get(*pos).copied().ok_or_else(|| JsonStringError {
        at: *pos,
        detail: "unexpected end of document".into(),
    })
}
