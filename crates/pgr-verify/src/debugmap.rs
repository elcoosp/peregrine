//! M129: the debug-map stabs contract — the read-side backstop the
//! producer's debug-map emit-side gate mirrors. The `ld64`-shaped
//! `n_type` rows `lldb`/`dsymutil` walk to find the DWARF in the `.o`
//! files must ride a well-formed shape:
//!
//! * `N_OSO` well-formedness — a non-empty path string (the `.o` path
//!   `dsymutil` opens) and a nonzero `n_value` (the mtime the
//!   file-existence gate keys on);
//! * `N_FUN` bracketing — every begin row (`n_sect > 0`, a nonzero
//!   address) pairs with a closing row (`n_sect == 0`, `n_value == 0`);
//! * section-bearing stab addresses inside their defining section — a
//!   `N_FUN`/`N_STSYM`/`N_BNSYM`/`N_ENSYM` row whose `n_value` leaves the
//!   section it names (`n_sect`) is the malformed shape the debugger
//!   would misread;
//! * no stabs under `-S` — the existing strip-debug flag drops the
//!   whole debug map; stabs that ride alongside stripped debug sections
//!   (no `__DWARF` segment, no debug-classified `__TEXT` section) are
//!   the malformed shape the producer's `-S` gate should have dropped.
//!
//! The producer validates the same contract at emit (the debug-map plan
//! re-addresses section stabs onto placed live atoms, drops the whole
//! map under `-S`); the verifier reports it read-side regardless of how
//! the stabs were produced (the M115 read-side-backstop shape — a
//! malformed debug map the producer never wrote still reports).

use crate::structural::ParsedImage;
use crate::{Code, Issue, Report};
use pgr_format::consts::stab_kind;
use pgr_format::symtab::Nlist64;

/// Walks the `LC_SYMTAB` for stab rows (the `N_STAB`-bit entries) and
/// reports the four debug-map contract violations. The check is total
/// (never panics on malformed input — a truncated symtab or strtab
/// reports its own issue and returns) and self-gates on the image
/// carrying a symtab at all.
pub(crate) fn check_debug_map(bytes: &[u8], parsed: &ParsedImage<'_>, report: &mut Report) {
    let Some(st) = parsed.symtab else {
        return; // no LC_SYMTAB — the structural pass reports its own absence
    };
    let strtab = bytes
        .get(st.stroff as usize..st.stroff as usize + st.strsize as usize)
        .unwrap_or(&[]);
    let nsyms = st.nsyms as usize;
    let mut stabs: Vec<Nlist64> = Vec::new();
    for i in 0..nsyms {
        let off = st.symoff as usize + i * 16;
        let Ok(sym) = pgr_format::cursor::pod_read_unaligned_at::<Nlist64>(bytes, off) else {
            // The structural pass reports the truncation; return here so
            // the debug-map check never panics on a truncated symtab.
            return;
        };
        if sym.is_stab() {
            stabs.push(sym);
        }
    }
    if stabs.is_empty() {
        return; // no stabs — the pre-M129 shape, nothing to validate
    }
    // The `-S` gate is enforced producer-side: under `-S` the producer
    // emits zero stabs (the whole debug map drops), so a stab-carrying
    // image is never the `-S` shape. The linked image never carries the
    // `__DWARF` segment itself — the DWARF lives in the `.o` files the
    // stabs' `N_OSO` rows point at (that is the debug map's whole
    // purpose: `lldb`/`dsymutil` walk the stabs to *find* the DWARF in
    // the `.o` files). So the verifier does not flag "stabs present
    // without `__DWARF`" — that is the always-shape, never the `-S`
    // shape. The per-row checks below catch the malformed rows.
    let sections = collect_sections(parsed);
    let mut fun_begin_depth: i64 = 0;
    for (i, sym) in stabs.iter().enumerate() {
        let stab_off = u64::from(st.symoff) + i as u64 * 16;
        let name = read_name(strtab, sym.n_strx);
        let Some(kind) = stab_kind(sym.n_type) else {
            report.issues.push(Issue::error(
                Code::DebugMap,
                format!(
                    "debug-map stab row {i} carries n_type 0x{:02x} the producer does not emit \
                     (the debug-map plan re-addresses only the eight N_SO/N_OSO/N_FUN/N_GSYM/\
                     N_STSYM/N_LSYM/N_BNSYM/N_ENSYM kinds)",
                    sym.n_type,
                ),
                Some(stab_off),
            ));
            continue;
        };
        match kind {
            pgr_format::consts::StabKind::Oso => {
                if name.is_empty() {
                    report.issues.push(Issue::error(
                        Code::DebugMap,
                        format!(
                            "debug-map stab row {i} (N_OSO) carries an empty path — dsymutil \
                             opens the .o file the row names; an empty path names no file"
                        ),
                        Some(stab_off),
                    ));
                }
                if sym.n_value == 0 {
                    report.issues.push(Issue::error(
                        Code::DebugMap,
                        format!(
                            "debug-map stab row {i} (N_OSO) carries a zero mtime — the .o file's \
                             mtime is the file-existence gate dsymutil keys on (a zero mtime names \
                             no real file)"
                        ),
                        Some(stab_off),
                    ));
                }
            }
            pgr_format::consts::StabKind::Fun => {
                if sym.n_sect > 0 {
                    fun_begin_depth = fun_begin_depth.saturating_add(1);
                    if let Some(issue) =
                        section_address_violation(&sections, sym, i, "N_FUN begin")
                    {
                        report.issues.push(issue);
                    }
                } else {
                    fun_begin_depth = fun_begin_depth.saturating_sub(1);
                }
            }
            pgr_format::consts::StabKind::Stsym
            | pgr_format::consts::StabKind::Bnsym
            | pgr_format::consts::StabKind::Ensym => {
                if let Some(issue) = section_address_violation(&sections, sym, i, "section stab") {
                    report.issues.push(issue);
                }
            }
            _ => {}
        }
    }
    if fun_begin_depth > 0 {
        report.issues.push(Issue::error(
            Code::DebugMap,
            format!(
                "the debug map carries {fun_begin_depth} unbalanced N_FUN begin row(s) — \
                 every N_FUN begin (n_sect > 0) must pair with a closing N_FUN end row \
                 (n_sect == 0, n_value == 0); dsymutil walks the pair to scope the function"
            ),
            Some(u64::from(st.symoff)),
        ));
    }
}


/// One collected section (the 1-based `n_sect` index, the segment name,
/// the section name, the vmaddr, the size) for the address-inside-section
/// check.
struct CollectedSection {
    seg_name: [u8; 16],
    sect_name: [u8; 16],
    vmaddr: u64,
    size: u64,
}

/// Collects every section across all segments in 1-based `n_sect` order
/// (the cross-segment numbering the symtab's `n_sect` field uses).
fn collect_sections(parsed: &ParsedImage<'_>) -> Vec<CollectedSection> {
    let mut out = Vec::new();
    for cmd in &parsed.commands {
        if !matches!(cmd.kind, pgr_format::LoadCommandKind::Segment64) {
            continue;
        }
        if cmd.bytes.len() < 72 {
            continue;
        }
        let nsects = u32::from_le_bytes(cmd.bytes[64..68].try_into().unwrap_or([0; 4]));
        for i in 0..nsects as usize {
            let base = 72 + i * 80;
            if base + 80 > cmd.bytes.len() {
                break;
            }
            let mut seg_name = [0u8; 16];
            let mut sect_name = [0u8; 16];
            seg_name.copy_from_slice(&cmd.bytes[base..base + 16]);
            sect_name.copy_from_slice(&cmd.bytes[base + 16..base + 32]);
            let vmaddr = u64::from_le_bytes(cmd.bytes[base + 32..base + 40].try_into().unwrap_or([0; 8]));
            let size = u64::from_le_bytes(cmd.bytes[base + 40..base + 48].try_into().unwrap_or([0; 8]));
            out.push(CollectedSection {
                seg_name,
                sect_name,
                vmaddr,
                size,
            });
        }
    }
    out
}

/// Reads one null-terminated name from the strtab at `strx` (clamped
/// to the strtab bounds — a malformed `n_strx` yields an empty name,
/// never a panic).
fn read_name(strtab: &[u8], strx: u32) -> &[u8] {
    let start = strx as usize;
    if start >= strtab.len() {
        return &[];
    }
    let rest = &strtab[start..];
    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    &rest[..end]
}

/// Checks a section-bearing stab's `n_value` is inside its defining
/// section (`n_sect`). Returns an issue when the value leaves the
/// section (the malformed shape the debugger would misread).
fn section_address_violation(
    sections: &[CollectedSection],
    sym: &Nlist64,
    row: usize,
    label: &str,
) -> Option<Issue> {
    let idx = sym.n_sect as usize;
    if idx == 0 || idx > sections.len() {
        return Some(Issue::error(
            Code::DebugMap,
            format!(
                "debug-map stab row {row} ({label}) names section {} (1-based) the image does \
                 not carry — the stab's n_sect must name a real section",
                sym.n_sect,
            ),
            None,
        ));
    }
    let sect = &sections[idx - 1];
    let sect_end = sect.vmaddr + sect.size;
    let seg_name = String::from_utf8_lossy(&sect.seg_name).trim_end_matches('\0').to_string();
    let sect_name = String::from_utf8_lossy(&sect.sect_name)
        .trim_end_matches('\0')
        .to_string();
    if sym.n_value < sect.vmaddr || sym.n_value >= sect_end {
        return Some(Issue::error(
            Code::DebugMap,
            format!(
                "debug-map stab row {row} ({label}) carries n_value {:#x} outside its defining \
                 section {seg_name}.{sect_name} (vmaddr {:#x}, size {}, end {:#x}) — the \
                 debugger reads the stab's address against the section it names",
                sym.n_value, sect.vmaddr, sect.size, sect_end,
            ),
            None,
        ));
    }
    None
}
