//! M119: the `LC_DYSYMTAB` module table contract — the read-side backstop
//! the producer's emit-side gate mirrors. When the command carries a
//! module table (`nmodtab > 0`, the `-single_module` shape), the table's
//! bytes fit the file and every entry's `ilocalsym`/`nlocalsym`/
//! `iextdefsym`/`nextdefsym` subrange stays within the `LC_SYMTAB`'s
//! symbol count. The producer validates the same contract at emit under
//! `-single_module` (it writes exactly one well-formed entry whose
//! subranges mirror the `LC_DYSYMTAB`'s); the verifier reports it
//! read-side regardless of how the table was produced (the M115
//! read-side-backstop shape — a malformed table the producer never wrote
//! still reports).

use crate::{Code, Issue, Report};

/// Walks the load commands for `LC_SYMTAB` and `LC_DYSYMTAB`; when the
/// dysymtab carries a module table (`nmodtab > 0`), the table slice must
/// fit the file (the `DysymtabCommand::modules` bounds gate) and every
/// entry's `ilocalsym`/`nlocalsym`/`iextdefsym`/`nextdefsym` subrange must
/// stay within `LC_SYMTAB.nsyms`. A truncated table, an out-of-bounds
/// `modtaboff`, a misaligned table, or an entry whose subranges exceed the
/// symbol table is the malformed shape dyld's two-level-namespace consumer
/// would misread. The default `-multi_module` shape (`nmodtab = 0`) is
/// inert — nothing to validate (the pre-M119 bytes peregrine always
/// carried).
pub(crate) fn check_module_table(bytes: &[u8], report: &mut Report) {
    let Ok(hdr) = pgr_format::MachHeader64::parse(bytes) else {
        return; // the header gate reports its own issue
    };
    let Ok(mut it) = pgr_format::LoadCommandIter::new(
        bytes,
        pgr_format::MachHeader64::SIZE,
        hdr.ncmds,
        hdr.sizeofcmds,
    ) else {
        return;
    };
    let mut symtab: Option<pgr_format::SymtabCommand> = None;
    let mut dysymtab: Option<pgr_format::DysymtabCommand> = None;
    let mut dys_off: u64 = 0;
    while let Ok(Some(cmd)) = it.next_command() {
        match cmd.kind {
            pgr_format::LoadCommandKind::Symtab if symtab.is_none() => {
                symtab = pgr_format::SymtabCommand::parse(cmd.bytes, 0).ok();
            }
            pgr_format::LoadCommandKind::Dysymtab if dysymtab.is_none() => {
                dys_off = u64::try_from(cmd.offset).unwrap_or(0);
                dysymtab = pgr_format::DysymtabCommand::parse(cmd.bytes, 0).ok();
            }
            _ => {}
        }
    }
    let Some(dys) = dysymtab else {
        return; // no LC_DYSYMTAB — the structural pass reports its own absence
    };
    if dys.nmodtab == 0 {
        return; // the default -multi_module shape — no module table to validate
    }
    let nsyms = symtab.map_or(0, |st| st.nsyms);
    match dys.modules(bytes) {
        Ok(modules) => {
            for entry in modules {
                let local_end =
                    u64::from(entry.ilocalsym).saturating_add(u64::from(entry.nlocalsym));
                let extdef_end =
                    u64::from(entry.iextdefsym).saturating_add(u64::from(entry.nextdefsym));
                if local_end > u64::from(nsyms) || extdef_end > u64::from(nsyms) {
                    report.issues.push(Issue::error(
                        Code::ModuleTable,
                        format!(
                            "LC_DYSYMTAB module table entry subranges exceed the symbol table \
                             (ilocalsym {}+{} or iextdefsym {}+{} > nsyms {}) — dyld's \
                             two-level-namespace consumer reads the entry's subranges against \
                             the symbol table",
                            entry.ilocalsym,
                            entry.nlocalsym,
                            entry.iextdefsym,
                            entry.nextdefsym,
                            nsyms,
                        ),
                        Some(dys_off),
                    ));
                    return;
                }
            }
        }
        Err(what) => {
            report.issues.push(Issue::error(
                Code::ModuleTable,
                format!(
                    "LC_DYSYMTAB module table (nmodtab {}, modtaboff {:#x}) is malformed — \
                     {what} (the producer's -single_module emit-side gate writes one \
                     well-formed 8-aligned entry; a malformed table the producer never \
                     wrote still reports read-side)",
                    dys.nmodtab, dys.modtaboff,
                ),
                Some(dys_off),
            ));
        }
    }
}
