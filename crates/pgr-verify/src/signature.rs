//! Code-signature verification: `SuperBlob` layout and SHA-256 page-hash
//! recomputation (TDD §9, §11 "signature recompute").

use crate::structural::ParsedImage;
use crate::{Code, Issue, Report, issue_from};
use pgr_format::consts::{
    CS_HASHTYPE_SHA256, CS_PAGE_SIZE, CS_PAGE_SIZE_LOG2, CS_SHA256_LEN, CSSLOT_CODEDIRECTORY,
};
use sha2::{Digest, Sha256};

/// Validates the `LC_CODE_SIGNATURE` `SuperBlob` and, when `recompute` is set,
/// recomputes every 4 KiB page hash and compares it against the
/// `CodeDirectory`.
pub(crate) fn check_signature(
    bytes: &[u8],
    img: &ParsedImage<'_>,
    recompute: bool,
    report: &mut Report,
) {
    let Some(lc) = img.code_signature else {
        report.issues.push(Issue::error(
            Code::SignatureLayout,
            "arm64 images require an ad-hoc code signature (LC_CODE_SIGNATURE)",
            None,
        ));
        return;
    };
    let file_len = bytes.len() as u64;
    if u64::from(lc.dataoff) >= file_len
        || u64::from(lc.dataoff) + u64::from(lc.datasize) != file_len
    {
        report.issues.push(Issue::error(
            Code::SignatureLayout,
            format!(
                "signature must be the last bytes of the file (ends {:#x}, file size {:#x})",
                u64::from(lc.dataoff) + u64::from(lc.datasize),
                file_len
            ),
            Some(u64::from(lc.dataoff)),
        ));
    }
    if lc.dataoff == 0 || lc.datasize == 0 {
        report.issues.push(Issue::error(
            Code::SignatureLayout,
            "signature dataoff/datasize must be nonzero",
            Some(u64::from(lc.dataoff)),
        ));
        return;
    }
    let sb_bytes = match lc.data(bytes) {
        Ok(b) => b,
        Err(e) => {
            report.issues.push(issue_from(&e, Code::SignatureLayout));
            return;
        }
    };
    let sb = match pgr_format::SuperBlob::parse(sb_bytes) {
        Ok(sb) => sb,
        Err(e) => {
            report.issues.push(issue_from(&e, Code::SignatureLayout));
            return;
        }
    };
    let blob = match sb.blob_for_slot(CSSLOT_CODEDIRECTORY) {
        Ok(Some(b)) => b,
        Ok(None) => {
            report.issues.push(Issue::error(
                Code::SignatureLayout,
                "SuperBlob carries no code directory slot",
                Some(u64::from(lc.dataoff)),
            ));
            return;
        }
        Err(e) => {
            report.issues.push(issue_from(&e, Code::SignatureLayout));
            return;
        }
    };
    let cd = match pgr_format::CodeDirectory::parse(blob) {
        Ok(cd) => cd,
        Err(e) => {
            report.issues.push(issue_from(&e, Code::SignatureLayout));
            return;
        }
    };
    if cd.hash_size != CS_SHA256_LEN as u8 {
        report.issues.push(Issue::error(
            Code::SignatureLayout,
            format!("hash size {} is not SHA-256 (32)", cd.hash_size),
            Some(u64::from(lc.dataoff)),
        ));
    }
    if cd.hash_type != CS_HASHTYPE_SHA256 {
        report.issues.push(Issue::error(
            Code::SignatureLayout,
            format!(
                "hash type {} is not SHA-256 ({CS_HASHTYPE_SHA256})",
                cd.hash_type
            ),
            Some(u64::from(lc.dataoff)),
        ));
    }
    if cd.page_size_log2 != CS_PAGE_SIZE_LOG2 {
        report.issues.push(Issue::error(
            Code::SignatureLayout,
            format!(
                "page size exponent {} != {CS_PAGE_SIZE_LOG2} (4 KiB code pages, TDD §3.6)",
                cd.page_size_log2
            ),
            Some(u64::from(lc.dataoff)),
        ));
    }
    if u64::from(cd.code_limit) != u64::from(lc.dataoff) {
        report.issues.push(Issue::error(
            Code::SignatureLayout,
            format!(
                "codeLimit {:#x} must equal the signature offset {:#x}",
                cd.code_limit, lc.dataoff
            ),
            Some(u64::from(lc.dataoff)),
        ));
    }
    let expected_slots = u64::from(cd.code_limit).div_ceil(CS_PAGE_SIZE) as u32;
    if cd.n_code_slots != expected_slots {
        report.issues.push(Issue::error(
            Code::SignatureLayout,
            format!(
                "nCodeSlots {} != ceil(codeLimit / 4096) = {expected_slots}",
                cd.n_code_slots
            ),
            Some(u64::from(lc.dataoff)),
        ));
    }
    if cd.identifier(blob).is_err() {
        report.issues.push(Issue::error(
            Code::SignatureLayout,
            "CodeDirectory identifier is missing or unterminated",
            Some(u64::from(lc.dataoff)),
        ));
    }
    if let Some(limit) = cd.exec_seg_limit {
        let text_vmsize = img
            .segments
            .iter()
            .find(|s| s.name() == Ok("__TEXT"))
            .map_or(0, |s| s.vmsize);
        if limit != text_vmsize {
            report.issues.push(Issue::warning(
                Code::Suspicious,
                format!("execSegLimit {limit:#x} != __TEXT vmsize {text_vmsize:#x}"),
                Some(u64::from(lc.dataoff)),
            ));
        }
    }
    if cd.code_hashes(blob).is_err() {
        report.issues.push(Issue::error(
            Code::SignatureLayout,
            "code hash array extends beyond the code directory blob",
            Some(u64::from(lc.dataoff)),
        ));
        return;
    }

    if !recompute {
        return;
    }
    let Ok(hashes) = cd.code_hashes(blob) else {
        return;
    };
    let hash_len = cd.hash_size as usize;
    for slot in 0..cd.n_code_slots as usize {
        let start = slot * CS_PAGE_SIZE as usize;
        let end = ((slot + 1) * CS_PAGE_SIZE as usize).min(cd.code_limit as usize);
        if start >= cd.code_limit as usize {
            break;
        }
        let mut h = Sha256::new();
        h.update(&bytes[start..end]);
        let digest = h.finalize();
        let stored = &hashes[slot * hash_len..(slot + 1) * hash_len];
        if digest.as_slice() != stored {
            report.issues.push(Issue::error(
                Code::SignatureHashMismatch,
                format!(
                    "page {slot} (file range [{start:#x}, {end:#x})): stored hash does not match recomputed SHA-256"
                ),
                Some(start as u64),
            ));
            return; // first mismatch is enough; the file content is wrong
        }
        report.stats.hash_pages += 1;
    }
}
