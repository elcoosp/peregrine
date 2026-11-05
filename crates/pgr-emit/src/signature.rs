//! Ad-hoc code signature (TDD §9): big-endian SuperBlob + v0x20400
//! CodeDirectory of SHA-256 page hashes over 4 KiB code pages.
//!
//! Invariants this module keeps (the verifier recomputes every hash):
//!
//! * `codeLimit == signature file offset` (everything before is signed),
//! * `nCodeSlots == ceil(codeLimit / 4096)`,
//! * hash pages are 4 KiB (CS_PAGE_SIZE_LOG2 = 12), independent of the
//!   16 KiB VM pages,
//! * the blob is the last thing in the file,
//! * UUID derivation (mold's rule): first 16 bytes of SHA-256 over the page
//!   hashes computed with the UUID field zeroed — reproducible builds.

use crate::EmitError;
use pgr_format::consts::{
    CS_ADHOC, CS_CODEDIRECTORY_VERSION_EXECSEG, CS_EXECSEG_MAIN_BINARY, CS_HASHTYPE_SHA256,
    CS_PAGE_SIZE, CS_PAGE_SIZE_LOG2, CS_SHA256_LEN, CSMAGIC_CODEDIRECTORY,
    CSMAGIC_EMBEDDED_SIGNATURE, CSSLOT_CODEDIRECTORY,
};
use sha2::{Digest, Sha256};

/// The exact size the signature blob will occupy at `code_limit` (the
/// layout pass uses the same formula; kept in one place).
#[must_use]
pub fn blob_size(ident_len: usize, code_limit: u64) -> usize {
    let nblocks = code_limit.div_ceil(CS_PAGE_SIZE) as usize;
    let ident_padded = ident_len
        .checked_add(1)
        .map(|v| v.div_ceil(4) * 4)
        .unwrap_or(0);
    let dir_len = 88 + ident_padded + nblocks * CS_SHA256_LEN as usize;
    (12 + 8 + dir_len).div_ceil(8) * 8
}

/// Computes SHA-256 over every 4 KiB page of `buf[0..code_limit]`, zeroing
/// the 16 UUID bytes first when `zero_uuid` is set (two-pass derivation).
#[must_use]
pub fn page_hashes(buf: &mut [u8], uuid_at: usize, code_limit: u64, zero_uuid: bool) -> Vec<u8> {
    let saved: Option<[u8; 16]> = if zero_uuid {
        buf.get(uuid_at..uuid_at + 16)
            .and_then(|b| <[u8; 16]>::try_from(b).ok())
    } else {
        None
    };
    if zero_uuid {
        if let Some(dst) = buf.get_mut(uuid_at..uuid_at + 16) {
            dst.fill(0);
        }
    }
    let limit = (code_limit as usize).min(buf.len());
    let mut out = Vec::with_capacity(limit.div_ceil(CS_PAGE_SIZE as usize) * 32);
    for chunk in buf[..limit].chunks(CS_PAGE_SIZE as usize) {
        let mut h = Sha256::new();
        h.update(chunk);
        out.extend_from_slice(&h.finalize());
    }
    if let Some(saved) = saved {
        if let Some(dst) = buf.get_mut(uuid_at..uuid_at + 16) {
            dst.copy_from_slice(&saved);
        }
    }
    out
}

/// Derives the content UUID from the (UUID-zeroed) page hashes.
#[must_use]
pub fn derive_uuid(zeroed_hashes: &[u8]) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(zeroed_hashes);
    let mut out = [0u8; 16];
    out.copy_from_slice(&h.finalize()[..16]);
    out
}

/// Builds the ad-hoc SuperBlob covering `code_limit` bytes with `hashes`
/// (concatenated 32-byte page hashes).
///
/// # Errors
/// [`EmitError::Contract`] when `hashes` does not cover `code_limit`.
pub fn build_superblob(
    ident: &str,
    code_limit: u64,
    hashes: &[u8],
    exec_seg_limit: u64,
    is_exec: bool,
) -> Result<Vec<u8>, EmitError> {
    let nslots = code_limit.div_ceil(CS_PAGE_SIZE) as usize;
    if hashes.len() != nslots * CS_SHA256_LEN as usize {
        return Err(EmitError::Contract {
            message: format!(
                "page hash table is {} bytes but {} slots × 32 = {} are required",
                hashes.len(),
                nslots,
                nslots * CS_SHA256_LEN as usize
            ),
        });
    }
    let ident_padded = (ident.len() + 1).div_ceil(4) * 4;
    let dir_len = 88 + ident_padded + hashes.len();
    let mut cd = Vec::with_capacity(dir_len);
    let be32 = |v: u32| v.to_be_bytes();
    let be64 = |v: u64| v.to_be_bytes();
    cd.extend_from_slice(&be32(CSMAGIC_CODEDIRECTORY));
    cd.extend_from_slice(&be32(dir_len as u32));
    cd.extend_from_slice(&be32(CS_CODEDIRECTORY_VERSION_EXECSEG));
    cd.extend_from_slice(&be32(CS_ADHOC));
    cd.extend_from_slice(&be32(((88 + ident_padded) / 4) as u32)); // hashOffset
    cd.extend_from_slice(&be32(22)); // identOffset = 88 / 4
    cd.extend_from_slice(&be32(0)); // nSpecialSlots (ad-hoc)
    cd.extend_from_slice(&be32(nslots as u32));
    cd.extend_from_slice(&be32(code_limit as u32));
    cd.push(CS_SHA256_LEN as u8);
    cd.push(CS_HASHTYPE_SHA256);
    cd.push(0); // platform
    cd.push(CS_PAGE_SIZE_LOG2);
    cd.extend_from_slice(&be32(0)); // spare2
    cd.extend_from_slice(&be32(0)); // scatterOffset
    cd.extend_from_slice(&be32(0)); // teamOffset
    cd.extend_from_slice(&be32(0)); // spare3
    cd.extend_from_slice(&be64(code_limit)); // codeLimit64
    cd.extend_from_slice(&be64(0)); // execSegBase
    cd.extend_from_slice(&be64(exec_seg_limit));
    cd.extend_from_slice(&be64(if is_exec { CS_EXECSEG_MAIN_BINARY } else { 0 }));
    debug_assert_eq!(cd.len(), 88, "CodeDirectory fixed head is 88 bytes");
    cd.extend_from_slice(ident.as_bytes());
    cd.push(0);
    cd.resize(88 + ident_padded, 0);
    cd.extend_from_slice(hashes);

    let blob_len = (12 + 8 + dir_len).div_ceil(8) * 8;
    let mut sb = Vec::with_capacity(blob_len);
    sb.extend_from_slice(&be32(CSMAGIC_EMBEDDED_SIGNATURE));
    sb.extend_from_slice(&be32(blob_len as u32));
    sb.extend_from_slice(&be32(1)); // count
    sb.extend_from_slice(&be32(CSSLOT_CODEDIRECTORY));
    sb.extend_from_slice(&be32(20)); // offset of the directory
    sb.extend_from_slice(&cd);
    sb.resize(blob_len, 0);
    Ok(sb)
}

#[cfg(test)]
mod tests {
    use super::{blob_size, build_superblob, derive_uuid, page_hashes};
    use pgr_format::consts::{CS_ADHOC, CSMAGIC_EMBEDDED_SIGNATURE};
    use pgr_format::{CodeDirectory, SuperBlob};

    #[test]
    fn size_formula_matches_mold() {
        // mold: directory = 88 + ident + 1 + nblocks * hash_size,
        // superblob = 12 + 8 + dirs, padded to 8.
        assert_eq!(blob_size(16, 0x4000), {
            let nblocks: usize = 4;
            let dir: usize = 88 + (17usize.div_ceil(4) * 4) + nblocks * 32;
            (12 + 8 + dir).div_ceil(8) * 8
        });
    }

    #[test]
    fn superblob_parses_and_hashes_match() {
        let mut buf = vec![0u8; 9000];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let uuid_at = 0x40;
        let code_limit = 0x2000u64; // two pages, tail zeros excluded by limit
        let zeroed = page_hashes(&mut buf, uuid_at, code_limit, true);
        let uuid = derive_uuid(&zeroed);
        buf[uuid_at..uuid_at + 16].copy_from_slice(&uuid);
        let hashes = page_hashes(&mut buf, uuid_at, code_limit, false);
        let blob =
            build_superblob("peregrine.test", code_limit, &hashes, 0x1_0000_0000, true).unwrap();
        assert_eq!(blob.len(), blob_size("peregrine.test".len(), code_limit));

        let sb = SuperBlob::parse(&blob).unwrap();
        let cd_blob = sb
            .blob_for_slot(pgr_format::consts::CSSLOT_CODEDIRECTORY)
            .unwrap()
            .unwrap();
        let cd = CodeDirectory::parse(cd_blob).unwrap();
        assert_eq!(cd.code_limit, code_limit as u32);
        assert_eq!(cd.n_code_slots, 2);
        assert_eq!(cd.flags & CS_ADHOC, CS_ADHOC);
        let stored = cd.code_hashes(cd_blob).unwrap();
        assert_eq!(stored.len(), 2 * 32);
        assert_eq!(
            stored,
            &hashes[..],
            "stored hashes match the recompute input"
        );
        // Identifier round-trips.
        assert_eq!(cd.identifier(cd_blob).unwrap(), b"peregrine.test");
        let _ = CSMAGIC_EMBEDDED_SIGNATURE;
    }

    #[test]
    fn uuid_is_stable_and_content_sensitive() {
        let mut a = vec![1u8; 8192];
        let mut b = vec![1u8; 8192];
        let ha = page_hashes(&mut a, 0, 8192, true);
        let hb = page_hashes(&mut b, 0, 8192, true);
        assert_eq!(ha, hb);
        assert_eq!(derive_uuid(&ha), derive_uuid(&hb));
        b[100] = 2;
        let hb2 = page_hashes(&mut b, 0, 8192, true);
        assert_ne!(
            derive_uuid(&ha),
            derive_uuid(&hb2),
            "content change moves the UUID"
        );
    }

    #[test]
    fn wrong_hash_table_size_errors() {
        let err = build_superblob("x", 4096, &[0u8; 16], 0, true).unwrap_err();
        assert!(matches!(err, super::EmitError::Contract { .. }));
    }
}
