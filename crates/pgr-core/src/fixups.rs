//! Chained-fixup planning (TDD §7): slot classification, the stride-bounded
//! greedy chain packer (§7.4), the `LC_DYLD_CHAINED_FIXUPS` payload assembler
//! (rebases *and* binds + import table) and the `__TEXT,__chain_starts`
//! static mirror (§7.5).
//!
//! Pointer formats (M10 rung 4, slice 2): the planner encodes either
//! `DYLD_CHAINED_PTR_64_OFFSET` — the M2 default (TDD §7.2), rebase
//! targets image-base-relative offsets — or the `DYLD_CHAINED_PTR_ARM64E`
//! family whose unauth rebases carry VM addresses and whose `next` counts
//! 8-byte strides ([`FixupPointerFormat`]). The read side has walked both
//! families since rung 4 slice 1; the import table stays
//! `DYLD_CHAINED_IMPORT_ADDEND` in both — its format is a separate payload
//! field a loader reads independently of the word family.
//!
//! Import ordinals (M2): assigned in **first-use order over address-sorted
//! fixups** (mold's model, TDD §7.3). Architecture-delta D7 proposed a
//! canonical `(lib, name, addend)` order to unblock tile-fused emit; spike
//! S6 (empirical, M2) showed `ld64.lld` assigns first-use order over the
//! address-sorted slot stream — dyld accepts any order, so Peregrine keeps
//! first-use for golden compatibility. *M4 update:* the tile scheduler
//! shipped without needing D7 — the import table is built here, in Pass 3,
//! and Pass 4's tiles only **read** the encoded slot words, so no
//! cross-tile mutation exists. *M9 update:* D7 closed — the
//! insertion-stable import table (`crate::stable_imports`) is load-bearing
//! for the §7.3 relink ladder (anchored ordinals across relink cycles,
//! gated in `tests/m9_stable_imports.rs`).
//!
//! Addend split (mirrors ld64/lld): an addend in `0..=255` travels inline in
//! the bind word's 8-bit field with a zero import addend; any other addend
//! travels in the import entry (`i32`) with a zero word addend. dyld adds
//! both (only one is ever nonzero). Auth binds (M10 rung 4, slice 3) are
//! the named exception: their word has no addend field, so the full addend
//! rides the import entry. Auth binds (M10 rung 4, slice 3) are
//! the named exception: their word has no addend field, so the full addend
//! rides the import entry.
//!
//! Determinism: slots are sorted by output address, pages packed in ascending
//! order, multi-start overflow tables appended in first-discovery order — the
//! whole payload is a pure function of the layout.

use crate::LinkError;
use crate::ids::StringId;
use crate::interner::Interner;
use crate::stable_imports::StableImport;
use pgr_format::consts::{
    DYLD_CHAINED_IMPORT_ADDEND, DYLD_CHAINED_PTR_64_OFFSET, DYLD_CHAINED_PTR_ARM64E,
    DYLD_CHAINED_PTR_START_MULTI, DYLD_CHAINED_PTR_START_MULTI_MASK, DYLD_CHAINED_PTR_START_NONE,
};
use pgr_format::fixups::{
    Import, encode_arm64e_auth_bind_word, encode_arm64e_auth_rebase_word,
    encode_arm64e_bind_word, encode_arm64e_rebase_word, encode_bind_word, encode_rebase_word,
};

/// `next` counts 4-byte units with 12 bits; only 0 ends a chain (TDD §7.4).
pub const MAX_CHAIN_STRIDE: u32 = 0xFFF;
/// Maximum forward distance between two fixups in the same chain (16 380 B).
pub const MAX_CHAIN_STRIDE_BYTES: u64 = (MAX_CHAIN_STRIDE as u64) * 4;

/// The chain word family Pass 3 encodes (M10 rung 4, slice 2 — the
/// producer half of the rung; the read side has walked both since slice 1).
/// The default is the M2-locked `DYLD_CHAINED_PTR_64_OFFSET` (§7.2): the
/// seam is invisible on every clean link until a consumer asks for the
/// arm64e family.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum FixupPointerFormat {
    /// `DYLD_CHAINED_PTR_64_OFFSET` (6): rebase targets are image-base
    /// relative offsets, `next` counts 4-byte units with 12 bits.
    #[default]
    Offset64,
    /// `DYLD_CHAINED_PTR_ARM64E` (1): unauth rebase targets are VM
    /// addresses (dyld subtracts the preferred load address walking back),
    /// binds carry a 16-bit ordinal and a signed 19-bit inline addend, and
    /// `next` counts 8-byte strides with 11 bits.
    Arm64e,
}

impl FixupPointerFormat {
    /// The `pointer_format` the payload's segment records and the
    /// `__chain_starts` mirror declare.
    #[must_use]
    pub const fn pointer_format(self) -> u16 {
        match self {
            Self::Offset64 => DYLD_CHAINED_PTR_64_OFFSET,
            Self::Arm64e => DYLD_CHAINED_PTR_ARM64E,
        }
    }

    /// The byte stride `next` counts (the format's slot pitch).
    #[must_use]
    pub const fn stride_bytes(self) -> u64 {
        match self {
            Self::Offset64 => 4,
            Self::Arm64e => 8,
        }
    }

    /// The `next` field's maximum stride count (12 bits for the 64 family,
    /// 11 for arm64e).
    #[must_use]
    pub const fn max_next(self) -> u32 {
        match self {
            Self::Offset64 => MAX_CHAIN_STRIDE,
            Self::Arm64e => 0x7FF,
        }
    }
}

/// The authentication policy for one fixup slot (M10 rung 4, slice 3):
/// the PAC triple dyld verifies at load time (`fixup-chains.h`'s
/// `diversity`/`addrDiv`/`key` bits; `key` is the 2-bit `ptrauth_key`).
/// An entry names its slot by output vaddr. Planning with a policy under
/// the default `DYLD_CHAINED_PTR_64_OFFSET` family refuses outright —
/// that word has no auth discriminator to set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixupAuth {
    /// The authenticated slot's output vaddr (the `FixupSlot` it signs).
    pub vaddr: u64,
    /// The 2-bit pointer-authentication key (0..=3).
    pub key: u8,
    /// The 16-bit diversity value.
    pub diversity: u16,
    /// Address diversity (`addrDiv`).
    pub addr_div: bool,
}

/// What dyld writes into one fixup slot at load time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixupKind {
    /// Rebase: `value = base + target` — `target_vaddr` is the resolved
    /// output vaddr (target address plus the slot's in-data addend).
    Rebase {
        /// The target's output vaddr.
        target_vaddr: u64,
    },
    /// Bind: `value = resolve(lib_ordinal, name) + addend` — an external
    /// reference (dylib export or dynamic lookup).
    Bind {
        /// 1-based `LC_LOAD_DYLIB` ordinal, or a `BIND_SPECIAL_DYLIB_*`
        /// special (0xFE flat lookup / 0xFD weak lookup).
        lib_ordinal: u8,
        /// Interned symbol name.
        name: StringId,
        /// Full addend (split between word and import entry by `plan_fixups`).
        addend: i64,
        /// Weak import (`N_WEAK_REF` / weak dylib).
        weak: bool,
    },
}

/// One pointer slot that becomes a chained fixup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixupSlot {
    /// Output vaddr of the 8-byte slot (8-byte aligned).
    pub vaddr: u64,
    /// What dyld writes into the slot.
    pub kind: FixupKind,
}

/// A fixup mid-packing: page offset, encoded word, chain stride.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackingSlot {
    /// Offset of the slot within its chain-walk page.
    pub page_off: u32,
    /// Distance to the next fixup, in 4-byte units (0 terminates).
    pub next: u32,
    /// Encoded word without the `next` field.
    pub word_base: u64,
}

/// Packs one page's fixups into chains (TDD §7.4, the stride-bounded greedy
/// linker). `page_off` must be ascending across `fx`. Returns the chain
/// heads as page offsets, in ascending slot order.
///
/// The 64 family's 4-byte stride (TDD §7.4); the format-generic form is
/// [`pack_page_strided`].
#[must_use]
pub fn pack_page(fx: &mut [PackingSlot]) -> Vec<u16> {
    pack_page_strided(fx, 4, MAX_CHAIN_STRIDE)
}

/// [`pack_page`] with the word family's stride: `next` counts `stride`
/// byte jumps and may not exceed `max_next` (12 strides-of-4 for the 64
/// family, 11 strides-of-8 for arm64e). Slots whose gap leaves the
/// `[stride, max_next * stride]` window start a fresh chain.
#[must_use]
pub fn pack_page_strided(fx: &mut [PackingSlot], stride: u64, max_next: u32) -> Vec<u16> {
    let max_gap = u64::from(max_next) * stride;
    debug_assert!(fx.windows(2).all(|w| w[0].page_off <= w[1].page_off));
    let mut heads = Vec::new();
    let mut i = 0usize;
    while i < fx.len() {
        heads.push(fx[i].page_off as u16); // new chain head
        let mut j = i;
        while j + 1 < fx.len() {
            let gap = u64::from(fx[j + 1].page_off - fx[j].page_off);
            if !(stride..=max_gap).contains(&gap) {
                break; // must start a fresh chain
            }
            j += 1;
        }
        for k in i..j {
            fx[k].next = (fx[k + 1].page_off - fx[k].page_off) as u32 / stride as u32;
        }
        fx[j].next = 0; // terminate
        i = j + 1;
    }
    heads
}

/// Encodes a rebase chain word for `DYLD_CHAINED_PTR_64_OFFSET` (bit 63
/// clear): `target44 | high8 << 36 | next << 51` — the target is the
/// image-base-relative offset.
fn rebase_word(target_vaddr: u64, image_base: u64) -> Result<u64, LinkError> {
    let off = target_vaddr
        .checked_sub(image_base)
        .ok_or(LinkError::Layout {
            message: format!(
                "rebase target {target_vaddr:#x} below the image base {image_base:#x}"
            ),
        })?;
    if off >> 44 != 0 {
        return Err(LinkError::Layout {
            message: format!(
                "rebase target {off:#x} exceeds the 44-bit chained-fixup field \
                 (image larger than 16 TiB)"
            ),
        });
    }
    encode_rebase_word(off & 0xF_FFFF_FFFF, (off >> 36) as u8, 0).map_err(|e| LinkError::Internal {
        message: format!("rebase word encode: {e}"),
    })
}

/// Encodes an unauth arm64e rebase chain word: `target43 | high8 << 43 |
/// next << 51` — format 1 carries the **VM address** (dyld subtracts the
/// preferred load address walking back), so the image base does not
/// participate. Bits 43..56 of a VM address have no home in the word (the
/// target field is 43 bits and `high8` covers 56..64): a target that
/// leaves them set refuses instead of silently truncating.
fn rebase_word_arm64e(target_vaddr: u64) -> Result<u64, LinkError> {
    if (target_vaddr >> 43) & 0x1FFF != 0 {
        return Err(LinkError::Layout {
            message: format!(
                "arm64e rebase target {target_vaddr:#x} exceeds the word fields \
                 (43-bit target + high8; bits 43..56 have no home)"
            ),
        });
    }
    let high8 = (target_vaddr >> 56) as u8;
    encode_arm64e_rebase_word(target_vaddr & 0x7_FFFF_FFFF_FFFF, high8, 0)
        .map_err(|e| LinkError::Internal {
            message: format!("arm64e rebase word encode: {e}"),
        })
}

/// Encodes a bind chain word (bit 63 set): `ordinal | addend8 << 24 |
/// next << 51`.
fn bind_word(ordinal: u32, inline_addend: u8) -> Result<u64, LinkError> {
    encode_bind_word(ordinal, inline_addend, 0).map_err(|e| LinkError::Internal {
        message: format!("bind word encode: {e}"),
    })
}

/// Encodes an authenticated arm64e rebase chain word: the 32-bit runtime
/// offset (`target − image base`, what dyld adds to the preferred load
/// address) rides the target field with the slot's PAC triple. A target
/// below the base or beyond the 32-bit field refuses with the slot named.
fn rebase_word_arm64e_auth(
    target_vaddr: u64,
    image_base: u64,
    slot_vaddr: u64,
    policy: &FixupAuth,
) -> Result<u64, LinkError> {
    let runtime_offset = target_vaddr.checked_sub(image_base).ok_or(LinkError::Layout {
        message: format!(
            "auth rebase target {target_vaddr:#x} sits below the image base \
             {image_base:#x} (slot {slot_vaddr:#x})"
        ),
    })?;
    let off32 = u32::try_from(runtime_offset).map_err(|_| LinkError::Layout {
        message: format!(
            "auth rebase target {runtime_offset:#x} exceeds the 32-bit runtime \
             offset (slot {slot_vaddr:#x})"
        ),
    })?;
    encode_arm64e_auth_rebase_word(
        u64::from(off32),
        policy.diversity,
        policy.addr_div,
        policy.key,
        0,
    )
    .map_err(|e| LinkError::Internal {
        message: format!("arm64e auth rebase word encode: {e}"),
    })
}

/// The M2 addend split (TDD §7.3): an addend in `0..=255` travels inline
/// in the bind word with a zero import addend, anything else travels in
/// the import entry with a zero word addend. The authenticated bind is
/// the named exception (slice 3): its word has no inline addend field, so
/// the full addend rides the import entry. Returns `(inline, outlined)`.
fn addend_split(addend: i64, auth: bool) -> (u8, i64) {
    if auth {
        (0, addend)
    } else if (0..=255).contains(&addend) {
        (addend as u8, 0)
    } else {
        (0, addend)
    }
}

/// Packing result for one segment.
#[derive(Debug, Default)]
struct SegmentChains {
    /// `page_start[]` entries (start offset / `START_NONE` / multi marker).
    page_start: Vec<u16>,
    /// Multi-start overflow tables in first-discovery order (each: count +
    /// head offsets, little-endian `u16`s).
    overflow: Vec<Vec<u8>>,
    /// Encoded slot words: `(slot vaddr, final word)` ascending.
    slot_words: Vec<(u64, u64)>,
    /// Image offsets of every chain head slot, ascending.
    head_image_offs: Vec<u32>,
}

impl SegmentChains {
    /// `dyld_chained_starts_in_segment.size` (22 fixed bytes + `page_start`
    /// array + overflow tables).
    fn record_size(&self) -> usize {
        22 + self.page_start.len() * 2 + self.overflow.iter().map(std::vec::Vec::len).sum::<usize>()
    }
}

/// The complete fixup plan (rebases + binds, M2).
#[derive(Debug, Clone)]
pub struct FixupPlan {
    /// `LC_DYLD_CHAINED_FIXUPS` payload bytes (header | starts | segment
    /// records | import table | name pool).
    pub payload: Vec<u8>,
    /// The payload's `__LINKEDIT` file offset as recorded at plan time —
    /// always `0`: the authoritative offset is assigned during LINKEDIT
    /// chunk placement (`LinkeditPlan::fixup_payload_off`) and consumed
    /// by emit from there; this field predates that plan and stays for
    /// constructor compatibility.
    pub payload_off: u64,
    /// Final slot words: `(slot vaddr, encoded word)` sorted by vaddr.
    pub slot_words: Vec<(u64, u64)>,
    /// `__TEXT,__chain_starts` section bytes (static mirror, TDD §7.5):
    /// `u32 pointer_format, u32 chain_count, u32 heads[]` as image offsets.
    pub chain_starts: Vec<u8>,
    /// Number of fixup slots packed.
    pub slot_count: usize,
    /// Import table in first-use order (`DYLD_CHAINED_IMPORT_ADDEND`).
    pub imports: Vec<Import>,
    /// Import name pool: names in import order, NUL-terminated.
    pub import_names: Vec<u8>,
    /// True when at least one bind is weak (`MH_BINDS_TO_WEAK` input).
    pub has_weak_binds: bool,
    /// The import table as identities, in ordinal order (M9 tier 2a): the
    /// exact keys the record stores, so a relink can anchor its ordinals
    /// to this table (insertion-stable growth; §7.3 step 5). The projection
    /// of `imports` onto `(lib_ordinal, name, outlined addend, weak)` —
    /// same order, one entry per import.
    pub stable_keys: Vec<StableImport>,
}

/// One import dedup key (first-use insertion order = the chained bind
/// ordinal space).
pub(crate) struct ImportKey {
    pub lib_ordinal: u8,
    pub name: Vec<u8>,
    pub outlined_addend: i64,
    pub weak: bool,
}

/// Builds the import table (first-use order over address-sorted slots):
/// `(imports, name pool, has_weak, dedup keys)`. Shared by the chained path
/// (`plan_fixups`) and the M6 classic path (`dyld_info`) — the symtab and
/// indirect-symbol-table construction reads the same metadata either way.
/// The classic path carries no auth policy: the M2 split rule (0..=255
/// inline) holds for every bind.
pub(crate) fn build_import_table(
    slots: &[FixupSlot],
    interner: &Interner,
) -> (Vec<Import>, Vec<u8>, bool, Vec<ImportKey>) {
    build_import_table_with_auth(slots, interner, &std::collections::HashMap::new())
}

/// [`build_import_table`] with the auth policy (M10 rung 4, slice 3): a
/// bind whose slot is signed has **no inline addend** — the auth bind
/// word has no addend field — so the full addend travels in the import
/// entry, making the signed bind a distinct dedup key beside its unauth
/// self. The M9 anchor treats the signed key like any other new key: it
/// appends without renumbering (§7.3 step 5).
pub(crate) fn build_import_table_with_auth(
    slots: &[FixupSlot],
    interner: &Interner,
    auth: &std::collections::HashMap<u64, FixupAuth>,
) -> (Vec<Import>, Vec<u8>, bool, Vec<ImportKey>) {
    let mut bind_keys: Vec<ImportKey> = Vec::new();
    let mut seen: std::collections::HashSet<(u8, Vec<u8>, i64, bool)> =
        std::collections::HashSet::new();
    let mut has_weak_binds = false;
    for slot in slots {
        let FixupKind::Bind {
            lib_ordinal,
            name,
            addend,
            weak,
        } = slot.kind
        else {
            continue;
        };
        let signed = auth.contains_key(&slot.vaddr);
        let (_inline, outlined) = addend_split(addend, signed);
        let key = (lib_ordinal, interner.bytes(name).to_vec(), outlined, weak);
        if seen.insert(key.clone()) {
            bind_keys.push(ImportKey {
                lib_ordinal,
                name: key.1.clone(),
                outlined_addend: outlined,
                weak,
            });
        }
        if weak {
            has_weak_binds = true;
        }
    }
    let mut imports: Vec<Import> = bind_keys
        .iter()
        .map(|k| Import {
            lib_ordinal: u16::from(k.lib_ordinal),
            weak_import: k.weak,
            name_offset: 0, // patched below once the pool exists
            addend: k.outlined_addend,
        })
        .collect();
    let mut import_names: Vec<u8> = Vec::new();
    let mut name_offsets: Vec<u32> = Vec::with_capacity(bind_keys.len());
    for k in &bind_keys {
        name_offsets.push(import_names.len() as u32);
        import_names.extend_from_slice(&k.name);
        import_names.push(0);
    }
    for (imp, off) in imports.iter_mut().zip(name_offsets.iter()) {
        imp.name_offset = *off;
    }
    (imports, import_names, has_weak_binds, bind_keys)
}

/// The stable-identity projection of an [`ImportKey`] (the record's table
/// entry form; M9 tier 2a). `pub(crate)`: the M6 classic path builds its
/// table inline and projects the same identities onto the plan.
pub(crate) fn import_key_identity(k: &ImportKey) -> StableImport {
    StableImport {
        lib_ordinal: k.lib_ordinal,
        name: k.name.clone(),
        outlined_addend: k.outlined_addend,
        weak: k.weak,
    }
}

/// The import table layout for one plan: the on-disk `Import` entries, the
/// name pool, the ordinal per dedup key (parallel to `bind_keys`), and the
/// table as identities (what the record stores). Without an anchor the
/// ordinals are first-use positions — the shipped M2 behavior, unchanged;
/// with an anchor (M9 tier 2a) the recorded table keeps every ordinal and
/// genuinely new imports append in canonical order (§7.3 step 5).
fn import_table_ordinals(
    bind_keys: &[ImportKey],
    import_anchor: Option<&[StableImport]>,
) -> Result<(Vec<u32>, Vec<StableImport>), LinkError> {
    let incoming: Vec<StableImport> = bind_keys.iter().map(import_key_identity).collect();
    match import_anchor {
        None => Ok(((0..bind_keys.len() as u32).collect(), incoming)),
        Some(anchor) => {
            let mut table = crate::stable_imports::StableImports::anchored(anchor.to_vec());
            let assignments = table.insert(incoming.clone());
            let ordinal_of: std::collections::HashMap<&StableImport, u32> = assignments
                .iter()
                .map(|a| (&a.key, a.ordinal as u32))
                .collect();
            // `insert` answers every incoming key by contract; an unanswered
            // key is a named internal failure, never a silent sentinel
            // ordinal (the pre-slice-2 fallback masked this arm with
            // `u32::MAX`, which would encode a bogus bind).
            let mut ordinals = Vec::with_capacity(incoming.len());
            for k in &incoming {
                let Some(o) = ordinal_of.get(k).copied() else {
                    return Err(LinkError::Internal {
                        message: "the anchored import table did not answer an \
                                  incoming key (insert is total over new keys)"
                            .into(),
                    });
                };
                ordinals.push(o);
            }
            Ok((ordinals, table.keys().to_vec()))
        }
    }
}

/// Plans all fixups (rebases and binds) for the image: import ordinals in
/// first-use order over the address-sorted slots (the M2 clean-link bytes).
///
/// `segments` are the image's `LC_SEGMENT_64` entries in command order as
/// `(vmaddr, vmsize, fileoff)`; each slot lands in the segment containing
/// its vaddr. `image_base` is `__PAGEZERO` vmsize (the constant-delta base);
/// `page_size` the chain-walk page size (16 KiB on arm64).
///
/// # Errors
/// [`LinkError::Layout`] on slots outside any segment, misaligned slots, or
/// targets beyond the 44-bit field.
pub fn plan_fixups(
    slots: Vec<FixupSlot>,
    segments: &[(u64, u64, u64)],
    image_base: u64,
    page_size: u64,
    interner: &Interner,
) -> Result<FixupPlan, LinkError> {
    plan_fixups_with_imports(slots, segments, image_base, page_size, interner, None)
}

/// [`plan_fixups`] with the M9 tier-2a import anchor (§7.3 step 5): when
/// `import_anchor` carries the previous link's recorded table, its ordinals
/// hold and genuinely new imports append — an edit that adds a bind no
/// longer renumbers the existing ones. `None` reproduces first-use exactly
/// (clean links are bit-deterministic, §7.3).
///
/// # Errors
/// [`LinkError::Layout`] on slots outside any segment, misaligned slots, or
/// targets beyond the 44-bit field.
pub fn plan_fixups_with_imports(
    slots: Vec<FixupSlot>,
    segments: &[(u64, u64, u64)],
    image_base: u64,
    page_size: u64,
    interner: &Interner,
    import_anchor: Option<&[StableImport]>,
) -> Result<FixupPlan, LinkError> {
    plan_fixups_with_format(
        slots,
        segments,
        image_base,
        page_size,
        interner,
        import_anchor,
        FixupPointerFormat::Offset64,
    )
}

/// [`plan_fixups_with_imports`] with the chain word family named (M10
/// rung 4, slice 2): `format` chooses the word encoding, the stride
/// semantics (`next` counts 4- or 8-byte units), and the `pointer_format`
/// the payload records and the `__chain_starts` mirror declare. The
/// default [`FixupPointerFormat::Offset64`] is byte-identical to the M2
/// planner (the seam is invisible unless asked for). The import table
/// stays `DYLD_CHAINED_IMPORT_ADDEND` in both families — its format is a
/// separate payload field a loader reads independently.
///
/// # Errors
/// [`LinkError::Layout`] on slots outside any segment, misaligned slots,
/// targets the word fields cannot represent, or an arm64e import table
/// beyond the 16-bit ordinal.
pub fn plan_fixups_with_format(
    slots: Vec<FixupSlot>,
    segments: &[(u64, u64, u64)],
    image_base: u64,
    page_size: u64,
    interner: &Interner,
    import_anchor: Option<&[StableImport]>,
    format: FixupPointerFormat,
) -> Result<FixupPlan, LinkError> {
    plan_fixups_with_auth(
        slots,
        segments,
        image_base,
        page_size,
        interner,
        import_anchor,
        format,
        &[],
    )
}

/// [`plan_fixups_with_format`] with the authentication policy (M10 rung
/// 4, slice 3): each [`FixupAuth`] entry signs its slot's word — auth
/// rebases carry the 32-bit runtime offset (`target − image base`) with
/// the PAC triple, auth binds carry the ordinal with the PAC triple and
/// move their whole addend into the import entry (the word has no
/// addend field). An empty policy plans byte-identically to the slice-2
/// planner; the 64_OFFSET family refuses a policy outright, as does an
/// entry that names no slot or names one twice.
///
/// # Errors
/// [`LinkError::Layout`] on slots outside any segment, misaligned slots,
/// targets the word fields cannot represent, an arm64e import table
/// beyond the 16-bit ordinal, an auth policy under the 64_OFFSET family,
/// an auth entry naming no slot or named twice, and auth rebase targets
/// beyond the 32-bit runtime offset.
pub fn plan_fixups_with_auth(
    mut slots: Vec<FixupSlot>,
    segments: &[(u64, u64, u64)],
    image_base: u64,
    page_size: u64,
    interner: &Interner,
    import_anchor: Option<&[StableImport]>,
    format: FixupPointerFormat,
    auth: &[FixupAuth],
) -> Result<FixupPlan, LinkError> {
    // The producer names its family on the tracing seam (the house
    // observability convention: inert until a subscriber installs).
    tracing::debug!(
        pointer_format = format.pointer_format(),
        slots = slots.len(),
        "the chain word format encodes the plan"
    );
    tracing::debug!(
        auth_slots = auth.len(),
        "the fixup auth policy signs the plan"
    );
    slots.sort_by_key(|s| s.vaddr);
    for s in &slots {
        if s.vaddr % 8 != 0 {
            return Err(LinkError::Layout {
                message: format!("fixup slot at {:#x} is not 8-byte aligned", s.vaddr),
            });
        }
    }

    // ---- the auth policy (M10 rung 4, slice 3) ----------------------------
    // One signer per slot, validated before anything encodes: the
    // 64_OFFSET family cannot carry auth words, a duplicate entry would
    // make the signing ambiguous, and an entry naming no slot is a plan
    // bug. The map rides the word loop and the import-table build (the
    // signed bind's addend split differs).
    let auth_map: std::collections::HashMap<u64, FixupAuth> = if auth.is_empty() {
        std::collections::HashMap::new()
    } else {
        if format == FixupPointerFormat::Offset64 {
            return Err(LinkError::Layout {
                message: format!(
                    "{} auth slot(s) declared; auth slots require the arm64e \
                     pointer format — the 64_OFFSET family has no auth \
                     discriminator to set",
                    auth.len()
                ),
            });
        }
        let mut map: std::collections::HashMap<u64, FixupAuth> =
            std::collections::HashMap::with_capacity(auth.len());
        for p in auth {
            if map.insert(p.vaddr, *p).is_some() {
                return Err(LinkError::Layout {
                    message: format!(
                        "the auth policy names slot {:#x} twice; one slot, \
                         one signer",
                        p.vaddr
                    ),
                });
            }
        }
        let slot_vaddrs: std::collections::HashSet<u64> = slots.iter().map(|s| s.vaddr).collect();
        for p in auth {
            if !slot_vaddrs.contains(&p.vaddr) {
                return Err(LinkError::Layout {
                    message: format!(
                        "the auth policy names {:#x}, which is no fixup slot \
                         in the plan",
                        p.vaddr
                    ),
                });
            }
        }
        map
    };

    // ---- import table: first-use order over address-sorted slots ----------
    // Key: (lib_ordinal, name bytes, outlined addend, weak). lld splits the
    // addend: 0..=255 inline in the word, everything else in the import
    // entry; only one side is ever nonzero, so dedup keys on the outlined
    // half. The anchor (when present) then fixes the recorded ordinals.
    let (_first_use, _first_use_pool, has_weak_binds, bind_keys) =
        build_import_table_with_auth(&slots, interner, &auth_map);
    let (ordinals, table_keys) = import_table_ordinals(&bind_keys, import_anchor)?;
    // The on-disk table and name pool follow the ordinal order: first-use
    // without an anchor (byte-identical to M2), recorded-order + appended
    // with one.
    let (imports, import_names) = imports_from_keys(&table_keys);
    // The arm64e bind word carries a 16-bit ordinal; a bind surface that
    // outgrows it must refuse at plan time, not encode a truncated one
    // (the 64 family's 24-bit field never trips this).
    if format == FixupPointerFormat::Arm64e && imports.len() > usize::from(u16::MAX) {
        return Err(LinkError::Layout {
            message: format!(
                "the import table carries {} entries; the arm64e bind \
                 ordinal field is 16-bit",
                imports.len()
            ),
        });
    }

    // ---- group slots per segment ----------------------------------------
    let mut per_segment: Vec<Vec<FixupSlot>> = vec![Vec::new(); segments.len()];
    for s in &slots {
        let seg_i = segments
            .iter()
            .position(|&(vm, vmsz, _)| s.vaddr >= vm && s.vaddr < vm + vmsz)
            .ok_or(LinkError::Layout {
                message: format!("fixup slot at {:#x} is outside every segment", s.vaddr),
            })?;
        per_segment[seg_i].push(*s);
    }

    // ---- pack chains per segment (independent; TDD §7.4) -----------------
    let mut chains: Vec<SegmentChains> = Vec::with_capacity(segments.len());
    let mut total_heads = 0usize;
    for (seg_i, seg_slots) in per_segment.iter().enumerate() {
        let (vmaddr, vmsize, _fileoff) = segments[seg_i];
        let mut seg = SegmentChains::default();
        if !seg_slots.is_empty() {
            let page_count = vmsize.div_ceil(page_size).max(1) as usize;
            let mut pages: Vec<Vec<PackingSlot>> = vec![Vec::new(); page_count];
            for s in seg_slots {
                let rel = s.vaddr - vmaddr;
                let page = (rel / page_size) as usize;
                let off_in_page = (rel % page_size) as u32;
                // The slot's signer, when the policy names it (slice 3).
                let policy = auth_map.get(&s.vaddr);
                let word_base = match s.kind {
                    FixupKind::Rebase { target_vaddr } => match format {
                        FixupPointerFormat::Offset64 => rebase_word(target_vaddr, image_base)?,
                        // Format 1: the VM address rides the word, dyld
                        // subtracts the preferred load address walking back.
                        // A signed slot swaps the shape: the 32-bit runtime
                        // offset plus the PAC triple.
                        FixupPointerFormat::Arm64e => match policy {
                            Some(p) => {
                                rebase_word_arm64e_auth(target_vaddr, image_base, s.vaddr, p)?
                            }
                            None => rebase_word_arm64e(target_vaddr)?,
                        },
                    },
                    FixupKind::Bind {
                        name,
                        addend,
                        weak,
                        lib_ordinal,
                    } => {
                        // Full-identity lookup: the same name bound through
                        // two libraries (or with different weak/addend
                        // splits) is two imports — a name+addend match
                        // would encode the wrong library's ordinal. A
                        // signed bind is its own key: the word has no
                        // inline addend field, so the full addend travels
                        // in the import entry (slice 3's named exception
                        // to the M2 split).
                        let signed = policy.is_some();
                        let (inline, outlined) = addend_split(addend, signed);
                        let key_pos = bind_keys
                            .iter()
                            .position(|k| {
                                k.lib_ordinal == lib_ordinal
                                    && k.name == interner.bytes(name)
                                    && k.outlined_addend == outlined
                                    && k.weak == weak
                            })
                            .ok_or(LinkError::Internal {
                                message: "bind slot missing from the import table".into(),
                            })?;
                        let ordinal = ordinals[key_pos];
                        // The M2 addend split rule holds in both families:
                        // 0..=255 travels inline, everything else in the
                        // import entry. The arm64e word's signed 19-bit
                        // field would admit more, but the import-table plan
                        // (and its M9 anchor) must not diverge per format —
                        // the one named exception is the auth bind (the
                        // word has no addend field; `addend_split` already
                        // moved the whole addend to the entry).
                        match format {
                            FixupPointerFormat::Offset64 => bind_word(ordinal, inline)?,
                            FixupPointerFormat::Arm64e => match policy {
                                Some(p) => {
                                    encode_arm64e_auth_bind_word(
                                        ordinal,
                                        p.diversity,
                                        p.addr_div,
                                        p.key,
                                        0,
                                    )
                                    .map_err(|e| LinkError::Internal {
                                        message: format!("arm64e auth bind word encode: {e}"),
                                    })?
                                }
                                None => {
                                    encode_arm64e_bind_word(u64::from(ordinal), i64::from(inline), 0)
                                        .map_err(|e| LinkError::Internal {
                                            message: format!("arm64e bind word encode: {e}"),
                                        })?
                                }
                            },
                        }
                    }
                };
                pages[page].push(PackingSlot {
                    page_off: off_in_page,
                    next: 0,
                    word_base,
                });
            }
            for page in &mut pages {
                page.sort_by_key(|p| p.page_off);
            }

            let mut overflow_heads: Vec<Vec<u16>> = Vec::new();
            let mut page_start: Vec<u16> = Vec::with_capacity(page_count);
            for (page_i, page) in pages.iter().enumerate() {
                if page.is_empty() {
                    page_start.push(DYLD_CHAINED_PTR_START_NONE);
                    continue;
                }
                let mut packed_words = page.clone();
                let heads = pack_page_strided(
                    &mut packed_words,
                    format.stride_bytes(),
                    format.max_next(),
                );
                for slot in &packed_words {
                    let slot_vaddr = vmaddr + page_i as u64 * page_size + u64::from(slot.page_off);
                    seg.slot_words
                        .push((slot_vaddr, slot.word_base | u64::from(slot.next) << 51));
                }
                if heads.len() == 1 {
                    page_start.push(heads[0]);
                } else {
                    // Multi-start (TDD §7.4): the marker indexes an overflow
                    // table appended after the page_start array.
                    overflow_heads.push(heads.clone());
                    page_start.push(DYLD_CHAINED_PTR_START_MULTI);
                }
                // Head slots: `pack_page_strided` returns the chain starts
                // in ascending page-offset order.
                for h in heads {
                    let head_vaddr = vmaddr + page_i as u64 * page_size + u64::from(h);
                    seg.head_image_offs.push((head_vaddr - image_base) as u32);
                }
            }
            seg.page_start = page_start;
            seg.overflow = overflow_heads
                .iter()
                .map(|heads| {
                    let mut b = Vec::with_capacity(2 + heads.len() * 2);
                    b.extend_from_slice(&(heads.len() as u16).to_le_bytes());
                    for &off in heads {
                        b.extend_from_slice(&off.to_le_bytes());
                    }
                    b
                })
                .collect();
            total_heads += seg.head_image_offs.len();
        }
        chains.push(seg);
    }

    // ---- payload assembly -------------------------------------------------
    // header (28 B padded to 32) | starts_in_image | per-segment records
    // (each 8-aligned) | import table (8 B/entry) | name pool
    let starts_offset: usize = 32;
    let seg_count = segments.len() as u32;
    let image_record_len = 4 + 4 * segments.len();

    // Phase 1: record offsets, then imports/pool offsets.
    let mut record_offsets = vec![0u32; segments.len()];
    let mut cursor = starts_offset + image_record_len;
    for (i, seg) in chains.iter().enumerate() {
        if seg.page_start.is_empty() {
            continue;
        }
        cursor = (cursor + 7) & !7;
        record_offsets[i] = (cursor - starts_offset) as u32;
        cursor += seg.record_size();
    }
    cursor = (cursor + 7) & !7;
    let imports_offset = cursor;
    cursor += imports.len() * 8;
    let symbols_offset = cursor;
    cursor += import_names.len();

    let mut payload: Vec<u8> = vec![0u8; cursor];
    payload[0..4].copy_from_slice(&0u32.to_le_bytes()); // fixups_version
    payload[4..8].copy_from_slice(&(starts_offset as u32).to_le_bytes());
    payload[8..12].copy_from_slice(&(imports_offset as u32).to_le_bytes());
    payload[12..16].copy_from_slice(&(symbols_offset as u32).to_le_bytes());
    payload[16..20].copy_from_slice(&(imports.len() as u32).to_le_bytes());
    payload[20..24].copy_from_slice(&DYLD_CHAINED_IMPORT_ADDEND.to_le_bytes());
    payload[24..28].copy_from_slice(&0u32.to_le_bytes()); // symbols_format (uncompressed)
    payload[starts_offset..starts_offset + 4].copy_from_slice(&seg_count.to_le_bytes());
    for (i, off) in record_offsets.iter().enumerate() {
        let at = starts_offset + 4 + i * 4;
        payload[at..at + 4].copy_from_slice(&off.to_le_bytes());
    }
    for (i, seg) in chains.iter().enumerate() {
        if seg.page_start.is_empty() {
            continue;
        }
        let (_vmaddr, _vmsize, fileoff) = segments[i];
        let at = starts_offset + record_offsets[i] as usize;
        payload[at..at + 4].copy_from_slice(&(seg.record_size() as u32).to_le_bytes());
        payload[at + 4..at + 6].copy_from_slice(&(page_size as u16).to_le_bytes());
        payload[at + 6..at + 8].copy_from_slice(&format.pointer_format().to_le_bytes());
        // segment_offset is image-base-relative; under the constant-delta
        // contract that equals the segment's file offset (the verifier
        // asserts exactly this).
        payload[at + 8..at + 16].copy_from_slice(&fileoff.to_le_bytes());
        payload[at + 16..at + 20].copy_from_slice(&0u32.to_le_bytes()); // max_valid_pointer
        payload[at + 20..at + 22].copy_from_slice(&(seg.page_start.len() as u16).to_le_bytes());
        let mut w = at + 22;
        let mut marker_seen = 0usize;
        let page_start_end = 22 + 2 * seg.page_start.len();
        for ps in &seg.page_start {
            if *ps == DYLD_CHAINED_PTR_START_MULTI {
                let mut toff = 0usize;
                for t in 0..marker_seen {
                    toff += seg.overflow[t].len();
                }
                let marker = DYLD_CHAINED_PTR_START_MULTI
                    | u16::try_from(page_start_end + toff).map_err(|_| LinkError::Layout {
                        message: "multi-start overflow table beyond 15-bit marker".into(),
                    })? & DYLD_CHAINED_PTR_START_MULTI_MASK;
                payload[w..w + 2].copy_from_slice(&marker.to_le_bytes());
                marker_seen += 1;
            } else {
                payload[w..w + 2].copy_from_slice(&ps.to_le_bytes());
            }
            w += 2;
        }
        for table in &seg.overflow {
            payload[w..w + table.len()].copy_from_slice(table);
            w += table.len();
        }
    }
    // Import table: `dyld_chained_import_addend` entries.
    for (i, imp) in imports.iter().enumerate() {
        let at = imports_offset + i * 8;
        let packed = u32::from(imp.lib_ordinal & 0xff)
            | u32::from(imp.weak_import) << 8
            | (imp.name_offset & 0x7f_ffff) << 9;
        payload[at..at + 4].copy_from_slice(&packed.to_le_bytes());
        payload[at + 4..at + 8].copy_from_slice(&(imp.addend as i32).to_le_bytes());
    }
    // Name pool.
    if !import_names.is_empty() {
        payload[symbols_offset..symbols_offset + import_names.len()].copy_from_slice(&import_names);
    }

    // ---- outputs -----------------------------------------------------------
    let mut slot_words: Vec<(u64, u64)> = Vec::new();
    for seg in &chains {
        slot_words.extend_from_slice(&seg.slot_words);
    }
    slot_words.sort_by_key(|(v, _)| *v);

    let mut chain_starts = Vec::with_capacity(8 + total_heads * 4);
    chain_starts.extend_from_slice(&u32::from(format.pointer_format()).to_le_bytes());
    chain_starts.extend_from_slice(&(total_heads as u32).to_le_bytes());
    for seg in &chains {
        for h in &seg.head_image_offs {
            chain_starts.extend_from_slice(&h.to_le_bytes());
        }
    }

    Ok(FixupPlan {
        payload,
        payload_off: 0,
        slot_words,
        chain_starts,
        slot_count: slots.len(),
        imports,
        import_names,
        has_weak_binds,
        stable_keys: table_keys,
    })
}

/// The on-disk import table for a set of identity keys, in the given
/// (ordinal) order: `Import` entries plus the NUL-terminated name pool
/// with `name_offset` patched.
fn imports_from_keys(keys: &[StableImport]) -> (Vec<Import>, Vec<u8>) {
    let mut imports = Vec::with_capacity(keys.len());
    let mut pool: Vec<u8> = Vec::new();
    let mut offsets: Vec<u32> = Vec::with_capacity(keys.len());
    for k in keys {
        offsets.push(pool.len() as u32);
        pool.extend_from_slice(&k.name);
        pool.push(0);
        imports.push(Import {
            lib_ordinal: u16::from(k.lib_ordinal),
            weak_import: k.weak,
            name_offset: 0,
            addend: k.outlined_addend,
        });
    }
    for (imp, off) in imports.iter_mut().zip(offsets.iter()) {
        imp.name_offset = *off;
    }
    (imports, pool)
}

#[cfg(test)]
mod tests {
    use super::{
        FixupKind, FixupSlot, MAX_CHAIN_STRIDE_BYTES, PackingSlot, pack_page, plan_fixups,
    };
    use crate::ids::StringId;
    use crate::interner::Interner;
    use pgr_format::consts::{
        DYLD_CHAINED_PTR_64_OFFSET, DYLD_CHAINED_PTR_START_NONE, PAGE_SIZE_16K,
    };
    use pgr_format::fixups::{
        ChainWord64, page_chain_starts, parse_header, parse_imports, parse_starts_in_image,
        parse_starts_in_segment,
    };

    fn slot(page_off: u32) -> PackingSlot {
        PackingSlot {
            page_off,
            next: 0,
            word_base: 0,
        }
    }

    fn rebase(vaddr: u64, target: u64) -> FixupSlot {
        FixupSlot {
            vaddr,
            kind: FixupKind::Rebase {
                target_vaddr: target,
            },
        }
    }

    /// Builds a two-name interner: id 0 = `_a`, id 1 = `_b` (canonical order
    /// is sorted, so `_a` < `_b`).
    fn interner2() -> Interner {
        let (inter, _ids) = Interner::build(&[b"_a".to_vec(), b"_b".to_vec()]);
        inter
    }

    fn bind(vaddr: u64, lib: u8, name: &str, addend: i64, weak: bool) -> FixupSlot {
        // Map the name to its interned id in the two-name interner.
        let id = match name {
            "_a" => StringId(0),
            _ => StringId(1),
        };
        FixupSlot {
            vaddr,
            kind: FixupKind::Bind {
                lib_ordinal: lib,
                name: id,
                addend,
                weak,
            },
        }
    }

    #[test]
    fn one_chain_across_dense_slots() {
        let mut page = vec![slot(0x10), slot(0x18), slot(0x20), slot(0x28)];
        let heads = pack_page(&mut page);
        assert_eq!(heads, vec![0x10]);
        assert_eq!(page[0].next, 2, "0x10 -> 0x18 is 8 bytes = 2 strides");
        assert_eq!(page[1].next, 2);
        assert_eq!(page[2].next, 2);
        assert_eq!(page[3].next, 0, "chain terminates");
    }

    #[test]
    fn stride_overflow_starts_a_fresh_chain() {
        // 0x10, then a slot beyond MAX_CHAIN_STRIDE_BYTES: new chain.
        let far = 0x10 + MAX_CHAIN_STRIDE_BYTES as u32 + 8;
        let mut page = vec![slot(0x10), slot(far)];
        let heads = pack_page(&mut page);
        assert_eq!(heads, vec![0x10, far as u16]);
        assert_eq!(page[0].next, 0);
        assert_eq!(page[1].next, 0);
    }

    #[test]
    fn payload_roundtrips_through_the_format_parser() {
        // Segment 0 (__TEXT at fileoff 0, 1 page) empty; segment 1 (__DATA
        // at fileoff 0x4000) with two dense rebase slots on page 0.
        let slots = vec![
            rebase(0x1_0000_4000, 0x1_0000_0000),
            rebase(0x1_0000_4008, 0x1_0000_1000),
        ];
        let segments = [
            (0x1_0000_0000, PAGE_SIZE_16K, 0),
            (0x1_0000_4000, PAGE_SIZE_16K, 0x4000),
        ];
        let inter = interner2();
        let plan = plan_fixups(slots, &segments, 0x1_0000_0000, PAGE_SIZE_16K, &inter).unwrap();

        let hdr = parse_header(&plan.payload).unwrap();
        assert_eq!(hdr.imports_count, 0);
        let starts = parse_starts_in_image(&plan.payload, hdr.starts_offset as usize).unwrap();
        assert_eq!(starts.seg_count, 2);
        assert_eq!(starts.seg_info_offset[0], 0, "no fixups in __TEXT");
        assert!(starts.seg_info_offset[1] != 0);
        let rec = parse_starts_in_segment(
            &plan.payload,
            hdr.starts_offset as usize + starts.seg_info_offset[1] as usize,
        )
        .unwrap();
        assert_eq!(rec.pointer_format, DYLD_CHAINED_PTR_64_OFFSET);
        assert_eq!(rec.page_size, PAGE_SIZE_16K as u16);
        assert_eq!(rec.segment_offset, 0x4000);
        assert_eq!(rec.page_count, 1);
        let heads = page_chain_starts(
            &plan.payload,
            hdr.starts_offset as usize + starts.seg_info_offset[1] as usize,
            &rec,
            0,
        )
        .unwrap();
        assert_eq!(heads, vec![0], "first slot sits at page offset 0");

        // The slot words decode as rebases to the expected image offsets.
        assert_eq!(plan.slot_words.len(), 2);
        let w0 = ChainWord64::new(plan.slot_words[0].1);
        assert!(!w0.is_bind());
        assert_eq!(w0.rebase_target(), 0);
        assert_eq!(w0.rebase_high8(), 0);
        assert_eq!(w0.next(), 2, "0x4000 -> 0x4008: 8 bytes = 2 strides");
        let w1 = ChainWord64::new(plan.slot_words[1].1);
        assert_eq!(w1.rebase_target(), 0x1000);
        assert_eq!(w1.next(), 0);

        // Empty imports parse cleanly.
        let imports = parse_imports(&plan.payload, &hdr).unwrap();
        assert_eq!(imports, [] as [pgr_format::fixups::Import; 0]);
    }

    #[test]
    fn binds_get_first_use_ordinals_and_a_name_pool() {
        // Two binds to the same lib in vaddr order: _b first (higher id but
        // lower address), then _a; plus a duplicate of _b (deduped).
        let slots = vec![
            bind(0x1_0000_4000, 1, "_b", 0, false),
            bind(0x1_0000_4008, 1, "_a", 0, false),
            bind(0x1_0000_4010, 1, "_b", 0, false),
        ];
        let segments = [(0x1_0000_4000, PAGE_SIZE_16K, 0x4000)];
        let inter = interner2();
        let plan = plan_fixups(slots, &segments, 0x1_0000_0000, PAGE_SIZE_16K, &inter).unwrap();

        assert_eq!(plan.imports.len(), 2, "duplicate bind deduped");
        assert_eq!(plan.imports[0].lib_ordinal, 1);
        assert_eq!(plan.imports[1].lib_ordinal, 1);
        // First-use order: the name pool carries _b then _a.
        assert_eq!(&plan.import_names, b"_b\0_a\0");
        assert_eq!(plan.imports[0].name_offset, 0);
        assert_eq!(plan.imports[1].name_offset, 3);

        let hdr = parse_header(&plan.payload).unwrap();
        assert_eq!(hdr.imports_count, 2);
        let parsed = parse_imports(&plan.payload, &hdr).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].lib_ordinal, 1);
        assert_eq!(parsed[1].lib_ordinal, 1);

        // Words: bind bit 63 set, ordinals 0 and 1.
        let w0 = ChainWord64::new(plan.slot_words[0].1);
        assert!(w0.is_bind());
        assert_eq!(w0.bind_ordinal(), 0);
        assert_eq!(w0.bind_addend(), 0);
        let w1 = ChainWord64::new(plan.slot_words[1].1);
        assert_eq!(w1.bind_ordinal(), 1);
        let w2 = ChainWord64::new(plan.slot_words[2].1);
        assert_eq!(w2.bind_ordinal(), 0, "duplicate shares the ordinal");
        assert_eq!(w2.next(), 0);
    }

    #[test]
    fn small_addends_travel_inline_large_in_the_import_entry() {
        let slots = vec![
            bind(0x1_0000_4000, 2, "_a", 24, false),
            bind(0x1_0000_4008, 2, "_a", 0x1000, false),
            bind(0x1_0000_4010, 2, "_a", -8, false),
        ];
        let segments = [(0x1_0000_4000, PAGE_SIZE_16K, 0x4000)];
        let inter = interner2();
        let plan = plan_fixups(slots, &segments, 0x1_0000_0000, PAGE_SIZE_16K, &inter).unwrap();

        assert_eq!(
            plan.imports.len(),
            3,
            "distinct addends are distinct imports"
        );
        // inline 24: import addend 0, word addend 24.
        let w0 = ChainWord64::new(plan.slot_words[0].1);
        assert_eq!(w0.bind_addend(), 24);
        assert_eq!(plan.imports[0].addend, 0);
        // 0x1000: outlined, word addend 0.
        let w1 = ChainWord64::new(plan.slot_words[1].1);
        assert_eq!(w1.bind_addend(), 0);
        assert_eq!(plan.imports[1].addend, 0x1000);
        // -8: outlined (negative), word addend 0.
        let w2 = ChainWord64::new(plan.slot_words[2].1);
        assert_eq!(w2.bind_addend(), 0);
        assert_eq!(plan.imports[2].addend, -8);
    }

    #[test]
    fn weak_binds_carry_the_weak_bit() {
        let slots = vec![bind(0x1_0000_4000, 1, "_a", 0, true)];
        let segments = [(0x1_0000_4000, PAGE_SIZE_16K, 0x4000)];
        let inter = interner2();
        let plan = plan_fixups(slots, &segments, 0x1_0000_0000, PAGE_SIZE_16K, &inter).unwrap();
        assert!(plan.has_weak_binds);
        assert!(plan.imports[0].weak_import);
        let hdr = parse_header(&plan.payload).unwrap();
        let parsed = parse_imports(&plan.payload, &hdr).unwrap();
        assert!(parsed[0].weak_import);
    }

    #[test]
    fn dense_page_packs_one_chain_with_every_slot() {
        // Within a 16 KiB page every pair of 8-aligned slots is at most
        // 0x3FF8 = 16 376 bytes apart, under the 16 380-byte stride bound,
        // so all four slots join one chain (multi-start is unreachable for
        // 64-bit formats on 16 KiB pages — kept for 32-bit/arm64e later).
        let slots = vec![
            rebase(0x1_0000_4010, 0x1_0000_0000),
            rebase(0x1_0000_4018, 0x1_0000_0000),
            rebase(0x1_0000_4100, 0x1_0000_0000),
            rebase(0x1_0000_4108, 0x1_0000_0000),
        ];
        let segments = [(0x1_0000_4000, 2 * PAGE_SIZE_16K, 0x4000)];
        let inter = interner2();
        let plan = plan_fixups(slots, &segments, 0x1_0000_0000, PAGE_SIZE_16K, &inter).unwrap();

        let hdr = parse_header(&plan.payload).unwrap();
        let starts = parse_starts_in_image(&plan.payload, hdr.starts_offset as usize).unwrap();
        let rec_off = hdr.starts_offset as usize + starts.seg_info_offset[0] as usize;
        let rec = parse_starts_in_segment(&plan.payload, rec_off).unwrap();
        assert_eq!(rec.page_count, 2);
        let heads0 = page_chain_starts(&plan.payload, rec_off, &rec, 0).unwrap();
        assert_eq!(heads0, vec![0x10], "single chain, head at page offset 0x10");
        assert_eq!(rec.page_start[1], DYLD_CHAINED_PTR_START_NONE);
        assert_eq!(plan.slot_words.len(), 4);
        // The chain walks 0x10 -> 0x18 -> 0x100 -> 0x108 -> end.
        assert_eq!(ChainWord64::new(plan.slot_words[0].1).next(), 2);
        assert_eq!(ChainWord64::new(plan.slot_words[2].1).next(), 2);
        assert_eq!(ChainWord64::new(plan.slot_words[3].1).next(), 0);
    }

    #[test]
    fn chain_starts_mirror_lists_every_head() {
        let slots = vec![
            rebase(0x1_0000_4010, 0x1_0000_0000),
            rebase(0x1_0000_4018, 0x1_0000_0000),
            rebase(0x1_0000_8010, 0x1_0000_0000),
        ];
        let segments = [(0x1_0000_4000, 2 * PAGE_SIZE_16K, 0x4000)];
        let inter = interner2();
        let plan = plan_fixups(slots, &segments, 0x1_0000_0000, PAGE_SIZE_16K, &inter).unwrap();
        assert_eq!(plan.chain_starts.len(), 8 + 2 * 4);
        let fmt = u32::from_le_bytes(plan.chain_starts[0..4].try_into().unwrap());
        let count = u32::from_le_bytes(plan.chain_starts[4..8].try_into().unwrap());
        assert_eq!(fmt, u32::from(DYLD_CHAINED_PTR_64_OFFSET));
        assert_eq!(count, 2, "one head on page 0, one on page 1");
        let h0 = u32::from_le_bytes(plan.chain_starts[8..12].try_into().unwrap());
        let h1 = u32::from_le_bytes(plan.chain_starts[12..16].try_into().unwrap());
        assert_eq!(h0, 0x4010, "image offset of the first head");
        assert_eq!(h1, 0x8010, "image offset of the page-1 head");
    }

    #[test]
    fn slots_outside_segments_error() {
        let slots = vec![rebase(0x2_0000_0000, 0)];
        let segments = [(0x1_0000_0000, PAGE_SIZE_16K, 0)];
        let inter = interner2();
        assert!(plan_fixups(slots, &segments, 0x1_0000_0000, PAGE_SIZE_16K, &inter).is_err());
    }

    #[test]
    fn misaligned_slots_error() {
        let slots = vec![rebase(0x1_0004_4012, 0)];
        let segments = [(0x1_0000_4000, PAGE_SIZE_16K, 0x4000)];
        let inter = interner2();
        assert!(plan_fixups(slots, &segments, 0x1_0000_0000, PAGE_SIZE_16K, &inter).is_err());
    }

    #[test]
    fn out_of_range_target_errors() {
        let slots = vec![rebase(
            0x1_0004_4010,
            0x10_0000_0000_0000, // > 44 bits
        )];
        let segments = [(0x1_0000_4000, PAGE_SIZE_16K, 0x4000)];
        let inter = interner2();
        assert!(plan_fixups(slots, &segments, 0, PAGE_SIZE_16K, &inter).is_err());
    }
}
