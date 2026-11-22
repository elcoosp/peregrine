//! The `-ObjC` archive pull (M43, widened at M49): ld64's liveness rule
//! — *"Loads all members of static archive libraries that implement an
//! Objective-C class or category"* (the `ld` man page) — as a nameable
//! decision on [`crate::layout::LinkConfig`]. The `ObjC` runtime
//! registers classes, categories and metaclasses by section address at
//! load time; no static reference to the member's symbols exists to
//! seed the archive pull fixpoint, so the decision rides the ranlib
//! index (the member's own defined externals, which every link already
//! parses): a member whose index entry names one of the metadata
//! families below rides the pull, everything else keeps the
//! reference-driven rule.
//!
//! Scope (M49 closes the ledger ld64's own matcher draws): the modern
//! clang emitter's metadata prefixes — the class (`_OBJC_CLASS_$_`),
//! its metaclass (a class's implementation defines it beside the class
//! symbol) and the category (`_OBJC_CATEGORY_$_`) — plus, since M49,
//! the ObjC1/GCC-era C symbols the same matcher reads: the class
//! (`.objc_class_name_<Class>`) and the category
//! (`.objc_category_name_<Class>_<Category>`) forms — the `.objc_c`
//! index-prefix family beside `_OBJC_CLASS_$_` (ld64-609
//! `archive_file.cpp`: the pull matches index entries on
//! `strncmp(name, ".objc_c", 7) == 0 || strncmp(name, "_OBJC_CLASS_$_", 14) == 0`).
//! The exclusions stay named and out: the protocol list
//! (`_OBJC_PROTOCOL_$_` — a protocol is neither a class nor a category,
//! which is what the man page names, and ld64's matcher reads neither)
//! and the pre-2.0 method-symbol form (`+[Class(Category) method]` —
//! ld64's matcher reads ranlib index entries only, and a method rides
//! its class or category's metadata symbols, so the form has no pull
//! role; the runtime registers methods by section address).

/// The modern `ObjC` metadata symbol prefixes the `-ObjC` pull reads,
/// in longest-first order (so a classifier can walk them either way).
pub const OBJC_METADATA_PREFIXES: [&[u8]; 3] = [
    b"_OBJC_METACLASS_$_",
    b"_OBJC_CATEGORY_$_",
    b"_OBJC_CLASS_$_",
];

/// The ObjC1/GCC-era `ObjC` symbol prefixes the `-ObjC` pull reads
/// (M49 — ld64's `.objc_c` index-prefix family): the category form
/// first, extending the class form. Neither prefix is a prefix of the
/// other (they diverge at `class` vs `category`), so the classifier's
/// arm order is a documentation choice this table pins.
pub const OBJC1_METADATA_PREFIXES: [&[u8]; 2] = [b".objc_category_name_", b".objc_class_name_"];

/// The `ObjC` metadata family a symbol name belongs to: the modern
/// clang emitter's `$_`-prefixed definitions or the ObjC1/GCC-era C
/// symbols (M49). The pull admits both families; the exclusions (the
/// protocol list, the pre-2.0 method-symbol form) classify as
/// [`None`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjcFamily {
    /// `_OBJC_CLASS_$_<Name>` — the modern class definition.
    Class,
    /// `_OBJC_METACLASS_$_<Name>` — the metaclass a class's
    /// implementation defines beside the class symbol.
    Metaclass,
    /// `_OBJC_CATEGORY_$_<Name>` — the modern category definition.
    Category,
    /// `.objc_class_name_<Name>` — the ObjC1/GCC-era class symbol
    /// (M49: ld64's `.objc_c` index-prefix family).
    PreTwoPointZeroClass,
    /// `.objc_category_name_<Class>_<Category>` — the ObjC1/GCC-era
    /// category symbol (M49: the same family).
    PreTwoPointZeroCategory,
}

/// Classifies a symbol name into the `ObjC` metadata family the `-ObjC`
/// pull honors, or [`None`] when the name is not pull-family metadata
/// (see the [module doc](self) for the scope and the exclusions).
#[must_use]
pub fn classify_objc_metadata(name: &[u8]) -> Option<ObjcFamily> {
    if name.starts_with(b"_OBJC_METACLASS_$_") {
        return Some(ObjcFamily::Metaclass);
    }
    if name.starts_with(b"_OBJC_CATEGORY_$_") {
        return Some(ObjcFamily::Category);
    }
    if name.starts_with(b"_OBJC_CLASS_$_") {
        return Some(ObjcFamily::Class);
    }
    if name.starts_with(b".objc_category_name_") {
        return Some(ObjcFamily::PreTwoPointZeroCategory);
    }
    if name.starts_with(b".objc_class_name_") {
        return Some(ObjcFamily::PreTwoPointZeroClass);
    }
    None
}

/// M115 — the category family's base-class name: the base the category
/// merges into. The modern family names it directly
/// (`_OBJC_CATEGORY_$_Dog` → `Dog`); the pre-2.0 GCC-era form names it
/// before the parenthesized category (`.objc_category_name_Dog(Traits)`
/// → `Dog`) — a form without the paren names no base (the classifier
/// stays conservative: a shape it cannot name never merges).
#[must_use]
pub fn category_base_class(name: &[u8]) -> Option<&[u8]> {
    if let Some(rest) = name.strip_prefix(b"_OBJC_CATEGORY_$_") {
        return Some(rest);
    }
    if let Some(rest) = name.strip_prefix(b".objc_category_name_") {
        let end = rest.iter().position(|&b| b == b'(')?;
        return Some(&rest[..end]);
    }
    None
}

/// M115 — the class family's base name: the class a category merges
/// into (`_OBJC_CLASS_$_Dog` and `_OBJC_METACLASS_$_Dog` both name
/// `Dog`).
#[must_use]
pub fn class_family_base(name: &[u8]) -> Option<&[u8]> {
    if let Some(rest) = name.strip_prefix(b"_OBJC_CLASS_$_") {
        return Some(rest);
    }
    if let Some(rest) = name.strip_prefix(b"_OBJC_METACLASS_$_") {
        return Some(rest);
    }
    None
}

/// M115 — the category-merge classification for one registration
/// section (`__objc_catlist` / `__objc_nlcatlist`): the section merges
/// when EVERY entry names — through its 8-byte unsigned-pointer slot's
/// relocation — a category family whose base class rides this image
/// (the image's own `_OBJC_CLASS_$_`/`_OBJC_METACLASS_$_` winners).
/// The classifier never mutates a shape it cannot parse: a size off
/// the pointer stride, a slot that is not an 8-byte unsigned pointer
/// at the entry boundary, or a bound name off the category families
/// keeps the section verbatim (the unmergeable shape registers exactly
/// as the input carried it). The ld64 optimization's decision point in
/// Pass 3's layout consults this — the merged category registers
/// through its base class's registration, so the separate section
/// drops (`usize::MAX`, the M105 sentinel).
pub(crate) fn registration_merges(
    in_sect: &crate::object::InputSection,
    interner: &crate::interner::Interner,
    defined_class_bases: &std::collections::HashSet<Vec<u8>>,
) -> bool {
    if !matches!(in_sect.name.as_str(), "__objc_catlist" | "__objc_nlcatlist") {
        return false;
    }
    if in_sect.size == 0 || in_sect.size % 8 != 0 {
        return false;
    }
    let entries = (in_sect.size / 8) as usize;
    // One 8-byte unsigned pointer slot per entry, at the entry boundary
    // (the map keeps it order-independent — the reader's order is the
    // input's, the classification must not ride it).
    let mut slots: std::collections::HashMap<u32, &crate::object::DecodedReloc> =
        std::collections::HashMap::new();
    for r in &in_sect.relocs {
        if matches!(r.kind, crate::object::RelocKind::Unsigned) && !r.pcrel && r.length_log2 == 3 {
            slots.insert(r.offset, r);
        }
    }
    for e in 0..entries as u32 {
        let Some(r) = slots.get(&(e * 8)) else {
            return false;
        };
        let crate::object::RelocTarget::Extern(id) = r.target else {
            return false;
        };
        let name = interner.name(id);
        let Some(base) = category_base_class(name.as_bytes()) else {
            return false;
        };
        if !defined_class_bases.contains(base) {
            return false;
        }
    }
    true
}

/// True when the name rides one of the metadata families the archive
/// pull reads (the M43 classifier's face).
#[must_use]
pub fn defines_objc_metadata(name: &[u8]) -> bool {
    classify_objc_metadata(name).is_some()
}

/// M6/D-R3: the `_objc_msgSend$<selector>` callsite family. Modern clang
/// emits one undefined `_objc_msgSend$<selector>` symbol per
/// `objc_msgSend` callsite; ld64 resolves each by synthesizing a stub in
/// `__TEXT,__objc_stubs` that loads the selector string (from
/// `__objc_methname`) into `x1`, the IMP (from a `__got` slot bound to
/// `_objc_msgSend`) into `x16`, and branches. This classifier splits the
/// selector suffix off the prefix — the string the synthesizer dedups
/// into `__objc_methname` (NUL-terminated, content-addressed like
/// `S_CSTRING_LITERALS`). Returns [`None`] for every other name (the
/// metadata families above, plain dylib calls, defined symbols).
#[must_use]
pub fn objc_msgsend_selector(name: &[u8]) -> Option<&[u8]> {
    name.strip_prefix(pgr_format::consts::OBJC_MSGSEND_PREFIX)
}

/// M6/D-R3: true when the name is a `_objc_msgSend$<selector>` callsite
/// the stub synthesizer resolves (the install-walk's classifier — the
/// resolution lane these names ride instead of the error lane).
#[must_use]
pub fn is_objc_msgsend_callsite(name: &[u8]) -> bool {
    objc_msgsend_selector(name).is_some()
}

#[cfg(test)]
mod tests {
    use super::{
        OBJC1_METADATA_PREFIXES, OBJC_METADATA_PREFIXES, ObjcFamily, classify_objc_metadata,
        defines_objc_metadata, is_objc_msgsend_callsite, objc_msgsend_selector,
    };

    #[test]
    fn the_metadata_family_classifies() {
        for (name, family) in [
            (&b"_OBJC_CLASS_$_Dog"[..], ObjcFamily::Class),
            (b"_OBJC_METACLASS_$_Dog", ObjcFamily::Metaclass),
            (b"_OBJC_CATEGORY_$_Dog_Tricks", ObjcFamily::Category),
            (b"_OBJC_CATEGORY_$_Dog_Tricks_Swift", ObjcFamily::Category),
            (b".objc_class_name_Dog", ObjcFamily::PreTwoPointZeroClass),
            (
                b".objc_category_name_Dog_Tricks",
                ObjcFamily::PreTwoPointZeroCategory,
            ),
        ] {
            assert_eq!(
                classify_objc_metadata(name),
                Some(family),
                "{:?} names class or category metadata",
                String::from_utf8_lossy(name)
            );
            assert!(
                defines_objc_metadata(name),
                "{:?} rides the pull",
                String::from_utf8_lossy(name)
            );
        }
    }

    #[test]
    fn the_exclusions_stay_out() {
        for name in [
            &b"_OBJC_PROTOCOL_$_Foo"[..],
            b"+[Dog(Tricks) bark]",
            b"_OBJC_IVAR_$_Dog._tail",
            b"_Dog",
            b"_plain_fn",
            b"",
        ] {
            assert!(
                !defines_objc_metadata(name),
                "{:?} is not the class-or-category metadata the man page names",
                String::from_utf8_lossy(name)
            );
            assert_eq!(
                classify_objc_metadata(name),
                None,
                "{:?} names no pull family",
                String::from_utf8_lossy(name)
            );
        }
    }

    #[test]
    fn the_prefixes_order_longest_first() {
        let mut sorted = OBJC_METADATA_PREFIXES;
        sorted.sort();
        assert_ne!(
            OBJC_METADATA_PREFIXES, sorted,
            "the table documents longest-first order (the metaclass prefix \
             extends the class prefix)"
        );
        let mut sorted1 = OBJC1_METADATA_PREFIXES;
        sorted1.sort();
        assert_eq!(
            OBJC1_METADATA_PREFIXES, sorted1,
            "the ObjC1 table lists the category form first (it extends the \
             class form); the two prefixes diverge before either ends, so \
             the order is a documentation choice the test pins"
        );
    }

    #[test]
    fn the_dot_family_reads_the_two_named_forms() {
        // The ObjC1 families are exactly the `.objc_class_name_` /
        // `.objc_category_name_` forms — ld64's `.objc_c` index prefix
        // matches nothing else in practice, and the classifier keeps the
        // two named forms rather than a bare `.objc_c` prefix (a bare
        // prefix would admit `.objc_...` runtime-internal names the
        // matcher never met in the wild).
        for name in [
            &b".objc_class_Dog"[..],
            b".objc_category_Dog_Tricks",
            b".objc_classname_Dog",
            b".objc_",
        ] {
            assert!(
                !defines_objc_metadata(name),
                "{:?} is not one of the two named ObjC1 forms",
                String::from_utf8_lossy(name)
            );
        }
    }

    #[test]
    fn the_msgsend_callsite_classifies_its_selector() {
        // The modern clang callsite family: one undefined
        // `_objc_msgSend$<selector>` per `objc_msgSend` call. The
        // classifier splits the selector suffix the synthesizer dedups
        // into `__objc_methname`.
        for (name, sel) in [
            (&b"_objc_msgSend$count"[..], &b"count"[..]),
            (b"_objc_msgSend$initWithFrame:options:", b"initWithFrame:options:"),
            (b"_objc_msgSend$alloc", b"alloc"),
            (b"_objc_msgSend$myCategory_selector:foo:", b"myCategory_selector:foo:"),
        ] {
            assert_eq!(
                objc_msgsend_selector(name),
                Some(sel),
                "{:?} splits its selector suffix",
                String::from_utf8_lossy(name)
            );
            assert!(
                is_objc_msgsend_callsite(name),
                "{:?} is the msgSend callsite family",
                String::from_utf8_lossy(name)
            );
        }
    }

    #[test]
    fn the_msgsend_classifier_stays_out_of_everything_else() {
        // The metadata families, plain dylib calls and defined symbols
        // never classify as a msgSend callsite — the synthesizer never
        // engages for them (the `-ObjC` pull, the `__stubs` family and
        // the in-image definitions ride their own lanes).
        for name in [
            &b"_OBJC_CLASS_$_Dog"[..],
            b".objc_class_name_Dog",
            b"_objc_msgSend",
            b"_printf",
            b"_main",
            b"_objc_msgSend_extra",     // not the `$` form
            b"objc_msgSend$count",      // missing the leading underscore
            b"",
        ] {
            assert_eq!(
                objc_msgsend_selector(name),
                None,
                "{:?} is not a msgSend callsite",
                String::from_utf8_lossy(name)
            );
            assert!(
                !is_objc_msgsend_callsite(name),
                "{:?} rides no synthesizer",
                String::from_utf8_lossy(name)
            );
        }
    }
}
