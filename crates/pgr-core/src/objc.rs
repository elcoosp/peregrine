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

/// True when the symbol name is `ObjC` metadata the `-ObjC` pull honors:
/// a class, metaclass or category definition — the modern clang
/// emitter's `$_`-prefixed family or the ObjC1/GCC-era C symbols
/// (M49; see the [module doc](self) for the scope and the exclusions).
#[must_use]
pub fn defines_objc_metadata(name: &[u8]) -> bool {
    classify_objc_metadata(name).is_some()
}

#[cfg(test)]
mod tests {
    use super::{
        OBJC_METADATA_PREFIXES, OBJC1_METADATA_PREFIXES, ObjcFamily, classify_objc_metadata,
        defines_objc_metadata,
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
}
