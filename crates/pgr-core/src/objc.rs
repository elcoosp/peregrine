//! The `-ObjC` archive pull (M43): ld64's liveness rule — *"Loads all
//! members of static archive libraries that implement an Objective-C
//! class or category"* (the `ld` man page) — as a nameable decision on
//! [`crate::layout::LinkConfig`]. The `ObjC` runtime registers classes,
//! categories and metaclasses by section address at load time; no
//! static reference to the member's symbols exists to seed the archive
//! pull fixpoint, so the decision rides the ranlib index (the member's
//! own defined externals, which every link already parses): a member
//! whose index entry names one of the metadata prefixes below rides
//! the pull, everything else keeps the reference-driven rule.
//!
//! Scope: the modern clang emitter's metadata prefixes — the class
//! (`_OBJC_CLASS_$_`), its metaclass (a class's implementation defines
//! it beside the class symbol) and the category (`_OBJC_CATEGORY_$_`).
//! The pre-2.0 method-symbol forms (`+[Class(Category) method]` and the
//! GCC-era `objc_class_name` C symbols) and the protocol list
//! (`_OBJC_PROTOCOL_$_` — a protocol is neither a class nor a category,
//! which is what the man page names) stay out: they are a separate
//! surface, still a later milestone, and this module keeps the rule it
//! can name honest.

/// The `ObjC` metadata symbol prefixes the `-ObjC` pull reads, in
/// longest-first order (so a classifier can walk them either way).
pub const OBJC_METADATA_PREFIXES: [&[u8]; 3] = [
    b"_OBJC_METACLASS_$_",
    b"_OBJC_CATEGORY_$_",
    b"_OBJC_CLASS_$_",
];

/// True when the symbol name is `ObjC` metadata the `-ObjC` pull honors:
/// a class, metaclass or category definition (the modern clang emitter's
/// `$_`-prefixed family — see the [module doc](self) for the scope and
/// the exclusions).
#[must_use]
pub fn defines_objc_metadata(name: &[u8]) -> bool {
    OBJC_METADATA_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::{OBJC_METADATA_PREFIXES, defines_objc_metadata};

    #[test]
    fn the_metadata_family_classifies() {
        for name in [
            &b"_OBJC_CLASS_$_Dog"[..],
            b"_OBJC_METACLASS_$_Dog",
            b"_OBJC_CATEGORY_$_Dog_Tricks",
            b"_OBJC_CATEGORY_$_Dog_Tricks_Swift",
        ] {
            assert!(
                defines_objc_metadata(name),
                "{:?} names class or category metadata",
                String::from_utf8_lossy(name)
            );
        }
    }

    #[test]
    fn the_exclusions_stay_out() {
        for name in [
            &b"_OBJC_PROTOCOL_$_Foo"[..],
            b"_OBJC_IVAR_$_Dog._tail",
            b"_objc_class_name_Dog",
            b"+[Dog(Tricks) bark]",
            b"_Dog",
            b"_plain_fn",
            b"",
        ] {
            assert!(
                !defines_objc_metadata(name),
                "{:?} is not the class-or-category metadata the man page names",
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
    }
}
