use super::error::{Error, Result};
use std::fmt::{self, Display};
use std::str::FromStr;

/// check that each char in the slice is either:
/// 1. `%x21`, or
/// 2. in the range `%x23` to `%x7E`, or
/// 3. above `%x80`
fn check_slice_validity(slice: &str) -> bool {
    slice
        .bytes()
        .all(|c| c == b'\x21' || (b'\x23'..=b'\x7e').contains(&c) | (c >= b'\x80'))
}

/// An entity tag, defined in [RFC7232](https://tools.ietf.org/html/rfc7232#section-2.3)
///
/// An entity tag consists of a string enclosed by two literal double quotes.
/// Preceding the first double quote is an optional weakness indicator,
/// which always looks like `W/`. Examples for valid tags are `"xyzzy"` and `W/"xyzzy"`.
///
/// # ABNF
///
/// ```text
/// entity-tag = [ weak ] opaque-tag
/// weak       = %x57.2F ; "W/", case-sensitive
/// opaque-tag = DQUOTE *etagc DQUOTE
/// etagc      = %x21 / %x23-7E / obs-text
///            ; VCHAR except double quotes, plus obs-text
/// ```
///
/// # Errors
///
/// Parsing rejects invalid opaque-value characters, missing quotes, or a weak
/// prefix other than the case-sensitive `W/`. Surrounding whitespace is not trimmed.
///
/// # Comparison
/// Use [`Self::strong_eq`] or [`Self::weak_eq`] according to the conditional
/// header being evaluated. `==` checks both the weakness flag and opaque value.
///
/// The example below shows the results for a set of entity-tag pairs and
/// both the weak and strong comparison function results:
///
/// | ETag 1  | ETag 2  | Strong Comparison | Weak Comparison |
/// |---------|---------|-------------------|-----------------|
/// | `W/"1"` | `W/"1"` | no match          | match           |
/// | `W/"1"` | `W/"2"` | no match          | no match        |
/// | `W/"1"` | `"1"`   | no match          | match           |
/// | `"1"`   | `"1"`   | match             | match           |
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntityTag {
    /// Whether the validator is weak; strong comparison rejects weak tags.
    pub weak: bool,
    /// The opaque string in between the DQUOTEs
    tag: String,
}

impl EntityTag {
    /// Constructs a tag from its weakness flag and unquoted opaque value.
    ///
    /// # Panics
    ///
    /// Panics if `tag` contains a double quote, space, ASCII control byte, or DEL.
    /// Empty and non-ASCII values are allowed.
    pub fn new(weak: bool, tag: String) -> EntityTag {
        assert!(check_slice_validity(&tag), "Invalid tag: {:?}", tag);
        EntityTag { weak, tag }
    }

    /// Constructs a weak tag from an unquoted opaque value.
    ///
    /// # Panics
    ///
    /// Panics for the invalid characters described by [`Self::new`].
    pub fn weak(tag: String) -> EntityTag {
        EntityTag::new(true, tag)
    }

    /// Constructs a strong tag from an unquoted opaque value.
    ///
    /// # Panics
    ///
    /// Panics for the invalid characters described by [`Self::new`].
    pub fn strong(tag: String) -> EntityTag {
        EntityTag::new(false, tag)
    }

    /// Returns the opaque value without quotes or the weakness prefix.
    pub fn tag(&self) -> &str {
        self.tag.as_ref()
    }

    /// Replaces the unquoted opaque value without changing the weakness flag.
    ///
    /// # Panics
    ///
    /// Panics for the invalid characters described by [`Self::new`], leaving the
    /// existing tag unchanged.
    pub fn set_tag(&mut self, tag: String) {
        assert!(check_slice_validity(&tag), "Invalid tag: {:?}", tag);
        self.tag = tag
    }

    /// For strong comparison two entity-tags are equivalent if both are not weak and their
    /// opaque-tags match character-by-character.
    pub fn strong_eq(&self, other: &EntityTag) -> bool {
        !self.weak && !other.weak && self.tag == other.tag
    }

    /// For weak comparison two entity-tags are equivalent if their
    /// opaque-tags match character-by-character, regardless of either or
    /// both being tagged as "weak".
    pub fn weak_eq(&self, other: &EntityTag) -> bool {
        self.tag == other.tag
    }

    /// Returns the inverse of [`Self::strong_eq`].
    pub fn strong_ne(&self, other: &EntityTag) -> bool {
        !self.strong_eq(other)
    }

    /// Returns the inverse of [`Self::weak_eq`].
    pub fn weak_ne(&self, other: &EntityTag) -> bool {
        !self.weak_eq(other)
    }
}

impl Display for EntityTag {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.weak {
            write!(f, "W/\"{}\"", self.tag)
        } else {
            write!(f, "\"{}\"", self.tag)
        }
    }
}

impl FromStr for EntityTag {
    type Err = Error;
    fn from_str(slice: &str) -> Result<EntityTag> {
        let length: usize = slice.len();
        // Early exits if it doesn't terminate in a DQUOTE.
        if !slice.ends_with('"') || slice.len() < 2 {
            return Err(Error::Header);
        }
        // The etag is weak if its first char is not a DQUOTE.
        if slice.len() >= 2 && slice.starts_with('"') && check_slice_validity(&slice[1..length - 1])
        {
            // No need to check if the last char is a DQUOTE,
            // we already did that above.
            return Ok(EntityTag {
                weak: false,
                tag: slice[1..length - 1].to_owned(),
            });
        } else if slice.len() >= 4
            && slice.starts_with("W/\"")
            && check_slice_validity(&slice[3..length - 1])
        {
            return Ok(EntityTag {
                weak: true,
                tag: slice[3..length - 1].to_owned(),
            });
        }
        Err(Error::Header)
    }
}

#[cfg(test)]
mod tests {
    use super::EntityTag;

    #[test]
    fn test_etag_parse_success() {
        // Expected success
        assert_eq!(
            "\"foobar\"".parse::<EntityTag>().unwrap(),
            EntityTag::strong("foobar".to_owned())
        );
        assert_eq!(
            "\"\"".parse::<EntityTag>().unwrap(),
            EntityTag::strong("".to_owned())
        );
        assert_eq!(
            "W/\"weaktag\"".parse::<EntityTag>().unwrap(),
            EntityTag::weak("weaktag".to_owned())
        );
        assert_eq!(
            "W/\"\x65\x62\"".parse::<EntityTag>().unwrap(),
            EntityTag::weak("\x65\x62".to_owned())
        );
        assert_eq!(
            "W/\"\"".parse::<EntityTag>().unwrap(),
            EntityTag::weak("".to_owned())
        );
    }

    #[test]
    fn test_etag_parse_failures() {
        // Expected failures
        assert!("no-dquotes".parse::<EntityTag>().is_err());
        assert!(
            "w/\"the-first-w-is-case-sensitive\""
                .parse::<EntityTag>()
                .is_err()
        );
        assert!("".parse::<EntityTag>().is_err());
        assert!("\"unmatched-dquotes1".parse::<EntityTag>().is_err());
        assert!("unmatched-dquotes2\"".parse::<EntityTag>().is_err());
        assert!("matched-\"dquotes\"".parse::<EntityTag>().is_err());
    }

    #[test]
    fn test_etag_fmt() {
        assert_eq!(
            format!("{}", EntityTag::strong("foobar".to_owned())),
            "\"foobar\""
        );
        assert_eq!(format!("{}", EntityTag::strong("".to_owned())), "\"\"");
        assert_eq!(
            format!("{}", EntityTag::weak("weak-etag".to_owned())),
            "W/\"weak-etag\""
        );
        assert_eq!(
            format!("{}", EntityTag::weak("\u{0065}".to_owned())),
            "W/\"\x65\""
        );
        assert_eq!(format!("{}", EntityTag::weak("".to_owned())), "W/\"\"");
    }

    #[test]
    fn test_cmp() {
        // | ETag 1  | ETag 2  | Strong Comparison | Weak Comparison |
        // |---------|---------|-------------------|-----------------|
        // | `W/"1"` | `W/"1"` | no match          | match           |
        // | `W/"1"` | `W/"2"` | no match          | no match        |
        // | `W/"1"` | `"1"`   | no match          | match           |
        // | `"1"`   | `"1"`   | match             | match           |
        let mut etag1 = EntityTag::weak("1".to_owned());
        let mut etag2 = EntityTag::weak("1".to_owned());
        assert!(!etag1.strong_eq(&etag2));
        assert!(etag1.weak_eq(&etag2));
        assert!(etag1.strong_ne(&etag2));
        assert!(!etag1.weak_ne(&etag2));

        etag1 = EntityTag::weak("1".to_owned());
        etag2 = EntityTag::weak("2".to_owned());
        assert!(!etag1.strong_eq(&etag2));
        assert!(!etag1.weak_eq(&etag2));
        assert!(etag1.strong_ne(&etag2));
        assert!(etag1.weak_ne(&etag2));

        etag1 = EntityTag::weak("1".to_owned());
        etag2 = EntityTag::strong("1".to_owned());
        assert!(!etag1.strong_eq(&etag2));
        assert!(etag1.weak_eq(&etag2));
        assert!(etag1.strong_ne(&etag2));
        assert!(!etag1.weak_ne(&etag2));

        etag1 = EntityTag::strong("1".to_owned());
        etag2 = EntityTag::strong("1".to_owned());
        assert!(etag1.strong_eq(&etag2));
        assert!(etag1.weak_eq(&etag2));
        assert!(!etag1.strong_ne(&etag2));
        assert!(!etag1.weak_ne(&etag2));
    }

    /// STATEMENT: Updating an `EntityTag` changes its validator while rejecting invalid replacements atomically.
    ///
    /// HOW:
    /// - Parse a strong revision tag, replace its opaque value with Unicode and punctuation, and reparse its formatting.
    /// - Check old and weak validators compare correctly, then reject spaces, quotes, and control bytes without changing the tag.
    #[test]
    fn updating_entity_tags_preserves_validation_and_comparison() {
        let original: EntityTag = "\"revision-1\"".parse().unwrap();
        let mut updated = original.clone();
        updated.set_tag("révision!#~\\".into());
        let reparsed: EntityTag = updated.to_string().parse().unwrap();
        assert_eq!(reparsed, updated);
        assert!(updated.strong_ne(&original));
        assert!(updated.weak_ne(&original));
        assert!(updated.strong_eq(&EntityTag::strong("révision!#~\\".into())));
        assert!(updated.weak_eq(&EntityTag::weak("révision!#~\\".into())));
        assert!(!updated.strong_eq(&EntityTag::weak("révision!#~\\".into())));
        for invalid in ["has space", "has\"quote", "has\tcontrol", "has\u{7f}delete"] {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                updated.set_tag(invalid.into());
            }));
            assert!(result.is_err(), "{invalid:?}");
            assert_eq!(updated, reparsed);
        }
    }
}
