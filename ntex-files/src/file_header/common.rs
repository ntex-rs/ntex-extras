use super::{EntityTag, HttpDate};
use crate::{header, standard_header};

header! {
    /// `If-Unmodified-Since` header, defined in
    /// [RFC7232](http://tools.ietf.org/html/rfc7232#section-3.4)
    ///
    /// The `If-Unmodified-Since` header field makes the request method
    /// conditional on the selected representation's last modification date
    /// being earlier than or equal to the date provided in the field-value.
    /// This field accomplishes the same purpose as If-Match for cases where
    /// the user agent does not have an entity-tag for the representation.
    ///
    /// # ABNF
    ///
    /// ```text
    /// If-Unmodified-Since = HTTP-date
    /// ```
    ///
    /// # Example values
    ///
    /// * `Sat, 29 Oct 1994 19:43:31 GMT`
    ///
    (IfUnmodifiedSince, "If-Unmodified-Since") => [HttpDate]
}

standard_header!(IfUnmodifiedSince, IF_UNMODIFIED_SINCE);

header! {
    /// `If-Modified-Since` header, defined in
    /// [RFC7232](http://tools.ietf.org/html/rfc7232#section-3.3)
    ///
    /// The `If-Modified-Since` header field makes a GET or HEAD request
    /// method conditional on the selected representation's modification date
    /// being more recent than the date provided in the field-value.
    /// Transfer of the selected representation's data is avoided if that
    /// data has not changed.
    ///
    /// # ABNF
    ///
    /// ```text
    /// If-Unmodified-Since = HTTP-date
    /// ```
    ///
    /// # Example values
    /// * `Sat, 29 Oct 1994 19:43:31 GMT`
    ///
    (IfModifiedSince, "If-Modified-Since") => [HttpDate]

}

standard_header!(IfModifiedSince, IF_MODIFIED_SINCE);

header! {
    /// `Last-Modified` header, defined in
    /// [RFC7232](http://tools.ietf.org/html/rfc7232#section-2.2)
    ///
    /// The `Last-Modified` header field in a response provides a timestamp
    /// indicating the date and time at which the origin server believes the
    /// selected representation was last modified, as determined at the
    /// conclusion of handling the request.
    ///
    /// # ABNF
    ///
    /// ```text
    /// Expires = HTTP-date
    /// ```
    ///
    /// # Example values
    ///
    /// * `Sat, 29 Oct 1994 19:43:31 GMT`
    ///
    (LastModified, "Last-Modified") => [HttpDate]

}

standard_header!(LastModified, LAST_MODIFIED);

header! {
    /// `ETag` header, defined in [RFC7232](http://tools.ietf.org/html/rfc7232#section-2.3)
    ///
    /// The `ETag` header field in a response provides the current entity-tag
    /// for the selected representation, as determined at the conclusion of
    /// handling the request.  An entity-tag is an opaque validator for
    /// differentiating between multiple representations of the same
    /// resource, regardless of whether those multiple representations are
    /// due to resource state changes over time, content negotiation
    /// resulting in multiple representations being valid at the same time,
    /// or both.  An entity-tag consists of an opaque quoted string, possibly
    /// prefixed by a weakness indicator.
    ///
    /// # ABNF
    ///
    /// ```text
    /// ETag       = entity-tag
    /// ```
    ///
    /// # Example values
    ///
    /// * `"xyzzy"`
    /// * `W/"xyzzy"`
    /// * `""`
    ///
    (ETag, "ETag") => [EntityTag]
}

standard_header!(ETag, ETAG);

header! {
    /// `If-None-Match` header, defined in
    /// [RFC7232](https://tools.ietf.org/html/rfc7232#section-3.2)
    ///
    /// The `If-None-Match` header field makes the request method conditional
    /// on a recipient cache or origin server either not having any current
    /// representation of the target resource, when the field-value is "*",
    /// or having a selected representation with an entity-tag that does not
    /// match any of those listed in the field-value.
    ///
    /// A recipient MUST use the weak comparison function when comparing
    /// entity-tags for If-None-Match (Section 2.3.2), since weak entity-tags
    /// can be used for cache validation even if there have been changes to
    /// the representation data.
    ///
    /// # ABNF
    ///
    /// ```text
    /// If-None-Match = "*" / 1#entity-tag
    /// ```
    ///
    /// # Example values
    ///
    /// * `"xyzzy"`
    /// * `W/"xyzzy"`
    /// * `"xyzzy", "r2d2xxxx", "c3piozzzz"`
    /// * `W/"xyzzy", W/"r2d2xxxx", W/"c3piozzzz"`
    /// * `*`
    ///
    (IfNoneMatch, "If-None-Match") => {Any / (EntityTag)+}
}

standard_header!(IfNoneMatch, IF_NONE_MATCH);

header! {
    /// `If-Match` header, defined in
    /// [RFC7232](https://tools.ietf.org/html/rfc7232#section-3.1)
    ///
    /// The `If-Match` header field makes the request method conditional on
    /// the recipient origin server either having at least one current
    /// representation of the target resource, when the field-value is "*",
    /// or having a current representation of the target resource that has an
    /// entity-tag matching a member of the list of entity-tags provided in
    /// the field-value.
    ///
    /// An origin server MUST use the strong comparison function when
    /// comparing entity-tags for `If-Match`, since the client
    /// intends this precondition to prevent the method from being applied if
    /// there have been any changes to the representation data.
    ///
    /// # ABNF
    ///
    /// ```text
    /// If-Match = "*" / 1#entity-tag
    /// ```
    ///
    /// # Example values
    ///
    /// * `"xyzzy"`
    /// * "xyzzy", "r2d2xxxx", "c3piozzzz"
    ///
    (IfMatch, "If-Match") => {Any / (EntityTag)+}

}

standard_header!(IfMatch, IF_MATCH);
