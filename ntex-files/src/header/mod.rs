//! Typed header values used for file responses and conditional requests.
//!
//! Parse values with [`Header::parse_header`](crate::header::Header::parse_header)
//! using [`Raw`](crate::header::Raw) or another
//! [`RawLike`](crate::header::RawLike) source. Format them with [`std::fmt::Display`];
//! [`StandardHeader::http_header_name`](crate::header::StandardHeader::http_header_name)
//! supplies the corresponding HTTP header name.
//! Single-value headers reject repeated lines. Entity-tag lists merge lines,
//! preserve quoted commas, and skip individual entries that fail to parse.
//! Wildcard `*` is recognized only as the exact contents of a single raw line.
//!
//! ```
//! use ntex_files::header::{EntityTag, Header, IfNoneMatch, Raw};
//!
//! let raw = Raw::from("W/\"revision-1\", \"revision-2\"");
//! let parsed = IfNoneMatch::parse_header(&raw).unwrap();
//! assert_eq!(parsed, IfNoneMatch::Items(vec![
//!     EntityTag::weak("revision-1".into()),
//!     EntityTag::strong("revision-2".into()),
//! ]));
//! ```

#![allow(dead_code, clippy::useless_conversion)]

mod charset;
mod common;
mod content_disposition;
mod entity;
pub(crate) mod error;
mod http_date;
pub(crate) mod method;
pub(crate) mod parsing;
mod raw;

pub use charset::Charset;
pub use common::*;
pub use content_disposition::*;
pub use entity::EntityTag;
use http::HeaderValue;
pub use http_date::HttpDate;
pub use raw::{Raw, RawLike};

use self::sealed::HeaderClone;

/// Identification, parsing, and formatting of a typed header value.
///
/// Header names and parsing require a concrete sized type; formatting is also
/// available through trait objects. Implementors must be [`Clone`], [`Send`],
/// [`Sync`], and `'static`.
pub trait Header: 'static + HeaderClone + Send + Sync {
    /// Returns the HTTP header field name, such as `Content-Disposition`.
    fn header_name() -> &'static str
    where
        Self: Sized;

    /// Parses raw field-value lines for a single header name.
    ///
    /// Single-value implementations reject multiple lines. List implementations
    /// may combine them; the accepted syntax depends on the header type.
    ///
    /// # Errors
    ///
    /// Returns a parsing error for invalid input or unsupported line counts.
    /// Entity-tag lists skip invalid individual items, but reject invalid UTF-8.
    fn parse_header<'a, T>(raw: &'a T) -> error::Result<Self>
    where
        T: RawLike<'a>,
        Self: Sized;

    /// Formats the value using the supplied header formatter.
    ///
    /// Implementations typically delegate to [`Formatter::fmt_line`]. Multiple
    /// calls represent multiple field-value lines.
    ///
    /// # Errors
    ///
    /// Returns [`std::fmt::Error`] if writing or formatting a value fails.
    fn fmt_header(&self, f: &mut Formatter) -> std::fmt::Result;
}

mod sealed {
    use super::Header;

    #[doc(hidden)]
    pub trait HeaderClone {
        fn clone_box(&self) -> Box<dyn Header + Send + Sync>;
    }

    impl<T: Header + Clone> HeaderClone for T {
        #[inline]
        fn clone_box(&self) -> Box<dyn Header + Send + Sync> {
            Box::new(self.clone())
        }
    }
}

/// A formatter used to serialize headers to an output stream.
#[allow(missing_debug_implementations)]
pub struct Formatter<'a, 'b: 'a>(Multi<'a, 'b>);

#[allow(unused)]
enum Multi<'a, 'b: 'a> {
    Line(&'a str, &'a mut std::fmt::Formatter<'b>),
    Join(bool, &'a mut std::fmt::Formatter<'b>),
    Raw(&'a mut raw::Raw),
}

impl<'a, 'b> Formatter<'a, 'b> {
    /// Formats one field-value line, replacing carriage returns and line feeds with spaces.
    ///
    /// Depending on the formatter's output mode, writes a named header line,
    /// joins values with `, `, or appends a raw value. Calling this repeatedly
    /// supports headers that require separate lines.
    ///
    /// # Errors
    ///
    /// Returns [`std::fmt::Error`] if the output or the value's formatting fails.
    pub fn fmt_line(&mut self, line: &dyn std::fmt::Display) -> std::fmt::Result {
        use std::fmt::Write;
        match self.0 {
            Multi::Line(name, ref mut f) => {
                f.write_str(name)?;
                f.write_str(": ")?;
                write!(NewlineReplacer(*f), "{}", line)?;
                f.write_str("\r\n")
            }
            Multi::Join(ref mut first, ref mut f) => {
                if !*first {
                    f.write_str(", ")?;
                } else {
                    *first = false;
                }
                write!(NewlineReplacer(*f), "{}", line)
            }
            Multi::Raw(ref mut raw) => {
                let mut s = String::new();
                write!(NewlineReplacer(&mut s), "{}", line)?;
                raw.push(s);
                Ok(())
            }
        }
    }

    fn danger_fmt_line_without_newline_replacer<T: std::fmt::Display>(
        &mut self,
        line: &T,
    ) -> std::fmt::Result {
        use std::fmt::Write;
        match self.0 {
            Multi::Line(name, ref mut f) => {
                f.write_str(name)?;
                f.write_str(": ")?;
                std::fmt::Display::fmt(line, f)?;
                f.write_str("\r\n")
            }
            Multi::Join(ref mut first, ref mut f) => {
                if !*first {
                    f.write_str(", ")?;
                } else {
                    *first = false;
                }
                std::fmt::Display::fmt(line, f)
            }
            Multi::Raw(ref mut raw) => {
                let mut s = String::new();
                write!(s, "{}", line)?;
                raw.push(s);
                Ok(())
            }
        }
    }
}

struct NewlineReplacer<'a, F: std::fmt::Write + 'a>(&'a mut F);

impl<'a, F: std::fmt::Write + 'a> std::fmt::Write for NewlineReplacer<'a, F> {
    #[inline]
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let mut since = 0;
        for (i, &byte) in s.as_bytes().iter().enumerate() {
            if byte == b'\r' || byte == b'\n' {
                self.0.write_str(&s[since..i])?;
                self.0.write_str(" ")?;
                since = i + 1;
            }
        }
        if since < s.len() {
            self.0.write_str(&s[since..])
        } else {
            Ok(())
        }
    }

    #[inline]
    fn write_fmt(&mut self, args: std::fmt::Arguments) -> std::fmt::Result {
        std::fmt::write(self, args)
    }
}

/// A typed header with a corresponding [`http::header::HeaderName`] constant.
pub trait StandardHeader: Header + Sized {
    /// Returns the [`http::header::HeaderName`] constant for this header.
    fn http_header_name() -> ::http::header::HeaderName;
}

impl<'a> RawLike<'a> for &'a HeaderValue {
    type IntoIter = ::std::iter::Once<&'a [u8]>;

    fn len(&'a self) -> usize {
        1
    }

    fn one(&'a self) -> Option<&'a [u8]> {
        Some(self.as_bytes())
    }

    fn iter(&'a self) -> Self::IntoIter {
        ::std::iter::once(self.as_bytes())
    }
}

#[doc(hidden)]
#[macro_export]
/// Implements [`StandardHeader`] for a typed header.
macro_rules! standard_header {
    ($local:ident, $hname:ident) => {
        impl $crate::header::StandardHeader for $local {
            #[inline]
            fn http_header_name() -> ::http::header::HeaderName {
                ::http::header::$hname
            }
        }
    };
}

#[doc(hidden)]
#[macro_export]
/// Implements dereferencing for a tuple-style header wrapper.
macro_rules! __deref__ {
    ($from:ty => $to:ty) => {
        impl ::std::ops::Deref for $from {
            type Target = $to;

            #[inline]
            fn deref(&self) -> &$to {
                &self.0
            }
        }

        impl ::std::ops::DerefMut for $from {
            #[inline]
            fn deref_mut(&mut self) -> &mut $to {
                &mut self.0
            }
        }
    };
}

#[doc(hidden)]
#[macro_export]
/// Generates an internal header test module.
macro_rules! __tm__ {
    ($id:ident, $tm:ident{$($tf:item)*}) => {
        #[allow(unused_imports)]
        #[cfg(test)]
        mod $tm{
            use std::str;
            use $crate::header::*;
            use mime::*;
            use $crate::header::method::Method;
            use super::$id as HeaderField;
            $($tf)*
        }

    }
}

/// Create a header type, for internal use only.
#[doc(hidden)]
#[macro_export]
macro_rules! header {
    // $a:meta: Attributes associated with the header item (usually docs)
    // $id:ident: Identifier of the header
    // $n:expr: Lowercase name of the header
    // $nn:expr: Nice name of the header

    // List header, zero or more items
    ($(#[$a:meta])*($id:ident, $n:expr) => ($item:ty)*) => {
        $(#[$a])*
        #[derive(Clone, Debug, PartialEq)]
        pub struct $id(
            /// The header's ordered values.
            pub Vec<$item>
        );
        $crate::__deref__!($id => Vec<$item>);
        impl $crate::header::Header for $id {
            fn header_name() -> &'static str {
                static NAME: &'static str = $n;
                NAME
            }
            #[inline]
            fn parse_header<'a, T>(raw: &'a T) -> $crate::header::error::Result<Self>
            where T: $crate::header::RawLike<'a>
            {
                $crate::header::parsing::from_comma_delimited(raw).map($id)
            }
            #[inline]
            fn fmt_header(&self, f: &mut $crate::header::Formatter) -> ::std::fmt::Result {
                f.fmt_line(self)
            }
        }
        impl ::std::fmt::Display for $id {
            #[inline]
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                $crate::header::parsing::fmt_comma_delimited(f, &self.0[..])
            }
        }
    };
    // List header, one or more items
    ($(#[$a:meta])*($id:ident, $n:expr) => ($item:ty)+) => {
        $(#[$a])*
        #[derive(Clone, Debug, PartialEq)]
        pub struct $id(
            /// The header's ordered values.
            pub Vec<$item>
        );
        $crate::__deref__!($id => Vec<$item>);
        impl $crate::header::Header for $id {
            #[inline]
            fn header_name() -> &'static str {
                static NAME: &'static str = $n;
                NAME
            }
            #[inline]
            fn parse_header<'a, T>(raw: &'a T) -> $crate::header::error::Result<Self>
            where T: $crate::header::RawLike<'a>
            {
                $crate::header::parsing::from_comma_delimited(raw).map($id)
            }
            #[inline]
            fn fmt_header(&self, f: &mut $crate::header::Formatter) -> ::std::fmt::Result {
                f.fmt_line(self)
            }
        }
        impl ::std::fmt::Display for $id {
            #[inline]
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                $crate::header::parsing::fmt_comma_delimited(f, &self.0[..])
            }
        }
    };
    // Single value header
    ($(#[$a:meta])*($id:ident, $n:expr) => [$value:ty]) => {
        $(#[$a])*
        #[derive(Clone, Debug, PartialEq)]
        pub struct $id(
            /// The wrapped header value.
            pub $value
        );
        $crate::__deref__!($id => $value);
        impl $crate::header::Header for $id {
            #[inline]
            fn header_name() -> &'static str {
                static NAME: &'static str = $n;
                NAME
            }
            #[inline]
            fn parse_header<'a, T>(raw: &'a T) -> $crate::header::error::Result<Self>
            where T: $crate::header::RawLike<'a>
            {
                $crate::header::parsing::from_one_raw_str(raw).map($id)
            }
            #[inline]
            fn fmt_header(&self, f: &mut $crate::header::Formatter) -> ::std::fmt::Result {
                f.fmt_line(self)
            }
        }
        impl ::std::fmt::Display for $id {
            #[inline]
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                ::std::fmt::Display::fmt(&self.0, f)
            }
        }
    };
    // Single value header (internal)
    ($(#[$a:meta])*($id:ident, $n:expr) => danger [$value:ty]) => {
        $(#[$a])*
        #[derive(Clone, Debug, PartialEq)]
        pub struct $id(
            /// The wrapped header value.
            pub $value
        );
        $crate::__deref__!($id => $value);
        impl $crate::header::Header for $id {
            #[inline]
            fn header_name() -> &'static str {
                static NAME: &'static str = $n;
                NAME
            }
            #[inline]
            fn parse_header<'a, T>(raw: &'a T) -> $crate::header::error::Result<Self>
            where T: $crate::header::RawLike<'a>
            {
                $crate::header::parsing::from_one_raw_str(raw).map($id)
            }
            #[inline]
            fn fmt_header(&self, f: &mut $crate::header::Formatter) -> ::std::fmt::Result {
                f.danger_fmt_line_without_newline_replacer(self)
            }
        }
        impl ::std::fmt::Display for $id {
            #[inline]
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                ::std::fmt::Display::fmt(&self.0, f)
            }
        }
    };
    // Single value cow header
    ($(#[$a:meta])*($id:ident, $n:expr) => Cow[$value:ty]) => {
        $(#[$a])*
        #[derive(Clone, Debug, PartialEq)]
        pub struct $id(::std::borrow::Cow<'static,$value>);
        impl $id {
            /// Creates a header wrapper from an owned or borrowed value.
            pub fn new<I: Into<::std::borrow::Cow<'static,$value>>>(value: I) -> Self {
                $id(value.into())
            }
        }
        impl ::std::ops::Deref for $id {
            type Target = $value;
            #[inline]
            fn deref(&self) -> &Self::Target {
                &(self.0)
            }
        }
        impl $crate::header::Header for $id {
            #[inline]
            fn header_name() -> &'static str {
                static NAME: &'static str = $n;
                NAME
            }
            #[inline]
            fn parse_header<'a, T>(raw: &'a T) -> $crate::header::error::Result<Self>
            where T: $crate::header::RawLike<'a>
            {
                $crate::header::parsing::from_one_raw_str::<_, <$value as ::std::borrow::ToOwned>::Owned>(raw).map($id::new)
            }
            #[inline]
            fn fmt_header(&self, f: &mut $crate::header::Formatter) -> ::std::fmt::Result {
                f.fmt_line(self)
            }
        }
        impl ::std::fmt::Display for $id {
            #[inline]
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                ::std::fmt::Display::fmt(&self.0, f)
            }
        }
    };
    // List header, one or more items with "*" option
    ($(#[$a:meta])*($id:ident, $n:expr) => {Any / ($item:ty)+}) => {
        $(#[$a])*
        #[derive(Clone, Debug, PartialEq)]
        pub enum $id {
            /// The wildcard `*`, testing whether a representation exists.
            Any,
            /// The entity tags against which a representation is compared.
            Items(Vec<$item>),
        }
        impl $crate::header::Header for $id {
            #[inline]
            fn header_name() -> &'static str {
                static NAME: &'static str = $n;
                NAME
            }
            #[inline]
            fn parse_header<'a, T>(raw: &'a T) -> $crate::header::error::Result<Self>
            where T: $crate::header::RawLike<'a>
            {
                // FIXME: Return None if no item is in $id::Only
                if let Some(l) = raw.one() {
                    if l == b"*" {
                        return Ok($id::Any)
                    }
                }
                $crate::header::parsing::from_comma_delimited(raw).map($id::Items)
            }
            #[inline]
            fn fmt_header(&self, f: &mut $crate::header::Formatter) -> ::std::fmt::Result {
                f.fmt_line(self)
            }
        }
        impl ::std::fmt::Display for $id {
            #[inline]
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                match *self {
                    $id::Any => f.write_str("*"),
                    $id::Items(ref fields) => $crate::header::parsing::fmt_comma_delimited(
                        f, &fields[..])
                }
            }
        }
    };

    // optional test module
    ($(#[$a:meta])*($id:ident, $n:expr) => ($item:ty)* $tm:ident{$($tf:item)*}) => {
        header! {
            $(#[$a])*
            ($id, $n) => ($item)*
        }

        $crate::__tm__! { $id, $tm { $($tf)* }}
    };
    ($(#[$a:meta])*($id:ident, $n:expr) => ($item:ty)+ $tm:ident{$($tf:item)*}) => {
        header! {
            $(#[$a])*
            ($id, $n) => ($item)+
        }

        $crate::__tm__! { $id, $tm { $($tf)* }}
    };
    ($(#[$a:meta])*($id:ident, $n:expr) => [$item:ty] $tm:ident{$($tf:item)*}) => {
        header! {
            $(#[$a])*
            ($id, $n) => [$item]
        }

        $crate::__tm__! { $id, $tm { $($tf)* }}
    };
    ($(#[$a:meta])*($id:ident, $n:expr) => danger [$item:ty] $tm:ident{$($tf:item)*}) => {
        header! {
            $(#[$a])*
            ($id, $n) => danger [$item]
        }

        $crate::__tm__! { $id, $tm { $($tf)* }}
    };
    ($(#[$a:meta])*($id:ident, $n:expr) => Cow[$item:ty] $tm:ident{$($tf:item)*}) => {
        header! {
            $(#[$a])*
            ($id, $n) => Cow[$item]
        }

        $crate::__tm__! { $id, $tm { $($tf)* }}
    };
    ($(#[$a:meta])*($id:ident, $n:expr) => {Any / ($item:ty)+} $tm:ident{$($tf:item)*}) => {
        header! {
            $(#[$a])*
            ($id, $n) => {Any / ($item)+}
        }

        $crate::__tm__! { $id, $tm { $($tf)* }}
    };
}

#[cfg(test)]
mod tests {
    use super::{ETag, EntityTag, Header, HeaderValue, IfMatch, IfNoneMatch, Raw};

    /// STATEMENT: Typed headers parse HTTP values and list serialization preserves entity-tag boundaries.
    ///
    /// HOW:
    /// - Parse a whitespace-padded weak `ETag` and round-trip wildcard `IfNoneMatch` through `HeaderValue`.
    /// - Format a three-tag `IfMatch` list and parse it back through `HeaderValue`.
    #[test]
    fn http_values_parse_typed_headers_and_round_trip_lists() {
        let value = HeaderValue::from_static(" \tW/\"version\" \t");
        assert_eq!(
            ETag::parse_header(&&value).unwrap().0,
            EntityTag::weak("version".into())
        );
        let wildcard = HeaderValue::from_static("*");
        assert_eq!(
            IfNoneMatch::parse_header(&&wildcard).unwrap(),
            IfNoneMatch::Any
        );
        let rendered = IfNoneMatch::parse_header(&&wildcard).unwrap().to_string();
        let value = HeaderValue::from_str(&rendered).unwrap();
        assert_eq!(
            IfNoneMatch::parse_header(&&value).unwrap(),
            IfNoneMatch::Any
        );
        let original = IfMatch::Items(vec![
            EntityTag::strong("one".into()),
            EntityTag::weak("two".into()),
            EntityTag::strong("three".into()),
        ]);
        let serialized = original.to_string();
        assert_eq!(serialized, "\"one\", W/\"two\", \"three\"");
        let value = HeaderValue::from_str(&serialized).unwrap();
        assert_eq!(IfMatch::parse_header(&&value).unwrap(), original);
    }

    /// STATEMENT: Comma-delimited header formatting propagates an output error without silently completing the list.
    ///
    /// HOW:
    /// - Format a parsed three-tag `IfMatch` through writers that fail before the first, second, and third tag.
    /// - Check each write fails and only the successfully written prefix remains, then verify unrestricted formatting reparses.
    #[test]
    fn list_formatting_propagates_output_errors() {
        use std::fmt::Write;

        struct LimitedWriter {
            remaining: usize,
            written: String,
        }
        impl std::fmt::Write for LimitedWriter {
            fn write_str(&mut self, value: &str) -> std::fmt::Result {
                if value.len() > self.remaining {
                    return Err(std::fmt::Error);
                }
                self.remaining -= value.len();
                self.written.push_str(value);
                Ok(())
            }
        }
        let raw = Raw::from("\"one\", \"two\", \"three\"");
        let parsed = IfMatch::parse_header(&raw).unwrap();
        for (limit, expected) in [(0, ""), (7, "\"one\", "), (14, "\"one\", \"two\", ")] {
            let mut writer = LimitedWriter {
                remaining: limit,
                written: String::new(),
            };
            assert!(write!(writer, "{parsed}").is_err());
            assert_eq!(writer.written, expected);
        }
        assert_eq!(
            IfMatch::parse_header(&Raw::from(parsed.to_string())).unwrap(),
            parsed
        );
    }
}
