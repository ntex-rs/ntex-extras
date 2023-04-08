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

/// A trait for any object that will represent a header field and value.
///
/// This trait represents the construction and identification of headers,
/// and contains trait-object unsafe methods.
pub trait Header: 'static + HeaderClone + Send + Sync {
    /// Returns the name of the header field this belongs to.
    ///
    /// This will become an associated constant once available.
    fn header_name() -> &'static str
    where
        Self: Sized;

    /// Parse a header from a raw stream of bytes.
    ///
    /// It's possible that a request can include a header field more than once,
    /// and in that case, the slice will have a length greater than 1. However,
    /// it's not necessarily the case that a Header is *allowed* to have more
    /// than one field value. If that's the case, you **should** return `None`
    /// if `raw.len() > 1`.
    fn parse_header<'a, T>(raw: &'a T) -> error::Result<Self>
    where
        T: RawLike<'a>,
        Self: Sized;

    /// Format a header to outgoing stream.
    ///
    /// Most headers should be formatted on one line, and so a common pattern
    /// would be to implement `std::fmt::Display` for this type as well, and
    /// then just call `f.fmt_line(self)`.
    ///
    /// ## Note
    ///
    /// This has the ability to format a header over multiple lines.
    ///
    /// The main example here is `Set-Cookie`, which requires that every
    /// cookie being set be specified in a separate line. Almost every other
    /// case should only format as 1 single line.
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
    /// Format one 'line' of a header.
    ///
    /// This writes the header name plus the `Display` value as a single line.
    ///
    /// ## Note
    ///
    /// This has the ability to format a header over multiple lines.
    ///
    /// The main example here is `Set-Cookie`, which requires that every
    /// cookie being set be specified in a separate line. Almost every other
    /// case should only format as 1 single line.
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

/// A trait for the "standard" headers that have an associated `HeaderName`
/// constant in the _http_ crate.
pub trait StandardHeader: Header + Sized {
    /// The `HeaderName` from the _http_ crate for this header.
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
macro_rules! standard_header {
    ($local:ident, $hname:ident) => {
        impl $crate::file_header::StandardHeader for $local {
            #[inline]
            fn http_header_name() -> ::http::header::HeaderName {
                ::http::header::$hname
            }
        }
    };
}

#[doc(hidden)]
#[macro_export]
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
macro_rules! __tm__ {
    ($id:ident, $tm:ident{$($tf:item)*}) => {
        #[allow(unused_imports)]
        #[cfg(test)]
        mod $tm{
            use std::str;
            use $crate::file_header::*;
            use mime::*;
            use $crate::method::Method;
            use super::$id as HeaderField;
            $($tf)*
        }

    }
}

/// Create a custom header type.
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
        pub struct $id(pub Vec<$item>);
        $crate::__deref__!($id => Vec<$item>);
        impl $crate::file_header::Header for $id {
            fn header_name() -> &'static str {
                static NAME: &'static str = $n;
                NAME
            }
            #[inline]
            fn parse_header<'a, T>(raw: &'a T) -> $crate::Result<Self>
            where T: $crate::file_header::RawLike<'a>
            {
                $crate::file_header::parsing::from_comma_delimited(raw).map($id)
            }
            #[inline]
            fn fmt_header(&self, f: &mut $crate::file_header::Formatter) -> ::std::fmt::Result {
                f.fmt_line(self)
            }
        }
        impl ::std::fmt::Display for $id {
            #[inline]
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                $crate::file_header::parsing::fmt_comma_delimited(f, &self.0[..])
            }
        }
    };
    // List header, one or more items
    ($(#[$a:meta])*($id:ident, $n:expr) => ($item:ty)+) => {
        $(#[$a])*
        #[derive(Clone, Debug, PartialEq)]
        pub struct $id(pub Vec<$item>);
        $crate::__deref__!($id => Vec<$item>);
        impl $crate::file_header::Header for $id {
            #[inline]
            fn header_name() -> &'static str {
                static NAME: &'static str = $n;
                NAME
            }
            #[inline]
            fn parse_header<'a, T>(raw: &'a T) -> $crate::Result<Self>
            where T: $crate::file_header::RawLike<'a>
            {
                $crate::file_header::parsing::from_comma_delimited(raw).map($id)
            }
            #[inline]
            fn fmt_header(&self, f: &mut $crate::file_header::Formatter) -> ::std::fmt::Result {
                f.fmt_line(self)
            }
        }
        impl ::std::fmt::Display for $id {
            #[inline]
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                $crate::file_header::parsing::fmt_comma_delimited(f, &self.0[..])
            }
        }
    };
    // Single value header
    ($(#[$a:meta])*($id:ident, $n:expr) => [$value:ty]) => {
        $(#[$a])*
        #[derive(Clone, Debug, PartialEq)]
        pub struct $id(pub $value);
        $crate::__deref__!($id => $value);
        impl $crate::file_header::Header for $id {
            #[inline]
            fn header_name() -> &'static str {
                static NAME: &'static str = $n;
                NAME
            }
            #[inline]
            fn parse_header<'a, T>(raw: &'a T) -> $crate::file_header::error::Result<Self>
            where T: $crate::file_header::RawLike<'a>
            {
                $crate::file_header::parsing::from_one_raw_str(raw).map($id)
            }
            #[inline]
            fn fmt_header(&self, f: &mut $crate::file_header::Formatter) -> ::std::fmt::Result {
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
        pub struct $id(pub $value);
        $crate::__deref__!($id => $value);
        impl $crate::file_header::Header for $id {
            #[inline]
            fn header_name() -> &'static str {
                static NAME: &'static str = $n;
                NAME
            }
            #[inline]
            fn parse_header<'a, T>(raw: &'a T) -> $crate::Result<Self>
            where T: $crate::file_header::RawLike<'a>
            {
                $crate::file_header::parsing::from_one_raw_str(raw).map($id)
            }
            #[inline]
            fn fmt_header(&self, f: &mut $crate::file_header::Formatter) -> ::std::fmt::Result {
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
            /// Creates a new $id
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
        impl $crate::file_header::Header for $id {
            #[inline]
            fn header_name() -> &'static str {
                static NAME: &'static str = $n;
                NAME
            }
            #[inline]
            fn parse_header<'a, T>(raw: &'a T) -> $crate::Result<Self>
            where T: $crate::file_header::RawLike<'a>
            {
                $crate::file_header::parsing::from_one_raw_str::<_, <$value as ::std::borrow::ToOwned>::Owned>(raw).map($id::new)
            }
            #[inline]
            fn fmt_header(&self, f: &mut $crate::file_header::Formatter) -> ::std::fmt::Result {
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
            /// Any value is a match
            Any,
            /// Only the listed items are a match
            Items(Vec<$item>),
        }
        impl $crate::file_header::Header for $id {
            #[inline]
            fn header_name() -> &'static str {
                static NAME: &'static str = $n;
                NAME
            }
            #[inline]
            fn parse_header<'a, T>(raw: &'a T) -> $crate::file_header::error::Result<Self>
            where T: $crate::file_header::RawLike<'a>
            {
                // FIXME: Return None if no item is in $id::Only
                if let Some(l) = raw.one() {
                    if l == b"*" {
                        return Ok($id::Any)
                    }
                }
                $crate::file_header::parsing::from_comma_delimited(raw).map($id::Items)
            }
            #[inline]
            fn fmt_header(&self, f: &mut $crate::file_header::Formatter) -> ::std::fmt::Result {
                f.fmt_line(self)
            }
        }
        impl ::std::fmt::Display for $id {
            #[inline]
            fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                match *self {
                    $id::Any => f.write_str("*"),
                    $id::Items(ref fields) => $crate::file_header::parsing::fmt_comma_delimited(
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
