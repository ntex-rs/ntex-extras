//! The HTTP request method
use std::convert::{AsRef, TryFrom};
use std::fmt;
use std::str::FromStr;

use self::Method::{Connect, Delete, Extension, Get, Head, Options, Patch, Post, Put, Trace};

/// The Request Method (VERB)
///
/// Currently includes 8 variants representing the 8 methods defined in
/// [RFC 7230](https://tools.ietf.org/html/rfc7231#section-4.1), plus PATCH,
/// and an Extension variant for all extensions.
///
/// It may make sense to grow this to include all variants currently
/// registered with IANA, if they are at all common to use.
#[derive(Default, Clone, PartialEq, Eq, Hash, Debug)]
pub enum Method {
    /// OPTIONS
    Options,
    /// GET
    #[default]
    Get,
    /// POST
    Post,
    /// PUT
    Put,
    /// DELETE
    Delete,
    /// HEAD
    Head,
    /// TRACE
    Trace,
    /// CONNECT
    Connect,
    /// PATCH
    Patch,
    /// Method extensions. An example would be `let m = Extension("FOO".to_string())`.
    Extension(String),
}

impl AsRef<str> for Method {
    fn as_ref(&self) -> &str {
        match *self {
            Options => "OPTIONS",
            Get => "GET",
            Post => "POST",
            Put => "PUT",
            Delete => "DELETE",
            Head => "HEAD",
            Trace => "TRACE",
            Connect => "CONNECT",
            Patch => "PATCH",
            Extension(ref s) => s.as_ref(),
        }
    }
}

impl Method {
    /// Whether a method is considered "safe", meaning the request is
    /// essentially read-only.
    ///
    /// See [the spec](https://tools.ietf.org/html/rfc7231#section-4.2.1)
    /// for more words.
    pub fn safe(&self) -> bool {
        matches!(*self, Get | Head | Options | Trace)
    }

    /// Whether a method is considered "idempotent", meaning the request has
    /// the same result if executed multiple times.
    ///
    /// See [the spec](https://tools.ietf.org/html/rfc7231#section-4.2.2) for
    /// more words.
    pub fn idempotent(&self) -> bool {
        if self.safe() {
            true
        } else {
            matches!(*self, Put | Delete)
        }
    }
}

macro_rules! from_str {
    ($s:ident, { $($n:pat => { $($text:pat => $var:ident,)* },)* }) => ({
        let s = $s;
        match s.len() {
            $(
            $n => match s {
                $(
                $text => return Ok($var),
                )*
                _ => {},
            },
            )*
            0 => return Err(super::error::Error::Method),
            _ => {},
        }
        Ok(Extension(s.to_owned()))
    })
}

impl FromStr for Method {
    type Err = super::error::Error;
    fn from_str(s: &str) -> Result<Method, super::error::Error> {
        from_str!(s, {
            3 => {
                "GET" => Get,
                "PUT" => Put,
            },
            4 => {
                "HEAD" => Head,
                "POST" => Post,
            },
            5 => {
                "PATCH" => Patch,
                "TRACE" => Trace,
            },
            6 => {
                "DELETE" => Delete,
            },
            7 => {
                "OPTIONS" => Options,
                "CONNECT" => Connect,
            },
        })
    }
}

impl fmt::Display for Method {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str(match *self {
            Options => "OPTIONS",
            Get => "GET",
            Post => "POST",
            Put => "PUT",
            Delete => "DELETE",
            Head => "HEAD",
            Trace => "TRACE",
            Connect => "CONNECT",
            Patch => "PATCH",
            Extension(ref s) => s.as_ref(),
        })
    }
}

impl From<http::Method> for Method {
    fn from(method: http::Method) -> Method {
        match method {
            http::Method::GET => Method::Get,
            http::Method::POST => Method::Post,
            http::Method::PUT => Method::Put,
            http::Method::DELETE => Method::Delete,
            http::Method::HEAD => Method::Head,
            http::Method::OPTIONS => Method::Options,
            http::Method::CONNECT => Method::Connect,
            http::Method::PATCH => Method::Patch,
            http::Method::TRACE => Method::Trace,
            _ => method.as_ref().parse().expect("attempted to convert invalid method"),
        }
    }
}

impl From<Method> for http::Method {
    fn from(method: Method) -> http::Method {
        match method {
            Method::Get => http::Method::GET,
            Method::Post => http::Method::POST,
            Method::Put => http::Method::PUT,
            Method::Delete => http::Method::DELETE,
            Method::Head => http::Method::HEAD,
            Method::Options => http::Method::OPTIONS,
            Method::Connect => http::Method::CONNECT,
            Method::Patch => http::Method::PATCH,
            Method::Trace => http::Method::TRACE,
            Method::Extension(s) => {
                http::Method::try_from(s.as_str()).expect("attempted to convert invalid method")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Method;
    use super::Method::{Extension, Get, Post, Put};
    use crate::file_header::error::Error;
    use std::collections::HashMap;
    use std::convert::TryFrom;
    use std::str::FromStr;

    #[test]
    fn test_safe() {
        assert!(Get.safe());
        assert!(!Post.safe());
    }

    #[test]
    fn test_idempotent() {
        assert!(Get.idempotent());
        assert!(Put.idempotent());
        assert!(!Post.idempotent());
    }

    #[test]
    fn test_from_str() {
        assert_eq!(Get, FromStr::from_str("GET").unwrap());
        assert_eq!(Extension("MOVE".to_owned()), FromStr::from_str("MOVE").unwrap());
        let x: Result<Method, _> = FromStr::from_str("");
        if let Err(Error::Method) = x {
        } else {
            panic!("An empty method is invalid!")
        }
    }

    #[test]
    fn test_fmt() {
        assert_eq!("GET".to_owned(), format!("{}", Get));
        assert_eq!("MOVE".to_owned(), format!("{}", Extension("MOVE".to_owned())));
    }

    #[test]
    fn test_hashable() {
        let mut counter: HashMap<Method, usize> = HashMap::new();
        counter.insert(Get, 1);
        assert_eq!(Some(&1), counter.get(&Get));
    }

    #[test]
    fn test_as_str() {
        assert_eq!(Get.as_ref(), "GET");
        assert_eq!(Post.as_ref(), "POST");
        assert_eq!(Put.as_ref(), "PUT");
        assert_eq!(Extension("MOVE".to_owned()).as_ref(), "MOVE");
    }

    #[test]
    fn test_compat() {
        let methods = vec!["GET", "POST", "PUT", "MOVE"];
        for method in methods {
            let orig_hyper_method = Method::from_str(method).unwrap();
            let orig_http_method = http::Method::try_from(method).unwrap();
            let conv_hyper_method: Method = orig_http_method.clone().into();
            let conv_http_method: http::Method = orig_hyper_method.clone().into();
            assert_eq!(orig_hyper_method, conv_hyper_method);
            assert_eq!(orig_http_method, conv_http_method);
        }
    }
}
