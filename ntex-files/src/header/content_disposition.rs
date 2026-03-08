// # References
//
// "The Content-Disposition Header Field" https://www.ietf.org/rfc/rfc2183.txt
// "The Content-Disposition Header Field in the Hypertext Transfer Protocol (HTTP)" https://www.ietf.org/rfc/rfc6266.txt
// "Returning Values from Forms: multipart/form-data" https://www.ietf.org/rfc/rfc2388.txt
// Browser conformance tests at: http://greenbytes.de/tech/tc2231/
// IANA assignment: http://www.iana.org/assignments/cont-disp/cont-disp.xhtml

use super::error;
use super::parsing::{self, ExtendedValue};
use super::{Header, RawLike};
use crate::standard_header;
use regex::Regex;
use std::fmt;
use std::sync::LazyLock;

/// The implied disposition of the content of the HTTP body.
#[derive(Clone, Debug, PartialEq)]
pub enum DispositionType {
    /// Inline implies default processing
    Inline,

    /// Attachment implies that the recipient should prompt the user to save the response locally,
    /// rather than process it normally (as per its media type).
    Attachment,

    /// Used in *multipart/form-data* as defined in
    /// [RFC 7578](https://datatracker.ietf.org/doc/html/rfc7578) to carry the field name and
    /// optional filename.
    FormData,

    /// Extension type.  Should be handled by recipients the same way as Attachment
    Ext(String),
}

impl<'a> From<&'a str> for DispositionType {
    fn from(origin: &'a str) -> DispositionType {
        if unicase::eq_ascii(origin, "inline") {
            DispositionType::Inline
        } else if unicase::eq_ascii(origin, "attachment") {
            DispositionType::Attachment
        } else if unicase::eq_ascii(origin, "form-data") {
            DispositionType::FormData
        } else {
            DispositionType::Ext(origin.to_owned())
        }
    }
}

/// A parameter to the disposition type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DispositionParam {
    /// For [`DispositionType::FormData`] (i.e. *multipart/form-data*), the name of an field from
    /// the form.
    Name(String),

    /// A plain file name.
    ///
    /// It is [not supposed](https://datatracker.ietf.org/doc/html/rfc6266#appendix-D) to contain
    /// any non-ASCII characters when used in a *Content-Disposition* HTTP response header, where
    /// [`FilenameExt`](DispositionParam::FilenameExt) with charset UTF-8 may be used instead
    /// in case there are Unicode characters in file names.
    Filename(String),

    /// An extended file name. It must not exist for `ContentType::Formdata` according to
    /// [RFC 7578 §4.2](https://datatracker.ietf.org/doc/html/rfc7578#section-4.2).
    FilenameExt(ExtendedValue),

    /// An unrecognized regular parameter as defined in
    /// [RFC 5987 §3.2.1](https://datatracker.ietf.org/doc/html/rfc5987#section-3.2.1) as
    /// `reg-parameter`, in
    /// [RFC 6266 §4.1](https://datatracker.ietf.org/doc/html/rfc6266#section-4.1) as
    /// `token "=" value`. Recipients should ignore unrecognizable parameters.
    Unknown(String, String),

    /// An unrecognized extended parameter as defined in
    /// [RFC 5987 §3.2.1](https://datatracker.ietf.org/doc/html/rfc5987#section-3.2.1) as
    /// `ext-parameter`, in
    /// [RFC 6266 §4.1](https://datatracker.ietf.org/doc/html/rfc6266#section-4.1) as
    /// `ext-token "=" ext-value`. The single trailing asterisk is not included. Recipients should
    /// ignore unrecognizable parameters.
    UnknownExt(String, ExtendedValue),
}

impl DispositionParam {
    /// Returns `true` if the parameter is [`Name`](DispositionParam::Name).
    #[inline]
    pub fn is_name(&self) -> bool {
        self.as_name().is_some()
    }

    /// Returns `true` if the parameter is [`Filename`](DispositionParam::Filename).
    #[inline]
    pub fn is_filename(&self) -> bool {
        self.as_filename().is_some()
    }

    /// Returns `true` if the parameter is [`FilenameExt`](DispositionParam::FilenameExt).
    #[inline]
    pub fn is_filename_ext(&self) -> bool {
        self.as_filename_ext().is_some()
    }

    /// Returns `true` if the parameter is [`Unknown`](DispositionParam::Unknown) and the `name`
    #[inline]
    /// matches.
    pub fn is_unknown<T: AsRef<str>>(&self, name: T) -> bool {
        self.as_unknown(name).is_some()
    }

    /// Returns `true` if the parameter is [`UnknownExt`](DispositionParam::UnknownExt) and the
    /// `name` matches.
    #[inline]
    pub fn is_unknown_ext<T: AsRef<str>>(&self, name: T) -> bool {
        self.as_unknown_ext(name).is_some()
    }

    /// Returns the name if applicable.
    #[inline]
    pub fn as_name(&self) -> Option<&str> {
        match self {
            DispositionParam::Name(name) => Some(name.as_str()),
            _ => None,
        }
    }

    /// Returns the filename if applicable.
    #[inline]
    pub fn as_filename(&self) -> Option<&str> {
        match self {
            DispositionParam::Filename(filename) => Some(filename.as_str()),
            _ => None,
        }
    }

    /// Returns the filename* if applicable.
    #[inline]
    pub fn as_filename_ext(&self) -> Option<&ExtendedValue> {
        match self {
            DispositionParam::FilenameExt(value) => Some(value),
            _ => None,
        }
    }

    /// Returns the value of the unrecognized regular parameter if it is
    /// [`Unknown`](DispositionParam::Unknown) and the `name` matches.
    #[inline]
    pub fn as_unknown<T: AsRef<str>>(&self, name: T) -> Option<&str> {
        match self {
            DispositionParam::Unknown(ext_name, value)
                if ext_name.eq_ignore_ascii_case(name.as_ref()) =>
            {
                Some(value.as_str())
            }
            _ => None,
        }
    }

    /// Returns the value of the unrecognized extended parameter if it is
    /// [`Unknown`](DispositionParam::Unknown) and the `name` matches.
    #[inline]
    pub fn as_unknown_ext<T: AsRef<str>>(&self, name: T) -> Option<&ExtendedValue> {
        match self {
            DispositionParam::UnknownExt(ext_name, value)
                if ext_name.eq_ignore_ascii_case(name.as_ref()) =>
            {
                Some(value)
            }
            _ => None,
        }
    }
}

/// A `Content-Disposition` header, (re)defined in [RFC6266](https://tools.ietf.org/html/rfc6266).
///
/// The Content-Disposition response header field is used to convey
/// additional information about how to process the response payload, and
/// also can be used to attach additional metadata, such as the filename
/// to use when saving the response payload locally.
///
/// # ABNF
///
/// ```text
/// content-disposition = "Content-Disposition" ":"
///                       disposition-type *( ";" disposition-parm )
///
/// disposition-type    = "inline" | "attachment" | disp-ext-type
///                       ; case-insensitive
///
/// disp-ext-type       = token
///
/// disposition-parm    = filename-parm | disp-ext-parm
///
/// filename-parm       = "filename" "=" value
///                     | "filename*" "=" ext-value
///
/// disp-ext-parm       = token "=" value
///                     | ext-token "=" ext-value
///
/// ext-token           = <the characters in token, followed by "*">
/// ```
///
#[derive(Clone, Debug, PartialEq)]
pub struct ContentDisposition {
    /// The disposition
    pub disposition: DispositionType,
    /// Disposition parameters
    pub parameters: Vec<DispositionParam>,
}

impl ContentDisposition {
    /// Returns `true` if type is [`Inline`](DispositionType::Inline).
    pub fn is_inline(&self) -> bool {
        matches!(self.disposition, DispositionType::Inline)
    }

    /// Returns `true` if type is [`Attachment`](DispositionType::Attachment).
    pub fn is_attachment(&self) -> bool {
        matches!(self.disposition, DispositionType::Attachment)
    }

    /// Returns `true` if type is [`FormData`](DispositionType::FormData).
    pub fn is_form_data(&self) -> bool {
        matches!(self.disposition, DispositionType::FormData)
    }

    /// Returns `true` if type is [`Ext`](DispositionType::Ext) and the `disp_type` matches.
    pub fn is_ext(&self, disp_type: impl AsRef<str>) -> bool {
        matches!(
            self.disposition,
            DispositionType::Ext(ref t) if t.eq_ignore_ascii_case(disp_type.as_ref())
        )
    }

    /// Return the value of *name* if exists.
    pub fn get_name(&self) -> Option<&str> {
        self.parameters.iter().find_map(DispositionParam::as_name)
    }

    /// Return the value of *filename* if exists.
    pub fn get_filename(&self) -> Option<&str> {
        self.parameters.iter().find_map(DispositionParam::as_filename)
    }

    /// Return the value of *filename\** if exists.
    pub fn get_filename_ext(&self) -> Option<&ExtendedValue> {
        self.parameters.iter().find_map(DispositionParam::as_filename_ext)
    }

    /// Return the value of the parameter which the `name` matches.
    pub fn get_unknown(&self, name: impl AsRef<str>) -> Option<&str> {
        let name = name.as_ref();
        self.parameters.iter().find_map(|p| p.as_unknown(name))
    }

    /// Return the value of the extended parameter which the `name` matches.
    pub fn get_unknown_ext(&self, name: impl AsRef<str>) -> Option<&ExtendedValue> {
        let name = name.as_ref();
        self.parameters.iter().find_map(|p| p.as_unknown_ext(name))
    }
}

impl Header for ContentDisposition {
    fn header_name() -> &'static str {
        static NAME: &str = "Content-Disposition";
        NAME
    }

    fn parse_header<'a, T>(raw: &'a T) -> error::Result<ContentDisposition>
    where
        T: RawLike<'a>,
    {
        parsing::from_one_raw_str(raw).and_then(|s: String| {
            let mut sections = s.split(';');
            let disposition = match sections.next() {
                Some(s) => s.trim(),
                None => return Err(error::Error::Header),
            };

            let mut cd =
                ContentDisposition { disposition: disposition.into(), parameters: Vec::new() };

            for section in sections {
                let mut parts = section.splitn(2, '=');

                let key = if let Some(key) = parts.next() {
                    let key_trimmed = key.trim();

                    if key_trimmed.is_empty() || key_trimmed == "*" {
                        return Err(error::Error::Header);
                    }

                    key_trimmed
                } else {
                    return Err(error::Error::Header);
                };

                let val = if let Some(val) = parts.next() {
                    val.trim()
                } else {
                    return Err(error::Error::Header);
                };

                if let Some(key) = key.strip_suffix('*') {
                    let ext_val = parsing::parse_extended_value(val)?;

                    cd.parameters.push(if unicase::eq_ascii(key, "filename") {
                        DispositionParam::FilenameExt(ext_val)
                    } else {
                        DispositionParam::UnknownExt(key.to_owned(), ext_val)
                    });
                } else {
                    let val = if val.starts_with('\"') {
                        // quoted-string: defined in RFC 6266 -> RFC 2616 Section 3.6
                        let mut escaping = false;
                        let mut quoted_string = vec![];

                        // search for closing quote
                        for (_, &c) in val.as_bytes().iter().skip(1).enumerate() {
                            if escaping {
                                escaping = false;
                                quoted_string.push(c);
                            } else if c == 0x5c {
                                // backslash
                                escaping = true;
                            } else if c == 0x22 {
                                // double quote
                                break;
                            } else {
                                quoted_string.push(c);
                            }
                        }

                        // In fact, it should not be Err if the above code is correct.
                        String::from_utf8(quoted_string).map_err(|_| error::Error::Header)?
                    } else {
                        if val.is_empty() {
                            // quoted-string can be empty, but token cannot be empty
                            return Err(error::Error::Header);
                        }

                        val.to_owned()
                    };

                    cd.parameters.push(if unicase::eq_ascii(key, "name") {
                        DispositionParam::Name(val)
                    } else if unicase::eq_ascii(key, "filename") {
                        // See also comments in test_from_raw_unnecessary_percent_decode.
                        DispositionParam::Filename(val)
                    } else {
                        DispositionParam::Unknown(key.to_owned(), val)
                    });
                }
            }

            Ok(cd)
        })
    }

    #[inline]
    fn fmt_header(&self, f: &mut super::Formatter) -> fmt::Result {
        f.fmt_line(self)
    }
}

impl fmt::Display for ContentDisposition {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.disposition {
            DispositionType::Inline => write!(f, "inline")?,
            DispositionType::Attachment => write!(f, "attachment")?,
            DispositionType::FormData => write!(f, "form-data")?,
            DispositionType::Ext(ref s) => write!(f, "{}", s)?,
        }

        static RE: LazyLock<Regex> =
            LazyLock::new(|| Regex::new("[\x00-\x08\x10-\x1F\x7F\"\\\\]").unwrap());

        for param in &self.parameters {
            match *param {
                DispositionParam::Name(ref value) => write!(f, "name={}", value)?,

                DispositionParam::Filename(ref value) => {
                    write!(f, "filename=\"{}\"", RE.replace_all(value, "\\$0").as_ref())?
                }

                DispositionParam::Unknown(ref name, ref value) => {
                    write!(f, "{}=\"{}\"", name, &RE.replace_all(value, "\\$0").as_ref())?
                }

                DispositionParam::FilenameExt(ref ext_value) => {
                    write!(f, "filename*={}", ext_value)?
                }

                DispositionParam::UnknownExt(ref name, ref ext_value) => {
                    write!(f, "{}*={}", name, ext_value)?
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{ContentDisposition, DispositionParam, DispositionType, Header};
    use crate::header::parsing::ExtendedValue;
    use crate::header::{Charset, Raw};

    #[test]
    fn test_parse_header() {
        let a: Raw = "".into();
        assert!(ContentDisposition::parse_header(&a).is_err());

        let a: Raw = "form-data; dummy=3; name=upload;\r\n filename=\"sample.png\"".into();
        let a: ContentDisposition = ContentDisposition::parse_header(&a).unwrap();
        let b = ContentDisposition {
            disposition: DispositionType::FormData,
            parameters: vec![
                DispositionParam::Unknown("dummy".to_owned(), "3".to_owned()),
                DispositionParam::Name("upload".to_owned()),
                DispositionParam::Filename("sample.png".to_owned()),
            ],
        };
        assert_eq!(a, b);

        let a: Raw = "attachment; filename=\"image.jpg\"".into();
        let a: ContentDisposition = ContentDisposition::parse_header(&a).unwrap();
        let b = ContentDisposition {
            disposition: DispositionType::Attachment,
            parameters: vec![DispositionParam::Filename("image.jpg".to_owned())],
        };
        assert_eq!(a, b);

        let a: Raw = "attachment; filename*=UTF-8''%c2%a3%20and%20%e2%82%ac%20rates".into();
        let a: ContentDisposition = ContentDisposition::parse_header(&a).unwrap();
        let b = ContentDisposition {
            disposition: DispositionType::Attachment,
            parameters: vec![DispositionParam::FilenameExt(ExtendedValue {
                charset: Charset::Ext(String::from("UTF-8")),
                language_tag: None,
                value: vec![
                    0xc2, 0xa3, 0x20, b'a', b'n', b'd', 0x20, 0xe2, 0x82, 0xac, 0x20, b'r',
                    b'a', b't', b'e', b's',
                ],
            })],
        };
        assert_eq!(a, b);
    }

    #[test]
    fn test_display() {
        let as_string = "attachment; filename*=UTF-8'en'%C2%A3%20and%20%E2%82%AC%20rates";
        let a: Raw = as_string.into();
        let a: ContentDisposition = ContentDisposition::parse_header(&a).unwrap();
        let display_rendered = format!("{}", a);
        assert_eq!(as_string, display_rendered);

        let a: Raw = "attachment; filename*=UTF-8''black%20and%20white.csv".into();
        let a: ContentDisposition = ContentDisposition::parse_header(&a).unwrap();
        let display_rendered = format!("{}", a);
        assert_eq!("attachment; filename=\"black and white.csv\"".to_owned(), display_rendered);

        let a: Raw = "attachment; filename=colourful.csv".into();
        let a: ContentDisposition = ContentDisposition::parse_header(&a).unwrap();
        let display_rendered = format!("{}", a);
        assert_eq!("attachment; filename=\"colourful.csv\"".to_owned(), display_rendered);
    }
}

standard_header!(ContentDisposition, CONTENT_DISPOSITION);
