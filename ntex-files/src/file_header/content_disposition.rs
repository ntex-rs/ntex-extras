// # References
//
// "The Content-Disposition Header Field" https://www.ietf.org/rfc/rfc2183.txt
// "The Content-Disposition Header Field in the Hypertext Transfer Protocol (HTTP)" https://www.ietf.org/rfc/rfc6266.txt
// "Returning Values from Forms: multipart/form-data" https://www.ietf.org/rfc/rfc2388.txt
// Browser conformance tests at: http://greenbytes.de/tech/tc2231/
// IANA assignment: http://www.iana.org/assignments/cont-disp/cont-disp.xhtml

use language_tags::LanguageTag;
use std::fmt;

use crate::standard_header;

use super::error;
use super::parsing::{self, http_percent_encode, parse_extended_value};
use super::{Charset, Header, RawLike};

/// The implied disposition of the content of the HTTP body.
#[derive(Clone, Debug, PartialEq)]
pub enum DispositionType {
    /// Inline implies default processing
    Inline,
    /// Attachment implies that the recipient should prompt the user to save the response locally,
    /// rather than process it normally (as per its media type).
    Attachment,
    /// Extension type.  Should be handled by recipients the same way as Attachment
    Ext(String),
}

/// A parameter to the disposition type.
#[derive(Clone, Debug, PartialEq)]
pub enum DispositionParam {
    /// A Filename consisting of a Charset, an optional LanguageTag, and finally a sequence of
    /// bytes representing the filename
    Filename(Charset, Option<LanguageTag>, Vec<u8>),
    /// Extension type consisting of token and value.  Recipients should ignore unrecognized
    /// parameters.
    Ext(String, String),
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

            let mut cd = ContentDisposition {
                disposition: if unicase::eq_ascii(disposition, "inline") {
                    DispositionType::Inline
                } else if unicase::eq_ascii(disposition, "attachment") {
                    DispositionType::Attachment
                } else {
                    DispositionType::Ext(disposition.to_owned())
                },
                parameters: Vec::new(),
            };

            for section in sections {
                let mut parts = section.splitn(2, '=');

                let key = if let Some(key) = parts.next() {
                    key.trim()
                } else {
                    return Err(error::Error::Header);
                };

                let val = if let Some(val) = parts.next() {
                    val.trim()
                } else {
                    return Err(error::Error::Header);
                };

                cd.parameters.push(if unicase::eq_ascii(key, "filename") {
                    DispositionParam::Filename(
                        Charset::Ext("UTF-8".to_owned()),
                        None,
                        val.trim_matches('"').as_bytes().to_owned(),
                    )
                } else if unicase::eq_ascii(key, "filename*") {
                    let extended_value = parse_extended_value(val)?;
                    DispositionParam::Filename(
                        extended_value.charset,
                        extended_value.language_tag,
                        extended_value.value,
                    )
                } else {
                    DispositionParam::Ext(key.to_owned(), val.trim_matches('"').to_owned())
                });
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
            DispositionType::Ext(ref s) => write!(f, "{}", s)?,
        }
        for param in &self.parameters {
            match *param {
                DispositionParam::Filename(ref charset, ref opt_lang, ref bytes) => {
                    let mut use_simple_format: bool = false;
                    if opt_lang.is_none() {
                        if let Charset::Ext(ref ext) = *charset {
                            if unicase::eq_ascii(&**ext, "utf-8") {
                                use_simple_format = true;
                            }
                        }
                    }
                    if use_simple_format {
                        write!(
                            f,
                            "; filename=\"{}\"",
                            match String::from_utf8(bytes.clone()) {
                                Ok(s) => s,
                                Err(_) => return Err(fmt::Error),
                            }
                        )?;
                    } else {
                        write!(f, "; filename*={}'", charset)?;
                        if let Some(ref lang) = *opt_lang {
                            write!(f, "{}", lang)?;
                        };
                        write!(f, "'")?;
                        http_percent_encode(f, bytes)?;
                    }
                }
                DispositionParam::Ext(ref k, ref v) => write!(f, "; {}=\"{}\"", k, v)?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Charset, ContentDisposition, DispositionParam, DispositionType, Header};
    use crate::file_header::Raw;

    #[test]
    fn test_parse_header() {
        let a: Raw = "".into();
        assert!(ContentDisposition::parse_header(&a).is_err());

        let a: Raw = "form-data; dummy=3; name=upload;\r\n filename=\"sample.png\"".into();
        let a: ContentDisposition = ContentDisposition::parse_header(&a).unwrap();
        let b = ContentDisposition {
            disposition: DispositionType::Ext("form-data".to_owned()),
            parameters: vec![
                DispositionParam::Ext("dummy".to_owned(), "3".to_owned()),
                DispositionParam::Ext("name".to_owned(), "upload".to_owned()),
                DispositionParam::Filename(
                    Charset::Ext("UTF-8".to_owned()),
                    None,
                    "sample.png".bytes().collect(),
                ),
            ],
        };
        assert_eq!(a, b);

        let a: Raw = "attachment; filename=\"image.jpg\"".into();
        let a: ContentDisposition = ContentDisposition::parse_header(&a).unwrap();
        let b = ContentDisposition {
            disposition: DispositionType::Attachment,
            parameters: vec![DispositionParam::Filename(
                Charset::Ext("UTF-8".to_owned()),
                None,
                "image.jpg".bytes().collect(),
            )],
        };
        assert_eq!(a, b);

        let a: Raw = "attachment; filename*=UTF-8''%c2%a3%20and%20%e2%82%ac%20rates".into();
        let a: ContentDisposition = ContentDisposition::parse_header(&a).unwrap();
        let b = ContentDisposition {
            disposition: DispositionType::Attachment,
            parameters: vec![DispositionParam::Filename(
                Charset::Ext("UTF-8".to_owned()),
                None,
                vec![
                    0xc2, 0xa3, 0x20, b'a', b'n', b'd', 0x20, 0xe2, 0x82, 0xac, 0x20, b'r',
                    b'a', b't', b'e', b's',
                ],
            )],
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
