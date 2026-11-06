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
        self.parameters
            .iter()
            .find_map(DispositionParam::as_filename)
    }

    /// Return the value of *filename\** if exists.
    pub fn get_filename_ext(&self) -> Option<&ExtendedValue> {
        self.parameters
            .iter()
            .find_map(DispositionParam::as_filename_ext)
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
            let mut sections = parsing::split_unquoted(&s, ';', true);
            let disposition = match sections.next() {
                Some(s) if parsing::is_token(s.trim()) => s.trim(),
                _ => return Err(error::Error::Header),
            };

            let mut cd = ContentDisposition {
                disposition: disposition.into(),
                parameters: Vec::new(),
            };

            for section in sections {
                let mut parts = section.splitn(2, '=');

                let key = if let Some(key) = parts.next() {
                    let key_trimmed = key.trim();

                    if !parsing::is_token(key_trimmed) || key_trimmed == "*" {
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
                        let mut quoted_string = vec![];
                        let mut chars = val.as_bytes()[1..].iter();
                        let mut closed = false;

                        // search for closing quote
                        while let Some(&c) = chars.next() {
                            match c {
                                b'\\' => match chars.next() {
                                    Some(&c) => quoted_string.push(c),
                                    None => break,
                                },
                                b'"' => {
                                    closed = true;
                                    break;
                                }
                                c => quoted_string.push(c),
                            }
                        }

                        // the value must end with the closing quote
                        if !closed || chars.next().is_some() {
                            return Err(error::Error::Header);
                        }

                        // In fact, it should not be Err if the above code is correct.
                        String::from_utf8(quoted_string).map_err(|_| error::Error::Header)?
                    } else {
                        // quoted-string can be empty, but token cannot be empty
                        if !parsing::is_token(val) {
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

impl fmt::Display for DispositionType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DispositionType::Inline => write!(f, "inline"),
            DispositionType::Attachment => write!(f, "attachment"),
            DispositionType::FormData => write!(f, "form-data"),
            DispositionType::Ext(s) => write!(f, "{}", s),
        }
    }
}

impl fmt::Display for DispositionParam {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // All ASCII control characters (0-30, 127) including horizontal tab, double quote, and
        // backslash should be escaped in quoted-string (i.e. "foobar").
        //
        // Ref: RFC 6266 §4.1 -> RFC 2616 §3.6
        //
        // filename-parm  = "filename" "=" value
        // value          = token | quoted-string
        // quoted-string  = ( <"> *(qdtext | quoted-pair ) <"> )
        // qdtext         = <any TEXT except <">>
        // quoted-pair    = "\" CHAR
        // TEXT           = <any OCTET except CTLs,
        //                  but including LWS>
        // LWS            = [CRLF] 1*( SP | HT )
        // OCTET          = <any 8-bit sequence of data>
        // CHAR           = <any US-ASCII character (octets 0 - 127)>
        // CTL            = <any US-ASCII control character
        //                  (octets 0 - 31) and DEL (127)>
        //
        // Ref: RFC 7578 S4.2 -> RFC 2183 S2 -> RFC 2045 S5.1
        // parameter := attribute "=" value
        // attribute := token
        //              ; Matching of attributes
        //              ; is ALWAYS case-insensitive.
        // value := token / quoted-string
        // token := 1*<any (US-ASCII) CHAR except SPACE, CTLs,
        //             or tspecials>
        // tspecials :=  "(" / ")" / "<" / ">" / "@" /
        //               "," / ";" / ":" / "\" / <">
        //               "/" / "[" / "]" / "?" / "="
        //               ; Must be in quoted-string,
        //               ; to use within parameter values
        //
        //
        // See also comments in test_from_raw_unnecessary_percent_decode.

        static RE: LazyLock<Regex> =
            LazyLock::new(|| Regex::new("[\x00-\x08\x10-\x1F\x7F\"\\\\]").unwrap());

        match self {
            DispositionParam::Name(value) => {
                write!(f, "name=\"{}\"", RE.replace_all(value, "\\$0").as_ref())
            }

            DispositionParam::Filename(value) => {
                write!(f, "filename=\"{}\"", RE.replace_all(value, "\\$0").as_ref())
            }

            DispositionParam::Unknown(name, value) => {
                write!(f, "{}=\"{}\"", name, RE.replace_all(value, "\\$0").as_ref())
            }

            DispositionParam::FilenameExt(ext_value) => {
                write!(f, "filename*={}", ext_value)
            }

            DispositionParam::UnknownExt(name, ext_value) => {
                write!(f, "{}*={}", name, ext_value)
            }
        }
    }
}

impl fmt::Display for ContentDisposition {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.disposition)?;

        for param in &self.parameters {
            write!(f, "; {}", param)?;
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
                    0xc2, 0xa3, 0x20, b'a', b'n', b'd', 0x20, 0xe2, 0x82, 0xac, 0x20, b'r', b'a',
                    b't', b'e', b's',
                ],
            })],
        };
        assert_eq!(a, b);
    }

    /// STATEMENT: A `;` inside of a quoted parameter value does not split the parameter.
    ///
    /// HOW:
    /// - Parse a header whose quoted `filename` contains `;` and an escaped quote.
    /// - Check that `name` and the whole `filename` are parsed.
    #[test]
    fn test_parse_quoted_separator() {
        let a: Raw = r#"form-data; name="f"; filename="a;b \"c\".txt""#.into();
        let a = ContentDisposition::parse_header(&a).unwrap();
        assert_eq!(a.get_name(), Some("f"));
        assert_eq!(a.get_filename(), Some(r#"a;b "c".txt"#));
    }

    #[test]
    fn test_display() {
        let as_string = "attachment; filename*=UTF-8'en'%C2%A3%20and%20%E2%82%AC%20rates";
        let a: Raw = as_string.into();
        let a: ContentDisposition = ContentDisposition::parse_header(&a).unwrap();
        let display_rendered = format!("{}", a);
        assert_eq!(as_string, display_rendered);

        // TODO Fix this test
        // let a: Raw = "attachment; filename*=UTF-8''black%20and%20white.csv".into();
        // let a: ContentDisposition = ContentDisposition::parse_header(&a).unwrap();
        // let display_rendered = format!("{}", a);
        // assert_eq!("attachment; filename=\"black and white.csv\"".to_owned(), display_rendered);

        let a: Raw = "attachment; filename=colourful.csv".into();
        let a: ContentDisposition = ContentDisposition::parse_header(&a).unwrap();
        let display_rendered = format!("{}", a);
        assert_eq!(
            "attachment; filename=\"colourful.csv\"".to_owned(),
            display_rendered
        );
    }

    /// STATEMENT: Disposition types and recognized parameter names are case-insensitive.
    ///
    /// HOW:
    /// - Parse mixed-case types and parameter names with surrounding whitespace.
    /// - Check the resulting variants, preserved extension spelling, and literal `%20` filename.
    #[test]
    fn disposition_types_and_parameter_names_are_case_insensitive() {
        for (token, disposition) in [
            ("InLiNe", DispositionType::Inline),
            ("ATTACHMENT", DispositionType::Attachment),
            ("Form-Data", DispositionType::FormData),
            ("X-Archive", DispositionType::Ext("X-Archive".to_owned())),
        ] {
            let raw = Raw::from(format!(
                " \t{token} ; NaMe = upload ; FiLeNaMe = file%20name.txt \t"
            ));
            assert_eq!(
                ContentDisposition::parse_header(&raw).unwrap(),
                ContentDisposition {
                    disposition,
                    parameters: vec![
                        DispositionParam::Name("upload".to_owned()),
                        DispositionParam::Filename("file%20name.txt".to_owned()),
                    ],
                },
                "{token}"
            );
        }
    }

    /// STATEMENT: Extended parameters retain their charset, language, and decoded octets.
    ///
    /// HOW:
    /// - Parse a fallback filename, mixed-case `filename*`, and regular and extended unknown parameters.
    /// - Check case-insensitive lookup and decoded bytes, then format and reparse the whole header.
    #[test]
    fn extended_parameters_preserve_metadata_and_round_trip() {
        let raw = Raw::from(
            "attachment; note=first; FiLeNaMe=fallback.txt; \
             X-Note*=x-vendor'fr'%FF%20note; \
             FILENAME*=utf-8'en-US'r%C3%A9sum%C3%A9%2Bdraft%3F.txt",
        );
        let parsed = ContentDisposition::parse_header(&raw).unwrap();
        assert_eq!(parsed.get_filename(), Some("fallback.txt"));
        assert_eq!(parsed.get_unknown("NOTE"), Some("first"));
        assert_eq!(parsed.get_unknown("absent"), None);
        assert_eq!(parsed.get_name(), None);
        assert_eq!(
            parsed.get_filename_ext(),
            Some(&ExtendedValue {
                charset: Charset::Ext("UTF-8".to_owned()),
                language_tag: Some("en-US".parse().unwrap()),
                value: "résumé+draft?.txt".as_bytes().to_vec(),
            })
        );
        assert_eq!(
            parsed.get_unknown_ext("x-NOTE"),
            Some(&ExtendedValue {
                charset: Charset::Ext("X-VENDOR".to_owned()),
                language_tag: Some("fr".parse().unwrap()),
                value: b"\xff note".to_vec(),
            })
        );
        assert_eq!(parsed.get_unknown_ext("absent"), None);
        let rendered = parsed.to_string();
        assert!(rendered.contains("X-Note*=X-VENDOR'fr'%FF%20note"));
        assert!(rendered.contains("filename*=UTF-8'en-US'r%C3%A9sum%C3%A9+draft%3F.txt"));
        assert_eq!(
            ContentDisposition::parse_header(&Raw::from(rendered)).unwrap(),
            parsed
        );
    }

    /// STATEMENT: Quoted parameters accept empty values and unescape quoted pairs.
    ///
    /// HOW:
    /// - Parse an empty `name`, escaped backslash and separators, and a quoted unknown parameter.
    /// - Check that escapes are removed without losing separators or embedded quotes.
    #[test]
    fn quoted_parameters_handle_empty_and_escaped_values() {
        let raw = Raw::from(r#"form-data; name=""; filename="a\\b\;c\=d"; CoMmEnT="say \"hi\"""#);
        let parsed = ContentDisposition::parse_header(&raw).unwrap();
        assert_eq!(parsed.get_name(), Some(""));
        assert_eq!(parsed.get_filename(), Some(r"a\b;c=d"));
        assert_eq!(parsed.get_unknown("comment"), Some(r#"say "hi""#));
    }

    /// STATEMENT: Formatting escapes quoted filenames and unknown values reversibly.
    ///
    /// HOW:
    /// - Format headers containing Unicode, quotes, backslashes, separators, and control bytes.
    /// - Check the escaped representation and that parsing recovers every original parameter.
    #[test]
    fn formatted_parameters_escape_and_round_trip() {
        for disposition in [
            DispositionType::FormData,
            DispositionType::Ext("x-file".into()),
        ] {
            let original = ContentDisposition {
                disposition,
                parameters: vec![
                    DispositionParam::Name("upload".into()),
                    DispositionParam::Filename("café\\\";notes.txt".into()),
                    DispositionParam::Unknown("comment".into(), "a\0\u{1}\u{1f}\u{7f}\\\"b".into()),
                ],
            };
            let rendered = original.to_string();
            assert!(rendered.contains(r#"filename="café\\\";notes.txt""#));
            assert!(rendered.contains("comment=\"a\\\0\\\u{1}\\\u{1f}\\\u{7f}\\\\\\\"b\""));
            assert_eq!(
                ContentDisposition::parse_header(&Raw::from(rendered)).unwrap(),
                original
            );
        }
    }

    /// STATEMENT: Missing parameter keys or values and invalid raw headers fail parsing.
    ///
    /// HOW:
    /// - Parse empty, malformed, non-UTF-8, and repeated header values.
    /// - Check that each produces an error rather than a partial disposition.
    #[test]
    fn malformed_parameters_and_raw_headers_are_rejected() {
        let mut cases = [
            "inline;",
            "inline; =value",
            "inline; *=value",
            "inline; filename",
            "inline; filename= \t",
            "attachment; filename*=UTF-8",
            "attachment; filename*=UTF-8'fr",
        ]
        .map(Raw::from)
        .to_vec();
        cases.push(Raw::from(Vec::<Vec<u8>>::new()));
        cases.push(Raw::from(b"attachment; filename=\xff".as_slice()));
        cases.push(Raw::from(vec![b"inline".to_vec(), b"attachment".to_vec()]));
        for raw in cases {
            assert!(ContentDisposition::parse_header(&raw).is_err(), "{raw:?}");
        }
    }

    /// STATEMENT: Malformed quoted filenames must not be silently accepted.
    ///
    /// HOW:
    /// - Parse a missing closing quote, a dangling quoted escape, and trailing text after a quote.
    /// - Collect accepted inputs and require that all malformed inputs were rejected.
    #[test]
    fn malformed_quoted_filenames_are_rejected() {
        let accepted: Vec<_> = [
            "attachment; filename=\"unterminated",
            "attachment; filename=\"dangling\\",
            "attachment; filename=\"a\"trailing",
        ]
        .into_iter()
        .filter(|value| ContentDisposition::parse_header(&Raw::from(*value)).is_ok())
        .collect();
        assert!(
            accepted.is_empty(),
            "accepted malformed headers: {accepted:?}"
        );
    }

    /// STATEMENT: Formatting preserves quoted form field names containing separators or quotes.
    ///
    /// HOW:
    /// - Parse quoted `name` values containing a semicolon and literal double quotes.
    /// - Format and reparse each header, requiring the original parameters to be recovered.
    #[test]
    fn quoted_form_field_names_round_trip() {
        let broken: Vec<_> = [
            r#"form-data; name="a;b""#,
            r#"form-data; name="\"quoted\"""#,
        ]
        .into_iter()
        .filter(|value| {
            let original = ContentDisposition::parse_header(&Raw::from(*value)).unwrap();
            !ContentDisposition::parse_header(&Raw::from(original.to_string()))
                .is_ok_and(|parsed| parsed == original)
        })
        .collect();
        assert!(
            broken.is_empty(),
            "field names do not round trip: {broken:?}"
        );
    }

    /// STATEMENT: Mixed-case dispositions and all parameter kinds survive canonical formatting and classification.
    ///
    /// HOW:
    /// - Parse inline, attachment, form-data, and extension headers with escaped names and regular and extended metadata.
    /// - Check case-insensitive type and parameter classification, decoded values, and equality after formatting and reparsing.
    #[test]
    fn mixed_dispositions_classify_and_round_trip_parameters() {
        for token in ["InLiNe", "ATTACHMENT", "Form-Data", "X-Archive"] {
            let raw = Raw::from(format!(
                r#"{token}; name="a;b"; filename="a\"b.txt"; filename*=UTF-8'en'%C3%A9.txt; X-Note=first; X-Note*=ISO-8859-1'fr'%A3"#
            ));
            let parsed = ContentDisposition::parse_header(&raw).unwrap();
            assert_eq!(parsed.is_inline(), token == "InLiNe");
            assert_eq!(parsed.is_attachment(), token == "ATTACHMENT");
            assert_eq!(parsed.is_form_data(), token == "Form-Data");
            assert_eq!(parsed.is_ext("x-archive"), token == "X-Archive");
            assert!(!parsed.is_ext("other"));
            assert_eq!(parsed.get_name(), Some("a;b"));
            assert_eq!(parsed.get_filename(), Some("a\"b.txt"));
            assert_eq!(parsed.get_filename_ext().unwrap().value, "é.txt".as_bytes());
            assert_eq!(parsed.get_unknown("x-note"), Some("first"));
            assert_eq!(parsed.get_unknown_ext("X-NOTE").unwrap().value, b"\xa3");
            for (index, param) in parsed.parameters.iter().enumerate() {
                assert_eq!(param.is_name(), index == 0);
                assert_eq!(param.is_filename(), index == 1);
                assert_eq!(param.is_filename_ext(), index == 2);
                assert_eq!(param.is_unknown("x-note"), index == 3);
                assert_eq!(param.is_unknown_ext("X-NOTE"), index == 4);
                assert!(!param.is_unknown("absent"));
                assert!(!param.is_unknown_ext("absent"));
            }
            let reparsed =
                ContentDisposition::parse_header(&Raw::from(parsed.to_string())).unwrap();
            assert_eq!(reparsed, parsed);
        }
    }

    /// STATEMENT: Disposition types, parameter names, and unquoted values must follow HTTP token syntax.
    ///
    /// HOW:
    /// - Parse headers with an absent or malformed disposition, illegal parameter names, and unquoted separators.
    /// - Require every invalid field to be rejected instead of retained as extension metadata.
    #[test]
    fn malformed_disposition_tokens_are_rejected() {
        for value in [
            " ",
            "; filename=a.txt",
            "two words; filename=a.txt",
            "\"attachment\"; filename=a.txt",
            "attachment; bad key=value",
            "attachment; filename=two words.txt",
            "attachment; filename=a/b.txt",
            "attachment; filename=a\"b.txt",
        ] {
            assert!(
                ContentDisposition::parse_header(&Raw::from(value)).is_err(),
                "{value:?}"
            );
        }
    }

    /// STATEMENT: Extended disposition parameters permit only encoded octets or RFC 5987 attribute characters.
    ///
    /// HOW:
    /// - Parse extended filenames containing raw spaces, asterisks, apostrophes, quotes, and non-ASCII bytes.
    /// - Require rejection, while checking the percent-encoded equivalents preserve the original bytes.
    #[test]
    fn unescaped_extended_value_characters_are_rejected() {
        for (invalid, encoded, expected) in [
            ("two words", "two%20words", "two words"),
            ("a*b", "a%2Ab", "a*b"),
            ("a'b", "a%27b", "a'b"),
            ("a\"b", "a%22b", "a\"b"),
            ("é.txt", "%C3%A9.txt", "é.txt"),
        ] {
            let valid = Raw::from(format!("attachment; filename*=UTF-8''{encoded}"));
            let parsed = ContentDisposition::parse_header(&valid).unwrap();
            assert_eq!(
                parsed.get_filename_ext().unwrap().value,
                expected.as_bytes()
            );
            let invalid = Raw::from(format!("attachment; filename*=UTF-8''{invalid}"));
            assert!(
                ContentDisposition::parse_header(&invalid).is_err(),
                "{invalid:?}"
            );
        }
    }
}

standard_header!(ContentDisposition, CONTENT_DISPOSITION);
