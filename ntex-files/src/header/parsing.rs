use language_tags::LanguageTag;
use std::fmt::{self, Display};
use std::str;
use std::str::FromStr;

use super::error;
use super::{Charset, RawLike};

/// Reads a single raw string when parsing a header.
pub fn from_one_raw_str<'a, R, T>(raw: &'a R) -> error::Result<T>
where
    R: RawLike<'a>,
    T: FromStr,
{
    if let Some(line) = raw.one()
        && !line.is_empty()
    {
        return from_raw_str(line);
    }
    Err(error::Error::Header)
}

/// Reads a raw string into a value.
pub fn from_raw_str<T: FromStr>(raw: &[u8]) -> error::Result<T> {
    let s = str::from_utf8(raw)?.trim();
    T::from_str(s).or(Err(error::Error::Header))
}

/// Reads a comma-delimited raw header into a Vec.
#[inline]
pub fn from_comma_delimited<'a, R, T>(raw: &'a R) -> error::Result<Vec<T>>
where
    R: RawLike<'a>,
    T: FromStr,
{
    let mut result = Vec::new();
    for s in raw.iter() {
        let s = str::from_utf8(s)?;
        result.extend(
            split_unquoted(s, ',', false)
                .filter_map(|x| match x.trim() {
                    "" => None,
                    y => Some(y),
                })
                .filter_map(|x| x.trim().parse().ok()),
        )
    }
    Ok(result)
}

/// Splits `s` on `sep`, ignoring separators inside of quoted strings.
///
/// With `escapes` a backslash escapes the next character of a quoted string,
/// entity tags have no escapes and may contain a backslash.
pub(crate) fn split_unquoted(s: &str, sep: char, escapes: bool) -> impl Iterator<Item = &str> {
    let mut quoted = false;
    let mut escaped = false;
    s.split(move |c: char| {
        if escaped {
            escaped = false;
        } else if escapes && quoted && c == '\\' {
            escaped = true;
        } else if c == '"' {
            quoted = !quoted;
        } else if !quoted && c == sep {
            return true;
        }
        false
    })
}

/// Format an array into a comma-delimited string.
pub fn fmt_comma_delimited<T: Display>(f: &mut fmt::Formatter, parts: &[T]) -> fmt::Result {
    let mut iter = parts.iter();
    if let Some(part) = iter.next() {
        Display::fmt(part, f)?;
    }
    for part in iter {
        f.write_str(", ")?;
        Display::fmt(part, f)?;
    }
    Ok(())
}

/// An RFC 5987 extended parameter: a charset label, optional language, and bytes.
///
/// Parsing validates `charset'language'value` syntax and percent-decodes bytes,
/// but does not decode or validate them according to `charset`. Unknown charset
/// labels are accepted. Formatting emits the charset, an empty or supplied
/// language, and the byte value with percent encoding; direct construction
/// does not validate the charset label.
///
/// # Formatting limitation
///
/// The current formatter leaves `@` and `=` unescaped in the byte value. Such
/// output is not valid RFC 5987 syntax and is rejected when parsed again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtendedValue {
    /// The declared charset of `value`; no charset decoding is performed.
    pub charset: Charset,
    /// The optional language tag describing the parameter value.
    pub language_tag: Option<LanguageTag>,
    /// The percent-decoded octets, which need not be valid UTF-8.
    pub value: Vec<u8>,
}

/// Parses extended header parameter values (`ext-value`), as defined in
/// [RFC 5987](https://tools.ietf.org/html/rfc5987#section-3.2).
///
/// Takes the value only, without the parameter name or enclosing quotes.
/// Parameter names ending in `*` select this syntax. Unknown syntactically valid
/// MIME charset labels are accepted and normalized to ASCII uppercase.
/// Percent-decoding preserves arbitrary octets, without charset conversion.
///
/// # Errors
///
/// Rejects missing separators, an empty or malformed charset label, invalid
/// language tags, malformed `%HH` escapes, and unescaped bytes outside
/// `attr-char`, including spaces, non-ASCII bytes, `*`, and extra apostrophes.
/// Empty language and value sections are valid.
///
/// # ABNF
///
/// ```text
/// ext-value     = charset  "'" [ language ] "'" value-chars
///               ; like RFC 2231's <extended-initial-value>
///               ; (see [RFC2231], Section 7)
///
/// charset       = "UTF-8" / "ISO-8859-1" / mime-charset
///
/// mime-charset  = 1*mime-charsetc
/// mime-charsetc = ALPHA / DIGIT
///               / "!" / "#" / "$" / "%" / "&"
///               / "+" / "-" / "^" / "_" / "`"
///               / "{" / "}" / "~"
///               ; as <mime-charset> in Section 2.3 of [RFC2978]
///               ; except that the single quote is not included
///               ; SHOULD be registered in the IANA charset registry
///
/// language      = <Language-Tag, defined in [RFC5646], Section 2.1>
///
/// value-chars   = *( pct-encoded / attr-char )
///
/// pct-encoded   = "%" HEXDIG HEXDIG
///               ; see [RFC3986], Section 2.1
///
/// attr-char     = ALPHA / DIGIT
///               / "!" / "#" / "$" / "&" / "+" / "-" / "."
///               / "^" / "_" / "`" / "|" / "~"
///               ; token except ( "*" / "'" / "%" )
/// ```
pub fn parse_extended_value(val: &str) -> error::Result<ExtendedValue> {
    // Break into three pieces separated by the single-quote character
    let mut parts = val.splitn(3, '\'');

    // Interpret the first piece as a Charset
    let charset: Charset = match parts.next() {
        Some(n) if !n.is_empty() && n.bytes().all(is_mime_charset_char) => FromStr::from_str(n)?,
        _ => return Err(error::Error::Header),
    };

    // Interpret the second piece as a language tag
    let lang: Option<LanguageTag> = match parts.next() {
        None => return Err(error::Error::Header),
        Some("") => None,
        Some(s) => match s.parse() {
            Ok(lt) => Some(lt),
            Err(_) => return Err(error::Error::Header),
        },
    };

    // Interpret the third piece as a sequence of value characters
    let value: Vec<u8> = match parts.next() {
        None => return Err(error::Error::Header),
        Some(v) if is_valid_value_chars(v.as_bytes()) => {
            percent_encoding::percent_decode(v.as_bytes()).collect()
        }
        _ => return Err(error::Error::Header),
    };

    Ok(ExtendedValue {
        charset,
        language_tag: lang,
        value,
    })
}

fn is_mime_charset_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&+-^_`{}~".contains(&c)
}

/// Checks `value-chars = *( pct-encoded / attr-char )`.
fn is_valid_value_chars(v: &[u8]) -> bool {
    let mut i = 0;
    while i < v.len() {
        if v[i] == b'%' {
            if !v
                .get(i + 1..i + 3)
                .is_some_and(|h| h.iter().all(u8::is_ascii_hexdigit))
            {
                return false;
            }
            i += 3;
        } else if is_attr_char(v[i]) {
            i += 1;
        } else {
            return false;
        }
    }
    true
}

fn is_attr_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(&c)
}

/// Checks `token` as defined in RFC 9110, Section 5.6.2.
pub(crate) fn is_token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| is_attr_char(c) || b"%'*".contains(&c))
}

impl Display for ExtendedValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let encoded_value =
            percent_encoding::percent_encode(&self.value[..], percent_encoding_http::HTTP_VALUE);
        if let Some(ref lang) = self.language_tag {
            write!(f, "{}'{}'{}", self.charset, lang, encoded_value)
        } else {
            write!(f, "{}''{}", self.charset, encoded_value)
        }
    }
}

/// Percent encode a sequence of bytes with a character set defined in
/// [https://tools.ietf.org/html/rfc5987#section-3.2][url]
///
/// [url]: https://tools.ietf.org/html/rfc5987#section-3.2
pub fn http_percent_encode(f: &mut fmt::Formatter, bytes: &[u8]) -> fmt::Result {
    let encoded = percent_encoding::percent_encode(bytes, percent_encoding_http::HTTP_VALUE);
    Display::fmt(&encoded, f)
}

mod percent_encoding_http {
    use percent_encoding::{AsciiSet, NON_ALPHANUMERIC};

    // Everything except `attr-char` from
    // https://tools.ietf.org/html/rfc5987#section-3.2
    pub const HTTP_VALUE: &AsciiSet = &NON_ALPHANUMERIC
        .remove(b'!')
        .remove(b'#')
        .remove(b'$')
        .remove(b'&')
        .remove(b'+')
        .remove(b'-')
        .remove(b'.')
        .remove(b'^')
        .remove(b'_')
        .remove(b'`')
        .remove(b'|')
        .remove(b'~');
}

#[cfg(test)]
mod tests {
    use super::{Charset, ExtendedValue, from_comma_delimited, parse_extended_value};
    use crate::header::{EntityTag, Raw};
    use language_tags::LanguageTag;

    /// STATEMENT: A comma inside of a quoted entity tag does not split the list.
    ///
    /// HOW:
    /// - Parse a list with a tag containing `,` and a weak tag ending in `\`.
    /// - Check that exactly those tags plus the trailing one are returned.
    #[test]
    fn test_comma_delimited_quoted_entity_tags() {
        let raw: Raw = r#""x,y", W/"a\", "b""#.into();
        let tags: Vec<EntityTag> = from_comma_delimited(&raw).unwrap();
        assert_eq!(
            tags,
            vec![
                EntityTag::strong("x,y".to_owned()),
                EntityTag::weak("a\\".to_owned()),
                EntityTag::strong("b".to_owned()),
            ]
        );
    }

    #[test]
    fn test_parse_extended_value_with_encoding_and_language_tag() {
        let expected_language_tag = "en".parse::<LanguageTag>().unwrap();
        // RFC 5987, Section 3.2.2
        // Extended notation, using the Unicode character U+00A3 (POUND SIGN)
        let result = parse_extended_value("iso-8859-1'en'%A3%20rates");
        assert!(result.is_ok());
        let extended_value = result.unwrap();
        assert_eq!(Charset::Iso_8859_1, extended_value.charset);
        assert!(extended_value.language_tag.is_some());
        assert_eq!(expected_language_tag, extended_value.language_tag.unwrap());
        assert_eq!(
            vec![163, b' ', b'r', b'a', b't', b'e', b's'],
            extended_value.value
        );
    }

    #[test]
    fn test_parse_extended_value_with_encoding() {
        // RFC 5987, Section 3.2.2
        // Extended notation, using the Unicode characters U+00A3 (POUND SIGN)
        // and U+20AC (EURO SIGN)
        let result = parse_extended_value("UTF-8''%c2%a3%20and%20%e2%82%ac%20rates");
        assert!(result.is_ok());
        let extended_value = result.unwrap();
        assert_eq!(Charset::Ext("UTF-8".to_string()), extended_value.charset);
        assert!(extended_value.language_tag.is_none());
        assert_eq!(
            vec![
                194, 163, b' ', b'a', b'n', b'd', b' ', 226, 130, 172, b' ', b'r', b'a', b't',
                b'e', b's'
            ],
            extended_value.value
        );
    }

    #[test]
    fn test_parse_extended_value_missing_language_tag_and_encoding() {
        // From: https://greenbytes.de/tech/tc2231/#attwithfn2231quot2
        let result = parse_extended_value("foo%20bar.html");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_extended_value_partially_formatted() {
        let result = parse_extended_value("UTF-8'missing third part");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_extended_value_partially_formatted_blank() {
        let result = parse_extended_value("blank second part'");
        assert!(result.is_err());
    }

    #[test]
    fn test_fmt_extended_value_with_encoding_and_language_tag() {
        let extended_value = ExtendedValue {
            charset: Charset::Iso_8859_1,
            language_tag: Some("en".parse().expect("Could not parse language tag")),
            value: vec![163, b' ', b'r', b'a', b't', b'e', b's'],
        };
        assert_eq!("ISO-8859-1'en'%A3%20rates", format!("{}", extended_value));
    }

    #[test]
    fn test_fmt_extended_value_with_encoding() {
        let extended_value = ExtendedValue {
            charset: Charset::Ext("UTF-8".to_string()),
            language_tag: None,
            value: vec![
                194, 163, b' ', b'a', b'n', b'd', b' ', 226, 130, 172, b' ', b'r', b'a', b't',
                b'e', b's',
            ],
        };
        assert_eq!(
            "UTF-8''%C2%A3%20and%20%E2%82%AC%20rates",
            format!("{}", extended_value)
        );
    }

    /// STATEMENT: Single-value parsing trims whitespace but rejects empty, repeated, and invalid values.
    ///
    /// HOW:
    /// - Parse an integer from a one-line vector containing surrounding whitespace.
    /// - Try absent, empty, repeated, non-UTF-8, and nonnumeric lines and require errors.
    #[test]
    fn single_value_parsing_validates_sources() {
        let raw = Raw::from(vec![b" \t42\t ".to_vec()]);
        assert_eq!(super::from_one_raw_str::<_, u32>(&raw).unwrap(), 42);
        for raw in [
            Raw::from(Vec::<Vec<u8>>::new()),
            Raw::from(""),
            Raw::from(" \t "),
            Raw::from(vec![b"1".to_vec(), b"2".to_vec()]),
            Raw::from(b"\xff".as_slice()),
            Raw::from("not-a-number"),
        ] {
            assert!(super::from_one_raw_str::<_, u32>(&raw).is_err(), "{raw:?}");
        }
    }

    /// STATEMENT: Comma-delimited parsing merges lines and skips invalid items but rejects invalid UTF-8.
    ///
    /// HOW:
    /// - Parse integers from multiple lines containing whitespace, empty items, and an invalid number.
    /// - Check the surviving order and that a later non-UTF-8 line fails the entire parse.
    #[test]
    fn comma_lists_merge_lines_and_validate_encoding() {
        let mut raw = Raw::from(vec![b" 1, invalid, ,2 ".to_vec(), b",3,".to_vec()]);
        assert_eq!(from_comma_delimited::<_, u32>(&raw).unwrap(), vec![1, 2, 3]);
        raw.push(b"\xff".as_slice());
        assert!(from_comma_delimited::<_, u32>(&raw).is_err());
    }

    /// STATEMENT: Extended-value parsing validates language tags while retaining arbitrary encoded octets.
    ///
    /// HOW:
    /// - Parse an ISO-8859-1 value without a language and an empty value with a valid language.
    /// - Check decoded octets and empty data, then require malformed language tags to fail.
    #[test]
    fn extended_values_validate_language_and_preserve_octets() {
        let parsed = parse_extended_value("ISO-8859-1''%00%fF+").unwrap();
        assert_eq!(parsed.charset, Charset::Iso_8859_1);
        assert_eq!(parsed.language_tag, None);
        assert_eq!(parsed.value, b"\0\xff+");
        let empty = parse_extended_value("UTF-8'zh-Hant'").unwrap();
        assert_eq!(empty.language_tag, Some("zh-Hant".parse().unwrap()));
        assert!(empty.value.is_empty());
        for language in ["en_US", "en--US", "1234", "en US"] {
            assert!(
                parse_extended_value(&format!("UTF-8'{language}'value")).is_err(),
                "{language}"
            );
        }
    }

    /// STATEMENT: Extended values must have a nonempty token charset and well-formed percent escapes.
    ///
    /// HOW:
    /// - Parse an empty charset, a charset with spaces, and malformed percent-encoded values.
    /// - Collect accepted inputs and require all invalid RFC 5987 syntax to be rejected.
    #[test]
    fn malformed_extended_value_syntax_is_rejected() {
        let accepted: Vec<_> = [
            "''file.txt",
            "UTF 8''file.txt",
            "UTF-8''bad%ZZ",
            "UTF-8''bad%A",
        ]
        .into_iter()
        .filter(|value| parse_extended_value(value).is_ok())
        .collect();
        assert!(
            accepted.is_empty(),
            "accepted malformed extended values: {accepted:?}"
        );
    }

    /// STATEMENT: Formatting an extended value escapes every byte that is not an RFC 5987 `attr-char`.
    ///
    /// HOW:
    /// - Format a value containing `@`, `=`, and `attr-char` punctuation.
    /// - Confirm only the non-`attr-char` bytes are escaped and the output parses back to the same bytes.
    #[test]
    fn formatted_extended_values_round_trip() {
        let value = b"a@b=c-d.e~!".to_vec();
        let formatted = ExtendedValue {
            charset: Charset::Ext("UTF-8".to_string()),
            language_tag: None,
            value: value.clone(),
        }
        .to_string();
        assert_eq!(formatted, "UTF-8''a%40b%3Dc-d.e~!");
        assert_eq!(parse_extended_value(&formatted).unwrap().value, value);
    }
}
