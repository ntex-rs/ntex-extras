use std::fmt::{self, Display};
use std::str::FromStr;

use self::Charset::*;
use super::error;

/// A MIME character-set label, not a character decoder.
///
/// Parsing recognizes the listed charsets case-insensitively and normalizes
/// unknown labels to ASCII uppercase. It accepts arbitrary labels without
/// validating their syntax. Formatting uses built-in names (`Shift-JIS` for
/// [`Self::Shift_Jis`]) and preserves a directly constructed [`Self::Ext`] string.
///
/// See the [IANA character-set registry](https://www.iana.org/assignments/character-sets/character-sets.xhtml).
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum Charset {
    /// US ASCII
    Us_Ascii,
    /// ISO-8859-1
    Iso_8859_1,
    /// ISO-8859-2
    Iso_8859_2,
    /// ISO-8859-3
    Iso_8859_3,
    /// ISO-8859-4
    Iso_8859_4,
    /// ISO-8859-5
    Iso_8859_5,
    /// ISO-8859-6
    Iso_8859_6,
    /// ISO-8859-7
    Iso_8859_7,
    /// ISO-8859-8
    Iso_8859_8,
    /// ISO-8859-9
    Iso_8859_9,
    /// ISO-8859-10
    Iso_8859_10,
    /// Shift JIS, formatted as `Shift-JIS`.
    Shift_Jis,
    /// EUC-JP
    Euc_Jp,
    /// ISO-2022-KR
    Iso_2022_Kr,
    /// EUC-KR
    Euc_Kr,
    /// ISO-2022-JP
    Iso_2022_Jp,
    /// ISO-2022-JP-2
    Iso_2022_Jp_2,
    /// ISO-8859-6-E
    Iso_8859_6_E,
    /// ISO-8859-6-I
    Iso_8859_6_I,
    /// ISO-8859-8-E
    Iso_8859_8_E,
    /// ISO-8859-8-I
    Iso_8859_8_I,
    /// GB2312
    Gb2312,
    /// Big5
    Big5,
    /// KOI8-R
    Koi8_R,
    /// An unrecognized label; parsing uppercases it, but direct construction preserves it.
    Ext(String),
}

impl Charset {
    fn name(&self) -> &str {
        match *self {
            Us_Ascii => "US-ASCII",
            Iso_8859_1 => "ISO-8859-1",
            Iso_8859_2 => "ISO-8859-2",
            Iso_8859_3 => "ISO-8859-3",
            Iso_8859_4 => "ISO-8859-4",
            Iso_8859_5 => "ISO-8859-5",
            Iso_8859_6 => "ISO-8859-6",
            Iso_8859_7 => "ISO-8859-7",
            Iso_8859_8 => "ISO-8859-8",
            Iso_8859_9 => "ISO-8859-9",
            Iso_8859_10 => "ISO-8859-10",
            Shift_Jis => "Shift-JIS",
            Euc_Jp => "EUC-JP",
            Iso_2022_Kr => "ISO-2022-KR",
            Euc_Kr => "EUC-KR",
            Iso_2022_Jp => "ISO-2022-JP",
            Iso_2022_Jp_2 => "ISO-2022-JP-2",
            Iso_8859_6_E => "ISO-8859-6-E",
            Iso_8859_6_I => "ISO-8859-6-I",
            Iso_8859_8_E => "ISO-8859-8-E",
            Iso_8859_8_I => "ISO-8859-8-I",
            Gb2312 => "GB2312",
            Big5 => "BIG5",
            Koi8_R => "KOI8-R",
            Ext(ref s) => s,
        }
    }
}

impl Display for Charset {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Charset {
    type Err = error::Error;
    fn from_str(s: &str) -> error::Result<Charset> {
        Ok(match s.to_ascii_uppercase().as_ref() {
            "US-ASCII" => Us_Ascii,
            "ISO-8859-1" => Iso_8859_1,
            "ISO-8859-2" => Iso_8859_2,
            "ISO-8859-3" => Iso_8859_3,
            "ISO-8859-4" => Iso_8859_4,
            "ISO-8859-5" => Iso_8859_5,
            "ISO-8859-6" => Iso_8859_6,
            "ISO-8859-7" => Iso_8859_7,
            "ISO-8859-8" => Iso_8859_8,
            "ISO-8859-9" => Iso_8859_9,
            "ISO-8859-10" => Iso_8859_10,
            "SHIFT-JIS" => Shift_Jis,
            "EUC-JP" => Euc_Jp,
            "ISO-2022-KR" => Iso_2022_Kr,
            "EUC-KR" => Euc_Kr,
            "ISO-2022-JP" => Iso_2022_Jp,
            "ISO-2022-JP-2" => Iso_2022_Jp_2,
            "ISO-8859-6-E" => Iso_8859_6_E,
            "ISO-8859-6-I" => Iso_8859_6_I,
            "ISO-8859-8-E" => Iso_8859_8_E,
            "ISO-8859-8-I" => Iso_8859_8_I,
            "GB2312" => Gb2312,
            "BIG5" => Big5,
            "KOI8-R" => Koi8_R,
            s => Ext(s.to_owned()),
        })
    }
}

#[test]
fn test_parse() {
    assert_eq!(Us_Ascii, "us-ascii".parse().unwrap());
    assert_eq!(Us_Ascii, "US-Ascii".parse().unwrap());
    assert_eq!(Us_Ascii, "US-ASCII".parse().unwrap());
    assert_eq!(Shift_Jis, "Shift-JIS".parse().unwrap());
    assert_eq!(Ext("ABCD".to_owned()), "abcd".parse().unwrap());
}

#[test]
fn test_display() {
    assert_eq!("US-ASCII", format!("{}", Us_Ascii));
    assert_eq!("ABCD", format!("{}", Ext("ABCD".to_owned())));
}

/// STATEMENT: The `Big5` charset uses its registered name `BIG5`.
///
/// HOW:
/// - Parse `big5` and check that it yields `Big5`.
/// - Format `Big5` and check that it prints `BIG5`.
#[test]
fn test_big5_name() {
    assert_eq!(Big5, "big5".parse().unwrap());
    assert_eq!("BIG5", format!("{}", Big5));
}

#[cfg(test)]
mod tests {
    use super::Charset::{self, *};

    /// STATEMENT: Registered charset names parse case-insensitively and extensions normalize to uppercase.
    ///
    /// HOW:
    /// - Parse mixed-case ISO, Asian, and Cyrillic charset names and a vendor extension.
    /// - Check the selected variants and their canonical names survive reparsing.
    #[test]
    fn charset_names_normalize_and_round_trip() {
        for (name, expected) in [
            ("iSo-8859-2", Iso_8859_2),
            ("iso-8859-3", Iso_8859_3),
            ("iso-8859-4", Iso_8859_4),
            ("iso-8859-5", Iso_8859_5),
            ("iso-8859-6", Iso_8859_6),
            ("iso-8859-7", Iso_8859_7),
            ("iso-8859-8", Iso_8859_8),
            ("iso-8859-9", Iso_8859_9),
            ("iso-8859-10", Iso_8859_10),
            ("sHiFt-JiS", Shift_Jis),
            ("euc-jp", Euc_Jp),
            ("iso-2022-kr", Iso_2022_Kr),
            ("euc-kr", Euc_Kr),
            ("iso-2022-jp", Iso_2022_Jp),
            ("iso-2022-jp-2", Iso_2022_Jp_2),
            ("iso-8859-6-e", Iso_8859_6_E),
            ("iso-8859-6-i", Iso_8859_6_I),
            ("iso-8859-8-e", Iso_8859_8_E),
            ("iso-8859-8-i", Iso_8859_8_I),
            ("gb2312", Gb2312),
            ("kOi8-r", Koi8_R),
            ("x-Vendor", Ext("X-VENDOR".into())),
        ] {
            let parsed: Charset = name.parse().unwrap();
            assert_eq!(parsed, expected, "{name}");
            let canonical = if parsed == Shift_Jis {
                "Shift-JIS".into()
            } else {
                name.to_ascii_uppercase()
            };
            assert_eq!(parsed.to_string(), canonical, "{name}");
            assert_eq!(parsed.to_string().parse::<Charset>().unwrap(), expected);
        }
    }
}
