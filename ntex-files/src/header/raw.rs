use ntex::util::Bytes;
use std::borrow::Cow;
use std::fmt;

/// Trait for raw bytes parsing access to header values (aka lines) for a single
/// header name.
pub trait RawLike<'a> {
    /// The associated type of `Iterator` over values.
    type IntoIter: Iterator<Item = &'a [u8]> + 'a;

    /// Return the number of values (lines) in the headers.
    fn len(&'a self) -> usize;

    /// Return the bool if there are no values (lines) in the headers.
    fn is_empty(&'a self) -> bool {
        self.len() == 0
    }

    /// Return the single value (line), if and only if there is exactly
    /// one. Otherwise return `None`.
    fn one(&'a self) -> Option<&'a [u8]>;

    /// Iterate the values (lines) as raw bytes.
    fn iter(&'a self) -> Self::IntoIter;
}

/// A raw header value.
#[derive(Clone, Debug)]
pub struct Raw(Lines);

impl Raw {
    /// Append a line to this `Raw` header value.
    pub fn push<V: Into<Raw>>(&mut self, val: V) {
        let raw = val.into();
        match raw.0 {
            Lines::Empty => (),
            Lines::One(one) => self.push_line(one),
            Lines::Many(lines) => {
                for line in lines {
                    self.push_line(line);
                }
            }
        }
    }

    fn push_line(&mut self, line: Bytes) {
        let lines = ::std::mem::replace(&mut self.0, Lines::Empty);
        match lines {
            Lines::Empty => {
                self.0 = Lines::One(line);
            }
            Lines::One(one) => {
                self.0 = Lines::Many(vec![one, line]);
            }
            Lines::Many(mut lines) => {
                lines.push(line);
                self.0 = Lines::Many(lines);
            }
        }
    }
}

impl<'a> RawLike<'a> for Raw {
    type IntoIter = RawLines<'a>;

    #[inline]
    fn len(&'a self) -> usize {
        match self.0 {
            Lines::Empty => 0,
            Lines::One(..) => 1,
            Lines::Many(ref lines) => lines.len(),
        }
    }

    #[inline]
    fn one(&'a self) -> Option<&'a [u8]> {
        match self.0 {
            Lines::One(ref line) => Some(line.as_ref()),
            Lines::Many(ref lines) if lines.len() == 1 => Some(lines[0].as_ref()),
            _ => None,
        }
    }

    #[inline]
    fn iter(&'a self) -> RawLines<'a> {
        RawLines {
            inner: &self.0,
            pos: 0,
        }
    }
}

#[derive(Clone)]
enum Lines {
    Empty,
    One(Bytes),
    Many(Vec<Bytes>),
}

fn eq_many<A: AsRef<[u8]>, B: AsRef<[u8]>>(a: &[A], b: &[B]) -> bool {
    if a.len() != b.len() {
        false
    } else {
        for (a, b) in a.iter().zip(b.iter()) {
            if a.as_ref() != b.as_ref() {
                return false;
            }
        }
        true
    }
}

fn eq<B: AsRef<[u8]>>(raw: &Raw, b: &[B]) -> bool {
    match raw.0 {
        Lines::Empty => b.is_empty(),
        Lines::One(ref line) => eq_many(&[line], b),
        Lines::Many(ref lines) => eq_many(lines, b),
    }
}

impl PartialEq for Raw {
    fn eq(&self, other: &Raw) -> bool {
        match other.0 {
            Lines::Empty => eq(self, &[] as &[Bytes]),
            Lines::One(ref line) => eq(self, &[line]),
            Lines::Many(ref lines) => eq(self, lines),
        }
    }
}

impl Eq for Raw {}

impl PartialEq<[Vec<u8>]> for Raw {
    fn eq(&self, bytes: &[Vec<u8>]) -> bool {
        eq(self, bytes)
    }
}

impl PartialEq<[&[u8]]> for Raw {
    fn eq(&self, bytes: &[&[u8]]) -> bool {
        eq(self, bytes)
    }
}

impl PartialEq<[String]> for Raw {
    fn eq(&self, bytes: &[String]) -> bool {
        eq(self, bytes)
    }
}

impl<'a> PartialEq<[&'a str]> for Raw {
    fn eq(&self, bytes: &[&'a str]) -> bool {
        eq(self, bytes)
    }
}

impl PartialEq<[u8]> for Raw {
    fn eq(&self, bytes: &[u8]) -> bool {
        match self.0 {
            Lines::Empty => bytes.is_empty(),
            Lines::One(ref line) => line.as_ref() == bytes,
            Lines::Many(..) => false,
        }
    }
}

impl PartialEq<str> for Raw {
    fn eq(&self, s: &str) -> bool {
        self == s.as_bytes()
    }
}

impl From<Vec<Vec<u8>>> for Raw {
    #[inline]
    fn from(val: Vec<Vec<u8>>) -> Raw {
        Raw(Lines::Many(
            val.into_iter()
                .map(|vec| maybe_literal(vec.into()))
                .collect(),
        ))
    }
}

impl From<String> for Raw {
    #[inline]
    fn from(val: String) -> Raw {
        Raw::from(val.into_bytes())
    }
}

impl From<Vec<u8>> for Raw {
    #[inline]
    fn from(val: Vec<u8>) -> Raw {
        Raw(Lines::One(maybe_literal(val.into())))
    }
}

impl<'a> From<&'a str> for Raw {
    fn from(val: &'a str) -> Raw {
        Raw::from(val.as_bytes())
    }
}

impl<'a> From<&'a [u8]> for Raw {
    fn from(val: &'a [u8]) -> Raw {
        Raw(Lines::One(maybe_literal(val.into())))
    }
}

impl From<Bytes> for Raw {
    #[inline]
    fn from(val: Bytes) -> Raw {
        Raw(Lines::One(val))
    }
}

pub fn parsed(val: Bytes) -> Raw {
    Raw(Lines::One(From::from(val)))
}

pub fn push(raw: &mut Raw, val: Bytes) {
    raw.push_line(val);
}

pub fn new() -> Raw {
    Raw(Lines::Empty)
}

impl fmt::Debug for Lines {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Lines::Empty => f.pad("[]"),
            Lines::One(ref line) => fmt::Debug::fmt(&[line], f),
            Lines::Many(ref lines) => fmt::Debug::fmt(lines, f),
        }
    }
}

impl ::std::ops::Index<usize> for Raw {
    type Output = [u8];

    fn index(&self, idx: usize) -> &[u8] {
        match self.0 {
            Lines::Empty => panic!("index of out of bounds: {}", idx),
            Lines::One(ref line) => {
                if idx == 0 {
                    line.as_ref()
                } else {
                    panic!("index out of bounds: {}", idx)
                }
            }
            Lines::Many(ref lines) => lines[idx].as_ref(),
        }
    }
}

macro_rules! literals {
    ($($len:expr => $($value:expr),+;)+) => (
        fn maybe_literal(s: Cow<[u8]>) -> Bytes {
            match s.len() {
                $($len => {
                    for value in [$($value),+] {
                        if s.as_ref() == value {
                            return Bytes::from_static(value);
                        }
                    }
                })+

                _ => ()
            }

            Bytes::from(s.into_owned())
        }

        #[test]
        fn test_literal_lens() {
            $(
            $({
                let s = $value;
                assert!(s.len() == $len, "{:?} has len of {}, listed as {}", s, s.len(), $len);
            })+
            )+
        }
    );
}

literals! {
    1  => b"*", b"0";
    3  => b"*/*";
    4  => b"gzip";
    5  => b"close";
    7  => b"chunked";
    10 => b"keep-alive";
}

impl<'a> IntoIterator for &'a Raw {
    type IntoIter = RawLines<'a>;
    type Item = &'a [u8];

    fn into_iter(self) -> RawLines<'a> {
        self.iter()
    }
}

pub struct RawLines<'a> {
    inner: &'a Lines,
    pos: usize,
}

impl<'a> fmt::Debug for RawLines<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("RawLines").field(&self.inner).finish()
    }
}

impl<'a> Iterator for RawLines<'a> {
    type Item = &'a [u8];

    #[inline]
    fn next(&mut self) -> Option<&'a [u8]> {
        let current_pos = self.pos;
        self.pos += 1;
        match *self.inner {
            Lines::Empty => None,
            Lines::One(ref line) => {
                if current_pos == 0 {
                    Some(line.as_ref())
                } else {
                    None
                }
            }
            Lines::Many(ref lines) => lines.get(current_pos).map(|l| l.as_ref()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Raw, RawLike};
    use crate::header::{EntityTag, Header, IfMatch};
    use ntex::util::Bytes;

    /// STATEMENT: Appending raw values preserves line order without joining header fields.
    ///
    /// HOW:
    /// - Append single, multiple, and empty groups to an initial entity-tag line.
    /// - Check raw boundaries, iterator exhaustion, and the combined typed `IfMatch` list.
    #[test]
    fn appending_values_preserves_header_lines() {
        let mut raw = Raw::from("\"first\"");
        raw.push(vec![b"W/\"second\"".to_vec(), b"\"third\"".to_vec()]);
        raw.push(String::from("\"fourth\""));
        raw.push(Vec::<Vec<u8>>::new());
        assert_eq!(raw.len(), 4);
        assert_eq!(raw.one(), None);
        assert_eq!(&raw[1], b"W/\"second\"");
        let expected: Vec<&[u8]> = vec![b"\"first\"", b"W/\"second\"", b"\"third\"", b"\"fourth\""];
        assert_eq!((&raw).into_iter().collect::<Vec<_>>(), expected);
        let mut iter = raw.iter();
        for line in expected {
            assert_eq!(iter.next(), Some(line));
        }
        assert_eq!(iter.next(), None);
        assert_eq!(iter.next(), None);
        assert_eq!(
            IfMatch::parse_header(&raw).unwrap(),
            IfMatch::Items(vec![
                EntityTag::strong("first".into()),
                EntityTag::weak("second".into()),
                EntityTag::strong("third".into()),
                EntityTag::strong("fourth".into()),
            ])
        );
    }

    /// STATEMENT: Empty groups can grow into a single parsed value before becoming multiline.
    ///
    /// HOW:
    /// - Start from an empty vector, append an entity tag as `Bytes`, then append another group.
    /// - Check single-value parsing succeeds only before the second line and empty iteration ends.
    #[test]
    fn empty_groups_grow_without_losing_single_value_semantics() {
        let mut raw = Raw::from(Vec::<Vec<u8>>::new());
        assert!(raw.iter().next().is_none());
        assert!(crate::header::ETag::parse_header(&raw).is_err());
        raw.push(Bytes::from_static(b"\"one\""));
        assert_eq!(
            crate::header::ETag::parse_header(&raw).unwrap().0,
            EntityTag::strong("one".into())
        );
        raw.push(vec![b"\"two\"".to_vec()]);
        assert!(crate::header::ETag::parse_header(&raw).is_err());
        assert_eq!(
            raw.iter().collect::<Vec<_>>(),
            vec![b"\"one\"".as_slice(), b"\"two\"".as_slice()]
        );
    }

    /// STATEMENT: Raw storage preserves literal-looking and arbitrary binary bytes exactly.
    ///
    /// HOW:
    /// - Store optimized literals, same-length non-literals, whitespace, and non-UTF-8 bytes.
    /// - Check borrowed, owned, and `Bytes` inputs retain their exact bytes through append and iteration.
    #[test]
    fn storage_preserves_literals_and_binary_values() {
        let values: &[&[u8]] = &[
            b"*",
            b"0",
            b"x",
            b"*/*",
            b"abc",
            b"gzip",
            b"br  ",
            b"close",
            b"other",
            b"chunked",
            b"unknown",
            b"keep-alive",
            b"0123456789",
            b" \t spaced \t ",
            b"\0\xff\x80",
        ];
        let mut combined = Raw::from(Vec::<Vec<u8>>::new());
        for &value in values {
            let borrowed = Raw::from(value);
            let owned = Raw::from(value.to_vec());
            let bytes = Raw::from(Bytes::copy_from_slice(value));
            assert_eq!(borrowed.one(), Some(value));
            assert_eq!(owned, borrowed);
            assert_eq!(bytes, borrowed);
            combined.push(borrowed);
        }
        assert_eq!(combined.iter().collect::<Vec<_>>(), values);
    }

    /// STATEMENT: Equality compares raw line boundaries and ordering, not concatenated text.
    ///
    /// HOW:
    /// - Build equivalent values by appending and by vector conversion.
    /// - Compare them with reversed, shorter, and joined values and with byte and string line slices.
    #[test]
    fn equality_preserves_line_boundaries_and_order() {
        let mut appended = Raw::from("first");
        appended.push("second");
        let grouped = Raw::from(vec![b"first".to_vec(), b"second".to_vec()]);
        assert_eq!(appended, grouped);
        assert_eq!(appended, appended.clone());
        assert!(appended == ["first", "second"][..]);
        assert!(appended == [String::from("first"), String::from("second")][..]);
        assert!(appended == [b"first".as_slice(), b"second".as_slice()][..]);
        assert!(appended == [b"first".to_vec(), b"second".to_vec()][..]);
        assert_ne!(
            appended,
            Raw::from(vec![b"second".to_vec(), b"first".to_vec()])
        );
        assert_ne!(appended, Raw::from("first"));
        assert!(appended != "firstsecond"[..]);
        assert_ne!(Raw::from(""), Raw::from(Vec::<Vec<u8>>::new()));
        assert_eq!(Raw::from(vec![b"first".to_vec()]), Raw::from("first"));
    }

    /// STATEMENT: Raw single-line equality and indexing retain entity-tag bytes without accepting extra header lines.
    ///
    /// HOW:
    /// - Build equivalent borrowed, owned, and grouped raw entity tags, then parse each and check its formatted bytes.
    /// - Check byte and string equality, reject out-of-range indexing, and require appending a second line to invalidate `ETag` parsing.
    #[test]
    fn single_line_storage_round_trips_and_rejects_extra_lines() {
        let serialized = "W/\"révision\"";
        let expected = EntityTag::weak("révision".into());
        for mut raw in [
            Raw::from(serialized),
            Raw::from(serialized.as_bytes().to_vec()),
            Raw::from(vec![serialized.as_bytes().to_vec()]),
        ] {
            let tag = crate::header::ETag::parse_header(&raw).unwrap();
            assert_eq!(tag.0, expected);
            assert_eq!(tag.to_string(), serialized);
            assert_eq!(&raw[0], serialized.as_bytes());
            assert_eq!(raw, Raw::from(serialized));
            assert!(std::panic::catch_unwind(|| &raw[1]).is_err());
            let mut iter = raw.iter();
            assert_eq!(iter.next(), Some(serialized.as_bytes()));
            assert_eq!(iter.next(), None);
            raw.push("\"another\"");
            assert!(crate::header::ETag::parse_header(&raw).is_err());
            assert!(raw != serialized[..]);
            assert!(raw != serialized.as_bytes()[..]);
        }
        let raw = Raw::from(serialized);
        assert!(raw == serialized[..]);
        assert!(raw == serialized.as_bytes()[..]);
        assert!(raw != b"different"[..]);
    }
}
