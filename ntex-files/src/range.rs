/// HTTP Range header representation.
#[derive(Debug, Clone, Copy)]
pub struct HttpRange {
    pub start: u64,
    pub length: u64,
}

static PREFIX: &str = "bytes=";
const PREFIX_LEN: usize = 6;

impl HttpRange {
    /// Parses Range HTTP header string as per RFC 2616.
    ///
    /// `header` is HTTP Range header (e.g. `bytes=bytes=0-9`).
    /// `size` is full size of response (file).
    pub fn parse(header: &str, size: u64) -> Result<Vec<HttpRange>, ()> {
        if header.is_empty() {
            return Ok(Vec::new());
        }
        if !header
            .get(..PREFIX_LEN)
            .is_some_and(|unit| unit.eq_ignore_ascii_case(PREFIX))
        {
            return Err(());
        }

        let mut no_overlap = false;

        let all_ranges: Vec<Option<HttpRange>> = header[PREFIX_LEN..]
            .split(',')
            .map(|x| x.trim())
            .filter(|x| !x.is_empty())
            .map(|ra| {
                let mut start_end_iter = ra.split('-');

                let start_str = start_end_iter.next().ok_or(())?.trim();
                let end_str = start_end_iter.next().ok_or(())?.trim();

                if start_str.is_empty() {
                    // If no start is specified, end specifies the
                    // range start relative to the end of the file.
                    let length = parse_pos(end_str)?;

                    if length == 0 {
                        // A zero-length suffix range selects no bytes.
                        no_overlap = true;
                        return Ok(None);
                    }
                    let length = length.min(size);

                    Ok(Some(HttpRange {
                        start: size - length,
                        length,
                    }))
                } else {
                    let start = parse_pos(start_str)?;

                    if start >= size {
                        no_overlap = true;
                        return Ok(None);
                    }

                    let length = if end_str.is_empty() {
                        // If no end is specified, range extends to end of the file.
                        size - start
                    } else {
                        let end = parse_pos(end_str)?;

                        if start > end {
                            return Err(());
                        }

                        end.min(size - 1) - start + 1
                    };

                    Ok(Some(HttpRange { start, length }))
                }
            })
            .collect::<Result<_, _>>()?;

        let ranges: Vec<HttpRange> = all_ranges.into_iter().flatten().collect();

        if no_overlap && ranges.is_empty() {
            return Err(());
        }

        Ok(ranges)
    }
}

/// Parses a byte position, a value too large for `u64` saturates
/// since it lies past the end of any file.
fn parse_pos(s: &str) -> Result<u64, ()> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    Ok(s.parse().unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct T(&'static str, u64, Vec<HttpRange>);

    /// STATEMENT: `HttpRange::parse` selects the bytes requested by a `Range` header.
    ///
    /// HOW:
    /// - Parse a table of headers against file sizes, including positions too large for `u64`.
    /// - Check that invalid or unsatisfiable headers fail and others return the expected ranges.
    #[test]
    fn test_parse() {
        let tests = vec![
            T("", 0, vec![]),
            T("", 1000, vec![]),
            T("foo", 0, vec![]),
            T("bytes=", 0, vec![]),
            T("bytes=7", 10, vec![]),
            T("bytes= 7 ", 10, vec![]),
            T("bytes=1-", 0, vec![]),
            T("bytes=5-4", 10, vec![]),
            T("bytes=0-2,5-4", 10, vec![]),
            T("bytes=2-5,4-3", 10, vec![]),
            T("bytes=--5,4--3", 10, vec![]),
            T("bytes=A-", 10, vec![]),
            T("bytes=A- ", 10, vec![]),
            T("bytes=A-Z", 10, vec![]),
            T("bytes= -Z", 10, vec![]),
            T("bytes=5-Z", 10, vec![]),
            T("bytes=Ran-dom, garbage", 10, vec![]),
            T("bytes=0x01-0x02", 10, vec![]),
            T("bytes=         ", 10, vec![]),
            T("bytes= , , ,   ", 10, vec![]),
            T("bytes=-0", 10, vec![]),
            T("bytes=+1-2", 10, vec![]),
            T("bytes=99999999999999999999-", 10, vec![]),
            T(
                "bytes=0-99999999999999999999",
                10,
                vec![HttpRange {
                    start: 0,
                    length: 10,
                }],
            ),
            T(
                "bytes=-99999999999999999999",
                10,
                vec![HttpRange {
                    start: 0,
                    length: 10,
                }],
            ),
            T(
                "bytes=-0,2-3",
                10,
                vec![HttpRange {
                    start: 2,
                    length: 2,
                }],
            ),
            T(
                "bytes=0-9",
                10,
                vec![HttpRange {
                    start: 0,
                    length: 10,
                }],
            ),
            T(
                "Bytes=0-9",
                10,
                vec![HttpRange {
                    start: 0,
                    length: 10,
                }],
            ),
            T(
                "bytes=0-",
                10,
                vec![HttpRange {
                    start: 0,
                    length: 10,
                }],
            ),
            T(
                "bytes=5-",
                10,
                vec![HttpRange {
                    start: 5,
                    length: 5,
                }],
            ),
            T(
                "bytes=0-20",
                10,
                vec![HttpRange {
                    start: 0,
                    length: 10,
                }],
            ),
            T(
                "bytes=15-,0-5",
                10,
                vec![HttpRange {
                    start: 0,
                    length: 6,
                }],
            ),
            T(
                "bytes=1-2,5-",
                10,
                vec![
                    HttpRange {
                        start: 1,
                        length: 2,
                    },
                    HttpRange {
                        start: 5,
                        length: 5,
                    },
                ],
            ),
            T(
                "bytes=-2 , 7-",
                11,
                vec![
                    HttpRange {
                        start: 9,
                        length: 2,
                    },
                    HttpRange {
                        start: 7,
                        length: 4,
                    },
                ],
            ),
            T(
                "bytes=0-0 ,2-2, 7-",
                11,
                vec![
                    HttpRange {
                        start: 0,
                        length: 1,
                    },
                    HttpRange {
                        start: 2,
                        length: 1,
                    },
                    HttpRange {
                        start: 7,
                        length: 4,
                    },
                ],
            ),
            T(
                "bytes=-5",
                10,
                vec![HttpRange {
                    start: 5,
                    length: 5,
                }],
            ),
            T(
                "bytes=-15",
                10,
                vec![HttpRange {
                    start: 0,
                    length: 10,
                }],
            ),
            T(
                "bytes=0-499",
                10000,
                vec![HttpRange {
                    start: 0,
                    length: 500,
                }],
            ),
            T(
                "bytes=500-999",
                10000,
                vec![HttpRange {
                    start: 500,
                    length: 500,
                }],
            ),
            T(
                "bytes=-500",
                10000,
                vec![HttpRange {
                    start: 9500,
                    length: 500,
                }],
            ),
            T(
                "bytes=9500-",
                10000,
                vec![HttpRange {
                    start: 9500,
                    length: 500,
                }],
            ),
            T(
                "bytes=0-0,-1",
                10000,
                vec![
                    HttpRange {
                        start: 0,
                        length: 1,
                    },
                    HttpRange {
                        start: 9999,
                        length: 1,
                    },
                ],
            ),
            T(
                "bytes=500-600,601-999",
                10000,
                vec![
                    HttpRange {
                        start: 500,
                        length: 101,
                    },
                    HttpRange {
                        start: 601,
                        length: 399,
                    },
                ],
            ),
            T(
                "bytes=500-700,601-999",
                10000,
                vec![
                    HttpRange {
                        start: 500,
                        length: 201,
                    },
                    HttpRange {
                        start: 601,
                        length: 399,
                    },
                ],
            ),
            // Match Apache laxity:
            T(
                "bytes=   1 -2   ,  4- 5, 7 - 8 , ,,",
                11,
                vec![
                    HttpRange {
                        start: 1,
                        length: 2,
                    },
                    HttpRange {
                        start: 4,
                        length: 2,
                    },
                    HttpRange {
                        start: 7,
                        length: 2,
                    },
                ],
            ),
        ];

        for t in tests {
            let header = t.0;
            let size = t.1;
            let expected = t.2;

            let got = match HttpRange::parse(header, size) {
                Ok(got) => got,
                Err(_) if expected.is_empty() => continue,
                Err(e) => panic!("parse({}, {}) returned error {:?}", header, size, e),
            };

            if got.len() != expected.len() {
                panic!(
                    "len(parseRange({}, {})) = {}, want {}",
                    header,
                    size,
                    got.len(),
                    expected.len()
                );
            }

            for i in 0..expected.len() {
                if got[i].start != expected[i].start {
                    panic!(
                        "parseRange({}, {})[{}].start = {}, want {}",
                        header, size, i, got[i].start, expected[i].start
                    )
                }
                if got[i].length != expected[i].length {
                    panic!(
                        "parseRange({}, {})[{}].length = {}, want {}",
                        header, size, i, got[i].length, expected[i].length
                    )
                }
            }
        }
    }
}
