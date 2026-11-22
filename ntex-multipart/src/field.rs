use crate::MultipartError;
use crate::payload::{MAX_LINE_SIZE, PayloadBuffer, PayloadRef};
use crate::safety::Safety;
use futures::Stream;
use memchr::memmem;
use mime::Mime;
use ntex::http::error::PayloadError;
use ntex::http::{HeaderMap, header};
use ntex::util::Bytes;
use ntex_files::header::ContentDisposition;
use std::cell::RefCell;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};
use std::{cmp, fmt};

/// One part of a [`Multipart`](crate::Multipart) body, streamed as byte chunks.
///
/// Implements [`Stream`] with items of type `Result<Bytes, MultipartError>`.
/// Chunks contain body data, not part headers or boundary delimiters. A valid
/// part `Content-Length`, when present, determines how many body bytes are read;
/// otherwise the parser scans for a boundary followed by `--`, or by CRLF after
/// optional spaces and tabs (RFC 2046 transport padding).
///
/// Read and drop this field before requesting another part. Dropping it early
/// lets the parent drain the unread data; keeping it alive prevents the parent
/// from advancing even after EOF.
///
/// # Errors
///
/// Polling can return payload, incomplete-body, or boundary errors. A field that
/// outlives its parent [`Multipart`](crate::Multipart) returns
/// [`MultipartError::NotConsumed`] when polled.
///
/// # Panics
///
/// Polling after the field has returned `None` may panic. If repeated polling
/// after EOF is needed, wrap it with [`StreamExt::fuse`](futures::StreamExt::fuse).
pub struct Field {
    /// Field's Content-Type.
    content_type: Option<mime::Mime>,

    /// Field's Content-Disposition.
    content_disposition: Option<ContentDisposition>,

    /// Form field name.
    pub(crate) form_field_name: String,

    /// Field's header map.
    headers: HeaderMap,

    inner: Rc<RefCell<InnerField>>,
    safety: Safety,
}

impl Field {
    pub(crate) fn new(
        safety: Safety,
        headers: HeaderMap,
        content_type: Option<mime::Mime>,
        content_disposition: Option<ContentDisposition>,
        form_field_name: Option<String>,
        inner: Rc<RefCell<InnerField>>,
    ) -> Self {
        Field {
            content_type,
            content_disposition,
            form_field_name: form_field_name.unwrap_or_default(),
            headers,
            inner,
            safety,
        }
    }

    /// Returns the parsed headers of this part, not the request headers.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Returns the parsed part `Content-Type`, or `None` if absent or invalid.
    ///
    /// No default media type is inserted and no charset conversion is performed.
    pub fn content_type(&self) -> Option<&mime::Mime> {
        self.content_type.as_ref()
    }

    /// Returns the parsed `Content-Disposition` only for a valid `form-data` disposition.
    ///
    /// Missing, malformed, and other disposition types yield `None` for non-form
    /// multipart bodies; in `multipart/form-data` they prevent the field from being yielded.
    pub fn content_disposition(&self) -> Option<&ContentDisposition> {
        self.content_disposition.as_ref()
    }

    /// Returns the `name` parameter of a parsed `form-data` disposition, if present.
    ///
    /// A name is required for fields in a `multipart/form-data` body.
    pub fn name(&self) -> Option<&str> {
        self.content_disposition()?.get_name()
    }
}

impl Stream for Field {
    type Item = Result<Bytes, MultipartError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        if self.safety.current() {
            let mut inner = self.inner.borrow_mut();
            if let Some(mut payload) = inner.payload.as_ref().unwrap().get_mut(&self.safety) {
                payload.poll_stream(cx)?;
            }
            let res = inner.poll(&self.safety);
            if res.is_pending()
                && let Some(payload) = inner.payload.as_ref()
                && let Some(payload) = payload.get_mut(&self.safety)
                && payload.is_full()
            {
                // a delimiter line does not fit in the buffer
                return Poll::Ready(Some(Err(PayloadError::Overflow.into())));
            }
            res
        } else if !self.safety.is_clean() {
            Poll::Ready(Some(Err(MultipartError::NotConsumed)))
        } else {
            Poll::Pending
        }
    }
}

impl fmt::Debug for Field {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(ct) = &self.content_type {
            writeln!(f, "\nField: {}", ct)?;
        } else {
            writeln!(f, "\nField:")?;
        }
        writeln!(f, "  boundary: {}", self.inner.borrow().boundary)?;
        writeln!(f, "  headers:")?;
        for (key, val) in self.headers.iter() {
            writeln!(f, "    {:?}: {:?}", key, val)?;
        }
        Ok(())
    }
}

/// How a field without `Content-Length` scans its body for delimiter candidates.
///
/// Chosen per field from its declared content type. Both strategies accept the
/// same delimiters; they differ only in which bytes the scan stops at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BoundarySearch {
    /// Stop at every CR; cheapest for text with LF line endings.
    Cr,
    /// Stop at `-` followed by the first non-dash boundary byte, so incidental
    /// CR bytes in binary data are skipped.
    Marker {
        needle: [u8; 2],
        /// Number of delimiter dashes before the needle.
        offset: usize,
    },
}

impl BoundarySearch {
    pub(crate) fn new(boundary: &str, content_type: Option<&Mime>) -> Self {
        if let Some(ct) = content_type {
            let subtype = ct.subtype().as_str();
            // CSV and SQL often use CRLF lines, so they keep the marker search
            let text = !matches!(subtype, "csv" | "sql")
                && (ct.type_() == mime::TEXT
                    || matches!(subtype, "json" | "xml" | "yaml")
                    || ct
                        .suffix()
                        .is_some_and(|s| matches!(s.as_str(), "json" | "xml")));
            if text {
                return BoundarySearch::Cr;
            }
        }

        // the needle starts at the last dash before the first non-dash boundary
        // byte; a boundary of only dashes uses "--" right after the CRLF
        let boundary = boundary.as_bytes();
        match boundary.iter().position(|&b| b != b'-') {
            Some(idx) => BoundarySearch::Marker {
                needle: [b'-', boundary[idx]],
                offset: idx + 1,
            },
            None => BoundarySearch::Marker {
                needle: *b"--",
                offset: 0,
            },
        }
    }

    /// Returns the position of the first CR at or after `pos` that can start a
    /// delimiter, either a complete `\r\n--` prefix or a prefix cut by the
    /// buffer end. The caller still checks the `\r\n--` prefix.
    fn find(self, buf: &[u8], pos: usize) -> Option<usize> {
        match self {
            BoundarySearch::Cr => memchr::memchr(b'\r', &buf[pos..]).map(|i| pos + i),
            BoundarySearch::Marker { needle, offset } => {
                let mut from = pos;
                while let Some(i) = memmem::find(&buf[from..], &needle) {
                    let at = from + i;
                    // a delimiter has CRLF and `offset` dashes before the needle
                    if let Some(cr) = at.checked_sub(offset + 2)
                        && cr >= pos
                        && buf[cr..cr + 2] == *b"\r\n"
                        && buf[cr + 2..at].iter().all(|&b| b == b'-')
                    {
                        return Some(cr);
                    }
                    from = at + 1;
                }
                // the needle of a delimiter cut by the buffer end is incomplete,
                // so look for its CR in the bytes that cannot hold a whole needle
                let tail = buf.len().saturating_sub(offset + 3).max(pos);
                memchr::memchr(b'\r', &buf[tail..]).map(|i| tail + i)
            }
        }
    }
}

pub(crate) struct InnerField {
    payload: Option<PayloadRef>,
    boundary: String,
    search: BoundarySearch,
    eof: bool,
    length: Option<u64>,
}

impl InnerField {
    pub(crate) fn new(
        payload: PayloadRef,
        boundary: String,
        search: BoundarySearch,
        headers: &HeaderMap,
    ) -> Result<InnerField, PayloadError> {
        let len = if let Some(len) = headers.get(&header::CONTENT_LENGTH) {
            if let Ok(s) = len.to_str() {
                if let Ok(len) = s.parse::<u64>() {
                    Some(len)
                } else {
                    return Err(PayloadError::Incomplete(None));
                }
            } else {
                return Err(PayloadError::Incomplete(None));
            }
        } else {
            None
        };

        Ok(InnerField {
            boundary,
            search,
            payload: Some(payload),
            eof: false,
            length: len,
        })
    }

    /// Reads body part content chunk of the specified size.
    /// The body part must has `Content-Length` header with proper value.
    pub(crate) fn read_len(
        payload: &mut PayloadBuffer,
        size: &mut u64,
    ) -> Poll<Option<Result<Bytes, MultipartError>>> {
        if *size == 0 {
            Poll::Ready(None)
        } else {
            match payload.read_max(*size)? {
                Some(mut chunk) => {
                    let len = cmp::min(chunk.len() as u64, *size);
                    *size -= len;
                    let ch = chunk.split_to(len as usize);
                    if !chunk.is_empty() {
                        payload.unprocessed(chunk);
                    }
                    Poll::Ready(Some(Ok(ch)))
                }
                None => {
                    if payload.eof && (*size != 0) {
                        Poll::Ready(Some(Err(MultipartError::Incomplete)))
                    } else {
                        Poll::Pending
                    }
                }
            }
        }
    }

    /// Reads content chunk of body part with unknown length.
    /// The `Content-Length` header for body part is not necessary.
    pub(crate) fn read_stream(
        payload: &mut PayloadBuffer,
        boundary: &str,
        search: BoundarySearch,
    ) -> Poll<Option<Result<Bytes, MultipartError>>> {
        let len = payload.buf.len();
        if len == 0 {
            return if payload.eof {
                Poll::Ready(Some(Err(MultipartError::Incomplete)))
            } else {
                Poll::Pending
            };
        }

        // check boundary, the delimiter is always CRLF followed by "--" (RFC 2046)
        if len >= 4 && &payload.buf[..4] == b"\r\n--" {
            let b_size = boundary.len() + 4;
            // the boundary must be followed by "--", or by CRLF after optional
            // transport padding (spaces and tabs, RFC 2046 §5.1.1)
            if len < b_size + 2 {
                return if payload.eof {
                    Poll::Ready(Some(Err(MultipartError::Incomplete)))
                } else {
                    Poll::Pending
                };
            } else if &payload.buf[4..b_size] == boundary.as_bytes() {
                let rest = &payload.buf[b_size..];
                let pad = rest
                    .iter()
                    .take_while(|b| matches!(b, b' ' | b'\t'))
                    .count();
                match &rest[pad..] {
                    // found boundary
                    [b'\r', b'\n', ..] => return Poll::Ready(None),
                    [b'-', b'-', ..] if pad == 0 => return Poll::Ready(None),
                    // padding reaches the end of the buffer, wait for the line end;
                    // the delimiter line starts after the leading CRLF
                    [] | [b'\r'] => {
                        return if len - 2 >= MAX_LINE_SIZE {
                            Poll::Ready(Some(Err(MultipartError::Payload(PayloadError::Overflow))))
                        } else if payload.eof {
                            Poll::Ready(Some(Err(MultipartError::Incomplete)))
                        } else {
                            Poll::Pending
                        };
                    }
                    _ => {}
                }
            }
        }

        let mut pos = 0;
        loop {
            let Some(cur) = search.find(&payload.buf, pos) else {
                return Poll::Ready(Some(Ok(payload.buf.take())));
            };

            // check if we have enough data for boundary detection
            if cur + 4 > len {
                return if cur > 0 {
                    Poll::Ready(Some(Ok(payload.buf.split_to(cur))))
                } else if payload.eof {
                    Poll::Ready(Some(Err(MultipartError::Incomplete)))
                } else {
                    Poll::Pending
                };
            }

            // return data before a possible delimiter; one at the buffer start
            // was already rejected by the check above
            if cur != 0 && &payload.buf[cur..cur + 4] == b"\r\n--" {
                return Poll::Ready(Some(Ok(payload.buf.split_to(cur))));
            }
            pos = cur + 1;
        }
    }

    pub(crate) fn poll(&mut self, s: &Safety) -> Poll<Option<Result<Bytes, MultipartError>>> {
        if self.payload.is_none() {
            return Poll::Ready(None);
        }

        let result = if let Some(mut payload) = self.payload.as_ref().unwrap().get_mut(s) {
            if !self.eof {
                let res = if let Some(ref mut len) = self.length {
                    InnerField::read_len(&mut payload, len)
                } else {
                    InnerField::read_stream(&mut payload, &self.boundary, self.search)
                };

                match res {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Some(Ok(bytes))) => return Poll::Ready(Some(Ok(bytes))),
                    Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                    Poll::Ready(None) => self.eof = true,
                }
            }

            match payload.readline() {
                Ok(None) => Poll::Pending,
                Ok(Some(line)) => {
                    if line.as_ref() == b"\r\n" {
                        Poll::Ready(None)
                    } else {
                        // field data must end right before the boundary
                        Poll::Ready(Some(Err(MultipartError::Boundary)))
                    }
                }
                Err(e) => Poll::Ready(Some(Err(e))),
            }
        } else {
            Poll::Pending
        };

        if let Poll::Ready(None) = result {
            self.payload.take();
        }
        result
    }
}
