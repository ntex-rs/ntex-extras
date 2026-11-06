use crate::MultipartError;
use crate::payload::{PayloadBuffer, PayloadRef};
use crate::safety::Safety;
use futures::Stream;
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
/// otherwise the parser scans for a boundary followed by CRLF or `--`.
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
            inner.poll(&self.safety)
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

pub(crate) struct InnerField {
    payload: Option<PayloadRef>,
    boundary: String,
    eof: bool,
    length: Option<u64>,
}

impl InnerField {
    pub(crate) fn new(
        payload: PayloadRef,
        boundary: String,
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
    ) -> Poll<Option<Result<Bytes, MultipartError>>> {
        let mut pos = 0;

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
            // the boundary must be followed by CRLF or by "--"
            if len < b_size + 2 {
                return if payload.eof {
                    Poll::Ready(Some(Err(MultipartError::Incomplete)))
                } else {
                    Poll::Pending
                };
            } else if &payload.buf[4..b_size] == boundary.as_bytes()
                && matches!(&payload.buf[b_size..b_size + 2], b"\r\n" | b"--")
            {
                // found boundary
                return Poll::Ready(None);
            }
        }

        loop {
            return if let Some(idx) = memchr::memchr(b'\r', &payload.buf[pos..]) {
                let cur = pos + idx;

                // check if we have enough data for boundary detection
                if cur + 4 > len {
                    if cur > 0 {
                        Poll::Ready(Some(Ok(payload.buf.split_to(cur))))
                    } else if payload.eof {
                        Poll::Ready(Some(Err(MultipartError::Incomplete)))
                    } else {
                        Poll::Pending
                    }
                } else {
                    // check boundary
                    if &payload.buf[cur..cur + 4] == b"\r\n--" {
                        if cur != 0 {
                            // return buffer
                            Poll::Ready(Some(Ok(payload.buf.split_to(cur))))
                        } else {
                            pos = cur + 1;
                            continue;
                        }
                    } else {
                        // not boundary
                        pos = cur + 1;
                        continue;
                    }
                }
            } else {
                Poll::Ready(Some(Ok(payload.buf.take())))
            };
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
                    InnerField::read_stream(&mut payload, &self.boundary)
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
