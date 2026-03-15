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

/// A single field in a multipart stream
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

    /// Get a map of headers
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// Get the content type of the field
    pub fn content_type(&self) -> Option<&mime::Mime> {
        self.content_type.as_ref()
    }

    /// Returns this field's parsed Content-Disposition header, if set.
    pub fn content_disposition(&self) -> Option<&ContentDisposition> {
        self.content_disposition.as_ref()
    }

    /// Returns the field's name, if set.
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

        Ok(InnerField { boundary, payload: Some(payload), eof: false, length: len })
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

        // check boundary
        if len > 4 && payload.buf[0] == b'\r' {
            let b_len = if &payload.buf[..2] == b"\r\n" && &payload.buf[2..4] == b"--" {
                Some(4)
            } else if &payload.buf[1..3] == b"--" {
                Some(3)
            } else {
                None
            };

            if let Some(b_len) = b_len {
                let b_size = boundary.len() + b_len;
                if len < b_size {
                    return Poll::Pending;
                } else if &payload.buf[b_len..b_size] == boundary.as_bytes() {
                    // found boundary
                    return Poll::Ready(None);
                }
            }
        }

        loop {
            return if let Some(idx) = twoway::find_bytes(&payload.buf[pos..], b"\r") {
                let cur = pos + idx;

                // check if we have enough data for boundary detection
                if cur + 4 > len {
                    if cur > 0 {
                        Poll::Ready(Some(Ok(payload.buf.split_to(cur))))
                    } else {
                        Poll::Pending
                    }
                } else {
                    // check boundary
                    if (&payload.buf[cur..cur + 2] == b"\r\n"
                        && &payload.buf[cur + 2..cur + 4] == b"--")
                        || (&payload.buf[cur..=cur] == b"\r"
                            && &payload.buf[cur + 1..cur + 3] == b"--")
                    {
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
                    if line.as_ref() != b"\r\n" {
                        log::warn!(
                            "multipart field did not read all the data or it is malformed"
                        );
                    }
                    Poll::Ready(None)
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
