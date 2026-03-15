//! Multipart payload support

use crate::Field;
use crate::error::MultipartError;
use crate::field::InnerField;
use crate::payload::{PayloadBuffer, PayloadRef};
use crate::safety::Safety;
use futures::stream::Stream;
use mime::Mime;
use ntex::http::error::{DecodeError, PayloadError};
use ntex::http::header::{self, HeaderMap, HeaderName, HeaderValue};
use ntex::util::Bytes;
use ntex_files::header::DispositionType;
use ntex_files::header::{ContentDisposition, Header};
use std::cell::RefCell;
use std::task::{Context, Poll};
use std::{convert::TryFrom, pin::Pin, rc::Rc};

const MAX_HEADERS: usize = 32;

/// The server-side implementation of `multipart/form-data` requests.
///
/// This will parse the incoming stream into `MultipartItem` instances via its
/// Stream implementation.
/// `MultipartItem::Field` contains multipart field. `MultipartItem::Multipart`
/// is used for nested multipart streams.
pub struct Multipart {
    safety: Safety,
    error: Option<MultipartError>,
    inner: Option<Rc<RefCell<InnerMultipart>>>,
}

enum InnerMultipartItem {
    None,
    Field(Rc<RefCell<InnerField>>),
}

#[derive(PartialEq, Debug)]
enum InnerState {
    /// Stream eof
    Eof,
    /// Skip data until first boundary
    FirstBoundary,
    /// Reading boundary
    Boundary,
    /// Reading Headers,
    Headers,
}

struct InnerMultipart {
    payload: PayloadRef,
    content_type: Mime,
    boundary: String,
    state: InnerState,
    item: InnerMultipartItem,
}

impl Multipart {
    /// Create multipart instance for boundary.
    pub fn new<S>(headers: &HeaderMap, stream: S) -> Multipart
    where
        S: Stream<Item = Result<Bytes, PayloadError>> + Unpin + 'static,
    {
        match Self::boundary(headers) {
            Ok((ct, boundary)) => Multipart {
                error: None,
                safety: Safety::new(),
                inner: Some(Rc::new(RefCell::new(InnerMultipart {
                    boundary,
                    content_type: ct,
                    payload: PayloadRef::new(PayloadBuffer::new(Box::new(stream))),
                    state: InnerState::FirstBoundary,
                    item: InnerMultipartItem::None,
                }))),
            },
            Err(err) => Multipart { error: Some(err), safety: Safety::new(), inner: None },
        }
    }

    /// Extract boundary info from headers.
    pub(crate) fn boundary(headers: &HeaderMap) -> Result<(Mime, String), MultipartError> {
        if let Some(content_type) = headers.get(&header::CONTENT_TYPE) {
            if let Ok(content_type) = content_type.to_str() {
                if let Ok(ct) = content_type.parse::<Mime>() {
                    if ct.type_() == mime::MULTIPART {
                        if let Some(boundary) = ct.get_param(mime::BOUNDARY) {
                            Ok((ct.clone(), boundary.as_str().to_owned()))
                        } else {
                            Err(MultipartError::Boundary)
                        }
                    } else {
                        Err(MultipartError::IncompatibleContentType)
                    }
                } else {
                    Err(MultipartError::ParseContentType)
                }
            } else {
                Err(MultipartError::ParseContentType)
            }
        } else {
            Err(MultipartError::NoContentType)
        }
    }

    /// Return requests parsed Content-Type or raise the stored error.
    pub(crate) fn content_type(&mut self) -> Result<Mime, MultipartError> {
        if let Some(err) = self.error.take() {
            Err(err)
        } else {
            Ok(self.inner.as_ref().unwrap().borrow().content_type.clone())
        }
    }
}

impl Stream for Multipart {
    type Item = Result<Field, MultipartError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        if let Some(err) = self.error.take() {
            Poll::Ready(Some(Err(err)))
        } else if self.safety.current() {
            let this = self.get_mut();
            let mut inner = this.inner.as_mut().unwrap().borrow_mut();
            if let Some(mut payload) = inner.payload.get_mut(&this.safety) {
                payload.poll_stream(cx)?;
            }
            inner.poll(&this.safety, cx)
        } else if !self.safety.is_clean() {
            Poll::Ready(Some(Err(MultipartError::NotConsumed)))
        } else {
            Poll::Pending
        }
    }
}

impl InnerMultipart {
    fn read_headers(payload: &mut PayloadBuffer) -> Result<Option<HeaderMap>, MultipartError> {
        match payload.read_until(b"\r\n\r\n")? {
            None => {
                if payload.eof {
                    Err(MultipartError::Incomplete)
                } else {
                    Ok(None)
                }
            }
            Some(bytes) => {
                let mut hdrs = [httparse::EMPTY_HEADER; MAX_HEADERS];
                match httparse::parse_headers(&bytes, &mut hdrs) {
                    Ok(httparse::Status::Complete((_, hdrs))) => {
                        // convert headers
                        let mut headers = HeaderMap::with_capacity(hdrs.len());
                        for h in hdrs {
                            if let Ok(name) = HeaderName::try_from(h.name) {
                                if let Ok(value) = HeaderValue::try_from(h.value) {
                                    headers.append(name, value);
                                } else {
                                    return Err(DecodeError::Header.into());
                                }
                            } else {
                                return Err(DecodeError::Header.into());
                            }
                        }
                        Ok(Some(headers))
                    }
                    Ok(httparse::Status::Partial) => Err(DecodeError::Header.into()),
                    Err(err) => Err(DecodeError::from(err).into()),
                }
            }
        }
    }

    fn read_boundary(
        payload: &mut PayloadBuffer,
        boundary: &str,
    ) -> Result<Option<bool>, MultipartError> {
        // TODO: need to read epilogue
        match payload.readline_or_eof()? {
            None => {
                if payload.eof {
                    Ok(Some(true))
                } else {
                    Ok(None)
                }
            }
            Some(chunk) => {
                if chunk.len() < boundary.len() + 4
                    || &chunk[..2] != b"--"
                    || &chunk[2..boundary.len() + 2] != boundary.as_bytes()
                {
                    Err(MultipartError::Boundary)
                } else if &chunk[boundary.len() + 2..] == b"\r\n" {
                    Ok(Some(false))
                } else if &chunk[boundary.len() + 2..boundary.len() + 4] == b"--"
                    && (chunk.len() == boundary.len() + 4
                        || &chunk[boundary.len() + 4..] == b"\r\n")
                {
                    Ok(Some(true))
                } else {
                    Err(MultipartError::Boundary)
                }
            }
        }
    }

    fn skip_until_boundary(
        payload: &mut PayloadBuffer,
        boundary: &str,
    ) -> Result<Option<bool>, MultipartError> {
        let mut eof = false;
        loop {
            match payload.readline()? {
                Some(chunk) => {
                    if chunk.is_empty() {
                        return Err(MultipartError::Boundary);
                    }
                    if chunk.len() < boundary.len() {
                        continue;
                    }
                    if &chunk[..2] == b"--" && &chunk[2..chunk.len() - 2] == boundary.as_bytes()
                    {
                        break;
                    } else {
                        if chunk.len() < boundary.len() + 2 {
                            continue;
                        }
                        let b: &[u8] = boundary.as_ref();
                        if &chunk[..boundary.len()] == b
                            && &chunk[boundary.len()..boundary.len() + 2] == b"--"
                        {
                            eof = true;
                            break;
                        }
                    }
                }
                None => {
                    return if payload.eof {
                        Err(MultipartError::Incomplete)
                    } else {
                        Ok(None)
                    };
                }
            }
        }
        Ok(Some(eof))
    }

    fn poll(
        &mut self,
        safety: &Safety,
        cx: &mut Context,
    ) -> Poll<Option<Result<Field, MultipartError>>> {
        if self.state == InnerState::Eof {
            Poll::Ready(None)
        } else {
            // release field
            loop {
                // Nested multipart streams of fields has to be consumed
                // before switching to next
                if safety.current() {
                    let stop = match self.item {
                        InnerMultipartItem::Field(ref mut field) => {
                            match field.borrow_mut().poll(safety) {
                                Poll::Pending => return Poll::Pending,
                                Poll::Ready(Some(Ok(_))) => continue,
                                Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
                                Poll::Ready(None) => true,
                            }
                        }
                        InnerMultipartItem::None => false,
                    };
                    if stop {
                        self.item = InnerMultipartItem::None;
                    }
                    if let InnerMultipartItem::None = self.item {
                        break;
                    }
                }
            }

            let headers = if let Some(mut payload) = self.payload.get_mut(safety) {
                match self.state {
                    // read until first boundary
                    InnerState::FirstBoundary => {
                        match InnerMultipart::skip_until_boundary(&mut payload, &self.boundary)?
                        {
                            Some(eof) => {
                                if eof {
                                    self.state = InnerState::Eof;
                                    return Poll::Ready(None);
                                } else {
                                    self.state = InnerState::Headers;
                                }
                            }
                            None => return Poll::Pending,
                        }
                    }
                    // read boundary
                    InnerState::Boundary => {
                        match InnerMultipart::read_boundary(&mut payload, &self.boundary)? {
                            None => return Poll::Pending,
                            Some(eof) => {
                                if eof {
                                    self.state = InnerState::Eof;
                                    return Poll::Ready(None);
                                } else {
                                    self.state = InnerState::Headers;
                                }
                            }
                        }
                    }
                    _ => (),
                }

                // read field headers for next field
                if self.state == InnerState::Headers {
                    if let Some(headers) = InnerMultipart::read_headers(&mut payload)? {
                        self.state = InnerState::Boundary;
                        headers
                    } else {
                        return Poll::Pending;
                    }
                } else {
                    unreachable!()
                }
            } else {
                log::debug!("NotReady: field is in flight");
                return Poll::Pending;
            };

            let field_content_disposition = if let Some(hv) =
                headers.get(&header::CONTENT_DISPOSITION)
                && let Ok(cd) = ContentDisposition::parse_header(
                    &ntex_files::header::Raw::from(hv.as_bytes()),
                )
                && cd.disposition == DispositionType::FormData
            {
                Some(cd)
            } else {
                None
            };

            let form_field_name = if self.content_type.subtype() == mime::FORM_DATA {
                let Some(cd) = &field_content_disposition else {
                    return Poll::Ready(Some(Err(MultipartError::ContentDispositionMissing)));
                };

                let Some(field_name) = cd.get_name() else {
                    return Poll::Ready(Some(Err(
                        MultipartError::ContentDispositionNameMissing,
                    )));
                };

                Some(field_name.to_owned())
            } else {
                None
            };

            let field_content_type: Option<Mime> = if let Some(content_type) =
                headers.get(&header::CONTENT_TYPE)
                && let Ok(content_type) = content_type.to_str()
                && let Ok(ct) = content_type.parse::<Mime>()
            {
                Some(ct)
            } else {
                None
            };

            self.state = InnerState::Boundary;

            // nested multipart stream is not supported
            if let Some(mime) = &field_content_type
                && mime.type_() == mime::MULTIPART
            {
                return Poll::Ready(Some(Err(MultipartError::Nested)));
            }

            let field = Rc::new(RefCell::new(InnerField::new(
                self.payload.clone(),
                self.boundary.clone(),
                &headers,
            )?));
            self.item = InnerMultipartItem::Field(Rc::clone(&field));

            Poll::Ready(Some(Ok(Field::new(
                safety.clone(cx),
                headers,
                field_content_type,
                field_content_disposition,
                form_field_name,
                field,
            ))))
        }
    }
}

impl Drop for InnerMultipart {
    fn drop(&mut self) {
        // InnerMultipartItem::Field has to be dropped first because of Safety.
        self.item = InnerMultipartItem::None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Field;
    use futures::{StreamExt as _, stream};
    use futures_test::stream::StreamTestExt as _;
    use ntex::util::BytesMut;
    use ntex::{channel::mpsc, util::Bytes};

    #[ntex::test]
    async fn test_boundary() {
        let headers = HeaderMap::new();
        match Multipart::boundary(&headers) {
            Err(MultipartError::NoContentType) => (),
            _ => unreachable!("should not happen"),
        }

        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("test"));

        match Multipart::boundary(&headers) {
            Err(MultipartError::ParseContentType) => (),
            _ => unreachable!("should not happen"),
        }

        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("multipart/mixed"));
        match Multipart::boundary(&headers) {
            Err(MultipartError::Boundary) => (),
            _ => unreachable!("should not happen"),
        }

        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(
                "multipart/mixed; boundary=\"5c02368e880e436dab70ed54e1c58209\"",
            ),
        );

        assert_eq!(
            Multipart::boundary(&headers).unwrap().1,
            "5c02368e880e436dab70ed54e1c58209"
        );
    }

    fn create_stream() -> (
        mpsc::Sender<Result<Bytes, PayloadError>>,
        impl Stream<Item = Result<Bytes, PayloadError>>,
    ) {
        let (tx, rx) = mpsc::channel();

        (tx, rx.map(|res| res.map_err(|_| panic!())))
    }

    fn create_simple_request_with_header() -> (Bytes, HeaderMap) {
        let bytes = Bytes::from(
            "testasdadsad\r\n\
             --abbc761f78ff4d7cb7573b5a23f96ef0\r\n\
             Content-Disposition: form-data; name=\"file\"; filename=\"fn.txt\"\r\n\
             Content-Type: text/plain; charset=utf-8\r\nContent-Length: 4\r\n\r\n\
             test\r\n\
             --abbc761f78ff4d7cb7573b5a23f96ef0\r\n\
             Content-Type: text/plain; charset=utf-8\r\nContent-Length: 4\r\n\r\n\
             data\r\n\
             --abbc761f78ff4d7cb7573b5a23f96ef0--\r\n",
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(
                "multipart/mixed; boundary=\"abbc761f78ff4d7cb7573b5a23f96ef0\"",
            ),
        );
        (bytes, headers)
    }

    #[ntex::test]
    async fn test_multipart_no_end_crlf() {
        let (sender, payload) = create_stream();
        let (mut bytes, headers) = create_simple_request_with_header();
        let bytes_stripped = bytes.split_to(bytes.len()); // strip crlf

        sender.send(Ok(bytes_stripped)).unwrap();
        drop(sender); // eof

        let mut multipart = Multipart::new(&headers, payload);

        match multipart.next().await.unwrap() {
            Ok(_) => (),
            _ => unreachable!(),
        }

        match multipart.next().await.unwrap() {
            Ok(_) => (),
            _ => unreachable!(),
        }

        match multipart.next().await {
            None => (),
            _ => unreachable!(),
        }
    }

    #[ntex::test]
    async fn test_multipart() {
        let (sender, payload) = create_stream();
        let (bytes, headers) = create_simple_request_with_header();

        sender.send(Ok(bytes)).unwrap();

        let mut multipart = Multipart::new(&headers, payload);
        match multipart.next().await {
            Some(Ok(mut field)) => {
                assert_eq!(field.content_type().unwrap().type_(), mime::TEXT);
                assert_eq!(field.content_type().unwrap().subtype(), mime::PLAIN);

                match field.next().await.unwrap() {
                    Ok(chunk) => assert_eq!(chunk, "test"),
                    _ => unreachable!(),
                }
                match field.next().await {
                    None => (),
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }

        match multipart.next().await.unwrap() {
            Ok(mut field) => {
                assert_eq!(field.content_type().unwrap().type_(), mime::TEXT);
                assert_eq!(field.content_type().unwrap().subtype(), mime::PLAIN);

                match field.next().await {
                    Some(Ok(chunk)) => assert_eq!(chunk, "data"),
                    _ => unreachable!(),
                }
                match field.next().await {
                    None => (),
                    _ => unreachable!(),
                }
            }
            _ => unreachable!(),
        }

        match multipart.next().await {
            None => (),
            _ => unreachable!(),
        }
    }

    // Loops, collecting all bytes until end-of-field
    async fn get_whole_field(field: &mut Field) -> BytesMut {
        let mut b = BytesMut::new();
        loop {
            match field.next().await {
                Some(Ok(chunk)) => b.extend_from_slice(&chunk),
                None => return b,
                _ => unreachable!(),
            }
        }
    }

    #[ntex::test]
    async fn test_stream() {
        let (bytes, headers) = create_simple_request_with_header();
        let payload = stream::iter(bytes)
            .map(|byte| Ok(Bytes::copy_from_slice(&[byte])))
            .interleave_pending();

        let mut multipart = Multipart::new(&headers, payload);
        match multipart.next().await.unwrap() {
            Ok(mut field) => {
                assert_eq!(field.content_type().unwrap().type_(), mime::TEXT);
                assert_eq!(field.content_type().unwrap().subtype(), mime::PLAIN);

                assert_eq!(get_whole_field(&mut field).await, "test");
            }
            _ => unreachable!(),
        }

        match multipart.next().await {
            Some(Ok(mut field)) => {
                assert_eq!(field.content_type().unwrap().type_(), mime::TEXT);
                assert_eq!(field.content_type().unwrap().subtype(), mime::PLAIN);

                assert_eq!(get_whole_field(&mut field).await, "data");
            }
            _ => unreachable!(),
        }

        match multipart.next().await {
            None => (),
            _ => unreachable!(),
        }
    }
}
