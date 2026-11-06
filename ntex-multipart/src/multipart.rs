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

/// Streaming parser for a `multipart/*` request body.
///
/// Implements [`Stream`] with items of type `Result<Field, MultipartError>`, in
/// wire order. Nested multipart fields are unsupported. For `multipart/form-data`,
/// each part requires a `Content-Disposition: form-data` header and a `name`.
/// Other multipart subtypes do not require these headers.
///
/// Consume and drop each [`Field`] before polling for the next. A live field keeps
/// this stream pending, even if fully read. Dropping an unread field causes its
/// remaining body to be drained on subsequent parent polls. If this parser is
/// dropped first, polling the surviving field returns [`MultipartError::NotConsumed`].
///
/// Part-header blocks and boundary/preamble lines are limited to 16 KiB including
/// delimiters; a part may have at most 32 headers. Field bodies have no aggregate
/// size limit here; use [`MultipartForm`](struct@crate::MultipartForm) for reader-managed limits.
/// In boundary-delimited bodies, a boundary prefix ends a field only when followed
/// by CRLF or `--`. A closing boundary does not require a trailing CRLF.
///
/// # Errors
///
/// Stream items report [`MultipartError`] for invalid request or part headers,
/// malformed boundaries, incomplete bodies, nested multipart fields, or payload
/// errors. Oversized lines/header blocks produce [`MultipartError::Payload`]
/// containing [`PayloadError::Overflow`], independent of chunking.
///
/// After an initial request-header error is returned, the stream ends.
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
    /// Creates a parser from the request headers and a stream of body chunks.
    ///
    /// The `Content-Type` must be a parseable `multipart/*` media type with a
    /// `boundary` parameter. Validation failures are stored, not returned here.
    ///
    /// The first stream item reports [`MultipartError::NoContentType`],
    /// [`MultipartError::ParseContentType`], [`MultipartError::IncompatibleContentType`],
    /// or [`MultipartError::Boundary`] if request-header validation fails.
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
            Err(err) => Multipart {
                error: Some(err),
                safety: Safety::new(),
                inner: None,
            },
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
        } else if self.inner.is_none() {
            // the content-type error has already been reported
            Poll::Ready(None)
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
        loop {
            match payload.readline_or_eof()? {
                Some(chunk) => {
                    let line = chunk.strip_suffix(b"\n").unwrap_or(&chunk);
                    let line = line.strip_suffix(b"\r").unwrap_or(line);
                    if let Some(rest) = line
                        .strip_prefix(b"--")
                        .and_then(|l| l.strip_prefix(boundary.as_bytes()))
                    {
                        if rest.is_empty() {
                            return Ok(Some(false));
                        } else if rest == b"--" {
                            return Ok(Some(true));
                        }
                    }
                    // unterminated last line at eof
                    if !chunk.ends_with(b"\n") {
                        return Err(MultipartError::Incomplete);
                    }
                }
                None => return Ok(None),
            }
        }
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
                        match InnerMultipart::skip_until_boundary(&mut payload, &self.boundary)? {
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
                && let Ok(cd) =
                    ContentDisposition::parse_header(&ntex_files::header::Raw::from(hv.as_bytes()))
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
                    return Poll::Ready(Some(Err(MultipartError::ContentDispositionNameMissing)));
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

    /// STATEMENT: Request boundary parsing rejects missing or malformed media types and missing boundaries.
    ///
    /// HOW:
    /// - Parse missing, invalid, and boundary-less headers, then a quoted multipart boundary.
    /// - Confirm the corresponding errors and the successfully extracted boundary value.
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
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("multipart/mixed"),
        );
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

    /// STATEMENT: Dropped unread fields are drained so a buffered multipart stream can reach its end.
    ///
    /// HOW:
    /// - Buffer two length-delimited fields and close the payload stream.
    /// - Drop each returned field unread and confirm both fields are yielded before end-of-stream.
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

    /// STATEMENT: Length-delimited multipart fields expose their media types and exact contents.
    ///
    /// HOW:
    /// - Submit two four-byte plain-text fields and read each field to completion.
    /// - Confirm their media types and data, followed by end-of-stream.
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

    /// STATEMENT: Length-delimited fields can be reconstructed from an intermittently pending byte-at-a-time stream.
    ///
    /// HOW:
    /// - Split a two-field request into individual bytes with pending polls between chunks.
    /// - Collect each field and confirm its media type, content, and the final stream termination.
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

    fn form_data_headers(boundary: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::try_from(format!("multipart/form-data; boundary={boundary}")).unwrap(),
        );
        headers
    }

    /// STATEMENT: Preamble lines shorter than the boundary delimiter are skipped without panicking.
    ///
    /// HOW:
    /// - Send a body for boundary `a` whose preamble contains `\n` and `--\n` lines.
    /// - Confirm the single field is returned with its data and the stream then ends.
    #[ntex::test]
    async fn test_short_preamble_lines() {
        let (sender, payload) = create_stream();
        sender
            .send(Ok(Bytes::from_static(
                b"\n--\n--a\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nv\r\n--a--\r\n",
            )))
            .unwrap();
        drop(sender);

        let mut multipart = Multipart::new(&form_data_headers("a"), payload);
        let mut field = multipart.next().await.unwrap().unwrap();
        assert_eq!(get_whole_field(&mut field).await, "v");
        drop(field);
        assert!(multipart.next().await.is_none());
    }

    /// STATEMENT: A boundary split right after its leading `\r\n--` is still detected.
    ///
    /// HOW:
    /// - Send a field followed by `\r\n--`, and read the first data chunk.
    /// - Send the rest of the closing boundary.
    /// - Confirm the field data excludes the delimiter and the stream then ends.
    #[ntex::test]
    async fn test_boundary_split_after_dashes() {
        let (sender, payload) = create_stream();
        sender
            .send(Ok(Bytes::from_static(
                b"--abc\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\ndata\r\n--",
            )))
            .unwrap();

        let mut multipart = Multipart::new(&form_data_headers("abc"), payload);
        let mut field = multipart.next().await.unwrap().unwrap();
        assert_eq!(field.next().await.unwrap().unwrap(), "data");

        sender.send(Ok(Bytes::from_static(b"abc--\r\n"))).unwrap();
        drop(sender);
        assert_eq!(get_whole_field(&mut field).await, "");
        drop(field);
        assert!(multipart.next().await.is_none());
    }

    /// STATEMENT: A body that ends with a lone `\r` inside a field reports `Incomplete`.
    ///
    /// HOW:
    /// - Send a field whose data ends with `\r`, then close the stream.
    /// - Confirm the data before `\r` is returned and the next read is `Incomplete`.
    #[ntex::test]
    async fn test_truncated_field_with_trailing_cr() {
        let (sender, payload) = create_stream();
        sender
            .send(Ok(Bytes::from_static(
                b"--abc\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\ndata\r",
            )))
            .unwrap();
        drop(sender);

        let mut multipart = Multipart::new(&form_data_headers("abc"), payload);
        let mut field = multipart.next().await.unwrap().unwrap();
        assert_eq!(field.next().await.unwrap().unwrap(), "data");
        assert!(matches!(
            field.next().await,
            Some(Err(MultipartError::Incomplete))
        ));
    }

    /// STATEMENT: Field headers without a terminator are rejected once they exceed `MAX_LINE_SIZE`.
    ///
    /// HOW:
    /// - Keep the stream open and send a boundary followed by an unterminated oversized header.
    /// - Confirm reading the field fails with `PayloadError::Overflow` instead of waiting for more data.
    #[ntex::test]
    async fn test_oversized_headers() {
        let (sender, payload) = create_stream();
        let mut body = b"--abc\r\nX-Big: ".to_vec();
        body.resize(body.len() + crate::payload::MAX_LINE_SIZE + 1, b'a');
        sender.send(Ok(Bytes::from(body))).unwrap();

        let mut multipart = Multipart::new(&form_data_headers("abc"), payload);
        assert!(matches!(
            multipart.next().await,
            Some(Err(MultipartError::Payload(PayloadError::Overflow)))
        ));
        drop(sender);
    }

    /// STATEMENT: Field data longer than its `Content-Length` is an error, not a silent truncation.
    ///
    /// HOW:
    /// - Send a `multipart/mixed` field declaring `Content-Length: 2` with data `test`.
    /// - Confirm the first two bytes are returned and the next read fails with `Boundary`.
    #[ntex::test]
    async fn test_field_longer_than_content_length() {
        let (sender, payload) = create_stream();
        sender
            .send(Ok(Bytes::from_static(
                b"--abc\r\nContent-Length: 2\r\n\r\ntest\r\n--abc--\r\n",
            )))
            .unwrap();
        drop(sender);

        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("multipart/mixed; boundary=abc"),
        );
        let mut multipart = Multipart::new(&headers, payload);
        let mut field = multipart.next().await.unwrap().unwrap();
        assert_eq!(field.next().await.unwrap().unwrap(), "te");
        assert!(matches!(
            field.next().await,
            Some(Err(MultipartError::Boundary))
        ));
    }

    fn multipart_body(body: impl Into<Bytes>) -> Multipart {
        Multipart::new(&form_data_headers("abc"), stream::iter([Ok(body.into())]))
    }

    /// STATEMENT: Invalid request media types are returned as stream errors before any field is yielded.
    ///
    /// HOW:
    /// - Construct streams with a nonmultipart type and a non-UTF-8 content-type header.
    /// - Confirm the first poll reports `IncompatibleContentType` and `ParseContentType`, respectively.
    #[ntex::test]
    async fn invalid_request_media_types_fail_on_poll() {
        for (value, expected) in [
            (
                b"text/plain".as_slice(),
                MultipartError::IncompatibleContentType,
            ),
            (b"\xff".as_slice(), MultipartError::ParseContentType),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_bytes(value).unwrap(),
            );
            let mut multipart = Multipart::new(&headers, stream::empty());
            let error = multipart.next().await.unwrap().err().unwrap();
            assert_eq!(
                std::mem::discriminant(&error),
                std::mem::discriminant(&expected)
            );
        }
    }

    /// STATEMENT: Malformed field headers and header counts exceeding `MAX_HEADERS` are rejected.
    ///
    /// HOW:
    /// - Submit an invalid header name, a control-character value, and too many individually valid headers.
    /// - Confirm reading the first field returns a header decoding error in every case.
    #[ntex::test]
    async fn malformed_field_headers_are_rejected() {
        let too_many = format!(
            "--abc\r\n{}\r\n",
            "X-Test: value\r\n".repeat(MAX_HEADERS + 1)
        );
        for body in [
            Bytes::from_static(b"--abc\r\nBad Header: value\r\n\r\n"),
            Bytes::from_static(b"--abc\r\nX-Test: \x01\r\n\r\n"),
            Bytes::from(too_many),
        ] {
            let mut multipart = multipart_body(body);
            assert!(matches!(
                multipart.next().await,
                Some(Err(MultipartError::Decode(_)))
            ));
        }
    }

    /// STATEMENT: Form-data fields require a valid form-data disposition with a name and reject nested multipart content.
    ///
    /// HOW:
    /// - Submit missing, malformed, attachment, and nameless dispositions plus a named nested multipart field.
    /// - Confirm each first field fails with the corresponding disposition or nesting error.
    #[ntex::test]
    async fn invalid_dispositions_and_nested_parts_are_rejected() {
        for (headers, expected) in [
            (
                "X-Test: value\r\n",
                MultipartError::ContentDispositionMissing,
            ),
            (
                "Content-Disposition: \r\n",
                MultipartError::ContentDispositionMissing,
            ),
            (
                "Content-Disposition: attachment; name=\"f\"\r\n",
                MultipartError::ContentDispositionMissing,
            ),
            (
                "Content-Disposition: form-data; filename=\"f.txt\"\r\n",
                MultipartError::ContentDispositionNameMissing,
            ),
            (
                "Content-Disposition: form-data; name=\"f\"\r\nContent-Type: multipart/mixed; boundary=inner\r\n",
                MultipartError::Nested,
            ),
        ] {
            let mut multipart =
                multipart_body(format!("--abc\r\n{headers}\r\ndata\r\n--abc--\r\n"));
            let error = multipart.next().await.unwrap().err().unwrap();
            assert_eq!(
                std::mem::discriminant(&error),
                std::mem::discriminant(&expected)
            );
        }
    }

    /// STATEMENT: Invalid numeric or non-UTF-8 field lengths fail before a field is yielded.
    ///
    /// HOW:
    /// - Submit named fields with nonnumeric and non-UTF-8 `Content-Length` values.
    /// - Confirm field creation reports `PayloadError::Incomplete` in both cases.
    #[ntex::test]
    async fn invalid_field_content_lengths_are_rejected() {
        for length in [b"invalid".as_slice(), b"\xff"] {
            let mut body =
                b"--abc\r\nContent-Disposition: form-data; name=\"f\"\r\nContent-Length: ".to_vec();
            body.extend_from_slice(length);
            body.extend_from_slice(b"\r\n\r\ndata\r\n--abc--\r\n");
            let mut multipart = multipart_body(body);
            assert!(matches!(
                multipart.next().await,
                Some(Err(MultipartError::Payload(PayloadError::Incomplete(_))))
            ));
        }
    }

    /// STATEMENT: Incomplete preambles and header blocks cannot yield a field after payload EOF.
    ///
    /// HOW:
    /// - Close streams before any boundary, midway through the first boundary, and before the header terminator.
    /// - Confirm each first field read fails with `Incomplete`.
    #[ntex::test]
    async fn truncated_preambles_and_headers_are_rejected() {
        for body in [
            b"preamble\r\n".as_slice(),
            b"--ab",
            b"--abc\r\nContent-Disposition: form-data; name=\"f\"\r\n",
        ] {
            let mut multipart = multipart_body(Bytes::copy_from_slice(body));
            assert!(matches!(
                multipart.next().await,
                Some(Err(MultipartError::Incomplete))
            ));
        }
    }

    /// STATEMENT: Field reads reject truncated bodies, whether they use boundary detection or a declared length.
    ///
    /// HOW:
    /// - Close streams with no data, data without a delimiter, a partial delimiter, and fewer bytes than declared.
    /// - Confirm any complete data chunk is preserved before the next read reports `Incomplete`.
    #[ntex::test]
    async fn truncated_field_bodies_are_rejected() {
        for (extra_header, tail) in [
            ("", ""),
            ("", "data"),
            ("", "data\r\n--ab"),
            ("Content-Length: 10\r\n", "data"),
        ] {
            let mut multipart = multipart_body(format!(
                "--abc\r\nContent-Disposition: form-data; name=\"f\"\r\n{extra_header}\r\n{tail}"
            ));
            let mut field = multipart.next().await.unwrap().unwrap();
            if !tail.is_empty() {
                assert_eq!(field.next().await.unwrap().unwrap(), "data");
            }
            assert!(matches!(
                field.next().await,
                Some(Err(MultipartError::Incomplete))
            ));
        }
    }

    /// STATEMENT: Boundary delimiters with wrong names or trailing garbage are rejected after length-delimited data.
    ///
    /// HOW:
    /// - Read a valid four-byte field followed by short, wrong, truncated, or garbage-suffixed delimiter lines.
    /// - Confirm field data is intact and advancing to the next field returns `Boundary`.
    #[ntex::test]
    async fn malformed_following_boundaries_are_rejected() {
        for closing in [
            "--\r\n",
            "--wrong\r\n",
            "--abc-extra\r\n",
            "--abc--garbage\r\n",
            "--ab",
        ] {
            let mut multipart = multipart_body(format!(
                "--abc\r\nContent-Disposition: form-data; name=\"f\"\r\nContent-Length: 4\r\n\r\ndata\r\n{closing}"
            ));
            let mut field = multipart.next().await.unwrap().unwrap();
            assert_eq!(get_whole_field(&mut field).await, "data");
            drop(field);
            assert!(matches!(
                multipart.next().await,
                Some(Err(MultipartError::Boundary))
            ));
        }
    }

    /// STATEMENT: Unknown-length fields preserve boundary-like data across fragmented payloads and permit a closing delimiter without trailing CRLF.
    ///
    /// HOW:
    /// - Stream a field byte-by-byte with pending polls, embedding carriage returns and nonmatching delimiter-like sequences.
    /// - Confirm the full body is preserved and the closing boundary without CRLF ends the multipart stream.
    #[ntex::test]
    async fn fragmented_boundary_like_data_is_preserved() {
        let data = "before\r\n--other\r\nmid\r--other\rXafter";
        let body =
            format!("--abc\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n{data}\r\n--abc--");
        let payload = stream::iter(body.into_bytes())
            .map(|byte| Ok(Bytes::copy_from_slice(&[byte])))
            .interleave_pending();
        let mut multipart = Multipart::new(&form_data_headers("abc"), payload);
        let mut field = multipart.next().await.unwrap().unwrap();
        assert_eq!(get_whole_field(&mut field).await, data);
        drop(field);
        assert!(multipart.next().await.is_none());
    }

    /// STATEMENT: A live field prevents advancing the parent stream, and dropping it drains unread data before yielding the next field.
    ///
    /// HOW:
    /// - Keep the first field alive and poll the parent, confirming it waits rather than skipping data.
    /// - Drop that field unread, read the second field, and confirm its content and stream termination.
    #[ntex::test]
    async fn live_fields_block_and_dropped_fields_are_drained() {
        let mut multipart = multipart_body(Bytes::from_static(
            b"--abc\r\nContent-Disposition: form-data; name=\"first\"\r\n\r\nunread\r\n--abc\r\nContent-Disposition: form-data; name=\"second\"\r\n\r\nread\r\n--abc--\r\n",
        ));
        let field = multipart.next().await.unwrap().unwrap();
        assert!(futures::poll!(multipart.next()).is_pending());
        drop(field);
        let mut field = multipart.next().await.unwrap().unwrap();
        assert_eq!(field.name(), Some("second"));
        assert_eq!(get_whole_field(&mut field).await, "read");
        drop(field);
        assert!(multipart.next().await.is_none());
    }

    /// STATEMENT: Errors in unread discarded fields are propagated when the parent stream advances.
    ///
    /// HOW:
    /// - Drop a field whose body is longer than its declared two-byte length without reading it.
    /// - Confirm advancing the parent returns `Boundary` instead of silently skipping malformed data.
    #[ntex::test]
    async fn discarded_field_errors_propagate() {
        let mut multipart = multipart_body(Bytes::from_static(
            b"--abc\r\nContent-Disposition: form-data; name=\"f\"\r\nContent-Length: 2\r\n\r\ntest\r\n--abc--\r\n",
        ));
        drop(multipart.next().await.unwrap().unwrap());
        assert!(matches!(
            multipart.next().await,
            Some(Err(MultipartError::Boundary))
        ));
    }

    /// STATEMENT: A payload error arriving after field creation is returned by the field reader.
    ///
    /// HOW:
    /// - Send only valid headers, obtain the field, then fail the payload stream with `Overflow`.
    /// - Confirm the field forwards `PayloadError::Overflow` instead of waiting or yielding data.
    #[ntex::test]
    async fn field_propagates_payload_stream_errors() {
        let (sender, payload) = mpsc::channel::<Result<Bytes, PayloadError>>();
        sender
            .send(Ok(Bytes::from_static(
                b"--abc\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n",
            )))
            .unwrap();
        let mut multipart = Multipart::new(&form_data_headers("abc"), payload);
        let mut field = multipart.next().await.unwrap().unwrap();
        sender.send(Err(PayloadError::Overflow)).unwrap();
        assert!(matches!(
            field.next().await,
            Some(Err(MultipartError::Payload(PayloadError::Overflow)))
        ));
    }

    /// STATEMENT: An empty length-delimited field does not consume bytes belonging to the following field.
    ///
    /// HOW:
    /// - Submit a zero-length field followed by a nonempty field.
    /// - Confirm the first field has no data and the second yields its full body before stream termination.
    #[ntex::test]
    async fn empty_length_delimited_fields_preserve_following_data() {
        let mut multipart = multipart_body(Bytes::from_static(
            b"--abc\r\nContent-Disposition: form-data; name=\"empty\"\r\nContent-Length: 0\r\n\r\n\r\n--abc\r\nContent-Disposition: form-data; name=\"next\"\r\n\r\ndata\r\n--abc--\r\n",
        ));
        let mut field = multipart.next().await.unwrap().unwrap();
        assert!(field.next().await.is_none());
        drop(field);
        let mut field = multipart.next().await.unwrap().unwrap();
        assert_eq!(get_whole_field(&mut field).await, "data");
        drop(field);
        assert!(multipart.next().await.is_none());
    }

    /// STATEMENT: The header-block size limit also applies when the oversized block has a complete terminator.
    ///
    /// HOW:
    /// - Submit a named field with a terminated header block exceeding `MAX_LINE_SIZE`.
    /// - Confirm the parser rejects it with `PayloadError::Overflow` before yielding a field.
    #[ntex::test]
    async fn terminated_oversized_headers_are_rejected() {
        let body = format!(
            "--abc\r\nContent-Disposition: form-data; name=\"f\"\r\nX-Big: {}\r\n\r\ndata\r\n--abc--\r\n",
            "a".repeat(crate::payload::MAX_LINE_SIZE + 1)
        );
        let mut multipart = multipart_body(body);
        assert!(matches!(
            multipart.next().await,
            Some(Err(MultipartError::Payload(PayloadError::Overflow)))
        ));
    }

    /// STATEMENT: A field outliving its parent reports `NotConsumed` instead of waiting forever.
    ///
    /// HOW:
    /// - Obtain a field, then drop its parent multipart stream while the field is still alive.
    /// - Poll the field once and confirm it returns `NotConsumed` rather than remaining pending.
    #[ntex::test]
    async fn fields_outliving_their_parent_report_not_consumed() {
        let mut multipart = multipart_body(Bytes::from_static(
            b"--abc\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\ndata\r\n--abc--\r\n",
        ));
        let mut field = multipart.next().await.unwrap().unwrap();
        drop(multipart);
        assert!(matches!(
            futures::poll!(field.next()),
            Poll::Ready(Some(Err(MultipartError::NotConsumed)))
        ));
    }

    /// STATEMENT: A carriage return followed by `--boundary` without a line feed is field data, not a delimiter.
    ///
    /// HOW:
    /// - Submit an unknown-length field whose data contains `\r--abc\r\n`, terminated by a real CRLF delimiter.
    /// - Confirm the field yields that data unchanged and the multipart stream then ends.
    /// - Submit a field terminated only by `\r--abc--` and confirm it reads as data and ends with `Incomplete`.
    #[ntex::test]
    async fn carriage_return_only_delimiters_are_field_data() {
        let mut multipart = multipart_body(Bytes::from_static(
            b"--abc\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\nx\r--abc\r\ny\r\n--abc--\r\n",
        ));
        let mut field = multipart.next().await.unwrap().unwrap();
        let mut data = Vec::new();
        while let Some(chunk) = field.next().await {
            data.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(data, b"x\r--abc\r\ny");
        drop(field);
        assert!(multipart.next().await.is_none());

        let mut multipart = multipart_body(Bytes::from_static(
            b"--abc\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\ndata\r--abc--\r\n",
        ));
        let mut field = multipart.next().await.unwrap().unwrap();
        let mut data = Vec::new();
        let err = loop {
            match field.next().await.unwrap() {
                Ok(chunk) => data.extend_from_slice(&chunk),
                Err(err) => break err,
            }
        };
        assert_eq!(data, b"data\r--abc--");
        assert!(matches!(err, MultipartError::Incomplete));
    }

    /// STATEMENT: Boundary-looking preamble lines are skipped until an exact closing delimiter ends an empty multipart body.
    ///
    /// HOW:
    /// - Stream preambles containing wrong boundaries and matching prefixes, followed by an exact closing delimiter.
    /// - Confirm no field is produced and subsequent polls remain at EOF for CRLF and LF preamble lines.
    #[ntex::test]
    async fn empty_bodies_skip_boundary_lookalikes_and_end() {
        for body in [
            "--abc--\r\n",
            "--ab\r\n--abc-extra\r\n--abc--extra\r\n--abc--\r\n",
            "preamble\n--abc-extra\n--abc--\n",
        ] {
            let payload = stream::iter(body.as_bytes().to_vec())
                .map(|byte| Ok(Bytes::copy_from_slice(&[byte])))
                .interleave_pending();
            let mut multipart = Multipart::new(&form_data_headers("abc"), payload);
            assert!(multipart.next().await.is_none());
            assert!(multipart.next().await.is_none());
        }
    }

    /// STATEMENT: Discarded length-delimited fields wait for fragmented data and separators before the following field is yielded.
    ///
    /// HOW:
    /// - Drop a four-byte field after only two body bytes arrive, then feed its remaining bytes and CRLF in separate chunks.
    /// - Confirm the parent stays pending until the separator is complete, then yields the next field with its intact body and reaches EOF.
    #[ntex::test]
    async fn discarded_fields_wait_for_fragmented_bodies_and_separators() {
        let (sender, payload) = create_stream();
        sender.send(Ok(Bytes::from_static(
            b"--abc\r\nContent-Disposition: form-data; name=\"first\"\r\nContent-Length: 4\r\n\r\nab",
        ))).unwrap();
        let mut multipart = Multipart::new(&form_data_headers("abc"), payload);
        drop(multipart.next().await.unwrap().unwrap());
        assert!(futures::poll!(multipart.next()).is_pending());
        sender.send(Ok(Bytes::from_static(b"cd\r"))).unwrap();
        assert!(futures::poll!(multipart.next()).is_pending());
        sender.send(Ok(Bytes::from_static(b"\n--ab"))).unwrap();
        assert!(futures::poll!(multipart.next()).is_pending());
        sender
            .send(Ok(Bytes::from_static(
                b"c\r\nContent-Disposition: form-data; name=\"second\"\r\n\r\nnext\r\n--abc--\r\n",
            )))
            .unwrap();
        drop(sender);
        let mut field = multipart.next().await.unwrap().unwrap();
        assert_eq!(field.name(), Some("second"));
        assert_eq!(get_whole_field(&mut field).await, "next");
        drop(field);
        assert!(multipart.next().await.is_none());
    }

    /// STATEMENT: A completed length-delimited body still requires a complete CRLF separator before payload EOF.
    ///
    /// HOW:
    /// - Send an exact four-byte body with an absent or partial separator and keep its stream open.
    /// - Confirm its data is returned, the next read waits, and closing the payload produces `Incomplete`.
    #[ntex::test]
    async fn length_delimited_fields_require_complete_separators() {
        for separator in ["", "\r"] {
            let (sender, payload) = create_stream();
            sender.send(Ok(Bytes::from(format!(
                "--abc\r\nContent-Disposition: form-data; name=\"f\"\r\nContent-Length: 4\r\n\r\ndata{separator}",
            )))).unwrap();
            let mut multipart = Multipart::new(&form_data_headers("abc"), payload);
            let mut field = multipart.next().await.unwrap().unwrap();
            assert_eq!(field.next().await.unwrap().unwrap(), "data");
            assert!(futures::poll!(field.next()).is_pending());
            drop(sender);
            assert!(matches!(
                field.next().await,
                Some(Err(MultipartError::Incomplete))
            ));
        }
    }

    /// STATEMENT: Invalid field media types do not discard mixed-part headers or body data.
    ///
    /// HOW:
    /// - Submit mixed parts with malformed and non-UTF-8 media types, an attachment disposition, and repeated custom headers.
    /// - Confirm optional parsed metadata is absent while both custom headers, attachment header, and binary content are preserved.
    #[ntex::test]
    async fn malformed_optional_metadata_preserves_mixed_field_data() {
        for content_type in [b"invalid".as_slice(), b"\xff"] {
            let mut body = b"--abc\r\nContent-Disposition: attachment; filename=\"file.bin\"\r\nX-Trace: first\r\nX-Trace: second\r\nContent-Type: ".to_vec();
            body.extend_from_slice(content_type);
            body.extend_from_slice(b"\r\n\r\n\0\xffdata\r\n--abc--\r\n");
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("multipart/mixed; boundary=abc"),
            );
            let mut multipart = Multipart::new(&headers, stream::iter([Ok(Bytes::from(body))]));
            let mut field = multipart.next().await.unwrap().unwrap();
            assert!(field.content_type().is_none());
            assert!(field.content_disposition().is_none());
            assert!(field.name().is_none());
            assert_eq!(
                field.headers().get_all("x-trace").collect::<Vec<_>>(),
                ["first", "second"]
            );
            assert_eq!(
                field.headers().get(header::CONTENT_DISPOSITION).unwrap(),
                "attachment; filename=\"file.bin\""
            );
            assert_eq!(get_whole_field(&mut field).await.as_ref(), b"\0\xffdata");
            drop(field);
            assert!(multipart.next().await.is_none());
        }
    }

    /// STATEMENT: A payload error before the first field is yielded propagates from the parent stream.
    ///
    /// HOW:
    /// - Send a partial first boundary, confirm the parent waits, then fail the stream with `Overflow`.
    /// - Confirm the next parent poll returns the original `PayloadError::Overflow`.
    #[ntex::test]
    async fn parent_propagates_errors_while_reading_first_boundary() {
        let (sender, payload) = mpsc::channel::<Result<Bytes, PayloadError>>();
        sender.send(Ok(Bytes::from_static(b"--ab"))).unwrap();
        let mut multipart = Multipart::new(&form_data_headers("abc"), payload);
        assert!(futures::poll!(multipart.next()).is_pending());
        sender.send(Err(PayloadError::Overflow)).unwrap();
        assert!(matches!(
            multipart.next().await,
            Some(Err(MultipartError::Payload(PayloadError::Overflow)))
        ));
    }

    /// STATEMENT: Boundary prefixes followed by ordinary data remain part of an unknown-length field.
    ///
    /// HOW:
    /// - Submit a body containing `\r\n--abc-extra` before the actual closing boundary.
    /// - Confirm the complete body is returned and only the exact closing delimiter ends the field and multipart stream.
    #[ntex::test]
    async fn matching_boundary_prefixes_in_data_are_preserved() {
        let data = "before\r\n--abc-extra\r\nafter";
        let mut multipart = multipart_body(format!(
            "--abc\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n{data}\r\n--abc--\r\n",
        ));
        let mut field = multipart.next().await.unwrap().unwrap();
        assert_eq!(get_whole_field(&mut field).await, data);
        drop(field);
        assert!(multipart.next().await.is_none());
    }

    /// STATEMENT: An empty multipart body can end with a closing delimiter without trailing CRLF.
    ///
    /// HOW:
    /// - Close the payload immediately after `--abc--`, with and without a preamble.
    /// - Confirm the first parent poll reaches EOF without yielding a field or an error.
    #[ntex::test]
    async fn empty_closing_boundary_without_crlf_is_accepted() {
        for body in ["--abc--", "preamble\r\n--abc--"] {
            let mut multipart = multipart_body(body);
            assert!(multipart.next().await.is_none());
        }
    }

    /// STATEMENT: Unknown-length fields wait for incoming body chunks without treating an empty live buffer as EOF.
    ///
    /// HOW:
    /// - Yield a field after sending only its headers, then send its body and closing boundary in separate chunks.
    /// - Confirm reads stay pending before each chunk, both chunks preserve their contents, and the field and parent terminate normally.
    #[ntex::test]
    async fn unknown_length_fields_wait_between_body_chunks() {
        let (sender, payload) = create_stream();
        sender
            .send(Ok(Bytes::from_static(
                b"--abc\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n",
            )))
            .unwrap();
        let mut multipart = Multipart::new(&form_data_headers("abc"), payload);
        let mut field = multipart.next().await.unwrap().unwrap();
        assert!(futures::poll!(field.next()).is_pending());
        sender.send(Ok(Bytes::from_static(b"first"))).unwrap();
        assert_eq!(field.next().await.unwrap().unwrap(), "first");
        assert!(futures::poll!(field.next()).is_pending());
        sender
            .send(Ok(Bytes::from_static(b"second\r\n--abc--\r\n")))
            .unwrap();
        drop(sender);
        assert_eq!(get_whole_field(&mut field).await, "second");
        drop(field);
        assert!(multipart.next().await.is_none());
    }

    /// STATEMENT: The stream ends after reporting a request content-type error.
    ///
    /// HOW:
    /// - Create a `Multipart` without a `Content-Type` header.
    /// - Confirm the first item is `NoContentType` and polling again yields `None` instead of panicking.
    #[ntex::test]
    async fn stream_ends_after_content_type_error() {
        let mut multipart = Multipart::new(&HeaderMap::new(), futures::stream::empty());
        assert!(matches!(
            multipart.next().await,
            Some(Err(MultipartError::NoContentType))
        ));
        assert!(multipart.next().await.is_none());
    }
}
