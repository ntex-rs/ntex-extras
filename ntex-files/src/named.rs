use std::fs::{File, Metadata};
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{error::Error, io, rc::Rc};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use bitflags::bitflags;
use futures::stream::TryStreamExt;
use mime_guess::from_path;
use ntex::http::body::SizedStream;
use ntex::http::header::ContentEncoding;
use ntex::http::{self, Method, StatusCode};
use ntex::web::{BodyEncoding, HttpRequest, HttpResponse, Responder, State};

use crate::{ChunkedReadFile, header, header::StandardHeader, range::HttpRange};

bitflags! {
    #[derive(Clone)]
    pub(crate) struct Flags: u8 {
        const ETAG = 0b0000_0001;
        const LAST_MD = 0b0000_0010;
        const CONTENT_DISPOSITION = 0b0000_0100;
    }
}

impl Default for Flags {
    fn default() -> Self {
        Flags::all()
    }
}

/// An opened file with a path used to select response headers.
///
/// Return this type from a web handler or call [`Self::into_response`] to stream
/// the file. Metadata and modification time are captured at construction; they
/// are not refreshed if the file later changes. This type dereferences to
/// [`File`], but serving seeks to the selected offset rather than using its
/// current cursor.
#[derive(Debug)]
pub struct NamedFile {
    path: PathBuf,
    file: File,
    modified: Option<SystemTime>,
    etag: Option<header::EntityTag>,
    pub(crate) md: Metadata,
    pub(crate) flags: Flags,
    pub(crate) status_code: StatusCode,
    pub(crate) content_type: mime::Mime,
    pub(crate) content_disposition: header::ContentDisposition,
    pub(crate) encoding: Option<ContentEncoding>,
}

impl std::fmt::Debug for Flags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Flags")
            .field("etag", &self.contains(Flags::ETAG))
            .field("last_modified", &self.contains(Flags::LAST_MD))
            .field(
                "content_disposition",
                &self.contains(Flags::CONTENT_DISPOSITION),
            )
            .finish()
    }
}

impl NamedFile {
    /// Creates a response file from an already opened [`File`] and a display path.
    ///
    /// `path` need not exist: it supplies the filename and extension used for
    /// `Content-Disposition` and `Content-Type`, and is returned by [`Self::path`].
    /// An unknown extension uses `application/octet-stream`.
    ///
    /// The default disposition is `inline` for `image/*`, `text/*`, `audio/*`,
    /// `video/*`, and the application subtypes `javascript`, `json`, `wasm`, and
    /// `xhtml`; all others use `attachment`. The filename is converted with
    /// [`OsStr::to_string_lossy`](std::ffi::OsStr::to_string_lossy), and line feed,
    /// vertical tab, form feed, and carriage return become `%0A`, `%0B`, `%0C`,
    /// and `%0D` in the plain filename. Non-ASCII names also get a UTF-8
    /// `filename*` parameter containing the original filename bytes after the
    /// lossy conversion.
    ///
    /// The default status is `200 OK`; `Content-Disposition`, `ETag`, and
    /// `Last-Modified` are enabled. Metadata is read from `file`, not `path`.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] if `path` has no filename, or an
    /// I/O error if metadata cannot be read. The file must support reading and
    /// seeking when the response is streamed; this is not checked here.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use std::{fs::File, io};
    /// use ntex_files::NamedFile;
    ///
    /// # fn main() -> io::Result<()> {
    /// let file = File::open("source.bin")?;
    /// let named_file = NamedFile::from_file(file, "download.txt")?;
    /// assert_eq!(named_file.path(), std::path::Path::new("download.txt"));
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_file<P: AsRef<Path>>(file: File, path: P) -> io::Result<NamedFile> {
        let path = path.as_ref().to_path_buf();

        // Get the name of the file and use it to construct default Content-Type
        // and Content-Disposition values
        let (content_type, content_disposition) = {
            let filename = match path.file_name() {
                Some(name) => name.to_string_lossy(),
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Provided path has no filename",
                    ));
                }
            };

            let ct = from_path(&path).first_or_octet_stream();
            let disposition = match ct.type_() {
                mime::IMAGE | mime::TEXT | mime::AUDIO | mime::VIDEO => {
                    header::DispositionType::Inline
                }
                mime::APPLICATION => match ct.subtype() {
                    mime::JAVASCRIPT | mime::JSON => header::DispositionType::Inline,
                    name if name == "wasm" || name == "xhtml" => header::DispositionType::Inline,
                    _ => header::DispositionType::Attachment,
                },
                _ => header::DispositionType::Attachment,
            };

            // replace special characters in filenames which could occur on some filesystems
            let filename_s = filename
                .replace('\n', "%0A") // \n line break
                .replace('\x0B', "%0B") // \v vertical tab
                .replace('\x0C', "%0C") // \f form feed
                .replace('\r', "%0D"); // \r carriage return
            let mut parameters = vec![header::DispositionParam::Filename(filename_s)];

            if !filename.is_ascii() {
                parameters.push(header::DispositionParam::FilenameExt(
                    header::parsing::ExtendedValue {
                        charset: header::Charset::Ext(String::from("UTF-8")),
                        language_tag: None,
                        value: filename.into_owned().into_bytes(),
                    },
                ))
            }

            let cd = header::ContentDisposition {
                disposition,
                parameters,
            };
            (ct, cd)
        };

        let md = file.metadata()?;
        let modified = md.modified().ok();
        let encoding = None;
        Ok(NamedFile {
            path,
            file,
            content_type,
            content_disposition,
            md,
            modified,
            etag: None,
            encoding,
            status_code: StatusCode::OK,
            flags: Flags::default(),
        })
    }

    /// Opens `path` read-only and constructs a [`NamedFile`] with that path.
    ///
    /// This synchronous operation follows symlinks and does not perform the
    /// URL segment validation or base-directory containment checks of [`crate::Files`].
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the file cannot be opened, or any error described
    /// by [`Self::from_file`].
    ///
    /// ```no_run
    /// use ntex_files::NamedFile;
    ///
    /// # fn main() -> std::io::Result<()> {
    /// let file = NamedFile::open("report.txt")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<NamedFile> {
        Self::from_file(File::open(&path)?, path)
    }

    /// Returns a reference to the underlying [`File`].
    #[inline]
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Returns the path supplied to [`Self::open`] or [`Self::from_file`].
    ///
    /// This is not necessarily the path of the underlying file or a canonical path.
    ///
    /// ```no_run
    /// use ntex_files::NamedFile;
    ///
    /// # fn main() -> std::io::Result<()> {
    /// let file = NamedFile::open("report.txt")?;
    /// assert_eq!(file.path(), std::path::Path::new("report.txt"));
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    /// Sets the response status, which defaults to `200 OK`.
    ///
    /// A status other than `200 OK` streams the entire file without evaluating
    /// conditional or range requests, or adding `ETag`, `Last-Modified`, or
    /// `Accept-Ranges`.
    pub fn set_status_code(mut self, status: StatusCode) -> Self {
        self.status_code = status;
        self
    }

    /// Sets `Content-Type`, overriding the type inferred from the path extension.
    ///
    /// Does not recompute the disposition type; use [`Self::set_content_disposition`]
    /// to change it separately.
    #[inline]
    pub fn set_content_type(mut self, mime_type: mime::Mime) -> Self {
        self.content_type = mime_type;
        self
    }

    /// Sets and enables `Content-Disposition`, including its filename parameters.
    ///
    /// See [`Self::from_file`] for the default MIME-based disposition and filename
    /// handling. This also re-enables a previously disabled header; it does not
    /// change `Content-Type`.
    #[inline]
    pub fn set_content_disposition(mut self, cd: header::ContentDisposition) -> Self {
        self.content_disposition = cd;
        self.flags.insert(Flags::CONTENT_DISPOSITION);
        self
    }

    /// Disables the `Content-Disposition` header, which is enabled by default.
    #[inline]
    pub fn disable_content_disposition(mut self) -> Self {
        self.flags.remove(Flags::CONTENT_DISPOSITION);
        self
    }

    /// Sets the response encoding override used by ntex's encoding middleware.
    ///
    /// Does not transform the file bytes itself. No override is set by default;
    /// successful partial responses force [`ContentEncoding::Identity`].
    #[inline]
    pub fn set_content_encoding(mut self, enc: ContentEncoding) -> Self {
        self.encoding = Some(enc);
        self
    }

    #[inline]
    /// Enables or disables `ETag` emission and use as a conditional validator.
    ///
    /// Defaults to `true`. Without a custom tag, metadata supplies a strong tag
    /// only when modification time is available and at or after the Unix epoch.
    /// Disabling it removes the validator for explicit tag comparisons and
    /// `If-Range`; wildcard `If-Match` and `If-None-Match` still test file existence.
    pub fn use_etag(mut self, value: bool) -> Self {
        self.flags.set(Flags::ETAG, value);
        self
    }

    #[inline]
    /// Enables or disables `Last-Modified` emission and date-based validators.
    ///
    /// Defaults to `true`. The header is omitted if modification time is
    /// unavailable, before the Unix epoch, or after the end of year 9999.
    /// HTTP dates have whole-second precision.
    pub fn use_last_modified(mut self, value: bool) -> Self {
        self.flags.set(Flags::LAST_MD, value);
        self
    }

    /// Set the `ETag` for serving this file.
    ///
    /// By default the `ETag` is derived from the file metadata: size, modification
    /// time and, on Unix, the inode. Use this method when the version of the content
    /// is known by other means, for example a hash of generated or cached content.
    /// The given tag is sent in the `ETag` header and used to evaluate the
    /// conditional request headers `If-Match` and `If-None-Match`.
    ///
    /// A strong tag must change whenever the bytes change. Use
    /// [`EntityTag::weak`](header::EntityTag::weak) when the version identifies
    /// semantic equivalence rather than byte-for-byte identity. `If-Match` uses
    /// strong comparison, so an explicit weak tag never satisfies it.
    ///
    /// This also enables the header; a later [`Self::use_etag`] call can disable it.
    /// If modification time does not reflect the content version, consider
    /// disabling `Last-Modified` with [`Self::use_last_modified`].
    ///
    /// ```rust,no_run
    /// use ntex_files::{NamedFile, header::EntityTag};
    ///
    /// # fn main() -> std::io::Result<()> {
    /// // for example a hex digest of the content, computed when the file was written
    /// let content_hash = String::from("4f9c2e1a");
    /// let file = NamedFile::open("index.html")?.set_etag(EntityTag::strong(content_hash));
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn set_etag(mut self, etag: header::EntityTag) -> Self {
        self.etag = Some(etag);
        self.flags.insert(Flags::ETAG);
        self
    }

    pub(crate) fn etag(&self) -> Option<header::EntityTag> {
        if let Some(ref etag) = self.etag {
            return Some(etag.clone());
        }

        // This etag format is similar to Apache's.
        // A modification time before the UNIX epoch gets no etag.
        let dur = self.modified?.duration_since(UNIX_EPOCH).ok()?;
        Some({
            let ino = {
                #[cfg(unix)]
                {
                    self.md.ino()
                }
                #[cfg(not(unix))]
                {
                    0
                }
            };

            header::EntityTag::strong(format!(
                "{:x}:{:x}:{:x}:{:x}",
                ino,
                self.md.len(),
                dur.as_secs(),
                dur.subsec_nanos()
            ))
        })
    }

    pub(crate) fn last_modified(&self) -> Option<header::HttpDate> {
        // `httpdate` can only represent times from 1970 up to the end of year
        // 9999, and converting any other time into an `HttpDate` panics.
        let mtime = self.modified?;
        let dur = mtime.duration_since(UNIX_EPOCH).ok()?;
        if dur.as_secs() >= 253_402_300_800 {
            return None;
        }
        Some(mtime.into())
    }

    /// Builds a streaming response, evaluating `req` against the captured metadata.
    ///
    /// For the default `200 OK` status, sends `Content-Type`, `Accept-Ranges:
    /// bytes`, and enabled `Content-Disposition`, `ETag`, and `Last-Modified`
    /// headers when their values are available. Reads run on the blocking thread
    /// pool. Read and seek failures are reported by the response body stream.
    ///
    /// Conditional requests take precedence over ranges. `If-Match` uses strong
    /// tag comparison and takes precedence over `If-Unmodified-Since`;
    /// `If-None-Match` uses weak comparison and takes precedence over
    /// `If-Modified-Since`. Preconditions are ignored for `CONNECT`, `OPTIONS`,
    /// and `TRACE`. An unchanged `GET`/`HEAD` response returns `304 Not Modified`;
    /// failed preconditions, including matching `If-None-Match` on other
    /// applicable methods, return `412 Precondition Failed`.
    ///
    /// Byte ranges are evaluated only for `GET`. Other range units are ignored.
    /// A nonmatching or invalid `If-Range` ignores the range; entity tags must
    /// match strongly and dates must equal the available `Last-Modified` value.
    /// Only the first selected range is served, with `206 Partial Content`,
    /// `Content-Range`, and identity encoding; no multipart response is generated.
    /// A zero-length suffix result for an empty file is ignored.
    ///
    /// # Errors
    ///
    /// An evaluated `Range` value that cannot be converted to text returns
    /// `400 Bad Request`. Malformed, empty, or wholly unsatisfiable byte range
    /// lists return `416 Range Not Satisfiable` with `Content-Range: bytes */size`.
    /// Failed preconditions return `412 Precondition Failed` as described above.
    /// These responses have no file body. A non-OK configured status bypasses
    /// these checks; see [`Self::set_status_code`].
    pub fn into_response(self, req: &HttpRequest) -> HttpResponse {
        if self.status_code != StatusCode::OK {
            let mut resp = HttpResponse::builder(self.status_code);
            if self.flags.contains(Flags::CONTENT_DISPOSITION) {
                resp.header(
                    http::header::CONTENT_DISPOSITION,
                    self.content_disposition.to_string(),
                );
            }
            if let Some(current_encoding) = self.encoding {
                resp.encoding(current_encoding);
            }
            let reader = ChunkedReadFile {
                size: self.md.len(),
                offset: 0,
                file: Some(self.file),
                fut: None,
                counter: 0,
            };
            resp.header(http::header::CONTENT_TYPE, self.content_type.to_string());
            return resp.streaming(reader);
        }

        let etag = if self.flags.contains(Flags::ETAG) {
            self.etag()
        } else {
            None
        };
        let last_modified = if self.flags.contains(Flags::LAST_MD) {
            self.last_modified()
        } else {
            None
        };

        // conditional headers are ignored for methods that neither select nor
        // modify a representation (RFC 9110 section 13.2.1)
        let ignore_preconditions = matches!(
            *req.method(),
            Method::CONNECT | Method::OPTIONS | Method::TRACE
        );
        let is_get_or_head = matches!(*req.method(), Method::GET | Method::HEAD);

        // check preconditions, in the order of RFC 9110 section 13.2.2
        let precondition_failed = if ignore_preconditions {
            false
        } else if !any_match(etag.as_ref(), req) {
            true
        } else if req.headers().contains_key(&http::header::IF_MATCH) {
            false
        } else if let (Some(ref m), Some(header::IfUnmodifiedSince(ref since))) =
            (last_modified, parse_field(req))
        {
            let t1: SystemTime = (*m).into();
            let t2: SystemTime = (*since).into();
            match (t1.duration_since(UNIX_EPOCH), t2.duration_since(UNIX_EPOCH)) {
                (Ok(t1), Ok(t2)) => t1 > t2,
                _ => false,
            }
        } else {
            false
        };

        // check last modified
        let not_modified = if ignore_preconditions {
            false
        } else if !none_match(etag.as_ref(), req) {
            true
        } else if !is_get_or_head || req.headers().contains_key(&http::header::IF_NONE_MATCH) {
            false
        } else if let (Some(ref m), Some(header::IfModifiedSince(ref since))) =
            (last_modified, parse_field(req))
        {
            let t1: SystemTime = (*m).into();
            let t2: SystemTime = (*since).into();
            match (t1.duration_since(UNIX_EPOCH), t2.duration_since(UNIX_EPOCH)) {
                (Ok(t1), Ok(t2)) => t1 <= t2,
                _ => false,
            }
        } else {
            false
        };

        // check If-Range: a validator that does not match makes Range ignored
        let range_allowed = if_range_matches(etag.as_ref(), last_modified, req);

        let mut resp = HttpResponse::builder(self.status_code);
        if self.flags.contains(Flags::CONTENT_DISPOSITION) {
            resp.header(
                http::header::CONTENT_DISPOSITION,
                self.content_disposition.to_string(),
            );
        }
        // default compressing
        if let Some(current_encoding) = self.encoding {
            resp.encoding(current_encoding);
        }
        if let Some(lm) = last_modified {
            resp.header(
                http::header::LAST_MODIFIED,
                header::LastModified(lm).to_string(),
            );
        }
        if let Some(etag) = etag {
            resp.header(http::header::ETAG, header::ETag(etag).to_string());
        }

        resp.header(http::header::CONTENT_TYPE, self.content_type.to_string());
        resp.header(http::header::ACCEPT_RANGES, "bytes");

        // a 412 or 304 response takes precedence over the range request
        if precondition_failed || (not_modified && !is_get_or_head) {
            return resp.status(StatusCode::PRECONDITION_FAILED).build();
        } else if not_modified {
            return resp.status(StatusCode::NOT_MODIFIED).build();
        }

        let mut length = self.md.len();
        let mut offset = 0;

        // range requests are defined only for GET, and a range unit
        // other than "bytes" is ignored (RFC 9110 section 14.2)
        let ranges = req.headers().get(&http::header::RANGE).filter(|ranges| {
            *req.method() == Method::GET
                && ranges
                    .to_str()
                    .ok()
                    .and_then(|value| value.split_once('='))
                    .is_none_or(|(unit, _)| unit.eq_ignore_ascii_case("bytes"))
        });

        // check for range header
        if let Some(ranges) = ranges.filter(|_| range_allowed) {
            if let Ok(rangesheader) = ranges.to_str() {
                if let Some(range) = HttpRange::parse(rangesheader, length)
                    .ok()
                    .and_then(|ranges| ranges.first().copied())
                {
                    // A suffix range of an empty file selects zero bytes, which
                    // a Content-Range cannot express, so the range is ignored.
                    if range.length > 0 {
                        length = range.length;
                        offset = range.start;
                        resp.status(StatusCode::PARTIAL_CONTENT);
                        resp.encoding(ContentEncoding::Identity);
                        resp.header(
                            http::header::CONTENT_RANGE,
                            format!("bytes {}-{}/{}", offset, offset + length - 1, self.md.len()),
                        );
                    }
                } else {
                    resp.header(http::header::CONTENT_RANGE, format!("bytes */{}", length));
                    return resp.status(StatusCode::RANGE_NOT_SATISFIABLE).build();
                };
            } else {
                return resp.status(StatusCode::BAD_REQUEST).build();
            };
        };

        let reader = ChunkedReadFile {
            offset,
            size: length,
            file: Some(self.file),
            fut: None,
            counter: 0,
        };
        resp.body(SizedStream::new(
            length,
            reader.map_err(|e| {
                let e: Rc<dyn Error> = Rc::new(e);
                e
            }),
        ))
    }
}

impl Deref for NamedFile {
    type Target = File;

    fn deref(&self) -> &File {
        &self.file
    }
}

impl DerefMut for NamedFile {
    fn deref_mut(&mut self) -> &mut File {
        &mut self.file
    }
}

/// Parses a request header from all of its lines.
///
/// A list header sent on several lines is the union of its lines, and a
/// single-value header sent on several lines fails to parse and is ignored.
fn parse_field<H: StandardHeader>(req: &HttpRequest) -> Option<H> {
    let mut lines = req.headers().get_all(H::http_header_name());
    let mut raw = header::Raw::from(lines.next()?.as_bytes());
    for line in lines {
        raw.push(line.as_bytes());
    }
    H::parse_header(&raw).ok()
}

/// Returns true if `req` has no `If-Match` header or one which matches `etag`.
fn any_match(etag: Option<&header::EntityTag>, req: &HttpRequest) -> bool {
    if let Some(val) = parse_field(req) {
        match val {
            header::IfMatch::Any => return true,
            header::IfMatch::Items(ref items) => {
                if let Some(some_etag) = etag {
                    for item in items {
                        if item.strong_eq(some_etag) {
                            return true;
                        }
                    }
                }
            }
        };
        return false;
    }
    true
}

/// Returns true if `req` has no `If-Range` header or one whose validator matches the file.
///
/// An entity-tag must match `etag` by strong comparison, an HTTP-date must be
/// equal to `last_modified`.
fn if_range_matches(
    etag: Option<&header::EntityTag>,
    last_modified: Option<header::HttpDate>,
    req: &HttpRequest,
) -> bool {
    let Some(val) = req.headers().get(http::header::IF_RANGE) else {
        return true;
    };
    let Ok(val) = val.to_str() else {
        return false;
    };
    if let Ok(tag) = val.parse::<header::EntityTag>() {
        etag.is_some_and(|etag| etag.strong_eq(&tag))
    } else if let Ok(date) = val.parse::<header::HttpDate>() {
        last_modified == Some(date)
    } else {
        false
    }
}

/// Returns true if `req` doesn't have an `If-None-Match` header matching `req`.
fn none_match(etag: Option<&header::EntityTag>, req: &HttpRequest) -> bool {
    if let Some(val) = parse_field(req) {
        return match val {
            header::IfNoneMatch::Any => false,
            header::IfNoneMatch::Items(ref items) => {
                if let Some(some_etag) = etag {
                    for item in items {
                        if item.weak_eq(some_etag) {
                            return false;
                        }
                    }
                }
                true
            }
        };
    }
    true
}

impl<St: State> Responder<St> for NamedFile {
    async fn respond_to(self, _: &St, req: &HttpRequest) -> HttpResponse {
        self.into_response(req)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ntex::web::test::{self, TestRequest};

    use super::*;

    /// Opens a file whose modification time is one day before the UNIX epoch.
    fn file_modified_before_epoch(dir: &tempfile::TempDir) -> NamedFile {
        let path = dir.path().join("old.txt");
        std::fs::write(&path, b"old").unwrap();
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(UNIX_EPOCH - Duration::from_secs(86_400))
            .unwrap();
        assert!(std::fs::metadata(&path).unwrap().modified().unwrap() < UNIX_EPOCH);

        NamedFile::open(&path).unwrap()
    }

    #[ntex::test]
    async fn test_modified_before_epoch() {
        let dir = tempfile::tempdir().unwrap();
        let file = file_modified_before_epoch(&dir);

        let req = TestRequest::default().to_http_request();
        let resp = test::respond_to(file, &req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get(http::header::ETAG).is_none());
        assert!(resp.headers().get(http::header::LAST_MODIFIED).is_none());
    }

    #[ntex::test]
    async fn test_modified_before_epoch_without_etag() {
        let dir = tempfile::tempdir().unwrap();
        let file = file_modified_before_epoch(&dir).use_etag(false);

        let req = TestRequest::default().to_http_request();
        let resp = test::respond_to(file, &req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get(http::header::ETAG).is_none());
        assert!(resp.headers().get(http::header::LAST_MODIFIED).is_none());
    }

    #[ntex::test]
    async fn test_modified_after_year_9999() {
        let mut file = NamedFile::open("Cargo.toml").unwrap();
        // 10000-01-01T00:00:00Z, the first instant an HTTP-date cannot express
        file.modified = Some(UNIX_EPOCH + Duration::from_secs(253_402_300_800));

        let req = TestRequest::default().to_http_request();
        let resp = test::respond_to(file, &req).await;

        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get(http::header::ETAG).is_some());
        assert!(resp.headers().get(http::header::LAST_MODIFIED).is_none());
    }

    /// STATEMENT: `NamedFile::from_file` rejects paths that cannot supply a filename.
    ///
    /// HOW:
    /// - Associate an existing open file with empty, root, and parent-only paths.
    /// - Check each construction fails with `InvalidInput` rather than inventing a filename.
    #[test]
    fn from_file_requires_a_filename() {
        for path in ["", "/", ".", ".."] {
            let error =
                NamedFile::from_file(File::open("tests/test.binary").unwrap(), path).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "{path:?}");
        }
    }

    /// STATEMENT: A supplied filename determines MIME and disposition independently of the opened file.
    ///
    /// HOW:
    /// - Associate the same binary file with script, JSON, Wasm, XHTML, media, message, and unknown extensions.
    /// - Check response MIME and parsed disposition, including the supplied filename.
    #[ntex::test]
    async fn supplied_filename_selects_mime_and_disposition() {
        use crate::header::{ContentDisposition, DispositionType, Header, Raw};

        for (filename, mime, disposition) in [
            ("script.js", "text/javascript", DispositionType::Inline),
            ("data.json", "application/json", DispositionType::Inline),
            ("module.wasm", "application/wasm", DispositionType::Inline),
            (
                "page.xhtml",
                "application/xhtml+xml",
                DispositionType::Inline,
            ),
            ("sound.mp3", "audio/mpeg", DispositionType::Inline),
            ("movie.mp4", "video/mp4", DispositionType::Inline),
            ("mail.eml", "message/rfc822", DispositionType::Attachment),
            (
                "archive.zip",
                "application/zip",
                DispositionType::Attachment,
            ),
            (
                "file.unregistered-extension",
                "application/octet-stream",
                DispositionType::Attachment,
            ),
        ] {
            let file =
                NamedFile::from_file(File::open("tests/test.binary").unwrap(), filename).unwrap();
            let req = TestRequest::default().to_http_request();
            let resp = file.into_response(&req);
            assert_eq!(resp.status(), StatusCode::OK, "{filename}");
            assert_eq!(
                resp.headers().get(http::header::CONTENT_TYPE).unwrap(),
                mime,
                "{filename}"
            );
            let raw = Raw::from(
                resp.headers()
                    .get(http::header::CONTENT_DISPOSITION)
                    .unwrap()
                    .as_bytes(),
            );
            let parsed = ContentDisposition::parse_header(&raw).unwrap();
            assert_eq!(parsed.disposition, disposition, "{filename}");
            assert_eq!(parsed.get_filename(), Some(filename));
        }
    }

    /// STATEMENT: Unicode filenames retain their original octets in `filename*` while line breaks are sanitized.
    ///
    /// HOW:
    /// - Respond from a file associated with a Unicode filename containing quotes and line-breaking controls.
    /// - Parse the response disposition and check sanitized fallback text, UTF-8 extended bytes, and no raw line breaks.
    #[ntex::test]
    async fn unicode_and_control_filenames_are_encoded_safely() {
        use crate::header::{Charset, ContentDisposition, Header, Raw};

        let filename = "résumé\n\u{b}\u{c}\r\".txt";
        let file =
            NamedFile::from_file(File::open("tests/test.binary").unwrap(), filename).unwrap();
        let req = TestRequest::default().to_http_request();
        let resp = file.into_response(&req);
        assert_eq!(resp.status(), StatusCode::OK);
        let value = resp
            .headers()
            .get(http::header::CONTENT_DISPOSITION)
            .unwrap();
        assert!(
            !value
                .as_bytes()
                .iter()
                .any(|b| matches!(b, b'\n' | b'\r' | 0x0b | 0x0c))
        );
        let parsed = ContentDisposition::parse_header(&Raw::from(value.as_bytes())).unwrap();
        assert_eq!(parsed.get_filename(), Some("résumé%0A%0B%0C%0D\".txt"));
        let extended = parsed.get_filename_ext().unwrap();
        assert_eq!(extended.charset, Charset::Ext("UTF-8".into()));
        assert_eq!(extended.language_tag, None);
        assert_eq!(extended.value, filename.as_bytes());
        let encoded = std::str::from_utf8(value.as_bytes()).unwrap();
        assert!(encoded.contains("filename*=UTF-8''r%C3%A9sum%C3%A9%0A%0B%0C%0D%22.txt"));
    }

    /// STATEMENT: A byte-range header with invalid text encoding returns `400` without a content range.
    ///
    /// HOW:
    /// - Send a `Range` field containing a non-ASCII byte to a named file.
    /// - Check the response is `BadRequest` and does not advertise a selected range.
    #[ntex::test]
    async fn invalid_range_encoding_returns_bad_request() {
        let value = http::header::HeaderValue::from_bytes(b"bytes=\xff").unwrap();
        let req = TestRequest::default()
            .header(http::header::RANGE, value)
            .to_http_request();
        let resp = NamedFile::open("tests/test.binary")
            .unwrap()
            .into_response(&req);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(!resp.headers().contains_key(http::header::CONTENT_RANGE));
    }

    /// STATEMENT: An explicit non-OK file response preserves configured MIME, encoding, and bytes while bypassing conditional and range evaluation.
    ///
    /// HOW:
    /// - Respond with `202 Accepted`, a custom MIME type, identity encoding, disabled disposition, and failing request preconditions and range.
    /// - Check the selected status and encoding, omitted validator and range headers, and the complete file body.
    #[ntex::test]
    async fn custom_status_preserves_representation_and_ignores_preconditions() {
        let file = NamedFile::open("tests/test.binary")
            .unwrap()
            .set_status_code(StatusCode::ACCEPTED)
            .set_content_type(mime::TEXT_PLAIN)
            .set_content_encoding(ContentEncoding::Identity)
            .disable_content_disposition();
        let req = TestRequest::default()
            .header(http::header::IF_MATCH, "\"other\"")
            .header(http::header::IF_NONE_MATCH, "*")
            .header(http::header::RANGE, "bytes=999-")
            .to_http_request();
        let resp = file.into_response(&req);
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        assert_eq!(resp.get_encoding(), Some(ContentEncoding::Identity));
        assert_eq!(
            resp.headers().get(http::header::CONTENT_TYPE).unwrap(),
            "text/plain"
        );
        for name in [
            http::header::ETAG,
            http::header::LAST_MODIFIED,
            http::header::CONTENT_DISPOSITION,
            http::header::CONTENT_RANGE,
        ] {
            assert!(!resp.headers().contains_key(name));
        }
        let body = test::read_body(resp).await;
        assert_eq!(body.as_ref(), std::fs::read("tests/test.binary").unwrap());
    }

    /// STATEMENT: Streaming a write-only file reports the underlying I/O error instead of returning an empty successful body.
    ///
    /// HOW:
    /// - Write bytes to a write-only file and associate its open handle with a named response.
    /// - Check response construction succeeds, then body collection fails with a downcastable I/O error.
    #[ntex::test]
    async fn unreadable_file_body_reports_io_error() {
        use std::io::Write;

        let root = tempfile::tempdir_in(".").unwrap();
        let path = root.path().join("write-only.txt");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"not readable").unwrap();
        let file = NamedFile::from_file(file, path).unwrap();
        let mut resp = file.into_response(&TestRequest::default().to_http_request());
        assert_eq!(resp.status(), StatusCode::OK);
        let error = test::load_stream(resp.take_body()).await.unwrap_err();
        assert!(error.downcast_ref::<io::Error>().is_some(), "{error}");
    }

    /// STATEMENT: Disabled entity-tag validators cannot satisfy tag lists, but wildcard preconditions still reflect the existing representation.
    ///
    /// HOW:
    /// - Supply a custom `ETag`, disable its use, and send listed and wildcard `IfMatch` and `IfNoneMatch` conditions.
    /// - Check the expected `412`, `304`, or `200` status, omitted `ETag`, empty conditional bodies, and complete successful bodies.
    #[ntex::test]
    async fn disabled_etags_preserve_wildcard_preconditions() {
        for (name, value, status) in [
            (
                http::header::IF_MATCH,
                "\"revision\"",
                StatusCode::PRECONDITION_FAILED,
            ),
            (http::header::IF_MATCH, "*", StatusCode::OK),
            (http::header::IF_NONE_MATCH, "\"revision\"", StatusCode::OK),
            (http::header::IF_NONE_MATCH, "*", StatusCode::NOT_MODIFIED),
        ] {
            let file = NamedFile::open("tests/test.binary")
                .unwrap()
                .set_etag(header::EntityTag::strong("revision".into()))
                .use_etag(false);
            let req = TestRequest::default().header(name, value).to_http_request();
            let resp = file.into_response(&req);
            assert_eq!(resp.status(), status, "{value}");
            assert!(!resp.headers().contains_key(http::header::ETAG));
            let body = test::read_body(resp).await;
            if status == StatusCode::OK {
                assert_eq!(body.as_ref(), std::fs::read("tests/test.binary").unwrap());
            } else {
                assert!(body.is_empty());
            }
        }
    }
}
