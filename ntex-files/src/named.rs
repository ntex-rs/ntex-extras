use std::error::Error;
use std::fs::{File, Metadata};
use std::io;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::rc::Rc;
use bitflags::bitflags;
use mime_guess::from_path;

use futures::stream::TryStreamExt;
use ntex::http::body::SizedStream;
use ntex::http::header::ContentEncoding;
use ntex::http::{self, StatusCode};
use ntex::web::{BodyEncoding, ErrorRenderer, HttpRequest, HttpResponse, Responder};

use crate::file_header::{self, Header};

use crate::range::HttpRange;
use crate::ChunkedReadFile;

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

/// A file with an associated name.
#[derive(Debug)]
pub struct NamedFile {
    path: PathBuf,
    file: File,
    modified: Option<SystemTime>,
    pub(crate) md: Metadata,
    pub(crate) flags: Flags,
    pub(crate) status_code: StatusCode,
    pub(crate) content_type: mime::Mime,
    pub(crate) content_disposition: file_header::ContentDisposition,
    pub(crate) encoding: Option<ContentEncoding>,
}

impl std::fmt::Debug for Flags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Flags")
            .field("etag", &self.contains(Flags::ETAG))
            .field("last_modified", &self.contains(Flags::LAST_MD))
            .field("content_disposition", &self.contains(Flags::CONTENT_DISPOSITION))
            .finish()
    }
}

impl NamedFile {
    /// Creates an instance from a previously opened file.
    ///
    /// The given `path` need not exist and is only used to determine the `ContentType` and
    /// `ContentDisposition` headers.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use ntex_files::NamedFile;
    /// use std::io::{self, Write};
    /// use std::env;
    /// use std::fs::File;
    ///
    /// fn main() -> io::Result<()> {
    ///     let mut file = File::create("foo.txt")?;
    ///     file.write_all(b"Hello, world!")?;
    ///     let named_file = NamedFile::from_file(file, "bar.txt")?;
    ///     # std::fs::remove_file("foo.txt");
    ///     Ok(())
    /// }
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
                mime::IMAGE | mime::TEXT | mime::VIDEO => file_header::DispositionType::Inline,
                _ => file_header::DispositionType::Attachment,
            };
            let parameters = vec![file_header::DispositionParam::Filename(
                file_header::Charset::Ext(String::from("UTF-8")),
                None,
                filename.into_owned().into_bytes(),
            )];
            let cd = file_header::ContentDisposition { disposition, parameters };
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
            encoding,
            status_code: StatusCode::OK,
            flags: Flags::default(),
        })
    }

    /// Attempts to open a file in read-only mode.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use ntex_files::NamedFile;
    ///
    /// let file = NamedFile::open("foo.txt");
    /// ```
    pub fn open<P: AsRef<Path>>(path: P) -> io::Result<NamedFile> {
        Self::from_file(File::open(&path)?, path)
    }

    /// Returns reference to the underlying `File` object.
    #[inline]
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Retrieve the path of this file.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use ntex_files::NamedFile;
    ///
    /// # fn path() -> std::io::Result<()> {
    /// let file = NamedFile::open("test.txt")?;
    /// assert_eq!(file.path().as_os_str(), "foo.txt");
    /// # Ok(())
    /// # }
    /// ```
    #[inline]
    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    /// Set response **Status Code**
    pub fn set_status_code(mut self, status: StatusCode) -> Self {
        self.status_code = status;
        self
    }

    /// Set the MIME Content-Type for serving this file. By default
    /// the Content-Type is inferred from the filename extension.
    #[inline]
    pub fn set_content_type(mut self, mime_type: mime::Mime) -> Self {
        self.content_type = mime_type;
        self
    }

    /// Set the Content-Disposition for serving this file. This allows
    /// changing the inline/attachment disposition as well as the filename
    /// sent to the peer. By default the disposition is `inline` for text,
    /// image, and video content types, and `attachment` otherwise, and
    /// the filename is taken from the path provided in the `open` method
    /// after converting it to UTF-8 using.
    /// [to_string_lossy](https://doc.rust-lang.org/std/ffi/struct.OsStr.html#method.to_string_lossy).
    #[inline]
    pub fn set_content_disposition(mut self, cd: file_header::ContentDisposition) -> Self {
        self.content_disposition = cd;
        self.flags.insert(Flags::CONTENT_DISPOSITION);
        self
    }

    /// Disable `Content-Disposition` header.
    ///
    /// By default Content-Disposition` header is enabled.
    #[inline]
    pub fn disable_content_disposition(mut self) -> Self {
        self.flags.remove(Flags::CONTENT_DISPOSITION);
        self
    }

    /// Set content encoding for serving this file
    #[inline]
    pub fn set_content_encoding(mut self, enc: ContentEncoding) -> Self {
        self.encoding = Some(enc);
        self
    }

    #[inline]
    ///Specifies whether to use ETag or not.
    ///
    ///Default is true.
    pub fn use_etag(mut self, value: bool) -> Self {
        self.flags.set(Flags::ETAG, value);
        self
    }

    #[inline]
    ///Specifies whether to use Last-Modified or not.
    ///
    ///Default is true.
    pub fn use_last_modified(mut self, value: bool) -> Self {
        self.flags.set(Flags::LAST_MD, value);
        self
    }

    pub(crate) fn etag(&self) -> Option<file_header::EntityTag> {
        // This etag format is similar to Apache's.
        self.modified.as_ref().map(|mtime| {
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

            let dur = mtime
                .duration_since(UNIX_EPOCH)
                .expect("modification time must be after epoch");
            file_header::EntityTag::strong(format!(
                "{:x}:{:x}:{:x}:{:x}",
                ino,
                self.md.len(),
                dur.as_secs(),
                dur.subsec_nanos()
            ))
        })
    }

    pub(crate) fn last_modified(&self) -> Option<file_header::HttpDate> {
        self.modified.map(|mtime| mtime.into())
    }

    pub fn into_response(self, req: &HttpRequest) -> HttpResponse {
        if self.status_code != StatusCode::OK {
            let mut resp = HttpResponse::build(self.status_code);
            resp.header(http::header::CONTENT_TYPE, self.content_type.to_string()).if_true(
                self.flags.contains(Flags::CONTENT_DISPOSITION),
                |res| {
                    res.header(
                        http::header::CONTENT_DISPOSITION,
                        self.content_disposition.to_string(),
                    );
                },
            );
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
            return resp.streaming(reader);
        }

        let etag = if self.flags.contains(Flags::ETAG) { self.etag() } else { None };
        let last_modified =
            if self.flags.contains(Flags::LAST_MD) { self.last_modified() } else { None };

        // check preconditions
        let precondition_failed = if !any_match(etag.as_ref(), req) {
            true
        } else if let (Some(ref m), Some(file_header::IfUnmodifiedSince(ref since))) = {
            let mut header = None;
            for hdr in req.headers().get_all(http::header::IF_UNMODIFIED_SINCE) {
                if let Ok(v) = file_header::IfUnmodifiedSince::parse_header(
                    &file_header::Raw::from(hdr.as_bytes()),
                ) {
                    header = Some(v);
                    break;
                }
            }

            (last_modified, header)
        } {
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
        let not_modified = if !none_match(etag.as_ref(), req) {
            true
        } else if req.headers().contains_key(&http::header::IF_NONE_MATCH) {
            false
        } else if let (Some(ref m), Some(file_header::IfModifiedSince(ref since))) = {
            let mut header = None;
            for hdr in req.headers().get_all(http::header::IF_MODIFIED_SINCE) {
                if let Ok(v) = file_header::IfModifiedSince::parse_header(
                    &file_header::Raw::from(hdr.as_bytes()),
                ) {
                    header = Some(v);
                    break;
                }
            }
            (last_modified, header)
        } {
            let t1: SystemTime = (*m).into();
            let t2: SystemTime = (*since).into();
            match (t1.duration_since(UNIX_EPOCH), t2.duration_since(UNIX_EPOCH)) {
                (Ok(t1), Ok(t2)) => t1 <= t2,
                _ => false,
            }
        } else {
            false
        };

        let mut resp = HttpResponse::build(self.status_code);
        resp.header(http::header::CONTENT_TYPE, self.content_type.to_string()).if_true(
            self.flags.contains(Flags::CONTENT_DISPOSITION),
            |res| {
                res.header(
                    http::header::CONTENT_DISPOSITION,
                    self.content_disposition.to_string(),
                );
            },
        );
        // default compressing
        if let Some(current_encoding) = self.encoding {
            resp.encoding(current_encoding);
        }

        resp.if_some(last_modified, |lm, resp| {
            resp.header(http::header::LAST_MODIFIED, file_header::LastModified(lm).to_string());
        })
        .if_some(etag, |etag, resp| {
            resp.header(http::header::ETAG, file_header::ETag(etag).to_string());
        });

        resp.header(http::header::ACCEPT_RANGES, "bytes");

        let mut length = self.md.len();
        let mut offset = 0;

        // check for range header
        if let Some(ranges) = req.headers().get(&http::header::RANGE) {
            if let Ok(rangesheader) = ranges.to_str() {
                if let Ok(rangesvec) = HttpRange::parse(rangesheader, length) {
                    length = rangesvec[0].length;
                    offset = rangesvec[0].start;
                    resp.encoding(ContentEncoding::Identity);
                    resp.header(
                        http::header::CONTENT_RANGE,
                        format!("bytes {}-{}/{}", offset, offset + length - 1, self.md.len()),
                    );
                } else {
                    resp.header(http::header::CONTENT_RANGE, format!("bytes */{}", length));
                    return resp.status(StatusCode::RANGE_NOT_SATISFIABLE).finish();
                };
            } else {
                return resp.status(StatusCode::BAD_REQUEST).finish();
            };
        };

        if precondition_failed {
            return resp.status(StatusCode::PRECONDITION_FAILED).finish();
        } else if not_modified {
            return resp.status(StatusCode::NOT_MODIFIED).finish();
        }

        let reader = ChunkedReadFile {
            offset,
            size: length,
            file: Some(self.file),
            fut: None,
            counter: 0,
        };
        if offset != 0 || length != self.md.len() {
            resp.status(StatusCode::PARTIAL_CONTENT).streaming(reader)
        } else {
            resp.body(SizedStream::new(
                length,
                reader.map_err(|e| {
                    let e: Rc<dyn Error> = Rc::new(e);
                    e
                }),
            ))
        }
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

/// Returns true if `req` has no `If-Match` header or one which matches `etag`.
fn any_match(etag: Option<&file_header::EntityTag>, req: &HttpRequest) -> bool {
    if let Some(val) = req.headers().get(http::header::IF_MATCH) {
        let hdr = ::http::HeaderValue::from(val);
        if let Ok(val) = file_header::IfMatch::parse_header(&&hdr) {
            match val {
                file_header::IfMatch::Any => return true,
                file_header::IfMatch::Items(ref items) => {
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
    }
    true
}

/// Returns true if `req` doesn't have an `If-None-Match` header matching `req`.
fn none_match(etag: Option<&file_header::EntityTag>, req: &HttpRequest) -> bool {
    if let Some(val) = req.headers().get(http::header::IF_NONE_MATCH) {
        let hdr = ::http::HeaderValue::from(val);
        if let Ok(val) = file_header::IfNoneMatch::parse_header(&&hdr) {
            return match val {
                file_header::IfNoneMatch::Any => false,
                file_header::IfNoneMatch::Items(ref items) => {
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
    }
    true
}

impl<Err: ErrorRenderer> Responder<Err> for NamedFile {
    async fn respond_to(self, req: &HttpRequest) -> HttpResponse {
        self.into_response(req)
    }
}
