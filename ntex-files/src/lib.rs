#![allow(
    type_alias_bounds,
    clippy::borrow_interior_mutable_const,
    clippy::type_complexity,
    clippy::result_unit_err,
    clippy::enum_variant_names
)]

//! Static file and directory serving for [`ntex::web`].
//!
//! Register [`Files`] with [`App::service`](ntex::web::App::service) to serve a
//! directory, or return a [`NamedFile`] from a handler to serve a single file.
//! File responses support conditional requests and byte ranges.
//!
//! ```
//! use ntex::web::{self, App};
//! use ntex_files::{Files, NamedFile};
//!
//! async fn download() -> std::io::Result<NamedFile> {
//!     NamedFile::open("./manual.pdf")
//! }
//!
//! let app = App::default()
//!     .service(Files::new("/static", ".").index_file("index.html"))
//!     .route("/manual", web::get().to(download));
//! ```
//!
//! [`Files`] has no index file, directory listing, or directory redirect by
//! default. It accepts `GET` and `HEAD`, rejects URL segments beginning with
//! `.`, and confines resolved paths to its base directory unless
//! [`Files::follow_symlinks`] is enabled. See [`NamedFile::into_response`] for
//! response headers and status codes.
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::fs::{DirEntry, File, Metadata};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};
use std::{cmp, fmt, fmt::Write, io, pin::Pin, rc::Rc, sync::Arc, task::Context, task::Poll};

use futures::{Future, Stream, future::FutureExt, future::LocalBoxFuture};
use mime_guess::from_ext;
use ntex::error::{Failure, IntoFailure};
use ntex::http::header::{ACCEPT_ENCODING, ContentEncoding, HeaderMap, HeaderValue, VARY};
use ntex::http::{Method, Payload, RequestHead, error::BlockingError};
use ntex::router::{ResourceDef, ResourcePath};
use ntex::service::boxed::{self, BoxService, BoxServiceFactory};
use ntex::time::Millis;
use ntex::url::Url;
use ntex::util::{Bytes, BytesMut};
use ntex::web::dev::{WebServiceConfig, WebServiceFactory};
use ntex::web::error::{WebError, WebResponseError};
use ntex::web::guard::Guard;
use ntex::web::{self, FromRequest, HttpRequest, HttpResponse, State, WebRequest, WebResponse};
use ntex::{Ctx, IntoServiceFactory, Service, ServiceFactory};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};

mod error;
/// Typed HTTP headers used by static file responses.
pub mod header;
mod named;
mod range;

use self::error::{FilesError, UriSegmentError};
pub use crate::{
    named::{NamedFile, NamedFileService},
    range::{HttpRange, ParseRangeErr},
};

type HttpService<St: State, In> =
    BoxService<St, WebRequest<In>, WebResponse, WebError<St, St::Error>>;
type HttpServiceFactory<St: State, In> =
    BoxServiceFactory<St, WebRequest<In>, WebResponse, WebError<St, St::Error>, Failure>;

/// Return the MIME type associated with a filename extension (case-insensitive).
/// If `ext` is empty or no associated type for the extension was found, returns
/// the type `application/octet-stream`.
#[inline]
pub fn file_extension_to_mime(ext: &str) -> mime::Mime {
    from_ext(ext).first_or_octet_stream()
}

#[doc(hidden)]
/// A file stream that reads chunks of up to 64 KiB.
///
/// Chunks are read on the blocking thread pool, or on the current thread when
/// `sync` is set. Read failures, premature end of file, and canceled blocking
/// tasks yield an [`io::Error`]; the stream ends after an error.
pub struct ChunkedReadFile {
    size: u64,
    offset: u64,
    file: Option<File>,
    fut: Option<LocalBoxFuture<'static, Result<(File, Bytes), BlockingError<io::Error>>>>,
    counter: u64,
    sync: bool,
}

/// Reads up to `max_bytes` at `offset`; fewer bytes are returned only at end of file.
fn read_chunk(file: File, offset: u64, max_bytes: usize) -> io::Result<(File, Bytes)> {
    let mut buf = BytesMut::with_capacity(max_bytes);
    read_into(&file, &mut buf, offset, max_bytes)?;
    if buf.is_empty() {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok((file, buf.freeze()))
}

/// Appends up to `max_bytes` read at `offset` to the empty `buf`, reading into
/// the spare capacity without initializing it first.
#[cfg(all(unix, target_pointer_width = "64"))]
fn read_into(file: &File, buf: &mut BytesMut, offset: u64, max_bytes: usize) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let mut w = buf.spare_writer(max_bytes);
    while w.len() < max_bytes {
        let filled = w.len();
        let pos = libc::off_t::try_from(offset + filled as u64)
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let spare = &mut w.spare_capacity_mut()[..max_bytes - filled];
        // SAFETY: `pread` writes at most `spare.len()` bytes into `spare`
        let n = unsafe {
            libc::pread(
                file.as_raw_fd(),
                spare.as_mut_ptr().cast(),
                spare.len(),
                pos,
            )
        };
        match usize::try_from(n) {
            Ok(0) => break,
            // SAFETY: `pread` initialized the first `n` bytes of the spare capacity
            Ok(n) => unsafe { w.advance(n) },
            Err(_) => {
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::Interrupted {
                    return Err(e);
                }
            }
        }
    }
    Ok(())
}

/// Appends up to `max_bytes` read at `offset` to the empty `buf`.
#[cfg(not(all(unix, target_pointer_width = "64")))]
fn read_into(file: &File, buf: &mut BytesMut, offset: u64, max_bytes: usize) -> io::Result<()> {
    buf.resize(max_bytes, 0);
    let mut nbytes = 0;
    let res = loop {
        if nbytes == max_bytes {
            break Ok(());
        }
        match read_at(file, &mut buf[nbytes..], offset + nbytes as u64) {
            Ok(0) => break Ok(()),
            Ok(n) => nbytes += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => break Err(e),
        }
    };
    buf.truncate(nbytes);
    res
}

// 32-bit targets may have a 32-bit `off_t`, std picks the 64-bit `pread` variant
#[cfg(all(unix, not(target_pointer_width = "64")))]
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(file, buf, offset)
}

#[cfg(windows)]
fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(file, buf, offset)
}

#[cfg(not(any(unix, windows)))]
fn read_at(mut file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::io::{Read, Seek};

    file.seek(io::SeekFrom::Start(offset))?;
    file.read(buf)
}

impl Stream for ChunkedReadFile {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        if let Some(ref mut fut) = self.fut {
            return match Pin::new(fut).poll(cx) {
                Poll::Ready(Ok((file, bytes))) => {
                    self.fut.take();
                    self.file = Some(file);
                    self.offset += bytes.len() as u64;
                    self.counter += bytes.len() as u64;
                    Poll::Ready(Some(Ok(bytes)))
                }
                Poll::Ready(Err(e)) => {
                    let e = match e {
                        BlockingError::Error(e) => e,
                        BlockingError::Canceled => io::Error::other("Operation is canceled"),
                    };
                    // the file is consumed by the failed read, so the stream ends here
                    self.fut.take();
                    Poll::Ready(Some(Err(e)))
                }
                Poll::Pending => Poll::Pending,
            };
        }

        let size = self.size;
        let offset = self.offset;
        let counter = self.counter;

        if size == counter {
            Poll::Ready(None)
        } else {
            let Some(file) = self.file.take() else {
                return Poll::Ready(None);
            };
            let max_bytes = cmp::min(size.saturating_sub(counter), 65_536) as usize;
            if self.sync {
                // the file is consumed by a failed read, so the stream ends after an error
                return Poll::Ready(Some(read_chunk(file, offset, max_bytes).map(
                    |(file, bytes)| {
                        self.file = Some(file);
                        self.offset += bytes.len() as u64;
                        self.counter += bytes.len() as u64;
                        bytes
                    },
                )));
            }
            self.fut = Some(web::block(move || read_chunk(file, offset, max_bytes)).boxed_local());
            self.poll_next(cx)
        }
    }
}

type DirectoryRenderer = dyn Fn(&Directory, &HttpRequest) -> Result<WebResponse, io::Error>;

/// Directory paths passed to a [`Files::files_listing_renderer`] callback.
///
/// This type does not itself generate a response.
#[derive(Debug)]
pub struct Directory {
    /// Base directory configured for the static file service.
    pub base: PathBuf,
    /// Resolved directory for which a listing is requested.
    pub path: PathBuf,
}

impl Directory {
    /// Stores the base and listing paths without accessing or validating them.
    pub fn new(base: PathBuf, path: PathBuf) -> Directory {
        Directory { base, path }
    }

    /// Returns whether an entry is eligible for the default directory listing.
    ///
    /// Excludes names beginning with `.`, failed entries, and entries whose
    /// metadata cannot be read. Files, directories, and symlinks are eligible;
    /// this check does not enforce containment within [`Self::base`].
    pub fn is_visible(&self, entry: &io::Result<DirEntry>) -> bool {
        if let Ok(ref entry) = *entry {
            if let Some(name) = entry.file_name().to_str()
                && name.starts_with('.')
            {
                return false;
            }
            if let Ok(ref md) = entry.metadata() {
                let ft = md.file_type();
                return ft.is_dir() || ft.is_file() || ft.is_symlink();
            }
        }
        false
    }
}

// characters that must be percent-encoded in a file name used as an url path segment
const FILE_NAME_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'\'')
    .add(b'/')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'\\')
    .add(b'`');

// " -- &quot;  & -- &amp;  ' -- &#x27;  < -- &lt;  > -- &gt;  / -- &#x2f;
macro_rules! encode_file_name {
    ($entry:ident) => {
        v_htmlescape::escape_fmt(&$entry.file_name().to_string_lossy())
    };
}

// escape characters that are significant inside of a quoted html attribute
fn escape_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    v_html5escape::escape_string(s, &mut out);
    out
}

fn directory_listing(dir: &Directory, req: &HttpRequest) -> Result<WebResponse, io::Error> {
    const INDEX_OF: &str = "Index of ";
    let path = req.path();
    let mut index_of = String::with_capacity(INDEX_OF.len() + path.len());
    index_of.push_str(INDEX_OF);
    v_htmlescape::escape_string(req.path(), &mut index_of);
    let mut body = String::new();
    let base = req.path().trim_end_matches('/');

    for entry in dir.path.read_dir()? {
        if dir.is_visible(&entry) {
            let entry = entry.unwrap();
            let href = format!(
                "{}/{}",
                base,
                utf8_percent_encode(&entry.file_name().to_string_lossy(), FILE_NAME_ENCODE_SET)
            );
            let href = escape_attr(&href);

            // if file is a directory, add '/' to the end of the name
            if let Ok(metadata) = entry.metadata() {
                if metadata.is_dir() {
                    let _ = write!(
                        body,
                        "<li><a href=\"{}\">{}/</a></li>",
                        href,
                        encode_file_name!(entry),
                    );
                } else {
                    let _ = write!(
                        body,
                        "<li><a href=\"{}\">{}</a></li>",
                        href,
                        encode_file_name!(entry),
                    );
                }
            } else {
                continue;
            }
        }
    }

    let html = format!(
        "<html>\
         <head><title>{}</title></head>\
         <body><h1>{}</h1>\
         <ul>\
         {}\
         </ul></body>\n</html>",
        index_of, index_of, body
    );
    Ok(WebResponse::new(
        HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .body(html),
        req.clone(),
    ))
}

type MimeOverride = dyn Fn(&mime::Name) -> header::DispositionType;

type PathFilter = dyn Fn(&Path, &RequestHead) -> bool;

/// A configurable service factory for serving a directory of static files.
///
/// Register it with [`App::service`](ntex::web::App::service). The URL `path`
/// is a prefix; the remaining path selects a file under the base directory.
/// Defaults are `GET`/`HEAD` only, no index file, no directory listing, no
/// redirect, and enabled `Content-Disposition`, `ETag`, and `Last-Modified`.
///
/// URL segments are validated after percent-decoding: leading `.` or `*`,
/// trailing `:`, `>` or `<`, embedded `/` or NUL, and, on Windows, `\` are
/// rejected with `400 Bad Request`. Literal `..` segments remove a preceding
/// relative segment without escaping the base; percent-encoded `..` is rejected.
/// Resolved paths outside the base, including symlink targets and index files,
/// are rejected unless [`Self::follow_symlinks`] is enabled.
///
/// With the default web error handler, rejected methods or [`Self::use_guards`]
/// guards return `405 Method Not Allowed`; resolution failures and directories
/// without a listing return `404 Not Found`. Requests rejected by
/// [`Self::guard`] are routed to other services. [`Self::default_handler`] handles resolution
/// failures only.
///
/// ```rust
/// use ntex::web::App;
/// use ntex_files as fs;
///
/// let app = App::default()
///    .service(fs::Files::new("/static", "."));
/// ```
pub struct Files<St: State, In> {
    path: String,
    directory: PathBuf,
    canonical: bool,
    index: Option<String>,
    show_index: bool,
    redirect_to_slash: bool,
    permanent_redirect: bool,
    default: Option<HttpServiceFactory<St, In>>,
    renderer: Rc<DirectoryRenderer>,
    mime_override: Option<Rc<MimeOverride>>,
    file_flags: named::Flags,
    read_mode_threshold: u64,
    guards: Option<Rc<dyn Guard>>,
    resource_guards: Vec<Rc<dyn Guard>>,
    follow_symlinks: bool,
    hidden_files: bool,
    try_compressed: bool,
    path_filter: Option<Rc<PathFilter>>,
    cache: Option<Rc<MetaCache>>,
}

impl<St: State, In> Clone for Files<St, In> {
    fn clone(&self) -> Self {
        Self {
            directory: self.directory.clone(),
            canonical: self.canonical,
            index: self.index.clone(),
            show_index: self.show_index,
            redirect_to_slash: self.redirect_to_slash,
            permanent_redirect: self.permanent_redirect,
            default: self.default.clone(),
            renderer: self.renderer.clone(),
            file_flags: self.file_flags.clone(),
            read_mode_threshold: self.read_mode_threshold,
            path: self.path.clone(),
            mime_override: self.mime_override.clone(),
            guards: self.guards.clone(),
            resource_guards: self.resource_guards.clone(),
            follow_symlinks: self.follow_symlinks,
            hidden_files: self.hidden_files,
            try_compressed: self.try_compressed,
            path_filter: self.path_filter.clone(),
            cache: self.cache.clone(),
        }
    }
}

impl<St: State, In: 'static> Files<St, In> {
    /// Creates a service at the URL prefix `path` with filesystem base `dir`.
    ///
    /// Canonicalizes `dir` immediately. If this fails, logs the error and retains
    /// the supplied path; later request resolution may still fail. Resolution,
    /// metadata access, and file opening for requests run on the web worker
    /// unless [`Self::open_on_thread_pool`] is set. Files smaller than
    /// [`Self::read_mode_threshold`] are read on the web worker, larger files on
    /// the blocking thread pool. Directory rendering runs on the web worker.
    /// Resolved files are kept in a metadata cache, see [`Self::metadata_cache`].
    ///
    /// Request resolution failures use [`Self::default_handler`] when configured,
    /// or return `404 Not Found` with the default web error handler.
    pub fn new<T: Into<PathBuf>>(path: &str, dir: T) -> Self {
        let orig_dir = dir.into();
        let (dir, canonical) = match orig_dir.canonicalize() {
            Ok(canon_dir) => (canon_dir, cfg!(unix)),
            Err(e) => {
                log::error!("Cannot resolve static files directory {orig_dir:?}: {e}");
                (orig_dir, false)
            }
        };

        Files {
            path: path.to_string(),
            directory: dir,
            canonical,
            index: None,
            show_index: false,
            redirect_to_slash: false,
            permanent_redirect: false,
            default: None,
            renderer: Rc::new(directory_listing),
            mime_override: None,
            file_flags: named::Flags::default(),
            read_mode_threshold: named::DEFAULT_READ_MODE_THRESHOLD,
            guards: None,
            resource_guards: Vec::new(),
            follow_symlinks: false,
            hidden_files: false,
            try_compressed: false,
            path_filter: None,
            cache: MetaCache::new(DEFAULT_CACHE_CAPACITY, DEFAULT_CACHE_TTL),
        }
    }

    /// Sets the capacity and entry lifetime of the metadata cache.
    ///
    /// Defaults to 1024 entries for 1 second; `0` for either value disables the
    /// cache. Each worker caches, per request path, a file found below the base
    /// without crossing a symlink and its precompressed siblings. A cached
    /// path skips the per-component lookup: the file is opened without following
    /// a final symlink and served only if it is still the cached file, compared
    /// by device and inode; otherwise the path is resolved again. Length,
    /// modification time, and contents always come from the opened file, so
    /// files rewritten or replaced on disk are served with their new contents.
    ///
    /// Until an entry expires, a precompressed sibling created after the path
    /// was cached is not served, a cached sibling is still served after the
    /// original file is removed, and a cached file moved outside the base is
    /// still served if a symlinked parent directory leads to it from its old path.
    ///
    /// The cache is used only on Unix with a canonicalized base and is bypassed
    /// with [`Self::open_on_thread_pool`]. Directories and index files are not
    /// cached. Clones of this service share the cache.
    pub fn metadata_cache(mut self, capacity: usize, ttl: Millis) -> Self {
        self.cache = MetaCache::new(capacity, ttl.into());
        self
    }

    /// Allows resolved files and directories outside the base when `value` is `true`.
    ///
    /// Defaults to `false`. Symlinks whose targets remain inside the base are
    /// followed regardless of this setting. Rejected outside targets use the
    /// default handler, or `404 Not Found` with the default web error handler.
    /// URL segment validation remains enabled.
    pub fn follow_symlinks(mut self, value: bool) -> Self {
        self.follow_symlinks = value;
        self
    }

    /// Enables directory listings when no index file is configured.
    ///
    /// Disabled by default. The default HTML renderer excludes dot-prefixed
    /// entries and entries with unreadable metadata. A configured but missing
    /// index file uses the default handler or returns `404 Not Found`; it does
    /// not fall back to a listing.
    pub fn show_files_listing(mut self) -> Self {
        self.show_index = true;
        self
    }

    /// Enables redirects to slash-ended directory paths.
    ///
    /// Disabled by default, and only effective when an index file or directory
    /// listings are configured. The redirect uses the request path with `/`
    /// appended, without its query string, before attempting to open the index
    /// file or render the listing. It uses `302 Found` unless
    /// [`Self::with_permanent_redirect`] is set.
    pub fn redirect_to_slash_directory(mut self) -> Self {
        self.redirect_to_slash = true;
        self
    }

    /// Uses `308 Permanent Redirect` for slash-ended directory redirects.
    ///
    /// Redirects use `302 Found` by default. This does not enable redirects;
    /// call [`Self::redirect_to_slash_directory`] separately.
    pub fn with_permanent_redirect(mut self) -> Self {
        self.permanent_redirect = true;
        self
    }

    /// Sets the renderer used when directory listings are enabled.
    ///
    /// The callback runs on the web worker and must construct a [`WebResponse`].
    /// Returning an [`io::Error`] produces `404 Not Found` with the default web
    /// error handler; the default handler is not invoked. This does not enable
    /// listings; call [`Self::show_files_listing`] separately.
    pub fn files_listing_renderer<F>(mut self, f: F) -> Self
    where
        for<'r, 's> F:
            Fn(&'r Directory, &'s HttpRequest) -> Result<WebResponse, io::Error> + 'static,
    {
        self.renderer = Rc::new(f);
        self
    }

    /// Overrides the disposition type based on the file's top-level MIME type.
    ///
    /// The callback receives, for example, `text` or `application`, not a MIME
    /// subtype. It changes `inline`/`attachment` selection, not `Content-Type`
    /// or filename parameters. See [`NamedFile::from_file`] for the defaults.
    pub fn mime_override<F>(mut self, f: F) -> Self
    where
        F: Fn(&mime::Name) -> header::DispositionType + 'static,
    {
        self.mime_override = Some(Rc::new(f));
        self
    }

    /// Sets the index path to open for every requested directory.
    ///
    /// No index is configured by default. The path is joined to the requested
    /// directory and takes precedence over listings. Missing or rejected index
    /// paths use the default handler or return `404 Not Found` with the default
    /// web error handler; they do not fall back to a listing.
    pub fn index_file<T: Into<String>>(mut self, index: T) -> Self {
        self.index = Some(index.into());
        self
    }

    #[inline]
    /// Enables or disables metadata-derived `ETag` headers and tag validators.
    ///
    /// Defaults to `true`. See [`NamedFile::use_etag`] for availability and
    /// conditional request behavior.
    pub fn use_etag(mut self, value: bool) -> Self {
        self.file_flags.set(named::Flags::ETAG, value);
        self
    }

    #[inline]
    /// Enables or disables `Last-Modified` headers and date validators.
    ///
    /// Defaults to `true`. See [`NamedFile::use_last_modified`] for the supported
    /// timestamp range.
    pub fn use_last_modified(mut self, value: bool) -> Self {
        self.file_flags.set(named::Flags::LAST_MD, value);
        self
    }

    #[inline]
    /// Enables or disables the UTF-8 charset for text content types.
    ///
    /// Defaults to `true`. See [`NamedFile::prefer_utf8`] for the affected types.
    pub fn prefer_utf8(mut self, value: bool) -> Self {
        self.file_flags.set(named::Flags::PREFER_UTF8, value);
        self
    }

    #[inline]
    /// Sets the body size below which file chunks are read on the web worker.
    ///
    /// Defaults to 512 KiB. Use `0` to run all reads on the blocking thread pool.
    /// See [`NamedFile::read_mode_threshold`]. Path resolution and file opening
    /// are controlled separately by [`Self::open_on_thread_pool`].
    pub fn read_mode_threshold(mut self, size: u64) -> Self {
        self.read_mode_threshold = size;
        self
    }

    #[inline]
    /// Resolves paths and opens files on the blocking thread pool when `value` is `true`.
    ///
    /// Defaults to `false`, so path resolution, metadata access, precompressed
    /// sibling lookup, and file opening run on the web worker. This avoids a
    /// thread pool round trip per request, but a slow filesystem, such as a
    /// network mount or an uncached disk, blocks the worker. File reads are
    /// controlled separately by [`Self::read_mode_threshold`]. The
    /// [`Self::metadata_cache`] is not used when this is enabled.
    pub fn open_on_thread_pool(mut self, value: bool) -> Self {
        self.file_flags.set(named::Flags::POOL_OPEN, value);
        self
    }

    #[inline]
    /// Allows serving files and directories whose path segments start with a dot.
    ///
    /// Disabled by default, so such requests return `400 Bad Request`. The `.`
    /// and `..` segments are still rejected after decoding, resolved paths must
    /// stay inside the base unless [`Self::follow_symlinks`] is set, and directory
    /// listings still omit dot entries.
    pub fn use_hidden_files(mut self) -> Self {
        self.hidden_files = true;
        self
    }

    /// Serves precompressed sibling files when the client accepts their encoding.
    ///
    /// Disabled by default. For a resolved file, including an index file, looks
    /// for a sibling with a `.br`, `.zst`, or `.gz` suffix, for example
    /// `app.js.gz`, in the order of the `Accept-Encoding` header's `q` values;
    /// ties prefer `br`, then `zstd`, then `gzip`, and `q=0` excludes an encoding.
    /// The original file must exist; siblings are subject to the same base
    /// directory checks and are ignored if they cannot be opened.
    ///
    /// A sibling is served with `Content-Encoding` set to its encoding, so the
    /// compress middleware leaves it unchanged. `Content-Type` and
    /// `Content-Disposition` come from the original file name, while `ETag`,
    /// `Last-Modified`, length, and ranges come from the sibling. Every file
    /// response, including one for the original file, carries
    /// `Vary: accept-encoding`.
    pub fn try_compressed(mut self) -> Self {
        self.try_compressed = true;
        self
    }

    /// Sets a filter that accepts or rejects request paths before filesystem access.
    ///
    /// The filter receives the decoded path relative to the base directory, after
    /// URL segment validation, and the request head. Returning `false` rejects
    /// the request like a missing file: it uses [`Self::default_handler`] when
    /// configured, or returns `404 Not Found` with the default web error handler.
    /// The filter applies to the requested path only, not to symlink targets or
    /// index files.
    ///
    /// ```rust
    /// use ntex::web::App;
    /// use ntex_files::Files;
    ///
    /// let app = App::default().service(
    ///     Files::new("/static", ".")
    ///         .path_filter(|path, _| path.extension().is_none_or(|ext| ext != "toml")),
    /// );
    /// ```
    pub fn path_filter<F>(mut self, f: F) -> Self
    where
        F: Fn(&Path, &RequestHead) -> bool + 'static,
    {
        self.path_filter = Some(Rc::new(f));
        self
    }

    /// Adds a resource guard that selects this service during routing.
    ///
    /// Can be called multiple times; all guards must match. A request that does
    /// not match is routed to the next matching service or the application
    /// default service, unlike [`Self::use_guards`] which rejects requests that
    /// already selected this service. Use it, for example, with
    /// [`guard::Host`](ntex::web::guard::Host) to serve files for one host only.
    pub fn guard<G: Guard + 'static>(mut self, guard: G) -> Self {
        self.resource_guards.push(Rc::new(guard));
        self
    }

    /// Replaces the default `GET`/`HEAD` check with a custom guard.
    ///
    /// A failed guard returns `405 Method Not Allowed` with the default web
    /// error handler; the default handler is not invoked. A successful guard
    /// can permit other methods for both files and directory listings.
    #[inline]
    pub fn use_guards<G: Guard + 'static>(mut self, guards: G) -> Self {
        self.guards = Some(Rc::new(guards));
        self
    }

    /// Disables the `Content-Disposition` header for file responses.
    ///
    /// This header is enabled by default; see [`NamedFile::from_file`] for its
    /// MIME-based disposition and filename parameters.
    #[inline]
    pub fn disable_content_disposition(mut self) -> Self {
        self.file_flags.remove(named::Flags::CONTENT_DISPOSITION);
        self
    }

    /// Sets the fallback service for file resolution or opening failures.
    ///
    /// This includes missing files and index files, rejected outside-base
    /// targets, paths rejected by [`Self::path_filter`], and canceled blocking
    /// resolution tasks. It is not used for
    /// invalid URL segments, rejected guards, disabled listings, listing renderer
    /// errors, or errors while streaming an already opened file.
    pub fn default_handler<F, U>(mut self, f: F) -> Self
    where
        F: IntoServiceFactory<U, St, WebRequest<In>>,
        U: ServiceFactory<St, WebRequest<In>, Res = WebResponse> + 'static,
        U::Error: WebResponseError<St, St::Error>,
        U::InitError: IntoFailure,
    {
        // create and configure default resource
        self.default = Some(boxed::factory(
            f.into_factory()
                .map_err(WebError::from_err)
                .map_init_err(IntoFailure::fail),
        ));

        self
    }
}

impl<St: State, In: 'static> WebServiceFactory<St, In> for Files<St, In>
where
    FilesError: WebResponseError<St, St::Error>,
{
    fn register(self, config: &mut WebServiceConfig<St, In>) {
        let rdef = if config.is_root() {
            ResourceDef::root_prefix(&self.path)
        } else {
            ResourceDef::prefix(&self.path)
        };
        let guards = if self.resource_guards.is_empty() {
            None
        } else {
            Some(
                self.resource_guards
                    .iter()
                    .map(|guard| Box::new(SharedGuard(guard.clone())) as Box<dyn Guard>)
                    .collect(),
            )
        };
        config.register_service(rdef, guards, None, self)
    }
}

/// A guard shared between clones of a [`Files`] configuration.
struct SharedGuard(Rc<dyn Guard>);

impl Guard for SharedGuard {
    fn check(&self, request: &ntex::http::RequestHead) -> bool {
        self.0.check(request)
    }

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<St: State, In> ServiceFactory<St, WebRequest<In>> for Files<St, In>
where
    In: 'static,
    FilesError: WebResponseError<St, St::Error>,
{
    type Res = WebResponse;
    type Error = WebError<St, St::Error>;

    type Service = FilesService<St, In>;
    type InitError = Failure;

    async fn create(&self, cfg: &St) -> Result<Self::Service, Self::InitError> {
        let mut srv = FilesService {
            directory: self.directory.clone(),
            canonical: self.canonical,
            index: self.index.clone(),
            show_index: self.show_index,
            redirect_to_slash: self.redirect_to_slash,
            permanent_redirect: self.permanent_redirect,
            default: None,
            renderer: self.renderer.clone(),
            mime_override: self.mime_override.clone(),
            file_flags: self.file_flags.clone(),
            read_mode_threshold: self.read_mode_threshold,
            guards: self.guards.clone(),
            follow_symlinks: self.follow_symlinks,
            hidden_files: self.hidden_files,
            try_compressed: self.try_compressed,
            path_filter: self.path_filter.clone(),
            cache: if self.canonical && !self.file_flags.contains(named::Flags::POOL_OPEN) {
                self.cache.clone()
            } else {
                None
            },
        };

        if let Some(default) = self.default.as_ref() {
            default
                .create(cfg)
                .map(move |result| match result {
                    Ok(default) => {
                        srv.default = Some(default);
                        Ok(srv)
                    }
                    Err(e) => Err(e),
                })
                .await
        } else {
            Ok(srv)
        }
    }
}

/// The request-handling service created by the [`Files`] service factory.
///
/// Configure serving behavior through [`Files`] before creating this service.
pub struct FilesService<St: State, In> {
    directory: PathBuf,
    canonical: bool,
    index: Option<String>,
    show_index: bool,
    redirect_to_slash: bool,
    permanent_redirect: bool,
    default: Option<HttpService<St, In>>,
    renderer: Rc<DirectoryRenderer>,
    mime_override: Option<Rc<MimeOverride>>,
    file_flags: named::Flags,
    read_mode_threshold: u64,
    guards: Option<Rc<dyn Guard>>,
    follow_symlinks: bool,
    hidden_files: bool,
    try_compressed: bool,
    path_filter: Option<Rc<PathFilter>>,
    cache: Option<Rc<MetaCache>>,
}

impl<St: State, In> FilesService<St, In>
where
    FilesError: WebResponseError<St, St::Error>,
{
    async fn handle_io_error(
        &self,
        e: io::Error,
        req: WebRequest<In>,
        ctx: Ctx<'_, Self, St>,
    ) -> Result<WebResponse, WebError<St, St::Error>> {
        log::debug!("Files: Failed to handle {}: {}", req.path(), e);
        if let Some(ref default) = self.default {
            Ok(ctx.call(default, req).await?)
        } else {
            Ok(req.error_response(ctx.st(), &FilesError::from(e)))
        }
    }
}

impl<St: State, In> Service<St, WebRequest<In>> for FilesService<St, In>
where
    FilesError: WebResponseError<St, St::Error>,
{
    type Res = WebResponse;
    type Error = WebError<St, St::Error>;

    async fn call(
        &self,
        req: WebRequest<In>,
        ctx: Ctx<'_, Self, St>,
    ) -> Result<Self::Res, Self::Error> {
        let is_method_valid = if let Some(guard) = &self.guards {
            // execute user defined guards
            (**guard).check(req.head())
        } else {
            // default behaviour
            matches!(*req.method(), Method::HEAD | Method::GET)
        };

        if !is_method_valid {
            return Ok(req.error_response(ctx.st(), &FilesError::MethodNotAllowed));
        }

        let real_path = match PathBufWrp::get_pathbuf(req.match_info().path(), self.hidden_files) {
            Ok(item) => item,
            Err(e) => return Ok(req.error_response(ctx.st(), &FilesError::from(e))),
        };

        if let Some(filter) = &self.path_filter
            && !filter(&real_path.0, req.head())
        {
            let e = io::Error::new(io::ErrorKind::NotFound, "Path is filtered");
            return self.handle_io_error(e, req, ctx).await;
        }

        let redirect = self.redirect_to_slash
            && (self.index.is_some() || self.show_index)
            && !req.path().ends_with('/');
        let encodings = if self.try_compressed {
            accepted_encodings(req.headers())
        } else {
            Vec::new()
        };
        let opts = ResolveOpts {
            canonical: self.canonical,
            follow_symlinks: self.follow_symlinks,
            hidden_files: self.hidden_files,
        };
        let target = if self.file_flags.contains(named::Flags::POOL_OPEN) {
            let directory = self.directory.clone();
            let index = self.index.clone();
            let path = real_path.0;
            let target = web::block(move || {
                resolve(
                    &directory,
                    &path,
                    index.as_deref(),
                    redirect,
                    opts,
                    &encodings,
                    None,
                )
            })
            .await;
            match target {
                Ok(target) => Ok(target),
                Err(BlockingError::Error(e)) => Err(e),
                Err(BlockingError::Canceled) => Err(io::Error::other("Operation is canceled")),
            }
        } else {
            resolve(
                &self.directory,
                &real_path.0,
                self.index.as_deref(),
                redirect,
                opts,
                &encodings,
                self.cache.as_deref(),
            )
        };

        match target {
            Ok(Target::File(mut named_file)) => {
                if let Some(ref mime_override) = self.mime_override {
                    let new_disposition = mime_override(&named_file.content_type.type_());
                    named_file.content_disposition.disposition = new_disposition;
                }

                named_file.flags = self.file_flags.clone();
                named_file.read_mode_threshold = self.read_mode_threshold;
                let (req, _, _) = req.into_parts();
                let mut resp = (*named_file).into_response(&req);
                if self.try_compressed {
                    resp.headers_mut()
                        .append(VARY, HeaderValue::from_static("accept-encoding"));
                }
                Ok(WebResponse::new(resp, req))
            }
            Ok(Target::Redirect) => {
                let redirect_to = format!("{}/", req.path());
                let mut resp = if self.permanent_redirect {
                    HttpResponse::PermanentRedirect()
                } else {
                    HttpResponse::Found()
                };
                Ok(req.into_response(
                    resp.header(http::header::LOCATION, redirect_to)
                        .body("")
                        .into_body(),
                ))
            }
            Ok(Target::Dir(path)) => {
                if self.show_index {
                    let dir = Directory::new(self.directory.clone(), path);
                    let (req, _, _) = req.into_parts();
                    match (self.renderer)(&dir, &req) {
                        Ok(resp) => Ok(resp),
                        Err(e) => Ok(WebResponse::from_err(ctx.st(), &FilesError::from(e), req)),
                    }
                } else {
                    Ok(WebResponse::from_err(
                        ctx.st(),
                        &FilesError::IsDirectory,
                        req.into_parts().0,
                    ))
                }
            }
            Err(e) => self.handle_io_error(e, req, ctx).await,
        }
    }
}

/// Filesystem object a request path resolves to.
enum Target {
    File(Box<NamedFile>),
    Dir(PathBuf),
    Redirect,
}

/// Options for [`resolve`].
#[derive(Clone, Copy)]
struct ResolveOpts {
    /// The base directory was canonicalized on Unix, so symlink-free paths below it
    /// are canonical as they are.
    canonical: bool,
    follow_symlinks: bool,
    hidden_files: bool,
}

/// Resolves a request path inside of `directory`.
///
/// Runs on the web worker, or on the blocking thread pool when
/// [`Files::open_on_thread_pool`] is set.
///
/// A canonical path outside of `directory` is reported as not found,
/// unless `follow_symlinks` is set. On Windows, a canonical path with a hidden
/// component is reported as not found as well, unless `hidden_files` is set.
/// A resolved file is replaced by the first contained precompressed sibling
/// for `encodings`.
///
/// With a canonical base, a path is looked up one component at a time without
/// canonicalization; it falls back to canonicalization when it crosses a symlink.
/// The base itself is resolved once, so later changes to its ancestors are not
/// checked, and names keep the request's case on case-insensitive filesystems.
/// Regular files found this way are served from and added to `cache`.
fn resolve(
    directory: &Path,
    path: &Path,
    index: Option<&str>,
    redirect: bool,
    opts: ResolveOpts,
    encodings: &[ContentEncoding],
    cache: Option<&MetaCache>,
) -> io::Result<Target> {
    if let Some(cache) = cache
        && let Some(file) = cache.get(path, encodings)
    {
        return Ok(Target::File(Box::new(file)));
    }

    let contained = |path: PathBuf| -> io::Result<PathBuf> {
        let path = path.canonicalize()?;
        // Windows short names (`ENV~1`) hide the leading dot from the request path checks
        if cfg!(windows) && !opts.hidden_files && is_hidden(directory, &path) {
            return Err(io::ErrorKind::NotFound.into());
        }
        if opts.follow_symlinks || path.starts_with(directory) {
            Ok(path)
        } else {
            Err(io::ErrorKind::NotFound.into())
        }
    };
    let lookup = |base: &Path, rel: &Path| {
        if opts.canonical {
            lookup_canonical(base, rel)
        } else {
            None
        }
    };

    // `path` is canonical, `joined` the requested path, or `None` when `path` is
    // symlink-free below a canonical base and siblings need no canonicalization
    let open = |path: PathBuf, joined: Option<PathBuf>| -> io::Result<Target> {
        for &enc in encodings {
            let mut sibling = joined.as_ref().unwrap_or(&path).as_os_str().to_owned();
            sibling.push(compressed_suffix(enc));
            let sibling = PathBuf::from(sibling);
            let regular = if joined.is_none() {
                is_regular_file(&sibling)
            } else {
                None
            };
            let sibling = match regular {
                Some(true) => sibling,
                Some(false) => continue,
                None => match contained(sibling) {
                    Ok(sibling) if sibling.is_file() => sibling,
                    _ => continue,
                },
            };
            if let Ok(file) = File::open(&sibling) {
                let mut file = NamedFile::from_file(file, &path)?;
                file.precompressed = Some(enc);
                return Ok(Target::File(Box::new(file)));
            }
        }
        NamedFile::open(path).map(|file| Target::File(Box::new(file)))
    };

    let (path, joined, is_dir) = match lookup(directory, path) {
        Some(found) => {
            let (found, md) = found?;
            if let Some(cache) = cache
                && md.is_file()
                && let Some(file) = cache.insert(path, &found, &md, encodings)
            {
                return Ok(Target::File(Box::new(file)));
            }
            (found, None, md.is_dir())
        }
        None => {
            let joined = directory.join(path);
            let path = contained(joined.clone())?;
            let is_dir = path.is_dir();
            (path, Some(joined), is_dir)
        }
    };
    if !is_dir {
        return open(path, joined);
    }
    if redirect {
        return Ok(Target::Redirect);
    }
    match index {
        // the directory is canonical in both cases
        Some(index) => match lookup(&path, Path::new(index)) {
            Some(found) => open(found?.0, None),
            None => {
                let joined = path.join(index);
                open(contained(joined.clone())?, Some(joined))
            }
        },
        None => Ok(Target::Dir(path)),
    }
}

/// Looks up `rel` below the canonical `base` with `lstat` on each component.
///
/// Returns the joined path, which is canonical, and the metadata of its last
/// component, or of `base` when `rel` is empty. Returns `None` when `rel` has a
/// component other than a name or crosses a symlink; the caller then canonicalizes.
fn lookup_canonical(base: &Path, rel: &Path) -> Option<io::Result<(PathBuf, Metadata)>> {
    let mut path = base.to_path_buf();
    let mut md = None;
    for component in rel.components() {
        let Component::Normal(name) = component else {
            return None;
        };
        path.push(name);
        match path.symlink_metadata() {
            Ok(m) if m.file_type().is_symlink() => return None,
            Ok(m) => md = Some(m),
            Err(e) => return Some(Err(e)),
        }
    }
    let md = match md {
        Some(md) => md,
        None => match base.metadata() {
            Ok(md) => md,
            Err(e) => return Some(Err(e)),
        },
    };
    Some(Ok((path, md)))
}

/// Reports whether `path` is a regular file, or `None` if it is a symlink.
fn is_regular_file(path: &Path) -> Option<bool> {
    match path.symlink_metadata() {
        Ok(md) if md.file_type().is_symlink() => None,
        Ok(md) => Some(md.is_file()),
        Err(_) => Some(false),
    }
}

/// Encodings with precompressed sibling files, in server preference order.
const PRECOMPRESSED: [ContentEncoding; 3] = [
    ContentEncoding::Br,
    ContentEncoding::Zstd,
    ContentEncoding::Gzip,
];

/// File name suffix of a precompressed sibling.
fn compressed_suffix(enc: ContentEncoding) -> &'static str {
    match enc {
        ContentEncoding::Br => ".br",
        ContentEncoding::Zstd => ".zst",
        _ => ".gz",
    }
}

/// Index of the precompressed sibling for `enc` in [`CachedFile::siblings`].
fn sibling_index(enc: ContentEncoding) -> usize {
    match enc {
        ContentEncoding::Br => 0,
        ContentEncoding::Zstd => 1,
        _ => 2,
    }
}

/// Default capacity of the [`Files::metadata_cache`].
const DEFAULT_CACHE_CAPACITY: usize = 1024;

/// Default entry lifetime of the [`Files::metadata_cache`].
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(1);

/// Device and inode of a file.
type FileId = (u64, u64);

#[cfg(unix)]
fn file_id(md: &Metadata) -> Option<FileId> {
    use std::os::unix::fs::MetadataExt;

    Some((md.dev(), md.ino()))
}

#[cfg(not(unix))]
fn file_id(_: &Metadata) -> Option<FileId> {
    None
}

/// Opens `path` read-only, failing if its last component is a symlink.
#[cfg(unix)]
fn open_nofollow(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_nofollow(path: &Path) -> io::Result<File> {
    File::open(path)
}

/// Precompressed sibling of a [`CachedFile`].
enum Sibling {
    /// Not looked up yet.
    Unknown,
    /// Missing or not a regular file.
    Absent,
    /// A regular file with its last served validators.
    Present(PathBuf, FileId, Option<Arc<named::Validators>>),
    /// A symlink, which is left to [`resolve`].
    Symlink,
}

/// A regular file found below a canonical base without crossing a symlink.
struct CachedFile {
    /// Canonical path of the file.
    path: PathBuf,
    id: FileId,
    content_type: mime::Mime,
    content_disposition: header::ContentDisposition,
    /// Validators the file was last served with.
    validators: Option<Arc<named::Validators>>,
    /// Precompressed siblings by [`sibling_index`], looked up on first use.
    siblings: [Sibling; 3],
    expires: Instant,
}

impl CachedFile {
    /// Opens the first precompressed sibling for `encodings`, or the file itself.
    ///
    /// Returns `None` if the opened file is not the cached one, or if the sibling
    /// to serve is a symlink.
    fn open(&mut self, encodings: &[ContentEncoding]) -> Option<NamedFile> {
        let mut precompressed = None;
        for &enc in encodings {
            let sibling = &mut self.siblings[sibling_index(enc)];
            if let Sibling::Unknown = sibling {
                let mut path = self.path.as_os_str().to_owned();
                path.push(compressed_suffix(enc));
                let path = PathBuf::from(path);
                *sibling = match path.symlink_metadata() {
                    Ok(md) if md.file_type().is_symlink() => Sibling::Symlink,
                    Ok(md) if md.is_file() => Sibling::Present(path, file_id(&md)?, None),
                    _ => Sibling::Absent,
                };
            }
            match sibling {
                Sibling::Present(..) => {
                    precompressed = Some(enc);
                    break;
                }
                Sibling::Symlink => return None,
                Sibling::Unknown | Sibling::Absent => {}
            }
        }

        let (path, id, validators) =
            match precompressed.map(|enc| &mut self.siblings[sibling_index(enc)]) {
                Some(Sibling::Present(path, id, validators)) => (&*path, *id, validators),
                _ => (&self.path, self.id, &mut self.validators),
            };
        let file = open_nofollow(path).ok()?;
        let md = file.metadata().ok()?;
        if file_id(&md)? != id {
            return None;
        }
        let mut file = NamedFile::from_parts(
            self.path.clone(),
            file,
            md,
            self.content_type.clone(),
            self.content_disposition.clone(),
        );
        file.precompressed = precompressed;
        file.use_cached_validators(validators);
        Some(file)
    }
}

/// Per-worker cache of resolved files by request path, see [`Files::metadata_cache`].
struct MetaCache {
    capacity: usize,
    ttl: Duration,
    entries: RefCell<HashMap<PathBuf, CachedFile>>,
    /// Earliest time to drop expired entries from a full cache.
    next_sweep: Cell<Instant>,
}

impl MetaCache {
    /// Returns `None` if the cache is disabled or unsupported.
    fn new(capacity: usize, ttl: Duration) -> Option<Rc<Self>> {
        (cfg!(unix) && capacity > 0 && !ttl.is_zero()).then(|| {
            Rc::new(Self {
                capacity,
                ttl,
                entries: RefCell::default(),
                next_sweep: Cell::new(Instant::now()),
            })
        })
    }

    /// Opens the file cached for the request path `rel`.
    ///
    /// Drops the entry if it is expired or the file cannot be served from it.
    fn get(&self, rel: &Path, encodings: &[ContentEncoding]) -> Option<NamedFile> {
        let mut entries = self.entries.borrow_mut();
        let entry = entries.get_mut(rel)?;
        if entry.expires > ntex::time::now()
            && let Some(file) = entry.open(encodings)
        {
            return Some(file);
        }
        entries.remove(rel);
        None
    }

    /// Opens the regular file at the canonical `path` and caches it for the request path `rel`.
    ///
    /// `md` is the `lstat` metadata of `path`. The file is opened even if the
    /// cache is full; `None` means it cannot be served from a cache entry.
    fn insert(
        &self,
        rel: &Path,
        path: &Path,
        md: &Metadata,
        encodings: &[ContentEncoding],
    ) -> Option<NamedFile> {
        let now = ntex::time::now();
        let (content_type, content_disposition) = named::content_type_and_disposition(path).ok()?;
        let mut entry = CachedFile {
            path: path.to_path_buf(),
            id: file_id(md)?,
            content_type,
            content_disposition,
            validators: None,
            siblings: [Sibling::Unknown, Sibling::Unknown, Sibling::Unknown],
            expires: now + self.ttl,
        };
        let file = entry.open(encodings)?;

        let mut entries = self.entries.borrow_mut();
        if entries.len() >= self.capacity && now >= self.next_sweep.get() {
            entries.retain(|_, entry| entry.expires > now);
            self.next_sweep.set(now + self.ttl);
        }
        if entries.len() < self.capacity {
            entries.insert(rel.to_path_buf(), entry);
        }
        Some(file)
    }
}

/// Returns the precompressed encodings accepted by `Accept-Encoding`, most preferred first.
///
/// Entries are ranked by `q`, ties follow [`PRECOMPRESSED`]. `*` covers encodings
/// that are not listed, and `q=0` or a malformed `q` excludes an encoding.
fn accepted_encodings(headers: &HeaderMap) -> Vec<ContentEncoding> {
    let mut listed: Vec<(ContentEncoding, u16)> = Vec::new();
    let mut wildcard = None;
    let items = headers
        .get_all(ACCEPT_ENCODING)
        .filter_map(|val| val.to_str().ok())
        .flat_map(|val| val.split(','));
    for item in items {
        let mut parts = item.split(';');
        let name = parts.next().unwrap_or_default().trim();
        if name.is_empty() {
            continue;
        }
        let q = parts
            .filter_map(|param| param.split_once('='))
            .find(|(name, _)| name.trim().eq_ignore_ascii_case("q"))
            .map_or(Some(1000), |(_, val)| parse_q(val.trim()))
            .unwrap_or(0);
        if name == "*" {
            wildcard.get_or_insert(q);
        } else if let Ok(enc) = name.parse::<ContentEncoding>() {
            listed.push((enc, q));
        }
    }

    let mut accepted: Vec<_> = PRECOMPRESSED
        .into_iter()
        .filter_map(|enc| {
            let q = listed
                .iter()
                .find(|(e, _)| *e == enc)
                .map(|(_, q)| *q)
                .or(wildcard)?;
            (q > 0).then_some((enc, q))
        })
        .collect();
    accepted.sort_by_key(|(_, q)| cmp::Reverse(*q));
    accepted.into_iter().map(|(enc, _)| enc).collect()
}

/// Parses an RFC 9110 `qvalue` into thousandths.
fn parse_q(val: &str) -> Option<u16> {
    let (int, frac) = val.split_once('.').unwrap_or((val, ""));
    if frac.len() > 3 || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let int = match int {
        "0" => 0,
        "1" => 1000,
        _ => return None,
    };
    let frac = frac
        .bytes()
        .zip([100, 10, 1])
        .map(|(b, scale)| u16::from(b - b'0') * scale)
        .sum::<u16>();
    (int + frac <= 1000).then_some(int + frac)
}

/// Reports whether a component of `path` below `directory` starts with a dot.
/// All components are checked when `path` is outside of `directory`.
fn is_hidden(directory: &Path, path: &Path) -> bool {
    path.strip_prefix(directory).unwrap_or(path).components().any(|c| {
        matches!(c, std::path::Component::Normal(name) if name.as_encoded_bytes().starts_with(b"."))
    })
}

#[derive(Debug)]
struct PathBufWrp(PathBuf);

impl PathBufWrp {
    /// Parses a request path; `hidden` allows dot-prefixed segments.
    fn get_pathbuf(path: &str, hidden: bool) -> Result<Self, UriSegmentError> {
        let mut buf = PathBuf::new();
        for segment in path.split('/') {
            if segment == ".." {
                buf.pop();
                continue;
            }

            // validate the decoded segment, encoded characters must not bypass checks
            let segment = <Url as ResourcePath>::unquote(segment);
            if segment.starts_with('.') && (!hidden || is_dot_segment(&segment)) {
                return Err(UriSegmentError::BadStart('.'));
            } else if segment.starts_with('*') {
                return Err(UriSegmentError::BadStart('*'));
            } else if segment.ends_with(':') {
                return Err(UriSegmentError::BadEnd(':'));
            } else if segment.ends_with('>') {
                return Err(UriSegmentError::BadEnd('>'));
            } else if segment.ends_with('<') {
                return Err(UriSegmentError::BadEnd('<'));
            } else if segment.is_empty() {
                continue;
            } else if segment.contains('/') {
                return Err(UriSegmentError::BadChar('/'));
            } else if segment.contains('\0') {
                return Err(UriSegmentError::BadChar('\0'));
            } else if cfg!(windows) && segment.contains('\\') {
                return Err(UriSegmentError::BadChar('\\'));
            } else {
                buf.push(segment.as_ref())
            }
        }

        Ok(PathBufWrp(buf))
    }
}

impl<St> FromRequest<St> for PathBufWrp {
    type Error = UriSegmentError;

    async fn from_request(_: &St, req: &HttpRequest, _: &mut Payload) -> Result<Self, Self::Error> {
        PathBufWrp::get_pathbuf(req.match_info().path(), false)
    }
}

/// Reports whether a decoded segment is `.` or `..`, which must not reach the filesystem.
/// On Windows, trailing dots and spaces are dropped, so `...` and `.. ` count as well.
fn is_dot_segment(segment: &str) -> bool {
    let name = if cfg!(windows) {
        segment.trim_end_matches(['.', ' '])
    } else {
        segment
    };
    matches!(name, "" | "." | "..")
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use std::{fs, iter::FromIterator, ops::Add};

    use ntex::http::header::{IF_MATCH, IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_UNMODIFIED_SINCE};
    use ntex::http::{self, Method, StatusCode};
    use ntex::web::test::{self, TestRequest};
    use ntex::web::{App, guard, middleware::Compress};

    use super::*;

    #[ntex::test]
    async fn test_file_extension_to_mime() {
        let m = file_extension_to_mime("jpg");
        assert_eq!(m, mime::IMAGE_JPEG);

        let m = file_extension_to_mime("invalid extension!!");
        assert_eq!(m, mime::APPLICATION_OCTET_STREAM);

        let m = file_extension_to_mime("");
        assert_eq!(m, mime::APPLICATION_OCTET_STREAM);
    }

    #[ntex::test]
    async fn test_if_modified_since_without_if_none_match() {
        let file = NamedFile::open("Cargo.toml").unwrap();
        let since = header::HttpDate::from(SystemTime::now().add(Duration::from_secs(60)));

        let req = TestRequest::default()
            .header(http::header::IF_MODIFIED_SINCE, since.to_string())
            .to_http_request();
        let resp = test::respond_to(file, &req).await;
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
    }

    #[ntex::test]
    async fn test_if_modified_since_with_if_none_match() {
        let file = NamedFile::open("Cargo.toml").unwrap();
        let since = header::HttpDate::from(SystemTime::now().add(Duration::from_secs(60)));

        let req = TestRequest::default()
            .header(http::header::IF_NONE_MATCH, "miss_etag")
            .header(http::header::IF_MODIFIED_SINCE, since.to_string())
            .to_http_request();
        let resp = test::respond_to(file, &req).await;
        assert_ne!(resp.status(), StatusCode::NOT_MODIFIED);
    }

    /// The `ETag` that `NamedFile` sends for `path`.
    async fn named_file_etag(path: &str) -> String {
        let req = TestRequest::default().to_http_request();
        let resp = test::respond_to(NamedFile::open(path).unwrap(), &req).await;
        let etag = resp.headers().get(http::header::ETAG).unwrap();
        etag.to_str().unwrap().to_owned()
    }

    /// An HTTP-date `secs` seconds after the Unix epoch.
    fn http_date(secs: u64) -> String {
        header::HttpDate::from(UNIX_EPOCH + Duration::from_secs(secs)).to_string()
    }

    // 2004-01-01 and 2100-01-01: before and after the modification time of any test file.
    const PAST: u64 = 1_072_915_200;
    const FUTURE: u64 = 4_102_444_800;

    #[ntex::test]
    async fn test_preconditions_evaluated_before_range() {
        let etag = named_file_etag("tests/test.binary").await;
        let (past, future) = (http_date(PAST), http_date(FUTURE));
        let (etag, past, future) = (etag.as_str(), past.as_str(), future.as_str());
        let (failed, not_modified) = (StatusCode::PRECONDITION_FAILED, StatusCode::NOT_MODIFIED);

        // satisfiable and unsatisfiable ranges
        for range in ["bytes=10-20", "bytes=1000-2000"] {
            for (name, value, expected) in [
                (IF_MATCH, "\"other\"", failed),
                (IF_UNMODIFIED_SINCE, past, failed),
                (IF_NONE_MATCH, etag, not_modified),
                (IF_NONE_MATCH, "*", not_modified),
                (IF_MODIFIED_SINCE, future, not_modified),
            ] {
                let req = TestRequest::default()
                    .header(name.clone(), value)
                    .header(http::header::RANGE, range)
                    .to_http_request();
                let file = NamedFile::open("tests/test.binary").unwrap();
                let resp = test::respond_to(file, &req).await;
                assert_eq!(resp.status(), expected, "{name}: {value}, Range: {range}");
                assert!(
                    resp.headers().get(http::header::CONTENT_RANGE).is_none(),
                    "{name}: {value}, Range: {range}"
                );
            }
        }
    }

    #[ntex::test]
    async fn test_if_match_takes_precedence_over_if_unmodified_since() {
        let etag = named_file_etag("tests/test.binary").await;
        for (if_match, since, expected) in [
            (etag.as_str(), PAST, StatusCode::OK),
            ("*", PAST, StatusCode::OK),
            ("\"other\"", FUTURE, StatusCode::PRECONDITION_FAILED),
        ] {
            let req = TestRequest::default()
                .header(IF_MATCH, if_match)
                .header(IF_UNMODIFIED_SINCE, http_date(since))
                .to_http_request();
            let file = NamedFile::open("tests/test.binary").unwrap();
            let resp = test::respond_to(file, &req).await;
            assert_eq!(resp.status(), expected, "If-Match: {if_match}");
        }
    }

    #[ntex::test]
    async fn test_conditional_requests_by_method() {
        let etag = named_file_etag("tests/test.binary").await;
        let (past, future) = (http_date(PAST), http_date(FUTURE));
        let (etag, past, future) = (etag.as_str(), past.as_str(), future.as_str());
        let (ok, failed, not_modified) = (
            StatusCode::OK,
            StatusCode::PRECONDITION_FAILED,
            StatusCode::NOT_MODIFIED,
        );

        // expected status for GET/HEAD, for CONNECT/OPTIONS/TRACE
        // and for any other method
        let cases = [
            (IF_MATCH, "\"other\"", failed, ok, failed),
            (IF_UNMODIFIED_SINCE, past, failed, ok, failed),
            (IF_NONE_MATCH, etag, not_modified, ok, failed),
            (IF_NONE_MATCH, "*", not_modified, ok, failed),
            (IF_MODIFIED_SINCE, future, not_modified, ok, ok),
        ];
        let methods = [
            Method::GET,
            Method::HEAD,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::PATCH,
            Method::CONNECT,
            Method::OPTIONS,
            Method::TRACE,
        ];

        let mut mismatches = Vec::new();
        for method in methods {
            for (name, value, get_or_head, ignoring, other) in &cases {
                let expected = match method {
                    Method::GET | Method::HEAD => *get_or_head,
                    Method::CONNECT | Method::OPTIONS | Method::TRACE => *ignoring,
                    _ => *other,
                };
                let req = TestRequest::default()
                    .method(method.clone())
                    .header(name.clone(), *value)
                    .to_http_request();
                let file = NamedFile::open("tests/test.binary").unwrap();
                let status = test::respond_to(file, &req).await.status();
                if status != expected {
                    mismatches.push(format!(
                        "{method} {name}: {value} -> {status}, expected {expected}"
                    ));
                }
            }
        }
        assert!(mismatches.is_empty(), "{mismatches:#?}");
    }

    #[ntex::test]
    async fn test_conditional_headers_on_several_lines() {
        let etag = named_file_etag("tests/test.binary").await;
        let (past, future) = (http_date(PAST), http_date(FUTURE));
        let (etag, past, future) = (etag.as_str(), past.as_str(), future.as_str());

        for (name, first, second, expected) in [
            // a list header is the union of its lines
            (IF_NONE_MATCH, "\"other\"", etag, StatusCode::NOT_MODIFIED),
            (IF_MATCH, "\"other\"", etag, StatusCode::OK),
            // a date header with more than one value is ignored
            (IF_MODIFIED_SINCE, future, past, StatusCode::OK),
            (IF_MODIFIED_SINCE, past, future, StatusCode::OK),
            (IF_UNMODIFIED_SINCE, past, future, StatusCode::OK),
            (IF_UNMODIFIED_SINCE, future, past, StatusCode::OK),
        ] {
            let req = TestRequest::default()
                .header(name.clone(), first)
                .header(name.clone(), second)
                .to_http_request();
            let file = NamedFile::open("tests/test.binary").unwrap();
            let resp = test::respond_to(file, &req).await;
            assert_eq!(resp.status(), expected, "{name}: {first} / {second}");
        }
    }

    #[ntex::test]
    async fn test_range_applies_only_to_get() {
        for (method, expected) in [
            (Method::GET, StatusCode::PARTIAL_CONTENT),
            (Method::HEAD, StatusCode::OK),
            (Method::POST, StatusCode::OK),
        ] {
            let req = TestRequest::default()
                .method(method.clone())
                .header(http::header::RANGE, "bytes=10-20")
                .to_http_request();
            let file = NamedFile::open("tests/test.binary").unwrap();
            let resp = test::respond_to(file, &req).await;
            assert_eq!(resp.status(), expected, "{method}");
            assert_eq!(
                resp.headers().contains_key(http::header::CONTENT_RANGE),
                expected == StatusCode::PARTIAL_CONTENT,
                "{method}"
            );
        }
    }

    #[ntex::test]
    async fn test_range_units() {
        // the unit is case-insensitive
        let req = TestRequest::default()
            .header(http::header::RANGE, "Bytes=10-20")
            .to_http_request();
        let file = NamedFile::open("tests/test.binary").unwrap();
        let resp = test::respond_to(file, &req).await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            resp.headers().get(http::header::CONTENT_RANGE).unwrap(),
            "bytes 10-20/100"
        );

        // an unknown unit is ignored
        let req = TestRequest::default()
            .header(http::header::RANGE, "items=0-5")
            .to_http_request();
        let file = NamedFile::open("tests/test.binary").unwrap();
        let resp = test::respond_to(file, &req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get(http::header::CONTENT_RANGE).is_none());
    }

    #[ntex::test]
    async fn test_named_file_custom_etag() {
        let file = NamedFile::open("Cargo.toml")
            .unwrap()
            .set_etag(header::EntityTag::strong("v1".to_string()));

        let req = TestRequest::default().to_http_request();
        let resp = test::respond_to(file, &req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(http::header::ETAG).map(|v| v.as_bytes()),
            Some(&b"\"v1\""[..])
        );

        let file = NamedFile::open("Cargo.toml")
            .unwrap()
            .use_etag(false)
            .set_etag(header::EntityTag::strong("v1".to_string()));
        let resp = test::respond_to(file, &req).await;
        assert_eq!(
            resp.headers().get(http::header::ETAG).map(|v| v.as_bytes()),
            Some(&b"\"v1\""[..])
        );

        let file = NamedFile::open("Cargo.toml")
            .unwrap()
            .set_etag(header::EntityTag::strong("v1".to_string()))
            .use_etag(false);
        let resp = test::respond_to(file, &req).await;
        assert!(resp.headers().get(http::header::ETAG).is_none());
    }

    #[ntex::test]
    async fn test_named_file_custom_etag_content_change() {
        struct RemoveOnDrop(std::path::PathBuf);
        impl Drop for RemoveOnDrop {
            fn drop(&mut self) {
                let _ = fs::remove_file(&self.0);
            }
        }

        let path = RemoveOnDrop(
            std::env::temp_dir().join(format!("ntex-files-custom-etag-{}.txt", std::process::id())),
        );
        let mtime = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
        let write = |content: &str| {
            fs::write(&path.0, content).unwrap();
            fs::File::options()
                .write(true)
                .open(&path.0)
                .unwrap()
                .set_modified(mtime)
                .unwrap();
        };

        write("version 1");
        let old_etag = NamedFile::open(&path.0).unwrap().etag().unwrap();

        // same size and modification time, different bytes
        write("version 2");

        // the metadata-derived tag does not change, so a client that revalidates
        // its copy of version 1 is told that the copy is still current
        let req = TestRequest::default()
            .header(http::header::IF_NONE_MATCH, old_etag.to_string())
            .to_http_request();
        let resp = test::respond_to(NamedFile::open(&path.0).unwrap(), &req).await;
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);

        // a tag that follows the content makes the same client fetch version 2
        let file = NamedFile::open(&path.0)
            .unwrap()
            .set_etag(header::EntityTag::strong("v2".to_string()));
        let req = TestRequest::default()
            .header(http::header::IF_NONE_MATCH, "\"v1\"")
            .to_http_request();
        let resp = test::respond_to(file, &req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(http::header::ETAG).map(|v| v.as_bytes()),
            Some(&b"\"v2\""[..])
        );
    }

    #[ntex::test]
    async fn test_named_file_custom_etag_if_none_match() {
        let file = NamedFile::open("Cargo.toml")
            .unwrap()
            .set_etag(header::EntityTag::strong("v1".to_string()));

        let req = TestRequest::default()
            .header(http::header::IF_NONE_MATCH, "\"v1\"")
            .to_http_request();
        let resp = test::respond_to(file, &req).await;
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(
            resp.headers().get(http::header::ETAG).map(|v| v.as_bytes()),
            Some(&b"\"v1\""[..])
        );

        // the tag derived from file metadata no longer matches
        let default_etag = NamedFile::open("Cargo.toml").unwrap().etag().unwrap();
        let file = NamedFile::open("Cargo.toml")
            .unwrap()
            .set_etag(header::EntityTag::strong("v1".to_string()));

        let req = TestRequest::default()
            .header(http::header::IF_NONE_MATCH, default_etag.to_string())
            .to_http_request();
        let resp = test::respond_to(file, &req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[ntex::test]
    async fn test_named_file_custom_etag_if_match() {
        let file = NamedFile::open("Cargo.toml")
            .unwrap()
            .set_etag(header::EntityTag::strong("v1".to_string()));

        let req = TestRequest::default()
            .header(http::header::IF_MATCH, "\"v1\"")
            .to_http_request();
        let resp = test::respond_to(file, &req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // the tag derived from file metadata no longer matches
        let default_etag = NamedFile::open("Cargo.toml").unwrap().etag().unwrap();
        let file = NamedFile::open("Cargo.toml")
            .unwrap()
            .set_etag(header::EntityTag::strong("v1".to_string()));

        let req = TestRequest::default()
            .header(http::header::IF_MATCH, default_etag.to_string())
            .to_http_request();
        let resp = test::respond_to(file, &req).await;
        assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    }

    #[ntex::test]
    async fn test_named_file_custom_etag_weak() {
        // If-None-Match uses the weak comparison, so a weak tag satisfies it
        let file = NamedFile::open("Cargo.toml")
            .unwrap()
            .set_etag(header::EntityTag::weak("v1".to_string()));

        let req = TestRequest::default()
            .header(http::header::IF_NONE_MATCH, "\"v1\"")
            .to_http_request();
        let resp = test::respond_to(file, &req).await;
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(
            resp.headers().get(http::header::ETAG).map(|v| v.as_bytes()),
            Some(&b"W/\"v1\""[..])
        );

        // If-Match uses the strong comparison, so a weak tag never satisfies it
        let file = NamedFile::open("Cargo.toml")
            .unwrap()
            .set_etag(header::EntityTag::weak("v1".to_string()));

        let req = TestRequest::default()
            .header(http::header::IF_MATCH, "\"v1\"")
            .to_http_request();
        let resp = test::respond_to(file, &req).await;
        assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    }

    #[ntex::test]
    async fn test_named_file_text() {
        assert!(NamedFile::open("test--").is_err());
        let mut file = NamedFile::open("Cargo.toml").unwrap();
        {
            file.file();
            let _f: &File = &file;
        }
        {
            let _f: &mut File = &mut file;
        }

        let req = TestRequest::default().to_http_request();
        let resp = test::respond_to(file, &req).await;
        assert_eq!(
            resp.headers().get(http::header::CONTENT_TYPE).unwrap(),
            "text/x-toml"
        );
        assert_eq!(
            resp.headers()
                .get(http::header::CONTENT_DISPOSITION)
                .unwrap(),
            "inline; filename=\"Cargo.toml\""
        );
    }

    #[ntex::test]
    async fn test_named_file_content_disposition() {
        assert!(NamedFile::open("test--").is_err());
        let mut file = NamedFile::open("Cargo.toml").unwrap();
        {
            file.file();
            let _f: &File = &file;
        }
        {
            let _f: &mut File = &mut file;
        }

        let req = TestRequest::default().to_http_request();
        let resp = test::respond_to(file, &req).await;
        assert_eq!(
            resp.headers()
                .get(http::header::CONTENT_DISPOSITION)
                .unwrap(),
            "inline; filename=\"Cargo.toml\""
        );

        let file = NamedFile::open("Cargo.toml")
            .unwrap()
            .disable_content_disposition();
        let req = TestRequest::default().to_http_request();
        let resp = test::respond_to(file, &req).await;
        assert!(
            resp.headers()
                .get(http::header::CONTENT_DISPOSITION)
                .is_none()
        );
    }

    // #[ntex::test]
    // async fn test_named_file_non_ascii_file_name() {
    //     let mut file =
    //         NamedFile::from_file(File::open("Cargo.toml").unwrap(), "貨物.toml")
    //             .unwrap();
    //     {
    //         file.file();
    //         let _f: &File = &file;
    //     }
    //     {
    //         let _f: &mut File = &mut file;
    //     }

    //     let req = TestRequest::default().to_http_request();
    //     let resp = test::respond_to(file, &req).await;
    //     assert_eq!(
    //         resp.headers().get(http::header::CONTENT_TYPE).unwrap(),
    //         "text/x-toml"
    //     );
    //     assert_eq!(
    //         resp.headers()
    //             .get(http::header::CONTENT_DISPOSITION)
    //             .unwrap(),
    //         "inline; filename=\"貨物.toml\"; filename*=UTF-8''%E8%B2%A8%E7%89%A9.toml"
    //     );
    // }

    #[ntex::test]
    async fn test_named_file_set_content_type() {
        let mut file = NamedFile::open("Cargo.toml")
            .unwrap()
            .set_content_type(mime::TEXT_XML);
        {
            file.file();
            let _f: &File = &file;
        }
        {
            let _f: &mut File = &mut file;
        }

        let req = TestRequest::default().to_http_request();
        let resp = test::respond_to(file, &req).await;
        assert_eq!(
            resp.headers().get(http::header::CONTENT_TYPE).unwrap(),
            "text/xml"
        );
        assert_eq!(
            resp.headers()
                .get(http::header::CONTENT_DISPOSITION)
                .unwrap(),
            "inline; filename=\"Cargo.toml\""
        );
    }

    /// STATEMENT: `Files` adds a UTF-8 charset to text content types by default, and
    /// `prefer_utf8(false)` sends the bare type.
    ///
    /// HOW:
    /// - Serve html, txt, css, csv, js, xml and png files with default settings and
    ///   with `prefer_utf8(false)`.
    /// - Confirm html, txt, css, csv and js get `charset=utf-8` only by default.
    /// - Confirm xml and png are sent unchanged in both cases.
    #[ntex::test]
    async fn test_files_prefer_utf8() {
        let root = tempfile::tempdir().unwrap();
        for name in [
            "a.html", "a.txt", "a.css", "a.csv", "a.js", "a.xml", "a.png",
        ] {
            fs::write(root.path().join(name), "x").unwrap();
        }
        let cases = [
            ("/a.html", "text/html"),
            ("/a.txt", "text/plain"),
            ("/a.css", "text/css"),
            ("/a.csv", "text/csv"),
            ("/a.js", "text/javascript"),
        ];

        for prefer in [true, false] {
            let mut files = Files::new("/", root.path());
            if !prefer {
                files = files.prefer_utf8(false);
            }
            let srv = test::init_service(App::new().service(files)).await;

            for (uri, ct) in cases {
                let resp = test::call_service(&srv, TestRequest::with_uri(uri).to_request()).await;
                let expected = if prefer {
                    format!("{ct}; charset=utf-8")
                } else {
                    ct.to_string()
                };
                assert_eq!(
                    resp.headers().get(http::header::CONTENT_TYPE).unwrap(),
                    &expected
                );
            }
            for (uri, ct) in [("/a.xml", "text/xml"), ("/a.png", "image/png")] {
                let resp = test::call_service(&srv, TestRequest::with_uri(uri).to_request()).await;
                assert_eq!(resp.headers().get(http::header::CONTENT_TYPE).unwrap(), ct);
            }
        }
    }

    /// STATEMENT: `NamedFile` applies `prefer_utf8` for custom status codes, and an explicit
    /// `set_content_type` is sent unchanged unless `prefer_utf8` is enabled again.
    ///
    /// HOW:
    /// - Respond with a `.html` file using status `404` and check for `charset=utf-8`.
    /// - Set the content type to `text/plain` and check the bare type is sent.
    /// - Call `prefer_utf8(true)` after `set_content_type` and check the charset is added.
    #[ntex::test]
    async fn test_named_file_prefer_utf8() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("page.html");
        fs::write(&path, "x").unwrap();
        let req = TestRequest::default().to_http_request();

        let file = NamedFile::open(&path)
            .unwrap()
            .set_status_code(StatusCode::NOT_FOUND);
        let resp = test::respond_to(file, &req).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            resp.headers().get(http::header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );

        let file = NamedFile::open(&path)
            .unwrap()
            .set_content_type(mime::TEXT_PLAIN);
        let resp = test::respond_to(file, &req).await;
        assert_eq!(
            resp.headers().get(http::header::CONTENT_TYPE).unwrap(),
            "text/plain"
        );

        let file = NamedFile::open(&path)
            .unwrap()
            .set_content_type(mime::TEXT_PLAIN)
            .prefer_utf8(true);
        let resp = test::respond_to(file, &req).await;
        assert_eq!(
            resp.headers().get(http::header::CONTENT_TYPE).unwrap(),
            "text/plain; charset=utf-8"
        );
    }

    #[ntex::test]
    async fn test_named_file_image() {
        let mut file = NamedFile::open("tests/test.png").unwrap();
        {
            file.file();
            let _f: &File = &file;
        }
        {
            let _f: &mut File = &mut file;
        }

        let req = TestRequest::default().to_http_request();
        let resp = test::respond_to(file, &req).await;
        assert_eq!(
            resp.headers().get(http::header::CONTENT_TYPE).unwrap(),
            "image/png"
        );
        assert_eq!(
            resp.headers()
                .get(http::header::CONTENT_DISPOSITION)
                .unwrap(),
            "inline; filename=\"test.png\""
        );
    }

    #[ntex::test]
    async fn test_named_file_image_attachment() {
        use crate::header::{ContentDisposition, DispositionParam, DispositionType};

        let cd = ContentDisposition {
            disposition: DispositionType::Attachment,
            parameters: vec![DispositionParam::Filename(String::from("test.png"))],
        };
        let mut file = NamedFile::open("tests/test.png")
            .unwrap()
            .set_content_disposition(cd);
        {
            file.file();
            let _f: &File = &file;
        }
        {
            let _f: &mut File = &mut file;
        }

        let req = TestRequest::default().to_http_request();
        let resp = test::respond_to(file, &req).await;
        assert_eq!(
            resp.headers().get(http::header::CONTENT_TYPE).unwrap(),
            "image/png"
        );
        assert_eq!(
            resp.headers()
                .get(http::header::CONTENT_DISPOSITION)
                .unwrap(),
            "attachment; filename=\"test.png\""
        );
    }

    #[ntex::test]
    async fn test_named_file_binary() {
        let mut file = NamedFile::open("tests/test.binary").unwrap();
        {
            file.file();
            let _f: &File = &file;
        }
        {
            let _f: &mut File = &mut file;
        }

        let req = TestRequest::default().to_http_request();
        let resp = test::respond_to(file, &req).await;
        assert_eq!(
            resp.headers().get(http::header::CONTENT_TYPE).unwrap(),
            "application/octet-stream"
        );
        assert_eq!(
            resp.headers()
                .get(http::header::CONTENT_DISPOSITION)
                .unwrap(),
            "attachment; filename=\"test.binary\""
        );
    }

    #[ntex::test]
    async fn test_named_file_status_code_text() {
        let mut file = NamedFile::open("Cargo.toml")
            .unwrap()
            .set_status_code(StatusCode::NOT_FOUND);
        {
            file.file();
            let _f: &File = &file;
        }
        {
            let _f: &mut File = &mut file;
        }

        let req = TestRequest::default().to_http_request();
        let resp = test::respond_to(file, &req).await;
        assert_eq!(
            resp.headers().get(http::header::CONTENT_TYPE).unwrap(),
            "text/x-toml"
        );
        assert_eq!(
            resp.headers()
                .get(http::header::CONTENT_DISPOSITION)
                .unwrap(),
            "inline; filename=\"Cargo.toml\""
        );
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[ntex::test]
    async fn test_mime_override() {
        fn all_attachment(_: &mime::Name) -> header::DispositionType {
            header::DispositionType::Attachment
        }

        let srv = test::init_service(
            App::new().service(
                Files::new("/", ".")
                    .mime_override(all_attachment)
                    .index_file("Cargo.toml"),
            ),
        )
        .await;

        let request = TestRequest::get().uri("/").to_request();
        let response = test::call_service(&srv, request).await;
        assert_eq!(response.status(), StatusCode::OK);

        let content_disposition = response
            .headers()
            .get(http::header::CONTENT_DISPOSITION)
            .expect("To have CONTENT_DISPOSITION");
        let content_disposition = content_disposition
            .to_str()
            .expect("Convert CONTENT_DISPOSITION to str");
        assert_eq!(content_disposition, "attachment; filename=\"Cargo.toml\"");
    }

    #[ntex::test]
    async fn test_named_file_ranges_status_code() {
        let srv = test::init_service(
            App::new().service(Files::new("/test", ".").index_file("Cargo.toml")),
        )
        .await;

        // Valid range header
        let request = TestRequest::get()
            .uri("/t%65st/Cargo.toml")
            .header(http::header::RANGE, "bytes=10-20")
            .to_request();
        let response = test::call_service(&srv, request).await;
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);

        // Invalid range header
        let request = TestRequest::get()
            .uri("/t%65st/Cargo.toml")
            .header(http::header::RANGE, "bytes=1-0")
            .to_request();
        let response = test::call_service(&srv, request).await;

        assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    }

    #[ntex::test]
    async fn test_named_file_ignores_unsupported_range_requests() {
        for (method, range) in [(Method::GET, "items=0-9"), (Method::HEAD, "items=0-9")] {
            let file = NamedFile::open("Cargo.toml").unwrap();
            let req = TestRequest::default()
                .method(method)
                .header(http::header::RANGE, range)
                .to_http_request();
            let resp = test::respond_to(file, &req).await;

            assert_eq!(resp.status(), StatusCode::OK);
            assert!(!resp.headers().contains_key(http::header::CONTENT_RANGE));
        }
    }

    #[ntex::test]
    async fn test_named_file_content_range_headers() {
        let srv = test::init_service(
            App::new().service(Files::new("/test", ".").index_file("tests/test.binary")),
        )
        .await;

        // Valid range header
        let request = TestRequest::get()
            .uri("/t%65st/tests/test.binary")
            .header(http::header::RANGE, "bytes=10-20")
            .to_request();

        let response = test::call_service(&srv, request).await;
        let contentrange = response
            .headers()
            .get(http::header::CONTENT_RANGE)
            .unwrap()
            .to_str()
            .unwrap();

        assert_eq!(contentrange, "bytes 10-20/100");

        // Invalid range header
        let request = TestRequest::get()
            .uri("/t%65st/tests/test.binary")
            .header(http::header::RANGE, "bytes=10-5")
            .to_request();
        let response = test::call_service(&srv, request).await;

        let contentrange = response
            .headers()
            .get(http::header::CONTENT_RANGE)
            .unwrap()
            .to_str()
            .unwrap();

        assert_eq!(contentrange, "bytes */100");
    }

    #[ntex::test]
    async fn test_named_file_empty_range_header() {
        let srv = test::init_service(App::new().service(Files::new("/", "."))).await;

        for range in ["", "bytes=", "bytes=,", "bytes= , ,"] {
            let request = TestRequest::get()
                .uri("/tests/test.binary")
                .header(http::header::RANGE, range)
                .to_request();
            let response = test::call_service(&srv, request).await;

            assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
            assert_eq!(
                response.headers().get(http::header::CONTENT_RANGE).unwrap(),
                "bytes */100"
            );
        }
    }

    #[ntex::test]
    async fn test_named_file_zero_length_suffix_range() {
        let srv = test::init_service(App::new().service(Files::new("/", "."))).await;

        let request = TestRequest::get()
            .uri("/tests/test.binary")
            .header(http::header::RANGE, "bytes=-0")
            .to_request();
        let response = test::call_service(&srv, request).await;

        assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            response.headers().get(http::header::CONTENT_RANGE).unwrap(),
            "bytes */100"
        );
    }

    #[ntex::test]
    async fn test_named_file_suffix_range_of_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("empty"), b"").unwrap();
        let srv = test::init_service(App::new().service(Files::new("/", dir.path()))).await;

        let request = TestRequest::get()
            .uri("/empty")
            .header(http::header::RANGE, "bytes=-5")
            .to_request();
        let response = test::call_service(&srv, request).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response
                .headers()
                .get(http::header::CONTENT_RANGE)
                .is_none()
        );
        assert!(test::read_body(response).await.is_empty());
    }

    #[ntex::test]
    async fn test_named_file_one_byte_range() {
        let srv = test::init_service(App::new().service(Files::new("/", "."))).await;
        let data = fs::read("tests/test.binary").unwrap();

        for (range, content_range, body) in [
            ("bytes=0-0", "bytes 0-0/100", &data[..1]),
            ("bytes=-1", "bytes 99-99/100", &data[99..]),
        ] {
            let request = TestRequest::get()
                .uri("/tests/test.binary")
                .header(http::header::RANGE, range)
                .to_request();
            let response = test::call_service(&srv, request).await;

            assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT, "{range}");
            assert_eq!(
                response.headers().get(http::header::CONTENT_RANGE).unwrap(),
                content_range,
                "{range}"
            );
            assert_eq!(&test::read_body(response).await[..], body, "{range}");
        }
    }

    #[ntex::test]
    async fn test_named_file_range_responses_match_the_selected_bytes() {
        // What a single-range request selects in a file of `size` bytes
        // (RFC 9110, section 14.1.2).
        enum Selected {
            Bytes(u64, u64),
            // A suffix range of an empty file: satisfiable, but there is no
            // byte to describe in a Content-Range, so the range is ignored.
            Ignored,
            Unsatisfiable,
        }

        let dir = tempfile::tempdir().unwrap();
        let srv = test::init_service(App::new().service(Files::new("/", dir.path()))).await;

        for size in [5u64, 2, 1, 0] {
            let data: Vec<u8> = (0..size as u8).collect();
            fs::write(dir.path().join(size.to_string()), &data).unwrap();

            let mut cases = Vec::new();
            for a in 0..=size + 1 {
                cases.push((
                    format!("bytes={a}-"),
                    if a < size {
                        Selected::Bytes(a, size - 1)
                    } else {
                        Selected::Unsatisfiable
                    },
                ));
                cases.push((
                    format!("bytes=-{a}"),
                    if a == 0 {
                        Selected::Unsatisfiable
                    } else if size == 0 {
                        Selected::Ignored
                    } else {
                        Selected::Bytes(size - a.min(size), size - 1)
                    },
                ));
                for b in 0..=size + 1 {
                    cases.push((
                        format!("bytes={a}-{b}"),
                        if a <= b && a < size {
                            Selected::Bytes(a, b.min(size - 1))
                        } else {
                            Selected::Unsatisfiable
                        },
                    ));
                }
            }
            for range in ["", "bytes=", "bytes=,"] {
                cases.push((range.to_string(), Selected::Unsatisfiable));
            }

            for (range, selected) in cases {
                let request = TestRequest::get()
                    .uri(&format!("/{size}"))
                    .header(http::header::RANGE, range.as_str())
                    .to_request();
                let response = test::call_service(&srv, request).await;
                let status = response.status();
                let content_range = response
                    .headers()
                    .get(http::header::CONTENT_RANGE)
                    .map(|v| v.to_str().unwrap().to_string());
                let body = test::read_body(response).await;

                let (expected_status, expected_range, expected_body) = match selected {
                    // A range that covers the whole file is a 206 as well.
                    Selected::Bytes(first, last) => (
                        StatusCode::PARTIAL_CONTENT,
                        Some(format!("bytes {first}-{last}/{size}")),
                        &data[first as usize..=last as usize],
                    ),
                    Selected::Ignored => (StatusCode::OK, None, &data[..]),
                    Selected::Unsatisfiable => (
                        StatusCode::RANGE_NOT_SATISFIABLE,
                        Some(format!("bytes */{size}")),
                        &[][..],
                    ),
                };
                assert_eq!(status, expected_status, "{range} on {size} bytes");
                assert_eq!(content_range, expected_range, "{range} on {size} bytes");
                assert_eq!(&body[..], expected_body, "{range} on {size} bytes");
            }
        }
    }

    #[ntex::test]
    async fn test_named_file_if_range_match() {
        let file = NamedFile::open("Cargo.toml").unwrap();
        let etag = file.etag().unwrap();
        let req = TestRequest::default()
            .header(http::header::RANGE, "bytes=0-9")
            .header(http::header::IF_RANGE, etag.to_string())
            .to_http_request();
        let resp = test::respond_to(file, &req).await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);

        let file = NamedFile::open("Cargo.toml").unwrap();
        let modified = file.last_modified().unwrap();
        let req = TestRequest::default()
            .header(http::header::RANGE, "bytes=0-9")
            .header(http::header::IF_RANGE, modified.to_string())
            .to_http_request();
        let resp = test::respond_to(file, &req).await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
    }

    #[ntex::test]
    async fn test_named_file_if_range_mismatch() {
        let file = NamedFile::open("Cargo.toml").unwrap();
        let etag = file.etag().unwrap();
        let modified = file.last_modified().unwrap();
        let later = header::HttpDate::from(SystemTime::from(modified).add(Duration::from_secs(60)));

        // (If-Range, use_etag, use_last_modified)
        let cases = [
            ("\"stale\"".to_owned(), true, true),
            (format!("W/{}", etag), true, true),
            (later.to_string(), true, true),
            ("not a validator".to_owned(), true, true),
            (etag.to_string(), false, true),
            (modified.to_string(), true, false),
        ];
        for (if_range, use_etag, use_last_modified) in cases {
            let file = NamedFile::open("Cargo.toml")
                .unwrap()
                .use_etag(use_etag)
                .use_last_modified(use_last_modified);
            let req = TestRequest::default()
                .header(http::header::RANGE, "bytes=0-9")
                .header(http::header::IF_RANGE, if_range.as_str())
                .to_http_request();
            let resp = test::respond_to(file, &req).await;
            assert_eq!(resp.status(), StatusCode::OK, "If-Range: {}", if_range);
            assert!(
                !resp.headers().contains_key(http::header::CONTENT_RANGE),
                "If-Range: {}",
                if_range
            );
        }
    }

    #[ntex::test]
    async fn test_named_file_if_range_earlier_date() {
        // the date must be equal to Last-Modified, not merely not later
        let file = NamedFile::open("Cargo.toml").unwrap();
        let modified = file.last_modified().unwrap();
        let earlier = header::HttpDate::from(SystemTime::from(modified) - Duration::from_secs(60));
        let req = TestRequest::default()
            .header(http::header::RANGE, "bytes=0-9")
            .header(http::header::IF_RANGE, earlier.to_string())
            .to_http_request();
        let resp = test::respond_to(file, &req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(!resp.headers().contains_key(http::header::CONTENT_RANGE));
    }

    #[ntex::test]
    async fn test_named_file_if_range_not_utf8() {
        let file = NamedFile::open("Cargo.toml").unwrap();
        let req = TestRequest::default()
            .header(http::header::RANGE, "bytes=0-9")
            .header(
                http::header::IF_RANGE,
                http::header::HeaderValue::from_bytes(b"\"\xff\"").unwrap(),
            )
            .to_http_request();
        let resp = test::respond_to(file, &req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(!resp.headers().contains_key(http::header::CONTENT_RANGE));
    }

    #[ntex::test]
    async fn test_files_if_range() {
        let srv = test::init_service(App::new().service(Files::new("/", "."))).await;
        let data = Bytes::from(fs::read("tests/test.binary").unwrap());

        // a validator that no longer matches yields the whole file,
        // whether the range is satisfiable or not
        for range in ["bytes=10-20", "bytes=200-300"] {
            let request = TestRequest::get()
                .uri("/tests/test.binary")
                .header(http::header::RANGE, range)
                .header(http::header::IF_RANGE, "\"stale\"")
                .to_request();
            let response = test::call_service(&srv, request).await;
            assert_eq!(response.status(), StatusCode::OK, "Range: {}", range);
            assert!(!response.headers().contains_key(http::header::CONTENT_RANGE));
            let bytes = test::read_body(response).await;
            assert_eq!(bytes, data);
        }

        // the validator of the current file yields the requested range
        let request = TestRequest::get().uri("/tests/test.binary").to_request();
        let response = test::call_service(&srv, request).await;
        let etag = response
            .headers()
            .get(http::header::ETAG)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let request = TestRequest::get()
            .uri("/tests/test.binary")
            .header(http::header::RANGE, "bytes=10-20")
            .header(http::header::IF_RANGE, etag.as_str())
            .to_request();
        let response = test::call_service(&srv, request).await;
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        let bytes = test::read_body(response).await;
        assert_eq!(bytes, data.slice(10..21));
    }

    #[ntex::test]
    async fn test_named_file_content_length_headers() {
        let srv = test::server(async |_| App::new().service(Files::new("/", ".")));
        let data = Bytes::from(fs::read("tests/test.binary").unwrap());

        // Valid range header
        let response = srv
            .get("/tests/test.binary")
            .header(http::header::RANGE, "bytes=10-20")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        let content_length = response.headers().get(http::header::CONTENT_LENGTH);
        assert_eq!(content_length.map(|v| v.to_str().unwrap()), Some("11"));
        let transfer_encoding = response.headers().get(http::header::TRANSFER_ENCODING);
        assert!(transfer_encoding.is_none());
        let bytes = response.body().await.unwrap();
        assert_eq!(bytes, data.slice(10..21));

        // Valid range header, starting from 0
        let response = srv
            .get("/tests/test.binary")
            .header(http::header::RANGE, "bytes=0-20")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        let content_length = response.headers().get(http::header::CONTENT_LENGTH);
        assert_eq!(content_length.map(|v| v.to_str().unwrap()), Some("21"));
        let transfer_encoding = response.headers().get(http::header::TRANSFER_ENCODING);
        assert!(transfer_encoding.is_none());
        let bytes = response.body().await.unwrap();
        assert_eq!(bytes, data.slice(0..21));

        // Invalid range header
        let response = srv
            .get("/tests/test.binary")
            .header(http::header::RANGE, "bytes=10-8")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);

        // Without range header
        let response = srv.get("/tests/test.binary").send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let content_length = response.headers().get(http::header::CONTENT_LENGTH);
        assert_eq!(content_length.map(|v| v.to_str().unwrap()), Some("100"));
        let transfer_encoding = response.headers().get(http::header::TRANSFER_ENCODING);
        assert!(transfer_encoding.is_none());
        let bytes = response.body().await.unwrap();
        assert_eq!(bytes, data);
    }

    #[ntex::test]
    async fn test_head_content_length_headers() {
        let srv = test::server(async |_| App::new().service(Files::new("/", ".")));

        // Without range header
        let response = srv.head("/tests/test.binary").send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let content_length = response.headers().get(http::header::CONTENT_LENGTH);
        assert_eq!(content_length.map(|v| v.to_str().unwrap()), Some("100"));

        // Range is ignored for HEAD
        let response = srv
            .head("/tests/test.binary")
            .header(http::header::RANGE, "bytes=10-20")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let content_range = response.headers().get(http::header::CONTENT_RANGE);
        assert!(content_range.is_none());
        let content_length = response.headers().get(http::header::CONTENT_LENGTH);
        assert_eq!(content_length.map(|v| v.to_str().unwrap()), Some("100"));
        let transfer_encoding = response.headers().get(http::header::TRANSFER_ENCODING);
        assert!(transfer_encoding.is_none());
    }

    #[ntex::test]
    async fn test_static_files_with_spaces() {
        let srv =
            test::init_service(App::new().service(Files::new("/", ".").index_file("Cargo.toml")))
                .await;
        let request = TestRequest::get()
            .uri("/tests/test%20space.binary")
            .to_request();
        let response = test::call_service(&srv, request).await;
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = test::read_body(response).await;
        let data = Bytes::from(fs::read("tests/test space.binary").unwrap());
        assert_eq!(bytes, data);
    }

    #[ntex::test]
    async fn test_files_not_allowed() {
        let srv = test::init_service(App::new().service(Files::new("/", "."))).await;

        let req = TestRequest::default()
            .uri("/Cargo.toml")
            .method(Method::POST)
            .to_request();

        let resp = test::call_service(&srv, req).await;
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);

        let srv = test::init_service(App::new().service(Files::new("/", "."))).await;
        let req = TestRequest::default()
            .method(Method::PUT)
            .uri("/Cargo.toml")
            .to_request();
        let resp = test::call_service(&srv, req).await;
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[ntex::test]
    async fn test_files_guards() {
        let srv =
            test::init_service(App::new().service(Files::new("/", ".").use_guards(guard::Post())))
                .await;

        let req = TestRequest::default()
            .uri("/Cargo.toml")
            .method(Method::POST)
            .to_request();

        let resp = test::call_service(&srv, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// STATEMENT: Resource guards select the `Files` service during routing, so
    /// requests rejected by them fall through to other services.
    ///
    /// HOW:
    /// - Register two `Files` services for the same prefix with different `Host`
    ///   guards, plus a third with a header guard, then a fallback resource.
    /// - Check each host is served its own directory, a request matching both
    ///   `Files::guard` calls on one service is served, and an unmatched request
    ///   reaches the fallback.
    #[ntex::test]
    async fn test_files_resource_guards() {
        let srv = test::init_service(
            App::new()
                .service(Files::new("/", "tests").guard(guard::Host("a.example")))
                .service(Files::new("/", ".").guard(guard::Host("b.example")))
                .service(
                    Files::new("/", ".")
                        .guard(guard::Host("c.example"))
                        .guard(guard::Header("x-files", "1")),
                )
                .default_service(web::to(|| async { HttpResponse::Gone() })),
        )
        .await;

        let get = |host: &'static str, uri: &'static str| {
            TestRequest::with_uri(uri)
                .header(http::header::HOST, host)
                .to_request()
        };
        let resp = test::call_service(&srv, get("a.example", "/test.binary")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = test::call_service(&srv, get("b.example", "/tests/test.binary")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = test::call_service(&srv, get("c.example", "/Cargo.toml")).await;
        assert_eq!(resp.status(), StatusCode::GONE);
        let req = TestRequest::with_uri("/Cargo.toml")
            .header(http::header::HOST, "c.example")
            .header("x-files", "1")
            .to_request();
        let resp = test::call_service(&srv, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = test::call_service(&srv, get("d.example", "/Cargo.toml")).await;
        assert_eq!(resp.status(), StatusCode::GONE);
    }

    #[ntex::test]
    async fn test_named_file_content_encoding() {
        let srv = test::init_service(App::new().middleware(Compress::default()).service(
            web::resource("/").to(|| async {
                NamedFile::open("Cargo.toml")
                    .unwrap()
                    .set_content_encoding(http::header::ContentEncoding::Identity)
            }),
        ))
        .await;

        let request = TestRequest::get()
            .uri("/")
            .header(http::header::ACCEPT_ENCODING, "gzip")
            .to_request();
        let res = test::call_service(&srv, request).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert!(!res.headers().contains_key(http::header::CONTENT_ENCODING));
    }

    #[ntex::test]
    async fn test_named_file_content_encoding_gzip() {
        let srv = test::init_service(App::new().middleware(Compress::default()).service(
            web::resource("/").to(|| async {
                NamedFile::open("Cargo.toml")
                    .unwrap()
                    .set_content_encoding(http::header::ContentEncoding::Gzip)
            }),
        ))
        .await;

        let request = TestRequest::get()
            .uri("/")
            .header(http::header::ACCEPT_ENCODING, "gzip")
            .to_request();
        let res = test::call_service(&srv, request).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers()
                .get(http::header::CONTENT_ENCODING)
                .unwrap()
                .to_str()
                .unwrap(),
            "gzip"
        );
    }

    /// STATEMENT: `Files::try_compressed` serves the precompressed sibling preferred by
    /// `Accept-Encoding` with the original file's headers, and the original otherwise.
    ///
    /// HOW:
    /// - Create `app.js` with `.br` and `.gz` siblings, and `docs/index.html` with a
    ///   `.gz` sibling, and serve them behind `Compress` with `try_compressed`.
    /// - For each `Accept-Encoding` value, check the body, `Content-Encoding`, and
    ///   `Vary: accept-encoding`.
    /// - Check `Content-Type` and `Content-Disposition` match the original file, and
    ///   that the index file uses its `.gz` sibling as `text/html`.
    #[ntex::test]
    async fn test_files_try_compressed() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("app.js"), b"plain").unwrap();
        fs::write(dir.path().join("app.js.gz"), b"gzip-bytes").unwrap();
        fs::write(dir.path().join("app.js.br"), b"br-bytes").unwrap();
        fs::create_dir(dir.path().join("docs")).unwrap();
        fs::write(dir.path().join("docs/index.html"), b"<p>").unwrap();
        fs::write(dir.path().join("docs/index.html.gz"), b"index-gzip").unwrap();
        let srv = test::init_service(
            App::new().middleware(Compress::default()).service(
                Files::new("/", dir.path())
                    .index_file("index.html")
                    .try_compressed(),
            ),
        )
        .await;
        let get = |uri: &str, accept: Option<&str>| {
            let mut req = TestRequest::get().uri(uri);
            if let Some(accept) = accept {
                req = req.header(http::header::ACCEPT_ENCODING, accept);
            }
            req.to_request()
        };

        let plain = test::call_service(&srv, get("/app.js", None)).await;
        let content_type = plain
            .headers()
            .get(http::header::CONTENT_TYPE)
            .cloned()
            .unwrap();
        assert_eq!(
            plain
                .headers()
                .get(http::header::CONTENT_DISPOSITION)
                .unwrap(),
            "inline; filename=\"app.js\""
        );

        for (accept, body, encoding) in [
            (None, "plain", None),
            (Some("gzip, br"), "br-bytes", Some("br")),
            (Some("gzip, br;q=0.5"), "gzip-bytes", Some("gzip")),
            (Some("br;q=0, gzip"), "gzip-bytes", Some("gzip")),
            (Some("*"), "br-bytes", Some("br")),
            (Some("gzip;q=0.5, *;q=0"), "gzip-bytes", Some("gzip")),
            (Some("zstd, identity"), "plain", None),
            (Some("gzip;q=bogus, br;q=0"), "plain", None),
        ] {
            let resp = test::call_service(&srv, get("/app.js", accept)).await;
            assert_eq!(resp.status(), StatusCode::OK, "{accept:?}");
            let headers = resp.headers();
            assert_eq!(
                headers
                    .get(http::header::CONTENT_ENCODING)
                    .map(|v| v.to_str().unwrap()),
                encoding,
                "{accept:?}"
            );
            assert_eq!(headers.get(http::header::VARY).unwrap(), "accept-encoding");
            assert_eq!(headers.get(http::header::CONTENT_TYPE), Some(&content_type));
            assert_eq!(
                headers.get(http::header::CONTENT_DISPOSITION).unwrap(),
                "inline; filename=\"app.js\""
            );
            assert_eq!(test::read_body(resp).await, body.as_bytes(), "{accept:?}");
        }

        let resp = test::call_service(&srv, get("/docs/", Some("gzip"))).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(http::header::CONTENT_ENCODING).unwrap(),
            "gzip"
        );
        assert!(
            resp.headers()
                .get(http::header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );
        assert_eq!(test::read_body(resp).await, "index-gzip".as_bytes());
    }

    /// STATEMENT: Precompressed siblings are ignored unless enabled and usable, and
    /// ranges and validators apply to the sibling's bytes.
    ///
    /// HOW:
    /// - Without `try_compressed`, request `data.txt` with `gzip` and check the plain
    ///   body and no `Vary` header.
    /// - With it, request a `bytes=0-3` range and check `206`, `Content-Encoding: gzip`,
    ///   and a `Content-Range` of the sibling's length, then compare the `ETag` with
    ///   the plain response.
    /// - Make `.br` a directory and, on Unix, `.gz` of another file a symlink outside
    ///   the base, and check both requests fall back to the original file.
    #[ntex::test]
    async fn test_files_try_compressed_sibling_handling() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("data.txt"), b"plain-data").unwrap();
        fs::write(dir.path().join("data.txt.gz"), b"0123456789abcdef").unwrap();
        fs::create_dir(dir.path().join("data.txt.br")).unwrap();
        fs::write(dir.path().join("other.txt"), b"other").unwrap();
        fs::write(outside.path().join("secret.gz"), b"secret").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            outside.path().join("secret.gz"),
            dir.path().join("other.txt.gz"),
        )
        .unwrap();
        let get = |uri: &str, accept: &str| {
            TestRequest::get()
                .uri(uri)
                .header(http::header::ACCEPT_ENCODING, accept)
        };

        let srv = test::init_service(App::new().service(Files::new("/", dir.path()))).await;
        let resp = test::call_service(&srv, get("/data.txt", "gzip").to_request()).await;
        assert!(!resp.headers().contains_key(http::header::CONTENT_ENCODING));
        assert!(!resp.headers().contains_key(http::header::VARY));
        assert_eq!(test::read_body(resp).await, "plain-data".as_bytes());

        let srv =
            test::init_service(App::new().service(Files::new("/", dir.path()).try_compressed()))
                .await;
        let req = get("/data.txt", "gzip").header(http::header::RANGE, "bytes=0-3");
        let resp = test::call_service(&srv, req.to_request()).await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            resp.headers().get(http::header::CONTENT_ENCODING).unwrap(),
            "gzip"
        );
        assert_eq!(
            resp.headers().get(http::header::CONTENT_RANGE).unwrap(),
            "bytes 0-3/16"
        );
        let etag = resp.headers().get(http::header::ETAG).cloned();
        assert_eq!(test::read_body(resp).await, "0123".as_bytes());

        let resp = test::call_service(&srv, get("/data.txt", "identity").to_request()).await;
        assert_ne!(resp.headers().get(http::header::ETAG).cloned(), etag);

        for (uri, body) in [("/data.txt", "plain-data"), ("/other.txt", "other")] {
            let accept = if uri == "/data.txt" { "br" } else { "gzip" };
            let resp = test::call_service(&srv, get(uri, accept).to_request()).await;
            assert_eq!(resp.status(), StatusCode::OK, "{uri}");
            assert!(
                !resp.headers().contains_key(http::header::CONTENT_ENCODING),
                "{uri}"
            );
            assert_eq!(test::read_body(resp).await, body.as_bytes(), "{uri}");
        }
    }

    /// STATEMENT: `path_filter` sees the decoded relative path and request head before
    /// filesystem access, and a rejection behaves like a missing file.
    ///
    /// HOW:
    /// - Serve a directory with a filter that records its arguments and rejects
    ///   `.toml` paths and `HEAD` requests.
    /// - Request `/sub/%61.txt` and check `200` and the recorded path `sub/a.txt`.
    /// - Request `/secret.toml`, an existing file, and check `404 Not Found`.
    /// - Request an existing file with `HEAD` and check `404 Not Found`.
    /// - With a default handler, check `/secret.toml` returns the handler's body.
    #[ntex::test]
    async fn test_files_path_filter() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub").join("a.txt"), b"a").unwrap();
        fs::write(dir.path().join("secret.toml"), b"secret").unwrap();
        let seen = Rc::new(std::cell::RefCell::new(Vec::new()));
        let files = {
            let seen = seen.clone();
            Files::new("/", dir.path()).path_filter(move |path, head| {
                seen.borrow_mut().push(path.to_path_buf());
                head.method != Method::HEAD && path.extension().is_none_or(|ext| ext != "toml")
            })
        };

        let srv = test::init_service(App::new().service(files.clone())).await;
        let resp =
            test::call_service(&srv, TestRequest::with_uri("/sub/%61.txt").to_request()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(test::read_body(resp).await, "a".as_bytes());
        assert_eq!(
            seen.borrow().as_slice(),
            [Path::new("sub").join("a.txt")].as_slice()
        );

        let resp =
            test::call_service(&srv, TestRequest::with_uri("/secret.toml").to_request()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let req = TestRequest::with_uri("/sub/a.txt").method(Method::HEAD);
        let resp = test::call_service(&srv, req.to_request()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let srv = test::init_service(App::new().service(files.default_handler(
            |req: WebRequest<()>| async move {
                Ok::<_, Infallible>(req.into_response(HttpResponse::Ok().body("default")))
            },
        )))
        .await;
        let resp =
            test::call_service(&srv, TestRequest::with_uri("/secret.toml").to_request()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(test::read_body(resp).await, "default".as_bytes());
    }

    /// STATEMENT: A `NamedFile` registered as a service is served at its path with its
    /// configured settings, for `GET` and `HEAD` only.
    ///
    /// HOW:
    /// - Register `Cargo.toml` with an overridden content type and disabled
    ///   disposition, at the root and inside a `/s` scope.
    /// - Request `/Cargo.toml` and `/s/Cargo.toml` and check `200`, the content type,
    ///   no `Content-Disposition`, and the file body.
    /// - Check `/Cargo.toml/x` returns `404 Not Found` and `POST` returns
    ///   `405 Method Not Allowed`.
    #[ntex::test]
    async fn test_named_file_service() {
        let file = || {
            NamedFile::open("Cargo.toml")
                .unwrap()
                .set_content_type(mime::APPLICATION_OCTET_STREAM)
                .disable_content_disposition()
        };
        let srv = test::init_service(
            App::new()
                .service(file())
                .service(web::scope("/s").service(file())),
        )
        .await;

        for uri in ["/Cargo.toml", "/s/Cargo.toml"] {
            let resp = test::call_service(&srv, TestRequest::with_uri(uri).to_request()).await;
            assert_eq!(resp.status(), StatusCode::OK, "{uri}");
            assert_eq!(
                resp.headers().get(http::header::CONTENT_TYPE).unwrap(),
                "application/octet-stream"
            );
            assert!(
                !resp
                    .headers()
                    .contains_key(http::header::CONTENT_DISPOSITION)
            );
            assert_eq!(test::read_body(resp).await, fs::read("Cargo.toml").unwrap());
        }

        let resp =
            test::call_service(&srv, TestRequest::with_uri("/Cargo.toml/x").to_request()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let req = TestRequest::with_uri("/Cargo.toml").method(Method::POST);
        let resp = test::call_service(&srv, req.to_request()).await;
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    /// STATEMENT: The `NamedFile` service reopens its path for each request, keeps a
    /// custom `ETag`, and works as a default handler.
    ///
    /// HOW:
    /// - Use a temporary `index.html` with a custom `ETag` as the default handler
    ///   of `Files` and as the application default service.
    /// - Request a missing file through `Files` and an unrouted path, and check
    ///   both return the file body and the custom `ETag`.
    /// - Rewrite the file and check the next response has the new body.
    /// - Remove the file and check `404 Not Found`.
    #[ntex::test]
    async fn test_named_file_service_reopens_file() {
        let dir = tempfile::tempdir().unwrap();
        let index = dir.path().join("index.html");
        fs::write(&index, b"v1").unwrap();
        let file = || {
            NamedFile::open(&index)
                .unwrap()
                .set_etag(header::EntityTag::strong("fixed".into()))
        };
        let srv = test::init_service(
            App::new()
                .service(Files::new("/static", dir.path()).default_handler(file()))
                .default_service(file()),
        )
        .await;
        let get = |uri: &str| TestRequest::with_uri(uri).to_request();

        for uri in ["/static/missing", "/missing"] {
            let resp = test::call_service(&srv, get(uri)).await;
            assert_eq!(resp.status(), StatusCode::OK, "{uri}");
            assert_eq!(resp.headers().get(http::header::ETAG).unwrap(), "\"fixed\"");
            assert_eq!(test::read_body(resp).await, "v1".as_bytes(), "{uri}");
        }

        fs::write(&index, b"version-2").unwrap();
        let resp = test::call_service(&srv, get("/missing")).await;
        assert_eq!(test::read_body(resp).await, "version-2".as_bytes());

        fs::remove_file(&index).unwrap();
        let resp = test::call_service(&srv, get("/missing")).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[ntex::test]
    async fn test_named_file_allowed_method() {
        let req = TestRequest::default().method(Method::GET).to_http_request();
        let file = NamedFile::open("Cargo.toml").unwrap();
        let resp = test::respond_to(file, &req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[ntex::test]
    async fn test_static_files() {
        let srv =
            test::init_service(App::new().service(Files::new("/", ".").show_files_listing())).await;
        let req = TestRequest::with_uri("/missing").to_request();

        let resp = test::call_service(&srv, req).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let srv = test::init_service(App::new().service(Files::new("/", "."))).await;

        let req = TestRequest::default().to_request();
        let resp = test::call_service(&srv, req).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let srv =
            test::init_service(App::new().service(Files::new("/", ".").show_files_listing())).await;
        let req = TestRequest::with_uri("/tests").to_request();
        let resp = test::call_service(&srv, req).await;
        assert_eq!(
            resp.headers().get(http::header::CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );

        let bytes = test::read_body(resp).await;
        assert!(format!("{:?}", bytes).contains("/tests/test.png"));
    }

    /// STATEMENT: Directory redirects require an index file or listing and use
    /// `302 Found` unless permanent redirects are enabled.
    ///
    /// HOW:
    /// - Request a directory without a trailing slash with neither index nor listing
    ///   and check `404 Not Found`.
    /// - With an index file, check `302 Found` and a `404` for a missing path.
    /// - With a listing and no index, check `302 Found` with a slash-ended `Location`,
    ///   and that the slash-ended path renders the listing.
    /// - With `with_permanent_redirect`, check `308 Permanent Redirect` for both an
    ///   index file and a listing.
    #[ntex::test]
    async fn test_redirect_to_slash_directory() {
        // should not redirect if no index
        let srv = test::init_service(
            App::new().service(Files::new("/", ".").redirect_to_slash_directory()),
        )
        .await;
        let req = TestRequest::with_uri("/tests").to_request();
        let resp = test::call_service(&srv, req).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // should redirect if index present
        let srv = test::init_service(
            App::new().service(
                Files::new("/", ".")
                    .index_file("test.png")
                    .redirect_to_slash_directory(),
            ),
        )
        .await;
        let req = TestRequest::with_uri("/tests").to_request();
        let resp = test::call_service(&srv, req).await;
        assert_eq!(resp.status(), StatusCode::FOUND);

        // should not redirect if the path is wrong
        let req = TestRequest::with_uri("/not_existing").to_request();
        let resp = test::call_service(&srv, req).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // should redirect if listing is enabled
        let srv = test::init_service(
            App::new().service(
                Files::new("/", ".")
                    .show_files_listing()
                    .redirect_to_slash_directory(),
            ),
        )
        .await;
        let req = TestRequest::with_uri("/tests").to_request();
        let resp = test::call_service(&srv, req).await;
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(
            resp.headers().get(http::header::LOCATION).unwrap(),
            "/tests/"
        );
        let req = TestRequest::with_uri("/tests/").to_request();
        let resp = test::call_service(&srv, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        for files in [
            Files::new("/", ".").index_file("test.png"),
            Files::new("/", ".").show_files_listing(),
        ] {
            let srv = test::init_service(
                App::new().service(
                    files
                        .redirect_to_slash_directory()
                        .with_permanent_redirect(),
                ),
            )
            .await;
            let req = TestRequest::with_uri("/tests").to_request();
            let resp = test::call_service(&srv, req).await;
            assert_eq!(resp.status(), StatusCode::PERMANENT_REDIRECT);
            assert_eq!(
                resp.headers().get(http::header::LOCATION).unwrap(),
                "/tests/"
            );
        }
    }

    #[ntex::test]
    async fn test_static_files_bad_directory() {
        let _st: Files<(), ()> = Files::new("/", "missing");
        let _st: Files<(), ()> = Files::new("/", "Cargo.toml");
    }

    #[ntex::test]
    async fn test_default_handler_file_missing() {
        let st = Files::new("/", ".")
            .default_handler(|req: WebRequest<()>| async move {
                Ok::<_, Infallible>(req.into_response(HttpResponse::Ok().body("default content")))
            })
            .pipeline(())
            .await
            .unwrap();
        let req = TestRequest::with_uri("/missing").to_srv_request();

        let resp = st.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = test::read_body(resp).await;
        assert_eq!(bytes, Bytes::from_static(b"default content"));
    }

    //     #[ntex::test]
    //     async fn test_serve_index() {
    //         let st = Files::new(".").index_file("test.binary");
    //         let req = TestRequest::default().uri("/tests").finish();

    //         let resp = st.handle(&req).respond_to(&req).unwrap();
    //         let resp = resp.as_msg();
    //         assert_eq!(resp.status(), StatusCode::OK);
    //         assert_eq!(
    //             resp.headers()
    //                 .get(header::CONTENT_TYPE)
    //                 .expect("content type"),
    //             "application/octet-stream"
    //         );
    //         assert_eq!(
    //             resp.headers()
    //                 .get(header::CONTENT_DISPOSITION)
    //                 .expect("content disposition"),
    //             "attachment; filename=\"test.binary\""
    //         );

    //         let req = TestRequest::default().uri("/tests/").finish();
    //         let resp = st.handle(&req).respond_to(&req).unwrap();
    //         let resp = resp.as_msg();
    //         assert_eq!(resp.status(), StatusCode::OK);
    //         assert_eq!(
    //             resp.headers().get(header::CONTENT_TYPE).unwrap(),
    //             "application/octet-stream"
    //         );
    //         assert_eq!(
    //             resp.headers().get(header::CONTENT_DISPOSITION).unwrap(),
    //             "attachment; filename=\"test.binary\""
    //         );

    //         // nonexistent index file
    //         let req = TestRequest::default().uri("/tests/unknown").finish();
    //         let resp = st.handle(&req).respond_to(&req).unwrap();
    //         let resp = resp.as_msg();
    //         assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    //         let req = TestRequest::default().uri("/tests/unknown/").finish();
    //         let resp = st.handle(&req).respond_to(&req).unwrap();
    //         let resp = resp.as_msg();
    //         assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    //     }

    //     #[ntex::test]
    //     async fn test_serve_index_nested() {
    //         let st = Files::new(".").index_file("mod.rs");
    //         let req = TestRequest::default().uri("/src/client").finish();
    //         let resp = st.handle(&req).respond_to(&req).unwrap();
    //         let resp = resp.as_msg();
    //         assert_eq!(resp.status(), StatusCode::OK);
    //         assert_eq!(
    //             resp.headers().get(header::CONTENT_TYPE).unwrap(),
    //             "text/x-rust"
    //         );
    //         assert_eq!(
    //             resp.headers().get(header::CONTENT_DISPOSITION).unwrap(),
    //             "inline; filename=\"mod.rs\""
    //         );
    //     }

    //     #[ntex::test]
    //     fn integration_serve_index() {
    //         let srv = test::TestServer::with_factory(|| {
    //             App::new().handler(
    //                 "test",
    //                 Files::new(".").index_file("Cargo.toml"),
    //             )
    //         });

    //         let request = srv.get().uri(srv.url("/test")).finish().unwrap();
    //         let response = srv.execute(request.send()).unwrap();
    //         assert_eq!(response.status(), StatusCode::OK);
    //         let bytes = srv.execute(response.body()).unwrap();
    //         let data = Bytes::from(fs::read("Cargo.toml").unwrap());
    //         assert_eq!(bytes, data);

    //         let request = srv.get().uri(srv.url("/test/")).finish().unwrap();
    //         let response = srv.execute(request.send()).unwrap();
    //         assert_eq!(response.status(), StatusCode::OK);
    //         let bytes = srv.execute(response.body()).unwrap();
    //         let data = Bytes::from(fs::read("Cargo.toml").unwrap());
    //         assert_eq!(bytes, data);

    //         // nonexistent index file
    //         let request = srv.get().uri(srv.url("/test/unknown")).finish().unwrap();
    //         let response = srv.execute(request.send()).unwrap();
    //         assert_eq!(response.status(), StatusCode::NOT_FOUND);

    //         let request = srv.get().uri(srv.url("/test/unknown/")).finish().unwrap();
    //         let response = srv.execute(request.send()).unwrap();
    //         assert_eq!(response.status(), StatusCode::NOT_FOUND);
    //     }

    //     #[ntex::test]
    //     fn integration_percent_encoded() {
    //         let srv = test::TestServer::with_factory(|| {
    //             App::new().handler(
    //                 "test",
    //                 Files::new(".").index_file("Cargo.toml"),
    //             )
    //         });

    //         let request = srv
    //             .get()
    //             .uri(srv.url("/test/%43argo.toml"))
    //             .finish()
    //             .unwrap();
    //         let response = srv.execute(request.send()).unwrap();
    //         assert_eq!(response.status(), StatusCode::OK);
    //     }

    #[ntex::test]
    async fn test_path_buf() {
        assert_eq!(
            PathBufWrp::get_pathbuf("/test/.tt", false).map(|t| t.0),
            Err(UriSegmentError::BadStart('.'))
        );
        assert_eq!(
            PathBufWrp::get_pathbuf("/test/*tt", false).map(|t| t.0),
            Err(UriSegmentError::BadStart('*'))
        );
        assert_eq!(
            PathBufWrp::get_pathbuf("/test/tt:", false).map(|t| t.0),
            Err(UriSegmentError::BadEnd(':'))
        );
        assert_eq!(
            PathBufWrp::get_pathbuf("/test/tt<", false).map(|t| t.0),
            Err(UriSegmentError::BadEnd('<'))
        );
        assert_eq!(
            PathBufWrp::get_pathbuf("/test/tt>", false).map(|t| t.0),
            Err(UriSegmentError::BadEnd('>'))
        );
        assert_eq!(
            PathBufWrp::get_pathbuf("/seg1/seg2/", false).unwrap().0,
            PathBuf::from_iter(vec!["seg1", "seg2"])
        );
        assert_eq!(
            PathBufWrp::get_pathbuf("/seg1/../seg2/", false).unwrap().0,
            PathBuf::from_iter(vec!["seg2"])
        );
    }

    /// STATEMENT: Percent-encoded segments are validated after decoding, so they cannot
    /// bypass the traversal and hidden-file checks.
    ///
    /// HOW:
    /// - Call `PathBufWrp::get_pathbuf` with encoded `..`, a leading `.`, `/` and NUL.
    /// - Confirm each is rejected with the matching `UriSegmentError`.
    #[test]
    fn test_path_buf_encoded_segments() {
        assert_eq!(
            PathBufWrp::get_pathbuf("/%2e%2e/Cargo.toml", false).map(|t| t.0),
            Err(UriSegmentError::BadStart('.'))
        );
        assert_eq!(
            PathBufWrp::get_pathbuf("/%2ehidden", false).map(|t| t.0),
            Err(UriSegmentError::BadStart('.'))
        );
        assert_eq!(
            PathBufWrp::get_pathbuf("/%2Fetc%2Fpasswd", false).map(|t| t.0),
            Err(UriSegmentError::BadChar('/'))
        );
        assert_eq!(
            PathBufWrp::get_pathbuf("/src%2F..%2F..%2FCargo.toml", false).map(|t| t.0),
            Err(UriSegmentError::BadChar('/'))
        );
        assert_eq!(
            PathBufWrp::get_pathbuf("/a%00b", false).map(|t| t.0),
            Err(UriSegmentError::BadChar('\0'))
        );
    }

    /// STATEMENT: With hidden files enabled, dot-prefixed segments are accepted, while
    /// decoded `.` and `..` segments are still rejected.
    ///
    /// HOW:
    /// - Parse `.env`, `.git/config` and `..rc` with `hidden` set and check the resulting paths.
    /// - Parse plain and percent-encoded `.` and `..` segments and expect `BadStart('.')`.
    /// - On Windows, expect `...` and `.. ` to be rejected, since Windows drops trailing
    ///   dots and spaces.
    #[test]
    fn test_path_buf_hidden() {
        for (path, expected) in [
            ("/.env", vec![".env"]),
            ("/.git/config", vec![".git", "config"]),
            ("/a/..rc", vec!["a", "..rc"]),
            ("/a/../.env", vec![".env"]),
        ] {
            assert_eq!(
                PathBufWrp::get_pathbuf(path, true).unwrap().0,
                PathBuf::from_iter(expected),
                "{path}"
            );
        }
        for path in ["/a/./b", "/%2e/b", "/%2e%2e/Cargo.toml", "/a/.%2e"] {
            assert_eq!(
                PathBufWrp::get_pathbuf(path, true).map(|t| t.0),
                Err(UriSegmentError::BadStart('.')),
                "{path}"
            );
        }
        if cfg!(windows) {
            for path in ["/...", "/..%20", "/.%20."] {
                assert_eq!(
                    PathBufWrp::get_pathbuf(path, true).map(|t| t.0),
                    Err(UriSegmentError::BadStart('.')),
                    "{path}"
                );
            }
        }
    }

    /// STATEMENT: `Files::use_hidden_files` serves dot files and directories, keeps them
    /// out of listings, and still confines requests to the base directory.
    ///
    /// HOW:
    /// - Serve a directory with `.secret` and `.hidden-dir/inner.txt` with hidden files
    ///   and listings enabled.
    /// - Request both files and compare the bodies.
    /// - Check the root listing omits both dot entries.
    /// - Request `.` and encoded `..` segments and expect `400 Bad Request`.
    #[ntex::test]
    async fn test_files_use_hidden_files() {
        let root = tempfile::tempdir_in(".").unwrap();
        fs::write(root.path().join(".secret"), b"hidden").unwrap();
        fs::create_dir(root.path().join(".hidden-dir")).unwrap();
        fs::write(root.path().join(".hidden-dir/inner.txt"), b"inner").unwrap();
        let srv = test::init_service(
            App::new().service(
                Files::new("/static", root.path())
                    .use_hidden_files()
                    .show_files_listing(),
            ),
        )
        .await;

        for (uri, body) in [
            ("/static/.secret", &b"hidden"[..]),
            ("/static/.hidden-dir/inner.txt", b"inner"),
        ] {
            let resp = test::call_service(&srv, TestRequest::with_uri(uri).to_request()).await;
            assert_eq!(resp.status(), StatusCode::OK, "{uri}");
            assert_eq!(test::read_body(resp).await, body, "{uri}");
        }

        let resp = test::call_service(&srv, TestRequest::with_uri("/static/").to_request()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
        assert!(!body.contains(".secret"), "{body}");
        assert!(!body.contains(".hidden-dir"), "{body}");

        for uri in ["/static/./.secret", "/static/%2e%2e/Cargo.toml"] {
            let resp = test::call_service(&srv, TestRequest::with_uri(uri).to_request()).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{uri}");
        }
    }

    /// STATEMENT: Encoded traversal requests cannot read files outside of the base directory.
    ///
    /// HOW:
    /// - Serve the `src` directory, so the crate's `Cargo.toml` lies outside the root.
    /// - Request it through encoded `..` and `/` segments.
    /// - Confirm each request is rejected with `400 Bad Request`.
    #[ntex::test]
    async fn test_encoded_traversal_rejected() {
        let srv = test::init_service(App::new().service(Files::new("/", "src"))).await;

        for uri in [
            "/%2e%2e/Cargo.toml",
            "/lib.rs%2F..%2F..%2FCargo.toml",
            "/%2FCargo.toml",
        ] {
            let req = TestRequest::with_uri(uri).to_request();
            let resp = test::call_service(&srv, req).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{uri}");
        }
    }

    /// STATEMENT: Symlinks that resolve outside of the base directory are only served
    /// when `Files::follow_symlinks` is enabled.
    ///
    /// HOW:
    /// - Create a root directory with a symlinked file and a symlinked index file,
    ///   both pointing at a file in another directory.
    /// - Confirm both answer `404 Not Found` by default.
    /// - Enable `follow_symlinks(true)` and confirm both are served with `200 OK`.
    #[cfg(unix)]
    #[ntex::test]
    async fn test_symlink_outside_root() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let secret = outside.path().join("secret.txt");
        fs::write(&secret, "secret").unwrap();
        std::os::unix::fs::symlink(&secret, root.path().join("link.txt")).unwrap();
        fs::create_dir(root.path().join("sub")).unwrap();
        std::os::unix::fs::symlink(&secret, root.path().join("sub/index.txt")).unwrap();

        for (follow, status) in [(false, StatusCode::NOT_FOUND), (true, StatusCode::OK)] {
            let files = Files::new("/", root.path())
                .index_file("index.txt")
                .follow_symlinks(follow);
            let srv = test::init_service(App::new().service(files)).await;

            for uri in ["/link.txt", "/sub/"] {
                let req = TestRequest::with_uri(uri).to_request();
                let resp = test::call_service(&srv, req).await;
                assert_eq!(resp.status(), status, "{uri} follow={follow}");
            }
        }
    }

    /// STATEMENT: `is_hidden` checks dot-prefixed components below the root, or the whole
    /// path when it lies outside of the root.
    ///
    /// HOW:
    /// - Pass a root that itself has a dot component and confirm visible paths below it
    ///   are not hidden.
    /// - Confirm a dot-prefixed file or directory below the root is hidden.
    /// - Confirm a path outside of the root with a dot component is hidden.
    #[test]
    fn test_is_hidden() {
        let root = Path::new("/srv/.site");
        assert!(!is_hidden(root, &root.join("index.html")));
        assert!(!is_hidden(root, &root.join("a.b/c.txt")));
        assert!(is_hidden(root, &root.join(".env")));
        assert!(is_hidden(root, &root.join(".git/config")));
        assert!(is_hidden(root, Path::new("/home/user/.ssh/id")));
        assert!(!is_hidden(root, Path::new("/home/user/file")));
    }

    /// STATEMENT: On Windows, a short-name alias of a hidden file is not served.
    ///
    /// HOW:
    /// - Create `.secret-file` and look up its 8.3 short name with `cmd`; skip when the
    ///   volume has no short names.
    /// - Request the short name and confirm `404 Not Found` instead of the file contents.
    #[cfg(windows)]
    #[ntex::test]
    async fn test_windows_short_name_hidden() {
        use std::os::windows::process::CommandExt;

        let root = tempfile::tempdir().unwrap();
        let secret = root.path().join(".secret-file");
        fs::write(&secret, "secret").unwrap();

        let out = std::process::Command::new("cmd")
            .raw_arg(format!(
                "/C for %I in (\"{}\") do @echo %~sI",
                secret.display()
            ))
            .output()
            .unwrap();
        let short = String::from_utf8_lossy(&out.stdout);
        let Some(name) = Path::new(short.trim())
            .file_name()
            .and_then(|n| n.to_str())
            .filter(|n| !n.starts_with('.'))
            .map(ToString::to_string)
        else {
            return;
        };

        let srv = test::init_service(App::new().service(Files::new("/", root.path()))).await;
        let req = TestRequest::with_uri(&format!("/{name}")).to_request();
        let resp = test::call_service(&srv, req).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{name}");
    }

    /// STATEMENT: Directory listings escape file names in both link targets and link text.
    ///
    /// HOW:
    /// - List a directory holding a file whose name contains `"`, `<` and `>`.
    /// - Confirm the raw markup never appears in the body.
    /// - Confirm the link target is percent-encoded and the link text is html-escaped.
    #[cfg(unix)]
    #[ntex::test]
    async fn test_files_listing_escapes_names() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("a\"><b>.txt"), "x").unwrap();

        let srv = test::init_service(
            App::new().service(Files::new("/", root.path()).show_files_listing()),
        )
        .await;
        let req = TestRequest::with_uri("/").to_request();
        let resp = test::call_service(&srv, req).await;
        let body = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();

        assert!(!body.contains("\"><b>"), "{body}");
        assert!(body.contains("href=\"/a%22%3E%3Cb%3E.txt\""), "{body}");
        assert!(body.contains(">a&quot;&gt;&lt;b&gt;.txt</a>"), "{body}");
    }

    /// STATEMENT: A base directory that cannot be resolved never falls back to serving
    /// the current working directory.
    ///
    /// HOW:
    /// - Create `Files` for a missing directory.
    /// - Request `Cargo.toml`, which exists in the current working directory.
    /// - Confirm the response is `404 Not Found`.
    #[ntex::test]
    async fn test_missing_root_serves_nothing() {
        let srv = test::init_service(App::new().service(Files::new("/", "missing"))).await;
        let req = TestRequest::with_uri("/Cargo.toml").to_request();
        let resp = test::call_service(&srv, req).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
    /// STATEMENT: `ChunkedReadFile` ends after a failed read instead of polling it again.
    ///
    /// HOW:
    /// - Read `tests/test.binary` with a `size` larger than the file.
    /// - Check that the stream yields the file, then `UnexpectedEof`, then ends.
    #[ntex::test]
    async fn test_chunked_read_file_ends_after_error() {
        use futures::StreamExt;

        let mut reader = ChunkedReadFile {
            size: 110,
            offset: 0,
            file: Some(File::open("tests/test.binary").unwrap()),
            fut: None,
            counter: 0,
            sync: false,
        };
        assert_eq!(reader.next().await.unwrap().unwrap().len(), 100);
        let err = reader.next().await.unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert!(reader.next().await.is_none());
    }

    /// STATEMENT: A synchronous `ChunkedReadFile` returns each chunk from the first poll
    /// and still ends after a failed read.
    ///
    /// HOW:
    /// - Read `tests/test.binary` with `sync` set and a `size` larger than the file.
    /// - Poll with a no-op waker and require `Ready` for the file bytes, then for
    ///   `UnexpectedEof`, then for the end of the stream.
    #[test]
    fn test_chunked_read_file_sync() {
        let mut reader = ChunkedReadFile {
            size: 110,
            offset: 0,
            file: Some(File::open("tests/test.binary").unwrap()),
            fut: None,
            counter: 0,
            sync: true,
        };
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        let Poll::Ready(Some(Ok(chunk))) = Pin::new(&mut reader).poll_next(&mut cx) else {
            panic!("expected a ready chunk");
        };
        assert_eq!(chunk, fs::read("tests/test.binary").unwrap());
        let Poll::Ready(Some(Err(err))) = Pin::new(&mut reader).poll_next(&mut cx) else {
            panic!("expected a ready error");
        };
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert!(matches!(
            Pin::new(&mut reader).poll_next(&mut cx),
            Poll::Ready(None)
        ));
    }

    /// STATEMENT: `Files::read_mode_threshold` makes ranges smaller than the threshold
    /// readable without the blocking thread pool.
    ///
    /// HOW:
    /// - Serve the crate directory with a 1 MiB threshold and request bytes 10-19 of
    ///   `tests/test.binary`.
    /// - Poll the response body once with a no-op waker and require the ready chunk
    ///   to equal those file bytes.
    #[ntex::test]
    async fn test_files_read_mode_threshold() {
        use futures::StreamExt;

        let srv = test::init_service(
            App::new().service(Files::new("/", ".").read_mode_threshold(1024 * 1024)),
        )
        .await;
        let req = TestRequest::with_uri("/tests/test.binary")
            .header(http::header::RANGE, "bytes=10-19")
            .to_request();
        let mut resp = test::call_service(&srv, req).await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);

        let mut body = resp.take_body();
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());
        let Poll::Ready(Some(Ok(chunk))) = body.poll_next_unpin(&mut cx) else {
            panic!("expected a ready chunk");
        };
        assert_eq!(chunk, fs::read("tests/test.binary").unwrap()[10..20]);
    }

    /// STATEMENT: `Files` resolves and opens files on the web worker by default, and on
    /// the blocking thread pool when `Files::open_on_thread_pool` is enabled.
    ///
    /// HOW:
    /// - Call the default service for `/Cargo.toml`, poll the response future once with
    ///   a no-op waker, and require a ready `200 OK`.
    /// - Repeat with `open_on_thread_pool(true)`; require the first poll to be pending
    ///   and the awaited response to be `200 OK`.
    #[ntex::test]
    async fn test_files_open_on_thread_pool() {
        let mut cx = Context::from_waker(futures::task::noop_waker_ref());

        let st = Files::new("/", ".").pipeline(()).await.unwrap();
        let mut fut =
            std::pin::pin!(st.call(TestRequest::with_uri("/Cargo.toml").to_srv_request()));
        let Poll::Ready(Ok(resp)) = fut.as_mut().poll(&mut cx) else {
            panic!("expected a ready response");
        };
        assert_eq!(resp.status(), StatusCode::OK);

        let st = Files::new("/", ".")
            .open_on_thread_pool(true)
            .pipeline(())
            .await
            .unwrap();
        let mut fut =
            std::pin::pin!(st.call(TestRequest::with_uri("/Cargo.toml").to_srv_request()));
        assert!(fut.as_mut().poll(&mut cx).is_pending());
        assert_eq!(fut.await.unwrap().status(), StatusCode::OK);
    }

    /// Returns the number of entries in the metadata cache of `files`.
    fn cached<St: State, In>(files: &Files<St, In>) -> usize {
        files
            .cache
            .as_ref()
            .map_or(0, |cache| cache.entries.borrow().len())
    }

    /// STATEMENT: A cached file is served with its current contents after it is rewritten
    /// or replaced on disk, and is not served once it is removed or its path becomes a
    /// symlink to it.
    ///
    /// HOW:
    /// - Serve `a.txt` through a metadata cache and check one cached entry.
    /// - Rewrite it in place with a longer body, then rename another file over it, and
    ///   check each response returns the new bytes.
    /// - Remove it and check `404 Not Found` and an empty cache.
    /// - Recreate and serve it, move it outside of the base, put a symlink to it at its
    ///   old path, and check `404 Not Found` instead of the cached file.
    /// - Serve `sub/b.txt`, replace `sub` with a symlink to an outside directory with
    ///   another `b.txt`, and check `404 Not Found` instead of the outside file.
    #[cfg(unix)]
    #[ntex::test]
    async fn cached_files_follow_disk_changes() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let path = root.path().join("a.txt");
        fs::write(&path, "one").unwrap();
        let files = Files::new("/", root.path()).metadata_cache(16, Millis(60_000));
        let srv = test::init_service(App::new().service(files.clone())).await;
        let req = || TestRequest::with_uri("/a.txt").to_request();

        let resp = test::call_service(&srv, req()).await;
        assert_eq!(test::read_body(resp).await, "one".as_bytes());
        assert_eq!(cached(&files), 1);

        fs::write(&path, "rewritten").unwrap();
        let resp = test::call_service(&srv, req()).await;
        assert_eq!(test::read_body(resp).await, "rewritten".as_bytes());

        let tmp = root.path().join("a.tmp");
        fs::write(&tmp, "replaced").unwrap();
        fs::rename(&tmp, &path).unwrap();
        let resp = test::call_service(&srv, req()).await;
        assert_eq!(test::read_body(resp).await, "replaced".as_bytes());
        assert_eq!(cached(&files), 1);

        fs::remove_file(&path).unwrap();
        let resp = test::call_service(&srv, req()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(cached(&files), 0);

        fs::write(&path, "moved").unwrap();
        let resp = test::call_service(&srv, req()).await;
        assert_eq!(test::read_body(resp).await, "moved".as_bytes());
        let moved = outside.path().join("a.txt");
        fs::rename(&path, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &path).unwrap();
        let resp = test::call_service(&srv, req()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        fs::create_dir(root.path().join("sub")).unwrap();
        fs::write(root.path().join("sub/b.txt"), "inside").unwrap();
        fs::write(outside.path().join("b.txt"), "outside").unwrap();
        let req = || TestRequest::with_uri("/sub/b.txt").to_request();
        let resp = test::call_service(&srv, req()).await;
        assert_eq!(test::read_body(resp).await, "inside".as_bytes());
        fs::rename(root.path().join("sub"), root.path().join("old")).unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("sub")).unwrap();
        let resp = test::call_service(&srv, req()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// STATEMENT: A cached file serves its precompressed siblings as they are on disk and
    /// looks up a missing sibling again once the entry expires.
    ///
    /// HOW:
    /// - Serve `app.js` with a `.br` sibling through a metadata cache with a 50 ms
    ///   lifetime and check a `br` request gets the sibling.
    /// - Remove the sibling and check the original is served without `Content-Encoding`.
    /// - Create the sibling again, sleep past the lifetime, and check the new sibling
    ///   is served with `Content-Encoding: br`.
    #[cfg(unix)]
    #[ntex::test]
    async fn cached_files_follow_sibling_changes() {
        let root = tempfile::tempdir().unwrap();
        let br = root.path().join("app.js.br");
        fs::write(root.path().join("app.js"), "plain").unwrap();
        fs::write(&br, "br-bytes").unwrap();
        let files = Files::new("/", root.path())
            .try_compressed()
            .metadata_cache(16, Millis(50));
        let srv = test::init_service(App::new().service(files.clone())).await;
        let req = || {
            TestRequest::with_uri("/app.js")
                .header(http::header::ACCEPT_ENCODING, "br")
                .to_request()
        };
        let encoding = |resp: &http::Response| {
            resp.headers()
                .get(http::header::CONTENT_ENCODING)
                .map(|v| v.to_str().unwrap().to_owned())
        };

        let resp = test::call_service(&srv, req()).await;
        assert_eq!(encoding(&resp).as_deref(), Some("br"));
        assert_eq!(test::read_body(resp).await, "br-bytes".as_bytes());
        assert_eq!(cached(&files), 1);

        fs::remove_file(&br).unwrap();
        let resp = test::call_service(&srv, req()).await;
        assert_eq!(encoding(&resp), None);
        assert_eq!(test::read_body(resp).await, "plain".as_bytes());

        fs::write(&br, "new-br").unwrap();
        ntex::time::sleep(Millis(100)).await;
        let resp = test::call_service(&srv, req()).await;
        assert_eq!(encoding(&resp).as_deref(), Some("br"));
        assert_eq!(test::read_body(resp).await, "new-br".as_bytes());
    }

    /// STATEMENT: The metadata cache is enabled by default, holds at most its capacity,
    /// and is not used for index files, paths through symlinks, or files opened on the
    /// thread pool.
    ///
    /// HOW:
    /// - With a capacity of 1, request two files and check both are served while one
    ///   entry is cached.
    /// - With the default cache, request a directory with an index file and the index
    ///   file through a symlinked directory, and check both are served without an
    ///   entry; then request a file and check it is cached.
    /// - With `open_on_thread_pool(true)`, request a file and check it is served
    ///   without an entry.
    #[cfg(unix)]
    #[ntex::test]
    async fn metadata_cache_capacity_and_scope() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("a.txt"), "a").unwrap();
        fs::write(root.path().join("b.txt"), "b").unwrap();
        fs::create_dir(root.path().join("dir")).unwrap();
        fs::write(root.path().join("dir/index.html"), "index").unwrap();
        std::os::unix::fs::symlink(root.path().join("dir"), root.path().join("link")).unwrap();
        let check = async |files: &Files<_, _>, uri: &str, body: &str, entries: usize| {
            let srv = test::init_service(App::new().service(files.clone())).await;
            let resp = test::call_service(&srv, TestRequest::with_uri(uri).to_request()).await;
            assert_eq!(resp.status(), StatusCode::OK, "{uri}");
            assert_eq!(test::read_body(resp).await, body.as_bytes(), "{uri}");
            assert_eq!(cached(files), entries, "{uri}");
        };

        let files = Files::new("/", root.path()).metadata_cache(1, Millis(60_000));
        check(&files, "/a.txt", "a", 1).await;
        check(&files, "/b.txt", "b", 1).await;

        let files = Files::new("/", root.path()).index_file("index.html");
        check(&files, "/dir/", "index", 0).await;
        check(&files, "/link/index.html", "index", 0).await;
        check(&files, "/a.txt", "a", 1).await;

        let files = Files::new("/", root.path()).open_on_thread_pool(true);
        check(&files, "/a.txt", "a", 0).await;
    }

    /// STATEMENT: Files served through the metadata cache send the same `ETag` and
    /// `Last-Modified` values as freshly opened files, including after in-place changes
    /// of the modification time or length, and precompressed siblings get their own.
    ///
    /// HOW:
    /// - Serve `a.txt` with a `.br` sibling through a cache with a 60 s lifetime and
    ///   compare both headers with values formatted from `NamedFile::open`.
    /// - Change only the modification time, then only the length, and check after each
    ///   change that the `ETag` changes and both headers match the fresh values.
    /// - Check `If-None-Match` with the current tag returns `304 Not Modified`.
    /// - Request the `.br` sibling and the original again, and check each matches its
    ///   own fresh values.
    #[cfg(unix)]
    #[ntex::test]
    async fn cached_files_send_current_validators() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("a.txt");
        let br = root.path().join("a.txt.br");
        fs::write(&br, "br-bytes").unwrap();
        let set = |content: &str, secs: u64| {
            fs::write(&path, content).unwrap();
            fs::File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_modified(UNIX_EPOCH + Duration::from_secs(secs))
                .unwrap();
        };
        let fresh = |path: &Path| {
            let file = NamedFile::open(path).unwrap();
            (
                header::ETag(file.etag().unwrap()).to_string(),
                header::LastModified(file.last_modified().unwrap()).to_string(),
            )
        };
        let files = Files::new("/", root.path())
            .try_compressed()
            .metadata_cache(16, Millis(60_000));
        let srv = test::init_service(App::new().service(files.clone())).await;
        let validators = async |encoding: Option<&str>| {
            let mut req = TestRequest::with_uri("/a.txt");
            if let Some(encoding) = encoding {
                req = req.header(http::header::ACCEPT_ENCODING, encoding);
            }
            let resp = test::call_service(&srv, req.to_request()).await;
            assert_eq!(resp.status(), StatusCode::OK);
            let value = |name| {
                resp.headers()
                    .get(name)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_owned()
            };
            (
                value(http::header::ETAG),
                value(http::header::LAST_MODIFIED),
            )
        };

        set("one", 1_000_000_000);
        let first = validators(None).await;
        assert_eq!(first, fresh(&path));
        assert_eq!(cached(&files), 1);

        set("one", 1_000_000_100);
        let touched = validators(None).await;
        assert_ne!(touched.0, first.0);
        assert_eq!(touched, fresh(&path));

        set("longer", 1_000_000_100);
        let resized = validators(None).await;
        assert_ne!(resized.0, touched.0);
        assert_eq!(resized, fresh(&path));
        assert_eq!(cached(&files), 1);

        let req = TestRequest::with_uri("/a.txt")
            .header(http::header::IF_NONE_MATCH, resized.0.as_str())
            .to_request();
        let resp = test::call_service(&srv, req).await;
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);

        assert_eq!(validators(Some("br")).await, fresh(&br));
        assert_eq!(validators(None).await, fresh(&path));
    }

    /// STATEMENT: Listings hide dot entries, escape ampersands, and mark visible directories with a slash.
    ///
    /// HOW:
    /// - Serve a directory containing a visible file, a named subdirectory, and hidden file and directory entries.
    /// - Check visible links and escaped directory text, then require direct hidden-file requests to fail.
    #[ntex::test]
    async fn listings_hide_dot_entries_and_mark_subdirectories() {
        let root = tempfile::tempdir_in(".").unwrap();
        fs::write(root.path().join("shown.txt"), b"visible").unwrap();
        fs::write(root.path().join(".secret"), b"hidden").unwrap();
        fs::create_dir(root.path().join("sub&dir")).unwrap();
        fs::create_dir(root.path().join(".hidden-dir")).unwrap();
        let srv = test::init_service(
            App::new().service(Files::new("/static", root.path()).show_files_listing()),
        )
        .await;
        let resp = test::call_service(&srv, TestRequest::with_uri("/static/").to_request()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
        assert!(body.contains("href=\"/static/shown.txt\""), "{body}");
        assert!(
            body.contains("href=\"/static/sub&amp;dir\">sub&amp;dir/</a>"),
            "{body}"
        );
        assert!(!body.contains(".secret"), "{body}");
        assert!(!body.contains(".hidden-dir"), "{body}");
        for uri in ["/static/.secret", "/static/.hidden-dir/"] {
            let resp = test::call_service(&srv, TestRequest::with_uri(uri).to_request()).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{uri}");
        }
    }

    /// STATEMENT: Entries whose metadata disappeared are excluded from directory listings.
    ///
    /// HOW:
    /// - Obtain a directory entry for a file, then remove the file before visibility checking.
    /// - Check the formerly visible entry becomes invisible instead of causing a panic.
    /// - Skipped on Windows, where `DirEntry::metadata` returns data cached by the
    ///   directory scan and still succeeds after removal.
    #[cfg(not(windows))]
    #[test]
    fn disappeared_directory_entries_are_not_visible() {
        let root = tempfile::tempdir_in(".").unwrap();
        let path = root.path().join("gone.txt");
        fs::write(&path, b"gone").unwrap();
        let entry = root.path().read_dir().unwrap().next().unwrap();
        let directory = Directory::new(root.path().into(), root.path().into());
        assert!(directory.is_visible(&entry));
        fs::remove_file(path).unwrap();
        assert!(!directory.is_visible(&entry));
    }

    /// STATEMENT: A custom listing renderer controls directory responses but not regular files.
    ///
    /// HOW:
    /// - Configure successful and failing renderers and request the root directory and a regular file.
    /// - Check the custom body or `404` error body for directories and unchanged bytes for the file.
    #[ntex::test]
    async fn custom_listing_renderer_handles_success_and_errors() {
        for fail in [false, true] {
            let files = Files::new("/static", "tests")
                .show_files_listing()
                .files_listing_renderer(move |_, req| {
                    if fail {
                        Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "listing denied",
                        ))
                    } else {
                        Ok(WebResponse::new(
                            HttpResponse::Ok().body("custom listing"),
                            req.clone(),
                        ))
                    }
                });
            let srv = test::init_service(App::new().service(files)).await;
            let resp =
                test::call_service(&srv, TestRequest::with_uri("/static/").to_request()).await;
            assert_eq!(
                resp.status(),
                if fail {
                    StatusCode::NOT_FOUND
                } else {
                    StatusCode::OK
                }
            );
            let body = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
            if fail {
                assert!(body.contains("listing denied"), "{body}");
            } else {
                assert_eq!(body, "custom listing");
            }
            let resp = test::call_service(
                &srv,
                TestRequest::with_uri("/static/test.binary").to_request(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK);
            assert_eq!(
                test::read_body(resp).await.as_ref(),
                fs::read("tests/test.binary").unwrap()
            );
        }
    }

    /// STATEMENT: Cloned `Files` configurations preserve guards, index serving, and disabled response headers in scopes.
    ///
    /// HOW:
    /// - Register a configured `Files` instance and its clone at root and nested scope mounts.
    /// - Check POST serves index bytes without disabled headers and GET is rejected at both mounts.
    #[ntex::test]
    async fn cloned_files_preserve_configuration_in_scopes() {
        let files = Files::new("/assets", "tests")
            .index_file("test.binary")
            .use_guards(guard::Post())
            .use_etag(false)
            .use_last_modified(false)
            .disable_content_disposition();
        let srv = test::init_service(
            App::new()
                .service(files.clone())
                .service(web::scope("/nested").service(files)),
        )
        .await;
        for uri in ["/assets/", "/nested/assets/"] {
            let req = TestRequest::with_uri(uri).method(Method::POST).to_request();
            let resp = test::call_service(&srv, req).await;
            assert_eq!(resp.status(), StatusCode::OK, "{uri}");
            for name in [
                http::header::ETAG,
                http::header::LAST_MODIFIED,
                http::header::CONTENT_DISPOSITION,
            ] {
                assert!(!resp.headers().contains_key(name.clone()), "{uri}: {name}");
            }
            assert_eq!(
                test::read_body(resp).await.as_ref(),
                fs::read("tests/test.binary").unwrap()
            );
            let resp = test::call_service(&srv, TestRequest::with_uri(uri).to_request()).await;
            assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED, "{uri}");
        }
    }

    /// STATEMENT: Directory visibility rejects unreadable entries and Unix sockets while keeping ordinary files visible.
    ///
    /// HOW:
    /// - Create a visible file and a bound Unix-domain socket, and provide an entry error.
    /// - Check visibility for each and require the served listing to contain only the ordinary file.
    #[cfg(unix)]
    #[ntex::test]
    async fn directory_listings_exclude_entry_errors_and_sockets() {
        let root = tempfile::tempdir_in(".").unwrap();
        fs::write(root.path().join("visible.txt"), b"visible").unwrap();
        let _socket = std::os::unix::net::UnixListener::bind(root.path().join("socket")).unwrap();
        let directory = Directory::new(root.path().into(), root.path().into());
        assert!(!directory.is_visible(&Err(io::Error::from(io::ErrorKind::PermissionDenied))));
        for entry in root.path().read_dir().unwrap() {
            let entry = entry.unwrap();
            let visible = entry.file_name() == "visible.txt";
            assert_eq!(directory.is_visible(&Ok(entry)), visible);
        }
        let srv = test::init_service(
            App::new().service(Files::new("/", root.path()).show_files_listing()),
        )
        .await;
        let resp = test::call_service(&srv, TestRequest::with_uri("/").to_request()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
        assert!(body.contains("href=\"/visible.txt\""));
        assert!(!body.contains("socket"));
    }

    /// STATEMENT: Listing links escape significant HTML characters in the mounted request path.
    ///
    /// HOW:
    /// - Mount a directory under a path containing quotes, apostrophes, angle brackets, and an ampersand.
    /// - Request its listing and check the link prefix is attribute-escaped and the file link remains usable.
    #[ntex::test]
    async fn directory_listing_escapes_mount_path_attributes() {
        let root = tempfile::tempdir_in(".").unwrap();
        fs::write(root.path().join("shown.txt"), b"shown").unwrap();
        let mount = "/\"'<&>";
        let srv = test::init_service(
            App::new().service(Files::new(mount, root.path()).show_files_listing()),
        )
        .await;
        let resp = test::call_service(
            &srv,
            TestRequest::with_uri(&format!("{mount}/")).to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = String::from_utf8(test::read_body(resp).await.to_vec()).unwrap();
        assert!(
            body.contains("href=\"/&quot;&#x27;&lt;&amp;&gt;/shown.txt\">shown.txt</a>"),
            "{body}"
        );
        let resp = test::call_service(
            &srv,
            TestRequest::with_uri(&format!("{mount}/shown.txt")).to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(test::read_body(resp).await.as_ref(), b"shown");
    }

    /// STATEMENT: Failing default-handler initialization prevents creation of the `Files` service.
    ///
    /// HOW:
    /// - Configure a fallback factory that fails to initialize with an I/O error.
    /// - Attempt to build the pipeline and require failure rather than serving without the configured fallback.
    #[ntex::test]
    async fn default_handler_initialization_errors_propagate() {
        struct FailingFactory;
        impl ServiceFactory<(), WebRequest<()>> for FailingFactory {
            type Res = WebResponse;
            type Error = Infallible;
            type Service = boxed::BoxService<(), WebRequest<()>, WebResponse, Infallible>;
            type InitError = io::Error;

            async fn create(&self, _: &()) -> Result<Self::Service, Self::InitError> {
                Err(io::Error::other("fallback initialization failed"))
            }
        }
        let result = Files::new("/", "tests")
            .default_handler(FailingFactory)
            .pipeline(())
            .await;
        assert!(result.is_err());
    }

    /// STATEMENT: Serving a `Range` with additional hyphens rejects the malformed byte-range specification.
    ///
    /// HOW:
    /// - Request a file with extra components after a closed or open byte range.
    /// - Require `416 Range Not Satisfiable` with the complete representation size in `Content-Range`.
    #[ntex::test]
    async fn malformed_ranges_with_extra_components_are_rejected() {
        for range in [
            "bytes=0-1-2",
            "bytes=1--2",
            "bytes=-1-2",
            "bytes=0-1-garbage",
        ] {
            let req = TestRequest::default()
                .header(http::header::RANGE, range)
                .to_http_request();
            let resp = NamedFile::open("tests/test.binary")
                .unwrap()
                .into_response(&req);
            assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE, "{range}");
            assert_eq!(
                resp.headers().get(http::header::CONTENT_RANGE).unwrap(),
                "bytes */100"
            );
        }
    }

    /// STATEMENT: Updating a parsed date header changes the file precondition from failed to satisfied.
    ///
    /// HOW:
    /// - Parse an `IfUnmodifiedSince` date before the file modification time and send it to the file.
    /// - Advance the wrapped date past the modification time and check `412` becomes `200` with the full body.
    #[ntex::test]
    async fn editing_parsed_date_headers_changes_conditional_responses() {
        use header::Header;

        let mut condition =
            header::IfUnmodifiedSince::parse_header(&header::Raw::from(http_date(PAST))).unwrap();
        let req = TestRequest::default()
            .header(IF_UNMODIFIED_SINCE, condition.to_string())
            .to_http_request();
        let resp = NamedFile::open("tests/test.binary")
            .unwrap()
            .into_response(&req);
        assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
        assert!(test::read_body(resp).await.is_empty());
        *condition = (SystemTime::from(*condition) + Duration::from_secs(FUTURE - PAST)).into();
        let req = TestRequest::default()
            .header(IF_UNMODIFIED_SINCE, condition.to_string())
            .to_http_request();
        let resp = NamedFile::open("tests/test.binary")
            .unwrap()
            .into_response(&req);
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            test::read_body(resp).await.as_ref(),
            fs::read("tests/test.binary").unwrap()
        );
    }
}
