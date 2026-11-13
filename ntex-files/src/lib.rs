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
use std::fs::{DirEntry, File};
use std::path::{Path, PathBuf};
use std::{cmp, fmt::Write, io, io::Read, io::Seek, pin::Pin, rc::Rc, task::Context, task::Poll};

use futures::{Future, Stream, future::FutureExt, future::LocalBoxFuture};
use mime_guess::from_ext;
use ntex::error::{Failure, IntoFailure};
use ntex::http::{Method, Payload, error::BlockingError};
use ntex::router::{ResourceDef, ResourcePath};
use ntex::service::boxed::{self, BoxService, BoxServiceFactory};
use ntex::url::Url;
use ntex::web::dev::{WebServiceConfig, WebServiceFactory};
use ntex::web::error::{WebError, WebResponseError};
use ntex::web::guard::Guard;
use ntex::web::{self, FromRequest, HttpRequest, HttpResponse, State, WebRequest, WebResponse};
use ntex::{Ctx, IntoServiceFactory, Service, ServiceFactory, util::Bytes};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};

mod error;
/// Typed HTTP headers used by static file responses.
pub mod header;
mod named;
mod range;

use self::error::{FilesError, UriSegmentError};
pub use crate::{named::NamedFile, range::HttpRange};

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
/// A file stream that reads chunks of up to 64 KiB on the blocking thread pool.
///
/// Read failures, premature end of file, and canceled blocking tasks yield an
/// [`io::Error`]; the stream ends after an error.
pub struct ChunkedReadFile {
    size: u64,
    offset: u64,
    file: Option<File>,
    fut: Option<LocalBoxFuture<'static, Result<(File, Bytes), BlockingError<io::Error>>>>,
    counter: u64,
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
            let Some(mut file) = self.file.take() else {
                return Poll::Ready(None);
            };
            self.fut = Some(
                web::block(move || {
                    let max_bytes: usize = cmp::min(size.saturating_sub(counter), 65_536) as usize;
                    let mut buf = Vec::with_capacity(max_bytes);
                    file.seek(io::SeekFrom::Start(offset))?;
                    let nbytes = file.by_ref().take(max_bytes as u64).read_to_end(&mut buf)?;
                    if nbytes == 0 {
                        return Err(io::ErrorKind::UnexpectedEof.into());
                    }
                    Ok((file, Bytes::from(buf)))
                })
                .boxed_local(),
            );
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
/// With the default web error handler, rejected methods or guards return
/// `405 Method Not Allowed`; resolution failures and directories without a
/// listing return `404 Not Found`. [`Self::default_handler`] handles resolution
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
    index: Option<String>,
    show_index: bool,
    redirect_to_slash: bool,
    default: Option<HttpServiceFactory<St, In>>,
    renderer: Rc<DirectoryRenderer>,
    mime_override: Option<Rc<MimeOverride>>,
    file_flags: named::Flags,
    guards: Option<Rc<dyn Guard>>,
    follow_symlinks: bool,
}

impl<St: State, In> Clone for Files<St, In> {
    fn clone(&self) -> Self {
        Self {
            directory: self.directory.clone(),
            index: self.index.clone(),
            show_index: self.show_index,
            redirect_to_slash: self.redirect_to_slash,
            default: self.default.clone(),
            renderer: self.renderer.clone(),
            file_flags: self.file_flags.clone(),
            path: self.path.clone(),
            mime_override: self.mime_override.clone(),
            guards: self.guards.clone(),
            follow_symlinks: self.follow_symlinks,
        }
    }
}

impl<St: State, In: 'static> Files<St, In> {
    /// Creates a service at the URL prefix `path` with filesystem base `dir`.
    ///
    /// Canonicalizes `dir` immediately. If this fails, logs the error and retains
    /// the supplied path; later request resolution may still fail. Resolution,
    /// metadata access, and file opening for requests run on the blocking
    /// thread pool, as do file reads. Directory rendering runs on the web worker.
    ///
    /// Request resolution failures use [`Self::default_handler`] when configured,
    /// or return `404 Not Found` with the default web error handler.
    pub fn new<T: Into<PathBuf>>(path: &str, dir: T) -> Self {
        let orig_dir = dir.into();
        let dir = match orig_dir.canonicalize() {
            Ok(canon_dir) => canon_dir,
            Err(e) => {
                log::error!("Cannot resolve static files directory {orig_dir:?}: {e}");
                orig_dir
            }
        };

        Files {
            path: path.to_string(),
            directory: dir,
            index: None,
            show_index: false,
            redirect_to_slash: false,
            default: None,
            renderer: Rc::new(directory_listing),
            mime_override: None,
            file_flags: named::Flags::default(),
            guards: None,
            follow_symlinks: false,
        }
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

    /// Enables `302 Found` redirects to slash-ended directory paths.
    ///
    /// Disabled by default, and only effective when an index file is configured.
    /// The redirect uses the request path with `/` appended, without its query
    /// string, before attempting to open the index file.
    pub fn redirect_to_slash_directory(mut self) -> Self {
        self.redirect_to_slash = true;
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
    /// targets, and canceled blocking resolution tasks. It is not used for
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
        config.register_service(rdef, None, None, self)
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
            index: self.index.clone(),
            show_index: self.show_index,
            redirect_to_slash: self.redirect_to_slash,
            default: None,
            renderer: self.renderer.clone(),
            mime_override: self.mime_override.clone(),
            file_flags: self.file_flags.clone(),
            guards: self.guards.clone(),
            follow_symlinks: self.follow_symlinks,
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
    index: Option<String>,
    show_index: bool,
    redirect_to_slash: bool,
    default: Option<HttpService<St, In>>,
    renderer: Rc<DirectoryRenderer>,
    mime_override: Option<Rc<MimeOverride>>,
    file_flags: named::Flags,
    guards: Option<Rc<dyn Guard>>,
    follow_symlinks: bool,
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

        let real_path = match PathBufWrp::get_pathbuf(req.match_info().path()) {
            Ok(item) => item,
            Err(e) => return Ok(req.error_response(ctx.st(), &FilesError::from(e))),
        };

        let directory = self.directory.clone();
        let index = self.index.clone();
        let redirect = self.redirect_to_slash && !req.path().ends_with('/');
        let follow_symlinks = self.follow_symlinks;
        let target = web::block(move || {
            resolve(
                &directory,
                real_path.0,
                index.as_deref(),
                redirect,
                follow_symlinks,
            )
        })
        .await;

        match target {
            Ok(Target::File(mut named_file)) => {
                if let Some(ref mime_override) = self.mime_override {
                    let new_disposition = mime_override(&named_file.content_type.type_());
                    named_file.content_disposition.disposition = new_disposition;
                }

                named_file.flags = self.file_flags.clone();
                let (req, _, _) = req.into_parts();
                Ok(WebResponse::new((*named_file).into_response(&req), req))
            }
            Ok(Target::Redirect) => {
                let redirect_to = format!("{}/", req.path());
                Ok(req.into_response(
                    HttpResponse::Found()
                        .header(http::header::LOCATION, redirect_to)
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
            Err(BlockingError::Error(e)) => self.handle_io_error(e, req, ctx).await,
            Err(BlockingError::Canceled) => {
                let e = io::Error::other("Operation is canceled");
                self.handle_io_error(e, req, ctx).await
            }
        }
    }
}

/// Filesystem object a request path resolves to.
enum Target {
    File(Box<NamedFile>),
    Dir(PathBuf),
    Redirect,
}

/// Resolves a request path inside of `directory`, runs on the blocking thread pool.
///
/// A canonical path outside of `directory` is reported as not found,
/// unless `follow_symlinks` is set.
fn resolve(
    directory: &Path,
    path: PathBuf,
    index: Option<&str>,
    redirect: bool,
    follow_symlinks: bool,
) -> io::Result<Target> {
    let contained = |path: PathBuf| -> io::Result<PathBuf> {
        let path = path.canonicalize()?;
        if follow_symlinks || path.starts_with(directory) {
            Ok(path)
        } else {
            Err(io::ErrorKind::NotFound.into())
        }
    };

    let path = contained(directory.join(path))?;
    if !path.is_dir() {
        return NamedFile::open(path).map(|file| Target::File(Box::new(file)));
    }
    match index {
        Some(_) if redirect => Ok(Target::Redirect),
        Some(index) => {
            NamedFile::open(contained(path.join(index))?).map(|file| Target::File(Box::new(file)))
        }
        None => Ok(Target::Dir(path)),
    }
}

#[derive(Debug)]
struct PathBufWrp(PathBuf);

impl PathBufWrp {
    fn get_pathbuf(path: &str) -> Result<Self, UriSegmentError> {
        let mut buf = PathBuf::new();
        for segment in path.split('/') {
            if segment == ".." {
                buf.pop();
                continue;
            }

            // validate the decoded segment, encoded characters must not bypass checks
            let segment = <Url as ResourcePath>::unquote(segment);
            if segment.starts_with('.') {
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
        PathBufWrp::get_pathbuf(req.match_info().path())
    }
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
            PathBufWrp::get_pathbuf("/test/.tt").map(|t| t.0),
            Err(UriSegmentError::BadStart('.'))
        );
        assert_eq!(
            PathBufWrp::get_pathbuf("/test/*tt").map(|t| t.0),
            Err(UriSegmentError::BadStart('*'))
        );
        assert_eq!(
            PathBufWrp::get_pathbuf("/test/tt:").map(|t| t.0),
            Err(UriSegmentError::BadEnd(':'))
        );
        assert_eq!(
            PathBufWrp::get_pathbuf("/test/tt<").map(|t| t.0),
            Err(UriSegmentError::BadEnd('<'))
        );
        assert_eq!(
            PathBufWrp::get_pathbuf("/test/tt>").map(|t| t.0),
            Err(UriSegmentError::BadEnd('>'))
        );
        assert_eq!(
            PathBufWrp::get_pathbuf("/seg1/seg2/").unwrap().0,
            PathBuf::from_iter(vec!["seg1", "seg2"])
        );
        assert_eq!(
            PathBufWrp::get_pathbuf("/seg1/../seg2/").unwrap().0,
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
            PathBufWrp::get_pathbuf("/%2e%2e/Cargo.toml").map(|t| t.0),
            Err(UriSegmentError::BadStart('.'))
        );
        assert_eq!(
            PathBufWrp::get_pathbuf("/%2ehidden").map(|t| t.0),
            Err(UriSegmentError::BadStart('.'))
        );
        assert_eq!(
            PathBufWrp::get_pathbuf("/%2Fetc%2Fpasswd").map(|t| t.0),
            Err(UriSegmentError::BadChar('/'))
        );
        assert_eq!(
            PathBufWrp::get_pathbuf("/src%2F..%2F..%2FCargo.toml").map(|t| t.0),
            Err(UriSegmentError::BadChar('/'))
        );
        assert_eq!(
            PathBufWrp::get_pathbuf("/a%00b").map(|t| t.0),
            Err(UriSegmentError::BadChar('\0'))
        );
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
        };
        assert_eq!(reader.next().await.unwrap().unwrap().len(), 100);
        let err = reader.next().await.unwrap().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert!(reader.next().await.is_none());
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
