#![allow(type_alias_bounds, clippy::borrow_interior_mutable_const, clippy::type_complexity)]

//! Static files support
use std::fs::{DirEntry, File};
use std::path::{Path, PathBuf};
use std::{
    cmp, fmt::Write, io, io::Read, io::Seek, pin::Pin, rc::Rc, task::Context, task::Poll,
};

use futures::future::{ok, ready, Either, FutureExt, LocalBoxFuture, Ready};
use futures::{Future, Stream};
use hyperx::header::DispositionType;
use mime_guess::from_ext;
use ntex::http::error::BlockingError;
use ntex::http::{header, Method, Payload, Uri};
use ntex::router::{ResourceDef, ResourcePath};
use ntex::service::boxed::{self, BoxService, BoxServiceFactory};
use ntex::service::{IntoServiceFactory, Service, ServiceFactory};
use ntex::util::Bytes;
use ntex::web::{WebRequest, WebResponse, dev::WebServiceConfig, WebServiceFactory};
use ntex::web::error::ErrorRenderer;
use ntex::web::guard::Guard;
use ntex::web::{self, FromRequest, HttpRequest, HttpResponse};
use percent_encoding::{utf8_percent_encode, CONTROLS};
use v_htmlescape::escape as escape_html_entity;

mod error;
mod named;
mod range;

use self::error::{FilesError, UriSegmentError};
pub use crate::named::NamedFile;
pub use crate::range::HttpRange;

type HttpService<Err: ErrorRenderer> = BoxService<WebRequest<Err>, WebResponse, Err::Container>;
type HttpServiceFactory<Err: ErrorRenderer> =
    BoxServiceFactory<(), WebRequest<Err>, WebResponse, Err::Container, ()>;

/// Return the MIME type associated with a filename extension (case-insensitive).
/// If `ext` is empty or no associated type for the extension was found, returns
/// the type `application/octet-stream`.
#[inline]
pub fn file_extension_to_mime(ext: &str) -> mime::Mime {
    from_ext(ext).first_or_octet_stream()
}

#[doc(hidden)]
/// A helper created from a `std::fs::File` which reads the file
/// chunk-by-chunk on a `ThreadPool`.
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
                        BlockingError::Canceled => {
                            io::Error::new(io::ErrorKind::Other, "Operation is canceled")
                        }
                    };
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
            let mut file = self.file.take().expect("Use after completion");
            self.fut = Some(
                web::block(move || {
                    let max_bytes: usize;
                    max_bytes = cmp::min(size.saturating_sub(counter), 65_536) as usize;
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

/// A directory; responds with the generated directory listing.
#[derive(Debug)]
pub struct Directory {
    /// Base directory
    pub base: PathBuf,
    /// Path of subdirectory to generate listing for
    pub path: PathBuf,
}

impl Directory {
    /// Create a new directory
    pub fn new(base: PathBuf, path: PathBuf) -> Directory {
        Directory { base, path }
    }

    /// Is this entry visible from this directory?
    pub fn is_visible(&self, entry: &io::Result<DirEntry>) -> bool {
        if let Ok(ref entry) = *entry {
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with('.') {
                    return false;
                }
            }
            if let Ok(ref md) = entry.metadata() {
                let ft = md.file_type();
                return ft.is_dir() || ft.is_file() || ft.is_symlink();
            }
        }
        false
    }
}

// show file url as relative to static path
macro_rules! encode_file_url {
    ($path:ident) => {
        utf8_percent_encode(&$path, CONTROLS)
    };
}

// " -- &quot;  & -- &amp;  ' -- &#x27;  < -- &lt;  > -- &gt;  / -- &#x2f;
macro_rules! encode_file_name {
    ($entry:ident) => {
        escape_html_entity(&$entry.file_name().to_string_lossy())
    };
}

fn directory_listing(dir: &Directory, req: &HttpRequest) -> Result<WebResponse, io::Error> {
    let index_of = format!("Index of {}", req.path());
    let mut body = String::new();
    let base = Path::new(req.path());

    for entry in dir.path.read_dir()? {
        if dir.is_visible(&entry) {
            let entry = entry.unwrap();
            let p = match entry.path().strip_prefix(&dir.path) {
                Ok(p) if cfg!(windows) => base.join(p).to_string_lossy().replace("\\", "/"),
                Ok(p) => base.join(p).to_string_lossy().into_owned(),
                Err(_) => continue,
            };

            // if file is a directory, add '/' to the end of the name
            if let Ok(metadata) = entry.metadata() {
                if metadata.is_dir() {
                    let _ = write!(
                        body,
                        "<li><a href=\"{}\">{}/</a></li>",
                        encode_file_url!(p),
                        encode_file_name!(entry),
                    );
                } else {
                    let _ = write!(
                        body,
                        "<li><a href=\"{}\">{}</a></li>",
                        encode_file_url!(p),
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
        HttpResponse::Ok().content_type("text/html; charset=utf-8").body(html),
        req.clone(),
    ))
}

type MimeOverride = dyn Fn(&mime::Name) -> DispositionType;

/// Static files handling
///
/// `Files` service must be registered with `App::service()` method.
///
/// ```rust
/// use ntex::web::App;
/// use ntex_files as fs;
///
/// fn main() {
///     let app = App::new()
///         .service(fs::Files::new("/static", "."));
/// }
/// ```
pub struct Files<Err: ErrorRenderer> {
    path: String,
    directory: PathBuf,
    index: Option<String>,
    show_index: bool,
    redirect_to_slash: bool,
    default: Option<Rc<HttpServiceFactory<Err>>>,
    renderer: Rc<DirectoryRenderer>,
    mime_override: Option<Rc<MimeOverride>>,
    file_flags: named::Flags,
    guards: Option<Rc<dyn Guard>>,
}

impl<Err: ErrorRenderer> Clone for Files<Err> {
    fn clone(&self) -> Self {
        Self {
            directory: self.directory.clone(),
            index: self.index.clone(),
            show_index: self.show_index,
            redirect_to_slash: self.redirect_to_slash,
            default: self.default.clone(),
            renderer: self.renderer.clone(),
            file_flags: self.file_flags,
            path: self.path.clone(),
            mime_override: self.mime_override.clone(),
            guards: self.guards.clone(),
        }
    }
}

impl<Err: ErrorRenderer> Files<Err> {
    /// Create new `Files` instance for specified base directory.
    ///
    /// `File` uses `ThreadPool` for blocking filesystem operations.
    /// By default pool with 5x threads of available cpus is used.
    /// Pool size can be changed by setting ACTIX_THREADPOOL environment variable.
    pub fn new<T: Into<PathBuf>>(path: &str, dir: T) -> Self {
        let orig_dir = dir.into();
        let dir = match orig_dir.canonicalize() {
            Ok(canon_dir) => canon_dir,
            Err(_) => {
                log::error!("Specified path is not a directory: {:?}", orig_dir);
                PathBuf::new()
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
        }
    }

    /// Show files listing for directories.
    ///
    /// By default show files listing is disabled.
    pub fn show_files_listing(mut self) -> Self {
        self.show_index = true;
        self
    }

    /// Redirects to a slash-ended path when browsing a directory.
    ///
    /// By default never redirect.
    pub fn redirect_to_slash_directory(mut self) -> Self {
        self.redirect_to_slash = true;
        self
    }

    /// Set custom directory renderer
    pub fn files_listing_renderer<F>(mut self, f: F) -> Self
    where
        for<'r, 's> F:
            Fn(&'r Directory, &'s HttpRequest) -> Result<WebResponse, io::Error> + 'static,
    {
        self.renderer = Rc::new(f);
        self
    }

    /// Specifies mime override callback
    pub fn mime_override<F>(mut self, f: F) -> Self
    where
        F: Fn(&mime::Name) -> DispositionType + 'static,
    {
        self.mime_override = Some(Rc::new(f));
        self
    }

    /// Set index file
    ///
    /// Shows specific index file for directory "/" instead of
    /// showing files listing.
    pub fn index_file<T: Into<String>>(mut self, index: T) -> Self {
        self.index = Some(index.into());
        self
    }

    #[inline]
    /// Specifies whether to use ETag or not.
    ///
    /// Default is true.
    pub fn use_etag(mut self, value: bool) -> Self {
        self.file_flags.set(named::Flags::ETAG, value);
        self
    }

    #[inline]
    /// Specifies whether to use Last-Modified or not.
    ///
    /// Default is true.
    pub fn use_last_modified(mut self, value: bool) -> Self {
        self.file_flags.set(named::Flags::LAST_MD, value);
        self
    }

    /// Specifies custom guards to use for directory listings and files.
    ///
    /// Default behaviour allows GET and HEAD.
    #[inline]
    pub fn use_guards<G: Guard + 'static>(mut self, guards: G) -> Self {
        self.guards = Some(Rc::new(guards));
        self
    }

    /// Disable `Content-Disposition` header.
    ///
    /// By default Content-Disposition` header is enabled.
    #[inline]
    pub fn disable_content_disposition(mut self) -> Self {
        self.file_flags.remove(named::Flags::CONTENT_DISPOSITION);
        self
    }

    /// Sets default handler which is used when no matched file could be found.
    pub fn default_handler<F, U>(mut self, f: F) -> Self
    where
        F: IntoServiceFactory<U>,
        U: ServiceFactory<
                Config = (),
                Request = WebRequest<Err>,
                Response = WebResponse,
                Error = Err::Container,
            > + 'static,
    {
        // create and configure default resource
        self.default = Some(Rc::new(boxed::factory(f.into_factory().map_init_err(|_| ()))));

        self
    }
}

impl<Err> WebServiceFactory<Err> for Files<Err>
where
    Err: ErrorRenderer,
    Err::Container: From<FilesError>,
{
    fn register(mut self, config: &mut WebServiceConfig<Err>) {
        if self.default.is_none() {
            self.default = Some(config.default_service());
        }
        let rdef = if config.is_root() {
            ResourceDef::root_prefix(&self.path)
        } else {
            ResourceDef::prefix(&self.path)
        };
        config.register_service(rdef, None, self, None)
    }
}

impl<Err> ServiceFactory for Files<Err>
where
    Err: ErrorRenderer,
    Err::Container: From<FilesError>,
{
    type Request = WebRequest<Err>;
    type Response = WebResponse;
    type Error = Err::Container;
    type Config = ();
    type Service = FilesService<Err>;
    type InitError = ();
    type Future = LocalBoxFuture<'static, Result<Self::Service, Self::InitError>>;

    fn new_service(&self, _: ()) -> Self::Future {
        let mut srv = FilesService {
            directory: self.directory.clone(),
            index: self.index.clone(),
            show_index: self.show_index,
            redirect_to_slash: self.redirect_to_slash,
            default: None,
            renderer: self.renderer.clone(),
            mime_override: self.mime_override.clone(),
            file_flags: self.file_flags,
            guards: self.guards.clone(),
        };

        if let Some(ref default) = self.default.as_ref() {
            default
                .new_service(())
                .map(move |result| match result {
                    Ok(default) => {
                        srv.default = Some(default);
                        Ok(srv)
                    }
                    Err(_) => Err(()),
                })
                .boxed_local()
        } else {
            ok(srv).boxed_local()
        }
    }
}

pub struct FilesService<Err: ErrorRenderer> {
    directory: PathBuf,
    index: Option<String>,
    show_index: bool,
    redirect_to_slash: bool,
    default: Option<HttpService<Err>>,
    renderer: Rc<DirectoryRenderer>,
    mime_override: Option<Rc<MimeOverride>>,
    file_flags: named::Flags,
    guards: Option<Rc<dyn Guard>>,
}

impl<Err: ErrorRenderer> FilesService<Err>
where
    Err::Container: From<FilesError>,
{
    fn handle_io_error(
        &self,
        e: io::Error,
        req: WebRequest<Err>,
    ) -> Either<
        Ready<Result<WebResponse, Err::Container>>,
        LocalBoxFuture<'static, Result<WebResponse, Err::Container>>,
    > {
        log::debug!("Files: Failed to handle {}: {}", req.path(), e);
        if let Some(ref default) = self.default {
            Either::Right(default.call(req))
        } else {
            Either::Left(ok(req.error_response(FilesError::from(e))))
        }
    }
}

impl<Err> Service for FilesService<Err>
where
    Err: ErrorRenderer,
    Err::Container: From<FilesError>,
{
    type Request = WebRequest<Err>;
    type Response = WebResponse;
    type Error = Err::Container;
    type Future = Either<
        Ready<Result<Self::Response, Self::Error>>,
        LocalBoxFuture<'static, Result<Self::Response, Self::Error>>,
    >;

    fn poll_ready(&self, _: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&self, req: WebRequest<Err>) -> Self::Future {
        let is_method_valid = if let Some(guard) = &self.guards {
            // execute user defined guards
            (**guard).check(req.head())
        } else {
            // default behaviour
            match *req.method() {
                Method::HEAD | Method::GET => true,
                _ => false,
            }
        };

        if !is_method_valid {
            return Either::Left(ok(req.error_response(FilesError::MethodNotAllowed)));
        }

        let real_path = match PathBufWrp::get_pathbuf(req.match_info().path()) {
            Ok(item) => item,
            Err(e) => return Either::Left(ok(req.error_response(FilesError::from(e)))),
        };

        // full filepath
        let path = match self.directory.join(&real_path.0).canonicalize() {
            Ok(path) => path,
            Err(e) => return self.handle_io_error(e, req),
        };

        if path.is_dir() {
            if let Some(ref redir_index) = self.index {
                if self.redirect_to_slash && !req.path().ends_with('/') {
                    let redirect_to = format!("{}/", req.path());
                    return Either::Left(ok(req.into_response(
                        HttpResponse::Found()
                            .header(header::LOCATION, redirect_to)
                            .body("")
                            .into_body(),
                    )));
                }

                let path = path.join(redir_index);

                match NamedFile::open(path) {
                    Ok(mut named_file) => {
                        if let Some(ref mime_override) = self.mime_override {
                            let new_disposition =
                                mime_override(&named_file.content_type.type_());
                            named_file.content_disposition.disposition = new_disposition;
                        }

                        named_file.flags = self.file_flags;
                        let (req, _) = req.into_parts();
                        Either::Left(ok(WebResponse::new(named_file.into_response(&req), req)))
                    }
                    Err(e) => self.handle_io_error(e, req),
                }
            } else if self.show_index {
                let dir = Directory::new(self.directory.clone(), path);
                let (req, _) = req.into_parts();
                let x = (self.renderer)(&dir, &req);
                match x {
                    Ok(resp) => Either::Left(ok(resp)),
                    Err(e) => Either::Left(ok(WebResponse::from_err::<Err, _>(
                        FilesError::from(e),
                        req,
                    ))),
                }
            } else {
                Either::Left(ok(WebResponse::from_err::<Err, _>(
                    FilesError::IsDirectory,
                    req.into_parts().0,
                )))
            }
        } else {
            match NamedFile::open(path) {
                Ok(mut named_file) => {
                    if let Some(ref mime_override) = self.mime_override {
                        let new_disposition = mime_override(&named_file.content_type.type_());
                        named_file.content_disposition.disposition = new_disposition;
                    }

                    named_file.flags = self.file_flags;
                    let (req, _) = req.into_parts();
                    Either::Left(ok(WebResponse::new(named_file.into_response(&req), req)))
                }
                Err(e) => self.handle_io_error(e, req),
            }
        }
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
            } else if segment.starts_with('.') {
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
            } else if cfg!(windows) && segment.contains('\\') {
                return Err(UriSegmentError::BadChar('\\'));
            } else {
                buf.push(Uri::unquote(segment).as_ref())
            }
        }

        Ok(PathBufWrp(buf))
    }
}

impl<Err> FromRequest<Err> for PathBufWrp {
    type Error = UriSegmentError;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        ready(PathBufWrp::get_pathbuf(req.match_info().path()))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::iter::FromIterator;
    use std::ops::Add;
    use std::time::{Duration, SystemTime};

    use super::*;
    use ntex::http::{self, Method, StatusCode};
    use ntex::web::middleware::Compress;
    use ntex::web::test::{self, TestRequest};
    use ntex::web::{guard, App, DefaultError};

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
        let since =
            hyperx::header::HttpDate::from(SystemTime::now().add(Duration::from_secs(60)));

        let req = TestRequest::default()
            .header(http::header::IF_MODIFIED_SINCE, since.to_string())
            .to_http_request();
        let resp = test::respond_to(file, &req).await;
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
    }

    #[ntex::test]
    async fn test_if_modified_since_with_if_none_match() {
        let file = NamedFile::open("Cargo.toml").unwrap();
        let since =
            hyperx::header::HttpDate::from(SystemTime::now().add(Duration::from_secs(60)));

        let req = TestRequest::default()
            .header(http::header::IF_NONE_MATCH, "miss_etag")
            .header(http::header::IF_MODIFIED_SINCE, since.to_string())
            .to_http_request();
        let resp = test::respond_to(file, &req).await;
        assert_ne!(resp.status(), StatusCode::NOT_MODIFIED);
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
        assert_eq!(resp.headers().get(http::header::CONTENT_TYPE).unwrap(), "text/x-toml");
        assert_eq!(
            resp.headers().get(http::header::CONTENT_DISPOSITION).unwrap(),
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
            resp.headers().get(http::header::CONTENT_DISPOSITION).unwrap(),
            "inline; filename=\"Cargo.toml\""
        );

        let file = NamedFile::open("Cargo.toml").unwrap().disable_content_disposition();
        let req = TestRequest::default().to_http_request();
        let resp = test::respond_to(file, &req).await;
        assert!(resp.headers().get(http::header::CONTENT_DISPOSITION).is_none());
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
        let mut file = NamedFile::open("Cargo.toml").unwrap().set_content_type(mime::TEXT_XML);
        {
            file.file();
            let _f: &File = &file;
        }
        {
            let _f: &mut File = &mut file;
        }

        let req = TestRequest::default().to_http_request();
        let resp = test::respond_to(file, &req).await;
        assert_eq!(resp.headers().get(http::header::CONTENT_TYPE).unwrap(), "text/xml");
        assert_eq!(
            resp.headers().get(http::header::CONTENT_DISPOSITION).unwrap(),
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
        assert_eq!(resp.headers().get(http::header::CONTENT_TYPE).unwrap(), "image/png");
        assert_eq!(
            resp.headers().get(http::header::CONTENT_DISPOSITION).unwrap(),
            "inline; filename=\"test.png\""
        );
    }

    #[ntex::test]
    async fn test_named_file_image_attachment() {
        use hyperx::header::{Charset, ContentDisposition, DispositionParam, DispositionType};

        let cd = ContentDisposition {
            disposition: DispositionType::Attachment,
            parameters: vec![DispositionParam::Filename(
                Charset::Ext(String::from("UTF-8")),
                None,
                "test.png".to_string().into_bytes(),
            )],
        };
        let mut file = NamedFile::open("tests/test.png").unwrap().set_content_disposition(cd);
        {
            file.file();
            let _f: &File = &file;
        }
        {
            let _f: &mut File = &mut file;
        }

        let req = TestRequest::default().to_http_request();
        let resp = test::respond_to(file, &req).await;
        assert_eq!(resp.headers().get(http::header::CONTENT_TYPE).unwrap(), "image/png");
        assert_eq!(
            resp.headers().get(http::header::CONTENT_DISPOSITION).unwrap(),
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
            resp.headers().get(http::header::CONTENT_DISPOSITION).unwrap(),
            "attachment; filename=\"test.binary\""
        );
    }

    #[ntex::test]
    async fn test_named_file_status_code_text() {
        let mut file =
            NamedFile::open("Cargo.toml").unwrap().set_status_code(StatusCode::NOT_FOUND);
        {
            file.file();
            let _f: &File = &file;
        }
        {
            let _f: &mut File = &mut file;
        }

        let req = TestRequest::default().to_http_request();
        let resp = test::respond_to(file, &req).await;
        assert_eq!(resp.headers().get(http::header::CONTENT_TYPE).unwrap(), "text/x-toml");
        assert_eq!(
            resp.headers().get(http::header::CONTENT_DISPOSITION).unwrap(),
            "inline; filename=\"Cargo.toml\""
        );
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[ntex::test]
    async fn test_mime_override() {
        fn all_attachment(_: &mime::Name) -> DispositionType {
            DispositionType::Attachment
        }

        let mut srv = test::init_service(App::new().service(
            Files::new("/", ".").mime_override(all_attachment).index_file("Cargo.toml"),
        ))
        .await;

        let request = TestRequest::get().uri("/").to_request();
        let response = test::call_service(&mut srv, request).await;
        assert_eq!(response.status(), StatusCode::OK);

        let content_disposition = response
            .headers()
            .get(http::header::CONTENT_DISPOSITION)
            .expect("To have CONTENT_DISPOSITION");
        let content_disposition =
            content_disposition.to_str().expect("Convert CONTENT_DISPOSITION to str");
        assert_eq!(content_disposition, "attachment; filename=\"Cargo.toml\"");
    }

    #[ntex::test]
    async fn test_named_file_ranges_status_code() {
        let mut srv = test::init_service(
            App::new().service(Files::new("/test", ".").index_file("Cargo.toml")),
        )
        .await;

        // Valid range header
        let request = TestRequest::get()
            .uri("/t%65st/Cargo.toml")
            .header(http::header::RANGE, "bytes=10-20")
            .to_request();
        let response = test::call_service(&mut srv, request).await;
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);

        // Invalid range header
        let request = TestRequest::get()
            .uri("/t%65st/Cargo.toml")
            .header(http::header::RANGE, "bytes=1-0")
            .to_request();
        let response = test::call_service(&mut srv, request).await;

        assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    }

    #[ntex::test]
    async fn test_named_file_content_range_headers() {
        let mut srv = test::init_service(
            App::new().service(Files::new("/test", ".").index_file("tests/test.binary")),
        )
        .await;

        // Valid range header
        let request = TestRequest::get()
            .uri("/t%65st/tests/test.binary")
            .header(http::header::RANGE, "bytes=10-20")
            .to_request();

        let response = test::call_service(&mut srv, request).await;
        let contentrange =
            response.headers().get(http::header::CONTENT_RANGE).unwrap().to_str().unwrap();

        assert_eq!(contentrange, "bytes 10-20/100");

        // Invalid range header
        let request = TestRequest::get()
            .uri("/t%65st/tests/test.binary")
            .header(http::header::RANGE, "bytes=10-5")
            .to_request();
        let response = test::call_service(&mut srv, request).await;

        let contentrange =
            response.headers().get(http::header::CONTENT_RANGE).unwrap().to_str().unwrap();

        assert_eq!(contentrange, "bytes */100");
    }

    #[ntex::test]
    async fn test_named_file_content_length_headers() {
        let mut srv = test::init_service(
            App::new().service(Files::new("test", ".").index_file("tests/test.binary")),
        )
        .await;

        // Valid range header
        let request = TestRequest::get()
            .uri("/t%65st/tests/test.binary")
            .header(http::header::RANGE, "bytes=10-20")
            .to_request();
        let _response = test::call_service(&mut srv, request).await;

        // let contentlength = _response
        //     .headers()
        //     .get(header::CONTENT_LENGTH)
        //     .unwrap()
        //     .to_str()
        //     .unwrap();
        // assert_eq!(contentlength, "11");

        // Invalid range header
        let request = TestRequest::get()
            .uri("/t%65st/tests/test.binary")
            .header(http::header::RANGE, "bytes=10-8")
            .to_request();
        let response = test::call_service(&mut srv, request).await;
        assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);

        // Without range header
        let request = TestRequest::get()
            .uri("/t%65st/tests/test.binary")
            // .no_default_headers()
            .to_request();
        let _response = test::call_service(&mut srv, request).await;

        // let contentlength = response
        //     .headers()
        //     .get(header::CONTENT_LENGTH)
        //     .unwrap()
        //     .to_str()
        //     .unwrap();
        // assert_eq!(contentlength, "100");

        // chunked
        let request = TestRequest::get().uri("/t%65st/tests/test.binary").to_request();
        let response = test::call_service(&mut srv, request).await;

        // with enabled compression
        // {
        //     let te = response
        //         .headers()
        //         .get(header::TRANSFER_ENCODING)
        //         .unwrap()
        //         .to_str()
        //         .unwrap();
        //     assert_eq!(te, "chunked");
        // }

        let bytes = test::read_body(response).await;
        let data = Bytes::from(fs::read("tests/test.binary").unwrap());
        assert_eq!(bytes, data);
    }

    #[ntex::test]
    async fn test_head_content_length_headers() {
        let mut srv = test::init_service(
            App::new().service(Files::new("test", ".").index_file("tests/test.binary")),
        )
        .await;

        // Valid range header
        let request = TestRequest::default()
            .method(Method::HEAD)
            .uri("/t%65st/tests/test.binary")
            .to_request();
        let _response = test::call_service(&mut srv, request).await;

        // TODO: fix check
        // let contentlength = response
        //     .headers()
        //     .get(header::CONTENT_LENGTH)
        //     .unwrap()
        //     .to_str()
        //     .unwrap();
        // assert_eq!(contentlength, "100");
    }

    #[ntex::test]
    async fn test_static_files_with_spaces() {
        let srv = test::init_service(
            App::new().service(Files::new("/", ".").index_file("Cargo.toml")),
        )
        .await;
        let request = TestRequest::get().uri("/tests/test%20space.binary").to_request();
        let response = test::call_service(&srv, request).await;
        assert_eq!(response.status(), StatusCode::OK);

        let bytes = test::read_body(response).await;
        let data = Bytes::from(fs::read("tests/test space.binary").unwrap());
        assert_eq!(bytes, data);
    }

    #[ntex::test]
    async fn test_files_not_allowed() {
        let mut srv = test::init_service(App::new().service(Files::new("/", "."))).await;

        let req = TestRequest::default().uri("/Cargo.toml").method(Method::POST).to_request();

        let resp = test::call_service(&mut srv, req).await;
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);

        let mut srv = test::init_service(App::new().service(Files::new("/", "."))).await;
        let req = TestRequest::default().method(Method::PUT).uri("/Cargo.toml").to_request();
        let resp = test::call_service(&mut srv, req).await;
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[ntex::test]
    async fn test_files_guards() {
        let mut srv = test::init_service(
            App::new().service(Files::new("/", ".").use_guards(guard::Post())),
        )
        .await;

        let req = TestRequest::default().uri("/Cargo.toml").method(Method::POST).to_request();

        let resp = test::call_service(&mut srv, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[ntex::test]
    async fn test_named_file_content_encoding() {
        let mut srv = test::init_service(App::new().wrap(Compress::default()).service(
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
        let res = test::call_service(&mut srv, request).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert!(!res.headers().contains_key(http::header::CONTENT_ENCODING));
    }

    #[ntex::test]
    async fn test_named_file_content_encoding_gzip() {
        let mut srv = test::init_service(App::new().wrap(Compress::default()).service(
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
        let res = test::call_service(&mut srv, request).await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers().get(http::header::CONTENT_ENCODING).unwrap().to_str().unwrap(),
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
        let mut srv =
            test::init_service(App::new().service(Files::new("/", ".").show_files_listing()))
                .await;
        let req = TestRequest::with_uri("/missing").to_request();

        let resp = test::call_service(&mut srv, req).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let mut srv = test::init_service(App::new().service(Files::new("/", "."))).await;

        let req = TestRequest::default().to_request();
        let resp = test::call_service(&mut srv, req).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let mut srv =
            test::init_service(App::new().service(Files::new("/", ".").show_files_listing()))
                .await;
        let req = TestRequest::with_uri("/tests").to_request();
        let resp = test::call_service(&mut srv, req).await;
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
        let mut srv = test::init_service(
            App::new().service(Files::new("/", ".").redirect_to_slash_directory()),
        )
        .await;
        let req = TestRequest::with_uri("/tests").to_request();
        let resp = test::call_service(&mut srv, req).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // should redirect if index present
        let mut srv = test::init_service(App::new().service(
            Files::new("/", ".").index_file("test.png").redirect_to_slash_directory(),
        ))
        .await;
        let req = TestRequest::with_uri("/tests").to_request();
        let resp = test::call_service(&mut srv, req).await;
        assert_eq!(resp.status(), StatusCode::FOUND);

        // should not redirect if the path is wrong
        let req = TestRequest::with_uri("/not_existing").to_request();
        let resp = test::call_service(&mut srv, req).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[ntex::test]
    async fn test_static_files_bad_directory() {
        let _st: Files<DefaultError> = Files::new("/", "missing");
        let _st: Files<DefaultError> = Files::new("/", "Cargo.toml");
    }

    #[ntex::test]
    async fn test_default_handler_file_missing() {
        let mut st = Files::new("/", ".")
            .default_handler(|req: WebRequest<DefaultError>| {
                ok(req.into_response(HttpResponse::Ok().body("default content")))
            })
            .new_service(())
            .await
            .unwrap();
        let req = TestRequest::with_uri("/missing").to_srv_request();

        let resp = test::call_service(&mut st, req).await;
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
    //         let mut srv = test::TestServer::with_factory(|| {
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
    //         let mut srv = test::TestServer::with_factory(|| {
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
}
