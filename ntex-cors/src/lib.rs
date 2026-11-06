#![allow(
    clippy::borrow_interior_mutable_const,
    clippy::type_complexity,
    clippy::mutable_key_type
)]
//! Cross-origin resource sharing (CORS) middleware for ntex applications.
//!
//! Configure a [`Cors`] builder, call [`Cors::build`], and register the resulting
//! middleware with [`App::middleware`](ntex::web::App::middleware),
//! [`Resource::middleware`](ntex::web::Resource::middleware), or
//! [`Scope::middleware`](ntex::web::Scope::middleware).
//!
//! By default, all origins and request headers are allowed. Requests with an
//! `Origin` header are validated on ordinary requests; ordinary requests without
//! one reach the application.
//! Preflight requests (`OPTIONS` with `Access-Control-Request-Method`) are
//! validated and answered directly. Method and request-header restrictions
//! apply only to preflights, not to ordinary requests.
//!
//! # Example
//!
//! ```rust
//! use ntex::{http::{header, Method}, web};
//! use ntex_cors::Cors;
//!
//! let app = web::App::default()
//!     .middleware(
//!         Cors::new()
//!             .allowed_origin("https://www.rust-lang.org")
//!             .allowed_methods([Method::GET, Method::POST])
//!             .allowed_headers([header::AUTHORIZATION, header::ACCEPT])
//!             .allowed_header(header::CONTENT_TYPE)
//!             .max_age(3600)
//!             .build::<()>(),
//!     )
//!     .service(web::resource("/").to(|| async { "Hello world" }));
//! ```
use std::{
    collections::HashSet, convert::TryFrom, iter::FromIterator, marker::PhantomData, rc::Rc,
};

use derive_more::Display;
use ntex::error::{ErrorDiagnostic, Failure, IntoFailure};
use ntex::http::header::{self, HeaderName, HeaderValue};
use ntex::http::{HeaderMap, Method, RequestHead, StatusCode, error::HttpError};
use ntex::service::{BindCtx, Ctx, Middleware, Service};
use ntex::url::{InvalidUrl, Url};
use ntex::util::{ByteString, Either};
use ntex::web::{DefaultError, HttpResponse, State, WebRequest, WebResponse, WebResponseError};

/// Invalid cors configuration
#[derive(Debug, thiserror::Error)]
enum ConfigError {
    #[error(transparent)]
    Http(HttpError),
    #[error(transparent)]
    Origin(InvalidUrl),
}

impl ErrorDiagnostic for ConfigError {
    fn signature(&self) -> &'static str {
        match self {
            ConfigError::Http(_) => "ntex-cors-InvalidConfig",
            ConfigError::Origin(_) => "ntex-cors-InvalidOrigin",
        }
    }
}

/// CORS request validation errors.
///
/// With ntex's [`DefaultError`] renderer, these produce `400 Bad Request`.
#[derive(Debug, Display, thiserror::Error)]
pub enum CorsError {
    /// A preflight is missing `Origin` while the origin allowlist is restricted.
    #[display("The HTTP request header `Origin` is required but was not provided")]
    MissingOrigin,
    /// The `Origin` header cannot be converted to text.
    #[display("The HTTP request header `Origin` could not be parsed correctly.")]
    BadOrigin,
    /// The request header `Access-Control-Request-Method` is required but is
    /// missing
    #[display("The request header `Access-Control-Request-Method` is required but is missing")]
    MissingRequestMethod,
    /// The request header `Access-Control-Request-Method` has an invalid value
    #[display("The request header `Access-Control-Request-Method` has an invalid value")]
    BadRequestMethod,
    /// The restricted preflight `Access-Control-Request-Headers` list is malformed.
    #[display("The request header `Access-Control-Request-Headers`  has an invalid value")]
    BadRequestHeaders,
    /// The `Origin` header does not exactly match an allowed origin.
    #[display("Origin is not allowed to make this request")]
    OriginNotAllowed,
    /// The preflight method is not in the allowed method set.
    #[display("Requested method is not allowed")]
    MethodNotAllowed,
    /// One or more preflight header names are not allowed.
    #[display("One or more headers requested are not allowed")]
    HeadersNotAllowed,
}

/// Renders [`CorsError`] as `400 Bad Request` with [`DefaultError`].
impl<St> WebResponseError<St, DefaultError> for CorsError {
    fn error_response(&self, _: &St) -> HttpResponse {
        HttpResponse::render_with(StatusCode::BAD_REQUEST, self)
    }
}

/// Either all values are allowed or only a specified set is allowed.
///
/// The default is [`All`](Self::All).
#[derive(Default, Clone, Debug, Eq, PartialEq)]
pub enum AllOrSome<T> {
    /// Everything is allowed; this does not necessarily send a `*` header.
    #[default]
    All,
    /// Only the values represented by `T` are allowed.
    Some(T),
}

impl<T> AllOrSome<T> {
    /// Returns whether this is [`All`](Self::All).
    pub fn is_all(&self) -> bool {
        match *self {
            AllOrSome::All => true,
            AllOrSome::Some(_) => false,
        }
    }

    /// Returns whether this is [`Some`](Self::Some).
    pub fn is_some(&self) -> bool {
        !self.is_all()
    }

    /// Returns the contained value for [`Some`](Self::Some), or `None` for [`All`](Self::All).
    pub fn as_ref(&self) -> Option<&T> {
        match *self {
            AllOrSome::All => None,
            AllOrSome::Some(ref t) => Some(t),
        }
    }
}

/// Builder for [`CorsMiddleware`].
///
/// Start with [`Cors::new`], configure the policy, then call [`Cors::build`].
/// Origin, method, and header additions accumulate across calls; scalar
/// settings such as [`max_age`](Self::max_age) replace their previous value.
/// Invalid configuration is reported by a panic in [`build`](Self::build),
/// rather than by the individual setters.
///
/// # Example
///
/// ```rust
/// use ntex::{http::{header, Method}, web::App};
/// use ntex_cors::Cors;
///
/// let app = App::default().middleware(
///     Cors::new()
///         .allowed_origin("https://www.rust-lang.org")
///         .allowed_methods([Method::GET, Method::POST])
///         .allowed_header(header::CONTENT_TYPE)
///         .build::<()>(),
/// );
/// ```
pub struct Cors {
    cors: Option<Inner>,
    methods: bool,
    expose_hdrs: HashSet<HeaderName>,
    error: Option<Failure>,
}

/// Same as [`Cors::new`].
///
/// The inherent [`Cors::default`] returns middleware instead; call this
/// implementation as `<Cors as Default>::default()`.
impl Default for Cors {
    fn default() -> Self {
        Cors::new()
    }
}

impl Cors {
    /// Creates a builder allowing all origins and request headers.
    ///
    /// Unless overridden, [`build`](Self::build) allows `GET`, `HEAD`, `POST`,
    /// `OPTIONS`, `PUT`, `PATCH`, and `DELETE`. Preflight handling and
    /// `Vary: Origin` are enabled; credentials, wildcard responses, exposed
    /// headers, and a preflight cache lifetime are disabled or unset.
    pub fn new() -> Self {
        Cors {
            cors: Some(Inner {
                origins: AllOrSome::All,
                origins_str: None,
                methods: HashSet::new(),
                headers: AllOrSome::All,
                expose_hdrs: None,
                max_age: None,
                preflight: true,
                send_wildcard: false,
                supports_credentials: false,
                vary_header: true,
            }),
            methods: false,
            error: None,
            expose_hdrs: HashSet::new(),
        }
    }

    #[allow(clippy::should_implement_trait)]
    /// Creates middleware with the same settings as `Cors::new().build()`.
    ///
    /// Unlike [`new`](Self::new), this returns middleware, not a builder.
    pub fn default<St>() -> CorsMiddleware<St> {
        let inner = Inner {
            origins: AllOrSome::default(),
            origins_str: None,
            methods: HashSet::from_iter(vec![
                Method::GET,
                Method::HEAD,
                Method::POST,
                Method::OPTIONS,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
            ]),
            headers: AllOrSome::All,
            expose_hdrs: None,
            max_age: None,
            preflight: true,
            send_wildcard: false,
            supports_credentials: false,
            vary_header: true,
        };
        CorsMiddleware {
            inner: Rc::new(inner),
            st: PhantomData,
        }
    }

    /// Adds an origin to the allowlist, matched exactly against `Origin`.
    ///
    /// All origins are allowed by default. The first non-wildcard call starts
    /// a restricted list; later calls add to it. `"*"` resets the list to all
    /// origins. A later non-wildcard call starts a new restricted list.
    ///
    /// Values are checked with [`Url::try_from`] but stored as supplied, without
    /// normalization. Use the browser's origin form, such as
    /// `https://example.com`, without a trailing slash or path. Invalid URLs
    /// cause [`build`](Self::build) to panic.
    ///
    /// Allowed request origins are echoed in `Access-Control-Allow-Origin`,
    /// unless all origins are allowed and [`send_wildcard`](Self::send_wildcard)
    /// is enabled.
    pub fn allowed_origin(mut self, origin: &str) -> Self {
        if let Some(cors) = cors(&mut self.cors, &self.error) {
            match Url::try_from(origin) {
                Ok(_) => {
                    // If the origin is "*", set the origins to `All`
                    if origin.trim() == "*" {
                        cors.origins = AllOrSome::All;
                        return self;
                    }
                    if cors.origins.is_all() {
                        cors.origins = AllOrSome::Some(HashSet::new());
                    }
                    if let AllOrSome::Some(ref mut origins) = cors.origins {
                        origins.insert(origin.to_owned());
                    }
                }
                Err(e) => {
                    self.error = Some(ConfigError::Origin(e).fail());
                }
            }
        }
        self
    }

    /// Adds methods allowed in `Access-Control-Request-Method` on preflights.
    ///
    /// Accepts strings such as `"GET"` or [`Method`] values. Calls accumulate;
    /// the first call replaces the default set (`GET`, `HEAD`, `POST`,
    /// `OPTIONS`, `PUT`, `PATCH`, `DELETE`), even if the iterator is empty.
    /// An empty set rejects every preflight. Ordinary request methods are not
    /// checked. Invalid method values cause [`build`](Self::build) to panic.
    ///
    /// # Example
    ///
    /// ```rust
    /// use ntex::http::Method;
    /// use ntex_cors::Cors;
    ///
    /// let cors = Cors::new().allowed_methods([Method::GET, Method::POST]);
    /// ```
    pub fn allowed_methods<U, M>(mut self, methods: U) -> Self
    where
        U: IntoIterator<Item = M>,
        Method: TryFrom<M>,
        <Method as TryFrom<M>>::Error: Into<HttpError>,
    {
        self.methods = true;
        if let Some(cors) = cors(&mut self.cors, &self.error) {
            for m in methods {
                match Method::try_from(m) {
                    Ok(method) => {
                        cors.methods.insert(method);
                    }
                    Err(e) => {
                        self.error = Some(ConfigError::Http(e.into()).fail());
                        break;
                    }
                }
            }
        }
        self
    }

    /// Adds one allowed preflight request header, using [`HeaderName`] or a string.
    ///
    /// The first addition restricts the default allow-all policy. Calls
    /// accumulate with [`allowed_headers`](Self::allowed_headers); names are
    /// case-insensitive. Invalid names cause [`build`](Self::build) to panic.
    pub fn allowed_header<H>(mut self, header: H) -> Self
    where
        HeaderName: TryFrom<H>,
        <HeaderName as TryFrom<H>>::Error: Into<HttpError>,
    {
        if let Some(cors) = cors(&mut self.cors, &self.error) {
            match HeaderName::try_from(header) {
                Ok(method) => {
                    if cors.headers.is_all() {
                        cors.headers = AllOrSome::Some(HashSet::new());
                    }
                    if let AllOrSome::Some(ref mut headers) = cors.headers {
                        headers.insert(method);
                    }
                }
                Err(e) => self.error = Some(ConfigError::Http(e.into()).fail()),
            }
        }
        self
    }

    /// Adds header names allowed in `Access-Control-Request-Headers` on preflights.
    ///
    /// All headers are allowed by default, and the request's header list is
    /// echoed verbatim in `Access-Control-Allow-Headers`, without validating
    /// its names. The first added name restricts this policy. Calls accumulate
    /// with [`allowed_header`](Self::allowed_header); an empty iterator has no
    /// effect. Invalid configured names cause [`build`](Self::build) to panic.
    ///
    /// With a restricted set, requested names are checked case-insensitively
    /// and the complete allowed set is returned in `Access-Control-Allow-Headers`.
    /// An absent request-header list is allowed; an empty or malformed one is not.
    pub fn allowed_headers<U, H>(mut self, headers: U) -> Self
    where
        U: IntoIterator<Item = H>,
        HeaderName: TryFrom<H>,
        <HeaderName as TryFrom<H>>::Error: Into<HttpError>,
    {
        if let Some(cors) = cors(&mut self.cors, &self.error) {
            for h in headers {
                match HeaderName::try_from(h) {
                    Ok(method) => {
                        if cors.headers.is_all() {
                            cors.headers = AllOrSome::Some(HashSet::new());
                        }
                        if let AllOrSome::Some(ref mut headers) = cors.headers {
                            headers.insert(method);
                        }
                    }
                    Err(e) => {
                        self.error = Some(ConfigError::Http(e.into()).fail());
                        break;
                    }
                }
            }
        }
        self
    }

    /// Adds response header names exposed to browser scripts.
    ///
    /// Calls accumulate; no headers are explicitly exposed by default.
    /// `Access-Control-Expose-Headers` is added only to ordinary responses to
    /// requests with `Origin`, not to preflight responses. Invalid names cause
    /// [`build`](Self::build) to panic.
    pub fn expose_headers<U, H>(mut self, headers: U) -> Self
    where
        U: IntoIterator<Item = H>,
        HeaderName: TryFrom<H>,
        <HeaderName as TryFrom<H>>::Error: Into<HttpError>,
    {
        for h in headers {
            match HeaderName::try_from(h) {
                Ok(method) => {
                    self.expose_hdrs.insert(method);
                }
                Err(e) => {
                    self.error = Some(ConfigError::Http(e.into()).fail());
                    break;
                }
            }
        }
        self
    }

    /// Sets the preflight cache lifetime in seconds via `Access-Control-Max-Age`.
    ///
    /// Unset by default. Repeated calls replace the previous value.
    pub fn max_age(mut self, max_age: usize) -> Self {
        if let Some(cors) = cors(&mut self.cors, &self.error) {
            cors.max_age = Some(max_age)
        }
        self
    }

    /// Sends `Access-Control-Allow-Origin: *` when all origins are allowed.
    ///
    /// Otherwise the request origin is echoed. Disabled by default; repeated
    /// calls have no additional effect. With a restricted origin list this
    /// setting has no effect.
    ///
    /// Combining all origins, this setting, and
    /// [`supports_credentials`](Self::supports_credentials) causes
    /// [`build`](Self::build) to panic.
    pub fn send_wildcard(mut self) -> Self {
        if let Some(cors) = cors(&mut self.cors, &self.error) {
            cors.send_wildcard = true
        }
        self
    }

    /// Enables `Access-Control-Allow-Credentials: true` on CORS responses.
    ///
    /// Disabled by default; repeated calls have no additional effect. Allowing
    /// all origins is compatible with credentials when the request origin is
    /// echoed, but not with [`send_wildcard`](Self::send_wildcard).
    /// The invalid combination is rejected by [`build`](Self::build).
    pub fn supports_credentials(mut self) -> Self {
        if let Some(cors) = cors(&mut self.cors, &self.error) {
            cors.supports_credentials = true
        }
        self
    }

    /// Stops adding `Origin` to the response's `Vary` header.
    ///
    /// By default, successful preflight and ordinary responses (including
    /// requests without `Origin`) vary by origin. Existing `Vary` values are
    /// preserved, and `Origin` is not added if any value already contains it
    /// case-insensitively or contains `*`. This informs caches that responses
    /// can differ by origin; it does not prohibit caching.
    ///
    /// Repeated calls have no additional effect. Existing `Vary` headers are
    /// not removed.
    pub fn disable_vary_header(mut self) -> Self {
        if let Some(cors) = cors(&mut self.cors, &self.error) {
            cors.vary_header = false
        }
        self
    }

    /// Passes preflight requests to the inner service instead of answering them.
    ///
    /// By default, `OPTIONS` requests with `Access-Control-Request-Method` are
    /// intercepted; other `OPTIONS` requests reach the application. Disabling
    /// this does not disable origin validation or CORS response headers, but
    /// method and requested-header checks no longer run.
    ///
    /// Repeated calls have no additional effect.
    pub fn disable_preflight(mut self) -> Self {
        if let Some(cors) = cors(&mut self.cors, &self.error) {
            cors.preflight = false
        }
        self
    }

    /// Consumes this builder and constructs [`CorsMiddleware`].
    ///
    /// # Panics
    ///
    /// Panics if a configured origin, method, or header name is invalid, or
    /// if an origin cannot be represented in a response header. Also panics
    /// when all origins, [`send_wildcard`](Self::send_wildcard), and
    /// [`supports_credentials`](Self::supports_credentials) are combined.
    pub fn build<St>(self) -> CorsMiddleware<St> {
        let mut slf = if !self.methods {
            self.allowed_methods(vec![
                Method::GET,
                Method::HEAD,
                Method::POST,
                Method::OPTIONS,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
            ])
        } else {
            self
        };

        if let Some(e) = slf.error.take() {
            panic!("{}", e);
        }

        let mut cors = slf.cors.take().expect("cannot reuse CorsBuilder");

        if cors.supports_credentials && cors.send_wildcard && cors.origins.is_all() {
            panic!("Credentials are allowed, but the Origin is set to \"*\"");
        }

        if let AllOrSome::Some(ref origins) = cors.origins {
            let s = origins
                .iter()
                .fold(String::new(), |s, v| format!("{}, {}", s, v));
            cors.origins_str = Some(HeaderValue::try_from(&s[2..]).unwrap());
        }

        if !slf.expose_hdrs.is_empty() {
            cors.expose_hdrs = Some(
                HeaderValue::try_from(
                    &slf.expose_hdrs
                        .iter()
                        .fold(String::new(), |s, v| format!("{}, {}", s, v.as_str()))[2..],
                )
                .unwrap(),
            );
        }

        CorsMiddleware {
            inner: Rc::new(cors),
            st: PhantomData,
        }
    }
}

fn cors<'a>(parts: &'a mut Option<Inner>, err: &Option<Failure>) -> Option<&'a mut Inner> {
    if err.is_some() {
        return None;
    }
    parts.as_mut()
}

struct Inner {
    methods: HashSet<Method>,
    origins: AllOrSome<HashSet<String>>,
    origins_str: Option<HeaderValue>,
    headers: AllOrSome<HashSet<HeaderName>>,
    expose_hdrs: Option<HeaderValue>,
    max_age: Option<usize>,
    preflight: bool,
    send_wildcard: bool,
    supports_credentials: bool,
    vary_header: bool,
}

impl Inner {
    fn validate_origin(&self, req: &RequestHead) -> Result<(), CorsError> {
        if let Some(hdr) = req.headers().get(&header::ORIGIN) {
            if let Ok(origin) = hdr.to_str() {
                return match self.origins {
                    AllOrSome::All => Ok(()),
                    AllOrSome::Some(ref allowed_origins) => allowed_origins
                        .get(origin)
                        .map(|_| ())
                        .ok_or(CorsError::OriginNotAllowed),
                };
            }
            Err(CorsError::BadOrigin)
        } else {
            match self.origins {
                AllOrSome::All => Ok(()),
                _ => Err(CorsError::MissingOrigin),
            }
        }
    }

    fn access_control_allow_origin(&self, headers: &HeaderMap) -> Option<HeaderValue> {
        match self.origins {
            AllOrSome::All => {
                if self.send_wildcard {
                    Some(HeaderValue::from_static("*"))
                } else {
                    headers.get(&header::ORIGIN).cloned()
                }
            }
            AllOrSome::Some(ref origins) => {
                if let Some(origin) = headers.get(&header::ORIGIN).filter(|o| match o.to_str() {
                    Ok(os) => origins.contains(os),
                    _ => false,
                }) {
                    Some(origin.clone())
                } else {
                    Some(self.origins_str.as_ref().unwrap().clone())
                }
            }
        }
    }

    fn validate_allowed_method(&self, req: &RequestHead) -> Result<(), CorsError> {
        if let Some(hdr) = req.headers().get(&header::ACCESS_CONTROL_REQUEST_METHOD) {
            if let Ok(meth) = hdr.to_str()
                && let Ok(method) = Method::try_from(meth)
            {
                return self
                    .methods
                    .get(&method)
                    .map(|_| ())
                    .ok_or(CorsError::MethodNotAllowed);
            }
            Err(CorsError::BadRequestMethod)
        } else {
            Err(CorsError::MissingRequestMethod)
        }
    }

    fn validate_allowed_headers(&self, req: &RequestHead) -> Result<(), CorsError> {
        match self.headers {
            AllOrSome::All => Ok(()),
            AllOrSome::Some(ref allowed_headers) => {
                if let Some(hdr) = req.headers().get(&header::ACCESS_CONTROL_REQUEST_HEADERS) {
                    if let Ok(headers) = hdr.to_str() {
                        let mut hdrs = HashSet::new();
                        for hdr in headers.split(',') {
                            match HeaderName::try_from(hdr.trim()) {
                                Ok(hdr) => hdrs.insert(hdr),
                                Err(_) => return Err(CorsError::BadRequestHeaders),
                            };
                        }
                        // `Access-Control-Request-Headers` must contain 1 or more
                        // `field-name`.
                        if !hdrs.is_empty() {
                            if !hdrs.is_subset(allowed_headers) {
                                return Err(CorsError::HeadersNotAllowed);
                            }
                            return Ok(());
                        }
                    }
                    Err(CorsError::BadRequestHeaders)
                } else {
                    Ok(())
                }
            }
        }
    }

    fn preflight_check(&self, req: &RequestHead) -> Result<Either<HttpResponse, ()>, CorsError> {
        if self.preflight
            && Method::OPTIONS == req.method
            && req
                .headers
                .contains_key(&header::ACCESS_CONTROL_REQUEST_METHOD)
        {
            self.validate_origin(req)
                .and_then(|_| self.validate_allowed_method(req))
                .and_then(|_| self.validate_allowed_headers(req))?;

            // allowed headers
            let headers = if let Some(headers) = self.headers.as_ref() {
                Some(
                    HeaderValue::try_from(
                        &headers
                            .iter()
                            .fold(String::new(), |s, v| s + "," + v.as_str())
                            .as_str()[1..],
                    )
                    .unwrap(),
                )
            } else {
                req.headers
                    .get(&header::ACCESS_CONTROL_REQUEST_HEADERS)
                    .cloned()
            };

            let mut res = HttpResponse::Ok();

            if let Some(ref max_age) = self.max_age {
                res.header(
                    header::ACCESS_CONTROL_MAX_AGE,
                    ByteString::from(format!("{}", max_age)),
                );
            }
            if let Some(headers) = headers {
                res.header(header::ACCESS_CONTROL_ALLOW_HEADERS, headers);
            }
            if let Some(origin) = self.access_control_allow_origin(req.headers()) {
                res.header(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
            }
            if self.supports_credentials {
                res.header(header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
            }
            let mut res = res
                .header(
                    header::ACCESS_CONTROL_ALLOW_METHODS,
                    &self
                        .methods
                        .iter()
                        .fold(String::new(), |s, v| s + "," + v.as_str())
                        .as_str()[1..],
                )
                .build()
                .into_body();
            self.add_vary(res.headers_mut());

            Ok(Either::Left(res))
        } else {
            if req.headers.contains_key(&header::ORIGIN) {
                // Only check requests with a origin header.
                self.validate_origin(req)?;
            }
            Ok(Either::Right(()))
        }
    }

    fn handle_response(&self, headers: &mut HeaderMap, allowed_origin: Option<HeaderValue>) {
        if let Some(origin) = allowed_origin {
            headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        };

        if let Some(ref expose) = self.expose_hdrs {
            headers.insert(header::ACCESS_CONTROL_EXPOSE_HEADERS, expose.clone());
        }
        if self.supports_credentials {
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            );
        }
        self.add_vary(headers);
    }

    /// Merge `Origin` into the `Vary` header unless it is already covered.
    fn add_vary(&self, headers: &mut HeaderMap) {
        if !self.vary_header {
            return;
        }

        let mut val: Vec<u8> = Vec::new();
        for hdr in headers.get_all(&header::VARY) {
            let covered = hdr.as_bytes().split(|b| *b == b',').any(|t| {
                let t = t.trim_ascii();
                t == b"*" || t.eq_ignore_ascii_case(b"origin")
            });
            if covered {
                return;
            }
            if !val.is_empty() {
                val.extend(b", ");
            }
            val.extend(hdr.as_bytes());
        }

        let value = if val.is_empty() {
            HeaderValue::from_static("Origin")
        } else {
            val.extend(b", Origin");
            match HeaderValue::try_from(&val[..]) {
                Ok(value) => value,
                Err(_) => return,
            }
        };
        headers.insert(header::VARY, value);
    }
}

/// Configured CORS middleware, created by [`Cors::build`] or [`Cors::default`].
///
/// Validates request origins and preflight policies, then adds CORS response
/// headers. CORS validation failures are rendered using [`CorsError`]; inner
/// service errors propagate unchanged.
pub struct CorsMiddleware<St> {
    inner: Rc<Inner>,
    st: PhantomData<St>,
}

impl<S, St> Middleware<S, St> for CorsMiddleware<St> {
    type Service = CorsService<S>;

    fn create(&self, _: &St, service: S) -> Self::Service {
        CorsService {
            service,
            inner: self.inner.clone(),
        }
    }
}

/// Service wrapping an inner service with the policy from [`CorsMiddleware`].
#[derive(Clone)]
pub struct CorsService<S> {
    service: S,
    inner: Rc<Inner>,
}

impl<S, St: State, In> Service<St, WebRequest<In>> for CorsService<S>
where
    S: Service<St, WebRequest<In>, Res = WebResponse>,
    CorsError: WebResponseError<St, St::Error>,
{
    type Res = WebResponse;
    type Error = S::Error;

    async fn call(
        &self,
        req: WebRequest<In>,
        ctx: Ctx<'_, Self, St>,
    ) -> Result<Self::Res, S::Error> {
        match self.inner.preflight_check(req.head()) {
            Ok(Either::Left(res)) => Ok(req.into_response(res)),
            Ok(Either::Right(_)) => {
                let inner = self.inner.clone();
                let has_origin = req.headers().contains_key(&header::ORIGIN);
                let allowed_origin = inner.access_control_allow_origin(req.headers());

                let mut res = ctx.call(&self.service, req).await?;

                if has_origin {
                    inner.handle_response(res.headers_mut(), allowed_origin);
                } else {
                    // response differs from the one for a cross-origin request
                    inner.add_vary(res.headers_mut());
                }
                Ok(res)
            }
            Err(e) => Ok(req.error_response(ctx.st(), &e)),
        }
    }

    #[inline]
    fn bind(&self, ctx: BindCtx<'_>) {
        ctx.bind(&self.service);
    }

    #[inline]
    async fn ready(&self, ctx: Ctx<'_, Self, St>) -> Result<(), Self::Error> {
        ctx.ready(&self.service).await
    }

    #[inline]
    async fn shutdown(&self, ctx: Ctx<'_, Self, St>) {
        ctx.shutdown(&self.service).await;
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use ntex::http::StatusCode;
    use ntex::service::fn_service;
    use ntex::web::{test, test::TestRequest};

    use super::*;

    #[ntex::test]
    #[should_panic(expected = "Credentials are allowed, but the Origin is set to")]
    async fn cors_validates_illegal_allow_credentials() {
        let _cors = Cors::new()
            .supports_credentials()
            .send_wildcard()
            .build::<()>();
    }

    #[ntex::test]
    async fn validate_origin_allows_all_origins() {
        let cors = Cors::new()
            .build()
            .create(&(), test::ok_service())
            .pipeline(());
        let req = TestRequest::with_header("Origin", "https://www.example.com").to_srv_request();

        let resp = cors.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[ntex::test]
    async fn default() {
        let cors = Cors::default().create(&(), test::ok_service()).pipeline(());
        let req = TestRequest::with_header("Origin", "https://www.example.com").to_srv_request();

        let resp = cors.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[ntex::test]
    async fn test_preflight() {
        let cors = Cors::new()
            .send_wildcard()
            .max_age(3600)
            .allowed_methods(vec![Method::GET, Method::OPTIONS, Method::POST])
            .allowed_headers(vec![header::AUTHORIZATION, header::ACCEPT])
            .allowed_header(header::CONTENT_TYPE)
            .build()
            .create(
                &(),
                fn_service(async move |req: WebRequest<()>| {
                    Ok::<_, Infallible>(
                        req.into_response(HttpResponse::builder(StatusCode::OK).build()),
                    )
                }),
            );

        let req = TestRequest::with_header("Origin", "https://www.example.com")
            .method(Method::OPTIONS)
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "X-Not-Allowed")
            .to_srv_request();

        assert!(cors.inner.validate_allowed_method(req.head()).is_ok());
        assert!(cors.inner.validate_allowed_headers(req.head()).is_err());

        let svc = cors.clone().pipeline(());
        let resp = svc.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let req = TestRequest::with_header("Origin", "https://www.example.com")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "put")
            .method(Method::OPTIONS)
            .to_srv_request();

        assert!(cors.inner.validate_allowed_method(req.head()).is_err());
        assert!(cors.inner.validate_allowed_headers(req.head()).is_ok());

        let req = TestRequest::with_header("Origin", "https://www.example.com")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .header(
                header::ACCESS_CONTROL_REQUEST_HEADERS,
                "AUTHORIZATION,ACCEPT",
            )
            .method(Method::OPTIONS)
            .to_srv_request();

        let svc = cors.clone().pipeline(());
        let resp = svc.call(req).await.unwrap();
        assert_eq!(
            &b"*"[..],
            resp.headers()
                .get(&header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap()
                .as_bytes()
        );
        assert_eq!(
            &b"3600"[..],
            resp.headers()
                .get(&header::ACCESS_CONTROL_MAX_AGE)
                .unwrap()
                .as_bytes()
        );
        let hdr = resp
            .headers()
            .get(&header::ACCESS_CONTROL_ALLOW_HEADERS)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(hdr.contains("authorization"));
        assert!(hdr.contains("accept"));
        assert!(hdr.contains("content-type"));

        let methods = resp
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_METHODS)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(methods.contains("POST"));
        assert!(methods.contains("GET"));
        assert!(methods.contains("OPTIONS"));

        // Rc::get_mut(&mut cors.inner).unwrap().preflight = false;

        // let req = TestRequest::with_header("Origin", "https://www.example.com")
        //     .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
        //     .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "AUTHORIZATION,ACCEPT")
        //     .method(Method::OPTIONS)
        //     .to_srv_request();

        // let resp = test::call_service(&cors, req).await;
        // assert_eq!(resp.status(), StatusCode::OK);
    }

    // #[ntex::test]
    // #[should_panic(expected = "MissingOrigin")]
    // async fn test_validate_missing_origin() {
    //    let cors = Cors::build()
    //        .allowed_origin("https://www.example.com")
    //        .build();
    //    let mut req = HttpRequest::default();
    //    cors.start(&req).unwrap();
    // }

    /// STATEMENT: Actual requests reject malformed or disallowed `Origin` values,
    /// while same-origin requests without `Origin` still reach the application.
    ///
    /// HOW:
    /// - Configure one allowed origin and an inner service that counts calls and replies `204`.
    /// - Send unknown, differently cased, and non-ASCII origins; assert `400`, no
    ///   `Access-Control-Allow-Origin`, and no calls to the inner service.
    /// - Send requests without `Origin` and with the allowed origin; assert `204`,
    ///   the appropriate absence or presence of the allow-origin header, and two inner calls.
    #[ntex::test]
    async fn test_validate_not_allowed_origin() {
        let calls = Rc::new(std::cell::Cell::new(0));
        let count = calls.clone();
        let cors = Cors::new()
            .allowed_origin("https://www.example.com")
            .build()
            .create(
                &(),
                fn_service(async move |req: WebRequest<()>| {
                    count.set(count.get() + 1);
                    Ok::<_, Infallible>(req.into_response(HttpResponse::NoContent().build()))
                }),
            )
            .pipeline(());

        for origin in [
            &b"https://www.unknown.com"[..],
            b"https://WWW.example.com",
            b"\xff",
        ] {
            let req = TestRequest::default()
                .header(header::ORIGIN, HeaderValue::try_from(origin).unwrap())
                .to_srv_request();
            let resp = cors.call(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            assert!(
                !resp
                    .headers()
                    .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            );
        }
        assert_eq!(calls.get(), 0);

        let resp = cors
            .call(TestRequest::default().to_srv_request())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert!(
            !resp
                .headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        );
        assert_eq!(resp.headers().get(header::VARY).unwrap(), "Origin");

        let req =
            TestRequest::with_header(header::ORIGIN, "https://www.example.com").to_srv_request();
        let resp = cors.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "https://www.example.com"
        );
        assert_eq!(calls.get(), 2);
    }

    #[ntex::test]
    async fn test_validate_origin() {
        let cors = Cors::new()
            .allowed_origin("https://www.example.com")
            .build()
            .create(&(), test::ok_service())
            .pipeline(());

        let req = TestRequest::with_header("Origin", "https://www.example.com")
            .method(Method::GET)
            .to_srv_request();

        let resp = cors.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[ntex::test]
    async fn test_no_origin_response() {
        let cors = Cors::new()
            .disable_preflight()
            .build()
            .create(&(), test::ok_service())
            .pipeline(());

        let req = TestRequest::default().method(Method::GET).to_srv_request();
        let resp = cors.call(req).await.unwrap();
        assert!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );

        let req = TestRequest::with_header("Origin", "https://www.example.com")
            .method(Method::OPTIONS)
            .to_srv_request();
        let resp = cors.call(req).await.unwrap();
        assert_eq!(
            &b"https://www.example.com"[..],
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap()
                .as_bytes()
        );
    }

    #[ntex::test]
    async fn test_response() {
        let exposed_headers = vec![header::AUTHORIZATION, header::ACCEPT];
        let cors = Cors::new()
            .send_wildcard()
            .disable_preflight()
            .max_age(3600)
            .allowed_methods(vec![Method::GET, Method::OPTIONS, Method::POST])
            .allowed_headers(exposed_headers.clone())
            .expose_headers(exposed_headers.clone())
            .allowed_header(header::CONTENT_TYPE)
            .build()
            .create(&(), test::ok_service())
            .pipeline(());

        let req = TestRequest::with_header("Origin", "https://www.example.com")
            .method(Method::OPTIONS)
            .to_srv_request();

        let resp = cors.call(req).await.unwrap();
        assert_eq!(
            &b"*"[..],
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap()
                .as_bytes()
        );
        assert_eq!(
            &b"Origin"[..],
            resp.headers().get(header::VARY).unwrap().as_bytes()
        );

        {
            let headers = resp
                .headers()
                .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
                .unwrap()
                .to_str()
                .unwrap()
                .split(',')
                .map(|s| s.trim())
                .collect::<Vec<&str>>();

            for h in exposed_headers {
                assert!(headers.contains(&h.as_str()));
            }
        }

        let exposed_headers = vec![header::AUTHORIZATION, header::ACCEPT];
        let cors =
            Cors::new()
                .send_wildcard()
                .disable_preflight()
                .max_age(3600)
                .allowed_methods(vec![Method::GET, Method::OPTIONS, Method::POST])
                .allowed_headers(exposed_headers.clone())
                .expose_headers(exposed_headers.clone())
                .allowed_header(header::CONTENT_TYPE)
                .build()
                .create(
                    &(),
                    fn_service(|req: WebRequest<()>| async move {
                        Ok::<_, std::convert::Infallible>(req.into_response(
                            HttpResponse::Ok().header(header::VARY, "Accept").build(),
                        ))
                    }),
                )
                .pipeline(());

        let req = TestRequest::with_header("Origin", "https://www.example.com")
            .method(Method::OPTIONS)
            .to_srv_request();
        let resp = cors.call(req).await.unwrap();
        assert_eq!(
            &b"Accept, Origin"[..],
            resp.headers().get(header::VARY).unwrap().as_bytes()
        );

        let cors = Cors::new()
            .disable_vary_header()
            .allowed_origin("https://www.example.com")
            .allowed_origin("https://www.google.com")
            .build()
            .create(&(), test::ok_service())
            .pipeline(());

        let req = TestRequest::with_header("Origin", "https://www.example.com")
            .method(Method::OPTIONS)
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .to_srv_request();
        let resp = cors.call(req).await.unwrap();

        let origins_str = resp
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap()
            .to_str()
            .unwrap();

        assert_eq!("https://www.example.com", origins_str);
    }

    #[ntex::test]
    async fn test_multiple_origins() {
        let cors = Cors::new()
            .allowed_origin("https://example.com")
            .allowed_origin("https://example.org")
            .allowed_methods(vec![Method::GET])
            .build()
            .create(&(), test::ok_service())
            .pipeline(());

        let req = TestRequest::with_header("Origin", "https://example.com")
            .method(Method::GET)
            .to_srv_request();

        let resp = cors.call(req).await.unwrap();
        assert_eq!(
            &b"https://example.com"[..],
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap()
                .as_bytes()
        );

        let req = TestRequest::with_header("Origin", "https://example.org")
            .method(Method::GET)
            .to_srv_request();

        let resp = cors.call(req).await.unwrap();
        assert_eq!(
            &b"https://example.org"[..],
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap()
                .as_bytes()
        );
    }

    #[ntex::test]
    async fn test_multiple_origins_preflight() {
        let cors = Cors::new()
            .allowed_origin("https://example.com")
            .allowed_origin("https://example.org")
            .allowed_methods(vec![Method::GET])
            .build()
            .create(&(), test::ok_service())
            .pipeline(());

        let req = TestRequest::with_header("Origin", "https://example.com")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
            .method(Method::OPTIONS)
            .to_srv_request();

        let resp = cors.call(req).await.unwrap();
        assert_eq!(
            &b"https://example.com"[..],
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap()
                .as_bytes()
        );

        let req = TestRequest::with_header("Origin", "https://example.org")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
            .method(Method::OPTIONS)
            .to_srv_request();

        let resp = cors.call(req).await.unwrap();
        assert_eq!(
            &b"https://example.org"[..],
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap()
                .as_bytes()
        );
    }

    /// STATEMENT: Setting `allowed_origin("*")` replaces an existing allowlist
    /// and echoes an origin that was not previously permitted.
    ///
    /// HOW:
    /// - Restrict the builder to one origin, then set `allowed_origin("*")`.
    /// - Send a request from another origin and assert `200` and its echoed
    ///   `Access-Control-Allow-Origin` value.
    #[ntex::test]
    async fn test_set_allowed_origin_to_all() {
        let cors = Cors::new()
            .allowed_origin("https://previous.example.com")
            .allowed_origin("*")
            .build()
            .create(&(), test::ok_service())
            .pipeline(());

        let req = TestRequest::with_header("Origin", "https://www.example.com")
            .method(Method::GET)
            .to_srv_request();

        let resp = cors.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap(),
            "https://www.example.com"
        );
    }

    /// STATEMENT: An `OPTIONS` request without `Access-Control-Request-Method`
    /// is not a preflight and reaches the inner service.
    ///
    /// HOW:
    /// - Send `OPTIONS` with only an `Origin` header through a middleware with
    ///   preflight enabled and an inner service that replies `204`.
    /// - Check the status is `204` and the normal CORS response headers
    ///   (`Access-Control-Allow-Origin`, `Vary`) are added.
    #[ntex::test]
    async fn options_without_request_method_is_not_preflight() {
        let cors = Cors::new()
            .build()
            .create(
                &(),
                fn_service(async move |req: WebRequest<()>| {
                    Ok::<_, Infallible>(req.into_response(HttpResponse::NoContent().build()))
                }),
            )
            .pipeline(());

        let req = TestRequest::with_header("Origin", "https://www.example.com")
            .method(Method::OPTIONS)
            .to_srv_request();
        let resp = cors.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .unwrap()
                .as_bytes(),
            b"https://www.example.com"
        );
        assert_eq!(
            resp.headers().get(header::VARY).unwrap().as_bytes(),
            b"Origin"
        );
    }

    /// STATEMENT: `Vary: Origin` is added to preflight responses and to responses
    /// for requests without `Origin`, so shared caches keep them apart.
    ///
    /// HOW:
    /// - Send a valid preflight and check its response has `Vary: Origin`.
    /// - Send a `GET` without `Origin` and check the response has no
    ///   `Access-Control-Allow-Origin` but does have `Vary: Origin`.
    #[ntex::test]
    async fn vary_is_set_for_preflight_and_requests_without_origin() {
        let cors = Cors::new()
            .build()
            .create(&(), test::ok_service())
            .pipeline(());

        let req = TestRequest::with_header("Origin", "https://www.example.com")
            .method(Method::OPTIONS)
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
            .to_srv_request();
        let resp = cors.call(req).await.unwrap();
        assert!(
            resp.headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_METHODS)
        );
        assert_eq!(
            resp.headers().get(header::VARY).unwrap().as_bytes(),
            b"Origin"
        );

        let req = TestRequest::default().method(Method::GET).to_srv_request();
        let resp = cors.call(req).await.unwrap();
        assert!(
            !resp
                .headers()
                .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN)
        );
        assert_eq!(
            resp.headers().get(header::VARY).unwrap().as_bytes(),
            b"Origin"
        );
    }

    /// STATEMENT: `Origin` is merged into all existing `Vary` headers and is not
    /// added when `Origin` or `*` is already listed.
    ///
    /// HOW:
    /// - The inner service sets `Vary` headers based on the request path.
    /// - `/two` sets two `Vary` headers; check they collapse into one value
    ///   ending with `Origin`.
    /// - `/origin` and `/star` already cover `Origin`; check `Vary` is unchanged.
    #[ntex::test]
    async fn vary_merges_existing_values() {
        let cors = Cors::new()
            .build()
            .create(
                &(),
                fn_service(async move |req: WebRequest<()>| {
                    let mut res = HttpResponse::Ok();
                    match req.path() {
                        "/two" => {
                            res.header(header::VARY, "Accept");
                            res.header(header::VARY, "Accept-Encoding");
                        }
                        "/origin" => {
                            res.header(header::VARY, "Accept, origin");
                        }
                        _ => {
                            res.header(header::VARY, "*");
                        }
                    }
                    Ok::<_, Infallible>(req.into_response(res.build()))
                }),
            )
            .pipeline(());

        for (path, expected) in [
            ("/two", &b"Accept, Accept-Encoding, Origin"[..]),
            ("/origin", b"Accept, origin"),
            ("/star", b"*"),
        ] {
            let req = TestRequest::with_uri(path)
                .header("Origin", "https://www.example.com")
                .to_srv_request();
            let resp = cors.call(req).await.unwrap();
            let vary: Vec<_> = resp.headers().get_all(header::VARY).collect();
            assert_eq!(vary.len(), 1, "{path}");
            assert_eq!(vary[0].as_bytes(), expected, "{path}");
        }
    }

    /// STATEMENT: Invalid origins, methods, and header names make `Cors::build`
    /// panic, and subsequent valid builder calls cannot erase that configuration error.
    ///
    /// HOW:
    /// - Supply an invalid origin, method, allowed header, allowed-header list, or exposed-header list.
    /// - Catch the build panic for each configuration, then rebuild after calling
    ///   the other setters with valid values and assert the same error is retained.
    #[test]
    fn builder_rejects_invalid_configuration_and_retains_errors() {
        let configurations: [fn() -> Cors; 5] = [
            || Cors::new().allowed_origin("http://["),
            || Cors::new().allowed_methods(["GET", "BAD METHOD", "POST"]),
            || Cors::new().allowed_header("bad header"),
            || Cors::new().allowed_headers(["authorization", "bad header", "accept"]),
            || Cors::new().expose_headers(["x-response", "bad header", "accept"]),
        ];
        for configuration in configurations {
            let panic_message = |builder: Cors| {
                let error = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    builder.build::<()>()
                }))
                .err()
                .expect("invalid CORS configuration must panic");
                *error
                    .downcast::<String>()
                    .expect("configuration error message")
            };
            let original = panic_message(configuration());
            assert!(!original.is_empty());
            let retained = panic_message(
                configuration()
                    .allowed_origin("https://example.com")
                    .allowed_methods([Method::GET])
                    .allowed_header(header::AUTHORIZATION)
                    .allowed_headers([header::ACCEPT])
                    .expose_headers(["x-response"])
                    .max_age(60)
                    .send_wildcard()
                    .supports_credentials()
                    .disable_vary_header()
                    .disable_preflight(),
            );
            assert_eq!(retained, original);
        }
    }

    /// STATEMENT: Credentialed CORS echoes the client origin and advertises the
    /// configured permissions on preflights, but only exposes headers on actual cross-origin responses.
    ///
    /// HOW:
    /// - Configure credentials, two methods, two allowed headers, an exposed header,
    ///   and a cache age for both unrestricted and explicitly allowed origins.
    /// - Send preflights with mixed-case repeated header names and without requested headers;
    ///   assert echoed origins, credentials, permissions, cache age, and no inner calls.
    /// - Send actual requests with and without `Origin`; assert the application's `204`,
    ///   CORS headers only for the cross-origin request, merged `Vary`, and two inner calls.
    #[ntex::test]
    async fn credentialed_preflight_and_actual_responses() {
        for builder in [
            Cors::new().supports_credentials(),
            Cors::new()
                .allowed_origin("https://example.com")
                .send_wildcard()
                .supports_credentials(),
        ] {
            let calls = Rc::new(std::cell::Cell::new(0));
            let count = calls.clone();
            let cors = builder
                .allowed_methods([Method::GET, Method::POST])
                .allowed_header(header::AUTHORIZATION)
                .allowed_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
                .expose_headers(["x-response"])
                .max_age(600)
                .build()
                .create(
                    &(),
                    fn_service(async move |req: WebRequest<()>| {
                        count.set(count.get() + 1);
                        Ok::<_, Infallible>(
                            req.into_response(
                                HttpResponse::NoContent()
                                    .header(header::VARY, "Accept-Encoding")
                                    .build(),
                            ),
                        )
                    }),
                )
                .pipeline(());

            for requested_headers in [Some(" Authorization , CONTENT-TYPE, authorization "), None] {
                let mut req = TestRequest::with_header(header::ORIGIN, "https://example.com")
                    .method(Method::OPTIONS)
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST");
                if let Some(headers) = requested_headers {
                    req = req.header(header::ACCESS_CONTROL_REQUEST_HEADERS, headers);
                }
                let resp = cors.call(req.to_srv_request()).await.unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
                assert_eq!(
                    resp.headers()
                        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                        .unwrap(),
                    "https://example.com"
                );
                assert_eq!(
                    resp.headers()
                        .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                        .unwrap(),
                    "true"
                );
                assert_eq!(
                    resp.headers().get(header::ACCESS_CONTROL_MAX_AGE).unwrap(),
                    "600"
                );
                let headers: HashSet<_> = resp
                    .headers()
                    .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .split(',')
                    .map(str::trim)
                    .collect();
                assert_eq!(headers, HashSet::from(["authorization", "content-type"]));
                let methods: HashSet<_> = resp
                    .headers()
                    .get(header::ACCESS_CONTROL_ALLOW_METHODS)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .split(',')
                    .map(str::trim)
                    .collect();
                assert_eq!(methods, HashSet::from(["GET", "POST"]));
                assert_eq!(resp.headers().get(header::VARY).unwrap(), "Origin");
                assert!(
                    !resp
                        .headers()
                        .contains_key(header::ACCESS_CONTROL_EXPOSE_HEADERS)
                );
            }
            assert_eq!(calls.get(), 0);

            for origin in [Some("https://example.com"), None] {
                let mut req = TestRequest::default();
                if let Some(origin) = origin {
                    req = req.header(header::ORIGIN, origin);
                }
                let resp = cors.call(req.to_srv_request()).await.unwrap();
                assert_eq!(resp.status(), StatusCode::NO_CONTENT);
                if origin.is_some() {
                    assert_eq!(
                        resp.headers()
                            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                            .unwrap(),
                        "https://example.com"
                    );
                    assert_eq!(
                        resp.headers()
                            .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                            .unwrap(),
                        "true"
                    );
                    assert_eq!(
                        resp.headers()
                            .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
                            .unwrap(),
                        "x-response"
                    );
                } else {
                    for name in [
                        header::ACCESS_CONTROL_ALLOW_ORIGIN,
                        header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                        header::ACCESS_CONTROL_EXPOSE_HEADERS,
                    ] {
                        assert!(!resp.headers().contains_key(name));
                    }
                }
                assert!(
                    !resp
                        .headers()
                        .contains_key(header::ACCESS_CONTROL_ALLOW_METHODS)
                );
                assert!(!resp.headers().contains_key(header::ACCESS_CONTROL_MAX_AGE));
                assert_eq!(
                    resp.headers().get(header::VARY).unwrap(),
                    "Accept-Encoding, Origin"
                );
            }
            assert_eq!(calls.get(), 2);
        }
    }

    /// STATEMENT: Unrestricted preflights echo requested headers verbatim and
    /// choose a wildcard or the supplied origin according to `send_wildcard`.
    ///
    /// HOW:
    /// - Build unrestricted middleware with and without `send_wildcard` and an inner service replying `204`.
    /// - Send preflights with and without `Origin` and requested headers; assert `200`,
    ///   the exact echoed or absent headers, the appropriate allow-origin value, and `Vary: Origin`.
    /// - Send an actual request with `Origin` and assert the inner service's `204`,
    ///   confirming that only preflight requests are intercepted.
    #[ntex::test]
    async fn unrestricted_preflight_echoes_requested_headers() {
        for wildcard in [false, true] {
            let builder = if wildcard {
                Cors::new().send_wildcard()
            } else {
                Cors::new()
            };
            let cors = builder
                .build()
                .create(
                    &(),
                    fn_service(async move |req: WebRequest<()>| {
                        Ok::<_, Infallible>(req.into_response(HttpResponse::NoContent().build()))
                    }),
                )
                .pipeline(());
            for with_headers in [false, true] {
                let mut req = TestRequest::default()
                    .method(Method::OPTIONS)
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET");
                if with_headers {
                    req = req.header(header::ORIGIN, "https://example.com").header(
                        header::ACCESS_CONTROL_REQUEST_HEADERS,
                        "X-Custom, Content-Type",
                    );
                }
                let resp = cors.call(req.to_srv_request()).await.unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
                let allowed_origin = resp.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN);
                if wildcard {
                    assert_eq!(allowed_origin.unwrap(), "*");
                } else if with_headers {
                    assert_eq!(allowed_origin.unwrap(), "https://example.com");
                } else {
                    assert!(allowed_origin.is_none());
                }
                let allowed_headers = resp.headers().get(header::ACCESS_CONTROL_ALLOW_HEADERS);
                if with_headers {
                    assert_eq!(allowed_headers.unwrap(), "X-Custom, Content-Type");
                } else {
                    assert!(allowed_headers.is_none());
                }
                assert!(
                    !resp
                        .headers()
                        .contains_key(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                );
                assert!(!resp.headers().contains_key(header::ACCESS_CONTROL_MAX_AGE));
                assert_eq!(resp.headers().get(header::VARY).unwrap(), "Origin");
            }
            let req =
                TestRequest::with_header(header::ORIGIN, "https://example.com").to_srv_request();
            let resp = cors.call(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::NO_CONTENT);
            assert!(
                !resp
                    .headers()
                    .contains_key(header::ACCESS_CONTROL_ALLOW_METHODS)
            );
        }
    }

    /// STATEMENT: Malformed or disallowed preflight origins, methods, and requested
    /// header names produce their respective `CorsError` and a `400` without calling the application.
    ///
    /// HOW:
    /// - Restrict origins, methods, and headers, and count calls to the inner service.
    /// - Send preflights with missing, malformed, case-mismatched, or forbidden origins,
    ///   malformed or forbidden methods, and malformed, empty, or forbidden header lists.
    /// - Assert each error variant, the middleware's `400`, no allow-origin header, and zero inner calls.
    /// - Send a valid actual request as a control and assert `204` and one inner call.
    #[ntex::test]
    async fn preflight_rejects_invalid_origin_method_and_headers() {
        let calls = Rc::new(std::cell::Cell::new(0));
        let count = calls.clone();
        let cors = Cors::new()
            .allowed_origin("https://example.com")
            .allowed_methods([Method::GET])
            .allowed_header(header::AUTHORIZATION)
            .build()
            .create(
                &(),
                fn_service(async move |req: WebRequest<()>| {
                    count.set(count.get() + 1);
                    Ok::<_, Infallible>(req.into_response(HttpResponse::NoContent().build()))
                }),
            );
        let inner = cors.inner.clone();
        let cors = cors.pipeline(());
        let cases: &[(&str, Option<&[u8]>, &[u8], Option<&[u8]>, CorsError)] = &[
            (
                "missing origin",
                None,
                b"GET",
                None,
                CorsError::MissingOrigin,
            ),
            (
                "malformed origin",
                Some(b"\xff"),
                b"GET",
                None,
                CorsError::BadOrigin,
            ),
            (
                "forbidden origin",
                Some(b"https://other.com"),
                b"GET",
                None,
                CorsError::OriginNotAllowed,
            ),
            (
                "case-mismatched origin",
                Some(b"https://EXAMPLE.com"),
                b"GET",
                None,
                CorsError::OriginNotAllowed,
            ),
            (
                "malformed method",
                Some(b"https://example.com"),
                b"GET POST",
                None,
                CorsError::BadRequestMethod,
            ),
            (
                "non-ASCII method",
                Some(b"https://example.com"),
                b"\xff",
                None,
                CorsError::BadRequestMethod,
            ),
            (
                "forbidden method",
                Some(b"https://example.com"),
                b"DELETE",
                None,
                CorsError::MethodNotAllowed,
            ),
            (
                "malformed header name",
                Some(b"https://example.com"),
                b"GET",
                Some(b"bad header"),
                CorsError::BadRequestHeaders,
            ),
            (
                "non-ASCII header name",
                Some(b"https://example.com"),
                b"GET",
                Some(b"\xff"),
                CorsError::BadRequestHeaders,
            ),
            (
                "empty header list",
                Some(b"https://example.com"),
                b"GET",
                Some(b""),
                CorsError::BadRequestHeaders,
            ),
            (
                "empty trailing header name",
                Some(b"https://example.com"),
                b"GET",
                Some(b"authorization,"),
                CorsError::BadRequestHeaders,
            ),
            (
                "forbidden header",
                Some(b"https://example.com"),
                b"GET",
                Some(b"authorization, x-forbidden"),
                CorsError::HeadersNotAllowed,
            ),
        ];
        for (name, origin, method, headers, expected) in cases {
            let mut req = TestRequest::default().method(Method::OPTIONS).header(
                header::ACCESS_CONTROL_REQUEST_METHOD,
                HeaderValue::try_from(*method).unwrap(),
            );
            if let Some(origin) = *origin {
                req = req.header(header::ORIGIN, HeaderValue::try_from(origin).unwrap());
            }
            if let Some(headers) = *headers {
                req = req.header(
                    header::ACCESS_CONTROL_REQUEST_HEADERS,
                    HeaderValue::try_from(headers).unwrap(),
                );
            }
            let req = req.to_srv_request();
            let error = inner.preflight_check(req.head()).expect_err(name);
            assert_eq!(
                std::mem::discriminant(&error),
                std::mem::discriminant(expected),
                "{name}"
            );
            let resp = cors.call(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{name}");
            assert!(
                !resp
                    .headers()
                    .contains_key(header::ACCESS_CONTROL_ALLOW_ORIGIN),
                "{name}"
            );
        }
        assert_eq!(calls.get(), 0);
        let req = TestRequest::with_header(header::ORIGIN, "https://example.com").to_srv_request();
        let resp = cors.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(calls.get(), 1);
    }

    /// STATEMENT: Disabling preflight delegates `OPTIONS` to the application without
    /// validating requested permissions, while retaining origin checks and respecting disabled `Vary` support.
    ///
    /// HOW:
    /// - Disable preflight and `Vary`, restrict methods and headers, and configure an inner
    ///   service that verifies the incoming `OPTIONS` headers and returns `202` with `Vary: Accept`.
    /// - Request a forbidden method and header from an allowed origin; assert `202`, normal
    ///   allow-origin, unchanged `Vary`, no preflight-only headers, and one inner call.
    /// - Repeat with a forbidden origin; assert `400` and no additional inner call.
    #[ntex::test]
    async fn disabled_preflight_preserves_application_response() {
        let calls = Rc::new(std::cell::Cell::new(0));
        let count = calls.clone();
        let cors = Cors::new()
            .allowed_origin("https://example.com")
            .allowed_methods([Method::GET])
            .allowed_header(header::AUTHORIZATION)
            .max_age(600)
            .disable_preflight()
            .disable_vary_header()
            .build()
            .create(
                &(),
                fn_service(async move |req: WebRequest<()>| {
                    count.set(count.get() + 1);
                    assert_eq!(req.method(), Method::OPTIONS);
                    assert_eq!(
                        req.headers()
                            .get(header::ACCESS_CONTROL_REQUEST_METHOD)
                            .unwrap(),
                        "DELETE"
                    );
                    assert_eq!(
                        req.headers()
                            .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
                            .unwrap(),
                        "X-Forbidden"
                    );
                    Ok::<_, Infallible>(
                        req.into_response(
                            HttpResponse::Accepted()
                                .header(header::VARY, "Accept")
                                .build(),
                        ),
                    )
                }),
            )
            .pipeline(());
        for (origin, expected) in [
            ("https://example.com", StatusCode::ACCEPTED),
            ("https://other.com", StatusCode::BAD_REQUEST),
        ] {
            let req = TestRequest::with_header(header::ORIGIN, origin)
                .method(Method::OPTIONS)
                .header(header::ACCESS_CONTROL_REQUEST_METHOD, "DELETE")
                .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "X-Forbidden")
                .to_srv_request();
            let resp = cors.call(req).await.unwrap();
            assert_eq!(resp.status(), expected);
            if expected == StatusCode::ACCEPTED {
                assert_eq!(
                    resp.headers()
                        .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                        .unwrap(),
                    origin
                );
                assert_eq!(resp.headers().get(header::VARY).unwrap(), "Accept");
            }
            for name in [
                header::ACCESS_CONTROL_ALLOW_METHODS,
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                header::ACCESS_CONTROL_MAX_AGE,
            ] {
                assert!(!resp.headers().contains_key(name));
            }
        }
        assert_eq!(calls.get(), 1);
    }

    /// STATEMENT: The `Default` trait builder behaves like `Cors::new`.
    ///
    /// HOW:
    /// - Build middleware from `<Cors as Default>::default()` instead of `Cors::new`.
    /// - Send a cross-origin request and confirm `build` does not panic and the request succeeds.
    #[ntex::test]
    async fn default_trait_builder_matches_new() {
        let cors = <Cors as Default>::default()
            .build()
            .create(&(), test::ok_service())
            .pipeline(());
        let req = TestRequest::with_header("Origin", "https://www.example.com").to_srv_request();

        let resp = cors.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
