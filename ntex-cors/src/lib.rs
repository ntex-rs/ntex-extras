#![allow(
    clippy::borrow_interior_mutable_const,
    clippy::type_complexity,
    clippy::mutable_key_type
)]
//! Cross-origin resource sharing (CORS) for ntex applications
//!
//! CORS middleware could be used with application and with resource.
//! Cors middleware could be used as parameter for `App::wrap()`,
//! `Resource::wrap()` or `Scope::wrap()` methods.
//!
//! # Example
//!
//! ```rust,no_run
//! use ntex_cors::Cors;
//! use ntex::{http, web};
//! use ntex::web::{App, HttpRequest, HttpResponse};
//!
//! async fn index(req: HttpRequest) -> &'static str {
//!     "Hello world"
//! }
//!
//! #[ntex::main]
//! async fn main() -> std::io::Result<()> {
//!     web::server(|| App::new()
//!         .wrap(
//!             Cors::new() // <- Construct CORS middleware builder
//!               .allowed_origin("https://www.rust-lang.org/")
//!               .allowed_methods(vec!["GET", "POST"])
//!               .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
//!               .allowed_header(http::header::CONTENT_TYPE)
//!               .max_age(3600)
//!               .finish())
//!         .service(
//!             web::resource("/index.html")
//!               .route(web::get().to(index))
//!               .route(web::head().to(|| async { HttpResponse::MethodNotAllowed() }))
//!         ))
//!         .bind("127.0.0.1:8080")?
//!         .run()
//!         .await
//! }
//! ```
//! In this example custom *CORS* middleware get registered for "/index.html"
//! endpoint.
//!
//! Cors middleware automatically handle *OPTIONS* preflight request.
use std::{
    collections::HashSet, convert::TryFrom, iter::FromIterator, marker::PhantomData, rc::Rc,
};

use derive_more::Display;
use ntex::http::header::{self, HeaderName, HeaderValue};
use ntex::http::{error::HttpError, HeaderMap, Method, RequestHead, StatusCode, Uri};
use ntex::service::{Middleware, Service, ServiceCtx};
use ntex::util::Either;
use ntex::web::{
    DefaultError, ErrorRenderer, HttpResponse, WebRequest, WebResponse, WebResponseError,
};

/// A set of errors that can occur during processing CORS
#[derive(Debug, Display)]
pub enum CorsError {
    /// The HTTP request header `Origin` is required but was not provided
    #[display(fmt = "The HTTP request header `Origin` is required but was not provided")]
    MissingOrigin,
    /// The HTTP request header `Origin` could not be parsed correctly.
    #[display(fmt = "The HTTP request header `Origin` could not be parsed correctly.")]
    BadOrigin,
    /// The request header `Access-Control-Request-Method` is required but is
    /// missing
    #[display(
        fmt = "The request header `Access-Control-Request-Method` is required but is missing"
    )]
    MissingRequestMethod,
    /// The request header `Access-Control-Request-Method` has an invalid value
    #[display(fmt = "The request header `Access-Control-Request-Method` has an invalid value")]
    BadRequestMethod,
    /// The request header `Access-Control-Request-Headers`  has an invalid
    /// value
    #[display(
        fmt = "The request header `Access-Control-Request-Headers`  has an invalid value"
    )]
    BadRequestHeaders,
    /// Origin is not allowed to make this request
    #[display(fmt = "Origin is not allowed to make this request")]
    OriginNotAllowed,
    /// Requested method is not allowed
    #[display(fmt = "Requested method is not allowed")]
    MethodNotAllowed,
    /// One or more headers requested are not allowed
    #[display(fmt = "One or more headers requested are not allowed")]
    HeadersNotAllowed,
}

/// DefaultError renderer support
impl WebResponseError<DefaultError> for CorsError {
    fn status_code(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }
}

/// An enum signifying that some of type T is allowed, or `All` (everything is
/// allowed).
///
/// `Default` is implemented for this enum and is `All`.
#[derive(Default, Clone, Debug, Eq, PartialEq)]
pub enum AllOrSome<T> {
    /// Everything is allowed. Usually equivalent to the "*" value.
    #[default]
    All,
    /// Only some of `T` is allowed
    Some(T),
}

impl<T> AllOrSome<T> {
    /// Returns whether this is an `All` variant
    pub fn is_all(&self) -> bool {
        match *self {
            AllOrSome::All => true,
            AllOrSome::Some(_) => false,
        }
    }

    /// Returns whether this is a `Some` variant
    pub fn is_some(&self) -> bool {
        !self.is_all()
    }

    /// Returns &T
    pub fn as_ref(&self) -> Option<&T> {
        match *self {
            AllOrSome::All => None,
            AllOrSome::Some(ref t) => Some(t),
        }
    }
}

/// Structure that follows the builder pattern for building `Cors` middleware
/// structs.
///
/// To construct a cors:
///
///   1. Call [`Cors::build`](struct.Cors.html#method.build) to start building.
///   2. Use any of the builder methods to set fields in the backend.
/// 3. Call [finish](struct.Cors.html#method.finish) to retrieve the
/// constructed backend.
///
/// # Example
///
/// ```rust
/// use ntex_cors::Cors;
/// use ntex::http::header;
///
/// let cors = Cors::new()
///     .allowed_origin("https://www.rust-lang.org/")
///     .allowed_methods(vec!["GET", "POST"])
///     .allowed_headers(vec![header::AUTHORIZATION, header::ACCEPT])
///     .allowed_header(header::CONTENT_TYPE)
///     .max_age(3600);
/// ```
#[derive(Default)]
pub struct Cors {
    cors: Option<Inner>,
    methods: bool,
    expose_hdrs: HashSet<HeaderName>,
    error: Option<HttpError>,
}

impl Cors {
    /// Build a new CORS middleware instance
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

    /// Build a new CORS default middleware
    pub fn default<Err>() -> CorsFactory<Err> {
        let inner = Inner {
            origins: AllOrSome::default(),
            origins_str: None,
            methods: HashSet::from_iter(
                vec![
                    Method::GET,
                    Method::HEAD,
                    Method::POST,
                    Method::OPTIONS,
                    Method::PUT,
                    Method::PATCH,
                    Method::DELETE,
                ]
                .into_iter(),
            ),
            headers: AllOrSome::All,
            expose_hdrs: None,
            max_age: None,
            preflight: true,
            send_wildcard: false,
            supports_credentials: false,
            vary_header: true,
        };
        CorsFactory { inner: Rc::new(inner), _t: PhantomData }
    }

    /// Add an origin that are allowed to make requests.
    /// Will be verified against the `Origin` request header.
    ///
    /// When `All` is set, and `send_wildcard` is set, "*" will be sent in
    /// the `Access-Control-Allow-Origin` response header. Otherwise, the
    /// client's `Origin` request header will be echoed back in the
    /// `Access-Control-Allow-Origin` response header.
    ///
    /// When `Some` is set, the client's `Origin` request header will be
    /// checked in a case-sensitive manner.
    ///
    /// This is the `list of origins` in the
    /// [Resource Processing Model](https://www.w3.org/TR/cors/#resource-processing-model).
    ///
    /// Defaults to `All`.
    ///
    /// Builder panics if supplied origin is not valid uri.
    pub fn allowed_origin(mut self, origin: &str) -> Self {
        if let Some(cors) = cors(&mut self.cors, &self.error) {
            match Uri::try_from(origin) {
                Ok(_) => {
                    if cors.origins.is_all() {
                        cors.origins = AllOrSome::Some(HashSet::new());
                    }
                    if let AllOrSome::Some(ref mut origins) = cors.origins {
                        origins.insert(origin.to_owned());
                    }
                }
                Err(e) => {
                    self.error = Some(e.into());
                }
            }
        }
        self
    }

    /// Set a list of methods which the allowed origins are allowed to access
    /// for requests.
    ///
    /// This is the `list of methods` in the
    /// [Resource Processing Model](https://www.w3.org/TR/cors/#resource-processing-model).
    ///
    /// Defaults to `[GET, HEAD, POST, OPTIONS, PUT, PATCH, DELETE]`
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
                        self.error = Some(e.into());
                        break;
                    }
                }
            }
        }
        self
    }

    /// Set an allowed header
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
                Err(e) => self.error = Some(e.into()),
            }
        }
        self
    }

    /// Set a list of header field names which can be used when
    /// this resource is accessed by allowed origins.
    ///
    /// If `All` is set, whatever is requested by the client in
    /// `Access-Control-Request-Headers` will be echoed back in the
    /// `Access-Control-Allow-Headers` header.
    ///
    /// This is the `list of headers` in the
    /// [Resource Processing Model](https://www.w3.org/TR/cors/#resource-processing-model).
    ///
    /// Defaults to `All`.
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
                        self.error = Some(e.into());
                        break;
                    }
                }
            }
        }
        self
    }

    /// Set a list of headers which are safe to expose to the API of a CORS API
    /// specification. This corresponds to the
    /// `Access-Control-Expose-Headers` response header.
    ///
    /// This is the `list of exposed headers` in the
    /// [Resource Processing Model](https://www.w3.org/TR/cors/#resource-processing-model).
    ///
    /// This defaults to an empty set.
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
                    self.error = Some(e.into());
                    break;
                }
            }
        }
        self
    }

    /// Set a maximum time for which this CORS request maybe cached.
    /// This value is set as the `Access-Control-Max-Age` header.
    ///
    /// This defaults to `None` (unset).
    pub fn max_age(mut self, max_age: usize) -> Self {
        if let Some(cors) = cors(&mut self.cors, &self.error) {
            cors.max_age = Some(max_age)
        }
        self
    }

    /// Set a wildcard origins
    ///
    /// If send wildcard is set and the `allowed_origins` parameter is `All`, a
    /// wildcard `Access-Control-Allow-Origin` response header is sent,
    /// rather than the request’s `Origin` header.
    ///
    /// This is the `supports credentials flag` in the
    /// [Resource Processing Model](https://www.w3.org/TR/cors/#resource-processing-model).
    ///
    /// This **CANNOT** be used in conjunction with `allowed_origins` set to
    /// `All` and `allow_credentials` set to `true`. Depending on the mode
    /// of usage, this will either result in an `Error::
    /// CredentialsWithWildcardOrigin` error during ntex launch or runtime.
    ///
    /// Defaults to `false`.
    pub fn send_wildcard(mut self) -> Self {
        if let Some(cors) = cors(&mut self.cors, &self.error) {
            cors.send_wildcard = true
        }
        self
    }

    /// Allows users to make authenticated requests
    ///
    /// If true, injects the `Access-Control-Allow-Credentials` header in
    /// responses. This allows cookies and credentials to be submitted
    /// across domains.
    ///
    /// This option cannot be used in conjunction with an `allowed_origin` set
    /// to `All` and `send_wildcards` set to `true`.
    ///
    /// Defaults to `false`.
    ///
    /// Builder panics if credentials are allowed, but the Origin is set to "*".
    /// This is not allowed by W3C
    pub fn supports_credentials(mut self) -> Self {
        if let Some(cors) = cors(&mut self.cors, &self.error) {
            cors.supports_credentials = true
        }
        self
    }

    /// Disable `Vary` header support.
    ///
    /// When enabled the header `Vary: Origin` will be returned as per the W3
    /// implementation guidelines.
    ///
    /// Setting this header when the `Access-Control-Allow-Origin` is
    /// dynamically generated (e.g. when there is more than one allowed
    /// origin, and an Origin than '*' is returned) informs CDNs and other
    /// caches that the CORS headers are dynamic, and cannot be cached.
    ///
    /// By default `vary` header support is enabled.
    pub fn disable_vary_header(mut self) -> Self {
        if let Some(cors) = cors(&mut self.cors, &self.error) {
            cors.vary_header = false
        }
        self
    }

    /// Disable *preflight* request support.
    ///
    /// When enabled cors middleware automatically handles *OPTIONS* request.
    /// This is useful application level middleware.
    ///
    /// By default *preflight* support is enabled.
    pub fn disable_preflight(mut self) -> Self {
        if let Some(cors) = cors(&mut self.cors, &self.error) {
            cors.preflight = false
        }
        self
    }

    /// Construct cors middleware
    pub fn finish<Err>(self) -> CorsFactory<Err> {
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
            let s = origins.iter().fold(String::new(), |s, v| format!("{}, {}", s, v));
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

        CorsFactory { inner: Rc::new(cors), _t: PhantomData }
    }
}

fn cors<'a>(parts: &'a mut Option<Inner>, err: &Option<HttpError>) -> Option<&'a mut Inner> {
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
                if let Some(origin) =
                    headers.get(&header::ORIGIN).filter(|o| match o.to_str() {
                        Ok(os) => origins.contains(os),
                        _ => false,
                    })
                {
                    Some(origin.clone())
                } else {
                    Some(self.origins_str.as_ref().unwrap().clone())
                }
            }
        }
    }

    fn validate_allowed_method(&self, req: &RequestHead) -> Result<(), CorsError> {
        if let Some(hdr) = req.headers().get(&header::ACCESS_CONTROL_REQUEST_METHOD) {
            if let Ok(meth) = hdr.to_str() {
                if let Ok(method) = Method::try_from(meth) {
                    return self
                        .methods
                        .get(&method)
                        .map(|_| ())
                        .ok_or(CorsError::MethodNotAllowed);
                }
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

    fn preflight_check(
        &self,
        req: &RequestHead,
    ) -> Result<Either<HttpResponse, ()>, CorsError> {
        if self.preflight && Method::OPTIONS == req.method {
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
                req.headers.get(&header::ACCESS_CONTROL_REQUEST_HEADERS).cloned()
            };

            let res = HttpResponse::Ok()
                .if_some(self.max_age.as_ref(), |max_age, resp| {
                    let _ = resp.header(
                        header::ACCESS_CONTROL_MAX_AGE,
                        format!("{}", max_age).as_str(),
                    );
                })
                .if_some(headers, |headers, resp| {
                    let _ = resp.header(header::ACCESS_CONTROL_ALLOW_HEADERS, headers);
                })
                .if_some(self.access_control_allow_origin(req.headers()), |origin, resp| {
                    let _ = resp.header(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
                })
                .if_true(self.supports_credentials, |resp| {
                    resp.header(header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true");
                })
                .header(
                    header::ACCESS_CONTROL_ALLOW_METHODS,
                    &self
                        .methods
                        .iter()
                        .fold(String::new(), |s, v| s + "," + v.as_str())
                        .as_str()[1..],
                )
                .finish()
                .into_body();

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
        if self.vary_header {
            let value = if let Some(hdr) = headers.get(&header::VARY) {
                let mut val: Vec<u8> = Vec::with_capacity(hdr.as_bytes().len() + 8);
                val.extend(hdr.as_bytes());
                val.extend(b", Origin");
                HeaderValue::try_from(&val[..]).unwrap()
            } else {
                HeaderValue::from_static("Origin")
            };
            headers.insert(header::VARY, value);
        }
    }
}

/// `Middleware` for Cross-origin resource sharing support
///
/// The Cors struct contains the settings for CORS requests to be validated and
/// for responses to be generated.
pub struct CorsFactory<Err> {
    inner: Rc<Inner>,
    _t: PhantomData<Err>,
}

impl<S, Err> Middleware<S> for CorsFactory<Err>
where
    S: Service<WebRequest<Err>, Response = WebResponse>,
{
    type Service = CorsMiddleware<S>;

    fn create(&self, service: S) -> Self::Service {
        CorsMiddleware { service, inner: self.inner.clone() }
    }
}

/// `Middleware` for Cross-origin resource sharing support
///
/// The Cors struct contains the settings for CORS requests to be validated and
/// for responses to be generated.
#[derive(Clone)]
pub struct CorsMiddleware<S> {
    service: S,
    inner: Rc<Inner>,
}

impl<S, Err> Service<WebRequest<Err>> for CorsMiddleware<S>
where
    S: Service<WebRequest<Err>, Response = WebResponse>,
    Err: ErrorRenderer,
    Err::Container: From<S::Error>,
    CorsError: WebResponseError<Err>,
{
    type Response = WebResponse;
    type Error = S::Error;

    ntex::forward_ready!(service);
    ntex::forward_shutdown!(service);

    async fn call(
        &self,
        req: WebRequest<Err>,
        ctx: ServiceCtx<'_, Self>,
    ) -> Result<Self::Response, S::Error> {
        match self.inner.preflight_check(req.head()) {
            Ok(Either::Left(res)) => Ok(req.into_response(res)),
            Ok(Either::Right(_)) => {
                let inner = self.inner.clone();
                let has_origin = req.headers().contains_key(&header::ORIGIN);
                let allowed_origin = inner.access_control_allow_origin(req.headers());

                let mut res = ctx.call(&self.service, req).await?;

                if has_origin {
                    inner.handle_response(res.headers_mut(), allowed_origin);
                }
                Ok(res)
            }
            Err(e) => Ok(req.render_error(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use ntex::service::{fn_service, Middleware, Pipeline};
    use ntex::web::{self, test, test::TestRequest};

    use super::*;

    #[ntex::test]
    #[should_panic(expected = "Credentials are allowed, but the Origin is set to")]
    async fn cors_validates_illegal_allow_credentials() {
        let _cors =
            Cors::new().supports_credentials().send_wildcard().finish::<web::DefaultError>();
    }

    #[ntex::test]
    async fn validate_origin_allows_all_origins() {
        let cors = Cors::new().finish().create(test::ok_service()).into();
        let req =
            TestRequest::with_header("Origin", "https://www.example.com").to_srv_request();

        let resp = test::call_service(&cors, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[ntex::test]
    async fn default() {
        let cors = Cors::default().create(test::ok_service()).into();
        let req =
            TestRequest::with_header("Origin", "https://www.example.com").to_srv_request();

        let resp = test::call_service(&cors, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[ntex::test]
    async fn test_preflight() {
        let cors: Pipeline<_> = Cors::new()
            .send_wildcard()
            .max_age(3600)
            .allowed_methods(vec![Method::GET, Method::OPTIONS, Method::POST])
            .allowed_headers(vec![header::AUTHORIZATION, header::ACCEPT])
            .allowed_header(header::CONTENT_TYPE)
            .finish()
            .create(test::ok_service())
            .into();

        let req = TestRequest::with_header("Origin", "https://www.example.com")
            .method(Method::OPTIONS)
            .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "X-Not-Allowed")
            .to_srv_request();

        assert!(cors.get_ref().inner.validate_allowed_method(req.head()).is_err());
        assert!(cors.get_ref().inner.validate_allowed_headers(req.head()).is_err());
        let resp = test::call_service(&cors, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let req = TestRequest::with_header("Origin", "https://www.example.com")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "put")
            .method(Method::OPTIONS)
            .to_srv_request();

        assert!(cors.get_ref().inner.validate_allowed_method(req.head()).is_err());
        assert!(cors.get_ref().inner.validate_allowed_headers(req.head()).is_ok());

        let req = TestRequest::with_header("Origin", "https://www.example.com")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "AUTHORIZATION,ACCEPT")
            .method(Method::OPTIONS)
            .to_srv_request();

        let resp = test::call_service(&cors, req).await;
        assert_eq!(
            &b"*"[..],
            resp.headers().get(&header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap().as_bytes()
        );
        assert_eq!(
            &b"3600"[..],
            resp.headers().get(&header::ACCESS_CONTROL_MAX_AGE).unwrap().as_bytes()
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

        let methods =
            resp.headers().get(header::ACCESS_CONTROL_ALLOW_METHODS).unwrap().to_str().unwrap();
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
    //        .finish();
    //    let mut req = HttpRequest::default();
    //    cors.start(&req).unwrap();
    // }

    #[ntex::test]
    #[should_panic(expected = "OriginNotAllowed")]
    async fn test_validate_not_allowed_origin() {
        let cors: Pipeline<_> = Cors::new()
            .allowed_origin("https://www.example.com")
            .finish()
            .create(test::ok_service::<web::DefaultError>())
            .into();

        let req = TestRequest::with_header("Origin", "https://www.unknown.com")
            .method(Method::GET)
            .to_srv_request();
        cors.get_ref().inner.validate_origin(req.head()).unwrap();
        cors.get_ref().inner.validate_allowed_method(req.head()).unwrap();
        cors.get_ref().inner.validate_allowed_headers(req.head()).unwrap();
    }

    #[ntex::test]
    async fn test_validate_origin() {
        let cors = Cors::new()
            .allowed_origin("https://www.example.com")
            .finish()
            .create(test::ok_service())
            .into();

        let req = TestRequest::with_header("Origin", "https://www.example.com")
            .method(Method::GET)
            .to_srv_request();

        let resp = test::call_service(&cors, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[ntex::test]
    async fn test_no_origin_response() {
        let cors = Cors::new().disable_preflight().finish().create(test::ok_service()).into();

        let req = TestRequest::default().method(Method::GET).to_srv_request();
        let resp = test::call_service(&cors, req).await;
        assert!(resp.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());

        let req = TestRequest::with_header("Origin", "https://www.example.com")
            .method(Method::OPTIONS)
            .to_srv_request();
        let resp = test::call_service(&cors, req).await;
        assert_eq!(
            &b"https://www.example.com"[..],
            resp.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap().as_bytes()
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
            .finish()
            .create(test::ok_service())
            .into();

        let req = TestRequest::with_header("Origin", "https://www.example.com")
            .method(Method::OPTIONS)
            .to_srv_request();

        let resp = test::call_service(&cors, req).await;
        assert_eq!(
            &b"*"[..],
            resp.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap().as_bytes()
        );
        assert_eq!(&b"Origin"[..], resp.headers().get(header::VARY).unwrap().as_bytes());

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
                .finish()
                .create(fn_service(|req: WebRequest<DefaultError>| async move {
                    Ok::<_, std::convert::Infallible>(req.into_response(
                        HttpResponse::Ok().header(header::VARY, "Accept").finish(),
                    ))
                }))
                .into();
        let req = TestRequest::with_header("Origin", "https://www.example.com")
            .method(Method::OPTIONS)
            .to_srv_request();
        let resp = test::call_service(&cors, req).await;
        assert_eq!(
            &b"Accept, Origin"[..],
            resp.headers().get(header::VARY).unwrap().as_bytes()
        );

        let cors = Cors::new()
            .disable_vary_header()
            .allowed_origin("https://www.example.com")
            .allowed_origin("https://www.google.com")
            .finish()
            .create(test::ok_service())
            .into();

        let req = TestRequest::with_header("Origin", "https://www.example.com")
            .method(Method::OPTIONS)
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
            .to_srv_request();
        let resp = test::call_service(&cors, req).await;

        let origins_str =
            resp.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap().to_str().unwrap();

        assert_eq!("https://www.example.com", origins_str);
    }

    #[ntex::test]
    async fn test_multiple_origins() {
        let cors = Cors::new()
            .allowed_origin("https://example.com")
            .allowed_origin("https://example.org")
            .allowed_methods(vec![Method::GET])
            .finish()
            .create(test::ok_service())
            .into();

        let req = TestRequest::with_header("Origin", "https://example.com")
            .method(Method::GET)
            .to_srv_request();

        let resp = test::call_service(&cors, req).await;
        assert_eq!(
            &b"https://example.com"[..],
            resp.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap().as_bytes()
        );

        let req = TestRequest::with_header("Origin", "https://example.org")
            .method(Method::GET)
            .to_srv_request();

        let resp = test::call_service(&cors, req).await;
        assert_eq!(
            &b"https://example.org"[..],
            resp.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap().as_bytes()
        );
    }

    #[ntex::test]
    async fn test_multiple_origins_preflight() {
        let cors = Cors::new()
            .allowed_origin("https://example.com")
            .allowed_origin("https://example.org")
            .allowed_methods(vec![Method::GET])
            .finish()
            .create(test::ok_service())
            .into();

        let req = TestRequest::with_header("Origin", "https://example.com")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
            .method(Method::OPTIONS)
            .to_srv_request();

        let resp = test::call_service(&cors, req).await;
        assert_eq!(
            &b"https://example.com"[..],
            resp.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap().as_bytes()
        );

        let req = TestRequest::with_header("Origin", "https://example.org")
            .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
            .method(Method::OPTIONS)
            .to_srv_request();

        let resp = test::call_service(&cors, req).await;
        assert_eq!(
            &b"https://example.org"[..],
            resp.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap().as_bytes()
        );
    }
}
