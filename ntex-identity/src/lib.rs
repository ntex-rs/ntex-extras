//! Request identity service for ntex applications.
//!
//! [**IdentityService**](struct.IdentityService.html) middleware can be
//! used with different policies types to store identity information.
//!
//! By default, only cookie identity policy is implemented. Other backend
//! implementations can be added separately.
//!
//! [**CookieIdentityPolicy**](struct.CookieIdentityPolicy.html)
//! uses cookies as identity storage.
//!
//! To access current request identity
//! [**Identity**](struct.Identity.html) extractor should be used.
//!
//! ```rust
//! use ntex::web;
//! use ntex_identity::{Identity, CookieIdentityPolicy, IdentityService};
//!
//! async fn index(id: Identity) -> String {
//!     // access request identity
//!     if let Some(id) = id.identity() {
//!         format!("Welcome! {}", id)
//!     } else {
//!         "Welcome Anonymous!".to_owned()
//!     }
//! }
//!
//! async fn login(id: Identity) -> web::HttpResponse {
//!     id.remember("User1".to_owned()); // <- remember identity
//!     web::HttpResponse::Ok().finish()
//! }
//!
//! async fn logout(id: Identity) -> web::HttpResponse {
//!     id.forget();                      // <- remove identity
//!     web::HttpResponse::Ok().finish()
//! }
//!
//! let app = web::App::new().wrap(IdentityService::new(
//!     // <- create identity middleware
//!     CookieIdentityPolicy::new(&[0; 32])    // <- create cookie identity policy
//!           .name("auth-cookie")
//!           .secure(false)))
//!     .service(web::resource("/index.html").to(index))
//!     .service(web::resource("/login.html").to(login))
//!     .service(web::resource("/logout.html").to(logout));
//! ```
use std::convert::Infallible;
use std::future::Future;
use std::marker::PhantomData;
use std::rc::Rc;
use std::task::{Context, Poll};
use std::time::SystemTime;

use cookie::{Cookie, CookieJar, Key, SameSite};
use derive_more::{Display, From};
use futures::future::{ok, FutureExt, LocalBoxFuture, Ready};
use serde::{Deserialize, Serialize};
use time::Duration;

use ntex::http::error::HttpError;
use ntex::http::header::{self, HeaderValue};
use ntex::http::{HttpMessage, Payload};
use ntex::service::{Service, Transform};
use ntex::util::Extensions;
use ntex::web::dev::{WebRequest, WebResponse};
use ntex::web::{DefaultError, ErrorRenderer, FromRequest, HttpRequest, WebResponseError};

/// The extractor type to obtain your identity from a request.
///
/// ```rust
/// use ntex::web::{self, Error};
/// use ntex_identity::Identity;
///
/// fn index(id: Identity) -> Result<String, web::Error> {
///     // access request identity
///     if let Some(id) = id.identity() {
///         Ok(format!("Welcome! {}", id))
///     } else {
///         Ok("Welcome Anonymous!".to_owned())
///     }
/// }
///
/// fn login(id: Identity) -> web::HttpResponse {
///     id.remember("User1".to_owned()); // <- remember identity
///     web::HttpResponse::Ok().finish()
/// }
///
/// fn logout(id: Identity) -> web::HttpResponse {
///     id.forget(); // <- remove identity
///     web::HttpResponse::Ok().finish()
/// }
/// # fn main() {}
/// ```
#[derive(Clone)]
pub struct Identity(HttpRequest);

impl Identity {
    /// Return the claimed identity of the user associated request or
    /// ``None`` if no identity can be found associated with the request.
    pub fn identity(&self) -> Option<String> {
        Identity::get_identity(&self.0.extensions())
    }

    /// Remember identity.
    pub fn remember(&self, identity: String) {
        if let Some(id) = self.0.extensions_mut().get_mut::<IdentityItem>() {
            id.id = Some(identity);
            id.changed = true;
        }
    }

    /// This method is used to 'forget' the current identity on subsequent
    /// requests.
    pub fn forget(&self) {
        if let Some(id) = self.0.extensions_mut().get_mut::<IdentityItem>() {
            id.id = None;
            id.changed = true;
        }
    }

    fn get_identity(extensions: &Extensions) -> Option<String> {
        if let Some(id) = extensions.get::<IdentityItem>() {
            id.id.clone()
        } else {
            None
        }
    }
}

struct IdentityItem {
    id: Option<String>,
    changed: bool,
}

/// Helper trait that allows to get Identity.
///
/// It could be used in middleware but identity policy must be set before any other middleware that needs identity
/// RequestIdentity is implemented both for `ServiceRequest` and `HttpRequest`.
pub trait RequestIdentity {
    fn get_identity(&self) -> Option<String>;
}

impl<T> RequestIdentity for T
where
    T: HttpMessage,
{
    fn get_identity(&self) -> Option<String> {
        Identity::get_identity(&self.message_extensions())
    }
}

/// Extractor implementation for Identity type.
///
/// ```rust
/// use ntex_identity::Identity;
///
/// fn index(id: Identity) -> String {
///     // access request identity
///     if let Some(id) = id.identity() {
///         format!("Welcome! {}", id)
///     } else {
///         "Welcome Anonymous!".to_owned()
///     }
/// }
/// # fn main() {}
/// ```
impl<Err: ErrorRenderer> FromRequest<Err> for Identity {
    type Error = Infallible;
    type Future = Ready<Result<Identity, Infallible>>;

    #[inline]
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        ok(Identity(req.clone()))
    }
}

/// Identity policy definition.
pub trait IdentityPolicy<Err>: Sized + 'static {
    /// The return type of the middleware
    type Future: Future<Output = Result<Option<String>, Self::Error>>;

    /// The return type of the middleware
    type ResponseFuture: Future<Output = Result<(), Self::Error>>;

    /// The error type of the policy
    type Error;

    /// Parse the session from request and load data from a service identity.
    fn from_request(&self, request: &mut WebRequest<Err>) -> Self::Future;

    /// Write changes to response
    fn to_response(
        &self,
        identity: Option<String>,
        changed: bool,
        response: &mut WebResponse,
    ) -> Self::ResponseFuture;
}

/// Request identity middleware
///
/// ```rust
/// use ntex::web::App;
/// use ntex_identity::{CookieIdentityPolicy, IdentityService};
///
/// let app = App::new().wrap(IdentityService::new(
///     // <- create identity middleware
///     CookieIdentityPolicy::new(&[0; 32])    // <- create cookie session backend
///           .name("auth-cookie")
///           .secure(false),
/// ));
/// ```
pub struct IdentityService<T, Err> {
    backend: Rc<T>,
    _t: PhantomData<Err>,
}

impl<T, Err> IdentityService<T, Err> {
    /// Create new identity service with specified backend.
    pub fn new(backend: T) -> Self {
        IdentityService { backend: Rc::new(backend), _t: PhantomData }
    }
}

impl<S, T, Err> Transform<S> for IdentityService<T, Err>
where
    S: Service<Request = WebRequest<Err>, Response = WebResponse> + 'static,
    S::Future: 'static,
    T: IdentityPolicy<Err>,
    Err: ErrorRenderer,
    Err::Container: From<S::Error>,
    Err::Container: From<T::Error>,
{
    type Request = WebRequest<Err>;
    type Response = WebResponse;
    type Error = S::Error;
    type InitError = ();
    type Transform = IdentityServiceMiddleware<S, T, Err>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(IdentityServiceMiddleware {
            backend: self.backend.clone(),
            service: Rc::new(service),
            _t: PhantomData,
        })
    }
}

#[doc(hidden)]
pub struct IdentityServiceMiddleware<S, T, Err> {
    backend: Rc<T>,
    service: Rc<S>,
    _t: PhantomData<Err>,
}

impl<S, T, Err> Clone for IdentityServiceMiddleware<S, T, Err> {
    fn clone(&self) -> Self {
        Self { backend: self.backend.clone(), service: self.service.clone(), _t: PhantomData }
    }
}

impl<S, T, Err> Service for IdentityServiceMiddleware<S, T, Err>
where
    S: Service<Request = WebRequest<Err>, Response = WebResponse> + 'static,
    S::Future: 'static,
    T: IdentityPolicy<Err>,
    Err: ErrorRenderer,
    Err::Container: From<S::Error>,
    Err::Container: From<T::Error>,
{
    type Request = WebRequest<Err>;
    type Response = WebResponse;
    type Error = S::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn poll_shutdown(&self, cx: &mut Context, is_error: bool) -> Poll<()> {
        self.service.poll_shutdown(cx, is_error)
    }

    fn call(&self, mut req: WebRequest<Err>) -> Self::Future {
        let srv = self.service.clone();
        let backend = self.backend.clone();
        let fut = self.backend.from_request(&mut req);

        async move {
            match fut.await {
                Ok(id) => {
                    req.extensions_mut().insert(IdentityItem { id, changed: false });

                    // https://github.com/actix/actix-web/issues/1263
                    let fut = { srv.call(req) };
                    let mut res = fut.await?;
                    let id = res.request().extensions_mut().remove::<IdentityItem>();

                    if let Some(id) = id {
                        match backend.to_response(id.id, id.changed, &mut res).await {
                            Ok(_) => Ok(res),
                            Err(e) => Ok(WebResponse::error_response::<Err, _>(res, e)),
                        }
                    } else {
                        Ok(res)
                    }
                }
                Err(err) => Ok(req.error_response(err)),
            }
        }
        .boxed_local()
    }
}

struct CookieIdentityInner<Err> {
    key: Key,
    key_v2: Key,
    name: String,
    path: String,
    domain: Option<String>,
    secure: bool,
    max_age: Option<Duration>,
    same_site: Option<SameSite>,
    visit_deadline: Option<Duration>,
    login_deadline: Option<Duration>,
    _t: PhantomData<Err>,
}

#[derive(Deserialize, Serialize, Debug)]
struct CookieValue {
    identity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    login_timestamp: Option<SystemTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    visit_timestamp: Option<SystemTime>,
}

#[derive(Debug)]
struct CookieIdentityExtention {
    login_timestamp: Option<SystemTime>,
}

impl<Err: ErrorRenderer> CookieIdentityInner<Err> {
    fn new(key: &[u8]) -> CookieIdentityInner<Err> {
        let key_v2: Vec<u8> = key.iter().chain([1, 0, 0, 0].iter()).cloned().collect();
        CookieIdentityInner {
            key: Key::derive_from(key),
            key_v2: Key::derive_from(&key_v2),
            name: "ntex-identity".to_owned(),
            path: "/".to_owned(),
            domain: None,
            secure: true,
            max_age: None,
            same_site: None,
            visit_deadline: None,
            login_deadline: None,
            _t: PhantomData,
        }
    }

    fn set_cookie(
        &self,
        resp: &mut WebResponse,
        value: Option<CookieValue>,
    ) -> Result<(), CookieIdentityPolicyError> {
        let add_cookie = value.is_some();
        let val = value.map(|val| {
            if !self.legacy_supported() {
                serde_json::to_string(&val)
            } else {
                Ok(val.identity)
            }
        });
        let mut cookie =
            Cookie::new(self.name.clone(), val.unwrap_or_else(|| Ok(String::new()))?);
        cookie.set_path(self.path.clone());
        cookie.set_secure(self.secure);
        cookie.set_http_only(true);

        if let Some(ref domain) = self.domain {
            cookie.set_domain(domain.clone());
        }

        if let Some(max_age) = self.max_age {
            cookie.set_max_age(max_age);
        }

        if let Some(same_site) = self.same_site {
            cookie.set_same_site(same_site);
        }

        let mut jar = CookieJar::new();
        let key = if self.legacy_supported() { &self.key } else { &self.key_v2 };
        if add_cookie {
            jar.private(&key).add(cookie);
        } else {
            jar.add_original(cookie.clone());
            jar.private(&key).remove(cookie);
        }
        for cookie in jar.delta() {
            let val = HeaderValue::from_str(&cookie.to_string()).map_err(HttpError::from)?;
            resp.headers_mut().append(header::SET_COOKIE, val);
        }
        Ok(())
    }

    fn load(&self, req: &WebRequest<Err>) -> Option<CookieValue> {
        let cookie = req.cookie(&self.name)?;
        let mut jar = CookieJar::new();
        jar.add_original(cookie.clone());
        let res = if self.legacy_supported() {
            jar.private(&self.key).get(&self.name).map(|n| CookieValue {
                identity: n.value().to_string(),
                login_timestamp: None,
                visit_timestamp: None,
            })
        } else {
            None
        };
        res.or_else(|| jar.private(&self.key_v2).get(&self.name).and_then(|c| self.parse(c)))
    }

    fn parse(&self, cookie: Cookie) -> Option<CookieValue> {
        let value: CookieValue = serde_json::from_str(cookie.value()).ok()?;
        let now = SystemTime::now();
        if let Some(visit_deadline) = self.visit_deadline {
            if now.duration_since(value.visit_timestamp?).ok()? > visit_deadline {
                return None;
            }
        }
        if let Some(login_deadline) = self.login_deadline {
            if now.duration_since(value.login_timestamp?).ok()? > login_deadline {
                return None;
            }
        }
        Some(value)
    }

    fn legacy_supported(&self) -> bool {
        self.visit_deadline.is_none() && self.login_deadline.is_none()
    }

    fn always_update_cookie(&self) -> bool {
        self.visit_deadline.is_some()
    }

    fn requires_oob_data(&self) -> bool {
        self.login_deadline.is_some()
    }
}

/// Use cookies for request identity storage.
///
/// The constructors take a key as an argument.
/// This is the private key for cookie - when this value is changed,
/// all identities are lost. The constructors will panic if the key is less
/// than 32 bytes in length.
///
/// # Example
///
/// ```rust
/// use ntex::web::App;
/// use ntex_identity::{CookieIdentityPolicy, IdentityService};
///
/// let app = App::new().wrap(IdentityService::new(
///     // <- create identity middleware
///     CookieIdentityPolicy::new(&[0; 32])  // <- construct cookie policy
///            .domain("www.rust-lang.org")
///            .name("ntex-auth")
///            .path("/")
///            .secure(true),
/// ));
/// ```
pub struct CookieIdentityPolicy<Err>(Rc<CookieIdentityInner<Err>>);

#[derive(Debug, Display, From)]
pub enum CookieIdentityPolicyError {
    Http(HttpError),
    Json(serde_json::error::Error),
}

impl WebResponseError<DefaultError> for CookieIdentityPolicyError {}

impl<Err: ErrorRenderer> CookieIdentityPolicy<Err> {
    /// Construct new `CookieIdentityPolicy` instance.
    ///
    /// Panics if key length is less than 32 bytes.
    pub fn new(key: &[u8]) -> Self {
        CookieIdentityPolicy(Rc::new(CookieIdentityInner::new(key)))
    }

    /// Sets the `path` field in the session cookie being built.
    pub fn path<S: Into<String>>(mut self, value: S) -> Self {
        Rc::get_mut(&mut self.0).unwrap().path = value.into();
        self
    }

    /// Sets the `name` field in the session cookie being built.
    pub fn name<S: Into<String>>(mut self, value: S) -> Self {
        Rc::get_mut(&mut self.0).unwrap().name = value.into();
        self
    }

    /// Sets the `domain` field in the session cookie being built.
    pub fn domain<S: Into<String>>(mut self, value: S) -> Self {
        Rc::get_mut(&mut self.0).unwrap().domain = Some(value.into());
        self
    }

    /// Sets the `secure` field in the session cookie being built.
    ///
    /// If the `secure` field is set, a cookie will only be transmitted when the
    /// connection is secure - i.e. `https`
    pub fn secure(mut self, value: bool) -> Self {
        Rc::get_mut(&mut self.0).unwrap().secure = value;
        self
    }

    /// Sets the `max-age` field in the session cookie being built with given number of seconds.
    pub fn max_age(self, seconds: i64) -> Self {
        self.max_age_time(Duration::seconds(seconds))
    }

    /// Sets the `max-age` field in the session cookie being built with `chrono::Duration`.
    pub fn max_age_time(mut self, value: Duration) -> Self {
        Rc::get_mut(&mut self.0).unwrap().max_age = Some(value);
        self
    }

    /// Sets the `same_site` field in the session cookie being built.
    pub fn same_site(mut self, same_site: SameSite) -> Self {
        Rc::get_mut(&mut self.0).unwrap().same_site = Some(same_site);
        self
    }

    /// Accepts only users whose cookie has been seen before the given deadline
    ///
    /// By default visit deadline is disabled.
    pub fn visit_deadline(mut self, value: Duration) -> Self {
        Rc::get_mut(&mut self.0).unwrap().visit_deadline = Some(value);
        self
    }

    /// Accepts only users which has been authenticated before the given deadline
    ///
    /// By default login deadline is disabled.
    pub fn login_deadline(mut self, value: Duration) -> Self {
        Rc::get_mut(&mut self.0).unwrap().login_deadline = Some(value);
        self
    }
}

impl<Err: ErrorRenderer> IdentityPolicy<Err> for CookieIdentityPolicy<Err> {
    type Error = CookieIdentityPolicyError;
    type Future = Ready<Result<Option<String>, CookieIdentityPolicyError>>;
    type ResponseFuture = Ready<Result<(), CookieIdentityPolicyError>>;

    fn from_request(&self, req: &mut WebRequest<Err>) -> Self::Future {
        ok(self.0.load(req).map(|CookieValue { identity, login_timestamp, .. }| {
            if self.0.requires_oob_data() {
                req.extensions_mut().insert(CookieIdentityExtention { login_timestamp });
            }
            identity
        }))
    }

    fn to_response(
        &self,
        id: Option<String>,
        changed: bool,
        res: &mut WebResponse,
    ) -> Self::ResponseFuture {
        let _ = if changed {
            let login_timestamp = SystemTime::now();
            self.0.set_cookie(
                res,
                id.map(|identity| CookieValue {
                    identity,
                    login_timestamp: self.0.login_deadline.map(|_| login_timestamp),
                    visit_timestamp: self.0.visit_deadline.map(|_| login_timestamp),
                }),
            )
        } else if self.0.always_update_cookie() && id.is_some() {
            let visit_timestamp = SystemTime::now();
            let login_timestamp = if self.0.requires_oob_data() {
                let CookieIdentityExtention { login_timestamp: lt } =
                    res.request().extensions_mut().remove().unwrap();
                lt
            } else {
                None
            };
            self.0.set_cookie(
                res,
                Some(CookieValue {
                    identity: id.unwrap(),
                    login_timestamp,
                    visit_timestamp: self.0.visit_deadline.map(|_| visit_timestamp),
                }),
            )
        } else {
            Ok(())
        };
        ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Borrow;

    use super::*;
    use ntex::http::StatusCode;
    use ntex::service::into_service;
    use ntex::web::test::{self, TestRequest};
    use ntex::web::{self, error, App, Error, HttpResponse};

    const COOKIE_KEY_MASTER: [u8; 32] = [0; 32];
    const COOKIE_NAME: &'static str = "ntex_auth";
    const COOKIE_LOGIN: &'static str = "test";

    #[ntex::test]
    async fn test_identity() {
        let mut srv = test::init_service(
            App::new()
                .wrap(IdentityService::new(
                    CookieIdentityPolicy::new(&COOKIE_KEY_MASTER)
                        .domain("www.rust-lang.org")
                        .name(COOKIE_NAME)
                        .path("/")
                        .secure(true),
                ))
                .service(web::resource("/index").to(|id: Identity| async move {
                    if id.identity().is_some() {
                        HttpResponse::Created()
                    } else {
                        HttpResponse::Ok()
                    }
                }))
                .service(web::resource("/login").to(|id: Identity| async move {
                    id.remember(COOKIE_LOGIN.to_string());
                    HttpResponse::Ok()
                }))
                .service(web::resource("/logout").to(|id: Identity| async move {
                    if id.identity().is_some() {
                        id.forget();
                        HttpResponse::Ok()
                    } else {
                        HttpResponse::BadRequest()
                    }
                })),
        )
        .await;
        let resp =
            test::call_service(&mut srv, TestRequest::with_uri("/index").to_request()).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let resp =
            test::call_service(&mut srv, TestRequest::with_uri("/login").to_request()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let c = resp.response().cookies().next().unwrap().to_owned();

        let resp = test::call_service(
            &mut srv,
            TestRequest::with_uri("/index").cookie(c.clone()).to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp = test::call_service(
            &mut srv,
            TestRequest::with_uri("/logout").cookie(c.clone()).to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().contains_key(header::SET_COOKIE))
    }

    #[ntex::test]
    async fn test_identity_max_age_time() {
        let duration = Duration::days(1);
        let mut srv = test::init_service(
            App::new()
                .wrap(IdentityService::new(
                    CookieIdentityPolicy::new(&COOKIE_KEY_MASTER)
                        .domain("www.rust-lang.org")
                        .name(COOKIE_NAME)
                        .path("/")
                        .max_age_time(duration)
                        .secure(true),
                ))
                .service(web::resource("/login").to(|id: Identity| async move {
                    id.remember("test".to_string());
                    HttpResponse::Ok()
                })),
        )
        .await;
        let resp =
            test::call_service(&mut srv, TestRequest::with_uri("/login").to_request()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().contains_key(header::SET_COOKIE));
        let c = resp.response().cookies().next().unwrap().to_owned();
        assert_eq!(duration, c.max_age().unwrap());
    }

    #[ntex::test]
    async fn test_identity_max_age() {
        let seconds = 60;
        let mut srv = test::init_service(
            App::new()
                .wrap(IdentityService::new(
                    CookieIdentityPolicy::new(&COOKIE_KEY_MASTER)
                        .domain("www.rust-lang.org")
                        .name(COOKIE_NAME)
                        .path("/")
                        .max_age(seconds)
                        .secure(true),
                ))
                .service(web::resource("/login").to(|id: Identity| async move {
                    id.remember("test".to_string());
                    HttpResponse::Ok()
                })),
        )
        .await;
        let resp =
            test::call_service(&mut srv, TestRequest::with_uri("/login").to_request()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().contains_key(header::SET_COOKIE));
        let c = resp.response().cookies().next().unwrap().to_owned();
        assert_eq!(Duration::seconds(seconds as i64), c.max_age().unwrap());
    }

    async fn create_identity_server<
        F: Fn(CookieIdentityPolicy<DefaultError>) -> CookieIdentityPolicy<DefaultError>
            + Sync
            + Send
            + Clone
            + 'static,
    >(
        f: F,
    ) -> impl ntex::service::Service<
        Request = ntex::http::Request,
        Response = WebResponse,
        Error = Error,
    > {
        test::init_service(
            App::new()
                .wrap(IdentityService::new(f(CookieIdentityPolicy::new(&COOKIE_KEY_MASTER)
                    .secure(false)
                    .name(COOKIE_NAME))))
                .service(web::resource("/").to(|id: Identity| async move {
                    let identity = id.identity();
                    if identity.is_none() {
                        id.remember(COOKIE_LOGIN.to_string())
                    }
                    web::types::Json(identity)
                })),
        )
        .await
    }

    fn legacy_login_cookie(identity: &'static str) -> Cookie<'static> {
        let mut jar = CookieJar::new();
        jar.private(&Key::derive_from(&COOKIE_KEY_MASTER))
            .add(Cookie::new(COOKIE_NAME, identity));
        jar.get(COOKIE_NAME).unwrap().clone()
    }

    fn login_cookie(
        identity: &'static str,
        login_timestamp: Option<SystemTime>,
        visit_timestamp: Option<SystemTime>,
    ) -> Cookie<'static> {
        let mut jar = CookieJar::new();
        let key: Vec<u8> =
            COOKIE_KEY_MASTER.iter().chain([1, 0, 0, 0].iter()).map(|e| *e).collect();
        jar.private(&Key::derive_from(&key)).add(Cookie::new(
            COOKIE_NAME,
            serde_json::to_string(&CookieValue {
                identity: identity.to_string(),
                login_timestamp,
                visit_timestamp,
            })
            .unwrap(),
        ));
        jar.get(COOKIE_NAME).unwrap().clone()
    }

    async fn assert_logged_in(response: WebResponse, identity: Option<&str>) {
        let bytes = test::read_body(response).await;
        let resp: Option<String> = serde_json::from_slice(&bytes[..]).unwrap();
        assert_eq!(resp.as_ref().map(|s| s.borrow()), identity);
    }

    fn assert_legacy_login_cookie(response: &mut WebResponse, identity: &str) {
        let mut cookies = CookieJar::new();
        for cookie in response.headers().get_all(header::SET_COOKIE) {
            cookies.add(Cookie::parse(cookie.to_str().unwrap().to_string()).unwrap());
        }
        let cookie =
            cookies.private(&Key::derive_from(&COOKIE_KEY_MASTER)).get(COOKIE_NAME).unwrap();
        assert_eq!(cookie.value(), identity);
    }

    enum LoginTimestampCheck {
        NoTimestamp,
        NewTimestamp,
        OldTimestamp(SystemTime),
    }

    enum VisitTimeStampCheck {
        NoTimestamp,
        NewTimestamp,
    }

    fn assert_login_cookie(
        response: &mut WebResponse,
        identity: &str,
        login_timestamp: LoginTimestampCheck,
        visit_timestamp: VisitTimeStampCheck,
    ) {
        let mut cookies = CookieJar::new();
        for cookie in response.headers().get_all(header::SET_COOKIE) {
            cookies.add(Cookie::parse(cookie.to_str().unwrap().to_string()).unwrap());
        }
        let key: Vec<u8> =
            COOKIE_KEY_MASTER.iter().chain([1, 0, 0, 0].iter()).map(|e| *e).collect();
        let cookie = cookies.private(&Key::derive_from(&key)).get(COOKIE_NAME).unwrap();
        let cv: CookieValue = serde_json::from_str(cookie.value()).unwrap();
        assert_eq!(cv.identity, identity);
        let now = SystemTime::now();
        let t30sec_ago = now - Duration::seconds(30);
        match login_timestamp {
            LoginTimestampCheck::NoTimestamp => assert_eq!(cv.login_timestamp, None),
            LoginTimestampCheck::NewTimestamp => assert!(
                t30sec_ago <= cv.login_timestamp.unwrap() && cv.login_timestamp.unwrap() <= now
            ),
            LoginTimestampCheck::OldTimestamp(old_timestamp) => {
                assert_eq!(cv.login_timestamp, Some(old_timestamp))
            }
        }
        match visit_timestamp {
            VisitTimeStampCheck::NoTimestamp => assert_eq!(cv.visit_timestamp, None),
            VisitTimeStampCheck::NewTimestamp => assert!(
                t30sec_ago <= cv.visit_timestamp.unwrap() && cv.visit_timestamp.unwrap() <= now
            ),
        }
    }

    fn assert_no_login_cookie(response: &mut WebResponse) {
        let mut cookies = CookieJar::new();
        for cookie in response.headers().get_all(header::SET_COOKIE) {
            cookies.add(Cookie::parse(cookie.to_str().unwrap().to_string()).unwrap());
        }
        assert!(cookies.get(COOKIE_NAME).is_none());
    }

    #[ntex::test]
    async fn test_identity_legacy_cookie_is_set() {
        let mut srv = create_identity_server(|c| c).await;
        let mut resp =
            test::call_service(&mut srv, TestRequest::with_uri("/").to_request()).await;
        assert_legacy_login_cookie(&mut resp, COOKIE_LOGIN);
        assert_logged_in(resp, None).await;
    }

    #[ntex::test]
    async fn test_identity_legacy_cookie_works() {
        let mut srv = create_identity_server(|c| c).await;
        let cookie = legacy_login_cookie(COOKIE_LOGIN);
        let mut resp = test::call_service(
            &mut srv,
            TestRequest::with_uri("/").cookie(cookie.clone()).to_request(),
        )
        .await;
        assert_no_login_cookie(&mut resp);
        assert_logged_in(resp, Some(COOKIE_LOGIN)).await;
    }

    #[ntex::test]
    async fn test_identity_legacy_cookie_rejected_if_visit_timestamp_needed() {
        let mut srv = create_identity_server(|c| c.visit_deadline(Duration::days(90))).await;
        let cookie = legacy_login_cookie(COOKIE_LOGIN);
        let mut resp = test::call_service(
            &mut srv,
            TestRequest::with_uri("/").cookie(cookie.clone()).to_request(),
        )
        .await;
        assert_login_cookie(
            &mut resp,
            COOKIE_LOGIN,
            LoginTimestampCheck::NoTimestamp,
            VisitTimeStampCheck::NewTimestamp,
        );
        assert_logged_in(resp, None).await;
    }

    #[ntex::test]
    async fn test_identity_legacy_cookie_rejected_if_login_timestamp_needed() {
        let mut srv = create_identity_server(|c| c.login_deadline(Duration::days(90))).await;
        let cookie = legacy_login_cookie(COOKIE_LOGIN);
        let mut resp = test::call_service(
            &mut srv,
            TestRequest::with_uri("/").cookie(cookie.clone()).to_request(),
        )
        .await;
        assert_login_cookie(
            &mut resp,
            COOKIE_LOGIN,
            LoginTimestampCheck::NewTimestamp,
            VisitTimeStampCheck::NoTimestamp,
        );
        assert_logged_in(resp, None).await;
    }

    #[ntex::test]
    async fn test_identity_cookie_rejected_if_login_timestamp_needed() {
        let mut srv = create_identity_server(|c| c.login_deadline(Duration::days(90))).await;
        let cookie = login_cookie(COOKIE_LOGIN, None, Some(SystemTime::now()));
        let mut resp = test::call_service(
            &mut srv,
            TestRequest::with_uri("/").cookie(cookie.clone()).to_request(),
        )
        .await;
        assert_login_cookie(
            &mut resp,
            COOKIE_LOGIN,
            LoginTimestampCheck::NewTimestamp,
            VisitTimeStampCheck::NoTimestamp,
        );
        assert_logged_in(resp, None).await;
    }

    #[ntex::test]
    async fn test_identity_cookie_rejected_if_visit_timestamp_needed() {
        let mut srv = create_identity_server(|c| c.visit_deadline(Duration::days(90))).await;
        let cookie = login_cookie(COOKIE_LOGIN, Some(SystemTime::now()), None);
        let mut resp = test::call_service(
            &mut srv,
            TestRequest::with_uri("/").cookie(cookie.clone()).to_request(),
        )
        .await;
        assert_login_cookie(
            &mut resp,
            COOKIE_LOGIN,
            LoginTimestampCheck::NoTimestamp,
            VisitTimeStampCheck::NewTimestamp,
        );
        assert_logged_in(resp, None).await;
    }

    #[ntex::test]
    async fn test_identity_cookie_rejected_if_login_timestamp_too_old() {
        let mut srv = create_identity_server(|c| c.login_deadline(Duration::days(90))).await;
        let cookie =
            login_cookie(COOKIE_LOGIN, Some(SystemTime::now() - Duration::days(180)), None);
        let mut resp = test::call_service(
            &mut srv,
            TestRequest::with_uri("/").cookie(cookie.clone()).to_request(),
        )
        .await;
        assert_login_cookie(
            &mut resp,
            COOKIE_LOGIN,
            LoginTimestampCheck::NewTimestamp,
            VisitTimeStampCheck::NoTimestamp,
        );
        assert_logged_in(resp, None).await;
    }

    #[ntex::test]
    async fn test_identity_cookie_rejected_if_visit_timestamp_too_old() {
        let mut srv = create_identity_server(|c| c.visit_deadline(Duration::days(90))).await;
        let cookie =
            login_cookie(COOKIE_LOGIN, None, Some(SystemTime::now() - Duration::days(180)));
        let mut resp = test::call_service(
            &mut srv,
            TestRequest::with_uri("/").cookie(cookie.clone()).to_request(),
        )
        .await;
        assert_login_cookie(
            &mut resp,
            COOKIE_LOGIN,
            LoginTimestampCheck::NoTimestamp,
            VisitTimeStampCheck::NewTimestamp,
        );
        assert_logged_in(resp, None).await;
    }

    #[ntex::test]
    async fn test_identity_cookie_not_updated_on_login_deadline() {
        let mut srv = create_identity_server(|c| c.login_deadline(Duration::days(90))).await;
        let cookie = login_cookie(COOKIE_LOGIN, Some(SystemTime::now()), None);
        let mut resp = test::call_service(
            &mut srv,
            TestRequest::with_uri("/").cookie(cookie.clone()).to_request(),
        )
        .await;
        assert_no_login_cookie(&mut resp);
        assert_logged_in(resp, Some(COOKIE_LOGIN)).await;
    }

    // https://github.com/actix/actix-web/issues/1263
    #[ntex::test]
    async fn test_identity_cookie_updated_on_visit_deadline() {
        let mut srv = create_identity_server(|c| {
            c.visit_deadline(Duration::days(90)).login_deadline(Duration::days(90))
        })
        .await;
        let timestamp = SystemTime::now() - Duration::days(1);
        let cookie = login_cookie(COOKIE_LOGIN, Some(timestamp), Some(timestamp));
        let mut resp = test::call_service(
            &mut srv,
            TestRequest::with_uri("/").cookie(cookie.clone()).to_request(),
        )
        .await;
        assert_login_cookie(
            &mut resp,
            COOKIE_LOGIN,
            LoginTimestampCheck::OldTimestamp(timestamp),
            VisitTimeStampCheck::NewTimestamp,
        );
        assert_logged_in(resp, Some(COOKIE_LOGIN)).await;
    }

    #[ntex::test]
    async fn test_borrowed_mut_error() {
        use futures::future::{lazy, ok, Ready};
        use ntex::web::{DefaultError, Error};

        struct Ident;
        impl<Err: ErrorRenderer> IdentityPolicy<Err> for Ident {
            type Error = Error;
            type Future = Ready<Result<Option<String>, Error>>;
            type ResponseFuture = Ready<Result<(), Error>>;

            fn from_request(&self, _: &mut WebRequest<Err>) -> Self::Future {
                ok(Some("test".to_string()))
            }

            fn to_response(
                &self,
                _: Option<String>,
                _: bool,
                _: &mut WebResponse,
            ) -> Self::ResponseFuture {
                ok(())
            }
        }

        let srv = IdentityServiceMiddleware {
            backend: Rc::new(Ident),
            service: Rc::new(into_service(|_: WebRequest<DefaultError>| async move {
                ntex::rt::time::delay_for(std::time::Duration::from_secs(100)).await;
                Err::<WebResponse, _>(error::ErrorBadRequest("error"))
            })),
            _t: PhantomData,
        };

        let srv2 = srv.clone();
        let req = TestRequest::default().to_srv_request();
        ntex::rt::spawn(async move {
            let _ = srv2.call(req).await;
        });
        ntex::rt::time::delay_for(std::time::Duration::from_millis(50)).await;

        let _ = lazy(|cx| srv.poll_ready(cx)).await;
    }
}
