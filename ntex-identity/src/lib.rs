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
//!     web::HttpResponse::Ok().build()
//! }
//!
//! async fn logout(id: Identity) -> web::HttpResponse {
//!     id.forget();                      // <- remove identity
//!     web::HttpResponse::Ok().build()
//! }
//!
//! let app = web::App::default().middleware(IdentityService::new(
//!     // <- create identity middleware
//!     CookieIdentityPolicy::new(&[0; 32])    // <- create cookie identity policy
//!           .name("auth-cookie")
//!           .secure(false)))
//!     .service(web::resource("/index.html").to(index))
//!     .service(web::resource("/login.html").to(login))
//!     .service(web::resource("/logout.html").to(logout));
//! ```
#![allow(async_fn_in_trait)]
use std::{convert::Infallible, rc::Rc, time::SystemTime};

use cookie::{Cookie, CookieJar, Key, SameSite};
use serde::{Deserialize, Serialize};
use time::Duration;

use ntex::http::header::{self, HeaderValue};
use ntex::http::{HttpMessage, Payload, error::HttpError};
use ntex::service::{BindCtx, Ctx, Middleware, Service};
use ntex::util::Extensions;
use ntex::web::{
    DefaultError, FromRequest, HttpRequest, State, WebRequest, WebResponse, WebResponseError,
};

/// Browsers drop cookies whose `name=value` pair is larger than this.
const MAX_COOKIE_SIZE: usize = 4096;

/// The extractor type to obtain your identity from a request.
///
/// ```rust
/// use std::convert::Infallible;
/// use ntex::web;
/// use ntex_identity::Identity;
///
/// fn index(id: Identity) -> Result<String, Infallible> {
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
///     web::HttpResponse::Ok().build()
/// }
///
/// fn logout(id: Identity) -> web::HttpResponse {
///     id.forget(); // <- remove identity
///     web::HttpResponse::Ok().build()
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
impl<St: State> FromRequest<St> for Identity {
    type Error = Infallible;

    #[inline]
    async fn from_request(
        _: &St,
        req: &HttpRequest,
        _: &mut Payload,
    ) -> Result<Identity, Infallible> {
        Ok(Identity(req.clone()))
    }
}

#[allow(clippy::wrong_self_convention)]
/// Identity policy definition.
pub trait IdentityPolicy<St, In>: Sized + 'static {
    /// The error type of the policy
    type Error;

    /// Parse the session from request and load data from a service identity.
    async fn from_request(
        &self,
        st: &St,
        request: &mut WebRequest<In>,
    ) -> Result<Option<String>, Self::Error>;

    /// Write changes to response
    async fn to_response(
        &self,
        st: &St,
        identity: Option<String>,
        changed: bool,
        response: &mut WebResponse,
    ) -> Result<(), Self::Error>;
}

/// Request identity middleware
///
/// ```rust
/// use ntex::web::App;
/// use ntex_identity::{CookieIdentityPolicy, IdentityService};
///
/// let app = App::default().middleware(IdentityService::new(
///     // <- create identity middleware
///     CookieIdentityPolicy::new(&[0; 32])    // <- create cookie session backend
///           .name("auth-cookie")
///           .secure(false),
/// ));
/// ```
pub struct IdentityService<T> {
    backend: Rc<T>,
}

impl<T> IdentityService<T> {
    /// Create new identity service with specified backend.
    pub fn new(backend: T) -> Self {
        IdentityService {
            backend: Rc::new(backend),
        }
    }
}

impl<S, St, T> Middleware<S, St> for IdentityService<T> {
    type Service = IdentityServiceMiddleware<S, T>;

    fn create(&self, _: &St, service: S) -> Self::Service {
        IdentityServiceMiddleware {
            service,
            backend: self.backend.clone(),
        }
    }
}

#[doc(hidden)]
pub struct IdentityServiceMiddleware<S, T> {
    backend: Rc<T>,
    service: S,
}

impl<S: Clone, T> Clone for IdentityServiceMiddleware<S, T> {
    fn clone(&self) -> Self {
        Self {
            backend: self.backend.clone(),
            service: self.service.clone(),
        }
    }
}

impl<S, St, In, T> Service<St, WebRequest<In>> for IdentityServiceMiddleware<S, T>
where
    S: Service<St, WebRequest<In>, Res = WebResponse> + 'static,
    St: State,
    T: IdentityPolicy<St, In>,
    T::Error: WebResponseError<St, St::Error>,
    S::Error: WebResponseError<St, St::Error>,
{
    type Res = WebResponse;
    type Error = S::Error;

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

    async fn call(
        &self,
        mut req: WebRequest<In>,
        ctx: Ctx<'_, Self, St>,
    ) -> Result<Self::Res, Self::Error> {
        match self.backend.from_request(ctx.st(), &mut req).await {
            Ok(id) => {
                req.extensions_mut()
                    .insert(IdentityItem { id, changed: false });

                // https://github.com/actix/actix-web/issues/1263
                let mut res = ctx.call(&self.service, req).await?;
                let id = res.request().extensions_mut().remove::<IdentityItem>();

                if let Some(id) = id {
                    match self
                        .backend
                        .to_response(ctx.st(), id.id, id.changed, &mut res)
                        .await
                    {
                        Ok(_) => Ok(res),
                        Err(e) => Ok(WebResponse::error_response(res, ctx.st(), &e)),
                    }
                } else {
                    Ok(res)
                }
            }
            Err(err) => Ok(req.error_response(ctx.st(), &err)),
        }
    }
}

struct CookieIdentityInner {
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

impl CookieIdentityInner {
    fn new(key: &[u8]) -> CookieIdentityInner {
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
        let mut cookie = Cookie::new(self.name.clone(), val.unwrap_or_else(|| Ok(String::new()))?);
        cookie.set_path(self.path.clone());
        cookie.set_secure(self.secure);
        cookie.set_http_only(true);
        cookie.set_max_age(self.max_age);

        if let Some(ref domain) = self.domain {
            cookie.set_domain(domain.clone());
        }

        if let Some(same_site) = self.same_site {
            cookie.set_same_site(same_site);
        }

        let mut jar = CookieJar::new();
        let key = if self.legacy_supported() {
            &self.key
        } else {
            &self.key_v2
        };
        if add_cookie {
            jar.private_mut(key).add(cookie);
        } else {
            jar.add_original(cookie.clone());
            jar.private_mut(key).remove(cookie);
        }
        for cookie in jar.delta() {
            let val = cookie.to_string();
            if val.split(';').next().map_or(0, str::len) > MAX_COOKIE_SIZE {
                return Err(CookieIdentityPolicyError::Overflow);
            }
            let val = HeaderValue::from_str(&val).map_err(HttpError::from)?;
            resp.headers_mut().append(header::SET_COOKIE, val);
        }
        Ok(())
    }

    fn load<In>(&self, req: &WebRequest<In>) -> Option<CookieValue> {
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
        res.or_else(|| {
            jar.private(&self.key_v2)
                .get(&self.name)
                .and_then(|c| self.parse(c))
        })
    }

    fn parse(&self, cookie: Cookie) -> Option<CookieValue> {
        let value: CookieValue = serde_json::from_str(cookie.value()).ok()?;
        let now = SystemTime::now();
        if let Some(visit_deadline) = self.visit_deadline
            && now.duration_since(value.visit_timestamp?).ok()? > visit_deadline
        {
            return None;
        }
        if let Some(login_deadline) = self.login_deadline
            && now.duration_since(value.login_timestamp?).ok()? > login_deadline
        {
            return None;
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
/// let app = App::default().middleware(IdentityService::new(
///     // <- create identity middleware
///     CookieIdentityPolicy::new(&[0; 32])  // <- construct cookie policy
///            .domain("www.rust-lang.org")
///            .name("ntex-auth")
///            .path("/")
///            .secure(true),
/// ));
/// ```
pub struct CookieIdentityPolicy(Rc<CookieIdentityInner>);

#[derive(Debug, thiserror::Error)]
pub enum CookieIdentityPolicyError {
    #[error("Http error {0}")]
    Http(#[from] HttpError),
    #[error("Json error {0}")]
    Json(#[from] serde_json::error::Error),
    #[error("Size of the identity cookie is greater than 4096 bytes")]
    Overflow,
}

impl<St> WebResponseError<St, DefaultError> for CookieIdentityPolicyError {}

impl CookieIdentityPolicy {
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

impl<St, In> IdentityPolicy<St, In> for CookieIdentityPolicy {
    type Error = CookieIdentityPolicyError;

    async fn from_request(
        &self,
        _: &St,
        req: &mut WebRequest<In>,
    ) -> Result<Option<String>, Self::Error> {
        Ok(self.0.load(req).map(
            |CookieValue {
                 identity,
                 login_timestamp,
                 ..
             }| {
                if self.0.requires_oob_data() {
                    req.extensions_mut()
                        .insert(CookieIdentityExtention { login_timestamp });
                }
                identity
            },
        ))
    }

    async fn to_response(
        &self,
        _: &St,
        id: Option<String>,
        changed: bool,
        res: &mut WebResponse,
    ) -> Result<(), Self::Error> {
        if changed {
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
                let CookieIdentityExtention {
                    login_timestamp: lt,
                } = res.request().extensions_mut().remove().unwrap();
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
        }
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Borrow;

    use super::*;
    use ntex::web::test::{self, TestRequest};
    use ntex::web::{self, App, HttpResponse, WebError, error};
    use ntex::{Pipeline, fn_service, http::Request, http::StatusCode};

    const COOKIE_KEY_MASTER: [u8; 32] = [0; 32];
    const COOKIE_NAME: &str = "ntex_auth";
    const COOKIE_LOGIN: &str = "test";

    /// STATEMENT: Identity login and logout update authentication, while anonymous logout is rejected.
    ///
    /// HOW:
    /// - Request the index anonymously and assert `200`; request logout anonymously and assert `400` without a cookie.
    /// - Log in, replay the returned cookie and assert the index returns `201`.
    /// - Log out, replay the removal cookie and assert the index returns `200` without reissuing an identity.
    #[ntex::test]
    async fn test_identity() {
        let srv = test::init_service(
            App::new()
                .middleware(IdentityService::new(
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
                }))
                .build(),
        )
        .await;

        let resp = test::call_service(&srv, TestRequest::with_uri("/index").to_request()).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = test::call_service(&srv, TestRequest::with_uri("/logout").to_request()).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(!resp.headers().contains_key(header::SET_COOKIE));

        let resp = test::call_service(&srv, TestRequest::with_uri("/login").to_request()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let c = resp.cookies().next().unwrap().into_owned();

        let resp = test::call_service(
            &srv,
            TestRequest::with_uri("/index")
                .cookie(c.clone())
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp = test::call_service(
            &srv,
            TestRequest::with_uri("/logout")
                .cookie(c.clone())
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().contains_key(header::SET_COOKIE));
        let deleted = resp.cookies().next().unwrap().into_owned();
        let resp = srv
            .call(TestRequest::with_uri("/index").cookie(deleted).to_request())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(!resp.headers().contains_key(header::SET_COOKIE));
    }

    #[ntex::test]
    async fn test_identity_max_age_time() {
        let duration = Duration::days(1);
        let srv = test::init_service(
            App::new()
                .middleware(IdentityService::new(
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
        let resp = test::call_service(&srv, TestRequest::with_uri("/login").to_request()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().contains_key(header::SET_COOKIE));
        let c = resp.cookies().next().unwrap().to_owned();
        assert_eq!(duration, c.max_age().unwrap());
    }

    #[ntex::test]
    async fn test_identity_max_age() {
        let seconds = 60;
        let srv = test::init_service(
            App::new()
                .middleware(IdentityService::new(
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
        let resp = test::call_service(&srv, TestRequest::with_uri("/login").to_request()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().contains_key(header::SET_COOKIE));
        let c = resp.cookies().next().unwrap().to_owned();
        assert_eq!(Duration::seconds(seconds), c.max_age().unwrap());
    }

    async fn create_identity_server<
        F: Fn(CookieIdentityPolicy) -> CookieIdentityPolicy + Sync + Send + Clone + 'static,
    >(
        f: F,
    ) -> Pipeline<Request, HttpResponse, WebError<(), DefaultError>> {
        test::init_service(
            App::new()
                .middleware(IdentityService::new(f(CookieIdentityPolicy::new(
                    &COOKIE_KEY_MASTER,
                )
                .secure(false)
                .name(COOKIE_NAME))))
                .service(web::resource("/").to(|id: Identity| async move {
                    let identity = id.identity();
                    if identity.is_none() {
                        id.remember(COOKIE_LOGIN.to_string())
                    }
                    web::types::Json(identity)
                }))
                .build(),
        )
        .await
    }

    fn legacy_login_cookie(identity: &'static str) -> Cookie<'static> {
        let mut jar = CookieJar::new();
        jar.private_mut(&Key::derive_from(&COOKIE_KEY_MASTER))
            .add(Cookie::new(COOKIE_NAME, identity));
        jar.get(COOKIE_NAME).unwrap().clone()
    }

    fn login_cookie(
        identity: &'static str,
        login_timestamp: Option<SystemTime>,
        visit_timestamp: Option<SystemTime>,
    ) -> Cookie<'static> {
        let mut jar = CookieJar::new();
        let key: Vec<u8> = COOKIE_KEY_MASTER
            .iter()
            .chain([1, 0, 0, 0].iter())
            .copied()
            .collect();
        jar.private_mut(&Key::derive_from(&key)).add(Cookie::new(
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

    async fn assert_logged_in(response: HttpResponse, identity: Option<&str>) {
        let bytes = test::read_body(response).await;
        let resp: Option<String> = serde_json::from_slice(&bytes[..]).unwrap();
        assert_eq!(resp.as_ref().map(|s| s.borrow()), identity);
    }

    fn assert_legacy_login_cookie(response: &mut HttpResponse, identity: &str) {
        let mut cookies = CookieJar::new();
        for cookie in response.headers().get_all(header::SET_COOKIE) {
            cookies.add(Cookie::parse(cookie.to_str().unwrap().to_string()).unwrap());
        }
        let cookie = cookies
            .private(&Key::derive_from(&COOKIE_KEY_MASTER))
            .get(COOKIE_NAME)
            .unwrap();
        assert_eq!(cookie.value(), identity);
    }

    enum LoginTimestampCheck {
        Incorrect,
        New,
        Old(SystemTime),
    }

    enum VisitTimeStampCheck {
        NoTimestamp,
        NewTimestamp,
    }

    fn assert_login_cookie(
        response: &mut HttpResponse,
        identity: &str,
        login_timestamp: LoginTimestampCheck,
        visit_timestamp: VisitTimeStampCheck,
    ) {
        let mut cookies = CookieJar::new();
        for cookie in response.headers().get_all(header::SET_COOKIE) {
            cookies.add(Cookie::parse(cookie.to_str().unwrap().to_string()).unwrap());
        }
        let key: Vec<u8> = COOKIE_KEY_MASTER
            .iter()
            .chain([1, 0, 0, 0].iter())
            .copied()
            .collect();
        let cookie = cookies
            .private(&Key::derive_from(&key))
            .get(COOKIE_NAME)
            .unwrap();
        let cv: CookieValue = serde_json::from_str(cookie.value()).unwrap();
        assert_eq!(cv.identity, identity);
        let now = SystemTime::now();
        let t30sec_ago = now - Duration::seconds(30);
        match login_timestamp {
            LoginTimestampCheck::Incorrect => assert_eq!(cv.login_timestamp, None),
            LoginTimestampCheck::New => assert!(
                t30sec_ago <= cv.login_timestamp.unwrap() && cv.login_timestamp.unwrap() <= now
            ),
            LoginTimestampCheck::Old(old_timestamp) => {
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

    fn assert_no_login_cookie(response: &mut HttpResponse) {
        let mut cookies = CookieJar::new();
        for cookie in response.headers().get_all(header::SET_COOKIE) {
            cookies.add(Cookie::parse(cookie.to_str().unwrap().to_string()).unwrap());
        }
        assert!(cookies.get(COOKIE_NAME).is_none());
    }

    #[ntex::test]
    async fn test_identity_legacy_cookie_is_set() {
        let srv = create_identity_server(|c| c).await;
        let mut resp = test::call_service(&srv, TestRequest::with_uri("/").to_request()).await;
        assert_legacy_login_cookie(&mut resp, COOKIE_LOGIN);
        assert_logged_in(resp, None).await;
    }

    #[ntex::test]
    async fn test_identity_legacy_cookie_works() {
        let srv = create_identity_server(|c| c).await;
        let cookie = legacy_login_cookie(COOKIE_LOGIN);
        let mut resp = test::call_service(
            &srv,
            TestRequest::with_uri("/")
                .cookie(cookie.clone())
                .to_request(),
        )
        .await;
        assert_no_login_cookie(&mut resp);
        assert_logged_in(resp, Some(COOKIE_LOGIN)).await;
    }

    #[ntex::test]
    async fn test_identity_legacy_cookie_rejected_if_visit_timestamp_needed() {
        let srv = create_identity_server(|c| c.visit_deadline(Duration::days(90))).await;
        let cookie = legacy_login_cookie(COOKIE_LOGIN);
        let mut resp = test::call_service(
            &srv,
            TestRequest::with_uri("/")
                .cookie(cookie.clone())
                .to_request(),
        )
        .await;
        assert_login_cookie(
            &mut resp,
            COOKIE_LOGIN,
            LoginTimestampCheck::Incorrect,
            VisitTimeStampCheck::NewTimestamp,
        );
        assert_logged_in(resp, None).await;
    }

    #[ntex::test]
    async fn test_identity_legacy_cookie_rejected_if_login_timestamp_needed() {
        let srv = create_identity_server(|c| c.login_deadline(Duration::days(90))).await;
        let cookie = legacy_login_cookie(COOKIE_LOGIN);
        let mut resp = test::call_service(
            &srv,
            TestRequest::with_uri("/")
                .cookie(cookie.clone())
                .to_request(),
        )
        .await;
        assert_login_cookie(
            &mut resp,
            COOKIE_LOGIN,
            LoginTimestampCheck::New,
            VisitTimeStampCheck::NoTimestamp,
        );
        assert_logged_in(resp, None).await;
    }

    #[ntex::test]
    async fn test_identity_cookie_rejected_if_login_timestamp_needed() {
        let srv = create_identity_server(|c| c.login_deadline(Duration::days(90))).await;
        let cookie = login_cookie(COOKIE_LOGIN, None, Some(SystemTime::now()));
        let mut resp = test::call_service(
            &srv,
            TestRequest::with_uri("/")
                .cookie(cookie.clone())
                .to_request(),
        )
        .await;
        assert_login_cookie(
            &mut resp,
            COOKIE_LOGIN,
            LoginTimestampCheck::New,
            VisitTimeStampCheck::NoTimestamp,
        );
        assert_logged_in(resp, None).await;
    }

    #[ntex::test]
    async fn test_identity_cookie_rejected_if_visit_timestamp_needed() {
        let srv = create_identity_server(|c| c.visit_deadline(Duration::days(90))).await;
        let cookie = login_cookie(COOKIE_LOGIN, Some(SystemTime::now()), None);
        let mut resp = test::call_service(
            &srv,
            TestRequest::with_uri("/")
                .cookie(cookie.clone())
                .to_request(),
        )
        .await;
        assert_login_cookie(
            &mut resp,
            COOKIE_LOGIN,
            LoginTimestampCheck::Incorrect,
            VisitTimeStampCheck::NewTimestamp,
        );
        assert_logged_in(resp, None).await;
    }

    #[ntex::test]
    async fn test_identity_cookie_rejected_if_login_timestamp_too_old() {
        let srv = create_identity_server(|c| c.login_deadline(Duration::days(90))).await;
        let cookie = login_cookie(
            COOKIE_LOGIN,
            Some(SystemTime::now() - Duration::days(180)),
            None,
        );
        let mut resp = test::call_service(
            &srv,
            TestRequest::with_uri("/")
                .cookie(cookie.clone())
                .to_request(),
        )
        .await;
        assert_login_cookie(
            &mut resp,
            COOKIE_LOGIN,
            LoginTimestampCheck::New,
            VisitTimeStampCheck::NoTimestamp,
        );
        assert_logged_in(resp, None).await;
    }

    #[ntex::test]
    async fn test_identity_cookie_rejected_if_visit_timestamp_too_old() {
        let srv = create_identity_server(|c| c.visit_deadline(Duration::days(90))).await;
        let cookie = login_cookie(
            COOKIE_LOGIN,
            None,
            Some(SystemTime::now() - Duration::days(180)),
        );
        let mut resp = test::call_service(
            &srv,
            TestRequest::with_uri("/")
                .cookie(cookie.clone())
                .to_request(),
        )
        .await;
        assert_login_cookie(
            &mut resp,
            COOKIE_LOGIN,
            LoginTimestampCheck::Incorrect,
            VisitTimeStampCheck::NewTimestamp,
        );
        assert_logged_in(resp, None).await;
    }

    #[ntex::test]
    async fn test_identity_cookie_not_updated_on_login_deadline() {
        let srv = create_identity_server(|c| c.login_deadline(Duration::days(90))).await;
        let cookie = login_cookie(COOKIE_LOGIN, Some(SystemTime::now()), None);
        let mut resp = test::call_service(
            &srv,
            TestRequest::with_uri("/")
                .cookie(cookie.clone())
                .to_request(),
        )
        .await;
        assert_no_login_cookie(&mut resp);
        assert_logged_in(resp, Some(COOKIE_LOGIN)).await;
    }

    // https://github.com/actix/actix-web/issues/1263
    #[ntex::test]
    async fn test_identity_cookie_updated_on_visit_deadline() {
        let srv = create_identity_server(|c| {
            c.visit_deadline(Duration::days(90))
                .login_deadline(Duration::days(90))
        })
        .await;
        let timestamp = SystemTime::now() - Duration::days(1);
        let cookie = login_cookie(COOKIE_LOGIN, Some(timestamp), Some(timestamp));
        let mut resp = test::call_service(
            &srv,
            TestRequest::with_uri("/")
                .cookie(cookie.clone())
                .to_request(),
        )
        .await;
        assert_login_cookie(
            &mut resp,
            COOKIE_LOGIN,
            LoginTimestampCheck::Old(timestamp),
            VisitTimeStampCheck::NewTimestamp,
        );
        assert_logged_in(resp, Some(COOKIE_LOGIN)).await;
    }

    /// STATEMENT: An identity cookie larger than 4096 bytes is reported as an error
    /// instead of being silently dropped.
    ///
    /// HOW:
    /// - Remember an identity long enough to push the encrypted cookie past
    ///   `MAX_COOKIE_SIZE`.
    /// - Confirm the response is a server error without a `Set-Cookie` header.
    /// - Remember a short identity and confirm the cookie is still set.
    #[ntex::test]
    async fn oversized_identity_cookie_is_an_error() {
        let srv = test::init_service(
            App::new()
                .middleware(IdentityService::new(
                    CookieIdentityPolicy::new(&COOKIE_KEY_MASTER).name(COOKIE_NAME),
                ))
                .service(web::resource("/{len}").to(
                    |id: Identity, len: web::types::Path<usize>| async move {
                        id.remember("a".repeat(*len));
                        HttpResponse::Ok()
                    },
                ))
                .build(),
        )
        .await;

        let resp = test::call_service(&srv, TestRequest::with_uri("/4096").to_request()).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!resp.headers().contains_key(header::SET_COOKIE));

        let resp = test::call_service(&srv, TestRequest::with_uri("/16").to_request()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().contains_key(header::SET_COOKIE));
    }

    /// STATEMENT: Identity middleware remains ready during an in-flight call and propagates inner errors.
    ///
    /// HOW:
    /// - Hold an inner request on a channel and assert middleware readiness while it is pending.
    /// - Release the request and assert the inner error is returned rather than rendered or persisted.
    /// - Make a successful request and assert the policy writes its identity header to the response.
    #[ntex::test]
    async fn test_borrowed_mut_error() {
        struct Ident;

        impl<St, In> IdentityPolicy<St, In> for Ident {
            type Error = Infallible;

            async fn from_request(
                &self,
                _: &St,
                _: &mut WebRequest<In>,
            ) -> Result<Option<String>, Infallible> {
                Ok(Some("test".to_string()))
            }

            async fn to_response(
                &self,
                _: &St,
                identity: Option<String>,
                changed: bool,
                response: &mut WebResponse,
            ) -> Result<(), Infallible> {
                assert!(!changed);
                response.headers_mut().insert(
                    header::HeaderName::from_static("x-identity"),
                    HeaderValue::from_str(&identity.unwrap()).unwrap(),
                );
                Ok(())
            }
        }

        let (tx, rx) = futures::channel::oneshot::channel::<()>();
        let rx = Rc::new(std::cell::RefCell::new(Some(rx)));
        let srv = IdentityServiceMiddleware {
            backend: Rc::new(Ident),
            service: fn_service(move |req: WebRequest<()>| {
                let rx = rx.clone();
                async move {
                    if req.path() == "/blocked" {
                        let receiver = rx.borrow_mut().take().unwrap();
                        receiver.await.unwrap();
                        Err(error::ErrorBadRequest("inner error"))
                    } else {
                        Ok(req.into_response(HttpResponse::Ok().build()))
                    }
                }
            }),
        }
        .pipeline(());

        let mut pending =
            std::pin::pin!(srv.call(TestRequest::with_uri("/blocked").to_srv_request()));
        assert!(futures::poll!(pending.as_mut()).is_pending());
        srv.ready().await.expect("srv to be ready");
        tx.send(()).unwrap();
        assert_eq!(pending.await.unwrap_err().to_string(), "inner error");

        let response = srv
            .call(TestRequest::default().to_srv_request())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("x-identity").unwrap(), "test");
    }

    /// STATEMENT: Identity mutations are shared across request handles only when a policy initialized them.
    ///
    /// HOW:
    /// - Extract `Identity` from requests with and without an initialized `IdentityItem` and clone the handle.
    /// - Remember an identity and assert the clone and `RequestIdentity` observe it only on the initialized request.
    /// - Forget through the clone and assert the original handle and request become anonymous.
    #[ntex::test]
    async fn identity_mutations_share_request_state() {
        for initialized in [false, true] {
            let (req, mut payload, state) = TestRequest::default().to_http_parts();
            if initialized {
                req.extensions_mut().insert(IdentityItem {
                    id: None,
                    changed: false,
                });
            }
            let identity = Identity::from_request(&state, &req, &mut payload)
                .await
                .unwrap();
            let clone = identity.clone();
            assert_eq!(req.get_identity(), None);
            identity.remember("alice".to_owned());
            let expected = initialized.then(|| "alice".to_owned());
            assert_eq!(clone.identity(), expected);
            assert_eq!(req.get_identity(), expected);
            clone.forget();
            assert_eq!(identity.identity(), None);
            assert_eq!(req.get_identity(), None);
            if initialized {
                assert!(req.extensions().get::<IdentityItem>().unwrap().changed);
            } else {
                assert!(req.extensions().get::<IdentityItem>().is_none());
            }
        }
    }

    /// STATEMENT: Policy errors are rendered at their respective stages, and removed identity state is not persisted.
    ///
    /// HOW:
    /// - Use a recording policy that rejects loading or saving according to the request path.
    /// - Assert load errors yield `403` without an inner call, and save errors yield `400` after an inner call.
    /// - Remove `IdentityItem` in another inner call and assert `202` without a save; assert normal calls save and remove the item.
    #[ntex::test]
    async fn middleware_policy_errors_and_removed_identity() {
        struct Policy(Rc<std::cell::RefCell<Vec<&'static str>>>);

        impl IdentityPolicy<(), ()> for Policy {
            type Error = WebError;

            async fn from_request(
                &self,
                _: &(),
                req: &mut WebRequest,
            ) -> Result<Option<String>, WebError> {
                self.0.borrow_mut().push("load");
                if req.path() == "/load-error" {
                    Err(WebError::from_err(error::ErrorForbidden("load denied")))
                } else {
                    Ok(Some("loaded".to_owned()))
                }
            }

            async fn to_response(
                &self,
                _: &(),
                id: Option<String>,
                changed: bool,
                res: &mut WebResponse,
            ) -> Result<(), WebError> {
                self.0.borrow_mut().push("save");
                assert_eq!(id.as_deref(), Some("loaded"));
                assert!(!changed);
                if res.request().path() == "/save-error" {
                    Err(WebError::from_err(error::ErrorBadRequest("save denied")))
                } else {
                    Ok(())
                }
            }
        }

        let events = Rc::new(std::cell::RefCell::new(Vec::new()));
        let inner_events = events.clone();
        let service = IdentityService::new(Policy(events.clone()))
            .create(
                &(),
                fn_service(move |req: WebRequest| {
                    inner_events.borrow_mut().push("call");
                    assert_eq!(req.get_identity().as_deref(), Some("loaded"));
                    if req.path() == "/removed" {
                        req.extensions_mut().remove::<IdentityItem>();
                    }
                    async move {
                        Ok::<_, Infallible>(req.into_response(HttpResponse::Accepted().build()))
                    }
                }),
            )
            .pipeline(());

        for (path, status, expected) in [
            ("/load-error", StatusCode::FORBIDDEN, vec!["load"]),
            (
                "/save-error",
                StatusCode::BAD_REQUEST,
                vec!["load", "call", "save"],
            ),
            ("/removed", StatusCode::ACCEPTED, vec!["load", "call"]),
            ("/ok", StatusCode::ACCEPTED, vec!["load", "call", "save"]),
        ] {
            events.borrow_mut().clear();
            let response = service
                .call(TestRequest::with_uri(path).to_srv_request())
                .await
                .unwrap();
            assert_eq!(response.status(), status);
            assert_eq!(*events.as_ref().borrow(), expected);
            assert!(
                response
                    .request()
                    .extensions()
                    .get::<IdentityItem>()
                    .is_none()
            );
        }
    }

    /// STATEMENT: Private identity cookies retain configured attributes when issued and removed.
    ///
    /// HOW:
    /// - Remember an identity with custom scope, `SameSite::Strict`, `Secure` and `Max-Age`, alongside an unrelated cookie.
    /// - Assert the unrelated cookie survives, the identity decrypts correctly and all configured attributes are present.
    /// - Replay it without changes and assert an unrelated cookie survives without an identity cookie being reissued.
    /// - Forget the identity; assert the removal cookie retains its attributes with empty value, zero `Max-Age` and past `Expires`.
    #[ntex::test]
    async fn identity_cookie_attributes_survive_logout() {
        let srv = test::init_service(
            App::new()
                .middleware(IdentityService::new(
                    CookieIdentityPolicy::new(&COOKIE_KEY_MASTER)
                        .name(COOKIE_NAME)
                        .path("/account")
                        .domain("localhost")
                        .secure(true)
                        .same_site(SameSite::Strict)
                        .max_age(120),
                ))
                .service(web::resource("/login").to(|id: Identity| async move {
                    id.remember(COOKIE_LOGIN.to_owned());
                    HttpResponse::Ok()
                        .header(header::SET_COOKIE, "unrelated=kept")
                        .build()
                }))
                .service(web::resource("/index").to(|id: Identity| async move {
                    assert_eq!(id.identity().as_deref(), Some(COOKIE_LOGIN));
                    HttpResponse::Ok()
                        .header(header::SET_COOKIE, "unrelated=kept")
                        .build()
                }))
                .service(web::resource("/logout").to(|id: Identity| async move {
                    assert_eq!(id.identity().as_deref(), Some(COOKIE_LOGIN));
                    id.forget();
                    HttpResponse::Ok()
                })),
        )
        .await;
        let response = srv
            .call(TestRequest::with_uri("/login").to_request())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response
                .cookies()
                .any(|c| c.name() == "unrelated" && c.value() == "kept")
        );
        let cookie = response
            .cookies()
            .find(|c| c.name() == COOKIE_NAME)
            .unwrap()
            .into_owned();
        assert_eq!(cookie.path(), Some("/account"));
        assert_eq!(cookie.domain(), Some("localhost"));
        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Strict));
        assert_eq!(cookie.max_age(), Some(Duration::seconds(120)));
        let mut jar = CookieJar::new();
        jar.add_original(cookie.clone());
        let key = Key::derive_from(&COOKIE_KEY_MASTER);
        assert_eq!(
            jar.private(&key).get(COOKIE_NAME).unwrap().value(),
            COOKIE_LOGIN
        );

        let mut unchanged = srv
            .call(
                TestRequest::with_uri("/index")
                    .cookie(cookie.clone())
                    .to_request(),
            )
            .await
            .unwrap();
        assert_eq!(unchanged.status(), StatusCode::OK);
        assert!(
            unchanged
                .cookies()
                .any(|c| c.name() == "unrelated" && c.value() == "kept")
        );
        assert_no_login_cookie(&mut unchanged);

        let response = srv
            .call(TestRequest::with_uri("/logout").cookie(cookie).to_request())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let deleted = response
            .cookies()
            .find(|c| c.name() == COOKIE_NAME)
            .unwrap();
        assert_eq!(deleted.value(), "");
        assert_eq!(deleted.path(), Some("/account"));
        assert_eq!(deleted.domain(), Some("localhost"));
        assert_eq!(deleted.secure(), Some(true));
        assert_eq!(deleted.http_only(), Some(true));
        assert_eq!(deleted.same_site(), Some(SameSite::Strict));
        assert_eq!(deleted.max_age(), Some(Duration::ZERO));
        assert!(deleted.expires().unwrap().datetime().unwrap() < ::time::OffsetDateTime::now_utc());
    }

    /// STATEMENT: A visit-only deadline refreshes authenticated cookies without adding a login timestamp.
    ///
    /// HOW:
    /// - Configure only `visit_deadline` and replay a valid cookie with a day-old visit timestamp and no login timestamp.
    /// - Assert the response keeps the identity and issues a cookie with a recent visit timestamp but no login timestamp.
    #[ntex::test]
    async fn visit_only_deadline_refreshes_identity() {
        let srv = create_identity_server(|c| c.visit_deadline(Duration::days(90))).await;
        let cookie = login_cookie(
            COOKIE_LOGIN,
            None,
            Some(SystemTime::now() - Duration::days(1)),
        );
        let mut response = srv
            .call(TestRequest::default().cookie(cookie).to_request())
            .await
            .unwrap();
        assert_login_cookie(
            &mut response,
            COOKIE_LOGIN,
            LoginTimestampCheck::Incorrect,
            VisitTimeStampCheck::NewTimestamp,
        );
        assert_logged_in(response, Some(COOKIE_LOGIN)).await;
    }

    /// STATEMENT: Invalid cookie header configuration becomes a server error rather than panicking.
    ///
    /// HOW:
    /// - Configure a cookie path containing a newline and remember an identity in the handler.
    /// - Assert the middleware returns `500` without emitting an invalid `Set-Cookie` header.
    #[ntex::test]
    async fn invalid_identity_cookie_header_returns_error() {
        let srv = test::init_service(
            App::new()
                .middleware(IdentityService::new(
                    CookieIdentityPolicy::new(&COOKIE_KEY_MASTER).path("/invalid\npath"),
                ))
                .service(web::resource("/").to(|id: Identity| async move {
                    id.remember(COOKIE_LOGIN.to_owned());
                    HttpResponse::Ok()
                })),
        )
        .await;
        let response = srv.call(TestRequest::default().to_request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!response.headers().contains_key(header::SET_COOKIE));
    }
}
