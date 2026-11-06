//! Cookie-backed sessions using [`CookieSession`].
//!
//! Signed cookies expose their contents but detect tampering; private cookies
//! additionally encrypt the contents. The protected, percent-encoded
//! `name=value` pair must fit within 4096 bytes, excluding cookie attributes.
//! Changing the secret key invalidates existing session cookies.

use std::{collections::HashMap, convert::Infallible, rc::Rc};

use cookie::{Cookie, CookieJar, Key, SameSite};
use derive_more::{Display, From};
use ntex::http::{HttpMessage, header::HeaderValue, header::SET_COOKIE};
use ntex::service::{BindCtx, Ctx, Middleware, Service};
use ntex::web::{DefaultError, State, WebRequest, WebResponse, WebResponseError};
use serde_json::error::Error as JsonError;
use time::{Duration, OffsetDateTime};

use crate::{Session, SessionStatus};

/// Browsers drop cookies whose `name=value` pair is larger than this.
const MAX_COOKIE_SIZE: usize = 4096;

/// `Path` and `Domain` values are written to `Set-Cookie` verbatim, so they
/// must be valid header bytes and must not start another attribute.
fn is_valid_attr(value: &str) -> bool {
    value
        .bytes()
        .all(|b| (0x20..0x7f).contains(&b) && b != b';')
}

/// Errors that can occur during handling cookie session.
#[derive(Debug, From, Display, thiserror::Error)]
pub enum CookieSessionError {
    /// The protected, percent-encoded `name=value` pair exceeds 4096 bytes, excluding attributes.
    #[display("Size of the encoded session cookie is greater than 4096 bytes.")]
    Overflow,
    /// Failed to serialize session state.
    #[display("Fail to serialize session")]
    Serialize(JsonError),
}

impl<St> WebResponseError<St, DefaultError> for CookieSessionError {}

enum CookieSecurity {
    Signed,
    Private,
}

struct CookieSessionInner {
    key: Key,
    security: CookieSecurity,
    name: String,
    path: String,
    domain: Option<String>,
    secure: bool,
    http_only: bool,
    max_age: Option<Duration>,
    expires_in: Option<Duration>,
    same_site: Option<SameSite>,
}

impl CookieSessionInner {
    fn new(key: &[u8], security: CookieSecurity) -> Self {
        CookieSessionInner {
            security,
            key: Key::derive_from(key),
            name: "ntex-session".to_owned(),
            path: "/".to_owned(),
            domain: None,
            secure: true,
            http_only: true,
            max_age: None,
            expires_in: None,
            same_site: None,
        }
    }

    fn set_cookie(
        &self,
        res: &mut WebResponse,
        state: impl Iterator<Item = (String, String)>,
    ) -> Result<(), CookieSessionError> {
        let state: HashMap<String, String> = state.collect();
        let value = serde_json::to_string(&state).map_err(CookieSessionError::Serialize)?;

        let mut cookie = self.cookie(value);
        if let Some(expires_in) = self.expires_in {
            cookie.set_expires(OffsetDateTime::now_utc() + expires_in);
        }

        if let Some(max_age) = self.max_age {
            cookie.set_max_age(max_age);
        }

        let mut jar = CookieJar::new();

        match self.security {
            CookieSecurity::Signed => jar.signed_mut(&self.key).add(cookie),
            CookieSecurity::Private => jar.private_mut(&self.key).add(cookie),
        }

        for cookie in jar.delta() {
            let val = cookie.encoded().to_string();
            // percent-encoded name and value never contain `;`
            if val.split(';').next().map_or(0, str::len) > MAX_COOKIE_SIZE {
                return Err(CookieSessionError::Overflow);
            }
            res.headers_mut()
                .append(SET_COOKIE, HeaderValue::from_str(&val).unwrap());
        }

        Ok(())
    }

    /// invalidates session cookie
    fn remove_cookie(&self, res: &mut WebResponse) -> Result<(), Infallible> {
        // removal must carry the same attributes, browsers reject `__Secure-`
        // and `__Host-` cookies without `Secure`
        let mut cookie = self.cookie(String::new());
        cookie.set_max_age(Duration::ZERO);
        cookie.set_expires(OffsetDateTime::now_utc() - Duration::days(365));

        let val = HeaderValue::from_str(&cookie.encoded().to_string()).unwrap();
        res.headers_mut().append(SET_COOKIE, val);

        Ok(())
    }

    fn cookie(&self, value: String) -> Cookie<'static> {
        let mut cookie = Cookie::new(self.name.clone(), value);
        cookie.set_path(self.path.clone());
        cookie.set_secure(self.secure);
        cookie.set_http_only(self.http_only);

        if let Some(ref domain) = self.domain {
            cookie.set_domain(domain.clone());
        }
        if let Some(same_site) = self.same_site {
            cookie.set_same_site(same_site);
        }
        cookie
    }

    fn load<St>(&self, req: &WebRequest<St>) -> (bool, HashMap<String, String>) {
        if let Ok(cookies) = req.cookies() {
            for cookie in cookies.iter() {
                if cookie.name() == self.name {
                    let mut jar = CookieJar::new();
                    jar.add_original(cookie.clone());

                    let cookie_opt = match self.security {
                        CookieSecurity::Signed => jar.signed(&self.key).get(&self.name),
                        CookieSecurity::Private => jar.private(&self.key).get(&self.name),
                    };
                    if let Some(cookie) = cookie_opt
                        && let Ok(val) = serde_json::from_str(cookie.value())
                    {
                        return (false, val);
                    }
                }
            }
        }
        (true, HashMap::new())
    }
}

/// Use cookies for session storage.
///
/// `CookieSession` creates sessions which are limited in size (as the payload
/// must fit into a single cookie). An Internal Server Error is generated if
/// the signed or encrypted, percent-encoded `name=value` pair exceeds 4096
/// bytes. Cookie attributes are not counted toward this limit.
///
/// A cookie may have a security policy of *signed* or *private*. Each has a
/// respective `CookieSession` constructor.
///
/// A *signed* cookie is stored on the client as plaintext alongside
/// a signature such that the cookie may be viewed but not modified by the
/// client.
///
/// A *private* cookie is stored on the client as encrypted text
/// such that it may neither be viewed nor modified by the client.
///
/// The constructors take a key as an argument.
/// Keep this key secret and stable; changing it makes existing session cookies
/// unreadable. The constructors require at least 32 bytes.
///
/// Missing, malformed, tampered, undecryptable, or invalid-JSON cookies load
/// an empty session and are replaced. A new cookie is sent when no valid
/// session cookie was loaded, when the session changes or is renewed, or
/// (with [`expires_in`](Self::expires_in)) on each response returned by the
/// inner service. [`Session::purge`] instead expires the cookie, preserving
/// its configured scope and security attributes. Inner service errors
/// propagate without writing a cookie.
///
/// The backend relies on `cookie` crate to create and read cookies.
/// Cookie values are percent encoded.
///
/// Defaults: name `ntex-session`, path `/`, `Secure` and `HttpOnly` set, no
/// domain, `SameSite`, `Max-Age` or `Expires`. Configuration methods replace
/// their previous values and do not validate cookie attributes.
///
/// # Panics
///
/// Configuration methods panic while this backend is shared with a live
/// middleware service. Writing a cookie panics if its configured attributes
/// cannot form a valid `Set-Cookie` header, or if its expiration is outside
/// the range supported by [`time::OffsetDateTime`].
///
/// # Example
///
/// ```rust
/// use ntex_session::CookieSession;
/// use ntex::web::{self, App, HttpResponse};
///
/// let app = App::default().middleware(
///     CookieSession::signed(&[0; 32])
///         .domain("www.rust-lang.org")
///         .name("ntex-session")
///         .path("/")
///         .secure(true))
///     .service(web::resource("/").to(|| async { HttpResponse::Ok() }));
/// ```
pub struct CookieSession(Rc<CookieSessionInner>);

impl CookieSession {
    /// Constructs a signed [`CookieSession`].
    ///
    /// The client can read but not modify the session state.
    ///
    /// # Panics
    ///
    /// Panics if `key` is shorter than 32 bytes.
    pub fn signed(key: &[u8]) -> Self {
        CookieSession(Rc::new(CookieSessionInner::new(
            key,
            CookieSecurity::Signed,
        )))
    }

    /// Constructs an encrypted [`CookieSession`].
    ///
    /// The session state is encrypted, the client can neither read nor modify it.
    ///
    /// # Panics
    ///
    /// Panics if `key` is shorter than 32 bytes.
    pub fn private(key: &[u8]) -> Self {
        CookieSession(Rc::new(CookieSessionInner::new(
            key,
            CookieSecurity::Private,
        )))
    }

    /// Sets the session cookie's `Path` attribute.
    ///
    /// Default is `/`.
    ///
    /// # Panics
    ///
    /// Panics if this backend is shared with a live middleware service, or if
    /// `value` contains `;` or characters other than printable ASCII.
    pub fn path<S: Into<String>>(mut self, value: S) -> Self {
        let value = value.into();
        assert!(
            is_valid_attr(&value),
            "invalid session cookie path: {value:?}"
        );
        Rc::get_mut(&mut self.0).unwrap().path = value;
        self
    }

    /// Sets the session cookie's name.
    ///
    /// Default is `ntex-session`. Names with the `__Secure-` prefix require
    /// [`secure`](Self::secure); `__Host-` also requires path `/` and no
    /// [`domain`](Self::domain).
    ///
    /// # Panics
    ///
    /// Panics if this backend is shared with a live middleware service.
    pub fn name<S: Into<String>>(mut self, value: S) -> Self {
        Rc::get_mut(&mut self.0).unwrap().name = value.into();
        self
    }

    /// Sets the session cookie's `Domain` attribute.
    ///
    /// Not set by default, the cookie is sent only to the origin host.
    ///
    /// # Panics
    ///
    /// Panics if this backend is shared with a live middleware service, or if
    /// `value` contains `;` or characters other than printable ASCII.
    pub fn domain<S: Into<String>>(mut self, value: S) -> Self {
        let value = value.into();
        assert!(
            is_valid_attr(&value),
            "invalid session cookie domain: {value:?}"
        );
        Rc::get_mut(&mut self.0).unwrap().domain = Some(value);
        self
    }

    /// Sets the session cookie's `Secure` attribute.
    ///
    /// If the `secure` field is set, a cookie will only be transmitted when the
    /// connection is secure - i.e. `https`. Default is `true`, set it to
    /// `false` to use sessions over plain `http`.
    ///
    /// # Panics
    ///
    /// Panics if this backend is shared with a live middleware service.
    pub fn secure(mut self, value: bool) -> Self {
        Rc::get_mut(&mut self.0).unwrap().secure = value;
        self
    }

    /// Sets the session cookie's `HttpOnly` attribute.
    ///
    /// If set, the cookie is not available to client side scripts. Default
    /// is `true`.
    ///
    /// # Panics
    ///
    /// Panics if this backend is shared with a live middleware service.
    pub fn http_only(mut self, value: bool) -> Self {
        Rc::get_mut(&mut self.0).unwrap().http_only = value;
        self
    }

    /// Sets the session cookie's [`SameSite`] attribute.
    ///
    /// Not set by default.
    ///
    /// # Panics
    ///
    /// Panics if this backend is shared with a live middleware service.
    pub fn same_site(mut self, value: SameSite) -> Self {
        Rc::get_mut(&mut self.0).unwrap().same_site = Some(value);
        self
    }

    /// Sets the session cookie's `Max-Age` attribute, in seconds.
    ///
    /// Unset by default. If [`expires_in`](Self::expires_in) is also unset,
    /// the cookie expires when the browser session ends.
    ///
    /// # Panics
    ///
    /// Panics if this backend is shared with a live middleware service.
    pub fn max_age(self, seconds: i64) -> Self {
        self.max_age_time(Duration::seconds(seconds))
    }

    /// Sets the session cookie's `Max-Age` attribute.
    ///
    /// Same as [`max_age`](Self::max_age), but takes a [`time::Duration`].
    ///
    /// # Panics
    ///
    /// Panics if this backend is shared with a live middleware service.
    pub fn max_age_time(mut self, value: time::Duration) -> Self {
        Rc::get_mut(&mut self.0).unwrap().max_age = Some(value);
        self
    }

    /// Sets the session cookie's `Expires` to the given number of seconds from now.
    ///
    /// The cookie is re-sent on each response returned by the inner service,
    /// unless the session is purged, so its expiration is extended on each
    /// request. Unset by default. If `Max-Age` is also configured, browsers
    /// give it precedence over `Expires`.
    ///
    /// # Panics
    ///
    /// Panics if this backend is shared with a live middleware service.
    pub fn expires_in(self, seconds: i64) -> Self {
        self.expires_in_time(Duration::seconds(seconds))
    }

    /// Sets the session cookie's `Expires` to the given duration from now.
    ///
    /// Same as [`expires_in`](Self::expires_in), but takes a [`time::Duration`].
    ///
    /// # Panics
    ///
    /// Panics if this backend is shared with a live middleware service.
    pub fn expires_in_time(mut self, value: Duration) -> Self {
        Rc::get_mut(&mut self.0).unwrap().expires_in = Some(value);
        self
    }
}

impl<S, St> Middleware<S, St> for CookieSession {
    type Service = CookieSessionMiddleware<S>;

    fn create(&self, _: &St, service: S) -> Self::Service {
        CookieSessionMiddleware {
            service,
            inner: self.0.clone(),
        }
    }
}

/// Cookie session middleware service, created by [`CookieSession`].
pub struct CookieSessionMiddleware<S> {
    service: S,
    inner: Rc<CookieSessionInner>,
}

impl<S, St: State, In> Service<St, WebRequest<In>> for CookieSessionMiddleware<S>
where
    S: Service<St, WebRequest<In>, Res = WebResponse>,
    S::Error: 'static,
    CookieSessionError: WebResponseError<St, St::Error>,
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

    /// Loads session state, calls the inner service, and persists or removes
    /// the session cookie according to [`SessionStatus`].
    ///
    /// # Errors
    ///
    /// Propagates inner service errors without writing cookies. Cookie size
    /// and serialization errors are rendered as error responses instead.
    ///
    /// # Panics
    ///
    /// Panics if the configured expiration is outside the supported date range.
    async fn call(
        &self,
        req: WebRequest<In>,
        ctx: Ctx<'_, Self, St>,
    ) -> Result<Self::Res, Self::Error> {
        let inner = self.inner.clone();
        let (is_new, state) = self.inner.load(&req);
        let prolong_expiration = self.inner.expires_in.is_some();
        Session::set_session(state.into_iter(), &req);

        ctx.call(&self.service, req).await.map(|mut res| {
            match Session::get_changes(&mut res) {
                (SessionStatus::Changed, Some(state)) | (SessionStatus::Renewed, Some(state)) => {
                    if let Err(e) = inner.set_cookie(&mut res, state) {
                        res.error_response(ctx.st(), &e)
                    } else {
                        res
                    }
                }
                (SessionStatus::Unchanged, Some(state)) if prolong_expiration => {
                    if let Err(e) = inner.set_cookie(&mut res, state) {
                        res.error_response(ctx.st(), &e)
                    } else {
                        res
                    }
                }
                (SessionStatus::Unchanged, _) =>
                // set a new session cookie upon first request (new client)
                {
                    if is_new {
                        let state: HashMap<String, String> = HashMap::new();

                        if let Err(e) = inner.set_cookie(&mut res, state.into_iter()) {
                            res.error_response(ctx.st(), &e)
                        } else {
                            res
                        }
                    } else {
                        res
                    }
                }
                (SessionStatus::Purged, _) => {
                    let _ = inner.remove_cookie(&mut res);
                    res
                }
                _ => res,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ntex::web::{self, App, test};
    use ntex::{time, util::Bytes};

    #[ntex::test]
    async fn cookie_session() {
        let app = test::init_service(
            App::new()
                .middleware(CookieSession::signed(&[0; 32]).secure(false))
                .service(web::resource("/").to(|ses: Session| async move {
                    let _ = ses.set("counter", 100);
                    "test"
                })),
        )
        .await;

        let request = test::TestRequest::get().to_request();
        let response = app.call(request).await.unwrap();
        assert!(response.cookies().any(|c| c.name() == "ntex-session"));
    }

    #[ntex::test]
    async fn private_cookie() {
        let app = test::init_service(
            App::new()
                .middleware(CookieSession::private(&[0; 32]).secure(false))
                .service(web::resource("/").to(|ses: Session| async move {
                    let _ = ses.set("counter", 100);
                    "test"
                })),
        )
        .await;

        let request = test::TestRequest::get().to_request();
        let response = app.call(request).await.unwrap();
        assert!(response.cookies().any(|c| c.name() == "ntex-session"));
    }

    #[ntex::test]
    async fn cookie_session_extractor() {
        let app = test::init_service(
            App::new()
                .middleware(CookieSession::signed(&[0; 32]).secure(false))
                .service(web::resource("/").to(|ses: Session| async move {
                    let _ = ses.set("counter", 100);
                    "test"
                })),
        )
        .await;

        let request = test::TestRequest::get().to_request();
        let response = app.call(request).await.unwrap();
        assert!(response.cookies().any(|c| c.name() == "ntex-session"));
    }

    #[ntex::test]
    async fn basics() {
        let app = test::init_service(
            App::new()
                .middleware(
                    CookieSession::signed(&[0; 32])
                        .path("/test/")
                        .name("ntex-test")
                        .domain("localhost")
                        .http_only(true)
                        .same_site(SameSite::Lax)
                        .max_age(100),
                )
                .service(web::resource("/").to(|ses: Session| async move {
                    let _ = ses.set("counter", 100);
                    "test"
                }))
                .service(web::resource("/test/").to(|ses: Session| async move {
                    let val: usize = ses.get("counter").unwrap().unwrap();
                    format!("counter: {}", val)
                })),
        )
        .await;

        let request = test::TestRequest::get().to_request();
        let response = app.call(request).await.unwrap();
        let cookie = response
            .cookies()
            .find(|c| c.name() == "ntex-test")
            .unwrap()
            .into_owned();
        assert_eq!(cookie.path().unwrap(), "/test/");

        let request = test::TestRequest::with_uri("/test/")
            .cookie(cookie)
            .to_request();
        let body = test::read_response(&app, request).await;
        assert_eq!(body, Bytes::from_static(b"counter: 100"));
    }

    #[ntex::test]
    async fn prolong_expiration() {
        let app = test::init_service(
            App::new()
                .middleware(CookieSession::signed(&[0; 32]).secure(false).expires_in(60))
                .service(web::resource("/").to(|ses: Session| async move {
                    let _ = ses.set("counter", 100);
                    "test"
                }))
                .service(web::resource("/test/").to(|| async move { "no-changes-in-session" })),
        )
        .await;

        let request = test::TestRequest::get().to_request();
        let response = app.call(request).await.unwrap();
        let expires_1 = response
            .cookies()
            .find(|c| c.name() == "ntex-session")
            .expect("Cookie is set")
            .expires()
            .expect("Expiration is set");

        time::sleep(time::Seconds::ONE).await;

        let request = test::TestRequest::with_uri("/test/").to_request();
        let response = app.call(request).await.unwrap();
        let expires_2 = response
            .cookies()
            .find(|c| c.name() == "ntex-session")
            .expect("Cookie is set")
            .expires()
            .expect("Expiration is set");

        assert!(
            expires_2.datetime().unwrap() - expires_1.datetime().unwrap() >= Duration::seconds(1)
        );
    }

    /// STATEMENT: The size limit applies to the encoded cookie, so a session whose
    /// JSON is small but grows past 4096 bytes after signing and encoding is
    /// rejected instead of being silently dropped by the browser.
    ///
    /// HOW:
    /// - Store 1000 `"` characters: about 2 KB of JSON, but every `"` becomes
    ///   `%5C%22` (6 bytes) in the cookie.
    /// - Check the response is `500` and carries no `Set-Cookie`.
    /// - Store 1000 plain characters and check the cookie is still set.
    #[ntex::test]
    async fn size_limit_applies_to_encoded_cookie() {
        let app = test::init_service(
            App::new()
                .middleware(CookieSession::signed(&[0; 32]).secure(false))
                .service(web::resource("/quotes").to(|ses: Session| async move {
                    let _ = ses.set("v", "\"".repeat(1000));
                    "test"
                }))
                .service(web::resource("/plain").to(|ses: Session| async move {
                    let _ = ses.set("v", "a".repeat(1000));
                    "test"
                })),
        )
        .await;

        let request = test::TestRequest::with_uri("/quotes").to_request();
        let response = app.call(request).await.unwrap();
        assert_eq!(
            response.status(),
            ntex::http::StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(!response.headers().contains_key(SET_COOKIE));

        let request = test::TestRequest::with_uri("/plain").to_request();
        let response = app.call(request).await.unwrap();
        assert!(response.status().is_success());
        assert!(response.cookies().any(|c| c.name() == "ntex-session"));
    }

    /// STATEMENT: The purge cookie carries the same `Secure`, `HttpOnly` and
    /// `SameSite` attributes as the session cookie, so browsers accept it for
    /// `__Host-` prefixed names.
    ///
    /// HOW:
    /// - Configure a `__Host-session` cookie with `SameSite::Strict` and call
    ///   `purge()` in the handler.
    /// - Parse the `Set-Cookie` header and check the name, empty value, zero
    ///   `Max-Age`, `Secure`, `HttpOnly`, `SameSite=Strict` and path `/`.
    #[ntex::test]
    async fn purge_cookie_keeps_security_attributes() {
        let app = test::init_service(
            App::new()
                .middleware(
                    CookieSession::signed(&[0; 32])
                        .name("__Host-session")
                        .same_site(SameSite::Strict),
                )
                .service(web::resource("/").to(|ses: Session| async move {
                    ses.purge();
                    "test"
                })),
        )
        .await;

        let request = test::TestRequest::get().to_request();
        let response = app.call(request).await.unwrap();
        let cookie = response
            .cookies()
            .find(|c| c.name() == "__Host-session")
            .unwrap();
        assert_eq!(cookie.value(), "");
        assert_eq!(cookie.max_age(), Some(Duration::ZERO));
        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Strict));
        assert_eq!(cookie.path(), Some("/"));
    }

    fn protected_session_cookie(private: bool, key: &[u8], value: String) -> Cookie<'static> {
        let mut jar = CookieJar::new();
        let cookie = Cookie::new("ntex-session", value);
        let key = Key::derive_from(key);
        if private {
            jar.private_mut(&key).add(cookie);
        } else {
            jar.signed_mut(&key).add(cookie);
        }
        jar.get("ntex-session").unwrap().clone()
    }

    /// STATEMENT: Signed and private sessions preserve values through renewal and reject invalid cookies.
    ///
    /// HOW:
    /// - For each security policy, store a counter with custom cookie attributes and replay the cookie.
    /// - Assert unchanged requests read the counter without reissuing cookies, while renewal preserves it and the attributes.
    /// - Replay tampered, wrong-key, authenticated invalid JSON and malformed cookie headers; assert empty sessions and replacement cookies.
    /// - Purge a valid session and assert the deletion retains its scope and security attributes with an expired lifetime.
    #[ntex::test]
    async fn protected_sessions_roundtrip_renew_reject_and_purge() {
        for private in [false, true] {
            let policy = if private {
                CookieSession::private(&[0; 32])
            } else {
                CookieSession::signed(&[0; 32])
            };
            let app = test::init_service(
                App::new()
                    .middleware(
                        policy
                            .path("/account")
                            .domain("localhost")
                            .http_only(false)
                            .same_site(SameSite::Strict)
                            .max_age(120),
                    )
                    .service(web::resource("/write").to(|ses: Session| async move {
                        ses.set("counter", 42).unwrap();
                        "stored"
                    }))
                    .service(web::resource("/read").to(|ses: Session| async move {
                        web::types::Json(ses.get::<u32>("counter").unwrap())
                    }))
                    .service(web::resource("/renew").to(|ses: Session| async move {
                        ses.renew();
                        web::types::Json(ses.get::<u32>("counter").unwrap())
                    }))
                    .service(web::resource("/purge").to(|ses: Session| async move {
                        ses.purge();
                        "purged"
                    })),
            )
            .await;

            let response = app
                .call(test::TestRequest::with_uri("/write").to_request())
                .await
                .unwrap();
            let cookie = response.cookies().next().unwrap().into_owned();
            let response = app
                .call(
                    test::TestRequest::with_uri("/read")
                        .cookie(cookie.clone())
                        .to_request(),
                )
                .await
                .unwrap();
            assert!(!response.headers().contains_key(SET_COOKIE));
            assert_eq!(test::read_body(response).await.as_ref(), b"42");

            let response = app
                .call(
                    test::TestRequest::with_uri("/renew")
                        .cookie(cookie.clone())
                        .to_request(),
                )
                .await
                .unwrap();
            let renewed = response.cookies().next().unwrap().into_owned();
            assert_eq!(renewed.path(), Some("/account"));
            assert_eq!(renewed.domain(), Some("localhost"));
            assert_eq!(renewed.secure(), Some(true));
            assert_ne!(renewed.http_only(), Some(true));
            assert_eq!(renewed.same_site(), Some(SameSite::Strict));
            assert_eq!(renewed.max_age(), Some(Duration::seconds(120)));
            assert_eq!(test::read_body(response).await.as_ref(), b"42");
            let response = app
                .call(
                    test::TestRequest::with_uri("/read")
                        .cookie(renewed)
                        .to_request(),
                )
                .await
                .unwrap();
            assert!(!response.headers().contains_key(SET_COOKIE));
            assert_eq!(test::read_body(response).await.as_ref(), b"42");

            let mut tampered = cookie.clone();
            tampered.set_value(format!("{}tampered", tampered.value()));
            let invalid = [
                tampered,
                protected_session_cookie(private, &[1; 32], r#"{"counter":"42"}"#.to_owned()),
                protected_session_cookie(private, &[0; 32], "not-json".to_owned()),
                protected_session_cookie(private, &[0; 32], r#"{"counter":42}"#.to_owned()),
            ];
            for invalid in invalid {
                let response = app
                    .call(
                        test::TestRequest::with_uri("/read")
                            .cookie(Cookie::new("unrelated", "value"))
                            .cookie(invalid)
                            .to_request(),
                    )
                    .await
                    .unwrap();
                assert!(response.status().is_success());
                assert!(response.cookies().any(|c| c.name() == "ntex-session"));
                assert_eq!(test::read_body(response).await.as_ref(), b"null");
            }
            let response = app
                .call(
                    test::TestRequest::with_uri("/read")
                        .header(
                            ntex::http::header::COOKIE,
                            HeaderValue::from_bytes(b"\xff").unwrap(),
                        )
                        .to_request(),
                )
                .await
                .unwrap();
            assert!(response.status().is_success());
            assert!(response.cookies().any(|c| c.name() == "ntex-session"));
            assert_eq!(test::read_body(response).await.as_ref(), b"null");

            let response = app
                .call(
                    test::TestRequest::with_uri("/purge")
                        .cookie(cookie)
                        .to_request(),
                )
                .await
                .unwrap();
            let deleted = response.cookies().next().unwrap();
            assert_eq!(deleted.value(), "");
            assert_eq!(deleted.path(), Some("/account"));
            assert_eq!(deleted.domain(), Some("localhost"));
            assert_eq!(deleted.secure(), Some(true));
            assert_ne!(deleted.http_only(), Some(true));
            assert_eq!(deleted.same_site(), Some(SameSite::Strict));
            assert_eq!(deleted.max_age(), Some(Duration::ZERO));
            assert!(deleted.expires().unwrap().datetime().unwrap() < OffsetDateTime::now_utc());
        }
    }

    /// STATEMENT: Cookie size errors become server-error responses even without session mutations.
    ///
    /// HOW:
    /// - Replay an authenticated oversized session to a policy with sliding expiration and no handler mutations.
    /// - Request a new session with a cookie name exceeding the size limit.
    /// - Assert both responses are `500` without `Set-Cookie` headers.
    #[ntex::test]
    async fn unchanged_sessions_report_cookie_size_errors() {
        let app = test::init_service(
            App::new()
                .middleware(CookieSession::signed(&[0; 32]).expires_in(60))
                .service(web::resource("/").to(|| async { "unchanged" })),
        )
        .await;
        let state = HashMap::from([("large", serde_json::to_string(&"a".repeat(4096)).unwrap())]);
        let cookie =
            protected_session_cookie(false, &[0; 32], serde_json::to_string(&state).unwrap());
        let response = app
            .call(test::TestRequest::get().cookie(cookie).to_request())
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            ntex::http::StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(!response.headers().contains_key(SET_COOKIE));

        let app = test::init_service(
            App::new()
                .middleware(CookieSession::signed(&[0; 32]).name("a".repeat(4096)))
                .service(web::resource("/").to(|| async { "unchanged" })),
        )
        .await;
        let response = app
            .call(test::TestRequest::get().to_request())
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            ntex::http::StatusCode::INTERNAL_SERVER_ERROR
        );
        assert!(!response.headers().contains_key(SET_COOKIE));
    }

    /// STATEMENT: A `Path` that cannot be sent in `Set-Cookie` is rejected when configured.
    ///
    /// HOW:
    /// - Configure a path containing a newline.
    /// - Confirm `path` panics instead of a later request panicking.
    #[test]
    #[should_panic(expected = "invalid session cookie path")]
    fn invalid_path_is_rejected_by_builder() {
        let _ = CookieSession::signed(&[0; 32]).path("/\n");
    }

    /// STATEMENT: A `Domain` that would inject another cookie attribute is rejected when configured.
    ///
    /// HOW:
    /// - Configure a domain containing `;`.
    /// - Confirm `domain` panics instead of emitting an extra attribute.
    #[test]
    #[should_panic(expected = "invalid session cookie domain")]
    fn domain_with_separator_is_rejected_by_builder() {
        let _ = CookieSession::signed(&[0; 32]).domain("example.com; HttpOnly");
    }
}
