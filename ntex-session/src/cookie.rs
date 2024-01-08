//! Cookie session.
//!
//! [**CookieSession**](struct.CookieSession.html)
//! uses cookies as session storage. `CookieSession` creates sessions
//! which are limited to storing fewer than 4000 bytes of data, as the payload
//! must fit into a single cookie. An internal server error is generated if a
//! session contains more than 4000 bytes.
//!
//! A cookie may have a security policy of *signed* or *private*. Each has
//! a respective `CookieSession` constructor.
//!
//! A *signed* cookie may be viewed but not modified by the client. A *private*
//! cookie may neither be viewed nor modified by the client.
//!
//! The constructors take a key as an argument. This is the private key
//! for cookie session - when this value is changed, all session data is lost.

use std::{collections::HashMap, convert::Infallible, rc::Rc};

use cookie::{Cookie, CookieJar, Key, SameSite};
use derive_more::{Display, From};
use ntex::http::{header::HeaderValue, header::SET_COOKIE, HttpMessage};
use ntex::service::{Middleware, Service, ServiceCtx};
use ntex::web::{DefaultError, ErrorRenderer, WebRequest, WebResponse, WebResponseError};
use serde_json::error::Error as JsonError;
use time::{Duration, OffsetDateTime};

use crate::{Session, SessionStatus};

/// Errors that can occur during handling cookie session
#[derive(Debug, From, Display)]
pub enum CookieSessionError {
    /// Size of the serialized session is greater than 4000 bytes.
    #[display(fmt = "Size of the serialized session is greater than 4000 bytes.")]
    Overflow,
    /// Fail to serialize session.
    #[display(fmt = "Fail to serialize session")]
    Serialize(JsonError),
}

impl WebResponseError<DefaultError> for CookieSessionError {}

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
        if value.len() > 4064 {
            return Err(CookieSessionError::Overflow);
        }

        let mut cookie = Cookie::new(self.name.clone(), value);
        cookie.set_path(self.path.clone());
        cookie.set_secure(self.secure);
        cookie.set_http_only(self.http_only);

        if let Some(ref domain) = self.domain {
            cookie.set_domain(domain.clone());
        }

        if let Some(expires_in) = self.expires_in {
            cookie.set_expires(OffsetDateTime::now_utc() + expires_in);
        }

        if let Some(max_age) = self.max_age {
            cookie.set_max_age(max_age);
        }

        if let Some(same_site) = self.same_site {
            cookie.set_same_site(same_site);
        }

        let mut jar = CookieJar::new();

        match self.security {
            CookieSecurity::Signed => jar.signed_mut(&self.key).add(cookie),
            CookieSecurity::Private => jar.private_mut(&self.key).add(cookie),
        }

        for cookie in jar.delta() {
            let val = HeaderValue::from_str(&cookie.encoded().to_string()).unwrap();
            res.headers_mut().append(SET_COOKIE, val);
        }

        Ok(())
    }

    /// invalidates session cookie
    fn remove_cookie(&self, res: &mut WebResponse) -> Result<(), Infallible> {
        let mut cookie = Cookie::from(self.name.clone());
        cookie.set_value("");
        cookie.set_max_age(Duration::ZERO);
        cookie.set_expires(OffsetDateTime::now_utc() - Duration::days(365));

        let val = HeaderValue::from_str(&cookie.to_string()).unwrap();
        res.headers_mut().append(SET_COOKIE, val);

        Ok(())
    }

    fn load<Err>(&self, req: &WebRequest<Err>) -> (bool, HashMap<String, String>) {
        if let Ok(cookies) = req.cookies() {
            for cookie in cookies.iter() {
                if cookie.name() == self.name {
                    let mut jar = CookieJar::new();
                    jar.add_original(cookie.clone());

                    let cookie_opt = match self.security {
                        CookieSecurity::Signed => jar.signed(&self.key).get(&self.name),
                        CookieSecurity::Private => jar.private(&self.key).get(&self.name),
                    };
                    if let Some(cookie) = cookie_opt {
                        if let Ok(val) = serde_json::from_str(cookie.value()) {
                            return (false, val);
                        }
                    }
                }
            }
        }
        (true, HashMap::new())
    }
}

/// Use cookies for session storage.
///
/// `CookieSession` creates sessions which are limited to storing
/// fewer than 4000 bytes of data (as the payload must fit into a single
/// cookie). An Internal Server Error is generated if the session contains more
/// than 4000 bytes.
///
/// A cookie may have a security policy of *signed* or *private*. Each has a
/// respective `CookieSessionBackend` constructor.
///
/// A *signed* cookie is stored on the client as plaintext alongside
/// a signature such that the cookie may be viewed but not modified by the
/// client.
///
/// A *private* cookie is stored on the client as encrypted text
/// such that it may neither be viewed nor modified by the client.
///
/// The constructors take a key as an argument.
/// This is the private key for cookie session - when this value is changed,
/// all session data is lost. The constructors will panic if the key is less
/// than 32 bytes in length.
///
/// The backend relies on `cookie` crate to create and read cookies.
/// By default all cookies are percent encoded, but certain symbols may
/// cause troubles when reading cookie, if they are not properly percent encoded.
///
/// # Example
///
/// ```rust
/// use ntex_session::CookieSession;
/// use ntex::web::{self, App, HttpResponse, HttpServer};
///
/// let app = App::new().wrap(
///     CookieSession::signed(&[0; 32])
///         .domain("www.rust-lang.org")
///         .name("ntex-session")
///         .path("/")
///         .secure(true))
///     .service(web::resource("/").to(|| async { HttpResponse::Ok() }));
/// ```
pub struct CookieSession(Rc<CookieSessionInner>);

impl CookieSession {
    /// Construct new *signed* `CookieSessionBackend` instance.
    ///
    /// Panics if key length is less than 32 bytes.
    pub fn signed(key: &[u8]) -> Self {
        CookieSession(Rc::new(CookieSessionInner::new(key, CookieSecurity::Signed)))
    }

    /// Construct new *private* `CookieSessionBackend` instance.
    ///
    /// Panics if key length is less than 32 bytes.
    pub fn private(key: &[u8]) -> Self {
        CookieSession(Rc::new(CookieSessionInner::new(key, CookieSecurity::Private)))
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

    /// Sets the `http_only` field in the session cookie being built.
    pub fn http_only(mut self, value: bool) -> Self {
        Rc::get_mut(&mut self.0).unwrap().http_only = value;
        self
    }

    /// Sets the `same_site` field in the session cookie being built.
    pub fn same_site(mut self, value: SameSite) -> Self {
        Rc::get_mut(&mut self.0).unwrap().same_site = Some(value);
        self
    }

    /// Sets the `max-age` field in the session cookie being built.
    pub fn max_age(self, seconds: i64) -> Self {
        self.max_age_time(Duration::seconds(seconds))
    }

    /// Sets the `max-age` field in the session cookie being built.
    pub fn max_age_time(mut self, value: time::Duration) -> Self {
        Rc::get_mut(&mut self.0).unwrap().max_age = Some(value);
        self
    }

    /// Sets the `expires` field in the session cookie being built.
    pub fn expires_in(self, seconds: i64) -> Self {
        self.expires_in_time(Duration::seconds(seconds))
    }

    /// Sets the `expires` field in the session cookie being built.
    pub fn expires_in_time(mut self, value: Duration) -> Self {
        Rc::get_mut(&mut self.0).unwrap().expires_in = Some(value);
        self
    }
}

impl<S> Middleware<S> for CookieSession {
    type Service = CookieSessionMiddleware<S>;

    fn create(&self, service: S) -> Self::Service {
        CookieSessionMiddleware { service, inner: self.0.clone() }
    }
}

/// Cookie session middleware
pub struct CookieSessionMiddleware<S> {
    service: S,
    inner: Rc<CookieSessionInner>,
}

impl<S, Err> Service<WebRequest<Err>> for CookieSessionMiddleware<S>
where
    S: Service<WebRequest<Err>, Response = WebResponse>,
    S::Error: 'static,
    Err: ErrorRenderer,
    Err::Container: From<CookieSessionError>,
{
    type Response = WebResponse;
    type Error = S::Error;

    ntex::forward_poll_ready!(service);
    ntex::forward_poll_shutdown!(service);

    /// On first request, a new session cookie is returned in response, regardless
    /// of whether any session state is set.  With subsequent requests, if the
    /// session state changes, then set-cookie is returned in response.  As
    /// a user logs out, call session.purge() to set SessionStatus accordingly
    /// and this will trigger removal of the session cookie in the response.
    async fn call(
        &self,
        req: WebRequest<Err>,
        ctx: ServiceCtx<'_, Self>,
    ) -> Result<Self::Response, Self::Error> {
        let inner = self.inner.clone();
        let (is_new, state) = self.inner.load(&req);
        let prolong_expiration = self.inner.expires_in.is_some();
        Session::set_session(state.into_iter(), &req);

        ctx.call(&self.service, req).await.map(|mut res| {
            match Session::get_changes(&mut res) {
                (SessionStatus::Changed, Some(state))
                | (SessionStatus::Renewed, Some(state)) => {
                    res.checked_expr::<Err, _, _>(|res| inner.set_cookie(res, state))
                }
                (SessionStatus::Unchanged, Some(state)) if prolong_expiration => {
                    res.checked_expr::<Err, _, _>(|res| inner.set_cookie(res, state))
                }
                (SessionStatus::Unchanged, _) =>
                // set a new session cookie upon first request (new client)
                {
                    if is_new {
                        let state: HashMap<String, String> = HashMap::new();
                        res.checked_expr::<Err, _, _>(|res| {
                            inner.set_cookie(res, state.into_iter())
                        })
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
    use ntex::web::{self, test, App};
    use ntex::{time, util::Bytes};

    #[ntex::test]
    async fn cookie_session() {
        let app = test::init_service(
            App::new().wrap(CookieSession::signed(&[0; 32]).secure(false)).service(
                web::resource("/").to(|ses: Session| async move {
                    let _ = ses.set("counter", 100);
                    "test"
                }),
            ),
        )
        .await;

        let request = test::TestRequest::get().to_request();
        let response = app.call(request).await.unwrap();
        assert!(response.response().cookies().any(|c| c.name() == "ntex-session"));
    }

    #[ntex::test]
    async fn private_cookie() {
        let app = test::init_service(
            App::new().wrap(CookieSession::private(&[0; 32]).secure(false)).service(
                web::resource("/").to(|ses: Session| async move {
                    let _ = ses.set("counter", 100);
                    "test"
                }),
            ),
        )
        .await;

        let request = test::TestRequest::get().to_request();
        let response = app.call(request).await.unwrap();
        assert!(response.response().cookies().any(|c| c.name() == "ntex-session"));
    }

    #[ntex::test]
    async fn cookie_session_extractor() {
        let app = test::init_service(
            App::new().wrap(CookieSession::signed(&[0; 32]).secure(false)).service(
                web::resource("/").to(|ses: Session| async move {
                    let _ = ses.set("counter", 100);
                    "test"
                }),
            ),
        )
        .await;

        let request = test::TestRequest::get().to_request();
        let response = app.call(request).await.unwrap();
        assert!(response.response().cookies().any(|c| c.name() == "ntex-session"));
    }

    #[ntex::test]
    async fn basics() {
        let app = test::init_service(
            App::new()
                .wrap(
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
            .response()
            .cookies()
            .find(|c| c.name() == "ntex-test")
            .unwrap()
            .into_owned();
        assert_eq!(cookie.path().unwrap(), "/test/");

        let request = test::TestRequest::with_uri("/test/").cookie(cookie).to_request();
        let body = test::read_response(&app, request).await;
        assert_eq!(body, Bytes::from_static(b"counter: 100"));
    }

    #[ntex::test]
    async fn prolong_expiration() {
        let app = test::init_service(
            App::new()
                .wrap(CookieSession::signed(&[0; 32]).secure(false).expires_in(60))
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
            .response()
            .cookies()
            .find(|c| c.name() == "ntex-session")
            .expect("Cookie is set")
            .expires()
            .expect("Expiration is set");

        time::sleep(time::Seconds::ONE).await;

        let request = test::TestRequest::with_uri("/test/").to_request();
        let response = app.call(request).await.unwrap();
        let expires_2 = response
            .response()
            .cookies()
            .find(|c| c.name() == "ntex-session")
            .expect("Cookie is set")
            .expires()
            .expect("Expiration is set");

        assert!(
            expires_2.datetime().unwrap() - expires_1.datetime().unwrap()
                >= Duration::seconds(1)
        );
    }
}
