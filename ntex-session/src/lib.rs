//! User sessions for the ntex web framework.
//!
//! The crate provides a backend-independent [`Session`] api. A session
//! middleware loads the session state for each request and writes changes
//! back to the response; handlers access the state through the [`Session`]
//! extractor or the [`UserSession`] trait.
//!
//! Session values are stored as JSON strings and are (de)serialized with
//! `serde_json`.
//!
//! Only a cookie based backend, [`CookieSession`], is provided (enabled by the
//! default `cookie-session` feature). Other backends can be built on top of
//! [`Session::set_session`] and [`Session::get_changes`].
//!
//! ```rust,no_run
//! use ntex::web::{self, App, HttpResponse, WebError};
//! use ntex_session::{Session, CookieSession};
//! use serde_json::error::Error as JsonError;
//!
//! fn index(session: Session) -> Result<&'static str, JsonError> {
//!     // access session data
//!     if let Some(count) = session.get::<i32>("counter")? {
//!         println!("SESSION value: {}", count);
//!         session.set("counter", count+1)?;
//!     } else {
//!         session.set("counter", 1)?;
//!     }
//!
//!     Ok("Welcome!")
//! }
//!
//! #[ntex::main]
//! async fn main() -> std::io::Result<()> {
//!     web::server(
//!         async |_| App::new().middleware(
//!               CookieSession::signed(&[0; 32]) // <- create cookie based session middleware
//!                     .secure(false)
//!              )
//!             .service(web::resource("/").to(|| async { HttpResponse::Ok() })))
//!         .bind("127.0.0.1:59880", ntex::SharedCfg::default())?
//!         .run()
//!         .await
//! }
//! ```
use std::{cell::RefCell, convert::Infallible, rc::Rc};

use ntex::http::{Payload, RequestHead};
use ntex::util::{Extensions, HashMap};
use ntex::web::{FromRequest, HttpRequest, WebRequest, WebResponse};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::error::Error as JsonError;

#[cfg(feature = "cookie-session")]
mod cookie;
#[cfg(feature = "cookie-session")]
pub use crate::cookie::CookieSession;

/// The high-level interface you use to read and modify session data.
///
/// `Session` is an extractor, it can also be obtained with
/// [`UserSession::get_session`] from an `HttpRequest`, `WebRequest` or
/// `RequestHead`. All handles for the same request share the same state.
///
/// Once the session is [purged](Session::purge), further changes are ignored.
///
/// ```rust
/// use ntex_session::Session;
/// use ntex::web::*;
/// use serde_json::error::Error as JsonError;
///
/// fn index(session: Session) -> Result<&'static str, JsonError> {
///     // access session data
///     if let Some(count) = session.get::<i32>("counter")? {
///         session.set("counter", count + 1)?;
///     } else {
///         session.set("counter", 1)?;
///     }
///
///     Ok("Welcome!")
/// }
/// # fn main() {}
/// ```
pub struct Session(Rc<RefCell<SessionInner>>);

/// Helper trait that allows to get the session of a request.
pub trait UserSession {
    /// Get the session of the request, creating an empty one if needed.
    fn get_session(&self) -> Session;
}

impl UserSession for HttpRequest {
    fn get_session(&self) -> Session {
        Session::get_session(&mut self.extensions_mut())
    }
}

impl<St> UserSession for WebRequest<St> {
    fn get_session(&self) -> Session {
        Session::get_session(&mut self.extensions_mut())
    }
}

impl UserSession for RequestHead {
    fn get_session(&self) -> Session {
        Session::get_session(&mut self.extensions_mut())
    }
}

/// Status of the session after the request is handled.
///
/// Returned by [`Session::get_changes`], backends use it to decide how to
/// update the client.
#[derive(PartialEq, Clone, Debug, Default)]
pub enum SessionStatus {
    /// Session state was modified with `set`, `remove` or `clear`.
    Changed,
    /// Session was purged, the backend should remove it.
    Purged,
    /// Session was renewed, the backend should re-issue it with the
    /// existing state.
    Renewed,
    /// Session was not modified.
    #[default]
    Unchanged,
}

#[derive(Default)]
struct SessionInner {
    state: HashMap<String, String>,
    pub status: SessionStatus,
}

impl Session {
    /// Get a value from the session.
    ///
    /// Returns `Ok(None)` if the key is not set, or an error if the stored
    /// value cannot be deserialized into `T`.
    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, JsonError> {
        if let Some(s) = self.0.borrow().state.get(key) {
            Ok(Some(serde_json::from_str(s)?))
        } else {
            Ok(None)
        }
    }

    /// Set a value in the session.
    ///
    /// Returns an error if the value cannot be serialized. Ignored if the
    /// session is purged.
    pub fn set<T: Serialize>(&self, key: &str, value: T) -> Result<(), JsonError> {
        let mut inner = self.0.borrow_mut();
        if inner.status != SessionStatus::Purged {
            inner.status = SessionStatus::Changed;
            inner
                .state
                .insert(key.to_owned(), serde_json::to_string(&value)?);
        }
        Ok(())
    }

    /// Remove a value from the session.
    ///
    /// Ignored if the session is purged.
    pub fn remove(&self, key: &str) {
        let mut inner = self.0.borrow_mut();
        if inner.status != SessionStatus::Purged {
            inner.status = SessionStatus::Changed;
            inner.state.remove(key);
        }
    }

    /// Remove all values from the session.
    ///
    /// Ignored if the session is purged.
    pub fn clear(&self) {
        let mut inner = self.0.borrow_mut();
        if inner.status != SessionStatus::Purged {
            inner.status = SessionStatus::Changed;
            inner.state.clear()
        }
    }

    /// Remove the session, both client and server side.
    ///
    /// All values are dropped and later changes in the same request are
    /// ignored.
    pub fn purge(&self) {
        let mut inner = self.0.borrow_mut();
        inner.status = SessionStatus::Purged;
        inner.state.clear();
    }

    /// Renew the session key, assigning existing session state to the new key.
    ///
    /// Ignored if the session is purged.
    pub fn renew(&self) {
        let mut inner = self.0.borrow_mut();
        if inner.status != SessionStatus::Purged {
            inner.status = SessionStatus::Renewed;
        }
    }

    /// Load session state into the request.
    ///
    /// Used by session backends before calling the inner service. Values must
    /// be JSON encoded, as returned by [`Session::get_changes`].
    pub fn set_session<St>(data: impl Iterator<Item = (String, String)>, req: &WebRequest<St>) {
        let session = Session::get_session(&mut req.extensions_mut());
        let mut inner = session.0.borrow_mut();
        inner.state.extend(data);
    }

    /// Take the session status and state from the response's request.
    ///
    /// Used by session backends after the inner service returns. The state is
    /// moved out of the session. Returns `(SessionStatus::Unchanged, None)` if
    /// the session was never accessed.
    pub fn get_changes(
        res: &mut WebResponse,
    ) -> (
        SessionStatus,
        Option<impl Iterator<Item = (String, String)> + use<>>,
    ) {
        if let Some(s_impl) = res
            .request()
            .extensions()
            .get::<Rc<RefCell<SessionInner>>>()
        {
            let state = std::mem::take(&mut s_impl.borrow_mut().state);
            (s_impl.borrow().status.clone(), Some(state.into_iter()))
        } else {
            (SessionStatus::Unchanged, None)
        }
    }

    fn get_session(extensions: &mut Extensions) -> Session {
        if let Some(s_impl) = extensions.get::<Rc<RefCell<SessionInner>>>() {
            return Session(Rc::clone(s_impl));
        }
        let inner = Rc::new(RefCell::new(SessionInner::default()));
        extensions.insert(inner.clone());
        Session(inner)
    }
}

/// Extractor implementation for Session type.
///
/// ```rust
/// use ntex_session::Session;
/// use serde_json::error::Error as JsonError;
///
/// fn index(session: Session) -> Result<&'static str, JsonError> {
///     // access session data
///     if let Some(count) = session.get::<i32>("counter")? {
///         session.set("counter", count + 1)?;
///     } else {
///         session.set("counter", 1)?;
///     }
///
///     Ok("Welcome!")
/// }
/// # fn main() {}
/// ```
impl<St> FromRequest<St> for Session {
    type Error = Infallible;

    #[inline]
    async fn from_request(
        _: &St,
        req: &HttpRequest,
        _: &mut Payload,
    ) -> Result<Session, Infallible> {
        Ok(Session::get_session(&mut req.extensions_mut()))
    }
}

#[cfg(test)]
mod tests {
    use ntex::web::{HttpResponse, test};

    use super::*;

    #[test]
    fn session() {
        let req = test::TestRequest::default().to_srv_request();

        Session::set_session(
            vec![("key".to_string(), "\"value\"".to_string())].into_iter(),
            &req,
        );
        let session = Session::get_session(&mut req.extensions_mut());
        let res = session.get::<String>("key").unwrap();
        assert_eq!(res, Some("value".to_string()));

        session.set("key2", "value2".to_string()).unwrap();
        session.remove("key");

        let mut res = req.into_response(HttpResponse::Ok().build());
        let (_status, state) = Session::get_changes(&mut res);
        let changes: Vec<_> = state.unwrap().collect();
        assert_eq!(changes, [("key2".to_string(), "\"value2\"".to_string())]);
    }

    #[test]
    fn get_session() {
        let req = test::TestRequest::default().to_srv_request();

        Session::set_session(
            vec![("key".to_string(), "\"value\"".to_string())].into_iter(),
            &req,
        );

        let session = req.get_session();
        let res = session.get::<String>("key").unwrap();
        assert_eq!(res, Some("value".to_string()));
    }

    #[test]
    fn get_session_from_request_head() {
        let mut req = test::TestRequest::default().to_srv_request();

        Session::set_session(
            vec![("key".to_string(), "\"value\"".to_string())].into_iter(),
            &req,
        );

        let session = req.head_mut().get_session();
        let res = session.get::<String>("key").unwrap();
        assert_eq!(res, Some("value".to_string()));
    }

    #[test]
    fn purge_session() {
        let req = test::TestRequest::default().to_srv_request();
        let session = Session::get_session(&mut req.extensions_mut());
        assert_eq!(session.0.borrow().status, SessionStatus::Unchanged);
        session.purge();
        assert_eq!(session.0.borrow().status, SessionStatus::Purged);
    }

    #[test]
    fn renew_session() {
        let req = test::TestRequest::default().to_srv_request();
        let session = Session::get_session(&mut req.extensions_mut());
        assert_eq!(session.0.borrow().status, SessionStatus::Unchanged);
        session.renew();
        assert_eq!(session.0.borrow().status, SessionStatus::Renewed);
    }
}
