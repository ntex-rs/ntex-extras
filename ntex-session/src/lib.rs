//! User sessions.
//!
//! Actix provides a general solution for session management. Session
//! middlewares could provide different implementations which could
//! be accessed via general session api.
//!
//! By default, only cookie session backend is implemented. Other
//! backend implementations can be added.
//!
//! In general, you insert a *session* middleware and initialize it
//! , such as a `CookieSessionBackend`. To access session data,
//! [*Session*](struct.Session.html) extractor must be used. Session
//! extractor allows us to get or set session data.
//!
//! ```rust,no_run
//! use ntex::web::{self, App, HttpResponse, Error};
//! use ntex_session::{Session, CookieSession};
//!
//! fn index(session: Session) -> Result<&'static str, Error> {
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
//!         async || App::new().wrap(
//!               CookieSession::signed(&[0; 32]) // <- create cookie based session middleware
//!                     .secure(false)
//!              )
//!             .service(web::resource("/").to(|| async { HttpResponse::Ok() })))
//!         .bind("127.0.0.1:59880")?
//!         .run()
//!         .await
//! }
//! ```
use std::cell::RefCell;
use std::collections::HashMap;
use std::convert::Infallible;
use std::rc::Rc;

use ntex::http::{Payload, RequestHead};
use ntex::util::Extensions;
use ntex::web::{Error, FromRequest, HttpRequest, WebRequest, WebResponse};
use serde::Serialize;
use serde::de::DeserializeOwned;

#[cfg(feature = "cookie-session")]
mod cookie;
#[cfg(feature = "cookie-session")]
pub use crate::cookie::CookieSession;

/// The high-level interface you use to modify session data.
///
/// Session object could be obtained with
/// [`RequestSession::session`](trait.RequestSession.html#tymethod.session)
/// method. `RequestSession` trait is implemented for `HttpRequest`.
///
/// ```rust
/// use ntex_session::Session;
/// use ntex::web::*;
///
/// fn index(session: Session) -> Result<&'static str, Error> {
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

/// Helper trait that allows to get session
pub trait UserSession {
    fn get_session(&self) -> Session;
}

impl UserSession for HttpRequest {
    fn get_session(&self) -> Session {
        Session::get_session(&mut self.extensions_mut())
    }
}

impl<Err> UserSession for WebRequest<Err> {
    fn get_session(&self) -> Session {
        Session::get_session(&mut self.extensions_mut())
    }
}

impl UserSession for RequestHead {
    fn get_session(&self) -> Session {
        Session::get_session(&mut self.extensions_mut())
    }
}

#[derive(PartialEq, Clone, Debug)]
pub enum SessionStatus {
    Changed,
    Purged,
    Renewed,
    Unchanged,
}

/// #[default] macro can be used but will depend on specific rust version
impl Default for SessionStatus {
    fn default() -> SessionStatus {
        SessionStatus::Unchanged
    }
}

#[derive(Default)]
struct SessionInner {
    state: HashMap<String, String>,
    pub status: SessionStatus,
}

impl Session {
    /// Get a `value` from the session.
    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Result<Option<T>, Error> {
        if let Some(s) = self.0.borrow().state.get(key) {
            Ok(Some(serde_json::from_str(s)?))
        } else {
            Ok(None)
        }
    }

    /// Set a `value` from the session.
    pub fn set<T: Serialize>(&self, key: &str, value: T) -> Result<(), Error> {
        let mut inner = self.0.borrow_mut();
        if inner.status != SessionStatus::Purged {
            inner.status = SessionStatus::Changed;
            inner.state.insert(key.to_owned(), serde_json::to_string(&value)?);
        }
        Ok(())
    }

    /// Remove value from the session.
    pub fn remove(&self, key: &str) {
        let mut inner = self.0.borrow_mut();
        if inner.status != SessionStatus::Purged {
            inner.status = SessionStatus::Changed;
            inner.state.remove(key);
        }
    }

    /// Clear the session.
    pub fn clear(&self) {
        let mut inner = self.0.borrow_mut();
        if inner.status != SessionStatus::Purged {
            inner.status = SessionStatus::Changed;
            inner.state.clear()
        }
    }

    /// Removes session, both client and server side.
    pub fn purge(&self) {
        let mut inner = self.0.borrow_mut();
        inner.status = SessionStatus::Purged;
        inner.state.clear();
    }

    /// Renews the session key, assigning existing session state to new key.
    pub fn renew(&self) {
        let mut inner = self.0.borrow_mut();
        if inner.status != SessionStatus::Purged {
            inner.status = SessionStatus::Renewed;
        }
    }

    pub fn set_session<Err>(
        data: impl Iterator<Item = (String, String)>,
        req: &WebRequest<Err>,
    ) {
        let session = Session::get_session(&mut req.extensions_mut());
        let mut inner = session.0.borrow_mut();
        inner.state.extend(data);
    }

    pub fn get_changes(
        res: &mut WebResponse,
    ) -> (SessionStatus, Option<impl Iterator<Item = (String, String)> + use<>>) {
        if let Some(s_impl) = res.request().extensions().get::<Rc<RefCell<SessionInner>>>() {
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
///
/// fn index(session: Session) -> Result<&'static str, ntex::web::Error> {
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
impl<Err> FromRequest<Err> for Session {
    type Error = Infallible;

    #[inline]
    async fn from_request(req: &HttpRequest, _: &mut Payload) -> Result<Session, Infallible> {
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

        let mut res = req.into_response(HttpResponse::Ok().finish());
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
