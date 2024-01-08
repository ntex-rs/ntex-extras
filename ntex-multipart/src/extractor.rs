//! Multipart payload support
use std::convert::Infallible;

use ntex::http::Payload;
use ntex::web::{FromRequest, HttpRequest};

use crate::server::Multipart;

/// Get request's payload as multipart stream
///
/// Content-type: multipart/form-data;
///
/// ## Server example
///
/// ```rust
/// use futures::{Stream, StreamExt};
/// use ntex::web::{self, HttpResponse, Error};
/// use ntex_multipart as mp;
///
/// async fn index(mut payload: mp::Multipart) -> Result<HttpResponse, Error> {
///     // iterate over multipart stream
///     while let Some(item) = payload.next().await {
///            let mut field = item?;
///
///            // Field in turn is stream of *Bytes* object
///            while let Some(chunk) = field.next().await {
///                println!("-- CHUNK: \n{:?}", std::str::from_utf8(&chunk?));
///            }
///     }
///     Ok(HttpResponse::Ok().into())
/// }
/// # fn main() {}
/// ```
impl<Err> FromRequest<Err> for Multipart {
    type Error = Infallible;

    #[inline]
    async fn from_request(
        req: &HttpRequest,
        payload: &mut Payload,
    ) -> Result<Multipart, Infallible> {
        Ok(Multipart::new(req.headers(), payload.take()))
    }
}
