//! Multipart payload support
use std::convert::Infallible;

use futures::TryStreamExt;
use ntex::web::{AppState, FromRequest, HttpRequest, WebResponseError};
use ntex::{http::Payload, util::HashMap};

#[cfg(feature = "form")]
use {
    crate::form::{Limits, State},
    crate::multipart_form::MultipartFormConfig,
    crate::{MultipartCollect, MultipartError, MultipartForm},
};

use crate::multipart::Multipart;

/// Get request's payload as multipart stream
///
/// Content-type: multipart/form-data;
///
/// ## Server example
///
/// ```rust
/// use futures::{Stream, StreamExt};
/// use ntex::web::{self, HttpResponse};
/// use ntex_multipart as mp;
///
/// async fn index(mut payload: mp::Multipart) -> Result<HttpResponse, mp::MultipartError> {
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
impl<St> FromRequest<St> for Multipart {
    type Error = Infallible;

    #[inline]
    async fn from_request(
        _: &St,
        req: &HttpRequest,
        payload: &mut Payload,
    ) -> Result<Self, Self::Error> {
        Ok(Multipart::new(req.headers(), payload.take()))
    }
}

#[cfg(feature = "form")]
impl<T, St> FromRequest<St> for MultipartForm<T>
where
    T: MultipartCollect + 'static,
    St: AppState,
    MultipartError: WebResponseError<St, St::Error>,
{
    type Error = MultipartError;

    #[inline]
    async fn from_request(
        _: &St,
        req: &HttpRequest,
        payload: &mut Payload,
    ) -> Result<Self, Self::Error> {
        let mut multipart = Multipart::new(req.headers(), payload.take());

        let content_type = match multipart.content_type() {
            Ok(content_type) => content_type,
            Err(err) => return Err(err),
        };

        if content_type.subtype() != mime::FORM_DATA {
            // this extractor only supports multipart/form-data
            return Err(MultipartError::IncompatibleContentType);
        };

        let config = MultipartFormConfig::from_req(req);
        let mut limits = Limits::new(config.total_limit, config.memory_limit);
        let mut state = State::default();

        // ensure limits are shared for all fields with this name
        let mut field_limits = HashMap::<String, Option<usize>>::default();

        while let Some(field) = multipart.try_next().await? {
            debug_assert!(
                !field.form_field_name.is_empty(),
                "multipart form fields should have names",
            );

            // Retrieve the limit for this field
            let entry = field_limits
                .entry(field.form_field_name.clone())
                .or_insert_with(|| T::limit(&field.form_field_name));

            limits.field_limit_remaining.clone_from(entry);

            T::handle_field(req, field, &mut limits, &mut state).await?;

            // Update the stored limit
            *entry = limits.field_limit_remaining;
        }

        let inner = T::from_state(state)?;
        Ok(MultipartForm(inner))
    }
}
