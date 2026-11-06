//! Multipart payload support
use std::convert::Infallible;

use futures::TryStreamExt;
use ntex::web::{self, FromRequest, HttpRequest, WebResponseError};
use ntex::{http::Payload, util::HashMap};

use crate::form::{Limits, State};
use crate::multipart::Multipart;
use crate::{MultipartCollect, MultipartError, MultipartForm, multipart_form::MultipartFormConfig};

/// Takes the request payload as a streaming [`Multipart`] parser.
///
/// Extraction itself is infallible: request-header errors appear as the first
/// stream item. All `multipart/*` request subtypes are accepted, but nested parts
/// are not supported.
///
/// ```
/// use futures::TryStreamExt;
/// use ntex::web::HttpResponse;
/// use ntex_multipart::{Multipart, MultipartError};
///
/// async fn upload(mut body: Multipart) -> Result<HttpResponse, MultipartError> {
///     while let Some(mut field) = body.try_next().await? {
///         while let Some(chunk) = field.try_next().await? {
///             // Process each chunk without collecting the whole field.
///             println!("received {} bytes", chunk.len());
///         }
///     }
///     Ok(HttpResponse::Ok().into())
/// }
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

/// Reads and collects a complete `multipart/form-data` body using request app-state configuration.
///
/// # Errors
///
/// Returns request-header, parsing, reader, limit, and form-assembly errors.
/// Other multipart subtypes return [`MultipartError::IncompatibleContentType`].
impl<T, St> FromRequest<St> for MultipartForm<T>
where
    T: MultipartCollect + 'static,
    St: web::State,
    MultipartError: WebResponseError<St, St::Error>,
{
    type Error = MultipartError;

    #[inline]
    async fn from_request(
        st: &St,
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
            // Retrieve the limit for this field
            let entry = field_limits
                .entry(field.form_field_name.clone())
                .or_insert_with(|| T::limit(&field.form_field_name));

            limits.field_limit_remaining.clone_from(entry);

            T::handle_field(st, req, field, &mut limits, &mut state).await?;

            // Update the stored limit
            *entry = limits.field_limit_remaining;
        }

        let inner = T::from_state(state)?;
        Ok(MultipartForm(inner))
    }
}
