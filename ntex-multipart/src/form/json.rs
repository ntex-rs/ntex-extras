//! Deserializes a field as JSON.

use derive_more::{Deref, DerefMut};
use ntex::http::StatusCode;
use ntex::web::{DefaultError, HttpRequest, HttpResponse, WebResponseError};
use serde::de::DeserializeOwned;

use crate::form::{FieldReader, Limits, bytes::Bytes};
use crate::{Field, MultipartError};

/// Deserializes an in-memory field body as JSON using [`serde_json`].
///
/// By default, a parsed part `Content-Type` is required and its subtype or
/// structured suffix must be `json` (for example, `application/json` or
/// `application/problem+json`). The top-level media type is not restricted and
/// charset parameters do not cause transcoding. Configure this check through
/// [`JsonConfig`] in request app state. Both total and memory budgets apply.
///
/// # Errors
///
/// Content-type and deserialization failures return [`MultipartError::Field`]
/// with a [`JsonFieldError`] rendered as a 400 response. Stream and budget errors
/// from [`Bytes`] propagate without being wrapped in a field error.
///
/// # Panics
///
/// Manual [`FieldReader::read_field`] calls inherit the parsed-disposition
/// precondition of [`Bytes`].
#[derive(Debug, Deref, DerefMut)]
pub struct Json<T: DeserializeOwned>(
    /// The deserialized JSON value.
    pub T,
);

impl<T: DeserializeOwned> Json<T> {
    /// Consumes the wrapper and returns the deserialized value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> FieldReader for Json<T>
where
    T: DeserializeOwned + 'static,
{
    async fn read_field<St>(
        st: &St,
        req: &HttpRequest,
        field: Field,
        limits: &mut Limits,
    ) -> Result<Self, MultipartError> {
        let config = req.app_state::<JsonConfig>().unwrap_or(&DEFAULT_CONFIG);

        if config.validate_content_type {
            let valid = if let Some(mime) = field.content_type() {
                mime.subtype() == mime::JSON || mime.suffix() == Some(mime::JSON)
            } else {
                false
            };

            if !valid {
                return Err(MultipartError::Field {
                    name: field.form_field_name,
                    source: JsonFieldError::ContentType.error_response(st),
                });
            }
        }

        let form_field_name = field.form_field_name.clone();

        let bytes = Bytes::read_field(st, req, field, limits).await?;

        Ok(Json(serde_json::from_slice(bytes.data.as_ref()).map_err(
            |err| MultipartError::Field {
                name: form_field_name,
                source: JsonFieldError::Deserialize(err).error_response(st),
            },
        )?))
    }
}

/// JSON-specific field failures, rendered as 400 Bad Request responses.
///
/// [`Json`] stores the rendered response in [`MultipartError::Field`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JsonFieldError {
    /// The field body could not be deserialized into the requested JSON type.
    #[error("Json deserialize error: {:?}", _0)]
    Deserialize(
        /// The JSON parser or deserializer failure.
        serde_json::Error,
    ),

    /// The parsed content type is missing, or neither its subtype nor suffix is `json`.
    #[error("Content type error")]
    ContentType,
}

/// Renders JSON field errors with HTTP status 400 Bad Request.
impl<St> WebResponseError<St, DefaultError> for JsonFieldError {
    fn error_response(&self, _: &St) -> HttpResponse {
        HttpResponse::render_with(StatusCode::BAD_REQUEST, self)
    }
}

/// Configuration for [`Json`], registered with `App::app_state`.
///
/// Content-type validation is enabled by default.
#[derive(Clone)]
pub struct JsonConfig {
    validate_content_type: bool,
}

const DEFAULT_CONFIG: JsonConfig = JsonConfig {
    validate_content_type: true,
};

impl JsonConfig {
    /// Enables or disables JSON media-type validation (enabled by default).
    ///
    /// When enabled, the parsed `Content-Type` must have subtype `json` or suffix
    /// `+json`; no top-level type is required. Missing or malformed headers fail.
    /// Disabling this check does not change JSON deserialization or charset handling.
    pub fn validate_content_type(mut self, validate_content_type: bool) -> Self {
        self.validate_content_type = validate_content_type;
        self
    }
}

impl Default for JsonConfig {
    fn default() -> Self {
        DEFAULT_CONFIG
    }
}
