//! Deserializes a field from plain text.
use std::str;

use derive_more::{Deref, DerefMut};
use ntex::http::StatusCode;
use ntex::web::{DefaultError, HttpRequest, HttpResponse, WebResponseError};
use serde::de::DeserializeOwned;

use crate::form::{FieldReader, Limits, bytes::Bytes};
use crate::{Field, MultipartError};

/// Deserializes an in-memory field body from UTF-8 plain text using [`serde_plain`].
///
/// Supports strings, numbers, and other scalar values supported by `serde_plain`,
/// including unit enum variants. By default, a parsed content type must have
/// subtype `plain` or suffix `+plain`; its top-level type is not restricted.
/// Missing or unparseable content types are accepted as the plain-text default.
/// Configure the check with [`TextConfig`] in request app state.
///
/// The body must always be UTF-8: `charset` parameters are ignored, and no
/// transcoding or whitespace trimming is performed. Both total and memory
/// budgets apply.
///
/// # Errors
///
/// Media-type, UTF-8, and deserialization failures return [`MultipartError::Field`]
/// with a [`TextError`] rendered as a 400 response. Stream and budget errors from
/// [`Bytes`] propagate directly.
///
/// # Panics
///
/// Manual [`FieldReader::read_field`] calls inherit the parsed-disposition
/// precondition of [`Bytes`].
#[derive(Debug, Deref, DerefMut)]
pub struct Text<T: DeserializeOwned>(
    /// The value deserialized from the field's UTF-8 text.
    pub T,
);

impl<T: DeserializeOwned> Text<T> {
    /// Consumes the wrapper and returns the deserialized value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> FieldReader for Text<T>
where
    T: DeserializeOwned + 'static,
{
    async fn read_field<St>(
        st: &St,
        req: &HttpRequest,
        field: Field,
        limits: &mut Limits,
    ) -> Result<Self, MultipartError> {
        let config = req.app_state::<TextConfig>().unwrap_or(&DEFAULT_CONFIG);

        if config.validate_content_type {
            let valid = if let Some(mime) = field.content_type() {
                mime.subtype() == mime::PLAIN || mime.suffix() == Some(mime::PLAIN)
            } else {
                // https://datatracker.ietf.org/doc/html/rfc7578#section-4.4
                // content type defaults to text/plain, so None should be considered valid
                true
            };

            if !valid {
                return Err(MultipartError::Field {
                    name: field.form_field_name,
                    source: TextError::ContentType.error_response(st),
                });
            }
        }

        let form_field_name = field.form_field_name.clone();

        let bytes = Bytes::read_field(st, req, field, limits).await?;

        let text = str::from_utf8(&bytes.data).map_err(|err| MultipartError::Field {
            name: form_field_name.clone(),
            source: TextError::Utf8Error(err).error_response(st),
        })?;

        Ok(Text(serde_plain::from_str(text).map_err(|err| {
            MultipartError::Field {
                name: form_field_name,
                source: TextError::Deserialize(err).error_response(st),
            }
        })?))
    }
}

/// Plain-text field failures, rendered as 400 Bad Request responses.
///
/// [`Text`] stores the rendered response in [`MultipartError::Field`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TextError {
    /// The body is not valid UTF-8, regardless of its declared charset.
    #[error("UTF-8 decoding error: {}", _0)]
    Utf8Error(
        /// The UTF-8 validation failure.
        str::Utf8Error,
    ),

    /// The UTF-8 text could not be deserialized into the requested type.
    #[error("Plain text deserialize error: {}", _0)]
    Deserialize(
        /// The plain-text deserializer failure.
        serde_plain::Error,
    ),

    /// A parsed content type has neither subtype `plain` nor suffix `+plain`.
    #[error("Content type error")]
    ContentType,
}

/// Renders plain-text field errors with HTTP status 400 Bad Request.
impl<St> WebResponseError<St, DefaultError> for TextError {
    fn error_response(&self, _: &St) -> HttpResponse {
        HttpResponse::render_with(StatusCode::BAD_REQUEST, self)
    }
}

/// Configuration for [`Text`], registered with `App::app_state`.
///
/// Plain-text media-type validation is enabled by default; UTF-8 validation is
/// always performed.
#[derive(Clone)]
pub struct TextConfig {
    validate_content_type: bool,
}

impl TextConfig {
    /// Enables or disables plain-text media-type validation (enabled by default).
    ///
    /// When enabled, a parsed type must have subtype `plain` or suffix `+plain`.
    /// Missing, empty, or malformed headers are accepted because [`Field`] exposes
    /// them as no parsed type, which this reader treats as the plain-text default.
    /// Disabling this check does not disable UTF-8 validation or enable transcoding.
    pub fn validate_content_type(mut self, validate_content_type: bool) -> Self {
        self.validate_content_type = validate_content_type;
        self
    }
}

const DEFAULT_CONFIG: TextConfig = TextConfig {
    validate_content_type: true,
};

impl Default for TextConfig {
    fn default() -> Self {
        DEFAULT_CONFIG
    }
}
