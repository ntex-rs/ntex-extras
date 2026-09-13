//! Deserializes a field as JSON.

use derive_more::{Deref, DerefMut};
use ntex::http::StatusCode;
use ntex::web::{DefaultError, HttpRequest, HttpResponse, WebResponseError};
use serde::de::DeserializeOwned;

use crate::form::{FieldReader, Limits, bytes::Bytes};
use crate::{Field, MultipartError};

/// Deserialize from JSON.
#[derive(Debug, Deref, DerefMut)]
pub struct Json<T: DeserializeOwned>(pub T);

impl<T: DeserializeOwned> Json<T> {
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

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JsonFieldError {
    /// Deserialize error.
    #[error("Json deserialize error: {:?}", _0)]
    Deserialize(serde_json::Error),

    /// Content type error.
    #[error("Content type error")]
    ContentType,
}

/// Return `BadRequest` for `JsonFieldError`
impl<St> WebResponseError<St, DefaultError> for JsonFieldError {
    fn error_response(&mut self, _: &St) -> HttpResponse {
        HttpResponse::render_with(StatusCode::BAD_REQUEST, self)
    }
}

/// Configuration for the [`Json`] field reader.
#[derive(Clone)]
pub struct JsonConfig {
    validate_content_type: bool,
}

const DEFAULT_CONFIG: JsonConfig = JsonConfig {
    validate_content_type: true,
};

impl JsonConfig {
    /// Sets whether or not the field must have a valid `Content-Type` header to be parsed.
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
