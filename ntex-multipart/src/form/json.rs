//! Deserializes a field as JSON.

use crate::{
    Field, MultipartError,
    form::{FieldReader, Limits, bytes::Bytes},
};
use derive_more::{Deref, DerefMut, Display};
use futures::future::LocalBoxFuture;
use ntex::http::StatusCode;
use ntex::web::{DefaultError, HttpRequest, WebResponseError};
use serde::de::DeserializeOwned;

/// Deserialize from JSON.
#[derive(Debug, Deref, DerefMut)]
pub struct Json<T: DeserializeOwned>(pub T);

impl<T: DeserializeOwned> Json<T> {
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<'t, T> FieldReader<'t> for Json<T>
where
    T: DeserializeOwned + 'static,
{
    type Future = LocalBoxFuture<'t, Result<Self, MultipartError>>;

    fn read_field(req: &'t HttpRequest, field: Field, limits: &'t mut Limits) -> Self::Future {
        Box::pin(async move {
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
                        source: JsonFieldError::ContentType.into(),
                    });
                }
            }

            let form_field_name = field.form_field_name.clone();

            let bytes = Bytes::read_field(req, field, limits).await?;

            Ok(Json(serde_json::from_slice(bytes.data.as_ref()).map_err(|err| {
                MultipartError::Field {
                    name: form_field_name,
                    source: JsonFieldError::Deserialize(err).into(),
                }
            })?))
        })
    }
}

#[derive(Debug, Display)]
#[non_exhaustive]
pub enum JsonFieldError {
    /// Deserialize error.
    #[display("Json deserialize error: {:?}", _0)]
    Deserialize(serde_json::Error),

    /// Content type error.
    #[display("Content type error")]
    ContentType,
}

/// Return `BadRequest` for `JsonFieldError`
impl WebResponseError<DefaultError> for JsonFieldError {
    fn status_code(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }
}

/// Configuration for the [`Json`] field reader.
#[derive(Clone)]
pub struct JsonConfig {
    validate_content_type: bool,
}

const DEFAULT_CONFIG: JsonConfig = JsonConfig { validate_content_type: true };

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
