//! Error and Result module
use derive_more::{Display, Error, From};
use ntex::http::StatusCode;
use ntex::http::error::{DecodeError, PayloadError};
use ntex::web::error::{DefaultError, WebResponseError};

/// A set of errors that can occur during parsing multipart streams
#[derive(Debug, Display, From, Error)]
pub enum MultipartError {
    /// Content-Type header is not found
    #[display("No Content-type header found")]
    NoContentType,

    /// Can not parse Content-Type header
    #[display("Can not parse Content-Type header")]
    ParseContentType,

    /// Parsed Content-Type did not have "multipart" top-level media type.
    #[display("Parsed Content-Type did not have 'multipart' top-level media type")]
    IncompatibleContentType,

    /// Multipart boundary is not found
    #[display("Multipart boundary is not found")]
    Boundary,

    /// Content-Disposition header was not found or not of disposition type "form-data" when parsing
    /// a "form-data" field.
    #[display("Content-Disposition header was not found when parsing a \"form-data\" field")]
    ContentDispositionMissing,

    /// Content-Disposition name parameter was not found when parsing a "form-data" field.
    #[display("Content-Disposition header was not found when parsing a \"form-data\" field")]
    ContentDispositionNameMissing,

    /// Nested multipart is not supported
    #[display("Nested multipart is not supported")]
    Nested,

    /// Multipart stream is incomplete
    #[display("Multipart stream is incomplete")]
    Incomplete,

    /// Error during field parsing
    #[display("{}", _0)]
    Decode(DecodeError),

    /// Payload error
    #[display("{}", _0)]
    Payload(PayloadError),

    /// Not consumed
    #[display("Multipart stream is not consumed")]
    NotConsumed,

    /// Form field handler raised error.
    #[display("An error occurred processing field: {}", name)]
    Field { name: String, source: ntex::web::Error },

    /// Duplicate field found (for structure that opted-in to denying duplicate fields).
    #[display("Duplicate field found: {}", _0)]
    #[from(ignore)]
    DuplicateField(#[error(not(source))] String),

    /// Required field is missing.
    #[display("Required field is missing: {}", _0)]
    #[from(ignore)]
    MissingField(#[error(not(source))] String),

    /// Unknown field (for structure that opted-in to denying unknown fields).
    #[display("Unknown field: {}", _0)]
    #[from(ignore)]
    UnknownField(#[error(not(source))] String),
}

/// Return `BadRequest` for `MultipartError`
impl WebResponseError<DefaultError> for MultipartError {
    fn status_code(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ntex::web::HttpResponse;
    use ntex::web::test::TestRequest;

    #[test]
    fn test_multipart_error() {
        let req = TestRequest::default().to_http_request();
        let resp: HttpResponse = MultipartError::Boundary.error_response(&req);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
