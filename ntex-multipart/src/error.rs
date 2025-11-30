//! Error and Result module
use derive_more::{Display, From};
use ntex::http::StatusCode;
use ntex::http::error::{DecodeError, PayloadError};
use ntex::web::error::{DefaultError, WebResponseError};

/// A set of errors that can occur during parsing multipart streams
#[derive(Debug, Display, From)]
pub enum MultipartError {
    /// Content-Type header is not found
    #[display("No Content-type header found")]
    NoContentType,
    /// Can not parse Content-Type header
    #[display("Can not parse Content-Type header")]
    ParseContentType,
    /// Multipart boundary is not found
    #[display("Multipart boundary is not found")]
    Boundary,
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
}

impl std::error::Error for MultipartError {}

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
