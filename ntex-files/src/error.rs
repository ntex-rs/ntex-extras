use ntex::http::StatusCode;
use ntex::web::{HttpResponse, error::DefaultError, error::WebResponseError};

/// Errors which can occur when serving static files.
#[derive(Debug, thiserror::Error)]
pub enum FilesError {
    /// Path is not a directory
    #[allow(dead_code)]
    #[error("Path is not a directory. Unable to serve static files.")]
    IsNotDirectory,

    /// Cannot render directory
    #[error("Unable to render directory without index file.")]
    IsDirectory,

    /// Only GET and HEAD methods are allowed
    #[error("Request did not meet this resource's requirements.")]
    MethodNotAllowed,

    /// Uri segments parsing error
    #[error("{}", _0)]
    Uri(#[from] UriSegmentError),

    /// IO Error
    #[error("Error reading: {}", _0)]
    Io(#[from] std::io::Error),
}

/// Return `NotFound` for `FilesError`
impl<St> WebResponseError<St, DefaultError> for FilesError {
    fn error_response(&mut self, _: &St) -> HttpResponse {
        match self {
            FilesError::Uri(_) => HttpResponse::render_with(StatusCode::BAD_REQUEST, self),
            FilesError::MethodNotAllowed => {
                HttpResponse::render_with(StatusCode::METHOD_NOT_ALLOWED, self)
            }
            _ => HttpResponse::render_with(StatusCode::NOT_FOUND, self),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum UriSegmentError {
    /// The segment started with the wrapped invalid character.
    #[error("The segment started with the wrapped invalid character")]
    BadStart(char),
    /// The segment contained the wrapped invalid character.
    #[error("The segment contained the wrapped invalid character")]
    BadChar(char),
    /// The segment ended with the wrapped invalid character.
    #[error("The segment ended with the wrapped invalid character")]
    BadEnd(char),
}

/// Return `BadRequest` for `UriSegmentError`
impl<St> WebResponseError<St, DefaultError> for UriSegmentError {
    fn error_response(&mut self, _: &St) -> HttpResponse {
        HttpResponse::render_with(StatusCode::BAD_REQUEST, self)
    }
}
