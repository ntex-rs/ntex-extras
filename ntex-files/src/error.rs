use ntex::http::StatusCode;
use ntex::web::{HttpResponse, error::DefaultError, error::WebResponseError};

/// Errors which can occur when serving static files.
#[derive(Debug, thiserror::Error)]
pub enum FilesError {
    /// The configured path is not a directory.
    #[allow(dead_code)]
    #[error("Path is not a directory. Unable to serve static files.")]
    IsNotDirectory,

    /// A directory was requested but directory listings are disabled.
    #[error("Unable to render directory without index file.")]
    IsDirectory,

    /// The request failed the configured guard or default `GET`/`HEAD` check.
    #[error("Request did not meet this resource's requirements.")]
    MethodNotAllowed,

    /// A decoded URL segment contains a rejected character.
    #[error("{}", _0)]
    Uri(#[from] UriSegmentError),

    /// File resolution, opening, or directory rendering failed.
    #[error("Error reading: {}", _0)]
    Io(#[from] std::io::Error),
}

/// Maps URL errors to `400`, rejected guards to `405`, and other file errors to `404`.
impl<St> WebResponseError<St, DefaultError> for FilesError {
    fn error_response(&self, _: &St) -> HttpResponse {
        match self {
            FilesError::Uri(_) => HttpResponse::render_with(StatusCode::BAD_REQUEST, self),
            FilesError::MethodNotAllowed => {
                HttpResponse::render_with(StatusCode::METHOD_NOT_ALLOWED, self)
            }
            _ => HttpResponse::render_with(StatusCode::NOT_FOUND, self),
        }
    }
}

/// A character rejected while validating a percent-decoded URL path segment.
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

/// Returns `400 Bad Request` for a rejected URL segment.
impl<St> WebResponseError<St, DefaultError> for UriSegmentError {
    fn error_response(&self, _: &St) -> HttpResponse {
        HttpResponse::render_with(StatusCode::BAD_REQUEST, self)
    }
}
