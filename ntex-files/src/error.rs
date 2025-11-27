use derive_more::{Display, From};
use ntex::http::StatusCode;
use ntex::web::error::{DefaultError, WebResponseError};

/// Errors which can occur when serving static files.
#[derive(Display, Debug, From)]
pub enum FilesError {
    /// Path is not a directory
    #[allow(dead_code)]
    #[display("Path is not a directory. Unable to serve static files.")]
    IsNotDirectory,

    /// Cannot render directory
    #[display("Unable to render directory without index file.")]
    IsDirectory,

    /// Only GET and HEAD methods are allowed
    #[display("Request did not meet this resource's requirements.")]
    MethodNotAllowed,

    /// Uri segments parsing error
    #[display("{}", _0)]
    Uri(UriSegmentError),

    /// IO Error
    #[display("Error reading: {}", _0)]
    Io(std::io::Error),
}

/// Return `NotFound` for `FilesError`
impl WebResponseError<DefaultError> for FilesError {
    fn status_code(&self) -> StatusCode {
        match self {
            FilesError::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
            FilesError::Uri(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::NOT_FOUND,
        }
    }
}

#[derive(Display, Debug, PartialEq, Eq)]
pub enum UriSegmentError {
    /// The segment started with the wrapped invalid character.
    #[display("The segment started with the wrapped invalid character")]
    BadStart(char),
    /// The segment contained the wrapped invalid character.
    #[display("The segment contained the wrapped invalid character")]
    BadChar(char),
    /// The segment ended with the wrapped invalid character.
    #[display("The segment ended with the wrapped invalid character")]
    BadEnd(char),
}

/// Return `BadRequest` for `UriSegmentError`
impl WebResponseError<DefaultError> for UriSegmentError {
    fn status_code(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }
}
