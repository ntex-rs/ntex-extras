//! Multipart parsing and typed form errors.
use derive_more::{Display, Error, From};
use ntex::http::{StatusCode, error::DecodeError, error::PayloadError};
use ntex::rt::BlockingError;
use ntex::web::{HttpResponse, error::DefaultError, error::WebResponseError};

/// Failures while parsing multipart bodies or collecting typed form fields.
///
/// The default [`WebResponseError`] implementation renders variants as
/// 400 Bad Request, except [`Self::Field`], which uses its stored response's status,
/// [`Self::IncompatibleContentType`], which is 415 Unsupported Media Type, and
/// [`Self::Payload`] with [`PayloadError::Overflow`], which is 413 Payload Too Large.
#[derive(Debug, Display, From, Error)]
#[non_exhaustive]
pub enum MultipartError {
    /// The request has no `Content-Type` header.
    #[display("No Content-type header found")]
    NoContentType,

    /// The request `Content-Type` is not valid header text or cannot be parsed as a MIME type.
    #[display("Can not parse Content-Type header")]
    ParseContentType,

    /// The request is not `multipart/*`, or the typed extractor received a subtype
    /// other than `form-data`.
    #[display("Parsed Content-Type did not have 'multipart' top-level media type")]
    IncompatibleContentType,

    /// The request lacks a `boundary` parameter that follows RFC 2046 (1 to 70
    /// allowed characters, not ending with a space), or a body boundary/delimiter
    /// is malformed.
    #[display("Multipart boundary is not found")]
    Boundary,

    /// A `multipart/form-data` part has a missing, malformed, or non-`form-data`
    /// `Content-Disposition` header.
    #[display("Content-Disposition header was not found when parsing a \"form-data\" field")]
    ContentDispositionMissing,

    /// A `multipart/form-data` part has no `name` parameter in `Content-Disposition`.
    #[display("Content-Disposition header was not found when parsing a \"form-data\" field")]
    ContentDispositionNameMissing,

    /// A part has a parsed `multipart/*` content type; nested multipart is unsupported.
    #[display("Nested multipart is not supported")]
    Nested,

    /// The body ends before a required header block, field body, or delimiter is complete.
    #[display("Multipart stream is incomplete")]
    Incomplete,

    /// A typed form received more parts than its part limit.
    ///
    /// See [`MultipartFormConfig::max_parts`](crate::MultipartFormConfig::max_parts).
    #[display("Multipart form has too many parts")]
    TooManyParts,

    /// A part-header block could not be decoded, including more than 32 headers.
    #[display("{}", _0)]
    Decode(
        /// The header decoder failure.
        DecodeError,
    ),

    /// A body-stream failure, invalid part `Content-Length`, or byte-limit failure.
    ///
    /// [`PayloadError::Overflow`] covers reader budgets and the parser's 16 KiB
    /// limit on boundary/preamble lines and entire part-header blocks, including delimiters.
    #[display("{}", _0)]
    Payload(
        /// The payload failure, including `Overflow` when a limit is exceeded.
        PayloadError,
    ),

    /// A parent multipart parser was dropped while its field was still alive.
    #[display("Multipart stream is not consumed")]
    NotConsumed,

    /// A field reader failed with a reader-specific HTTP response.
    ///
    /// The outer error's default response uses the status of `source`, but not
    /// its headers or body.
    #[display("An error occurred processing field: {}", name)]
    Field {
        /// The multipart field name whose reader failed.
        name: String,
        /// The response rendered by the reader, retained for inspection or custom handling.
        source: HttpResponse,
    },

    /// A scalar field occurred again in a form configured to deny duplicates.
    ///
    /// Vector groups always accept repeated names.
    #[display("Duplicate field found: {}", _0)]
    #[from(ignore)]
    DuplicateField(
        /// The repeated multipart field name.
        #[error(not(source))]
        String,
    ),

    /// A required scalar field is missing when the typed form is assembled.
    #[display("Required field is missing: {}", _0)]
    #[from(ignore)]
    MissingField(
        /// The missing multipart field name.
        #[error(not(source))]
        String,
    ),

    /// A field name is not recognized by a form configured to deny unknown fields.
    #[display("Unknown field: {}", _0)]
    #[from(ignore)]
    UnknownField(
        /// The unrecognized multipart field name.
        #[error(not(source))]
        String,
    ),

    /// A blocking file-operation task failed to complete.
    Blocking(
        /// The blocking-task failure, distinct from the task's I/O result.
        #[error]
        #[from]
        BlockingError,
    ),
}

/// Renders multipart errors as 400 Bad Request.
///
/// A [`MultipartError::Field`] uses the status of its field response; the
/// field response's headers and body are not forwarded. A
/// [`MultipartError::IncompatibleContentType`] renders as 415 Unsupported Media
/// Type, and a [`MultipartError::Payload`] with [`PayloadError::Overflow`] renders
/// as 413 Payload Too Large.
impl<St> WebResponseError<St, DefaultError> for MultipartError {
    fn error_response(&self, _: &St) -> HttpResponse {
        let status = match self {
            MultipartError::Field { source, .. } => source.status(),
            MultipartError::IncompatibleContentType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            MultipartError::Payload(PayloadError::Overflow) => StatusCode::PAYLOAD_TOO_LARGE,
            _ => StatusCode::BAD_REQUEST,
        };
        HttpResponse::render_with(status, self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ntex::web::HttpResponse;

    #[test]
    fn test_multipart_error() {
        let resp: HttpResponse = MultipartError::Boundary.error_response(&());
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// STATEMENT: A field error is rendered with its field response's status.
    ///
    /// HOW:
    /// - Wrap a 500 response in `MultipartError::Field`.
    /// - Confirm `error_response` returns 500 instead of 400.
    #[test]
    fn field_error_keeps_field_status() {
        let err = MultipartError::Field {
            name: "file".to_string(),
            source: HttpResponse::InternalServerError().into(),
        };
        let resp: HttpResponse = err.error_response(&());
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// STATEMENT: Only a payload overflow is rendered as 413; other payload errors stay 400.
    ///
    /// HOW:
    /// - Render `MultipartError::Payload` with `PayloadError::Overflow` and confirm 413.
    /// - Render it with `PayloadError::Incomplete` and confirm 400.
    #[test]
    fn payload_overflow_is_payload_too_large() {
        let resp: HttpResponse =
            MultipartError::Payload(PayloadError::Overflow).error_response(&());
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let resp: HttpResponse =
            MultipartError::Payload(PayloadError::Incomplete(None)).error_response(&());
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// STATEMENT: Only an incompatible media type is rendered as 415; missing or
    /// unparsable content types stay 400.
    ///
    /// HOW:
    /// - Render `IncompatibleContentType` and confirm 415.
    /// - Render `NoContentType` and `ParseContentType` and confirm 400 for each.
    #[test]
    fn incompatible_content_type_is_unsupported_media_type() {
        let resp: HttpResponse = MultipartError::IncompatibleContentType.error_response(&());
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        for err in [
            MultipartError::NoContentType,
            MultipartError::ParseContentType,
        ] {
            let resp: HttpResponse = err.error_response(&());
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        }
    }
}
