//! Collects a field body as raw bytes in memory.

use futures::TryStreamExt;
use mime::Mime;
use ntex::{util, util::BytesMut, web::HttpRequest};

use crate::{Field, MultipartError, form::FieldReader, form::Limits};

/// Collects the complete field body in memory without interpreting its contents.
///
/// Debits both total and memory budgets, plus any field-specific budget.
/// Neither the content type nor the filename is required or validated by this reader.
///
/// # Errors
///
/// Returns stream errors or [`MultipartError::Payload`] containing
/// [`PayloadError::Overflow`](ntex::http::error::PayloadError::Overflow) when a
/// budget is exceeded.
///
/// # Panics
///
/// Calling [`FieldReader::read_field`] manually with a field whose
/// [`Field::content_disposition`] is `None` panics after reading its body.
/// The typed form extractor ensures a `form-data` disposition is present.
#[derive(Debug)]
pub struct Bytes {
    /// The complete field body, excluding multipart framing.
    pub data: util::Bytes,

    /// The parsed part `Content-Type`, or `None` if absent or invalid.
    pub content_type: Option<Mime>,

    /// The `filename` parameter from `Content-Disposition`, if present.
    ///
    /// This client-supplied value is not sanitized for use as a filesystem path.
    pub file_name: Option<String>,
}

impl FieldReader for Bytes {
    async fn read_field<St>(
        _: &St,
        _: &HttpRequest,
        mut field: Field,
        limits: &mut Limits,
    ) -> Result<Self, MultipartError> {
        let mut buf = BytesMut::with_capacity(131_072);

        while let Some(chunk) = field.try_next().await? {
            limits.try_consume_limits(chunk.len(), true)?;
            buf.extend(chunk);
        }

        Ok(Bytes {
            data: buf.freeze(),
            content_type: field.content_type().map(ToOwned::to_owned),
            file_name: field
                .content_disposition()
                .expect("multipart form fields should have a content-disposition header")
                .get_filename()
                .map(ToOwned::to_owned),
        })
    }
}
