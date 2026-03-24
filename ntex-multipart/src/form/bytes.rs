use futures::TryStreamExt;
use mime::Mime;
use ntex::{util, util::BytesMut, web::HttpRequest};

use crate::{Field, MultipartError, form::FieldReader, form::Limits};

/// Read the field into memory.
#[derive(Debug)]
pub struct Bytes {
    /// The data.
    pub data: util::Bytes,

    /// The value of the `Content-Type` header.
    pub content_type: Option<Mime>,

    /// The `filename` value in the `Content-Disposition` header.
    pub file_name: Option<String>,
}

impl FieldReader for Bytes {
    async fn read_field(
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
