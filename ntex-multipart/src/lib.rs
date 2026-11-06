//! Streaming and typed extraction of multipart request bodies for `ntex`.
//!
//! # Streaming fields
//!
//! [`Multipart`] is a [`Stream`](futures::Stream) of [`Field`] values; each field is
//! a stream of body chunks. It accepts any `multipart/*` media type with a boundary,
//! but rejects nested multipart fields. For `multipart/form-data`, each part must
//! have a `Content-Disposition: form-data` header with a `name` parameter.
//!
//! Read and drop each field before requesting the next one. Dropping an unread
//! field lets the parent drain its remaining data. Keeping a field alive prevents
//! the parent stream from advancing, even after that field has reached EOF.
//!
//! ```
//! use futures::{stream, TryStreamExt};
//! use ntex::{http::{header, HeaderMap}, util::Bytes};
//! use ntex_multipart::Multipart;
//!
//! # fn main() -> Result<(), ntex_multipart::MultipartError> {
//! # futures::executor::block_on(async {
//! let mut headers = HeaderMap::new();
//! headers.insert(header::CONTENT_TYPE,
//!     "multipart/form-data; boundary=upload".parse().unwrap());
//! let body = Bytes::from_static(
//!     b"--upload\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nhello\r\n--upload--"
//! );
//! let mut multipart = Multipart::new(&headers, stream::iter([Ok(body)]));
//! while let Some(mut field) = multipart.try_next().await? {
//!     assert_eq!(field.name(), Some("title"));
//!     let mut data = Vec::new();
//!     while let Some(chunk) = field.try_next().await? {
//!         data.extend_from_slice(&chunk);
//!     }
//!     assert_eq!(data, b"hello");
//! } // `field` is dropped before the next iteration.
//! # Ok(())
//! # })
//! # }
//! ```
//!
//! # Typed forms
//!
//! Enable the `derive` feature and derive `MultipartForm` for a named-field struct,
//! then extract it with [`MultipartForm<T>`](struct@MultipartForm).
//! [`Text`](form::text::Text), [`Json`](form::json::Json), and
//! [`Bytes`](form::bytes::Bytes) read field bodies into memory;
//! [`TempFile`](form::temp_file::TempFile) writes them to disk. Use `Option<T>` for
//! optional fields and `Vec<T>` for repeated fields in their arrival order.
//!
//! ```
//! # #[cfg(feature = "derive")]
//! # fn main() -> Result<(), ntex_multipart::MultipartError> {
//! use ntex::web::{FromRequest, test::TestRequest};
//! use ntex_multipart::{MultipartForm, MultipartFormConfig};
//! use ntex_multipart::form::{bytes::Bytes, json::Json, temp_file::TempFile, text::Text};
//!
//! #[derive(MultipartForm)]
//! #[multipart(deny_unknown_fields, duplicate_field = "deny")]
//! struct Upload {
//!     #[multipart(limit = "2 KiB")]
//!     title: Text<String>,
//!     metadata: Json<Vec<u32>>,
//!     attachment: Option<Bytes>,
//!     #[multipart(rename = "files[]", limit = "10 MiB")]
//!     files: Vec<TempFile>,
//! }
//!
//! # futures::executor::block_on(async {
//! let config = MultipartFormConfig::default()
//!     .total_limit(20 * 1024 * 1024)
//!     .memory_limit(1024 * 1024);
//! let (req, mut payload, ()) = TestRequest::post()
//!     .app_state(config)
//!     .header("content-type", "multipart/form-data; boundary=upload")
//!     .payload(concat!(
//!         "--upload\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nhello\r\n",
//!         "--upload\r\nContent-Disposition: form-data; name=\"metadata\"\r\n",
//!         "Content-Type: application/json\r\n\r\n[1,2]\r\n--upload--"
//!     ))
//!     .to_http_parts();
//! let upload = MultipartForm::<Upload>::from_request(&(), &req, &mut payload).await?;
//! assert_eq!(&*upload.title, "hello");
//! assert_eq!(&*upload.metadata, &[1, 2]);
//! assert!(upload.attachment.is_none());
//! assert!(upload.files.is_empty());
//! # Ok(())
//! # })
//! # }
//! # #[cfg(not(feature = "derive"))]
//! # fn main() {}
//! ```
//!
//! [`MultipartFormConfig`] defaults to 50 MiB of total field-body data and 2 MiB
//! of field-body data read into memory. Readers debit these budgets through
//! [`Limits`](form::Limits); framing, headers, and ignored fields are not counted.
//! These are byte-accounting limits, not caps on the parser's buffering or on
//! deserialized allocations. A derived `#[multipart(limit = "...")]` budget is
//! shared by all processed occurrences of the same field name. Unknown fields and
//! duplicate scalar fields are ignored by default; the derive attributes can
//! reject them, or replace scalar fields with the last occurrence. See the
//! [derive documentation](https://docs.rs/ntex-multipart-derive/latest/ntex_multipart_derive/derive.MultipartForm.html)
//! for all supported attributes.
//!
//! The streaming parser separately limits boundary/preamble lines and each entire
//! part-header block to 16 KiB, including their delimiters, with at most 32 headers
//! per part. An oversized line or header block yields
//! [`MultipartError::Payload`] containing [`PayloadError::Overflow`](ntex::http::error::PayloadError::Overflow),
//! regardless of how the input is chunked. In boundary-delimited field data, a
//! boundary match must be followed by CRLF or `--`; other matching prefixes remain
//! data. A closing boundary is accepted without a trailing CRLF.

#![allow(dead_code, async_fn_in_trait, clippy::borrow_interior_mutable_const)]

mod error;
mod extractor;
pub(crate) mod field;
pub mod form;
mod multipart;
mod multipart_form;
pub(crate) mod payload;
pub(crate) mod safety;

pub use self::error::MultipartError;
pub use self::field::Field;
pub use self::multipart::Multipart;
pub use self::multipart_form::{MultipartCollect, MultipartForm, MultipartFormConfig};
