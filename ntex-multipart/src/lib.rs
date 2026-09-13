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
pub use self::multipart_form::{MultipartCollect, MultipartForm};
