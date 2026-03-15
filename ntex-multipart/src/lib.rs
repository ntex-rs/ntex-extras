#![allow(dead_code, clippy::borrow_interior_mutable_const)]

mod error;
mod extractor;
pub(crate) mod field;
#[cfg(feature = "form")]
pub mod form;
mod multipart;
#[cfg(feature = "form")]
mod multipart_form;
pub(crate) mod payload;
pub(crate) mod safety;

pub use self::error::MultipartError;
pub use self::field::Field;
pub use self::multipart::Multipart;
#[cfg(feature = "form")]
pub use self::multipart_form::{MultipartCollect, MultipartForm};
