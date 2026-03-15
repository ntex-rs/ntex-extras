use crate::form::Limits;
use crate::form::State;
use crate::{Field, MultipartError};
use derive_more::{Deref, DerefMut};
use futures::future::LocalBoxFuture;
use ntex::web::{Error, HttpRequest};
use std::sync::Arc;

#[cfg(feature = "derive")]
pub use ntex_multipart_derive::MultipartForm;

/// Trait that allows a type to be used in the [`struct@MultipartForm`] extractor.
///
/// You should use the [`macro@MultipartForm`] macro to derive this for your struct.
pub trait MultipartCollect: Sized {
    /// An optional limit in bytes to be applied a given field name. Note this limit will be shared
    /// across all fields sharing the same name.
    fn limit(field_name: &str) -> Option<usize>;

    /// The extractor will call this function for each incoming field, the state can be updated
    /// with the processed field data.
    fn handle_field<'t>(
        req: &'t HttpRequest,
        field: Field,
        limits: &'t mut Limits,
        state: &'t mut State,
    ) -> LocalBoxFuture<'t, Result<(), MultipartError>>;

    /// Once all the fields have been processed and stored in the state, this is called
    /// to convert into the struct representation.
    fn from_state(state: State) -> Result<Self, MultipartError>;
}

/// Typed `multipart/form-data` extractor.
///
/// To extract typed data from a multipart stream, the inner type `T` must implement the
/// [`MultipartCollect`] trait. You should use the [`macro@MultipartForm`] macro to derive this
/// for your struct.
///
/// Note that this extractor rejects requests with any other Content-Type such as `multipart/mixed`,
/// `multipart/related`, or non-multipart media types.
///
/// Add a [`MultipartFormConfig`] to your app data to configure extraction.
#[derive(Deref, DerefMut)]
pub struct MultipartForm<T: MultipartCollect>(pub T);

impl<T: MultipartCollect> MultipartForm<T> {
    /// Unwrap into inner `T` value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

type MultipartFormErrorHandler =
    Option<Arc<dyn Fn(MultipartError, &HttpRequest) -> Error + Send + Sync>>;

/// [`struct@MultipartForm`] extractor configuration.
///
/// Add to your app data to have it picked up by [`struct@MultipartForm`] extractors.
#[derive(Clone)]
pub struct MultipartFormConfig {
    pub(crate) total_limit: usize,
    pub(crate) memory_limit: usize,
    pub(crate) err_handler: MultipartFormErrorHandler,
}

impl MultipartFormConfig {
    /// Sets maximum accepted payload size for the entire form. By default this limit is 50MiB.
    pub fn total_limit(mut self, total_limit: usize) -> Self {
        self.total_limit = total_limit;
        self
    }

    /// Sets maximum accepted data that will be read into memory. By default this limit is 2MiB.
    pub fn memory_limit(mut self, memory_limit: usize) -> Self {
        self.memory_limit = memory_limit;
        self
    }

    /// Extracts payload config from app data. Check both `T` and `Data<T>`, in that order, and fall
    /// back to the default payload config.
    pub(crate) fn from_req(req: &HttpRequest) -> &Self {
        req.app_state::<Self>().unwrap_or(&DEFAULT_CONFIG)
    }
}

const DEFAULT_CONFIG: MultipartFormConfig = MultipartFormConfig {
    total_limit: 52_428_800, // 50 MiB
    memory_limit: 2_097_152, // 2 MiB
    err_handler: None,
};

impl Default for MultipartFormConfig {
    fn default() -> Self {
        DEFAULT_CONFIG
    }
}
