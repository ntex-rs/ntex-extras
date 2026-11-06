use derive_more::{Deref, DerefMut};
use ntex::web::HttpRequest;

use crate::{Field, MultipartError, form::Limits, form::State};

/// Derives [`MultipartCollect`] for a named-field struct (requires the `derive` feature).
///
/// Supports field-level `#[multipart(rename = "...")]` and
/// `#[multipart(limit = "...")]`, and struct-level `deny_unknown_fields` and
/// `duplicate_field = "ignore" | "deny" | "replace"`. Limits are shared by all
/// processed occurrences of a name. Unknown parts and scalar duplicates are
/// ignored by default; `deny` reports [`MultipartError::DuplicateField`].
/// `Vec<T>` and `Option<Vec<T>>` always collect all occurrences.
///
/// See the [macro documentation](https://docs.rs/ntex-multipart-derive/latest/ntex_multipart_derive/derive.MultipartForm.html)
/// for examples and attribute details.
#[cfg(feature = "derive")]
pub use ntex_multipart_derive::MultipartForm;

/// Collects typed fields for the [`struct@MultipartForm`] extractor.
///
/// Usually implemented with the `MultipartForm` derive macro, available with the
/// `derive` feature. Implement it manually to customize field routing and assembly.
pub trait MultipartCollect: Sized {
    /// Returns an optional body-byte budget for a multipart field name.
    ///
    /// The budget is shared across all processed occurrences of that name, not
    /// reset for each part. `None` disables only the field-specific limit.
    fn limit(field_name: &str) -> Option<usize>;

    /// Handles one part in arrival order, storing processed values in `state`.
    ///
    /// Readers must debit `limits`; the extractor retains the remaining budget
    /// for this field name. A dropped unread field is drained before the next part.
    ///
    /// # Errors
    ///
    /// Derived implementations propagate reader errors, reject unknown names with
    /// [`MultipartError::UnknownField`] when configured, and reject scalar
    /// duplicates with [`MultipartError::DuplicateField`] when configured.
    async fn handle_field<St>(
        st: &St,
        req: &HttpRequest,
        field: Field,
        limits: &mut Limits,
        state: &mut State,
    ) -> Result<(), MultipartError>;

    /// Builds the form after all parts have been processed.
    ///
    /// Derived forms use `None` for absent optional groups and an empty `Vec` for
    /// absent vector groups.
    ///
    /// # Errors
    ///
    /// Derived forms return [`MultipartError::MissingField`] for an absent required
    /// scalar field.
    ///
    /// # Panics
    ///
    /// Derived forms panic if `state` contains a value of the wrong type for a field.
    fn from_state(state: State) -> Result<Self, MultipartError>;
}

/// Typed `multipart/form-data` request extractor.
///
/// `T` implements [`MultipartCollect`], usually with the `MultipartForm` derive
/// macro (`derive` feature). Parts may arrive in any order and are read sequentially;
/// repeated vector values preserve arrival order. Derived scalar fields are
/// required, `Option<T>` fields are optional, and vector fields may be absent.
///
/// Only `multipart/form-data` is accepted; other multipart subtypes are rejected.
/// Register [`MultipartFormConfig`] with `App::app_state` to change the default
/// 50 MiB total and 2 MiB memory body-byte budgets. Ignored parts do not debit
/// those budgets. Reader configuration is also obtained from request app state.
///
/// # Errors
///
/// Extraction returns parser/payload errors or reader failures. Derived forms can
/// return [`MultipartError::MissingField`], [`MultipartError::UnknownField`], or
/// [`MultipartError::DuplicateField`] according to their required fields and
/// attributes. Exceeding a reader budget returns [`MultipartError::Payload`]
/// containing [`PayloadError::Overflow`](ntex::http::error::PayloadError::Overflow).
#[derive(Deref, DerefMut)]
pub struct MultipartForm<T: MultipartCollect>(
    /// The extracted typed form.
    pub T,
);

impl<T: MultipartCollect> MultipartForm<T> {
    /// Consumes the extractor and returns the typed form.
    pub fn into_inner(self) -> T {
        self.0
    }
}

/// Body-byte budgets for the [`struct@MultipartForm`] extractor.
///
/// Register with `App::app_state`; absent configuration defaults to 50 MiB total
/// and 2 MiB memory. Built-in readers debit field-body bytes, not headers/framing
/// or ignored parts. These are cumulative byte budgets, not bounds on actual
/// parser buffering, allocator overhead, or deserialized values.
#[derive(Clone)]
pub struct MultipartFormConfig {
    pub(crate) total_limit: usize,
    pub(crate) memory_limit: usize,
}

impl MultipartFormConfig {
    /// Sets the cumulative processed field-body budget in bytes (default: 50 MiB).
    ///
    /// Counts both in-memory and disk-backed readers. Multipart framing, headers,
    /// and ignored fields do not count. A reader exceeding it returns
    /// [`MultipartError::Payload`] with `PayloadError::Overflow`.
    pub fn total_limit(mut self, total_limit: usize) -> Self {
        self.total_limit = total_limit;
        self
    }

    /// Sets the cumulative in-memory field-body budget in bytes (default: 2 MiB).
    ///
    /// [`Text`](crate::form::text::Text), [`Json`](crate::form::json::Json), and
    /// [`Bytes`](crate::form::bytes::Bytes) debit this budget;
    /// [`TempFile`](crate::form::temp_file::TempFile) does not. It is not a limit on
    /// all memory used by the request parser or by deserialization.
    pub fn memory_limit(mut self, memory_limit: usize) -> Self {
        self.memory_limit = memory_limit;
        self
    }

    /// Returns configuration from request app state, or the default if none is registered.
    pub(crate) fn from_req(req: &HttpRequest) -> &Self {
        req.app_state::<Self>().unwrap_or(&DEFAULT_CONFIG)
    }
}

const DEFAULT_CONFIG: MultipartFormConfig = MultipartFormConfig {
    total_limit: 52_428_800, // 50 MiB
    memory_limit: 2_097_152, // 2 MiB
};

impl Default for MultipartFormConfig {
    fn default() -> Self {
        DEFAULT_CONFIG
    }
}
