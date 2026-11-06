//! Field readers for the typed [`MultipartForm`](struct@crate::MultipartForm) extractor.
//!
//! Use [`text::Text`] for UTF-8 plain-text values, [`json::Json`] for JSON,
//! [`bytes::Bytes`] for raw in-memory data, and [`temp_file::TempFile`] for disk-backed
//! uploads. Custom field types implement [`FieldReader`] and must debit [`Limits`]
//! as they read body chunks. Readers run sequentially in the order parts arrive.
//!
//! Reader configuration is taken from request app state: [`text::TextConfig`],
//! [`json::JsonConfig`], and [`temp_file::TempFileConfig`]. Global reader budgets
//! are configured with [`MultipartFormConfig`](crate::MultipartFormConfig).
use std::any::Any;

use derive_more::{Deref, DerefMut};
use ntex::{http::error::PayloadError, util::HashMap, web::HttpRequest};

pub mod bytes;
pub mod json;
pub mod temp_file;
pub mod text;

use crate::{Field, MultipartError};

/// Converts a multipart field into a typed value asynchronously.
///
/// Implement this for custom field types used in a derived form. Read field body
/// chunks and call [`Limits::try_consume_limits`] for each one before storing or
/// processing it; the extractor does not enforce reader budgets independently.
/// Readers are called sequentially, with shared total/memory budgets and the
/// remaining budget for the current field name.
pub trait FieldReader: Sized + Any {
    /// Reads one field, using the request and application state if needed.
    ///
    /// # Errors
    ///
    /// Propagate stream and limit errors. Reader-specific failures may be wrapped
    /// in [`MultipartError::Field`] with the field name and an HTTP response.
    ///
    /// # Panics
    ///
    /// Polling [`Field`] after EOF may panic. If your implementation polls beyond
    /// `None`, use [`StreamExt::fuse`](futures::StreamExt::fuse) first.
    async fn read_field<St>(
        st: &St,
        req: &HttpRequest,
        field: Field,
        limits: &mut Limits,
    ) -> Result<Self, MultipartError>;
}

/// Type-erased values accumulated by field name while extracting a form.
#[doc(hidden)]
#[derive(Default, Deref, DerefMut)]
pub struct State(
    /// Values stored by field readers, keyed by the multipart field name.
    pub HashMap<String, Box<dyn Any>>,
);

/// Collects fields into `T`, `Option<T>`, `Vec<T>`, or `Option<Vec<T>>`.
///
/// Scalar groups honor [`DuplicateField`]; vector groups always collect every
/// occurrence in arrival order.
#[doc(hidden)]
pub trait FieldGroupReader: Sized + Any {
    /// Reads one matching part into the group's entry in `state`.
    ///
    /// # Errors
    ///
    /// Returns reader errors, or [`MultipartError::DuplicateField`] when a scalar
    /// group already has a value and `duplicate_field` is [`DuplicateField::Deny`].
    /// Ignored scalar duplicates are dropped without invoking the reader.
    ///
    /// # Panics
    ///
    /// Built-in vector groups panic if an existing entry has an incompatible type.
    /// The `Option<Vec<T>>` implementation also requires a named field.
    async fn handle_field<St>(
        st: &St,
        req: &HttpRequest,
        field: Field,
        limits: &mut Limits,
        state: &mut State,
        duplicate_field: DuplicateField,
    ) -> Result<(), MultipartError>;

    /// Removes the named entry from `state` and constructs the group.
    ///
    /// An absent entry gives `None` for optional groups and an empty vector for
    /// `Vec<T>`.
    ///
    /// # Errors
    ///
    /// A required scalar `T` returns [`MultipartError::MissingField`] if absent.
    ///
    /// # Panics
    ///
    /// Built-in implementations panic if the stored value has an incompatible type.
    fn from_state(name: &str, state: &mut State) -> Result<Self, MultipartError>;
}

impl<T> FieldGroupReader for Option<T>
where
    T: FieldReader + 'static,
{
    async fn handle_field<St>(
        st: &St,
        req: &HttpRequest,
        field: Field,
        limits: &mut Limits,
        state: &mut State,
        duplicate_field: DuplicateField,
    ) -> Result<(), MultipartError> {
        if state.contains_key(&field.form_field_name) {
            match duplicate_field {
                DuplicateField::Ignore => return Ok(()),

                DuplicateField::Deny => {
                    return Err(MultipartError::DuplicateField(field.form_field_name));
                }

                DuplicateField::Replace => {}
            }
        }

        let field_name = field.form_field_name.clone();
        let t = T::read_field(st, req, field, limits).await?;
        state.insert(field_name, Box::new(t));
        Ok(())
    }

    fn from_state(name: &str, state: &mut State) -> Result<Self, MultipartError> {
        Ok(state.remove(name).map(|m| *m.downcast::<T>().unwrap()))
    }
}

impl<T> FieldGroupReader for Vec<T>
where
    T: FieldReader + 'static,
{
    async fn handle_field<St>(
        st: &St,
        req: &HttpRequest,
        field: Field,
        limits: &mut Limits,
        state: &mut State,
        _duplicate_field: DuplicateField,
    ) -> Result<(), MultipartError> {
        // Note: Vec GroupReader always allows duplicates

        let vec = state
            .entry(field.form_field_name.clone())
            .or_insert_with(|| Box::<Vec<T>>::default())
            .downcast_mut::<Vec<T>>()
            .unwrap();

        let item = T::read_field(st, req, field, limits).await?;
        vec.push(item);

        Ok(())
    }

    fn from_state(name: &str, state: &mut State) -> Result<Self, MultipartError> {
        Ok(state
            .remove(name)
            .map(|m| *m.downcast::<Vec<T>>().unwrap())
            .unwrap_or_default())
    }
}

impl<T> FieldGroupReader for T
where
    T: FieldReader,
{
    async fn handle_field<St>(
        st: &St,
        req: &HttpRequest,
        field: Field,
        limits: &mut Limits,
        state: &mut State,
        duplicate_field: DuplicateField,
    ) -> Result<(), MultipartError> {
        if state.contains_key(&field.form_field_name) {
            match duplicate_field {
                DuplicateField::Ignore => return Ok(()),

                DuplicateField::Deny => {
                    return Err(MultipartError::DuplicateField(field.form_field_name));
                }

                DuplicateField::Replace => {}
            }
        }

        let field_name = field.form_field_name.clone();
        let t = T::read_field(st, req, field, limits).await?;
        state.insert(field_name, Box::new(t));
        Ok(())
    }

    fn from_state(name: &str, state: &mut State) -> Result<Self, MultipartError> {
        state
            .remove(name)
            .map(|m| *m.downcast::<T>().unwrap())
            .ok_or_else(|| MultipartError::MissingField(name.to_owned()))
    }
}

impl<T> FieldGroupReader for Option<Vec<T>>
where
    T: FieldReader,
{
    async fn handle_field<St>(
        st: &St,
        req: &HttpRequest,
        field: Field,
        limits: &mut Limits,
        state: &mut State,
        _duplicate_field: DuplicateField,
    ) -> Result<(), MultipartError> {
        let field_name = field.name().unwrap().to_string();

        let vec = state
            .entry(field_name)
            .or_insert_with(|| Box::<Vec<T>>::default())
            .downcast_mut::<Vec<T>>()
            .unwrap();

        let item = T::read_field(st, req, field, limits).await?;
        vec.push(item);

        Ok(())
    }

    fn from_state(name: &str, state: &mut State) -> Result<Self, MultipartError> {
        if let Some(boxed_vec) = state.remove(name) {
            let vec = *boxed_vec.downcast::<Vec<T>>().unwrap();
            Ok(Some(vec))
        } else {
            Ok(None)
        }
    }
}

/// Policy for repeated scalar fields in a derived form; vector groups ignore it.
#[doc(hidden)]
pub enum DuplicateField {
    /// Keeps the first value; later occurrences bypass the reader and are drained.
    Ignore,

    /// Rejects a second scalar occurrence with [`MultipartError::DuplicateField`].
    Deny,

    /// Reads every occurrence and retains only the last value.
    Replace,
}

/// Remaining byte budgets for a form and its current field name.
///
/// Readers must debit these with [`Self::try_consume_limits`]. The counters measure
/// body bytes processed by readers, not framing, parser buffers, or deserialized
/// allocations. Ignored parts are drained without debiting these counters.
pub struct Limits {
    /// Remaining body bytes across all processed fields, including disk-backed fields.
    pub total_limit_remaining: usize,
    /// Remaining body bytes that readers may count as in-memory data.
    pub memory_limit_remaining: usize,
    /// Remaining body bytes for this field name, shared across its processed occurrences.
    ///
    /// `None` means no field-specific limit; global budgets still apply.
    pub field_limit_remaining: Option<usize>,
}

impl Limits {
    /// Creates byte budgets with no field-specific limit.
    ///
    /// Both arguments are byte counts; zero permits only empty processed bodies.
    pub fn new(total_limit: usize, memory_limit: usize) -> Self {
        Self {
            total_limit_remaining: total_limit,
            memory_limit_remaining: memory_limit,
            field_limit_remaining: None,
        }
    }

    /// Debits `bytes` from the total and current field budgets, and from the memory
    /// budget when `in_memory` is `true`.
    ///
    /// Call this within a [`FieldReader`] for every chunk before accepting it.
    /// [`TempFile`](temp_file::TempFile) passes `false`; in-memory readers pass `true`.
    ///
    /// # Errors
    ///
    /// Returns [`MultipartError::Payload`] containing
    /// [`PayloadError::Overflow`] if any applicable budget would be exceeded.
    /// Debits are sequential (total, memory, field), not transactional: counters
    /// already updated remain changed if a later budget fails.
    pub fn try_consume_limits(
        &mut self,
        bytes: usize,
        in_memory: bool,
    ) -> Result<(), MultipartError> {
        self.total_limit_remaining = self
            .total_limit_remaining
            .checked_sub(bytes)
            .ok_or(MultipartError::Payload(PayloadError::Overflow))?;

        if in_memory {
            self.memory_limit_remaining = self
                .memory_limit_remaining
                .checked_sub(bytes)
                .ok_or(MultipartError::Payload(PayloadError::Overflow))?;
        }

        if let Some(field_limit) = self.field_limit_remaining {
            self.field_limit_remaining = Some(
                field_limit
                    .checked_sub(bytes)
                    .ok_or(MultipartError::Payload(PayloadError::Overflow))?,
            );
        }

        Ok(())
    }
}
