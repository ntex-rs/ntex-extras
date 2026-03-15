//! Extract and process typed data from fields of a `multipart/form-data` request.

use crate::{Field, MultipartError};
use derive_more::{Deref, DerefMut};
use futures::future::LocalBoxFuture;
use ntex::http::error::PayloadError;
use ntex::web::HttpRequest;
use std::{
    any::Any,
    collections::HashMap,
    future::{Future, ready},
};

pub mod bytes;
pub mod json;
#[cfg(feature = "tempfile")]
pub mod temp_file;
pub mod text;

/// Trait that data types to be used in a multipart form struct should implement.
///
/// It represents an asynchronous handler that processes a multipart field to produce `Self`.
pub trait FieldReader<'t>: Sized + Any {
    /// Future that resolves to a `Self`.
    type Future: Future<Output = Result<Self, MultipartError>>;

    /// The form will call this function to handle the field.
    ///
    /// # Panics
    ///
    /// When reading the `field` payload using its `Stream` implementation, polling (manually or via
    /// `next()`/`try_next()`) may panic after the payload is exhausted. If this is a problem for
    /// your implementation of this method, you should [`fuse()`] the `Field` first.
    ///
    /// [`fuse()`]: futures_util::stream::StreamExt::fuse()
    fn read_field(req: &'t HttpRequest, field: Field, limits: &'t mut Limits) -> Self::Future;
}

/// Used to accumulate the state of the loaded fields.
#[doc(hidden)]
#[derive(Default, Deref, DerefMut)]
pub struct State(pub HashMap<String, Box<dyn Any>>);

/// Trait that the field collection types implement, i.e. `Vec<T>`, `Option<T>`, or `T` itself.
#[doc(hidden)]
pub trait FieldGroupReader<'t>: Sized + Any {
    type Future: Future<Output = Result<(), MultipartError>>;

    /// The form will call this function for each matching field.
    fn handle_field(
        req: &'t HttpRequest,
        field: Field,
        limits: &'t mut Limits,
        state: &'t mut State,
        duplicate_field: DuplicateField,
    ) -> Self::Future;

    /// Construct `Self` from the group of processed fields.
    fn from_state(name: &str, state: &'t mut State) -> Result<Self, MultipartError>;
}

impl<'t, T> FieldGroupReader<'t> for Option<T>
where
    T: FieldReader<'t>,
{
    type Future = LocalBoxFuture<'t, Result<(), MultipartError>>;

    fn handle_field(
        req: &'t HttpRequest,
        field: Field,
        limits: &'t mut Limits,
        state: &'t mut State,
        duplicate_field: DuplicateField,
    ) -> Self::Future {
        if state.contains_key(&field.form_field_name) {
            match duplicate_field {
                DuplicateField::Ignore => return Box::pin(ready(Ok(()))),

                DuplicateField::Deny => {
                    return Box::pin(ready(Err(MultipartError::DuplicateField(
                        field.form_field_name,
                    ))));
                }

                DuplicateField::Replace => {}
            }
        }

        Box::pin(async move {
            let field_name = field.form_field_name.clone();
            let t = T::read_field(req, field, limits).await?;
            state.insert(field_name, Box::new(t));
            Ok(())
        })
    }

    fn from_state(name: &str, state: &'t mut State) -> Result<Self, MultipartError> {
        Ok(state.remove(name).map(|m| *m.downcast::<T>().unwrap()))
    }
}

impl<'t, T> FieldGroupReader<'t> for Vec<T>
where
    T: FieldReader<'t>,
{
    type Future = LocalBoxFuture<'t, Result<(), MultipartError>>;

    fn handle_field(
        req: &'t HttpRequest,
        field: Field,
        limits: &'t mut Limits,
        state: &'t mut State,
        _duplicate_field: DuplicateField,
    ) -> Self::Future {
        Box::pin(async move {
            // Note: Vec GroupReader always allows duplicates

            let vec = state
                .entry(field.form_field_name.clone())
                .or_insert_with(|| Box::<Vec<T>>::default())
                .downcast_mut::<Vec<T>>()
                .unwrap();

            let item = T::read_field(req, field, limits).await?;
            vec.push(item);

            Ok(())
        })
    }

    fn from_state(name: &str, state: &'t mut State) -> Result<Self, MultipartError> {
        Ok(state.remove(name).map(|m| *m.downcast::<Vec<T>>().unwrap()).unwrap_or_default())
    }
}

impl<'t, T> FieldGroupReader<'t> for T
where
    T: FieldReader<'t>,
{
    type Future = LocalBoxFuture<'t, Result<(), MultipartError>>;

    fn handle_field(
        req: &'t HttpRequest,
        field: Field,
        limits: &'t mut Limits,
        state: &'t mut State,
        duplicate_field: DuplicateField,
    ) -> Self::Future {
        if state.contains_key(&field.form_field_name) {
            match duplicate_field {
                DuplicateField::Ignore => return Box::pin(ready(Ok(()))),

                DuplicateField::Deny => {
                    return Box::pin(ready(Err(MultipartError::DuplicateField(
                        field.form_field_name,
                    ))));
                }

                DuplicateField::Replace => {}
            }
        }

        Box::pin(async move {
            let field_name = field.form_field_name.clone();
            let t = T::read_field(req, field, limits).await?;
            state.insert(field_name, Box::new(t));
            Ok(())
        })
    }

    fn from_state(name: &str, state: &'t mut State) -> Result<Self, MultipartError> {
        state
            .remove(name)
            .map(|m| *m.downcast::<T>().unwrap())
            .ok_or_else(|| MultipartError::MissingField(name.to_owned()))
    }
}

impl<'t, T> FieldGroupReader<'t> for Option<Vec<T>>
where
    T: FieldReader<'t>,
{
    type Future = LocalBoxFuture<'t, Result<(), MultipartError>>;

    fn handle_field(
        req: &'t HttpRequest,
        field: Field,
        limits: &'t mut Limits,
        state: &'t mut State,
        _duplicate_field: DuplicateField,
    ) -> Self::Future {
        let field_name = field.name().unwrap().to_string();

        Box::pin(async move {
            let vec = state
                .entry(field_name)
                .or_insert_with(|| Box::<Vec<T>>::default())
                .downcast_mut::<Vec<T>>()
                .unwrap();

            let item = T::read_field(req, field, limits).await?;
            vec.push(item);

            Ok(())
        })
    }

    fn from_state(name: &str, state: &'t mut State) -> Result<Self, MultipartError> {
        if let Some(boxed_vec) = state.remove(name) {
            let vec = *boxed_vec.downcast::<Vec<T>>().unwrap();
            Ok(Some(vec))
        } else {
            Ok(None)
        }
    }
}

#[doc(hidden)]
pub enum DuplicateField {
    /// Additional fields are not processed.
    Ignore,

    /// An error will be raised.
    Deny,

    /// All fields will be processed, the last one will replace all previous.
    Replace,
}

/// Used to keep track of the remaining limits for the form and current field.
pub struct Limits {
    pub total_limit_remaining: usize,
    pub memory_limit_remaining: usize,
    pub field_limit_remaining: Option<usize>,
}

impl Limits {
    pub fn new(total_limit: usize, memory_limit: usize) -> Self {
        Self {
            total_limit_remaining: total_limit,
            memory_limit_remaining: memory_limit,
            field_limit_remaining: None,
        }
    }

    /// This function should be called within a [`FieldReader`] when reading each chunk of a field
    /// to ensure that the form limits are not exceeded.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The number of bytes being read from this chunk
    /// * `in_memory` - Whether to consume from the memory limits
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
