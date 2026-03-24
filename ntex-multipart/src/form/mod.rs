//! Extract and process typed data from fields of a `multipart/form-data` request.
use std::any::Any;

use derive_more::{Deref, DerefMut};
use ntex::{http::error::PayloadError, util::HashMap, web::HttpRequest};

pub mod bytes;
pub mod json;
pub mod temp_file;
pub mod text;

use crate::{Field, MultipartError};

/// Trait that data types to be used in a multipart form struct should implement.
///
/// It represents an asynchronous handler that processes a multipart field to produce `Self`.
pub trait FieldReader: Sized + Any {
    /// The form will call this function to handle the field.
    ///
    /// # Panics
    ///
    /// When reading the `field` payload using its `Stream` implementation, polling (manually or via
    /// `next()`/`try_next()`) may panic after the payload is exhausted. If this is a problem for
    /// your implementation of this method, you should [`fuse()`] the `Field` first.
    ///
    /// [`fuse()`]: futures_util::stream::StreamExt::fuse()
    async fn read_field(
        req: &HttpRequest,
        field: Field,
        limits: &mut Limits,
    ) -> Result<Self, MultipartError>;
}

/// Used to accumulate the state of the loaded fields.
#[doc(hidden)]
#[derive(Default, Deref, DerefMut)]
pub struct State(pub HashMap<String, Box<dyn Any>>);

/// Trait that the field collection types implement, i.e. `Vec<T>`, `Option<T>`, or `T` itself.
#[doc(hidden)]
pub trait FieldGroupReader: Sized + Any {
    /// The form will call this function for each matching field.
    async fn handle_field(
        req: &HttpRequest,
        field: Field,
        limits: &mut Limits,
        state: &mut State,
        duplicate_field: DuplicateField,
    ) -> Result<(), MultipartError>;

    /// Construct `Self` from the group of processed fields.
    fn from_state(name: &str, state: &mut State) -> Result<Self, MultipartError>;
}

impl<T> FieldGroupReader for Option<T>
where
    T: FieldReader + 'static,
{
    async fn handle_field(
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
        let t = T::read_field(req, field, limits).await?;
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
    async fn handle_field(
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

        let item = T::read_field(req, field, limits).await?;
        vec.push(item);

        Ok(())
    }

    fn from_state(name: &str, state: &mut State) -> Result<Self, MultipartError> {
        Ok(state.remove(name).map(|m| *m.downcast::<Vec<T>>().unwrap()).unwrap_or_default())
    }
}

impl<T> FieldGroupReader for T
where
    T: FieldReader,
{
    async fn handle_field(
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
        let t = T::read_field(req, field, limits).await?;
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
    async fn handle_field(
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

        let item = T::read_field(req, field, limits).await?;
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
