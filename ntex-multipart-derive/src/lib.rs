//! Derive support for typed `multipart/form-data` extraction in `ntex`.
//!
//! Enable `ntex-multipart`'s `derive` feature and import `MultipartForm` from
//! `ntex_multipart`; the extractor is also named
//! [`ntex_multipart::MultipartForm`](https://docs.rs/ntex-multipart/latest/ntex_multipart/struct.MultipartForm.html).
//! Field readers live in [`ntex_multipart::form`](https://docs.rs/ntex-multipart/latest/ntex_multipart/form/index.html).
//! See [`macro@MultipartForm`] for supported field and struct attributes.

use bytesize::ByteSize;
use darling::{FromDeriveInput, FromField, FromMeta};
use proc_macro::TokenStream;
use proc_macro2::Ident;
use quote::quote;
use std::collections::HashSet;
use syn::{Type, parse_macro_input};

#[derive(Default, FromMeta)]
enum DuplicateField {
    #[default]
    Ignore,
    Deny,
    Replace,
}

#[derive(FromDeriveInput, Default)]
#[darling(attributes(multipart), default)]
struct MultipartFormAttrs {
    deny_unknown_fields: bool,
    duplicate_field: DuplicateField,
}

#[allow(clippy::disallowed_names)] // false positive in macro expansion
#[derive(FromField, Default)]
#[darling(attributes(multipart), default)]
struct FieldAttrs {
    rename: Option<String>,
    limit: Option<String>,
}

struct ParsedField<'t> {
    serialization_name: String,
    rust_name: &'t Ident,
    limit: Option<usize>,
    ty: &'t Type,
}

/// Derives `ntex_multipart::MultipartCollect` for a struct with named fields.
///
/// Use the result with the [`ntex_multipart::MultipartForm`] extractor. The macro
/// is re-exported from `ntex_multipart` when its `derive` feature is enabled.
/// Generated code refers to both `::ntex` and `::ntex_multipart`, so both crates
/// must be available under those names in the consuming crate.
///
/// # Fields and ordering
///
/// Each scalar field type must implement [`FieldReader`]. A scalar `T` is required;
/// absence returns `MultipartError::MissingField`. `Option<T>` is optional and
/// defaults to `None`. `Vec<T>` accepts repeated parts of the same name and defaults
/// to an empty vector; `Option<Vec<T>>` is `None` if absent, or `Some` of the collected
/// values if present. Parts may arrive in any order; vectors retain arrival order.
///
/// ```
/// use ntex_multipart::MultipartForm;
/// use ntex_multipart::form::{temp_file::TempFile, text::Text};
///
/// #[derive(MultipartForm)]
/// struct Upload {
///     title: Text<String>,
///     description: Option<Text<String>>,
///     files: Vec<TempFile>,
/// }
/// ```
///
/// # Field attributes
///
/// - `#[multipart(rename = "name")]` uses the given multipart field name instead
///   of the Rust identifier. Names must be unique after renaming.
/// - `#[multipart(limit = "size")]` sets a body-byte budget parsed by [`bytesize`]
///   (for example, `"2 KiB"` or `"10 MiB"`). It is shared across all processed
///   occurrences of that name, including vector entries and replaced scalar values.
///   Ignored parts do not debit the budget. There is no field-specific limit by default.
///
/// Fields are also subject to [`MultipartFormConfig`] budgets (50 MiB total and
/// 2 MiB in memory by default). Readers must enforce budgets; built-in readers
/// return `MultipartError::Payload` containing `PayloadError::Overflow` when exceeded.
///
/// ```
/// use ntex_multipart::MultipartForm;
/// use ntex_multipart::form::{temp_file::TempFile, text::Text};
///
/// #[derive(MultipartForm)]
/// struct Upload {
///     #[multipart(limit = "2 KiB")]
///     title: Text<String>,
///     #[multipart(rename = "files[]", limit = "10 MiB")]
///     files: Vec<TempFile>,
/// }
/// ```
///
/// # Struct attributes
///
/// - `#[multipart(deny_unknown_fields)]` rejects unrecognized names with
///   `MultipartError::UnknownField`. Unknown parts are ignored by default.
/// - `#[multipart(duplicate_field = "ignore")]` (default) keeps the first scalar
///   value; later occurrences are ignored without invoking the reader.
/// - `#[multipart(duplicate_field = "deny")]` rejects the second scalar occurrence
///   with `MultipartError::DuplicateField`, not `UnknownField`.
/// - `#[multipart(duplicate_field = "replace")]` reads every scalar occurrence and
///   retains the last value. Every processed occurrence consumes reader budgets.
///
/// The duplicate policy is form-wide, not a field attribute. `Vec<T>` and
/// `Option<Vec<T>>` always collect all occurrences, regardless of this policy.
/// Ignored parts are drained by the multipart parser and still must be well-formed.
///
/// ```
/// use ntex_multipart::MultipartForm;
/// use ntex_multipart::form::text::Text;
///
/// #[derive(MultipartForm)]
/// #[multipart(deny_unknown_fields, duplicate_field = "deny")]
/// struct Upload {
///     title: Text<String>,
/// }
/// ```
///
/// # Compile-time failures
///
/// Enums, unions, tuple/unit structs, duplicate renamed names, invalid attributes,
/// and unparseable sizes are rejected. Field types must implement the appropriate
/// reader/group traits. Limits must fit the target's `usize`.
///
/// [`ntex_multipart::MultipartForm`]: https://docs.rs/ntex-multipart/latest/ntex_multipart/struct.MultipartForm.html
/// [`FieldReader`]: https://docs.rs/ntex-multipart/latest/ntex_multipart/form/trait.FieldReader.html
/// [`MultipartFormConfig`]: https://docs.rs/ntex-multipart/latest/ntex_multipart/struct.MultipartFormConfig.html
/// [`bytesize`]: https://docs.rs/bytesize/2
#[proc_macro_derive(MultipartForm, attributes(multipart))]
pub fn impl_multipart_form(input: TokenStream) -> TokenStream {
    expand(parse_macro_input!(input)).into()
}

/// Expands the derive, or returns `compile_error!` tokens for invalid input.
fn expand(input: syn::DeriveInput) -> proc_macro2::TokenStream {
    let name = &input.ident;

    let data_struct = match &input.data {
        syn::Data::Struct(data_struct) => data_struct,
        _ => {
            return compile_err(syn::Error::new(
                input.ident.span(),
                "`MultipartForm` can only be derived for structs",
            ));
        }
    };

    let fields = match &data_struct.fields {
        syn::Fields::Named(fields_named) => fields_named,
        _ => {
            return compile_err(syn::Error::new(
                input.ident.span(),
                "`MultipartForm` can only be derived for a struct with named fields",
            ));
        }
    };

    let attrs = match MultipartFormAttrs::from_derive_input(&input) {
        Ok(attrs) => attrs,
        Err(err) => return err.write_errors(),
    };

    // Parse the field attributes
    let parsed = match fields
        .named
        .iter()
        .map(|field| {
            let rust_name = field.ident.as_ref().unwrap();
            let attrs = FieldAttrs::from_field(field).map_err(|err| err.write_errors())?;
            let serialization_name = attrs.rename.unwrap_or_else(|| rust_name.to_string());

            let limit = match attrs.limit.map(|limit| match limit.parse::<ByteSize>() {
                Ok(ByteSize(size)) => usize::try_from(size).map_err(|_| {
                    syn::Error::new(
                        field.ident.as_ref().unwrap().span(),
                        format!("Size limit `{}` does not fit in `usize`", limit),
                    )
                }),
                Err(err) => Err(syn::Error::new(
                    field.ident.as_ref().unwrap().span(),
                    format!("Could not parse size limit `{}`: {}", limit, err),
                )),
            }) {
                Some(Err(err)) => return Err(compile_err(err)),
                limit => limit.map(Result::unwrap),
            };

            Ok(ParsedField {
                serialization_name,
                rust_name,
                limit,
                ty: &field.ty,
            })
        })
        .collect::<Result<Vec<_>, proc_macro2::TokenStream>>()
    {
        Ok(attrs) => attrs,
        Err(err) => return err,
    };

    // Check that field names are unique
    let mut set = HashSet::new();
    for field in &parsed {
        if !set.insert(field.serialization_name.clone()) {
            return compile_err(syn::Error::new(
                field.rust_name.span(),
                format!("Multiple fields named: `{}`", field.serialization_name),
            ));
        }
    }

    // Return value when a field name is not supported by the form
    let unknown_field_result = if attrs.deny_unknown_fields {
        quote!(::std::result::Result::Err(
            ::ntex_multipart::MultipartError::UnknownField(field.name().unwrap().to_string())
        ))
    } else {
        quote!(::std::result::Result::Ok(()))
    };

    // Value for duplicate action
    let duplicate_field = match attrs.duplicate_field {
        DuplicateField::Ignore => quote!(::ntex_multipart::form::DuplicateField::Ignore),
        DuplicateField::Deny => quote!(::ntex_multipart::form::DuplicateField::Deny),
        DuplicateField::Replace => quote!(::ntex_multipart::form::DuplicateField::Replace),
    };

    // limit() implementation
    let mut limit_impl = quote!();
    for field in &parsed {
        let name = &field.serialization_name;
        if let Some(value) = field.limit {
            limit_impl.extend(quote!(
                #name => ::std::option::Option::Some(#value),
            ));
        }
    }

    // handle_field() implementation
    let mut handle_field_impl = quote!();
    for field in &parsed {
        let name = &field.serialization_name;
        let ty = &field.ty;

        handle_field_impl.extend(quote!(
            #name => <#ty as ::ntex_multipart::form::FieldGroupReader>::handle_field(st, req, field, limits, state, #duplicate_field).await,
        ));
    }

    // from_state() implementation
    let mut from_state_impl = quote!();
    for field in &parsed {
        let name = &field.serialization_name;
        let rust_name = &field.rust_name;
        let ty = &field.ty;
        from_state_impl.extend(quote!(
            #rust_name: <#ty as ::ntex_multipart::form::FieldGroupReader>::from_state(#name, &mut state)?,
        ));
    }

    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    let generation = quote! {
        impl #impl_generics ::ntex_multipart::MultipartCollect for #name #ty_generics #where_clause {
            fn limit(field_name: &str) -> ::std::option::Option<usize> {
                match field_name {
                    #limit_impl
                    _ => None,
                }
            }

            async fn handle_field<St>(
                st: &St,
                req: &::ntex::web::HttpRequest,
                field: ::ntex_multipart::Field,
                limits: &mut ::ntex_multipart::form::Limits,
                state: &mut ::ntex_multipart::form::State,
            ) -> ::std::result::Result<(), ::ntex_multipart::MultipartError> {
                match field.name().unwrap() {
                    #handle_field_impl
                    _ => return #unknown_field_result,
                }
            }

            fn from_state(mut state: ::ntex_multipart::form::State) -> ::std::result::Result<Self, ::ntex_multipart::MultipartError> {
                Ok(Self {
                    #from_state_impl
                })
            }

        }
    };
    generation
}

/// Transform a syn error into a token stream for returning.
fn compile_err(err: syn::Error) -> proc_macro2::TokenStream {
    err.to_compile_error()
}

#[cfg(test)]
mod tests {
    use super::expand;

    /// Expands `input` and returns its `compile_error!` message tokens.
    fn expand_error(input: syn::DeriveInput) -> String {
        let output = expand(input).to_string();
        assert!(
            output.contains("compile_error"),
            "expected an error, got: {output}"
        );
        output
    }

    /// STATEMENT: Only structs with named fields can derive `MultipartForm`.
    ///
    /// HOW:
    /// - Expand the derive for an enum and for a tuple struct.
    /// - Confirm each produces a `compile_error!` naming the unsupported shape.
    #[test]
    fn non_struct_and_unnamed_fields_are_rejected() {
        let output = expand_error(syn::parse_quote! { enum Upload { A } });
        assert!(
            output.contains("can only be derived for structs"),
            "{output}"
        );

        let output = expand_error(syn::parse_quote! { struct Upload(String); });
        assert!(output.contains("struct with named fields"), "{output}");
    }

    /// STATEMENT: Invalid struct and field attributes are reported as compile errors.
    ///
    /// HOW:
    /// - Expand with an unknown `duplicate_field` value and with an unknown field attribute.
    /// - Confirm both outputs contain `compile_error!` mentioning the offending value or key.
    #[test]
    fn invalid_attributes_are_rejected() {
        let output = expand_error(syn::parse_quote! {
            #[multipart(duplicate_field = "bogus")]
            struct Upload { a: String }
        });
        assert!(output.contains("bogus"), "{output}");

        let output = expand_error(syn::parse_quote! {
            struct Upload {
                #[multipart(bogus = "x")]
                a: String,
            }
        });
        assert!(output.contains("bogus"), "{output}");
    }

    /// STATEMENT: An unparseable field `limit` is a compile error that quotes the value.
    ///
    /// HOW:
    /// - Expand a field with `limit = "lots"`.
    /// - Confirm the output is a `compile_error!` containing ``Could not parse size limit `lots` ``.
    #[test]
    fn unparseable_limits_are_rejected() {
        let output = expand_error(syn::parse_quote! {
            struct Upload {
                #[multipart(limit = "lots")]
                a: String,
            }
        });
        assert!(
            output.contains("Could not parse size limit `lots`"),
            "{output}"
        );
    }

    /// STATEMENT: Two fields that serialize to the same multipart name are rejected.
    ///
    /// HOW:
    /// - Expand a struct whose second field is renamed to the first field's name.
    /// - Confirm the output is a `compile_error!` containing ``Multiple fields named: `a` ``.
    #[test]
    fn duplicate_field_names_are_rejected() {
        let output = expand_error(syn::parse_quote! {
            struct Upload {
                a: String,
                #[multipart(rename = "a")]
                b: String,
            }
        });
        assert!(output.contains("Multiple fields named: `a`"), "{output}");
    }
}
