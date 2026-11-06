#![cfg(feature = "derive")]

use futures::{StreamExt, TryStreamExt};
use ntex::http::{StatusCode, header};
use ntex::web::{
    FromRequest,
    test::{TestRequest, read_body},
};
use ntex_multipart::form::{
    FieldReader,
    bytes::Bytes,
    json::{Json, JsonConfig},
    temp_file::{TempFile, TempFileConfig},
    text::{Text, TextConfig},
};
use ntex_multipart::{
    Multipart, MultipartCollect, MultipartError, MultipartForm, MultipartFormConfig,
};

#[derive(MultipartForm)]
struct Form<T: FieldReader> {
    name: T,
}

const BODY: &[u8] =
    b"--abc\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nhello\r\n--abc--\r\n";

fn request() -> TestRequest {
    TestRequest::post()
        .header(header::CONTENT_TYPE, "multipart/form-data; boundary=abc")
        .payload(BODY)
}

/// STATEMENT: `MultipartForm` can be derived for a generic struct.
///
/// HOW:
/// - Derive `MultipartForm` for `Form<T: FieldReader>` and extract `Form<Bytes>`.
/// - Confirm the `name` field holds the submitted data.
#[ntex::test]
async fn generic_form_is_extracted() {
    let (req, mut pl, ()) = request().to_http_parts();
    let form = MultipartForm::<Form<Bytes>>::from_request(&(), &req, &mut pl)
        .await
        .unwrap();
    assert_eq!(form.name.data, "hello");
}

/// STATEMENT: A `MultipartFormConfig` added to app state limits the extracted form.
///
/// HOW:
/// - Register `MultipartFormConfig` with a 3-byte total limit as app state.
/// - Extract a form with a 5-byte field and confirm it fails with `PayloadError::Overflow`.
#[ntex::test]
async fn config_from_app_state_limits_form() {
    let (req, mut pl, ()) = request()
        .app_state(MultipartFormConfig::default().total_limit(3))
        .to_http_parts();
    let res = MultipartForm::<Form<Bytes>>::from_request(&(), &req, &mut pl).await;
    assert!(matches!(
        res,
        Err(MultipartError::Payload(
            ntex::http::error::PayloadError::Overflow
        ))
    ));
}

struct Part<'a> {
    name: &'a str,
    data: &'a [u8],
    content_type: Option<&'a str>,
    file_name: Option<&'a str>,
}

impl<'a> Part<'a> {
    fn new(name: &'a str, data: &'a [u8]) -> Self {
        Self {
            name,
            data,
            content_type: None,
            file_name: None,
        }
    }

    fn content_type(mut self, content_type: &'a str) -> Self {
        self.content_type = Some(content_type);
        self
    }

    fn file_name(mut self, file_name: &'a str) -> Self {
        self.file_name = Some(file_name);
        self
    }
}

fn multipart_request(parts: &[Part<'_>]) -> TestRequest {
    let mut body = Vec::new();
    for part in parts {
        body.extend_from_slice(
            format!(
                "--abc\r\nContent-Disposition: form-data; name=\"{}\"",
                part.name
            )
            .as_bytes(),
        );
        if let Some(file_name) = part.file_name {
            body.extend_from_slice(format!("; filename=\"{file_name}\"").as_bytes());
        }
        body.extend_from_slice(b"\r\n");
        if let Some(content_type) = part.content_type {
            body.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
        }
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(part.data);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(b"--abc--\r\n");
    TestRequest::post()
        .header(header::CONTENT_TYPE, "multipart/form-data; boundary=abc")
        .payload(body)
}

async fn extract<T: MultipartCollect + 'static>(request: TestRequest) -> Result<T, MultipartError> {
    let (req, mut pl, ()) = request.to_http_parts();
    MultipartForm::<T>::from_request(&(), &req, &mut pl)
        .await
        .map(MultipartForm::into_inner)
}

async fn assert_field_error(error: MultipartError, status: StatusCode, message: &str) {
    let MultipartError::Field { name, source } = error else {
        panic!("expected a field error, got {error:?}");
    };
    assert_eq!(name, "name");
    assert_eq!(source.status(), status);
    let body = read_body(source).await;
    let body = std::str::from_utf8(&body).unwrap();
    assert!(body.contains(message), "{body}");
}

fn assert_overflow<T>(result: Result<T, MultipartError>) {
    assert!(matches!(
        result,
        Err(MultipartError::Payload(
            ntex::http::error::PayloadError::Overflow
        ))
    ));
}

/// STATEMENT: `Json` accepts JSON media types, including structured suffixes, and deserializes the field.
///
/// HOW:
/// - Extract an array under `application/json` and `application/example+json`.
/// - Confirm both extractions produce the submitted integer vector.
#[ntex::test]
async fn json_accepts_json_media_types() {
    for content_type in ["application/json", "application/example+json"] {
        let form =
            extract::<Form<Json<Vec<u32>>>>(multipart_request(&[
                Part::new("name", b"[1,2]").content_type(content_type)
            ]))
            .await
            .unwrap();
        assert_eq!(form.name.into_inner(), vec![1, 2]);
    }
}

/// STATEMENT: `Json` rejects absent or non-JSON media types before deserialization.
///
/// HOW:
/// - Submit valid JSON without a content type and with `text/plain`.
/// - Confirm each failure identifies `name` and returns a content-type error with status 400.
#[ntex::test]
async fn json_requires_json_content_type() {
    for content_type in [None, Some("text/plain")] {
        let mut part = Part::new("name", b"[1,2]");
        part.content_type = content_type;
        let error = extract::<Form<Json<Vec<u32>>>>(multipart_request(&[part]))
            .await
            .err()
            .unwrap();
        assert_field_error(error, StatusCode::BAD_REQUEST, "Content type error").await;
    }
}

/// STATEMENT: `Json` reports malformed JSON and incompatible values as field deserialization errors.
///
/// HOW:
/// - Submit an unfinished array and a string to a field expecting `Vec<u32>`.
/// - Confirm each failure identifies `name` and returns a JSON deserialization error with status 400.
#[ntex::test]
async fn json_reports_deserialization_errors() {
    for data in [b"[".as_slice(), b"\"not an array\""] {
        let error = extract::<Form<Json<Vec<u32>>>>(multipart_request(&[
            Part::new("name", data).content_type("application/json")
        ]))
        .await
        .err()
        .unwrap();
        assert_field_error(error, StatusCode::BAD_REQUEST, "Json deserialize error").await;
    }
}

/// STATEMENT: App-state `JsonConfig` can disable content-type validation without disabling parsing.
///
/// HOW:
/// - Register relaxed validation and submit JSON without a media type or with `text/plain`.
/// - Confirm both fields deserialize to the submitted vector.
#[ntex::test]
async fn json_config_allows_untyped_json() {
    for content_type in [None, Some("text/plain")] {
        let mut part = Part::new("name", b"[3]");
        part.content_type = content_type;
        let form = extract::<Form<Json<Vec<u32>>>>(
            multipart_request(&[part])
                .app_state(JsonConfig::default().validate_content_type(false)),
        )
        .await
        .unwrap();
        assert_eq!(form.name.into_inner(), vec![3]);
    }
}

/// STATEMENT: `Text` parses plain-text numbers and UTF-8 strings, treating a missing media type as plain text.
///
/// HOW:
/// - Submit a number with absent, plain, and structured plain media types, and a UTF-8 string.
/// - Confirm numeric values and Unicode text are preserved after deserialization.
#[ntex::test]
async fn text_parses_plain_and_untyped_fields() {
    for content_type in [
        None,
        Some("text/plain; charset=utf-8"),
        Some("application/example+plain"),
    ] {
        let mut part = Part::new("name", b"42");
        part.content_type = content_type;
        let form = extract::<Form<Text<u32>>>(multipart_request(&[part]))
            .await
            .unwrap();
        assert_eq!(form.name.into_inner(), 42);
    }
    let form =
        extract::<Form<Text<String>>>(multipart_request(&[Part::new("name", "héllo".as_bytes())]))
            .await
            .unwrap();
    assert_eq!(form.name.into_inner(), "héllo");
}

/// STATEMENT: `Text` rejects a non-plain media type by default.
///
/// HOW:
/// - Submit valid numeric text with `application/json`.
/// - Confirm the failure identifies `name` and returns a content-type error with status 400.
#[ntex::test]
async fn text_requires_plain_content_type() {
    let error = extract::<Form<Text<u32>>>(multipart_request(&[
        Part::new("name", b"42").content_type("application/json")
    ]))
    .await
    .err()
    .unwrap();
    assert_field_error(error, StatusCode::BAD_REQUEST, "Content type error").await;
}

/// STATEMENT: `Text` distinguishes invalid UTF-8 from values that cannot deserialize into the target type.
///
/// HOW:
/// - Submit an invalid UTF-8 byte and nonnumeric text to `Text<u32>`.
/// - Confirm each failure identifies `name`, returns status 400, and describes the respective decoding stage.
#[ntex::test]
async fn text_reports_decoding_and_deserialization_errors() {
    for (data, message) in [
        (b"\xff".as_slice(), "UTF-8 decoding error"),
        (b"not a number".as_slice(), "Plain text deserialize error"),
    ] {
        let error = extract::<Form<Text<u32>>>(multipart_request(&[Part::new("name", data)]))
            .await
            .err()
            .unwrap();
        assert_field_error(error, StatusCode::BAD_REQUEST, message).await;
    }
}

/// STATEMENT: App-state `TextConfig` can disable media-type validation while retaining text deserialization.
///
/// HOW:
/// - Register relaxed validation and submit numeric text with `application/octet-stream`.
/// - Confirm the field deserializes to the submitted number.
#[ntex::test]
async fn text_config_allows_other_media_types() {
    let form = extract::<Form<Text<u32>>>(
        multipart_request(&[Part::new("name", b"42").content_type("application/octet-stream")])
            .app_state(TextConfig::default().validate_content_type(false)),
    )
    .await
    .unwrap();
    assert_eq!(form.name.into_inner(), 42);
}

/// STATEMENT: `Bytes` preserves uploaded binary content and multipart file metadata.
///
/// HOW:
/// - Submit binary bytes with a filename and an octet-stream media type.
/// - Confirm the extracted data, filename, and media type match the upload.
#[ntex::test]
async fn bytes_preserves_upload_and_metadata() {
    let form = extract::<Form<Bytes>>(multipart_request(&[Part::new("name", b"\0\xff\rdata")
        .content_type("application/octet-stream")
        .file_name("upload.bin")]))
    .await
    .unwrap();
    assert_eq!(form.name.data.as_ref(), b"\0\xff\rdata");
    assert_eq!(form.name.file_name.as_deref(), Some("upload.bin"));
    assert_eq!(
        form.name.content_type.unwrap(),
        mime::APPLICATION_OCTET_STREAM
    );
}

/// STATEMENT: In-memory readers enforce both form limits and accept data exactly at the limit.
///
/// HOW:
/// - Submit five-byte fields through `Bytes`, `Json`, and `Text` with a four-byte memory limit.
/// - Also exceed total limits for `Json` and `Text`, then extract all three at exact five-byte limits.
/// - Confirm overflowing cases fail with `PayloadError::Overflow` and exact-limit data survives.
#[ntex::test]
async fn in_memory_readers_enforce_form_limits() {
    let memory = MultipartFormConfig::default().memory_limit(4);
    assert_overflow(extract::<Form<Bytes>>(request().app_state(memory.clone())).await);
    for config in [memory, MultipartFormConfig::default().total_limit(4)] {
        assert_overflow(
            extract::<Form<Json<Vec<u32>>>>(
                multipart_request(&[Part::new("name", b"[1,2]").content_type("application/json")])
                    .app_state(config.clone()),
            )
            .await,
        );
        assert_overflow(extract::<Form<Text<String>>>(request().app_state(config)).await);
    }
    let exact = MultipartFormConfig::default()
        .total_limit(5)
        .memory_limit(5);
    let bytes = extract::<Form<Bytes>>(request().app_state(exact.clone()))
        .await
        .unwrap();
    let json = extract::<Form<Json<Vec<u32>>>>(
        multipart_request(&[Part::new("name", b"[1,2]").content_type("application/json")])
            .app_state(exact.clone()),
    )
    .await
    .unwrap();
    let text = extract::<Form<Text<String>>>(request().app_state(exact))
        .await
        .unwrap();
    assert_eq!(bytes.name.data, "hello");
    assert_eq!(json.name.0, vec![1, 2]);
    assert_eq!(text.name.0, "hello");
}

#[derive(MultipartForm)]
struct Collections {
    required: Text<u32>,
    optional: Option<Text<String>>,
    repeated: Vec<Text<String>>,
    optional_repeated: Option<Vec<Text<String>>>,
}

/// STATEMENT: Missing optional groups stay absent and repeated groups preserve all fields in arrival order.
///
/// HOW:
/// - Extract only a required field, then extract a form with optional and repeated fields interleaved.
/// - Confirm absent `Option` and `Option<Vec>` groups are `None`, absent `Vec` groups are empty, and populated groups retain their values and order.
#[ntex::test]
async fn collections_preserve_presence_and_order() {
    let form = extract::<Collections>(multipart_request(&[Part::new("required", b"7")]))
        .await
        .unwrap();
    assert_eq!(form.required.0, 7);
    assert!(form.optional.is_none());
    assert!(form.repeated.is_empty());
    assert!(form.optional_repeated.is_none());

    let form = extract::<Collections>(multipart_request(&[
        Part::new("repeated", b"first"),
        Part::new("required", b"8"),
        Part::new("optional_repeated", b"a"),
        Part::new("optional", b"present"),
        Part::new("repeated", b"second"),
        Part::new("optional_repeated", b"b"),
    ]))
    .await
    .unwrap();
    assert_eq!(form.required.0, 8);
    assert_eq!(form.optional.unwrap().0, "present");
    assert_eq!(
        form.repeated
            .into_iter()
            .map(Text::into_inner)
            .collect::<Vec<_>>(),
        ["first", "second"]
    );
    assert_eq!(
        form.optional_repeated
            .unwrap()
            .into_iter()
            .map(Text::into_inner)
            .collect::<Vec<_>>(),
        ["a", "b"]
    );
}

/// STATEMENT: A missing required field prevents construction even when optional fields are present.
///
/// HOW:
/// - Submit an empty form and a form containing only an optional field.
/// - Confirm both extractions return `MissingField` naming `required`.
#[ntex::test]
async fn missing_required_fields_are_rejected() {
    for parts in [vec![], vec![Part::new("optional", b"present")]] {
        assert!(
            matches!(extract::<Collections>(multipart_request(&parts)).await,
            Err(MultipartError::MissingField(name)) if name == "required")
        );
    }
}

#[derive(MultipartForm)]
struct IgnoreDuplicates {
    required: Text<u32>,
    optional: Option<Text<u32>>,
}

#[derive(MultipartForm)]
#[multipart(duplicate_field = "replace")]
struct ReplaceDuplicates {
    required: Text<u32>,
    optional: Option<Text<u32>>,
}

#[derive(MultipartForm)]
#[multipart(duplicate_field = "deny")]
struct DenyDuplicates {
    required: Text<u32>,
    optional: Option<Text<u32>>,
    repeated: Vec<Text<u32>>,
    optional_repeated: Option<Vec<Text<u32>>>,
}

/// STATEMENT: The default duplicate policy retains the first required and optional values without parsing ignored duplicates.
///
/// HOW:
/// - Submit valid initial values followed by invalid numeric duplicates and an unknown field.
/// - Confirm extraction succeeds with the initial required and optional numbers.
#[ntex::test]
async fn duplicates_are_ignored_without_deserialization() {
    let form = extract::<IgnoreDuplicates>(multipart_request(&[
        Part::new("required", b"1"),
        Part::new("optional", b"2"),
        Part::new("required", b"invalid"),
        Part::new("unknown", b"ignored"),
        Part::new("optional", b"invalid"),
    ]))
    .await
    .unwrap();
    assert_eq!(form.required.0, 1);
    assert_eq!(form.optional.unwrap().0, 2);
}

/// STATEMENT: The replace policy parses each duplicate and retains the last required and optional values.
///
/// HOW:
/// - Submit two valid values for each single-value group and confirm the later values win.
/// - Submit an invalid replacement for each group and confirm it produces a field error rather than retaining the earlier value.
#[ntex::test]
async fn duplicates_replace_and_validate_later_values() {
    let form = extract::<ReplaceDuplicates>(multipart_request(&[
        Part::new("required", b"1"),
        Part::new("optional", b"2"),
        Part::new("required", b"3"),
        Part::new("optional", b"4"),
    ]))
    .await
    .unwrap();
    assert_eq!(form.required.0, 3);
    assert_eq!(form.optional.unwrap().0, 4);
    for duplicate in ["required", "optional"] {
        assert!(matches!(extract::<ReplaceDuplicates>(multipart_request(&[
            Part::new("required", b"1"), Part::new("optional", b"2"),
            Part::new(duplicate, b"invalid"),
        ])).await, Err(MultipartError::Field { name, .. }) if name == duplicate));
    }
}

/// STATEMENT: Denying duplicates rejects repeated single-value fields but still accepts repeated collection fields.
///
/// HOW:
/// - Duplicate the required and optional fields separately and confirm `DuplicateField` names the offending field.
/// - Repeat `Vec` and `Option<Vec>` fields under the same policy and confirm every numeric value is retained in order.
#[ntex::test]
async fn duplicate_deny_exempts_collections() {
    for duplicate in ["required", "optional"] {
        assert!(matches!(extract::<DenyDuplicates>(multipart_request(&[
            Part::new("required", b"1"), Part::new("optional", b"2"),
            Part::new(duplicate, b"invalid"),
        ])).await, Err(MultipartError::DuplicateField(name)) if name == duplicate));
    }
    let form = extract::<DenyDuplicates>(multipart_request(&[
        Part::new("required", b"1"),
        Part::new("optional", b"2"),
        Part::new("repeated", b"3"),
        Part::new("repeated", b"4"),
        Part::new("optional_repeated", b"5"),
        Part::new("optional_repeated", b"6"),
    ]))
    .await
    .unwrap();
    assert_eq!(form.required.0, 1);
    assert_eq!(form.optional.unwrap().0, 2);
    assert_eq!(
        form.repeated
            .into_iter()
            .map(Text::into_inner)
            .collect::<Vec<_>>(),
        [3, 4]
    );
    assert_eq!(
        form.optional_repeated
            .unwrap()
            .into_iter()
            .map(Text::into_inner)
            .collect::<Vec<_>>(),
        [5, 6]
    );
}

#[derive(MultipartForm)]
#[multipart(deny_unknown_fields)]
struct StrictForm {
    #[multipart(rename = "upload")]
    name: Bytes,
}

/// STATEMENT: Unknown-field denial respects renamed fields and rejects unrecognized names.
///
/// HOW:
/// - Extract a field using its renamed `upload` name and confirm its bytes.
/// - Submit the Rust field name instead and confirm `UnknownField` reports `name`.
#[ntex::test]
async fn unknown_fields_are_denied_after_renaming() {
    let form = extract::<StrictForm>(multipart_request(&[Part::new("upload", b"hello")]))
        .await
        .unwrap();
    assert_eq!(form.name.data, "hello");
    assert!(
        matches!(extract::<StrictForm>(multipart_request(&[Part::new("name", b"hello")])).await,
        Err(MultipartError::UnknownField(name)) if name == "name")
    );
}

#[derive(MultipartForm)]
struct LimitedCollection {
    #[multipart(limit = "5 B")]
    name: Vec<Bytes>,
    tail: Option<Bytes>,
}

/// STATEMENT: Field limits accumulate across repeated names and do not leak into unrelated fields.
///
/// HOW:
/// - Submit two `name` fields totaling exactly five bytes, followed by an unlimited six-byte `tail`.
/// - Confirm all data survives, then exceed the shared `name` limit by one byte and expect overflow.
#[ntex::test]
async fn field_limits_are_shared_only_by_matching_names() {
    let form = extract::<LimitedCollection>(multipart_request(&[
        Part::new("name", b"ab"),
        Part::new("name", b"cde"),
        Part::new("tail", b"abcdef"),
    ]))
    .await
    .unwrap();
    assert_eq!(
        form.name
            .into_iter()
            .map(|field| field.data)
            .collect::<Vec<_>>(),
        ["ab", "cde"]
    );
    assert_eq!(form.tail.unwrap().data, "abcdef");
    assert_overflow(
        extract::<LimitedCollection>(multipart_request(&[
            Part::new("name", b"ab"),
            Part::new("name", b"cdef"),
        ]))
        .await,
    );
}

/// STATEMENT: Memory and total budgets are shared across distinct form fields rather than reset per field.
///
/// HOW:
/// - Submit two three-byte fields under five-byte memory and total limits separately.
/// - Confirm both configurations reject the six-byte aggregate with overflow.
#[ntex::test]
async fn form_limits_accumulate_across_fields() {
    for config in [
        MultipartFormConfig::default().memory_limit(5),
        MultipartFormConfig::default().total_limit(5),
    ] {
        assert_overflow(
            extract::<LimitedCollection>(
                multipart_request(&[Part::new("name", b"abc"), Part::new("tail", b"def")])
                    .app_state(config),
            )
            .await,
        );
    }
}

/// STATEMENT: Typed forms reject absent, malformed, and incompatible request media types or missing boundaries.
///
/// HOW:
/// - Extract requests with no content type, malformed and nonmultipart types, a missing boundary, and mixed or related subtypes.
/// - Confirm each request fails with the corresponding multipart content-type or boundary error.
#[ntex::test]
async fn forms_reject_invalid_request_content_types() {
    for (content_type, expected) in [
        (None, MultipartError::NoContentType),
        (Some("invalid"), MultipartError::ParseContentType),
        (Some("text/plain"), MultipartError::IncompatibleContentType),
        (Some("multipart/form-data"), MultipartError::Boundary),
        (
            Some("multipart/mixed; boundary=abc"),
            MultipartError::IncompatibleContentType,
        ),
        (
            Some("multipart/related; boundary=abc"),
            MultipartError::IncompatibleContentType,
        ),
    ] {
        let mut request = TestRequest::post().payload(BODY);
        if let Some(content_type) = content_type {
            request = request.header(header::CONTENT_TYPE, content_type);
        }
        let error = extract::<Form<Bytes>>(request).await.err().unwrap();
        assert_eq!(
            std::mem::discriminant(&error),
            std::mem::discriminant(&expected)
        );
    }
}

/// STATEMENT: `TempFile` writes uploaded bytes to the configured project directory without using the memory budget and removes files on drop.
///
/// HOW:
/// - Upload binary data with and without file metadata using a zero-byte memory budget and an exact total limit.
/// - Confirm file contents, size, directory, and optional metadata, then drop the form and confirm the file is removed.
#[ntex::test]
async fn temp_files_preserve_data_metadata_and_cleanup() {
    for metadata in [false, true] {
        let mut part = Part::new("name", b"\0\xffabc");
        if metadata {
            part = part
                .content_type("application/octet-stream")
                .file_name("upload.bin");
        }
        let form = extract::<Form<TempFile>>(
            multipart_request(&[part])
                .app_state(TempFileConfig::default().directory("."))
                .app_state(
                    MultipartFormConfig::default()
                        .total_limit(5)
                        .memory_limit(0),
                ),
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read(form.name.file.path()).unwrap(), b"\0\xffabc");
        assert_eq!(form.name.size, 5);
        assert_eq!(
            form.name
                .file
                .path()
                .parent()
                .unwrap()
                .canonicalize()
                .unwrap(),
            std::env::current_dir().unwrap()
        );
        assert_eq!(
            form.name.file_name.as_deref(),
            metadata.then_some("upload.bin")
        );
        assert_eq!(
            form.name.content_type,
            metadata.then_some(mime::APPLICATION_OCTET_STREAM)
        );
        let path = form.name.file.path().to_owned();
        drop(form);
        assert!(!path.exists());
    }
}

#[derive(MultipartForm)]
struct LimitedTempFile {
    #[multipart(limit = "4 B")]
    name: TempFile,
}

/// STATEMENT: Disk-backed fields enforce total and field limits and accept data exactly at the field limit.
///
/// HOW:
/// - Submit a five-byte file with a four-byte total limit and then a four-byte field limit.
/// - Confirm both extractions fail with `PayloadError::Overflow`, then extract a four-byte file and verify its contents in a project-local directory.
#[ntex::test]
async fn temp_files_enforce_total_and_field_limits() {
    assert_overflow(
        extract::<Form<TempFile>>(
            request()
                .app_state(TempFileConfig::default().directory("."))
                .app_state(MultipartFormConfig::default().total_limit(4)),
        )
        .await,
    );
    assert_overflow(
        extract::<LimitedTempFile>(request().app_state(TempFileConfig::default().directory(".")))
            .await,
    );
    let form = extract::<LimitedTempFile>(
        multipart_request(&[Part::new("name", b"four")])
            .app_state(TempFileConfig::default().directory(".")),
    )
    .await
    .unwrap();
    assert_eq!(std::fs::read(form.name.file.path()).unwrap(), b"four");
}

/// STATEMENT: Failure to create an upload file is reported as a named field error with status 500.
///
/// HOW:
/// - Configure `TempFileConfig` to use the crate's `Cargo.toml` file as a directory.
/// - Confirm extraction fails for `name` with a file-I/O error response rather than panicking.
#[ntex::test]
async fn temp_file_creation_errors_are_reported() {
    let error = extract::<Form<TempFile>>(
        request().app_state(TempFileConfig::default().directory("Cargo.toml")),
    )
    .await
    .err()
    .unwrap();
    assert_field_error(error, StatusCode::INTERNAL_SERVER_ERROR, "File I/O error").await;
}

/// STATEMENT: The untyped `Multipart` extractor accepts mixed uploads and preserves headers and streamed data without requiring a form-field name.
///
/// HOW:
/// - Extract a `multipart/mixed` request containing an unnamed binary field and a custom header.
/// - Confirm the field has no name, retains its custom header and bytes, and the stream terminates after the field is consumed.
#[ntex::test]
async fn multipart_extractor_preserves_unnamed_uploads() {
    let (req, mut pl, ()) = TestRequest::post()
        .header(header::CONTENT_TYPE, "multipart/mixed; boundary=abc")
        .payload(b"--abc\r\nX-Upload: trace-id\r\nContent-Type: application/octet-stream\r\n\r\n\0\xffdata\r\n--abc--\r\n".as_slice())
        .to_http_parts();
    let mut multipart = Multipart::from_request(&(), &req, &mut pl).await.unwrap();
    let field = multipart.next().await.unwrap().unwrap();
    assert!(field.name().is_none());
    assert_eq!(field.headers().get("x-upload").unwrap(), "trace-id");
    let chunks = field.try_collect::<Vec<_>>().await.unwrap();
    assert_eq!(chunks.concat(), b"\0\xffdata");
    assert!(multipart.next().await.is_none());
}

#[derive(MultipartForm)]
#[multipart(deny_unknown_fields, duplicate_field = "deny")]
struct RenamedLimitedUploads {
    #[multipart(rename = "files[]", limit = "1 KiB")]
    uploads: Vec<Bytes>,
}

/// STATEMENT: Renamed collection fields share their parsed size limit while strict field and duplicate policies remain effective.
///
/// HOW:
/// - Upload two `files[]` parts totaling exactly one KiB, then exceed that aggregate limit by one byte.
/// - Confirm the exact-limit files retain their data, overflow is rejected, and using the Rust field name returns `UnknownField`.
#[ntex::test]
async fn renamed_uploads_share_limits_under_strict_policies() {
    let first = vec![b'a'; 512];
    let second = vec![b'b'; 512];
    let form = extract::<RenamedLimitedUploads>(multipart_request(&[
        Part::new("files[]", &first),
        Part::new("files[]", &second),
    ]))
    .await
    .unwrap();
    assert_eq!(form.uploads.len(), 2);
    assert_eq!(form.uploads[0].data.as_ref(), first);
    assert_eq!(form.uploads[1].data.as_ref(), second);
    assert_overflow(
        extract::<RenamedLimitedUploads>(multipart_request(&[
            Part::new("files[]", &first),
            Part::new("files[]", &second),
            Part::new("files[]", b"x"),
        ]))
        .await,
    );
    assert!(matches!(
        extract::<RenamedLimitedUploads>(multipart_request(&[Part::new("uploads", b"data")])).await,
        Err(MultipartError::UnknownField(name)) if name == "uploads"
    ));
}

/// STATEMENT: Disk-backed field readers preserve fragmented uploads and propagate payload errors after consuming earlier chunks.
///
/// HOW:
/// - Read a project-local `TempFile` from an intermittently pending stream with a three-byte chunk followed by another chunk or `Overflow`.
/// - Confirm success preserves all six bytes, file size, filename, media type, and zero memory usage; confirm failure preserves the payload error after charging only the earlier chunk.
#[ntex::test]
async fn temp_files_handle_fragmented_uploads_and_payload_errors() {
    use futures_test::stream::StreamTestExt;
    use ntex::http::error::PayloadError;
    use ntex::util::Bytes as PayloadBytes;
    use ntex_multipart::form::Limits;

    for fail in [false, true] {
        let (req, _, ()) = request()
            .app_state(TempFileConfig::default().directory("."))
            .to_http_parts();
        let mut chunks = vec![
            Ok(PayloadBytes::from_static(
                b"--abc\r\nContent-Disposition: form-data; name=\"name\"; filename=\"upload.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n",
            )),
            Ok(PayloadBytes::from_static(b"\0ab")),
        ];
        if fail {
            chunks.push(Err(PayloadError::Overflow));
        } else {
            chunks.push(Ok(PayloadBytes::from_static(b"\xffcd\r\n--abc--\r\n")));
        }
        let stream = futures::stream::iter(chunks).interleave_pending();
        let mut multipart = Multipart::new(req.headers(), stream);
        let field = multipart.next().await.unwrap().unwrap();
        let mut limits = Limits::new(6, 0);
        let result = TempFile::read_field(&(), &req, field, &mut limits).await;
        assert_eq!(limits.memory_limit_remaining, 0);
        if fail {
            assert!(matches!(
                result,
                Err(MultipartError::Payload(PayloadError::Overflow))
            ));
            assert_eq!(limits.total_limit_remaining, 3);
        } else {
            let upload = result.unwrap();
            assert_eq!(std::fs::read(upload.file.path()).unwrap(), b"\0ab\xffcd");
            assert_eq!(upload.size, 6);
            assert_eq!(upload.file_name.as_deref(), Some("upload.bin"));
            assert_eq!(upload.content_type, Some(mime::APPLICATION_OCTET_STREAM));
            assert_eq!(limits.total_limit_remaining, 0);
            let path = upload.file.path().to_owned();
            drop(upload);
            assert!(!path.exists());
            assert!(multipart.next().await.is_none());
        }
    }
}

/// STATEMENT: A part with an empty `name` is handled like any unknown field.
///
/// HOW:
/// - Submit a form with an extra part named `""` alongside the required field.
/// - Confirm extraction succeeds in a debug build and keeps the required value.
#[ntex::test]
async fn empty_field_name_is_ignored() {
    let form = extract::<IgnoreDuplicates>(multipart_request(&[
        Part::new("", b"ignored"),
        Part::new("required", b"1"),
    ]))
    .await
    .unwrap();
    assert_eq!(form.required.0, 1);
}
