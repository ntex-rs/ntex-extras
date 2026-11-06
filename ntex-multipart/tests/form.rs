#![cfg(feature = "derive")]

use ntex::http::header;
use ntex::web::{FromRequest, test::TestRequest};
use ntex_multipart::form::{FieldReader, bytes::Bytes};
use ntex_multipart::{MultipartError, MultipartForm, MultipartFormConfig};

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
