//! Writes a field to a temporary file on disk.
use std::{io, io::Write, path::Path, path::PathBuf};

use futures::TryStreamExt;
use mime::Mime;
use ntex::web::{DefaultError, HttpRequest, HttpResponse, WebResponseError};
use ntex::{http::StatusCode, rt::spawn_blocking};
use tempfile::NamedTempFile;

use crate::{Field, MultipartError, form::FieldReader, form::Limits};

/// Streams a field body to a newly created [`NamedTempFile`] on disk.
///
/// File writes run through [`spawn_blocking`]. This reader debits the total and
/// field-specific byte budgets, but not the memory budget. It does not validate
/// the content type or use the client filename as the on-disk name.
/// Configure the destination directory with [`TempFileConfig`] in request app state.
///
/// # Errors
///
/// Stream and budget errors propagate directly. File creation, reopening, writing,
/// and flushing failures return [`MultipartError::Field`] containing a
/// [`TempFileError`] rendered as a 500 response. Blocking task failures return
/// [`MultipartError::Blocking`].
///
/// # Panics
///
/// Calling [`FieldReader::read_field`] manually with a field whose
/// [`Field::content_disposition`] is `None` panics after writing its body.
/// The typed form extractor ensures a `form-data` disposition is present.
#[derive(Debug)]
pub struct TempFile {
    /// The disk-backed file, deleted on drop unless kept or persisted through `tempfile`.
    ///
    /// Its generated path is independent of [`Self::file_name`].
    pub file: NamedTempFile,

    /// The parsed part `Content-Type`, or `None` if absent or invalid.
    pub content_type: Option<Mime>,

    /// The optional client-supplied `filename` parameter from `Content-Disposition`.
    ///
    /// It is not sanitized for use as a filesystem path.
    pub file_name: Option<String>,

    /// The number of field-body bytes successfully written to the file.
    pub size: usize,
}

impl FieldReader for TempFile {
    async fn read_field<St>(
        st: &St,
        req: &HttpRequest,
        mut field: Field,
        limits: &mut Limits,
    ) -> Result<Self, MultipartError> {
        let config = req.app_state::<TempFileConfig>().unwrap_or(&DEFAULT_CONFIG);
        let mut size = 0;

        let file = config
            .create_tempfile()
            .map_err(|err| file_io_error(&field.form_field_name, st, err))?;

        let (file, mut f) = spawn_blocking(move || file.reopen().map(move |f| (file, f)))
            .await?
            .map_err(|err| file_io_error(&field.form_field_name, st, err))?;

        while let Some(chunk) = field.try_next().await? {
            limits.try_consume_limits(chunk.len(), false)?;
            size += chunk.len();
            f = spawn_blocking(move || f.write_all(chunk.as_ref()).map(move |_| f))
                .await?
                .map_err(|err| file_io_error(&field.form_field_name, st, err))?;
        }

        spawn_blocking(move || f.flush())
            .await?
            .map_err(|err| file_io_error(&field.form_field_name, st, err))?;

        Ok(TempFile {
            file,
            content_type: field.content_type().map(ToOwned::to_owned),
            file_name: field
                .content_disposition()
                .expect("multipart form fields should have a content-disposition header")
                .get_filename()
                .map(ToOwned::to_owned),
            size,
        })
    }
}

/// Wraps a temporary-file I/O failure as a field error with a 500 response.
fn file_io_error<St>(name: &str, st: &St, err: io::Error) -> MultipartError {
    MultipartError::Field {
        name: name.to_owned(),
        source: TempFileError::FileIo(err).error_response(st),
    }
}

/// Temporary-file I/O failures, rendered as 500 Internal Server Error responses.
///
/// [`TempFile`] stores the rendered response in [`MultipartError::Field`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TempFileError {
    /// Creating, reopening, writing, or flushing the file failed.
    #[error("File I/O error: {}", _0)]
    FileIo(
        /// The underlying filesystem I/O failure.
        io::Error,
    ),
}

/// Renders temporary-file errors with HTTP status 500 Internal Server Error.
impl<St> WebResponseError<St, DefaultError> for TempFileError {
    fn error_response(&self, _: &St) -> HttpResponse {
        HttpResponse::render_with(StatusCode::INTERNAL_SERVER_ERROR, self)
    }
}

/// Destination directory for [`TempFile`], registered with `App::app_state`.
///
/// By default, [`NamedTempFile::new`] selects the platform's temporary directory.
/// The configured directory is used as-is and is not created by this reader.
#[derive(Clone)]
pub struct TempFileConfig {
    directory: Option<PathBuf>,
}

impl TempFileConfig {
    fn create_tempfile(&self) -> io::Result<NamedTempFile> {
        if let Some(ref dir) = self.directory {
            NamedTempFile::new_in(dir)
        } else {
            NamedTempFile::new()
        }
    }
}

impl TempFileConfig {
    /// Sets the directory in which new temporary files are created.
    ///
    /// The directory must already exist and allow file creation; relative paths
    /// are relative to the process working directory. This setter only stores the
    /// path and performs no I/O. The default is the platform temporary directory.
    ///
    /// An unusable directory fails later during field reading with
    /// [`MultipartError::Field`], not when this setter is called.
    pub fn directory(mut self, dir: impl AsRef<Path>) -> Self {
        self.directory = Some(dir.as_ref().to_owned());
        self
    }
}

const DEFAULT_CONFIG: TempFileConfig = TempFileConfig { directory: None };

impl Default for TempFileConfig {
    fn default() -> Self {
        DEFAULT_CONFIG
    }
}
