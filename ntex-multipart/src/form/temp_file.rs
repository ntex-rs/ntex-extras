//! Writes a field to a temporary file on disk.
use std::{io, io::Write, path::Path, path::PathBuf};

use derive_more::Display;
use futures::TryStreamExt;
use mime::Mime;
use ntex::web::{DefaultError, HttpRequest, WebResponseError};
use ntex::{http::StatusCode, rt::spawn_blocking};
use tempfile::NamedTempFile;

use crate::{Field, MultipartError, form::FieldReader, form::Limits};

/// Write the field to a temporary file on disk.
#[derive(Debug)]
pub struct TempFile {
    /// The temporary file on disk.
    pub file: NamedTempFile,

    /// The value of the `content-type` header.
    pub content_type: Option<Mime>,

    /// The `filename` value in the `content-disposition` header.
    pub file_name: Option<String>,

    /// The size in bytes of the file.
    pub size: usize,
}

impl FieldReader for TempFile {
    async fn read_field(
        req: &HttpRequest,
        mut field: Field,
        limits: &mut Limits,
    ) -> Result<Self, MultipartError> {
        let config = req.app_state::<TempFileConfig>().unwrap_or(&DEFAULT_CONFIG);
        let mut size = 0;

        let file = config.create_tempfile().map_err(|err| MultipartError::Field {
            name: field.form_field_name.to_owned(),
            source: TempFileError::FileIo(err).into(),
        })?;

        let (file, mut f) = spawn_blocking(move || file.reopen().map(move |f| (file, f)))
            .await?
            .map_err(|err| MultipartError::Field {
                name: field.form_field_name.to_owned(),
                source: TempFileError::FileIo(err).into(),
            })?;

        while let Some(chunk) = field.try_next().await? {
            limits.try_consume_limits(chunk.len(), false)?;
            size += chunk.len();
            f = spawn_blocking(move || f.write_all(chunk.as_ref()).map(move |_| f))
                .await?
                .map_err(|err| MultipartError::Field {
                    name: field.form_field_name.to_owned(),
                    source: TempFileError::FileIo(err).into(),
                })?;
        }

        spawn_blocking(move || f.flush()).await?.map_err(|err| MultipartError::Field {
            name: field.form_field_name.to_owned(),
            source: TempFileError::FileIo(err).into(),
        })?;

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

#[derive(Debug, Display)]
#[non_exhaustive]
pub enum TempFileError {
    /// File I/O Error
    #[display("File I/O error: {}", _0)]
    FileIo(io::Error),
}

/// Return `BadRequest` for `TempFileError`
impl WebResponseError<DefaultError> for TempFileError {
    fn status_code(&self) -> StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

/// Configuration for the [`TempFile`] field reader.
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
    /// Sets the directory that temp files will be created in.
    ///
    /// The default temporary file location is platform dependent.
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
