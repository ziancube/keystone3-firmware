use aes::cipher::block_padding::UnpadError;
use super::scp11::TaggedError;

use thiserror;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, ScpError>;

#[derive(Error, Debug)]
pub enum ScpError {
    #[error("Invalid length")]
    InvalidLength,
    #[error("MAC not match")]
    MacNotMatch,
    #[error("Taged field parser failed: {0}")]
    TagedFieldParserFailed(String)
}

impl From<UnpadError> for ScpError {
    fn from(_: UnpadError) -> Self {
        ScpError::MacNotMatch
    }
}

impl From<TaggedError> for ScpError {
    fn from(value: TaggedError) -> Self {
        ScpError::TagedFieldParserFailed(value.to_string())
    }
}