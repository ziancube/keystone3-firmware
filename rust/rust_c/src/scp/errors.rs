use alloc::string::String;

use bitcoin::address::error;
use thiserror;
use thiserror::Error;

pub(crate) type Result<T> = ::core::result::Result<T, ScpError>;

#[derive(Error, Debug)]
pub enum ScpError {
    #[error("Invalid param")]
    InvalidParam,
    #[error("Invalid session")]
    InvalidSession,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Invalid certficate")]
    InvalidCertficate,
    #[error("Invalid length")]
    InvalidLength,
    #[error("Invalid padding")]
    InvalidPadding,
    #[error("Invalid receipt")]
    InvalidReceipt,
    #[error("Invalid string: {0}")]
    InvalidString(String),
    #[error("Invalid PIN")]
    InvalidPin,
    #[error("Unexpected content")]
    UnexpectedContent,
    #[error("Length not enough")]
    LengthNotEnough,
    #[error("MAC not match")]
    MacNotMatch,
    #[error("Tag not match, want: {want}, get: {get}")]
    TagNotMatch{want: u16, get: u16},
    #[error("C function failed, {0}: {1}")]
    FunctionFailed(String, i32),
    #[error("APDU response failed{0:04x}")]
    APDUResponseFailed(u16),
}
