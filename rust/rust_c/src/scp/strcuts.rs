use crate::common::types::PtrString;
use crate::{impl_c_ptr};

#[repr(C)]
pub struct SharedInfo {
    pub(crate) scp_id: u32,
    pub(crate) key_usage: u32,
    pub(crate) key_type: u32,
    pub(crate) key_length: u32,
    pub(crate) host_id: PtrString,
}

impl_c_ptr!(SharedInfo);