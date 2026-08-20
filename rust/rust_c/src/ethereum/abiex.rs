use alloc::string::ToString;
use alloc::boxed::Box;
use alloc::vec::Vec;
use itertools::Itertools;
use crate::clog::log_message;
use crate::common::errors::{ErrorCodes, RustCError};
use crate::common::ffi::CSliceFFI;
use crate::common::structs::Response;
use crate::common::utils::recover_c_array;
use crate::ethereum::structs::DisplayETHAbiexParsed;
use crate::{
    common::types::{Ptr, PtrBytes, PtrEthabiexParsed},
    extract_ptr_with_type,
};

use alloc::format;

use app_ethereum::abiex::{self, ContractCall};

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ETHAbiexParsedType {
    #[allow(non_camel_case_types)]
    ETHABIEX_PARSED_TYPE_TRANSFER = 0,
    #[allow(non_camel_case_types)]
    ETHABIEX_PARSED_TYPE_APPROVAL = 1,
    #[allow(non_camel_case_types)]
    ETHABIEX_PARSED_TYPE_TRANSFER_FROM = 2,
    #[allow(non_camel_case_types)]
    ETHABIEX_PARSED_TYPE_BATCH = 3,
    #[allow(non_camel_case_types)]
    ETHABIEX_PARSED_TYPE_UNKNOWN = 4,
}

#[no_mangle]
pub extern "C" fn eth_abiex_parse(
    chain_id: u64,
    address: Ptr<CSliceFFI<u8>>,
    data: Ptr<CSliceFFI<u8>>,
    parsed: Ptr<PtrEthabiexParsed>,
) -> i32 {
    let address = unsafe { recover_c_array(address) };
    let data = unsafe { recover_c_array(data) };
    let address: [u8; 20] = address[..20].try_into().unwrap();

    let calls = match abiex::contract_call_parse(chain_id, &address, &data) {
        Ok(calls) => calls,
        Err(e) => {
            log_message(&format!("contract_call_parse error: {:?}", e));
            return -1;
        }
    };
    let boxed = Box::new(calls);
    unsafe {
        *parsed = Box::into_raw(boxed) as PtrEthabiexParsed;
    }
    0
}

#[no_mangle]
pub extern "C" fn eth_abiex_parsed_count(parsed: PtrEthabiexParsed, count: Ptr<u32>) -> i32 {
    if parsed.is_null() || count.is_null() {
        return -1;
    }
    let calls: &Vec<ContractCall> = extract_ptr_with_type!(parsed, Vec<ContractCall>);
    unsafe {
        *count = calls.len() as u32;
    }
    0
}

#[no_mangle]
pub extern "C" fn eth_abiex_parsed_get(parsed: PtrEthabiexParsed, index: u32) -> Ptr<Response<DisplayETHAbiexParsed>> {
    if parsed.is_null() {
        return Response::from(RustCError::InvalidData("Invalid param".to_string())).c_ptr();
    }
    let calls: &Vec<ContractCall> = extract_ptr_with_type!(parsed, Vec<ContractCall>);
    let call = match calls.get(index as usize) {
        Some(call) => call,
        None => {
            return Response::from(RustCError::InvalidData("Invalid index".to_string())).c_ptr();
        }
    };

    match call {
        ContractCall::Transfer(ref transfer) => {
            let display = transfer.clone().into();
            Response::success(display).c_ptr()
        }
        ContractCall::Approval(ref approval) => {
            let display = approval.clone().into();
            Response::success(display).c_ptr()
        }
        ContractCall::TransferFrom(ref transfer_from) => {
            let display = transfer_from.clone().into();
            Response::success(display).c_ptr()
        }
        ContractCall::Unknown(ref data) => {
            let display = DisplayETHAbiexParsed::unknown(data);
            Response::success(display).c_ptr()
        }
    }
}
