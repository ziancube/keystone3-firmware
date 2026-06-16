use alloc::string::ToString;
use alloc::boxed::Box;
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

use app_ethereum::abiex::{self, BatchCall, ContractCall};

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

    let call = match abiex::contract_call_parse(chain_id, &address, &data) {
        Ok(call) => call,
        Err(e) => {
            log_message(&format!("contract_call_parse error: {:?}", e));
            return -1;
        }
    };
    let s = serde_json::to_string(&call).unwrap();
    log_message(&s);
    let boxed = Box::new(call);
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
    let call: &ContractCall = extract_ptr_with_type!(parsed, ContractCall);

    match call {
        ContractCall::Batch(ref batch) => unsafe {
            *count = batch.0.len() as u32;
        },
        _ => unsafe {
            *count = 1;
        },
    }

    0
}

#[no_mangle]
pub extern "C" fn eth_abiex_parsed_get(parsed: PtrEthabiexParsed, index: u32) -> Ptr<Response<DisplayETHAbiexParsed>> {
    if parsed.is_null() {
        return Response::from(RustCError::InvalidData("Invalid param".to_string())).c_ptr();
    }
    let call: &ContractCall = extract_ptr_with_type!(parsed, ContractCall);
    match call {
        ContractCall::Batch(ref batch) if index < batch.0.len() as u32 => {
            let item = batch.0[index as usize].clone();
            match item {
                BatchCall::Transfer(transfer) => {
                    let display = transfer.into();
                    Response::success(display).c_ptr()
                }
                BatchCall::Approval(approval) => {
                    let display = approval.into();
                    Response::success(display).c_ptr()
                }
                BatchCall::Unknown => {
                    let display = DisplayETHAbiexParsed::unknown();
                    Response::success(display).c_ptr()
                }
            }
        },
        ContractCall::Transfer(ref transfer) if index == 0 => {
            let display = transfer.clone().into();
            Response::success(display).c_ptr()
        },
        ContractCall::Approval(ref approval) if index == 0 => {
            let display = approval.clone().into();
            Response::success(display).c_ptr()
        },
        ContractCall::TransferFrom(ref transfer_from) if index == 0 => {
            let display = transfer_from.clone().into();
            Response::success(display).c_ptr()
        },
        ContractCall::Unknown => {
            let display = DisplayETHAbiexParsed::unknown();
            Response::success(display).c_ptr()
        },
        _  => {
            Response::from(RustCError::InvalidData("Invalid index".to_string())).c_ptr()
        },
    }
}
